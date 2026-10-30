"""Terminal hook handlers (plan §7): VWP-04 file-injection `tool_execution`
middleware + `transform_tool_result` redaction (SEC-01, v0.5.4) +
`post_tool_call` cleanup/metrics (observer-only).

SEC-01 (v0.5.4, HIGH): the confidentiality boundary for injected secrets is
the AUTHORITATIVE Hermes transformation hook `transform_tool_result`
(`make_result_redactor`) — its RETURN VALUE replaces the tool result before
it reaches the model. The `post_tool_call` observer may mutate its own
reference but that mutation is not guaranteed to be the result delivered to
the LLM, so it no longer performs any redaction; it only does placeholder
cleanup, metrics logging and secret-free error surfacing. The per-execution
injected-secret set is handed off from the middleware to the transformer via
a ContextVar (`_CURRENT_INJECTED_SECRETS`), cleared in a finally block so no
secret values persist across turns. See CHANGELOG.md [0.5.4] for details.
NOTE: SEC-01 / VWP-XX audit references are intentionally kept in comments and
docstrings (developer context) only — they must NOT appear in runtime log
messages; logs carry diagnostic information exclusively.

VWP-04 (v0.4.4, BREAKING): secrets are no longer written into the command
string. The middleware intercepts the terminal call via Hermes's
`tool_execution` middleware (which WRAPS the actual tool invocation, allowing
cleanup in a `finally` block), resolves every `$__VW_SECRET_x__` reference
through the single-use registry, writes the real secret to a mkstemp file
(chmod 600, atomic, symlink-protected) inside a dedicated chmod 700 directory
under `$XDG_RUNTIME_DIR` (tmpfs/RAM-backed in typical setups; falls back to
`/tmp/vw-secrets-<uid>`), and rewrites the command so the reference becomes
`$(< path)` — the shell reads the secret at execution time. After the call
returns (or raises) the temp files are deleted in a `finally` block.

Security properties:
- the raw secret NEVER appears in the command string, argv, shell history or
  any log line / tool response; it exists only inside the temp file for the
  duration of the command execution;
- every injected secret is registered with the RedactingFilter first, so even
  echoed output is scrubbed, AND the per-execution plaintext set is handed to
  the authoritative `transform_tool_result` redactor via a ContextVar
  (SEC-01, v0.5.4);
- SEC-02 (v0.5.7): resolution is strictly ATOMIC per unique token per command
  execution — the middleware extracts all unique tokens, consumes each exactly
  once via `PlaceholderRegistry.consume_and_resolve()` (marked used BEFORE the
  entry is returned), creates ONE temp file per unique token and globally
  replaces ALL occurrences of that token with the same `$(< path)` reference.
  A command referencing the same placeholder several times can no longer hit a
  sequential partial-resolution or unintended-reuse path;
- unresolved references (expired / unknown / already-used) are left EXACTLY as
  they were: the leading `$` makes them valid shell variable references that
  expand to an empty string — fail-safe, the secret cannot leak and the
  command simply fails with an empty value (a warning is logged and the error
  is recorded for post_tool_call to surface to the agent).

Double-quote requirement (documented in the skill and README): the rewritten
`$(< path)` substitution must be expanded by the shell. Shell expansion
happens inside double quotes and unquoted — but NOT inside single quotes.
Every placeholder reference therefore MUST be double-quoted (or unquoted).

Middleware chain safety rules (CRITICAL):
- non-terminal tools are passed straight through to next_call;
- commands without a "$__VW_SECRET_" substring are passed through untouched;
- args are only modified when a placeholder was actually resolved;
- never modify args unless an actual change was made.
"""
from __future__ import annotations

import contextvars
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import MutableMapping
from pathlib import Path
from typing import Any, Callable

from . import errors
from .auth import AuthManager
from .placeholders import PlaceholderRegistry
from .secure_fs import FilesystemSecurityError, ensure_hardened_directory
from .security import get_logger, get_redacting_filter
from .tools import _field_value

log = get_logger("hooks")

# ---------------------------------------------------------------------------
# AUD-02 (v0.6.5): execution-scoped secret retention.
#
# Runtime secrets injected during ONE tool execution used to be registered
# with the global RedactingFilter and retained indefinitely (unbounded
# memory growth of plaintext values). They are now retained only while the
# execution scope may still need redaction and released afterwards through
# the thread-safe reference-counted APIs on RedactingFilter:
#
#   - one ExecutionSecretScope per tool execution, carried via a
#     ContextVar (`_execution_secret_scope`) so overlapping / concurrent
#     executions each own their own scope;
#   - the middleware retains every injected plaintext in the scope (each
#     value at most once per scope) BEFORE running the tool;
#   - release is DEFERRED to the latest safe lifecycle point  -- after the
#     authoritative transform_tool_result pass and after the observer-side
#     post_tool_call cleanup/metrics have run (Hermes dispatch order:
#     middleware wraps next_call; transform runs on the returned result;
#     post_tool_call observes last). post_tool_call closes the scope when
#     it can attribute the call to it (task_id or an execution-id kwarg);
#   - the middleware's finally block is the FAIL-SAFE cleanup path for
#     exceptional cases where no later lifecycle point will run (next_call
#     raised, host never dispatched the observer). close() is release-once:
#     double-close is a silent no-op and secrets can never leak across
#     turns nor grow globally.
#   - process-scoped secrets (bootstrap client secret / master password,
#     live session key, startup-injection secrets) are NOT part of any
#     execution scope; releasing a scope only ever drops the scope's OWN
#     execution reference, never the process baseline.
#
# NEVER log secret values anywhere in this machinery  -- sanitized
# diagnostics carry lengths/counts only.
# ---------------------------------------------------------------------------


class ExecutionSecretScope:
    """Reference-counted, release-once secret scope for ONE tool execution.

    Every plaintext runtime secret retained through this scope increments
    the shared RedactingFilter's execution refcount exactly once per scope
    (a value referenced by several placeholders in one command keeps a
    single reference). :meth:`close` releases precisely those references  --
    idempotently, so closing twice (post_tool_call + middleware fail-safe)
    never double-decrements and never removes a value another active
    execution still retains.
    """

    def __init__(self, redactor: Any) -> None:
        self._redactor = redactor
        self._values: set[str] = set()
        # Values whose shared-refcount reference is still OUTSTANDING (not
        # yet returned via release_value/close). Normally 0/1 per value;
        # counted so a double bookkeeping call can never double-decrement.
        self._outstanding: dict[str, int] = {}
        #: AUD-02: per-value count of temp-file ("path-ref") references this
        #: scope took IN ADDITION to its deduplicated primary reference.
        #: ``release_value`` floors at this count: the entries themselves
        #: own those references and hand them back via
        #: :func:`_release_path_retention`, so neither an early per-path
        #: release nor close() can ever double-decrement or strand one.
        self._path_owned: dict[str, int] = {}
        self._closed = False
        self._lock = threading.Lock()

    def retain(self, value: str) -> None:
        """Retain *value* for this execution scope (once per distinct value).

        No-op after close (sanitized warning only  -- never the value).
        """
        if not value:
            return
        with self._lock:
            if self._closed:
                # Sanitized misuse diagnostic: length only, NEVER the value.
                log.warning(
                    "AUD-02: attempted to retain a runtime secret (len=%d) "
                    "in an already-closed execution scope; ignored.",
                    len(value))
                return
            if value in self._values:
                return  # same secret within one execution: ONE reference
            self._values.add(value)
            self._outstanding[value] = self._outstanding.get(value, 0) + 1
        self._redactor.retain_secret(value)

    def retain_path_reference(self, value: str) -> None:
        """Bookkeeping-only registration of one temp-file ("path-ref") reference.

        AUD-02: called by :func:`_resolve_placeholder_token` AFTER it took an
        EXTRA shared-refcount reference for the resolved temp file. The
        reference itself is OWNED BY THE ENTRY — releasing it goes through
        :func:`_release_path_retention`, never through this scope. The scope
        only records the count so its fail-safe release paths (``release_value``
        / ``close``) know how many references must survive them and can never
        double-decrement or strand one. Never logs the value.
        """
        if not value:
            return
        with self._lock:
            if self._closed:
                return  # stale handle after close: entry release still owns it
            self._path_owned[value] = self._path_owned.get(value, 0) + 1

    def has_value(self, value: str) -> bool:
        """Whether this OPEN scope already retains *value*.

        Observability helper (tests / sanitized diagnostics): never logs the
        value. A closed scope reports False — it no longer owns references.
        """
        with self._lock:
            return (not self._closed) and value in self._values

    def release_value(self, value: str) -> None:
        """Release THIS scope's PRIMARY execution reference for *value*.

        AUD-02 fail-safe release: called by the middleware when the
        execution cannot be attributed to a lifecycle id, or when the
        middleware frame unwinds via an exception before any later hook can
        run. The scope drops its outstanding primary references for the
        value (normally one — ``retain`` dedupes identical values inside a
        single execution) but FLOORS at the number of temp-file ("path-ref")
        references still owned by their entries: those are handed back only
        by :func:`_release_path_retention`, so this call can never double-
        decrement them and a second call is a silent no-op (release-once per
        value). An early release can therefore never strip redaction
        coverage from a value another active execution (or the process
        baseline) still retains. Process-scoped baselines are untouched —
        the redactor only removes the value from its state when BOTH the
        execution refcount and the process baseline reach zero. Never logs
        the value.
        """
        if not value:
            return
        with self._lock:
            if self._closed or value not in self._values:
                return  # already released / never retained here: no-op
            self._values.discard(value)
            n = self._outstanding.pop(value, 0)
        for _ in range(n):
            self._redactor.release_secret(value)

    def close(self) -> None:
        """Release every execution-scoped reference held by this scope.

        Release-once: subsequent calls are a no-op. Process-scoped
        baselines are untouched  -- the redactor only drops THIS scope's
        execution reference (a value stays redactable while any other
        active execution or the process baseline still holds it).
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
            # Release EXACTLY the outstanding references: release_value()
            # (per-placeholder early release on the no-attributable-id
            # fail-safe path) may already have dropped some of them.
            outstanding = list(self._outstanding.items())
            self._values.clear()
            self._outstanding.clear()
            self._path_owned.clear()
        for v, n in outstanding:
            for _ in range(n):
                self._redactor.release_secret(v)

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def retained_count(self) -> int:
        """Number of distinct values this scope currently retains.

        Observability helper for tests / sanitized diagnostics: returns a
        bare count, never exposes or logs any secret value.
        """
        with self._lock:
            return len(self._values)

    def retained_values(self) -> list[str]:
        """Snapshot copy of the plaintexts this OPEN scope still retains.

        AUD-02 (v0.6.5): consumed by the authoritative
        ``transform_tool_result`` redactor so exact-value scrubbing keeps
        working even when the host dispatches the transformer on a
        different context/thread than the middleware (ContextVar/task-store
        blind spot). A closed scope returns an empty list — released
        references must never re-enter redaction through a stale handle.
        Never logs the values.
        """
        with self._lock:
            if self._closed:
                return []
            return list(self._values)


#: Active execution scope per context (one tool execution == one scope).
_execution_secret_scope: contextvars.ContextVar["ExecutionSecretScope | None"] \
    = contextvars.ContextVar("vaultwarden_execution_secret_scope", default=None)

#: Fallback registry keyed by execution/task id  -- covers hosts that
#: dispatch post_tool_call on a different context than the middleware
#: (same belt-and-braces pattern as the task-keyed injected-secret store).
_EXEC_SCOPES_BY_ID: dict[str, "ExecutionSecretScope"] = {}
_EXEC_SCOPES_LOCK = threading.Lock()


def _exec_id_for(task_id: str, kwargs: dict | None = None) -> str:
    """Canonical execution id: explicit task_id first, then Hermes kwargs."""
    if task_id:
        return task_id
    kw = kwargs or {}
    for key in ("execution_id", "tool_call_id", "call_id", "turn_id"):
        val = kw.get(key)
        if isinstance(val, str) and val:
            return val
    return ""


def open_execution_scope(exec_id: str = "") -> tuple["ExecutionSecretScope", Any]:
    """Create the scope for one execution and publish it (middleware entry).

    Returns ``(scope, token)``; the caller MUST eventually
    :func:`close_execution_scope` (fail-safe in its finally block).
    """
    # AUD-02 adoption rule: if a previous execution left its scope slot
    # published (attributable executions defer their release to
    # post_tool_call, which may run on another context), that leftover
    # scope was already closed by the owner's fail-safe path OR is still
    # legitimately open under its OWN registry id. Never overwrite an
    # OPEN scope entry for the same id; adopt-and-clear the slot only for
    # a fresh execution so a stale reference can never capture new secrets
    # (tools._current_execution_scope additionally ignores closed scopes).
    stale = _execution_secret_scope.get()
    if stale is not None and stale.closed:
        _execution_secret_scope.set(None)
    scope = ExecutionSecretScope(get_redacting_filter())
    token = _execution_secret_scope.set(scope)
    if exec_id:
        with _EXEC_SCOPES_LOCK:
            prev = _EXEC_SCOPES_BY_ID.get(exec_id)
            if prev is not None and not prev.closed:
                # Same id re-used while still open: keep the ORIGINAL live
                # scope so its pending deferred release stays authoritative;
                # the new execution retains THROUGH it as well.
                _execution_secret_scope.reset(token)
                return prev, token
            _EXEC_SCOPES_BY_ID[exec_id] = scope
    return scope, token


def _clear_execution_scope_slot() -> None:
    """Clear the published ContextVar slot (host-side turn completion)."""
    _execution_secret_scope.set(None)


def current_execution_scope() -> "ExecutionSecretScope | None":
    """The active execution scope in this context, if any."""
    return _execution_secret_scope.get()


def close_execution_scope(token: Any = None, exec_id: str = "",
                          kwargs: dict | None = None) -> bool:
    """Close the execution scope at the safe final lifecycle point.

    Resolution order: the task-keyed fallback registry (when *exec_id* is
    known), then the ContextVar scope (closing it clears its registry
    entry too). Closing is release-once and idempotent; a call with no
    discoverable scope is a harmless no-op returning False. Never logs
    secret values.
    """
    found = False
    scoped: "ExecutionSecretScope | None" = None
    lookup_id = exec_id or _exec_id_for("", kwargs or {})
    if lookup_id:
        with _EXEC_SCOPES_LOCK:
            scoped = _EXEC_SCOPES_BY_ID.pop(lookup_id, None)
    if scoped is None:
        scoped = _execution_secret_scope.get()
        if scoped is not None and lookup_id:
            with _EXEC_SCOPES_LOCK:
                _EXEC_SCOPES_BY_ID.pop(lookup_id, None)
    if scoped is not None:
        scoped.close()
        found = True
        # If the published slot still points at exactly this scope, the
        # execution just completed its deferred release: clear the slot so
        # no stale reference can capture another execution's secrets.
        if _execution_secret_scope.get() is scoped:
            _execution_secret_scope.set(None)
    if token is not None:
        try:
            _execution_secret_scope.reset(token)
        except ValueError:  # token from a different context (asyncio)
            pass
    return found


def clear_execution_scopes() -> None:
    """Close EVERY open execution scope (session-end fail-safe).

    Also drains :data:`_PENDING_PATH_RETENTIONS`: every temp-file retention
    still pending belongs to an execution that just ended, so releasing it
    here keeps the scoped refcounts symmetric even when a host tears the
    session down before the per-path cleanup loop ran.
    """
    with _EXEC_SCOPES_LOCK:
        scopes = list(_EXEC_SCOPES_BY_ID.values())
        _EXEC_SCOPES_BY_ID.clear()
    for scope in scopes:
        scope.close()
    cur = _execution_secret_scope.get()
    if cur is not None:
        cur.close()
        _execution_secret_scope.set(None)
    with _PATH_RETENTION_LOCK:
        pending = list(_PENDING_PATH_RETENTIONS.keys())
    for path in pending:
        _release_path_retention(path)

#: Kept for backward-compat with tests/consumers that still import it.
#: VWP-04 does not inject sentinels anymore — unresolved references stay
#: verbatim and rely on the fail-safe `$` shell-variable semantics.
INVALID_SENTINEL = "__VW_PLACEHOLDER_INVALID__"

# Placeholder as it appears in a command string: $__VW_SECRET_<token>__
_VW_SECRET_CMD_RE = re.compile(r"\$__VW_SECRET_([0-9a-f]{12})__")

# terminal-ish arg keys we scan across backends (Local/Docker/SSH/Modal/
# Daytona/Singularity/Vercel Sandbox all pass the command string here).
# v0.2.2: names/keys are overridable via config (terminal_tool_names /
# terminal_command_keys); these are the defaults when config is absent/empty.
_DEFAULT_TERMINAL_TOOLS = {
    "terminal", "shell", "bash", "execute_command",
    "run_command", "exec", "code_execution",
}
_DEFAULT_COMMAND_KEYS = ("command", "cmd", "input", "script", "code")


#: Default stale-file lifetime (seconds) used when no configured
#: ``placeholder_ttl_seconds`` value is supplied to the startup cleanup.
#: Mirrors the config default (config.placeholder_ttl_seconds == 300) so
#: callers that predate TTL wiring keep working unchanged.
_DEFAULT_STALE_TTL_SECONDS = 300


def resolve_secrets_dir_path() -> Path:
    """Resolve (WITHOUT creating or validating) the secrets directory path.

    Prefers ``$XDG_RUNTIME_DIR/vw-secrets`` (typically tmpfs/RAM-backed);
    falls back to ``<tempdir>/vw-secrets-<uid>`` when XDG_RUNTIME_DIR is
    unusable. This is the single source of truth for WHERE the runtime
    placeholder temp files live — both the injection middleware
    (:func:`_secrets_dir`) and plugin load (AUD-03, ``register()``) derive
    the path from here so they can never disagree.
    """
    xdg = os.environ.get("XDG_RUNTIME_DIR", "")
    if xdg and os.path.isdir(xdg) and os.access(xdg, os.W_OK):
        return Path(os.path.join(xdg, "vw-secrets"))
    return Path(tempfile.gettempdir()) / f"vw-secrets-{os.getuid()}"


def _secrets_dir() -> str:
    """Return the dedicated secrets directory, creating it if needed.

    AUD-03 (v0.6.2): hardened through the SHARED validator module
    :func:`vaultwarden.secure_fs.ensure_hardened_directory` — absolute
    path, real directory (never a symlink, checked via ``os.lstat()``),
    owned by the CURRENT EFFECTIVE UID, mode EXACTLY ``0700``. A missing
    directory is created with mode 0700 (umask-forced); an existing but
    INSECURE directory is NEVER silently repaired (no implicit chmod/chown
    any more) — the operator must fix it explicitly.

    Raises:
        FilesystemSecurityError: on ANY validation failure (fail-closed —
        there is no fallback path). ``register()`` treats this as fatal
        and refuses to activate the plugin; the injection middleware
        surfaces it as a sanitized ``PlaceholderError``.
    """
    d = resolve_secrets_dir_path()
    ensure_hardened_directory(d, create_if_missing=True)
    return str(d)


def _cleanup_stale_secrets(ttl_seconds: int | None = None):
    """Remove temp files older than *ttl_seconds*.

    Handles files left behind by a previous SIGKILL/SIGTERM where the
    middleware's finally block did not run. The TTL MUST match the
    configured placeholder registry TTL (``placeholder_ttl_seconds``) —
    any file older than that is stale and should be removed. When the
    caller supplies no value, the config-default lifetime (300s) applies.

    Deletion rule: a regular file whose age
    ``time.time() - os.stat(path).st_mtime`` exceeds *ttl_seconds* is
    deleted. v0.5.8: deletions are OBSERVABLE — a failed unlink emits a
    sanitized WARNING (path + error only, never file contents), so
    operators learn about secret material left on disk instead of the
    failure being swallowed.

    Called at plugin startup (in register()) to ensure stale files are
    cleaned up even if the previous process crashed.

    AUD-03 (v0.6.2) load-time gate: the secrets directory is validated
    FAIL-CLOSED here before the scan runs — ``_secrets_dir()`` raises
    ``FilesystemSecurityError`` for an existing-but-insecure directory
    (symlink / wrong owner / mode != 0700) and the error PROPAGATES to
    register(), which refuses to activate the plugin. A merely-missing
    directory is created hardened (0700). Only after validation passes does
    the best-effort scan run; transient SCAN errors stay best-effort
    (sanitized warnings) because attempting removal of leftover secret
    files is always safe and never reads secret VALUES.
    """
    if ttl_seconds is None or ttl_seconds <= 0:
        ttl_seconds = _DEFAULT_STALE_TTL_SECONDS
    # Fail-closed load-time validation (AUD-03): do NOT catch
    # FilesystemSecurityError / OSError here — an insecure secrets
    # directory must abort plugin activation, not skip cleanup silently.
    secrets_dir = _secrets_dir()

    if not os.path.isdir(secrets_dir):
        return

    now = time.time()
    for entry in os.scandir(secrets_dir):
        try:
            if entry.is_file() and (now - entry.stat().st_mtime) > ttl_seconds:
                try:
                    os.unlink(entry.path)
                    log.info("cleaned stale secret file: %s", entry.name)
                except OSError as exc:
                    # Sanitized: path is safe (vw_<token>_XXXXXX filename);
                    # NEVER read or log the file contents.
                    log.warning("Failed to remove stale secret file %s: %s",
                                entry.path, exc)
        except OSError:
            pass  # best-effort cleanup (stat/race failures are transient)


def _cleanup_stale_sockets():
    """Remove stale ssh-agent sockets at plugin startup (VWP-02, v0.4.6).

    A socket is stale if the file exists but no agent is running on it.
    Checks both $VW_SSH_SOCKET_PATH and $XDG_RUNTIME_DIR/auth.sock — the
    two developer-controlled socket locations used by
    tools._resolve_socket_path(). Called from register() next to
    _cleanup_stale_secrets().
    """
    def _is_stale(sock: str) -> bool:
        if not os.path.exists(sock):
            return False
        try:
            r = subprocess.run(["ssh-add", "-l"],
                               env={"SSH_AUTH_SOCK": sock,
                                    "PATH": os.environ.get("PATH", "")},
                               capture_output=True, text=True, timeout=5)
            return r.returncode not in (0, 1)  # agent not running
        except Exception:
            return True  # cannot determine, treat as stale

    candidates = []
    vw_sock = os.environ.get("VW_SSH_SOCKET_PATH", "").strip()
    if vw_sock:
        candidates.append(os.path.abspath(vw_sock))
    xdg = os.environ.get("XDG_RUNTIME_DIR", "")
    if xdg:
        candidates.append(os.path.join(xdg, "auth.sock"))

    for sock in candidates:
        if _is_stale(sock):
            try:
                os.unlink(sock)
                log.info("cleaned stale ssh socket: %s", sock)
            except OSError:
                pass


def _write_secret_file(token: str, value: str, secrets_dir: str,
                       temp_files: list[str]) -> str:
    """Write *value* to a fresh mkstemp file (chmod 600, atomic, symlink-
    protected) inside *secrets_dir*; register it for finally-block cleanup.

    SEC-02 (v0.5.7): extracted from the old ``_inject_one`` helper so the
    atomic resolve loop can call it exactly once per unique token.

    Returns the temp-file path. The ``$__VW_SECRET_<token>__`` reference
    body itself is already known to (and safe to log for) every caller, so
    no extra token plumbing is needed to correlate a file with its
    placeholder.
    """
    fd, path = tempfile.mkstemp(dir=secrets_dir, prefix=f"vw_{token}_")
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, value.encode("utf-8"))
    finally:
        os.close(fd)
    temp_files.append(path)
    return path


#: AUD-02 (v0.6.5): resolved temp-file path -> (retention kind, plaintext,
#: owning execution id), where kind is "process" (fallback process baseline
#: taken when NO execution scope was active at resolve time) or "path-ref"
#: (an EXTRA execution-scoped reference taken alongside the scope's own
#: deduplicated primary reference, so a LATE attributable post_tool_call
#: can still redact exact plaintexts from a result even after the
#: middleware's finally block already deleted the temp files and restored
#: the SEC-01 handoff stores).
#: :func:`_resolve_placeholder_token` records the entries; the middleware
#: cleanup loop drops EXACTLY ONE matching reference per resolved temp file
#: once the file has been removed — i.e. after next_call returned AND the
#: authoritative transform_tool_result pass consumed every handoff channel
#: it can reach while the middleware frame is still alive (Hermes dispatch
#: order: middleware wraps next_call; transform runs on the returned result
#: BEFORE the middleware frame unwinds; post_tool_call observes last).
#: A "path-ref" is owned by the ENTRY ITSELF, not by the scope bookkeeping:
#: :meth:`ExecutionSecretScope.close` never re-touches it and
#: :meth:`ExecutionSecretScope.release_value` refuses to drop below the
#: number of path references still outstanding for that value, so neither
#: double-release nor premature removal can occur — an overlapping
#: execution sharing the same secret keeps its OWN primary + path
#: references untouched. When the LAST holder releases, the value leaves
#: the redaction state. Thread-safe; entries are popped on release so
#: nothing accumulates across executions. NEVER logged — values stay in
#: memory only.
_PENDING_PATH_RETENTIONS: dict[str, tuple[str, str, str]] = {}
_PATH_RETENTION_LOCK = threading.Lock()


def _release_path_retention(path: str, exec_id: str = "") -> None:
    """Release the AUD-02 retention attached to one resolved temp file.

    Sanitized diagnostics only (temp filename + error class); never the
    value. Missing entries are a harmless no-op (e.g. legacy/direct callers
    that built their own cleanup loop).

    Ownership rules per retention kind:

    - ``("path-ref", value, owner_exec_id)`` — an EXTRA execution-scoped
      reference taken by :func:`_resolve_placeholder_token` alongside the
      owning scope's deduplicated primary reference. The ENTRY owns this
      single reference: releasing it goes straight through
      :meth:`RedactingFilter.release_secret` (one decrement), symmetric to
      how it was taken. ``scope.release_value`` deliberately does NOT drop
      path-owned references (it floors at the outstanding path-ref count),
      so close() and this release can never double-decrement the same
      reference; every other holder (an overlapping execution's primary or
      path reference, a process baseline) keeps the value redactable until
      its OWN release.
    - ``("process", value, "")`` — fallback process baseline taken when NO
      execution scope was published at resolve time; dropped symmetrically
      here via :meth:`release_process_scoped_secret`. (If the same value is
      ALSO a genuine process-scoped secret, its own baseline count keeps it
      redactable.)
    """
    with _PATH_RETENTION_LOCK:
        entry = _PENDING_PATH_RETENTIONS.pop(path, None)
    if entry is None:
        return
    kind, value, owner_id = entry[0], entry[1], entry[2]
    try:
        redactor = get_redacting_filter()
        if kind == "path-ref":
            # Drop precisely the ONE extra execution reference this temp
            # file's resolution took. Refcount protection still guards any
            # other live holder (overlapping executions, baselines) — the
            # value leaves the redaction state only when the LAST holder
            # releases. Never logs the value.
            redactor.release_secret(value)
        else:
            # Fallback process baseline taken when NO execution scope was
            # published at resolve time: drop precisely that one baseline
            # reference now that the temp file carrying the plaintext is
            # gone. (If the same value is ALSO a genuine process-scoped
            # secret, its own baseline count keeps it redactable.)
            redactor.release_process_scoped_secret(value)
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("AUD-02: retention release failed for temp file %s (%s)",
                    os.path.basename(path), type(exc).__name__)


def _resolve_placeholder_token(six_hex: str, auth: AuthManager,
                               registry: PlaceholderRegistry, secrets_dir: str,
                               temp_files: list[str], task_id: str = "",
                               injected_values_out: list[str] | None = None,
                               task_errors: list[dict] | None = None,
                               exec_id: str = "",
                               scoped_retained_out: list[str] | None = None,
                               ) -> str | None:
    """SEC-02 (v0.5.7): atomically consume one unique token and create its
    single temp file; return the file path or ``None`` (fail-safe).

    ``six_hex`` is the 12-hex-character body of a ``$__VW_SECRET_<body>__``
    command reference. The middleware calls this EXACTLY ONCE per unique
    token per command execution — every occurrence of the same placeholder
    in the command string maps onto the same returned path via a global
    ``str.replace``.

    Atomic consumption: :meth:`PlaceholderRegistry.consume_and_resolve`
    marks the entry used BEFORE returning it, so a replayed/expired/unknown
    token yields ``None`` here without ever touching the vault. On ``None``
    we log a warning, record a PLACEHOLDER_ERROR for post_tool_call to
    surface, and leave the reference verbatim (the leading ``$`` makes it a
    valid shell variable that expands to an empty string — fail-safe).

    The real secret is ONLY ever written to the returned temp file — never
    into the command string. SEC-01 (v0.5.4): when *injected_values_out* is
    provided the plaintext is collected there LOCALLY (inside the middleware
    frame); the middleware publishes the exact set into the ContextVar
    handoff channel immediately before next_call and restores it in its
    finally block. record_task_secret still keeps the task-keyed dict
    fallback in sync for hosts that dispatch hooks on a different
    context/thread.
    """
    placeholder = f"__VW_SECRET_{six_hex}__"   # registry form (no $)
    entry = registry.consume_and_resolve(placeholder)
    if entry is None:
        err = errors.PlaceholderError(
            f"Placeholder '{placeholder}' cannot be resolved "
            "(unknown, expired, or already used - single-use policy).",
            suggestion="Request a fresh one via vaultwarden_get_secret_ref.")
        log.warning("Placeholder %s: %s", placeholder, err.message)
        if task_errors is not None:
            task_errors.append(err.to_dict())
        else:
            with _PENDING_LOCK:
                _PENDING_ERRORS.setdefault(task_id or "", []).append(err.to_dict())
        return None  # leave the reference verbatim ($ expands to empty)
    try:
        item = auth.get_item(entry.item_id)
        if entry.field_name.startswith("custom:"):
            value = _field_value(item, "password", entry.field_name.split(":", 1)[1])
        else:
            value = _field_value(item, entry.field_name, None)
        if not value:
            err = errors.PlaceholderError(
                f"Referenced field '{entry.field_name}' is now empty.")
            log.warning("Placeholder %s: %s", placeholder, err.message)
            with _PENDING_LOCK:
                _PENDING_ERRORS.setdefault(task_id or "", []).append(err.to_dict())
            return None
    except errors.VaultwardenError as exc:
        log.error("Secret fetch failed for %s (%s)", placeholder, exc.code)
        with _PENDING_LOCK:
            _PENDING_ERRORS.setdefault(task_id or "", []).append(exc.to_dict())
        return None
    # Write the secret to a mkstemp file (chmod 600, atomic, symlink-protected).
    path = _write_secret_file(six_hex, value, secrets_dir, temp_files)
    # AUD-02 (v0.6.5): retain the plaintext for redaction through the ACTIVE
    # EXECUTION SCOPE (reference-counted) instead of unbounded global
    # registration. The scope releases the reference once the execution has
    # passed every lifecycle point that may still need redaction
    # (transform_tool_result + post_tool_call observer). If no scope is active
    # (legacy/direct callers), fall back to process-scoped retention so the
    # value stays redactable  a runtime secret must never go unredacted.
    scope = current_execution_scope()
    redactor = get_redacting_filter()
    if scope is not None:
        # Execution-scoped retention, ONE deduplicated PRIMARY reference
        # per (scope, value): the scope's retain() collapses identical
        # values inside one execution, and the symmetric close()-time
        # release drops exactly that one primary reference when the
        # execution reaches its safe final lifecycle point
        # (post_tool_call -- AFTER transform_tool_result authoritative
        # redaction and observer cleanup consumed the plaintexts).
        # Overlapping executions sharing this secret each hold their own
        # reference in the shared refcount, so no owner's close can remove
        # the value while another active execution still needs it.
        scope.retain(value)
        # AUD-02 (v0.6.5): take ONE EXTRA execution reference PER RESOLVED
        # TEMP FILE, owned by the _PENDING_PATH_RETENTIONS entry itself --
        # released symmetrically by _release_path_retention once the file
        # carrying the plaintext is removed. This guarantees coverage for
        # every later consumer even on hosts where the middleware finally
        # block unwinds BEFORE transform_tool_result runs (the deferred
        # post_tool_call close may then never find an open scope): the
        # value leaves the redaction state only when the LAST holder --
        # primary reference, path reference, overlapping execution or
        # process baseline -- releases. The scope records the count via
        # retain_path_reference() so its fail-safe release paths can never
        # double-decrement an entry-owned reference. NOTE: the plaintext is
        # deliberately NOT mirrored into the task-keyed injected store --
        # the middleware finally block consumes that store before
        # transform_tool_result runs on async hosts; the transformer reads
        # the still-open scope directly instead (see make_result_redactor).
        redactor.retain_secret(value)
        scope.retain_path_reference(value)
        with _PATH_RETENTION_LOCK:
            _PENDING_PATH_RETENTIONS[path] = ("path-ref", value, exec_id)
        # AUD-02 (v0.6.5): report the scoped retention back to the calling
        # middleware execution so its fail-safe closure can release exactly
        # this reference if no later lifecycle point runs.
        if scoped_retained_out is not None:
            scoped_retained_out.append(value)
    else:
        # No active execution scope (legacy/direct callers): fall back to
        # PROCESS-scoped retention so the value stays redactable; the
        # symmetric baseline release happens in the middleware finally after
        # temp-file cleanup.
        redactor.register_process_scoped_secret(value)
        _PENDING_PATH_RETENTIONS[path] = ("process", value, "")
    # v0.1.4 (FAIL-6): also record the plaintext per-task so the redaction
    # layer can scrub it from this specific tool call's output even when the
    # global filter state was reset by another component in between.
    # SEC-01 (v0.5.4): the consumer is now the authoritative
    # transform_tool_result redactor (make_result_redactor). When called from
    # the middleware, *injected_values_out* collects the plaintext locally;
    # the middleware publishes/restores the ContextVar handoff around
    # next_call itself. Without that channel (legacy callers) fall back to
    # record_task_secret, which keeps both stores in sync.
    if injected_values_out is not None:
        injected_values_out.append(value)
        with _INJECTED_LOCK:
            _INJECTED_SECRETS.setdefault(task_id or "", []).append(value)
    else:
        record_task_secret(task_id, value)
    return path


def make_placeholder_resolver(auth: AuthManager,
                              registry: PlaceholderRegistry,
                              config: Any = None) -> Callable[..., Any]:
    """Build the `tool_execution` middleware callback (VWP-04 file injection).

    Signature follows Hermes's tool_execution contract:
    ``(tool_name, args, original_args, next_call, **kwargs)`` — the callback
    WRAPS the actual tool invocation and calls ``next_call(modified_args)``,
    which lets us delete the temp secret files in a guaranteed ``finally``.
    """

    terminal_tools = set(getattr(config, "terminal_tool_names", None) or _DEFAULT_TERMINAL_TOOLS)
    command_keys = tuple(getattr(config, "terminal_command_keys", None) or _DEFAULT_COMMAND_KEYS)

    def vaultwarden_inject_secrets(tool_name: str = "", args: dict | None = None,
                                   original_args: dict | None = None,
                                   next_call: Callable[..., Any] | None = None,
                                   task_id: str = "",
                                   **kwargs: Any) -> Any:
        # --- chain safety gates -------------------------------------------
        if tool_name not in terminal_tools:
            if next_call is not None:
                return next_call(args)
            return None
        if not isinstance(args, dict):
            if next_call is not None:
                return next_call(args)
            return None
        # Every command key holding a $__VW_SECRET_ reference gets injected.
        targets = [k for k in command_keys
                   if isinstance(args.get(k), str) and "$__VW_SECRET_" in args[k]]
        if not targets:
            # nothing to do — DO NOT touch other plugins' args
            if next_call is not None:
                return next_call(args)
            return None

        if next_call is None:
            # Legacy tool_request-style probe (no wrapper available): report
            # whether injection WOULD happen, without consuming anything.
            return {"args": args}

        # SEC-02 (v0.5.7) atomic resolution: every UNIQUE $__VW_SECRET_ token
        # is consumed exactly once per command execution — consumption and
        # entry retrieval happen atomically inside consume_and_resolve(), so
        # there is no sequential first-occurrence-consumes / second-occurrence
        # -fails window anymore. Each resolved token gets ONE temp file, and
        # ALL occurrences of that token are then globally replaced with the
        # same `$(< path)` reference. Unresolvable tokens (unknown / expired /
        # already-used, e.g. a replay across two tool calls) stay EXACTLY as
        # they were: the leading `$` makes them valid shell variable
        # references that expand to an empty string (fail-safe), a warning is
        # logged and a PLACEHOLDER_ERROR is recorded for post_tool_call to
        # surface to the agent.
        with _PENDING_LOCK:
            task_errors = _PENDING_ERRORS.setdefault(task_id or "", [])
        try:
            secrets_dir = _secrets_dir()
        except FilesystemSecurityError as exc:
            # AUD-03 (v0.6.2) fail-closed injection gate: the hardened
            # secrets-dir validation now also runs at plugin LOAD, so this
            # path only triggers when the directory became insecure AFTER
            # activation (e.g. an operator chmod/chown mid-session). NEVER
            # write secret material into an unsafe directory and NEVER fall
            # back to another path: every token in this command stays
            # verbatim ($__VW_SECRET_x__ expands to an empty string in the
            # shell — fail-safe, no leak, the command simply fails on the
            # empty value). The sanitized reason (PATH + error class only,
            # never secret values) is recorded for post_tool_call to
            # surface to the agent.
            log.error("fail-closed: secrets directory rejected by "
                      "hardening validation (%s); placeholders left "
                      "unresolved for %s", exc, tool_name)
            task_errors.append(
                errors.PlaceholderError(
                    "Secrets directory failed filesystem hardening "
                    "validation; injection blocked (fail-closed).").to_dict())
            return next_call(args)
        temp_files: list[str] = []
        #: AUD-02 (v0.6.5): plaintexts retained THROUGH this execution's
        #: scope, one entry per resolved token occurrence. The fail-safe
        #: closure below releases exactly these references when the
        #: execution cannot be attributed to a lifecycle id (or dies on an
        #: exceptional path); scoped retains deliberately have NO
        #: _PENDING_PATH_RETENTIONS entry so temp-file cleanup alone can
        #: never strip redaction coverage before transform_tool_result ran.
        scoped_retained: list[str] = []
        injected_values: list[str] = []
        new_args = dict(args)
        resolved_any = False
        # AUD-02 (v0.6.5): ONE execution scope per tool execution. Opened
        # here (after the no-op gates so non-injection calls never touch the
        # registry); every placeholder resolved below is retained THROUGH this
        # scope, reference-counted in the shared redactor. The scope is closed
        # at the safe final lifecycle point  post_tool_call (deferred release,
        # after transform_tool_result and observer cleanup have run), with the
        # finally block below as the FAIL-SAFE for exceptional paths where no
        # later hook will execute. close() is release-once: double-close is a
        # silent no-op and overlapping executions sharing a secret can never
        # cause premature removal.
        exec_id = _exec_id_for(task_id, kwargs)
        scope, cv_scope_token = open_execution_scope(exec_id)
        try:
            for key in targets:
                command = new_args[key]
                # 1. Extract unique token bodies (first-seen order preserved).
                unique_suffixes = list(dict.fromkeys(
                    m.group(1) for m in _VW_SECRET_CMD_RE.finditer(command)))
                if not unique_suffixes:
                    continue
                # 2. Atomic resolution loop: one consume + one temp file each.
                replacements: dict[str, str] = {}
                for suffix in unique_suffixes:
                    path = _resolve_placeholder_token(
                        suffix, auth, registry, secrets_dir, temp_files,
                        task_id, injected_values, task_errors, exec_id,
                        scoped_retained_out=scoped_retained)
                    if path is None:
                        continue  # unknown/expired/used -> leave verbatim
                    replacements[f"$__VW_SECRET_{suffix}__"] = f"$(< {path})"
                # 3. Global replacement: ALL occurrences map to the same file.
                new_command = command
                for ref, sub in replacements.items():
                    new_command = new_command.replace(ref, sub)
                if new_command != command:
                    new_args[key] = new_command
                    resolved_any = True
            if not resolved_any:
                return next_call(args)
            log.debug("Injected %d secret temp file(s) for %s.",
                      len(temp_files), tool_name)
            # SEC-01 (v0.5.4) handoff: publish the exact plaintext set that is
            # about to enter the shell into the ContextVar IMMEDIATELY BEFORE
            # the tool runs, so the authoritative transform_tool_result
            # redactor can scrub echoes of it from the result. The finally
            # block below restores the previous context value — no secret
            # values persist across turns.
            cv_token = _publish_injected_secrets(injected_values)
            try:
                # SEC-01 (v0.5.4): the authoritative confidentiality boundary
                # is the Hermes `transform_tool_result` hook
                # (make_result_redactor), which consumes the ContextVar /
                # task-store handoff established here. The middleware itself
                # only injects and hands off — it never mutates the result
                # for confidentiality reasons.
                #
                # IMPORTANT: bind the result to a name and return THAT exact
                # object (never call next_call twice). Hermes dispatches
                # transform_tool_result on the object returned from tool
                # execution; a second invocation would hand the redactor a
                # different instance than the one the shell actually ran.
                result = next_call(new_args)
                return result
            finally:
                _restore_injected_secrets(cv_token)
        finally:
            # Cleanup temp files — MUST run even if the command fails/times
            # out. v0.5.8 OBSERVABLE CLEANUP: a failed deletion is logged as
            # a sanitized WARNING (path + error only). The path itself is
            # safe to log (vw_<token>_XXXXXX filename); the file CONTENTS
            # (the resolved secret) are NEVER read or logged. Swallowing the
            # failure silently would hide leftover secret material on disk.
            for path in temp_files:
                try:
                    os.unlink(path)
                except OSError as exc:
                    log.warning("Failed to remove temp file %s: %s", path, exc)
                # AUD-02 (v0.6.5): release the PROCESS-FALLBACK baseline
                # retention attached to this resolved temp file (legacy /
                # direct callers with no active scope). Execution-scoped
                # retains have NO entry here: their single reference is
                # owned by the scope and released at its close() -- the
                # deferred safe final lifecycle point, never before
                # transform_tool_result has run.
                _release_path_retention(path, exec_id)
            # SEC-01 (v0.5.4): forget this execution's per-task plaintext set
            # too (the ContextVar was already restored above). The middleware
            # is the single OWNER that forgets injected values — neither the
            # transformer nor the observer pops them.
            take_task_secrets(task_id)
        # AUD-02 (v0.6.5) FAIL-SAFE scope closure: when this execution can be
        # attributed to a task/execution id, post_tool_call is the SAFE FINAL
        # lifecycle point and closes the scope THERE -- after
        # transform_tool_result and observer cleanup have consumed the
        # plaintexts for redaction. Here we only reset the ContextVar so no
        # scope reference leaks into other contexts; the scope object stays
        # open for the deferred release. When NO id is available the observer
        # cannot attribute the call to this scope, so this finally block IS
        # the guaranteed release point (fail-safe for exceptional paths where
        # no later lifecycle hook will run). close() is release-once: double
        # release can never occur and secrets can never leak across turns.
        if not exec_id:
            # No attributable id: this finally block IS the guaranteed
            # release point -- close now and clear the published slot.
            # AUD-02 fail-safe for the EXCEPTIONAL path: when next_call
            # raised, the code after the try/finally above never runs, so
            # release every plaintext this execution retained through its
            # scope HERE (release_value is silent no-op for values already
            # handed back; process-fallback entries were released by the
            # _release_path_retention loop above). On the normal path this
            # is symmetric with -- and consumed by -- the immediate close()
            # below, which then finds nothing outstanding left to release.
            for _value in scoped_retained:
                scope.release_value(_value)
            close_execution_scope(cv_scope_token, exec_id)
            _clear_execution_scope_slot()
        elif scoped_retained:
            # Attributable id but the middleware frame is unwinding via an
            # exception (or a sync host that shares one context across the
            # whole call stack, where the ContextVar token cannot be reset):
            # no later lifecycle hook may reliably run for this call, so the
            # scope's own references must not strand. Release precisely this
            # execution's outstanding references through the id-keyed registry
            # entry -- close() is release-once and decrements EXACTLY the
            # references this scope retained, so overlapping executions
            # sharing the same secret keep their own coverage and a late
            # post_tool_call close for the same id is a harmless no-op.
            # On the NORMAL path this branch never runs: the scope stays open
            # for the deferred release at post_tool_call (after
            # transform_tool_result consumed the plaintexts). Never logs
            # secret values.
            if sys.exc_info()[0] is not None:
                closed = close_execution_scope(None, exec_id)
                if not closed:  # pragma: no cover - defensive fallback
                    for _value in scoped_retained:
                        scope.release_value(_value)

    return vaultwarden_inject_secrets


#: transient error store surfaced by post_tool_call then cleared.
#: v0.2.2 (BUGFIX): task-scoped dict + lock — parallel tool calls can no
#: longer lose (or steal) each other's pending errors via a shared list.
_PENDING_ERRORS: dict[str, list[dict]] = {}
_PENDING_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Per-task injected-secret store (v0.1.4, FAIL-6) + SEC-01 ContextVar handoff
# (v0.5.4).
#
# When the middleware resolves a placeholder it knows the plaintext secret
# value that is about to enter the shell. We keep that value ONLY for the
# duration of the tool call (keyed by task_id) so the redaction layer can
# scrub it out of whatever the command echoed back — without ever registering
# vault item values in the global RedactingFilter (which would redact them
# from unrelated text forever and could collide with benign strings).
# The store is short-lived, memory-only and never logged.
#
# SEC-01 (v0.5.4): the authoritative confidentiality boundary is the
# `transform_tool_result` hook (see make_result_redactor), NOT the
# post_tool_call observer. Hermes does not guarantee that the transformer
# runs on the same OS thread as the middleware, so the per-execution
# plaintext set is handed off via a contextvars.ContextVar (the secure
# handoff channel — secrets are never passed as function arguments through
# Hermes internals). The ContextVar covers the asyncio/current-context case;
# the task-keyed dict below stays as belt-and-braces fallback for hosts that
# dispatch hooks on a different context or thread. Both stores are cleared
# in the middleware's finally block so no secret values persist across turns.
_INJECTED_SECRETS: dict[str, list[str]] = {}
_INJECTED_LOCK = threading.Lock()

_CURRENT_INJECTED_SECRETS: contextvars.ContextVar[frozenset[str] | None] = \
    contextvars.ContextVar("vaultwarden_injected_secrets", default=None)


def record_task_secret(task_id: str, value: str) -> None:
    if not value:
        return
    with _INJECTED_LOCK:
        _INJECTED_SECRETS.setdefault(task_id or "", []).append(value)
    # SEC-01 handoff: also publish into the ContextVar so the
    # transform_tool_result redactor sees the exact set injected for the
    # current execution, even when no task id is threaded through Hermes.
    cur = _CURRENT_INJECTED_SECRETS.get() or frozenset()
    _CURRENT_INJECTED_SECRETS.set(cur | {value})


def _publish_injected_secrets(values: list[str]) -> contextvars.Token:
    """SEC-01 (v0.5.4): publish the per-execution injected-secret set into
    the ContextVar handoff channel IMMEDIATELY BEFORE the tool runs.

    Returns the ContextVar token so the caller can restore the PREVIOUS
    context value in its ``finally`` block via
    :func:`_restore_injected_secrets`. Restoring by token (instead of
    blanket-clearing) keeps the store correctly nested when middlewares or
    tools run concurrently inside one event loop, while guaranteeing that
    plaintext values NEVER outlive the tool execution they belong to.
    """
    return _CURRENT_INJECTED_SECRETS.set(frozenset(v for v in values if v))


def _restore_injected_secrets(token: "contextvars.Token[frozenset[str] | None]") -> None:
    """Restore the previous injected-secrets context (middleware finally)."""
    try:
        _CURRENT_INJECTED_SECRETS.reset(token)
    except ValueError:  # pragma: no cover - token from a different context
        _CURRENT_INJECTED_SECRETS.set(None)


def take_task_secrets(task_id: str) -> list[str]:
    """Pop (and thereby forget) all pending secret values for *task_id*."""
    with _INJECTED_LOCK:
        return _INJECTED_SECRETS.pop(task_id or "", [])


def peek_task_secrets(task_id: str) -> list[str]:
    """Return (without forgetting) the pending secret values for *task_id*.

    Used by the SEC-01 `transform_tool_result` redactor: unlike the old
    post_tool_call path it must NOT pop, because both the transformer and
    the cleanup observer may run for the same task_id and the transformer
    may be invoked more than once. The middleware's finally block (and the
    session-end hook) remain the single owners that forget these values.
    """
    with _INJECTED_LOCK:
        return list(_INJECTED_SECRETS.get(task_id or "", []))


def clear_task_secrets() -> None:
    """Drop every pending secret (used on session end / registry clear)."""
    with _INJECTED_LOCK:
        _INJECTED_SECRETS.clear()
    # SEC-01: never let plaintext linger in the current context either.
    _CURRENT_INJECTED_SECRETS.set(None)


def _redact_in_result(result: Any) -> Any:
    """Scrub globally registered secret values out of a tool result object.

    v0.1.4 (FAIL-6): the shared RedactingFilter only knows bootstrap secrets,
    session keys and explicitly tracked write payloads — vault-stored item
    fields are deliberately NOT registered globally (they could collide with
    unrelated text). SEC-01 (v0.5.4): this global pass now runs inside the
    authoritative `transform_tool_result` redactor (see
    ``make_result_redactor``); the per-task injected values are scrubbed by
    ``_redact_task_secrets`` from the same place. The post_tool_call observer
    no longer performs any confidentiality mutation.
    """
    redactor = get_redacting_filter()
    if isinstance(result, str):
        return redactor.redact(result)
    if isinstance(result, dict):
        return {k: (_redact_in_result(v) if not isinstance(v, (int, float, bool)) else v)
                for k, v in result.items()}
    if isinstance(result, list):
        return [_redact_in_result(v) for v in result]
    if hasattr(result, "output") and isinstance(getattr(result, "output"), str):
        try:
            setattr(result, "output", redactor.redact(result.output))
        except Exception:  # pragma: no cover - immutable result objects
            pass
    return result


def _redact_task_secrets(task_id: str, result: Any,
                         values: list[str] | None = None) -> Any:
    """Remove freshly injected placeholder secrets from *result*.

    SEC-01 (v0.5.4): refactored from "pop the per-task store" to a helper
    that redacts an EXPLICIT set of plaintext values (exact replacement with
    ``[REDACTED]``), called from the authoritative `transform_tool_result`
    redactor. When *values* is None it falls back to peeking the task-keyed
    store (never popping — the middleware's finally block owns forgetting).
    Containers (dict / list / MutableMapping / writable ``.output`` objects)
    are scrubbed in place; a plain ``str`` result cannot be mutated, so the
    sanitized copy is RETURNED (the transformer returns it — that return
    value is what reaches the model). Pure in-memory string replacement:
    no I/O, no subprocesses, no network.
    """
    if values is None:
        values = peek_task_secrets(task_id)
    if not values:
        return result
    if isinstance(result, str):
        text = result
        for v in values:
            text = text.replace(v, "[REDACTED]")
        return text

    def _scrub(obj: Any) -> Any:
        if isinstance(obj, str):
            for v in values:
                obj = obj.replace(v, "[REDACTED]")
            return obj
        if isinstance(obj, dict):
            for k in list(obj):
                val = obj[k]
                if isinstance(val, (str, dict, list)):
                    obj[k] = _scrub(val)
            return obj
        if isinstance(obj, list):
            for i, val in enumerate(obj):
                if isinstance(val, (str, dict, list)):
                    obj[i] = _scrub(val)
            return obj
        return obj

    scrubbed = _scrub(result)
    if isinstance(result, dict) and isinstance(scrubbed, dict):
        # BUGFIX (v0.4.4): only merge back when _scrub actually produced a NEW
        # container. When no key holds a str/dict/list value (e.g. a plain
        # {"output": "..."} result), _scrub returns the SAME object — calling
        # result.clear()/update(result) on it would wipe the dict entirely.
        if scrubbed is not result:
            result.clear()
            result.update(scrubbed)
    elif scrubbed is not result and isinstance(result, MutableMapping):  # pragma: no cover
        result.clear()
        result.update(scrubbed)
    if hasattr(result, "output") and isinstance(getattr(result, "output"), str):
        out = result.output
        for v in values:
            out = out.replace(v, "[REDACTED]")
        try:
            result.output = out
        except Exception:  # pragma: no cover - immutable result objects
            pass
    return result


def make_result_redactor(auth: AuthManager,
                         registry: PlaceholderRegistry,
                         config: Any = None) -> Callable[..., Any]:
    """Build the `transform_tool_result` transformer for ctx.register_hook.

    SEC-01 (v0.5.4, HIGH): this is the AUTHORITATIVE confidentiality
    boundary. Hermes documents `transform_tool_result` as the hook whose
    return value REPLACES the tool result before it reaches the model —
    unlike `post_tool_call`, which is an observer-only hook and provides no
    such guarantee. The redaction previously done in the observer lives here
    now.

    The returned callable:
    1. follows the standard Hermes transformer signature
       ``(tool_name, result, task_id/turn_id, **kwargs)``;
    2. reads the per-execution injected-secret set from the ContextVar
       established by the tool_execution middleware (`_CURRENT_INJECTED_SECRETS`
       via record_task_secret), with the task-keyed store as fallback when
       Hermes dispatches the hook on a different context/thread;
    3. performs exact, recursive plaintext replacement of every injected
       secret value with the literal ``[REDACTED]`` on str / dict / list
       results and objects exposing a writable ``.output`` attribute;
    4. applies the global RedactingFilter pass (bootstrap secrets, session
       keys, tracked write payloads) to the same result;
    5. RETURNS the sanitized result — that return value is what the model
       observes. If the handoff stores are empty for this execution the
       result still passes through the global filter and is otherwise
       returned unchanged.

    Purely in-memory string replacement: no network calls, no subprocesses,
    no disk I/O.
    """

    def _scrub_str(text: str, values: list[str]) -> str:
        # Exact plaintext replacement first (per-execution injected set)...
        for v in values:
            text = text.replace(v, "[REDACTED]")
        # ...then the GLOBAL RedactingFilter pass (bootstrap secrets,
        # session keys, tracked write payloads). Both entry points share
        # this single helper — no duplicate redaction logic (SEC-01).
        return get_redacting_filter().redact(text)

    def _transform(obj: Any, values: list[str]) -> Any:
        """Recursively rebuild str/dict/list containers with scrubbed leaves."""
        if isinstance(obj, str):
            return _scrub_str(obj, values)
        if isinstance(obj, dict):
            out: dict[Any, Any] = {}
            for k, v in obj.items():
                # Non-string scalars cannot contain plaintext secrets —
                # leave them untouched (matches the historical behaviour).
                out[k] = (_transform(v, values)
                          if not isinstance(v, (int, float, bool)) else v)
            return out
        if isinstance(obj, list):
            return [_transform(v, values) for v in obj]
        return obj

    def vaultwarden_transform_tool_result(tool_name: str = "", result: Any = None,
                                          task_id: str = "", turn_id: str = "",
                                          **kwargs: Any) -> Any:
        # Hermes may key the execution by task_id or turn_id depending on
        # version/backend — accept both, prefer task_id.
        exec_id = task_id or kwargs.get("task_id") or turn_id \
            or kwargs.get("turn_id") or ""
        # 1) per-execution injected secrets (SEC-01 handoff). ContextVar is
        #    the primary channel; the task-keyed dict covers cross-context /
        #    cross-thread dispatch. Never pop here — the middleware's finally
        #    block owns forgetting the values.
        cv_values = _CURRENT_INJECTED_SECRETS.get()
        values = list(cv_values) if cv_values else peek_task_secrets(exec_id)
        # AUD-02 (v0.6.5): belt-and-braces — when both handoff stores are
        # blind for this dispatch (cross-context/thread host), the still-
        # OPEN execution scope itself knows exactly which plaintexts it
        # retains. A closed scope contributes nothing, so this can never
        # re-introduce stale values after release.
        if not values:
            scoped = _execution_secret_scope.get()
            if scoped is None and exec_id:
                with _EXEC_SCOPES_LOCK:
                    scoped = _EXEC_SCOPES_BY_ID.get(exec_id)
            if scoped is not None:
                values = scoped.retained_values()
        # 2) exact plaintext replacement of every injected value with the
        #    literal [REDACTED] (shared building block; in-place for
        #    containers / writable .output objects, returned copy for plain
        #    str results).
        if values:
            result = _redact_task_secrets(exec_id, result, values=values)
        # 3) global RedactingFilter pass (bootstrap secrets, session keys,
        #    tracked write payloads) — replaces the global redaction
        #    previously done in post_tool_call. String results produce a NEW
        #    scrubbed string; dict/list results are rebuilt/merged in place;
        #    other shapes pass through unchanged unless they carry a
        #    writable .output.
        scrubbed = _redact_in_result(result)
        # 4) THE authoritative part: whatever we RETURN becomes the result
        #    delivered to the conversation/model context.
        if isinstance(scrubbed, str) and isinstance(result, (dict, list)):
            # The global filter found secret material inside a container's
            # string leaves — rewrite every leaf through the same shared
            # string-scrubbing path so the returned container is clean too.
            fixed = _transform(result, [])
            if isinstance(result, MutableMapping) and isinstance(fixed, dict):
                result.clear()
                result.update(fixed)
                return result
            return fixed
        if isinstance(result, MutableMapping) and isinstance(scrubbed, dict) \
                and scrubbed is not result:
            result.clear()
            result.update(scrubbed)
            return result
        return scrubbed

    return vaultwarden_transform_tool_result


def make_post_cleanup_hook(auth: AuthManager,
                           registry: PlaceholderRegistry,
                           config: Any = None) -> Callable[..., None]:
    """Build the `post_tool_call` observer for ctx.register_hook.

    SEC-01 (v0.5.4): redaction moved to transform_tool_result. This
    hook is now observer-only for cleanup/metrics and must not mutate the
    result for confidentiality reasons.
    """

    terminal_tools = set(getattr(config, "terminal_tool_names", None) or _DEFAULT_TERMINAL_TOOLS)

    def vaultwarden_post_cleanup(tool_name: str = "", args: dict | None = None,
                                 result: Any = None, task_id: str = "",
                                 _vw_scope_token: Any = None,
                                 **kwargs: Any) -> None:
        # SEC-01 (v0.5.4): redaction moved to transform_tool_result. This
        # hook is now observer-only for cleanup/metrics and must not mutate
        # the result for confidentiality reasons. Observer duties kept here:
        #   - placeholder bookkeeping (cleanup_used),
        #   - secret-free diagnostic error surfacing,
        #   - debug/metrics logging.
        if tool_name not in terminal_tools:
            return
        n = registry.cleanup_used()
        if n:
            log.debug("post_tool_call cleaned %d used placeholder(s).", n)
        # AUD-02 (v0.6.5): SAFE FINAL LIFECYCLE POINT for execution-scoped
        # secret release. Hermes dispatch order: middleware wraps next_call;
        # transform_tool_result redacts the returned result; post_tool_call
        # observes LAST. Closing the scope here guarantees the authoritative
        # redaction and observer-side sanitized error surfacing already ran
        # while the plaintexts were still retained. When the execution cannot
        # be attributed (no task_id / exec kwarg), leave the scope open: the
        # middleware's finally fail-safe (or on_session_end) closes it  never
        # guess and never release another execution's scope prematurely.
        # The middleware hands its ContextVar token through the dispatch
        # kwargs when the host forwards them; passing it here lets the SAME
        # call perform the deferred release AND the context cleanup. Without
        # the token the scope still closes via the id-keyed registry; the
        # stale published slot is then adopted by the NEXT execution's
        # open (see open_execution_scope) so it can never leak a reference.
        close_execution_scope(_vw_scope_token,
                              exec_id=_exec_id_for(task_id, kwargs))
        # Surface fail-closed resolution errors to the agent (secret-free).
        # v0.2.2 (BUGFIX): pop only THIS task's errors — other in-flight
        # tasks keep their pending errors until their own post_tool_call.
        # NOTE: this is diagnostic telemetry, NOT a confidentiality boundary;
        # the error dicts never contain secret values by construction.
        with _PENDING_LOCK:
            task_errors = _PENDING_ERRORS.pop(task_id or "", [])
        if task_errors and isinstance(result, dict):
            result.setdefault("vaultwarden_placeholder_errors", []).extend(task_errors)
        log.debug("post_tool_call observer finished for %s (errors=%d).",
                  tool_name, len(task_errors))

    return vaultwarden_post_cleanup


def make_session_end_hook(auth: AuthManager,
                          registry: PlaceholderRegistry) -> Callable[..., None]:
    """`on_session_end`: clear session + placeholders, lock vault, keep .bw-data."""

    def vaultwarden_on_session_end(**kwargs: Any) -> None:
        registry.clear()
        # v0.1.5 (FAIL-6 wiring): drop every pending per-task injected secret.
        clear_task_secrets()
        # v0.2.2 (BUGFIX): drop any leftover task-scoped pending errors.
        with _PENDING_LOCK:
            _PENDING_ERRORS.clear()
        # AUD-02 (v0.6.5): close EVERY still-open execution scope as the
        # final fail-safe (e.g. executions whose post_tool_call observer
        # never ran). Process-scoped secrets are untouched by this release.
        clear_execution_scopes()
        auth.shutdown(keep_appdata=True)

    return vaultwarden_on_session_end

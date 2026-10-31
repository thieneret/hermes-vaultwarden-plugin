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

# ---------------------------------------------------------------------------
# AUD-02 (phase 2): execution-scoped secret retention.
#
# Runtime secrets injected during a tool execution are retained on the shared
# RedactingFilter ONLY for the lifetime of that execution scope (Phase-1 API:
# retain_secret / release_secret / register_process_scoped_secret). After the
# execution concludes — at the latest safe lifecycle point, i.e. AFTER the
# authoritative transform_tool_result redaction has run for this execution —
# the scope closes and releases each retained value exactly once.
#
# Overlapping executions sharing the same plaintext never cause premature
# removal: the refcount tracks active holders exactly. Process-scoped secrets
# (bootstrap credentials, session keys, startup-injection values) are pinned
# permanent by the redactor and survive execution-scoped cleanup untouched.
# ---------------------------------------------------------------------------


class ExecutionSecretScope:
    """Reference-counted secret scope for ONE tool execution (AUD-02 phase 2).

    Wraps the Phase-1 redactor refcount API so runtime injected secrets are
    retained only while the owning execution (and its downstream result
    redaction / error surfacing) still needs them.

    Guarantees:
    - ``retain(value)`` registers *value* with the redactor at most ONCE per
      unique value per scope (repeated injection of the same plaintext inside
      one execution does not inflate the refcount);
    - ``close()`` releases every retained value EXACTLY once, is idempotent
      and thread-safe, and never raises — an unknown release on the redactor
      side surfaces only as a sanitized warning there;
    - nothing is ever logged that could expose a secret value.
    """

    def __init__(self, redactor: Any,
                 values: "frozenset[str] | list[str] | None" = None) -> None:
        # AUD-02 (phase 2): the redactor is resolved LAZILY on every use —
        # never cached as an instance attribute. Tests isolate suites by
        # swapping vaultwarden.security._shared_filter after the scope was
        # constructed; a captured reference would retain the stale instance
        # and register secrets into a filter nobody consults any more.
        # Production behaviour is unchanged (the singleton is stable).
        self._default_redactor = redactor
        self._values: set[str] = set(values or ())
        self._closed = False
        self._lock = threading.Lock()
        # AUD-02 (phase 2): the exact plaintext set injected by THIS
        # execution. The authoritative transform_tool_result hook consumes
        # it via peek_scope_injected_secrets() as a ContextVar-independent
        # fallback channel — Hermes hosts may dispatch that hook on a
        # different context/thread than the middleware frame, where the
        # published ContextVar is not visible. This is NOT unbounded global
        # retention: the set lives only for the duration of this scope and
        # is cleared exactly once when close() runs.
        self._injected: frozenset[str] = frozenset(self._values)

    # -------------------------------------------------------- redactor pin
    def _get_redactor(self) -> Any:
        """Resolve the shared RedactingFilter at USE time (never cached).

        Falls back to the constructor-supplied instance only if the module
        import of ``get_redacting_filter`` is unavailable (defensive; tests
        monkeypatch it to a fresh isolated filter and expect the scope to
        follow that swap instead of writing into a stale singleton).
        """
        try:
            return get_redacting_filter()
        except Exception:  # pragma: no cover - defensive
            return self._default_redactor

    # ------------------------------------------------------------- retain
    def retain(self, value: str) -> None:
        """Retain *value* for this execution scope (once per unique value)."""
        if not value:
            return
        with self._lock:
            if self._closed:
                # Fail-safe: a late retain after close must NOT leak an
                # un-releasable reference. Release immediately instead.
                log.warning("ExecutionSecretScope.retain after close; "
                            "value released immediately (len=%d).", len(value))
                new_value = False
            else:
                new_value = value not in self._values
                if new_value:
                    self._values.add(value)
                    # Keep the transform-handoff snapshot in sync (see
                    # __init__): every plaintext retained by this scope is
                    # part of THIS execution's injected set.
                    self._injected = frozenset(self._values)
        if new_value:
            # Outside the scope lock: the redactor holds its own RLock and
            # re-acquiring locks in nested order across modules invites
            # lock-ordering bugs. The +1 happens exactly once per unique
            # value per scope regardless of concurrent duplicate retains.
            self._redactor.retain_secret(value)

    # -------------------------------------------------------------- close
    def close(self) -> None:
        """Release every retained value exactly once. Idempotent."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            values = list(self._values)
            self._values.clear()
            # Drop the transform-handoff snapshot too — after close() no
            # downstream consumer may read plaintext from this scope.
            self._injected = frozenset()
        for value in values:
            # release_secret never raises; unknown releases are sanitized
            # warnings on the redactor side (length fingerprint only).
            self._redactor.release_secret(value)

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def early_release(self, value: str) -> None:
        """Release *value* ahead of close (e.g. temp-file materialisation
        finished and the plaintext is no longer needed mid-execution).

        Removes it from the scope's tracked set so ``close()`` will not
        double-release it. Unknown/never-retained values are ignored without
        touching the redactor.
        """
        if not value:
            return
        with self._lock:
            if value not in self._values:
                return
            self._values.discard(value)
            self._injected = frozenset(self._values)
        self._redactor.release_secret(value)

    def injected_values(self) -> frozenset[str]:
        """Exact plaintext set retained by this scope (transform handoff).

        AUD-02 (phase 2): consumed by the authoritative
        ``transform_tool_result`` redactor as a ContextVar-independent
        channel. Returns an immutable snapshot; empty after ``close()``.
        Callers must never log the returned values.
        """
        with self._lock:
            return self._injected

    def retained_count(self) -> int:
        """Number of unique values this scope currently holds (no values)."""
        with self._lock:
            return len(self._values)


#: ContextVar carrying the ACTIVE execution secret scope for the current
#: execution context. Set by the tool_execution middleware around the actual
#: tool call; read by _resolve_placeholder_token when registering injected
#: plaintext for redaction.
_execution_secret_scope: contextvars.ContextVar["ExecutionSecretScope | None"] = \
    contextvars.ContextVar("vaultwarden_execution_secret_scope", default=None)


def current_execution_scope() -> "ExecutionSecretScope | None":
    """Return the active execution secret scope (None outside an execution)."""
    return _execution_secret_scope.get()


def _open_execution_scope(redactor: Any) -> tuple["ExecutionSecretScope", Any]:
    """Create + publish a fresh execution scope; returns (scope, cv_token)."""
    scope = ExecutionSecretScope(redactor)
    token = _execution_secret_scope.set(scope)
    return scope, token


# ---------------------------------------------------------------------------
# AUD-02 (phase 2): ACTIVE-SCOPE REGISTRY for the SEC-01 transform handoff.
#
# The authoritative `transform_tool_result` hook must be able to scrub echoes
# of THIS execution's injected plaintext even when Hermes dispatches it on a
# different context/thread than the middleware frame (where the published
# ContextVar is invisible). The per-task dict fallback only works when the
# host threads a task_id through — hosts that key executions by turn_id or
# pass none at all have no correlation channel.
#
# The registry below IS that channel: scopes register themselves while open
# and unregister in close(). It stores NO secret values directly — only scope
# objects whose lifetime is bounded by their own execution (entries vanish
# exactly once when each scope closes), so this can never become unbounded
# global retention. Consumers read plaintext ONLY through the narrow
# heuristics in peek_scope_injected_secrets(), which prefer the single most
# recently opened still-active scope and require an exact exec-id match
# against the scope's OWN task id before trusting a keyed lookup.
# ---------------------------------------------------------------------------

_ACTIVE_SCOPES: "list[ExecutionSecretScope]" = []
_ACTIVE_SCOPES_LOCK = threading.Lock()


def _register_active_scope(scope: ExecutionSecretScope) -> None:
    with _ACTIVE_SCOPES_LOCK:
        _ACTIVE_SCOPES.append(scope)


def _unregister_active_scope(scope: ExecutionSecretScope) -> None:
    with _ACTIVE_SCOPES_LOCK:
        try:
            _ACTIVE_SCOPES.remove(scope)
        except ValueError:  # pragma: no cover - defensive (double close)
            pass


def active_scope_count() -> int:
    """Number of currently-open execution scopes (no values exposed)."""
    with _ACTIVE_SCOPES_LOCK:
        return len(_ACTIVE_SCOPES)


def _bind_scope_task(scope: ExecutionSecretScope, task_id: str) -> None:
    """Attach the execution's task id to *scope* for transform correlation."""
    if task_id:
        scope._task_id = task_id  # noqa: SLF001 - internal correlation tag


def peek_scope_injected_secrets(exec_id: str) -> list[str]:
    """Injected-plaintext set from the ACTIVE scope(s) for one execution.

    AUD-02 (phase 2) transform-side fallback: consulted by the authoritative
    redactor AFTER the ContextVar channel and BEFORE the task-keyed store.
    Never raises; returns ``[]`` when no active scope plausibly matches.

    Correlation policy (deliberately conservative):
    - exec_id given and equal to a scope's bound task id -> that scope wins;
    - exec_id empty -> the MOST RECENTLY opened still-active scope wins
      (Hermes dispatches transform_tool_result right after the middleware
      call returns, while exactly its own scope is normally active);
    - exec_id given but matching no bound scope -> union of ALL active
      scopes' sets (fail-safe over-redaction: during overlapping executions
      every retained value is still needed by someone anyway, and extra
      scrubbing can never leak — only hide — text).
    """
    with _ACTIVE_SCOPES_LOCK:
        scopes = list(_ACTIVE_SCOPES)
    if not scopes:
        return []
    if exec_id:
        for scope in reversed(scopes):
            if getattr(scope, "_task_id", "") == exec_id:
                return list(scope.injected_values())
        merged: list[str] = []
        for scope in scopes:
            merged.extend(v for v in scope.injected_values() if v not in merged)
        return merged
    return list(scopes[-1].injected_values())


def _close_execution_scope(scope: ExecutionSecretScope, token: Any) -> None:
    """Close *scope* exactly once and restore the previous ContextVar value."""
    try:
        scope.close()
    finally:
        _unregister_active_scope(scope)
        try:
            _execution_secret_scope.reset(token)
        except ValueError:  # pragma: no cover - defensive (foreign context)
            _execution_secret_scope.set(None)


def retain_in_execution_scope(value: str, redactor: Any) -> None:
    """Register runtime-injected *value* via the ACTIVE execution scope.

    Falls back to a temporary LOCAL scope (retained now, released immediately)
    when called without a surrounding middleware execution scope — e.g. legacy
    direct callers. That path logs a sanitized warning (the missing parent
    scope), never the value, and guarantees no unbounded global retention:
    the local scope is closed in a finally block.
    """
    if not value:
        return
    scope = _execution_secret_scope.get()
    if scope is not None:
        scope.retain(value)
        return
    # Unexpected: no active parent scope. Fail-safe local scope so the value
    # is redacted for the duration of THIS operation and released right after
    # — never left registered process-wide (AUD-02: no unbounded retention).
    log.warning("No active execution secret scope; using temporary local "
                "scope (value length=%d, value itself never logged).",
                len(value))
    local = ExecutionSecretScope(redactor)
    try:
        local.retain(value)
    finally:
        local.close()


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
    """
    fd, path = tempfile.mkstemp(dir=secrets_dir, prefix=f"vw_{token}_")
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, value.encode("utf-8"))
    finally:
        os.close(fd)
    temp_files.append(path)
    return path


def _resolve_placeholder_token(six_hex: str, auth: AuthManager,
                               registry: PlaceholderRegistry, secrets_dir: str,
                               temp_files: list[str], task_id: str = "",
                               injected_values_out: list[str] | None = None,
                               task_errors: list[dict] | None = None,
                               scope: "ExecutionSecretScope | None" = None,
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
    # Register the value so it gets scrubbed from any log line / output echo.
    # AUD-02 (phase 2): runtime injected plaintext is retained through the
    # OWNING execution secret scope (refcounted via the Phase-1 redactor API)
    # instead of the raw unbounded register_secret path — the owning
    # middleware releases it exactly once when the execution concludes. The
    # middleware passes its own *scope* object explicitly so retention works
    # even when Hermes dispatches the tool on a different context/thread
    # (ContextVars would not propagate there). If no scope was passed and no
    # parent scope exists in this context (legacy/direct callers), the
    # fail-safe helper uses a temporary local scope that is closed right
    # after this operation and logs a sanitized warning (never the value).
    if scope is not None:
        scope.retain(value)
    else:
        retain_in_execution_scope(value, get_redacting_filter())
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
        injected_values: list[str] = []
        new_args = dict(args)
        resolved_any = False
        # AUD-02 (phase 2): open the execution secret scope BEFORE resolving
        # any placeholder so every injected plaintext is retained through it
        # (refcounted on the shared redactor). The scope closes exactly once,
        # in the OUTERMOST finally below — i.e. only AFTER next_call returned
        # (so the authoritative transform_tool_result redaction for THIS
        # execution has consumed the handoff), after temp-file cleanup
        # observability, and even when an exception aborts the lifecycle.
        _scope, _scope_token = _open_execution_scope(get_redacting_filter())
        # AUD-02 (phase 2): bind the execution id so the authoritative
        # transform_tool_result redactor can correlate THIS execution's
        # injected set through the active-scope registry even when Hermes
        # dispatches the hook on a different context/thread.
        _bind_scope_task(_scope, task_id or "")
        _register_active_scope(_scope)
        try:
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
                        task_id, injected_values, task_errors, scope=_scope)
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
            # SEC-01 (v0.5.4): forget this execution's per-task plaintext set
            # too (the ContextVar was already restored above). The middleware
            # is the single OWNER that forgets injected values — neither the
            # transformer nor the observer pops them.
            take_task_secrets(task_id)
        finally:
            # AUD-02 (phase 2): LATEST SAFE LIFECYCLE POINT. Everything that
            # may still need the injected plaintext has now run for THIS
            # execution: next_call returned (so Hermes dispatched
            # transform_tool_result on the returned object — the authoritative
            # SEC-01 redaction consumed the handoff BEFORE the inner finally
            # restored it), temp-file cleanup ran, and the per-task store was
            # forgotten. Close the scope exactly once: each value retained by
            # THIS scope is released once on the refcounted redactor, so an
            # overlapping execution holding the same secret keeps it redacted
            # until its own scope closes, and process-scoped secrets are never
            # dropped by this path. Runs even when an exception aborted the
            # lifecycle (fail-safe release). close() is idempotent and never
            # raises.
            _close_execution_scope(_scope, _scope_token)

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
        #    the primary channel; the AUD-02 active-scope registry is the
        #    context-independent fallback while the owning execution is still
        #    in flight (its middleware closes the scope only AFTER this hook
        #    has run); the task-keyed dict covers hosts that thread a task id
        #    through but dispatch on another thread after the scope closed.
        #    Never pop here — the middleware's finally block owns forgetting
        #    the values.
        cv_values = _CURRENT_INJECTED_SECRETS.get()
        if cv_values:
            values = list(cv_values)
        else:
            values = peek_scope_injected_secrets(exec_id)
            if not values:
                values = peek_task_secrets(exec_id)
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
        auth.shutdown(keep_appdata=True)

    return vaultwarden_on_session_end

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
- unresolved references (expired / unknown / already-used) are left EXACTLY as
  they were: the leading `$` makes them valid shell variable references that
  expand to an empty string — fail-safe, the secret cannot leak and the
  command simply fails with an empty value (the error is recorded for
  post_tool_call to surface to the agent).

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
from typing import Any, Callable

from . import errors
from .auth import AuthManager
from .placeholders import PlaceholderRegistry
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


def _secrets_dir() -> str:
    """Return the dedicated secrets directory, creating it if needed.

    Prefers $XDG_RUNTIME_DIR/vw-secrets (typically tmpfs/RAM-backed).
    Falls back to /tmp/vw-secrets-<uid> if XDG_RUNTIME_DIR is unavailable.
    The directory is chmod 700 so no other user can list its contents.
    """
    xdg = os.environ.get("XDG_RUNTIME_DIR", "")
    if xdg and os.path.isdir(xdg) and os.access(xdg, os.W_OK):
        d = os.path.join(xdg, "vw-secrets")
    else:
        d = os.path.join(tempfile.gettempdir(), f"vw-secrets-{os.getuid()}")
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def _cleanup_stale_secrets():
    """Remove temp files older than the placeholder TTL (300s).

    Handles files left behind by a previous SIGKILL/SIGTERM where the
    middleware's finally block did not run. The TTL matches the placeholder
    registry TTL — any file older than that is stale and should be removed.

    Called at plugin startup (in register()) to ensure stale files are
    cleaned up even if the previous process crashed.
    """
    try:
        secrets_dir = _secrets_dir()
    except OSError:
        return  # cannot create/access the dir, skip cleanup

    if not os.path.isdir(secrets_dir):
        return

    cutoff = time.time() - 300  # placeholder TTL (5 minutes)
    for entry in os.scandir(secrets_dir):
        try:
            if entry.is_file() and entry.stat().st_mtime < cutoff:
                os.unlink(entry.path)
                log.info("cleaned stale secret file: %s", entry.name)
        except OSError:
            pass  # best-effort cleanup


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


def _inject_one(token: str, auth: AuthManager, registry: PlaceholderRegistry,
                secrets_dir: str, temp_files: list[str],
                task_id: str = "",
                injected_values_out: list[str] | None = None) -> str | None:
    """Resolve one placeholder suffix; return the temp-file path or None.

    The middleware has ALREADY consumed the token (single-use marking happens
    up-front in ``vaultwarden_inject_secrets``), so here we only read the
    registry entry and fetch the field value. None means "leave the reference
    verbatim" (fail-safe `$` expansion): expired / unknown / already-used
    tokens, or items whose field went empty. The real secret is ONLY ever
    written to the returned temp file (mkstemp: atomic, O_EXCL, chmod 600) —
    never into the command string.

    SEC-01 (v0.5.4): when *injected_values_out* is provided the plaintext is
    collected there LOCALLY (inside the middleware frame) instead of being
    published into the ContextVar here — the middleware publishes the exact
    set into the ContextVar handoff channel immediately before next_call and
    restores it in its finally block. record_task_secret still keeps the
    task-keyed dict fallback in sync for hosts that dispatch hooks on a
    different context/thread.
    """
    placeholder = f"__VW_SECRET_{token}__"   # registry form (no $)
    entry = registry.peek(placeholder)
    if entry is None:
        return None  # unknown/expired/already-used — error recorded upstream
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
    fd, path = tempfile.mkstemp(dir=secrets_dir, prefix=f"vw_{token}_")
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, value.encode("utf-8"))
    finally:
        os.close(fd)
    temp_files.append(path)
    # Register the value so it gets scrubbed from any log line / output echo.
    get_redacting_filter().register_secret(value)
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

        # VWP-04 single-use semantics: every $__VW_SECRET_ reference that
        # reaches the middleware is CONSUMED — even if it later turns out to
        # be expired/unknown/already-used or its vault field went empty (that
        # reference stays verbatim as a fail-safe `$` expansion). Marking the
        # tokens used up-front makes replay detection deterministic.
        with _PENDING_LOCK:
            task_errors = _PENDING_ERRORS.setdefault(task_id or "", [])
        for key in targets:
            for m in _VW_SECRET_CMD_RE.finditer(args[key]):
                placeholder = f"__VW_SECRET_{m.group(1)}__"  # registry form
                try:
                    registry.consume(placeholder)
                except errors.PlaceholderError as exc:
                    log.warning("Placeholder %s: %s", placeholder, exc.message)
                    task_errors.append(exc.to_dict())

        secrets_dir = _secrets_dir()
        temp_files: list[str] = []
        injected_values: list[str] = []
        new_args = dict(args)
        resolved_any = False
        try:
            for key in targets:
                command = new_args[key]
                new_command = command
                for m in _VW_SECRET_CMD_RE.finditer(command):
                    path = _inject_one(m.group(1), auth, registry, secrets_dir,
                                       temp_files, task_id, injected_values)
                    if path is None:
                        continue  # expired/unknown/already-used -> leave as-is
                    new_command = new_command.replace(m.group(0), f"$(< {path})")
                    resolved_any = True
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
            # Cleanup temp files — MUST run even if the command fails/times out
            for path in temp_files:
                try:
                    os.unlink(path)
                except OSError:
                    pass
            # SEC-01 (v0.5.4): forget this execution's per-task plaintext set
            # too (the ContextVar was already restored above). The middleware
            # is the single OWNER that forgets injected values — neither the
            # transformer nor the observer pops them.
            take_task_secrets(task_id)

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

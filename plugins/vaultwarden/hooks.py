"""Terminal hook handlers (plan §7): VWP-04 file-injection `tool_execution`
middleware + `post_tool_call` cleanup/redaction.

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
  echoed output is scrubbed;
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

import os
import re
import tempfile
import threading
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


def _inject_one(token: str, auth: AuthManager, registry: PlaceholderRegistry,
                secrets_dir: str, temp_files: list[str],
                task_id: str = "") -> str | None:
    """Resolve one placeholder suffix; return the temp-file path or None.

    None means "leave the reference verbatim" (fail-safe `$` expansion):
    expired / unknown / already-used tokens, or items whose field went empty.
    The real secret is ONLY ever written to the returned temp file
    (mkstemp: atomic, O_EXCL, chmod 600) — never into the command string.
    """
    placeholder = f"__VW_SECRET_{token}__"   # registry form (no $)
    try:
        entry = registry.consume(placeholder)
    except errors.PlaceholderError as exc:
        log.warning("Placeholder %s: %s", placeholder, exc.message)
        with _PENDING_LOCK:
            _PENDING_ERRORS.setdefault(task_id or "", []).append(exc.to_dict())
        return None
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
    # v0.1.4 (FAIL-6): also record the plaintext per-task so post_tool_call can
    # redact it from this specific tool call's output even when the global
    # filter state was reset by another component in between.
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

        secrets_dir = _secrets_dir()
        temp_files: list[str] = []
        new_args = dict(args)
        resolved_any = False
        try:
            for key in targets:
                command = new_args[key]
                new_command = command
                for m in _VW_SECRET_CMD_RE.finditer(command):
                    path = _inject_one(m.group(1), auth, registry, secrets_dir,
                                       temp_files, task_id)
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
            return next_call(new_args)
        finally:
            # Cleanup temp files — MUST run even if the command fails/times out
            for path in temp_files:
                try:
                    os.unlink(path)
                except OSError:
                    pass

    return vaultwarden_inject_secrets


#: transient error store surfaced by post_tool_call then cleared.
#: v0.2.2 (BUGFIX): task-scoped dict + lock — parallel tool calls can no
#: longer lose (or steal) each other's pending errors via a shared list.
_PENDING_ERRORS: dict[str, list[dict]] = {}
_PENDING_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Per-task injected-secret store (v0.1.4, FAIL-6).
#
# When the middleware resolves a placeholder it knows the plaintext secret
# value that is about to enter the shell. We keep that value ONLY for the
# duration of the tool call (keyed by task_id) so the post_tool_call hook can
# scrub it out of whatever the command echoed back — without ever registering
# vault item values in the global RedactingFilter (which would redact them
# from unrelated text forever and could collide with benign strings).
# The store is short-lived, memory-only and never logged.
_INJECTED_SECRETS: dict[str, list[str]] = {}
_INJECTED_LOCK = threading.Lock()


def record_task_secret(task_id: str, value: str) -> None:
    if not value:
        return
    with _INJECTED_LOCK:
        _INJECTED_SECRETS.setdefault(task_id or "", []).append(value)


def take_task_secrets(task_id: str) -> list[str]:
    """Pop (and thereby forget) all pending secret values for *task_id*."""
    with _INJECTED_LOCK:
        return _INJECTED_SECRETS.pop(task_id or "", [])


def clear_task_secrets() -> None:
    """Drop every pending secret (used on session end / registry clear)."""
    with _INJECTED_LOCK:
        _INJECTED_SECRETS.clear()


def _redact_in_result(result: Any) -> Any:
    """Scrub registered secret values out of a tool result object.

    v0.1.4 (FAIL-6): the shared RedactingFilter only knows bootstrap secrets,
    session keys and explicitly tracked write payloads — vault-stored item
    fields are deliberately NOT registered globally (they could collide with
    unrelated text). For post_tool_call leak protection we therefore also
    redact every secret this plugin just INJECTED into a terminal command:
    ``hooks`` records the resolved values per task in _INJECTED_SECRETS and
    they are scrubbed from the matching task's output here, then forgotten.
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


def _redact_task_secrets(task_id: str, result: Any) -> None:
    """Remove freshly injected placeholder secrets from *result* (in place)."""
    values = take_task_secrets(task_id)
    if not values:
        return

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
        # _scrub returns a rebuilt container; merge back so callers holding the
        # original dict reference observe the redaction.
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


def make_post_cleanup_hook(auth: AuthManager,
                           registry: PlaceholderRegistry,
                           config: Any = None) -> Callable[..., None]:
    """Build the `post_tool_call` observer for ctx.register_hook."""

    terminal_tools = set(getattr(config, "terminal_tool_names", None) or _DEFAULT_TERMINAL_TOOLS)

    def vaultwarden_post_cleanup(tool_name: str = "", args: dict | None = None,
                                 result: Any = None, task_id: str = "",
                                 **kwargs: Any) -> None:
        if tool_name not in terminal_tools:
            return
        n = registry.cleanup_used()
        if n:
            log.debug("post_tool_call cleaned %d used placeholder(s).", n)
        # Leak protection: redact any resolved secret echoed by the command.
        # v0.1.5 (FAIL-6): _redact_in_result returns a NEW dict for dict results
        # (the old code discarded it, so {"output": ...} was never scrubbed);
        # merge the scrubbed copy back in place so callers observe redaction.
        scrubbed = _redact_in_result(result)
        if isinstance(result, dict) and isinstance(scrubbed, dict) \
                and scrubbed is not result:
            result.clear()
            result.update(scrubbed)
        # Task-scoped redaction for secrets this plugin just injected
        # (single-use per task_id; forgotten immediately after).
        _redact_task_secrets(task_id, result)
        # Surface fail-closed resolution errors to the agent (secret-free).
        # v0.2.2 (BUGFIX): pop only THIS task's errors — other in-flight
        # tasks keep their pending errors until their own post_tool_call.
        with _PENDING_LOCK:
            task_errors = _PENDING_ERRORS.pop(task_id or "", [])
        if task_errors and isinstance(result, dict):
            result.setdefault("vaultwarden_placeholder_errors", []).extend(task_errors)

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

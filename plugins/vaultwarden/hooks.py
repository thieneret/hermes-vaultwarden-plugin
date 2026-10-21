"""Terminal hook handlers (plan §7): env-injecting `tool_request` middleware +
`post_tool_call` cleanup/redaction.

VWP-04 (v0.4.4) — BREAKING CHANGE, env injection instead of string rewrite:
the middleware no longer substitutes the raw secret into the command string.
User-facing placeholders are written ``$__VW_SECRET_<12 hex>__`` inside
DOUBLE-QUOTED (or unquoted) command strings so the shell expands them. The
middleware resolves each placeholder via the single-use registry and:

- injects the real secret into the terminal tool's ``env`` parameter as
  ``VW_TOKEN_<suffix>`` (env dict ONLY — never the command string), and
- rewrites the reference ``$__VW_SECRET_<suffix>__`` -> ``$VW_TOKEN_<suffix>``.

The shell then expands ``$VW_TOKEN_<suffix>`` at execution time, so the raw
secret never appears in the command string, argv, shell history or ``ps``
output. Single quotes PREVENT shell expansion and therefore break injection —
documented in the skill, README and SECURITY.md.

Middleware chain safety rules (CRITICAL):
- only act on terminal-ish tools; every other tool's args pass through
  UNCHANGED (return the original object untouched);
- do nothing when the scanned arg keys contain NO "$__VW_SECRET_" substring;
- only return modified args when placeholders were found AND resolved;
- never modify args unless an actual change was made.

Resolution failures stay FAIL-CLOSED: an unknown/expired/already-used
placeholder is left EXACTLY as-is in the command (a dangling ``$__VW_...``
reference expands to an empty string at shell level, so no raw secret can
ever reach the shell), and the error is recorded for post_tool_call to
surface to the agent (never an empty string silently injected).
"""
from __future__ import annotations

import re
import threading
from collections.abc import MutableMapping
from typing import Any, Callable

from . import errors
from .auth import AuthManager
from .placeholders import TOKEN_PREFIX, TOKEN_SUFFIX, PlaceholderRegistry
from .security import get_logger, get_redacting_filter
from .tools import _field_value

log = get_logger("hooks")

# Placeholder as it appears in a command string: $__VW_SECRET_<token>__
_VW_SECRET_CMD_RE = re.compile(r"\$__VW_SECRET_([0-9a-f]{12})__")


def _env_var_for(token_suffix: str) -> str:
    """Map a placeholder token suffix to a valid shell env var name.

    e.g. 'a1b2c3d4e5f6' -> 'VW_TOKEN_a1b2c3d4e5f6'
    """
    return f"VW_TOKEN_{token_suffix}"


def _registry_token(token_suffix: str) -> str:
    """Rebuild the registry-form token '__VW_SECRET_<suffix>__' (no $)."""
    return f"{TOKEN_PREFIX}{token_suffix}{TOKEN_SUFFIX}"


# terminal-ish arg keys we scan across backends (Local/Docker/SSH/Modal/
# Daytona/Singularity/Vercel Sandbox all pass the command string here).
# v0.2.2: names/keys are overridable via config (terminal_tool_names /
# terminal_command_keys); these are the defaults when config is absent/empty.
_DEFAULT_TERMINAL_TOOLS = {
    "terminal", "shell", "bash", "execute_command",
    "run_command", "exec", "code_execution",
}
_DEFAULT_COMMAND_KEYS = ("command", "cmd", "input", "script", "code")


def _resolve_one_env(suffix: str, auth: AuthManager,
                     registry: PlaceholderRegistry,
                     task_id: str = "") -> tuple[str | None, dict | None]:
    """Consume one placeholder; return (secret_value, error_dict|None).

    Fail-closed: unknown/expired/already-used tokens (or vault fetch errors)
    yield ``(None, error)`` — the caller leaves the reference untouched, so a
    stale or forged placeholder can NEVER cause a secret to be injected.
    """
    token = _registry_token(suffix)
    try:
        entry = registry.consume(token)
    except errors.PlaceholderError as exc:
        log.warning("Placeholder %s: %s", token, exc.message)
        return None, exc.to_dict()
    try:
        item = auth.get_item(entry.item_id)
        if entry.field_name.startswith("custom:"):
            value = _field_value(item, "password", entry.field_name.split(":", 1)[1])
        else:
            value = _field_value(item, entry.field_name, None)
        if not value:
            raise errors.PlaceholderError(
                f"Referenced field '{entry.field_name}' is now empty.")
    except errors.VaultwardenError as exc:
        log.error("Secret fetch failed for %s (%s)", token, exc.code)
        return None, exc.to_dict()
    # Register the value so it gets scrubbed from any log line / output echo.
    get_redacting_filter().register_secret(value)
    # v0.1.4 (FAIL-6): also record the plaintext per-task so post_tool_call can
    # redact it from this specific tool call's output even when the global
    # filter state was reset by another component in between.
    record_task_secret(task_id, value)
    return value, None


def make_placeholder_resolver(auth: AuthManager,
                              registry: PlaceholderRegistry,
                              config: Any = None) -> Callable[..., Any]:
    """Build the `tool_request` middleware callback for ctx.register_middleware.

    VWP-04: env-injection variant — secrets go into the terminal tool's
    ``env`` argument; the command only gains a ``$VW_TOKEN_x`` reference.
    """

    terminal_tools = set(getattr(config, "terminal_tool_names", None) or _DEFAULT_TERMINAL_TOOLS)
    command_keys = tuple(getattr(config, "terminal_command_keys", None) or _DEFAULT_COMMAND_KEYS)

    def vaultwarden_resolve_placeholders(tool_name: str = "", args: dict | None = None,
                                         task_id: str = "",
                                         **kwargs: Any) -> dict | None:
        # --- chain safety gates -------------------------------------------
        if tool_name not in terminal_tools:
            return None
        if not isinstance(args, dict):
            return None
        key = next((k for k in command_keys
                    if isinstance(args.get(k), str) and "$__VW_SECRET_" in args[k]), None)
        if key is None:
            return None  # nothing to do — DO NOT touch other plugins' args

        env = dict(args.get("env") or {})
        changed = dict(args)
        resolved_count = 0

        for cmd_key in command_keys:
            command = changed.get(cmd_key)
            if not isinstance(command, str) or "$__VW_SECRET_" not in command:
                continue
            new_command = command
            for m in _VW_SECRET_CMD_RE.finditer(command):
                suffix = m.group(1)
                value, err = _resolve_one_env(suffix, auth, registry, task_id)
                if err:
                    with _PENDING_LOCK:
                        _PENDING_ERRORS.setdefault(task_id or "", []).append(err)
                    # fail closed: leave the reference untouched — the shell
                    # expands it to an empty string; no secret is ever injected.
                    continue
                var = _env_var_for(suffix)
                env[var] = value           # real secret -> subprocess env ONLY
                new_command = new_command.replace(m.group(0), f"${var}")
                resolved_count += 1
            if new_command != command:
                changed[cmd_key] = new_command

        if not resolved_count:
            return None

        changed["env"] = env
        log.debug("Injected terminal env var(s) for %d placeholder(s).", resolved_count)
        return {"args": changed}

    return vaultwarden_resolve_placeholders


#: transient error store surfaced by post_tool_call then cleared.
#: v0.2.2 (BUGFIX): task-scoped dict + lock — parallel tool calls can no
#: longer lose (or steal) each other's pending errors via a shared list.
_PENDING_ERRORS: dict[str, list[dict]] = {}
_PENDING_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Per-task injected-secret store (v0.1.4, FAIL-6).
#
# When the middleware resolves a placeholder it knows the plaintext secret
# value that is about to enter the subprocess environment. We keep that value
# ONLY for the duration of the tool call (keyed by task_id) so the
# post_tool_call hook can scrub it out of whatever the command echoed back —
# without ever registering vault item values in the global RedactingFilter
# (which would redact them from unrelated text forever and could collide with
# benign strings). The store is short-lived, memory-only and never logged.
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
    redact every secret this plugin just INJECTED into a terminal call:
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
    if isinstance(result, dict) and isinstance(scrubbed, dict) \
            and scrubbed is not result:
        # _scrub mutates dicts in place and returns the same object; only
        # rebuild-and-merge when it actually returned a NEW container —
        # clearing a dict into itself would wipe all of its data.
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

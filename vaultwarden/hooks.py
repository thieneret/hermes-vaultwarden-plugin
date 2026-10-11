"""Terminal hook handlers (plan §7): chain-safe `tool_request` middleware +
`post_tool_call` cleanup/redaction.

Middleware chain safety rules (CRITICAL):
- return None when the tool is not "terminal";
- return None when the command contains NO "__VW_SECRET_" substring;
- only return modified args when placeholders were found AND resolved;
- never modify args unless an actual change was made.

Resolution failures are FAIL-CLOSED: the placeholder token is replaced with a
safe invalid sentinel so the raw secret can never reach the shell, and the
error is recorded for post_tool_call to surface to the agent (never an empty
string silently injected).
"""
from __future__ import annotations

import re
import threading
from typing import Any, Callable

from . import errors
from .auth import AuthManager
from .placeholders import PlaceholderRegistry
from .security import (escape_for_context, get_logger, get_redacting_filter,
                       looks_like_url_context, placeholder_tokens, url_escape)
from .tools import _field_value

log = get_logger("hooks")

INVALID_SENTINEL = "__VW_PLACEHOLDER_INVALID__"

# terminal-ish arg keys we scan across backends (Local/Docker/SSH/Modal/
# Daytona/Singularity/Vercel Sandbox all pass the command string here).
_TERMINAL_TOOLS = {"terminal", "shell", "bash", "execute_command"}
_COMMAND_KEYS = ("command", "cmd", "input")


def _resolve_one(token: str, command: str, auth: AuthManager,
                 registry: PlaceholderRegistry,
                 task_id: str = "") -> tuple[str, dict | None]:
    """Return (replacement, error_dict|None). Replacement is context-escaped."""
    try:
        entry = registry.consume(token)
    except errors.PlaceholderError as exc:
        log.warning("Placeholder %s: %s", token, exc.message)
        return INVALID_SENTINEL, exc.to_dict()
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
        return INVALID_SENTINEL, exc.to_dict()
    # Register the value so it gets scrubbed from any log line / output echo.
    get_redacting_filter().register_secret(value)
    # v1.4 (FAIL-6): also record the plaintext per-task so post_tool_call can
    # redact it from this specific tool call's output even when the global
    # filter state was reset by another component in between.
    record_task_secret(task_id, value)
    if looks_like_url_context(command, token):
        escaped = url_escape(value)
    else:
        escaped = escape_for_context(value, command, token)
    return escaped, None


def resolve_all_placeholders(command: str, auth: AuthManager,
                             registry: PlaceholderRegistry,
                             task_id: str = "") -> tuple[str, list[dict]]:
    """Replace every token in *command*; returns (new_command, errors)."""
    errors_out: list[dict] = []
    for token in placeholder_tokens(command):
        replacement, err = _resolve_one(token, command, auth, registry, task_id)
        if err:
            errors_out.append(err)
        command = command.replace(token, replacement)
    return command, errors_out


def make_placeholder_resolver(auth: AuthManager,
                              registry: PlaceholderRegistry) -> Callable[..., Any]:
    """Build the `tool_request` middleware callback for ctx.register_middleware."""

    def vaultwarden_resolve_placeholders(tool_name: str = "", args: dict | None = None,
                                         task_id: str = "",
                                         **kwargs: Any) -> dict | None:
        # --- chain safety gates -------------------------------------------
        if tool_name not in _TERMINAL_TOOLS:
            return None
        if not isinstance(args, dict):
            return None
        key = next((k for k in _COMMAND_KEYS
                    if isinstance(args.get(k), str) and "__VW_SECRET_" in args[k]), None)
        if key is None:
            return None  # nothing to do — DO NOT touch other plugins' args
        command = args[key]
        modified, errs = resolve_all_placeholders(command, auth, registry, task_id)
        if errs:
            # stash for post_tool_call surfacing; fail-closed sentinel already applied
            _PENDING_ERRORS.extend(errs)
        if modified != command:
            new_args = {**args, key: modified}
            for extra_key in _COMMAND_KEYS:
                if extra_key != key and isinstance(args.get(extra_key), str) \
                        and "__VW_SECRET_" in args[extra_key]:
                    new_val, more = resolve_all_placeholders(
                        args[extra_key], auth, registry, task_id)
                    _PENDING_ERRORS.extend(more)
                    new_args[extra_key] = new_val
            log.debug("Rewrote terminal args (%d placeholder(s)).",
                      len(placeholder_tokens(command)))
            return {"args": new_args}
        return None

    return vaultwarden_resolve_placeholders


#: transient error store surfaced by post_tool_call then cleared
_PENDING_ERRORS: list[dict] = []

# ---------------------------------------------------------------------------
# Per-task injected-secret store (v1.4, FAIL-6).
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

    v1.4 (FAIL-6): the shared RedactingFilter only knows bootstrap secrets,
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
                           registry: PlaceholderRegistry) -> Callable[..., None]:
    """Build the `post_tool_call` observer for ctx.register_hook."""

    def vaultwarden_post_cleanup(tool_name: str = "", args: dict | None = None,
                                 result: Any = None, task_id: str = "",
                                 **kwargs: Any) -> None:
        if tool_name not in _TERMINAL_TOOLS:
            return
        n = registry.cleanup_used()
        if n:
            log.debug("post_tool_call cleaned %d used placeholder(s).", n)
        # Leak protection: redact any resolved secret echoed by the command.
        _redact_in_result(result)
        # Surface fail-closed resolution errors to the agent (secret-free).
        if _PENDING_ERRORS and isinstance(result, dict):
            result.setdefault("vaultwarden_placeholder_errors", []).extend(
                _PENDING_ERRORS[:])
            _PENDING_ERRORS.clear()

    return vaultwarden_post_cleanup


def make_session_end_hook(auth: AuthManager,
                          registry: PlaceholderRegistry) -> Callable[..., None]:
    """`on_session_end`: clear session + placeholders, lock vault, keep .bw-data."""

    def vaultwarden_on_session_end(**kwargs: Any) -> None:
        registry.clear()
        auth.shutdown(keep_appdata=True)

    return vaultwarden_on_session_end

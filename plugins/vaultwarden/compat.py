"""Centralized compatibility layer for Hermes API versions, bw CLI versions,
and Python version differences (VWP-17).

All Hermes-API capability detection lives here so auditors can review
version-specific behaviour in a single module:
- register_tool / register_hook: explicit capability detection (VWP-06) —
  inspect.signature() / hasattr(), NOT exception-based probing.
- Config extraction: native PluginContext.get_config() ONLY (VWP-05) —
  the former fallback layers (read_user_config_raw, direct YAML read) were
  removed after diagnostic testing confirmed the native API works.
- bw CLI version parsing / minimum-version enforcement.
- Exception code extraction.
"""
from __future__ import annotations

import inspect
import logging
from typing import Any

log = logging.getLogger("hermes.plugins.vaultwarden.compat")

# ── Hermes API compatibility ─────────────────────────────────────────


def register_tool_compat(ctx: Any, *, name: str, toolset: str, schema: dict,
                         handler: Any, check_fn: Any = None) -> None:
    """Register a tool with Hermes using capability detection (VWP-06).

    Inspects the register_tool signature to determine whether check_fn is
    supported. Fails closed if the API is unavailable.
    """
    register_fn = getattr(ctx, "register_tool", None)
    if not callable(register_fn):
        raise RuntimeError(
            "Hermes PluginContext.register_tool is not available. "
            "Check Hermes plugin API compatibility.")
    sig = inspect.signature(register_fn)
    if "check_fn" in sig.parameters:
        register_fn(name=name, toolset=toolset, schema=schema,
                    handler=handler, check_fn=check_fn)
    else:
        register_fn(name=name, toolset=toolset, schema=schema,
                    handler=handler)


def register_hook_if_available(ctx: Any, hook_name: str, hook_fn: Any) -> bool:
    """Register a hook if supported (VWP-06). Returns True if registered."""
    if not hasattr(ctx, "register_hook"):
        log.warning("Context lacks register_hook; %s not installed.", hook_name)
        return False
    try:
        ctx.register_hook(hook_name, hook_fn)
        return True
    except Exception as exc:
        log.error("register_hook(%r) failed: %s", hook_name, exc)
        return False


#: The single hook name whose presence is MANDATORY since SEC-01 (v0.5.4).
TRANSFORM_TOOL_RESULT_HOOK = "transform_tool_result"

#: Lifecycle hooks that are MANDATORY since AUD-06 (v0.6.3). These are the
#: hooks the plugin ACTUALLY implements and dispatches on: ``post_tool_call``
#: (placeholder cleanup, temp-file cleanup observability, metrics, post-call
#: hygiene) and ``on_session_end`` (session-end cleanup / session lifecycle
#: termination — the equivalent session-end hook implemented by this plugin
#: is named exactly ``on_session_end``; no other name is invented).
MANDATORY_LIFECYCLE_HOOKS = ("post_tool_call", "on_session_end")


def supports_lifecycle_hook(ctx: Any, hook_name: str) -> bool:
    """AUD-06 (v0.6.3): explicit capability detection for a lifecycle hook.

    Follows the SAME VWP-06 rule as every other capability check in this
    module: explicit introspection (``callable()`` / ``hasattr()`` /
    membership tests), NEVER exception-based probing. A host exposes a
    hook in one of three ways:

    1. as a bound attribute/method on the PluginContext,
    2. by declaring the hook name in a ``supported_hooks`` collection,
    3. via the module-level ``hermes_cli.plugins.VALID_HOOKS`` registry
       (VWP-18, current production Hermes builds).

    Detection order mirrors :func:`supports_transform_tool_result` exactly
    (SEC-01 / VWP-18): context attribute first, then a declared collection,
    and ONLY as a last resort the module-level registry. A declared
    ``supported_hooks`` collection that omits the hook means the host does
    NOT support it — the plugin fails closed instead of optimistically
    registering into a hook the dispatcher never calls.
    """
    if not callable(getattr(ctx, "register_hook", None)):
        return False
    if hasattr(ctx, hook_name):
        return True
    declared = getattr(ctx, "supported_hooks", None)
    if isinstance(declared, (list, tuple, set, frozenset)):
        return hook_name in set(declared)
    # VWP-18 hosts advertise ALL dispatchable hook names (lifecycle hooks
    # included) through the module-level VALID_HOOKS registry. Guarded
    # membership test — never raises, conservative False when absent.
    return _valid_hooks_registry_supports(hook_name)


def register_mandatory_lifecycle_hook(ctx: Any, hook_name: str,
                                      handler: Any) -> None:
    """AUD-06 (v0.6.3): register a MANDATORY lifecycle hook, FAIL-CLOSED.

    Raises ``errors.PluginInitializationError`` when:
      * the host does not support ``hook_name`` (explicit capability
        detection via :func:`supports_lifecycle_hook`), or
      * ``ctx.register_hook`` itself raises (the original exception type is
        reported as the sanitized failure reason), or
      * the host API signals failure EXPLICITLY by returning ``False``.

    A ``None`` return (or any non-``False`` return) from a supported host
    means SUCCESS: some Hermes builds' ``register_hook`` has no return
    value at all, and treating ``None`` as failure would falsely refuse
    healthy hosts. Only an explicit ``False`` is a failure indicator.

    Error messages contain the hook name and a sanitized failure reason
    ONLY — never secrets, YAML contents, environment values, or session
    material. Callers MUST NOT wrap this function in a swallowing
    try/except: failures propagate out of ``register()`` so the plugin
    never reaches a partially active state and tools are never exposed
    without their required lifecycle hooks.
    """
    from . import errors

    if not supports_lifecycle_hook(ctx, hook_name):
        raise errors.PluginInitializationError(
            f"fail-closed: host Hermes does not support the mandatory "
            f"lifecycle hook '{hook_name}'. Refusing to load the "
            f"Vaultwarden plugin without it — cleanup/session-termination "
            f"guarantees cannot be met on this host. Upgrade Hermes or "
            f"disable this plugin.")
    try:
        result = ctx.register_hook(hook_name, handler)
    except Exception as exc:
        # Re-raise as an initialization failure; keep the ORIGINAL
        # exception TYPE NAME only (sanitized reason), never its args —
        # host exception payloads are not trusted to be secret-free.
        raise errors.PluginInitializationError(
            f"fail-closed: register_hook('{hook_name}') raised "
            f"{type(exc).__name__}. Refusing to load the Vaultwarden "
            f"plugin without the mandatory lifecycle hook.") from None
    if result is False:
        # Explicit host-API failure indicator ONLY. None / truthy returns
        # are success (see docstring).
        raise errors.PluginInitializationError(
            f"fail-closed: register_hook('{hook_name}') returned an "
            f"explicit failure indicator. Refusing to load the "
            f"Vaultwarden plugin without the mandatory lifecycle hook.")


def supports_transform_tool_result(ctx: Any) -> bool:
    """SEC-01 (v0.5.4): capability detection for the authoritative result
    redaction hook.

    Hermes documents ``transform_tool_result`` as the ONLY hook that may
    return a replacement tool result string/object BEFORE it is passed to
    the model — i.e. the only guaranteed confidentiality boundary for
    injected secrets. Older Hermes builds do not expose it; on such hosts
    the plugin must refuse to load (fail-closed) instead of silently
    falling back to the observer-only ``post_tool_call`` redaction model
    that audit finding SEC-01 (HIGH) identified.

    Detection follows the VWP-06 rule: explicit ``hasattr()`` capability
    check, NOT exception-based probing. A host exposes the hook either as a
    bound attribute/method on the context, or by declaring the hook name in
    a ``supported_hooks`` collection (some Hermes builds ship a static list
    of valid hook names instead of attributes).

    v0.6.0 hotfix (VWP-18): current production Hermes builds advertise hook
    support via the module-level ``hermes_cli.plugins.VALID_HOOKS`` registry
    (e.g. ``python -c "from hermes_cli.plugins import VALID_HOOKS; print(...)"``)
    rather than through PluginContext attributes. That registry is consulted
    as a last-resort detection layer so up-to-date hosts are no longer
    misclassified as legacy and refused at load time. The fail-closed
    behaviour for genuinely old hosts (no hook anywhere) is unchanged.
    """
    if not callable(getattr(ctx, "register_hook", None)):
        return False
    if hasattr(ctx, TRANSFORM_TOOL_RESULT_HOOK):
        return True
    # Test doubles / stand-in contexts may opt in explicitly instead of
    # exposing the hook as an attribute or a supported_hooks collection.
    if getattr(ctx, "supports_transform_tool_result", False):
        return True
    declared = getattr(ctx, "supported_hooks", None)
    if isinstance(declared, (list, tuple, set, frozenset)):
        return TRANSFORM_TOOL_RESULT_HOOK in set(declared)
    return _valid_hooks_registry_supports(TRANSFORM_TOOL_RESULT_HOOK)


def _valid_hooks_registry_supports(hook_name: str) -> bool:
    """VWP-18 (v0.6.0 hotfix): consult the host's VALID_HOOKS registry.

    Modern Hermes hosts enumerate every hook name they dispatch in
    ``hermes_cli.plugins.VALID_HOOKS`` (a set/list/frozenset of strings),
    but do NOT mirror that capability on the PluginContext object. Reading
    this registry is a pure membership test — it never invokes host code
    and raises nothing: if the module is absent (older hosts, unit-test
    environments without Hermes installed) we conservatively return False
    and the caller keeps failing closed.
    """
    try:
        from hermes_cli.plugins import VALID_HOOKS  # type: ignore[attr-defined]
    except Exception:
        # No hermes_cli on sys.path, or the build predates VALID_HOOKS:
        # treat as unsupported (fail-closed default preserved).
        return False
    if isinstance(VALID_HOOKS, (list, tuple, set, frozenset)):
        return hook_name in set(VALID_HOOKS)
    return False

# ── Config loading compatibility ─────────────────────────────────────


def extract_plugin_section(source: Any, *, plugin_id: str = "vaultwarden") -> dict:
    """Extract plugin config section using ONLY the native Hermes API.

    VWP-05: fallbacks removed. Diagnostic testing confirmed the native
    PluginContext.get_config() API resolves config values correctly, so the
    former FALLBACK layers (hermes_cli.config.read_user_config_raw and the
    direct HERMES_HOME/config.yaml read) are gone. Returns the section dict,
    or empty dict if the native API yields no values. The caller decides
    fail-closed.
    """
    if source is None:
        return {}
    getter = getattr(source, "get_config", None)
    if not callable(getter):
        log.warning("source.get_config is not callable; returning empty dict.")
        return {}
    # Late import avoids a circular dependency (config.py imports compat).
    from .config import _DEFAULTS
    result: dict[str, Any] = {}
    for key in _DEFAULTS:
        try:
            value = getter(key, None)
        except Exception as exc:
            log.warning("get_config(%r) raised %s; skipping.", key, exc)
            continue
        if value is not None:
            result[key] = value
    return result

# ── bw CLI compatibility ─────────────────────────────────────────────

# VWP-11: minimum supported bw CLI version (hardcoded — NOT configurable).
# Moved here from bw_cli.py under VWP-17; bw_cli re-exports it as
# _MIN_BW_VERSION so the constant stays importable from both modules.
MIN_BW_VERSION = (2026, 9, 1)


def parse_bw_version(version_output: str) -> tuple[int, ...]:
    """Parse bw version string 'YYYY.M.P' into a tuple of ints.

    Raises ValueError if the version cannot be parsed.
    """
    parts = version_output.strip().split(".")
    if len(parts) < 2:
        raise ValueError(f"too few components: {version_output!r}")
    return tuple(int(p) for p in parts[:3])


def require_min_bw_version(version_output: str) -> None:
    """Enforce minimum bw version, raise UnsupportedBwVersionError if not met.

    Called from bw_cli._check_version() after parsing.
    """
    from . import errors

    version = parse_bw_version(version_output)
    min_str = ".".join(str(x) for x in MIN_BW_VERSION)

    if version < MIN_BW_VERSION:
        raise errors.UnsupportedBwVersionError(
            f"bw version {version_output.strip()} is below the minimum supported "
            f"version {min_str}. Upgrade the Bitwarden CLI."
        )

# ── Exception code compatibility ─────────────────────────────────────


def get_error_code(exc: Exception) -> str:
    """Extract error code from an exception, with fallback to class name.

    Handles both VaultwardenError (which has a .code attribute) and generic
    exceptions. Used in auth.py and __init__.py for logging.
    """
    return getattr(exc, "code", type(exc).__name__)

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

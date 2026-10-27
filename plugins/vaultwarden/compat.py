"""Centralized compatibility layer for Hermes API versions, bw CLI versions,
and Python version differences (VWP-17).

Every fallback that used to be scattered across __init__.py (register_tool /
register_hook signatures), config.py (config-loading fallbacks, YAML import
fallback), bw_cli.py (version parsing / minimum-version enforcement) and
auth.py (exception code extraction) lives here so auditors can review all
version-specific behaviour in a single module.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

log = logging.getLogger("hermes.plugins.vaultwarden.compat")

# ── Hermes API compatibility ─────────────────────────────────────────


def register_tool_compat(ctx: Any, *, name: str, toolset: str, schema: dict,
                         handler: Any, check_fn: Any = None) -> None:
    """Register a tool with Hermes, handling both old and new register_tool signatures.

    Tries the new signature with check_fn first; falls back to the old signature
    without check_fn on TypeError.
    """
    try:
        ctx.register_tool(name=name, toolset=toolset, schema=schema,
                          handler=handler, check_fn=check_fn)
    except TypeError:
        # older/newer register_tool signature without check_fn
        ctx.register_tool(name=name, toolset=toolset, schema=schema, handler=handler)


def register_hook_if_available(ctx: Any, hook_name: str, hook_fn: Any) -> bool:
    """Register a hook if the context supports it.

    Returns True if registered, False if the context lacks register_hook.
    """
    try:
        ctx.register_hook(hook_name, hook_fn)
        return True
    except AttributeError:
        log.warning("Context lacks register_hook; %s not installed.", hook_name)
        return False

# ── Config loading compatibility ─────────────────────────────────────


def extract_plugin_section(source: Any, *, plugin_id: str = "vaultwarden") -> dict:
    """Extract plugin config section with multi-layer fallback.

    Tries:
    1. PluginContext.get_config() (Hermes-native)
    2. read_user_config_raw() (Hermes raw YAML reader)
    3. Direct YAML file read from HERMES_HOME/config.yaml

    Returns empty dict if all fail. NOTE: layer 1 is handled by
    config.py::_extract_section itself (it needs the plugin's _DEFAULTS key
    list); this function provides the FALLBACK layers only and returns an
    empty dict to signal "no fallback data found".
    """
    if source is None:
        return {}

    # Layer 1: Hermes-native PluginContext.get_config()
    getter = getattr(source, "get_config", None)
    if callable(getter):
        # This is handled by config.py's _extract_section; compat.py provides
        # the fallback layers only. Return empty to signal "try next layer".
        pass

    # Layer 2: read_user_config_raw()
    try:
        from hermes_cli.config import read_user_config_raw
        data = read_user_config_raw()
        if data:
            entry = data.get("plugins", {}).get("entries", {}).get(plugin_id, {})
            section = entry.get("settings") or entry.get("config") or {}
            if section:
                log.warning(
                    "Fallback 1: read %d keys from plugins.entries.%s.settings "
                    "via read_user_config_raw().", len(section), plugin_id)
                return section
            log.warning("Fallback 1: read_user_config_raw() loaded but "
                        "plugins.entries.%s is empty. "
                        "plugins keys: %s", plugin_id,
                        list(data.get("plugins", {}).keys()))
        else:
            log.warning("Fallback 1: read_user_config_raw() returned empty dict.")
    except Exception as exc:
        log.warning("Fallback 1 failed: %s: %s", type(exc).__name__, exc)

    # Layer 3: Direct YAML file read
    try:
        import os
        hermes_home = os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))
        config_path = Path(hermes_home) / "config.yaml"
        log.warning("Fallback 2: trying direct read from %s (exists=%s)",
                    config_path, config_path.exists())
        if config_path.exists():
            data = safe_load_yaml(config_path)
            if data:
                entry = data.get("plugins", {}).get("entries", {}).get(plugin_id, {})
                section = entry.get("settings") or entry.get("config") or {}
                if section:
                    log.warning("Fallback 2: read %d keys directly from %s.",
                                len(section), config_path)
                    return section
                log.warning("Fallback 2: file loaded but %s entry empty. "
                            "Top keys: %s", plugin_id, list(data.keys())[:15])
    except Exception as exc:
        log.warning("Fallback 2 failed: %s: %s", type(exc).__name__, exc)

    return {}


def safe_load_yaml(path: Path) -> dict | None:
    """Load YAML file with fallback to stdlib parser if PyYAML is unavailable.

    The project has ZERO runtime dependencies, so PyYAML may be absent (e.g. CI venvs).
    Falls back to secrets._load_yaml_mapping() when the optional import fails.
    """
    try:
        import yaml
    except ImportError:
        yaml = None

    if yaml is not None:
        with open(path, encoding="utf-8-sig") as f:
            return yaml.safe_load(f) or {}
    else:
        # Fallback to stdlib parser in secrets.py
        from .secrets import _load_yaml_mapping
        return _load_yaml_mapping(path)

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

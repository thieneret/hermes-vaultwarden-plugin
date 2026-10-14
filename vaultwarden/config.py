# vaultwarden/config.py — v0.2.2
"""Configuration loading for the Vaultwarden plugin (plan §4, §9).

Layers:
- Hermes config (via PluginContext.get_config()) -> non-secret settings
  (URLs, ids, flags, ENV VAR NAMES)
- .env              -> secret VALUES (chmod 600; loaded by Hermes secret_scope)
- plugin memory     -> resolved values, never written back to os.environ
- .bw-data/         -> isolated bw CLI state (chmod 700)

``load_config`` accepts a Hermes ``PluginContext`` exposing
``get_config(key, default)`` — the ONLY supported configuration path
(since v0.2.0; current version v0.2.2). Object-style contexts with
``.config`` / ``.plugin_config`` attributes are also accepted and
unwrapped until a ``get_config()`` API is found. There is NO fallback
to reading config.yaml directly.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from . import errors

log = logging.getLogger("hermes.plugins.vaultwarden.config")

# Hermes internal API for multiplex-aware secret resolution (v0.1.7).
# In multiplex gateway mode, .env values are NOT in os.environ; they live
# in a context-local scope accessible only via get_secret(). This import
# is optional: older Hermes versions or non-gateway modes fall back to
# os.environ.
try:
    from agent.secret_scope import get_secret as _hermes_get_secret
except ImportError:
    _hermes_get_secret = None

PLUGIN_DIR = Path(__file__).resolve().parent

_DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "server_url": "",
    "client_id": "",
    "client_secret_env": "VW_CLIENT_SECRET",
    "master_password_env": "VW_MASTER_PASSWORD",
    "appdata_dir_env": "VW_APPDATA_DIR",
    "allow_write": False,
    "allow_startup_secret_injection": False,
    "allow_direct_secret_retrieval": False,
    "auto_sync": True,
    "sync_interval_seconds": 300,
    "session_timeout_seconds": 14400,
    "auto_unlock": True,
    "placeholder_ttl_seconds": 300,
    "max_placeholders": 50,
    "bw_cli_path": "",
    "terminal_tool_names": [],
    "terminal_command_keys": [],
}


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _extract_section(source: Any) -> dict:
    """Extract plugin config using ONLY the Hermes-native get_config() API.

    Since v0.2.0: No fallback to config.yaml file reading. The plugin
    relies entirely on PluginContext.get_config() which reads from
    plugins.entries.<plugin_id>.settings.<key>.
    """
    if source is None:
        return {}

    # Hermes-native PluginContext.get_config() — plugin-relative keys
    getter = getattr(source, "get_config", None)
    if callable(getter):
        result: dict[str, Any] = {}
        for key in _DEFAULTS:
            try:
                value = getter(key, None)
            except Exception:
                continue
            if value is not None:
                result[key] = value
        return result

    # Object-style contexts (.config / .plugin_config)
    for attr in ("config", "plugin_config"):
        inner = getattr(source, attr, None)
        if inner is not None and inner is not source:
            return _extract_section(inner)

    raise errors.ConfigError(
        "Unsupported configuration source. "
        "This plugin requires Hermes PluginContext.get_config() API.")


@dataclass
class PluginConfig:
    section: dict = field(default_factory=dict)
    env_snapshot: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))

    def _raw(self, key: str) -> Any:
        return self.section.get(key, _DEFAULTS[key])

    # --- typed accessors ------------------------------------------------
    @property
    def enabled(self) -> bool:
        return _as_bool(self._raw("enabled"))

    @property
    def server_url(self) -> str:
        return str(self._raw("server_url") or "").rstrip("/")

    @property
    def client_id(self) -> str:
        return str(self._raw("client_id") or "")

    @property
    def client_secret_env_name(self) -> str:
        return str(self._raw("client_secret_env") or "VW_CLIENT_SECRET")

    @property
    def master_password_env_name(self) -> str:
        return str(self._raw("master_password_env") or "VW_MASTER_PASSWORD")

    @property
    def appdata_dir_env_name(self) -> str:
        return str(self._raw("appdata_dir_env") or "VW_APPDATA_DIR")

    @property
    def allow_write(self) -> bool:
        return _as_bool(self._raw("allow_write"))

    @property
    def allow_startup_secret_injection(self) -> bool:
        return _as_bool(self._raw("allow_startup_secret_injection"))

    @property
    def allow_direct_secret_retrieval(self) -> bool:
        return _as_bool(self._raw("allow_direct_secret_retrieval"))

    @property
    def auto_sync(self) -> bool:
        return _as_bool(self._raw("auto_sync"))

    @property
    def sync_interval_seconds(self) -> int:
        return _as_int(self._raw("sync_interval_seconds"), 300)

    @property
    def session_timeout_seconds(self) -> int:
        return _as_int(self._raw("session_timeout_seconds"), 14400)

    @property
    def auto_unlock(self) -> bool:
        return _as_bool(self._raw("auto_unlock"))

    @property
    def placeholder_ttl_seconds(self) -> int:
        return _as_int(self._raw("placeholder_ttl_seconds"), 300)

    @property
    def max_placeholders(self) -> int:
        return _as_int(self._raw("max_placeholders"), 50)

    @property
    def bw_cli_path(self) -> str:
        return str(self.env_snapshot.get("BW_CLI_PATH") or self._raw("bw_cli_path") or "")

    # v0.2.2 (BUGFIX): configurable terminal tool names / command keys.
    # Empty list => hooks.py falls back to its built-in defaults.
    @property
    def terminal_tool_names(self) -> list[str]:
        raw = self._raw("terminal_tool_names")
        if isinstance(raw, list):
            return [str(t) for t in raw]
        return []

    @property
    def terminal_command_keys(self) -> list[str]:
        raw = self._raw("terminal_command_keys")
        if isinstance(raw, list):
            return [str(k) for k in raw]
        return []

    # --- resolved secret values (memory only!) --------------------------
    def resolve_secret(self, var_name: str, *, required: bool = True) -> str:
        """Resolve a secret value by env-var name.

        Resolution order (v0.1.7):
        1. Hermes internal API (agent.secret_scope.get_secret) — multiplex-aware,
           fail-closed, respects profile isolation and external secret sources.
        2. Fallback to env_snapshot (os.environ copy) — for non-multiplex modes
           or older Hermes versions without secret_scope.
        """
        # 1. Hermes internal API (primary)
        if _hermes_get_secret is not None:
            try:
                value = _hermes_get_secret(var_name)
                if value is not None:
                    return str(value).strip()
            except Exception:
                # UnscopedSecretError or other scope issues — fall through
                pass

        # 2. Fallback to env_snapshot
        value = str(self.env_snapshot.get(var_name, "")).strip()
        if not value and required:
            raise errors.ConfigError(
                f"Secret environment variable '{var_name}' is not set.",
                suggestion=f"Add {var_name}=... to ~/.hermes/.env (chmod 600). "
                           "The NAME is configured in config.yaml, the VALUE lives in .env.",
            )
        return value

    def appdata_dir(self) -> Path:
        override = str(self.env_snapshot.get(self.appdata_dir_env_name, "")).strip()
        if override:
            return Path(override).expanduser()
        hermes_home = str(self.env_snapshot.get("HERMES_HOME", "")).strip()
        if hermes_home:
            return Path(hermes_home).expanduser() / "plugins" / "vaultwarden" / ".bw-data"
        return PLUGIN_DIR / ".bw-data"

    def validate(self) -> None:
        if not self.server_url:
            raise errors.ConfigError("secrets.vaultwarden.server_url is required.")
        if not self.client_id:
            raise errors.ConfigError("secrets.vaultwarden.client_id is required.")
        if not self.client_id.startswith("user."):
            raise errors.ConfigError(
                "client_id must be an API-key client id of the form 'user.<uuid>'.")
        if self.placeholder_ttl_seconds <= 0:
            raise errors.ConfigError("placeholder_ttl_seconds must be > 0.")
        if self.max_placeholders <= 0:
            raise errors.ConfigError("max_placeholders must be > 0.")


def load_config(source: Any = None, *, env: Mapping[str, str] | None = None) -> PluginConfig:
    """Build a PluginConfig from a Hermes PluginContext (see module doc)."""
    section = _extract_section(source)
    snapshot = dict(os.environ) if env is None else dict(env)
    return PluginConfig(section=section, env_snapshot=snapshot)

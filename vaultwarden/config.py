"""Configuration loading for the Vaultwarden plugin (plan §4, §9).

Layers:
- config.yaml       -> non-secret settings (URLs, ids, flags, ENV VAR NAMES)
- .env              -> secret VALUES (chmod 600; loaded by Hermes secret_scope)
- plugin memory     -> resolved values, never written back to os.environ
- .bw-data/         -> isolated bw CLI state (chmod 700)

``load_config`` accepts several shapes so it works with any Hermes context
version and is easy to unit test:
  * a plain dict (possibly nested under "secrets"->"vaultwarden")
  * a path to a YAML file
  * an object exposing ``get_config(key)`` / ``config`` attributes
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from . import errors

PLUGIN_DIR = Path(__file__).resolve().parent
DEFAULT_SECTION_KEY = "secrets.vaultwarden"

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


def _minimal_yaml_mapping(text: str) -> dict:
    """Very small fallback parser for flat ``key: value`` config files.

    Used ONLY when PyYAML is unavailable (BUG-7). It intentionally handles
    just the simple top-level mapping style used by minimal plugin configs;
    anything richer raises ConfigError with an actionable suggestion rather
    than silently mis-parsing.
    """
    result: dict[str, Any] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise errors.ConfigError(
                "Cannot parse config file without PyYAML (unsupported YAML "
                "construct). Install it with: pip install pyyaml")
        key, _, val = line.partition(":")
        val = val.strip().strip("'\"")
        result[key.strip()] = val
    return result


def _load_yaml_text(text: str) -> dict:
    """Parse YAML config text, degrading gracefully when PyYAML is missing."""
    try:
        import yaml  # PyYAML ships with Hermes — but is NOT guaranteed (BUG-7)
    except ImportError:
        try:
            from .security import get_logger
            get_logger("config").warning(
                "PyYAML not installed; using minimal key:value parser for "
                "YAML config sources. Run 'pip install pyyaml' for full support.")
        except Exception:
            pass
        data = _minimal_yaml_mapping(text)
        return data if isinstance(data, dict) else {}
    data = yaml.safe_load(text) or {}
    if not isinstance(data, Mapping):
        raise errors.ConfigError("Config YAML must be a mapping at the top level.")
    return dict(data)


def _extract_section(source: Any) -> dict:
    """Normalise arbitrary config sources into the vaultwarden mapping."""
    if source is None:
        return {}

    if isinstance(source, (str, Path)):
        path = Path(source)
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        data = _load_yaml_text(text)
        return _extract_section(data)

    if isinstance(source, Mapping):
        node: Any = source
        # walk: {"secrets": {"vaultwarden": {...}}} or already the section
        if "secrets" in node and isinstance(node["secrets"], Mapping):
            node = node["secrets"]
        if "vaultwarden" in node and isinstance(node["vaultwarden"], Mapping):
            node = node["vaultwarden"]
        return dict(node)

    # Object-style contexts
    for attr in ("config", "plugin_config"):
        inner = getattr(source, attr, None)
        if inner is not None and inner is not source:
            return _extract_section(inner)
    getter = getattr(source, "get_config", None)
    if callable(getter):
        try:
            got = getter(DEFAULT_SECTION_KEY)
            if isinstance(got, Mapping):
                return dict(got)
        except Exception:
            pass
    raise errors.ConfigError("Unsupported configuration source.")


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

    # --- resolved secret values (memory only!) --------------------------
    def resolve_secret(self, var_name: str, *, required: bool = True) -> str:
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
    """Build a PluginConfig from a Hermes ctx/config/dict/path (see module doc)."""
    section = _extract_section(source)
    snapshot = dict(os.environ) if env is None else dict(env)
    return PluginConfig(section=section, env_snapshot=snapshot)

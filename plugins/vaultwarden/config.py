"""Configuration loading for the Vaultwarden plugin (plan §4, §9).

Layers:
- Hermes config (via PluginContext.get_config()) -> non-secret settings
  (URLs, ids, flags)
- secrets.yaml      -> bootstrap secret VALUES (chmod 600; read directly by
  secrets.py — v0.5.0 BREAKING: the .env / resolve_secret() channel is gone,
  secrets never enter the OS environment or Hermes secret_scope)
- plugin memory     -> resolved values, never written back to os.environ
- .bw-data/         -> isolated bw CLI state (chmod 700)

``load_config`` accepts a Hermes ``PluginContext`` exposing
``get_config(key, default)`` — the ONLY supported configuration path
(since v0.2.0; current version v0.2.3). Object-style contexts with
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

from . import compat, errors

log = logging.getLogger("hermes.plugins.vaultwarden.config")

PLUGIN_DIR = Path(__file__).resolve().parent

_DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "server_url": "",
    "client_id": "",
    # v0.5.0 (BREAKING): client_secret_env / master_password_env REMOVED —
    # bootstrap secrets now live in $HERMES_HOME/plugins/vaultwarden/
    # secrets.yaml (chmod 600), loaded directly by secrets.py. They never
    # enter the OS environment or Hermes secret_scope.
    "appdata_dir_env": "VW_APPDATA_DIR",
    "allow_write": False,
    "allow_startup_secret_injection": False,
    # v0.3.7 (VWP-14): allow_direct_secret_retrieval REMOVED entirely.
    # There is no code path that returns a raw secret to the LLM; the
    # placeholder model is the only supported path for secret access.
    "auto_sync": True,
    "sync_interval_seconds": 300,
    "session_timeout_seconds": 14400,
    "placeholder_ttl_seconds": 300,
    "max_placeholders": 50,
    "bw_cli_path": "",
    # VWP-10 (v0.3.8): retry / backoff for idempotent bw calls.
    "bw_max_retries": 3,
    "bw_backoff_base": 1.0,
    "bw_max_delay": 10.0,
    "terminal_tool_names": [],
    "terminal_command_keys": [],
    # VWP-13 (v0.4.3): metadata masking for list/search responses (opt-in).
    "metadata_masking": False,
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
    """Extract plugin config — tries Hermes API first, falls back to direct YAML read."""
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
        if result:
            return result

    # FALLBACK 1 & 2: handled by compat.extract_plugin_section() (VWP-17)
    section = compat.extract_plugin_section(source, plugin_id="vaultwarden")
    if section:
        return section

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
    # v0.5.0 (BREAKING): env_snapshot removed — the plugin no longer reads
    # secret VALUES from the environment. The optional ``env`` mapping passed
    # to load_config() is consulted ONLY for non-secret path overrides
    # (VW_APPDATA_DIR / HERMES_HOME); when absent, os.environ is used.
    # NOTE: the field name is underscored so PluginConfig(section=...) keeps
    # working unchanged; load_config() assigns it after construction.
    _env: Mapping[str, str] | None = field(default=None, repr=False,
                                           compare=False)

    def _lookup_env(self, key: str) -> str:
        """Non-secret env lookup: explicit mapping first, then os.environ."""
        if self._env is not None:
            return str(self._env.get(key, "") or "").strip()
        return str(os.environ.get(key, "") or "").strip()

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
    def appdata_dir_env_name(self) -> str:
        return str(self._raw("appdata_dir_env") or "VW_APPDATA_DIR")

    @property
    def allow_write(self) -> bool:
        return _as_bool(self._raw("allow_write"))

    @property
    def allow_startup_secret_injection(self) -> bool:
        return _as_bool(self._raw("allow_startup_secret_injection"))

    # VWP-13 (v0.4.3): when True, vaultwarden_list / vaultwarden_search mask
    # `username` and `uris` with "***". Default OFF preserves usability.
    @property
    def metadata_masking(self) -> bool:
        return _as_bool(self._raw("metadata_masking"))

    # v0.3.7 (VWP-14): allow_direct_secret_retrieval property removed —
    # direct secret retrieval no longer exists anywhere in the plugin.

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
    def placeholder_ttl_seconds(self) -> int:
        return _as_int(self._raw("placeholder_ttl_seconds"), 300)

    @property
    def max_placeholders(self) -> int:
        return _as_int(self._raw("max_placeholders"), 50)

    @property
    def bw_cli_path(self) -> str:
        # VWP-01 (v0.4.7 BREAKING): the former environment-variable
        # override is REMOVED — config.yaml is the single source of truth.
        # v0.5.0 keeps a MINIMAL os.environ check here solely so an empty
        # BW_CLI_PATH env var cannot resurrect the override; secrets never
        # flow through this channel (bootstrap secrets live in secrets.yaml).
        if os.environ.get("BW_CLI_PATH", "").strip():
            log.warning("BW_CLI_PATH is set but IGNORED (VWP-01): "
                        "bw_cli_path in config.yaml is the only source.")
        return str(self._raw("bw_cli_path") or "")

    # v0.2.2 (BUGFIX): configurable terminal tool names / command keys.
    # Empty list => hooks.py falls back to its built-in defaults.
    # VWP-10 (v0.3.8): retry / backoff accessors. NOTE: the minimum bw
    # version is NOT configurable (VWP-11 design decision — fail-closed,
    # no override; see bw_cli._MIN_BW_VERSION).
    @property
    def bw_max_retries(self) -> int:
        return _as_int(self._raw("bw_max_retries"), 3)

    @property
    def bw_backoff_base(self) -> float:
        try:
            return float(self._raw("bw_backoff_base"))
        except (TypeError, ValueError):
            return 1.0

    @property
    def bw_max_delay(self) -> float:
        try:
            return float(self._raw("bw_max_delay"))
        except (TypeError, ValueError):
            return 10.0

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

    # --- appdata dir -----------------------------------------------------
    # v0.5.0 (BREAKING): resolve_secret() REMOVED entirely. Bootstrap secret
    # values no longer come from the environment / Hermes secret_scope; they
    # are loaded directly from secrets.yaml by secrets.load_secrets().
    def appdata_dir(self) -> Path:
        override = self._lookup_env(self.appdata_dir_env_name)
        if override:
            return Path(override).expanduser()
        hermes_home = self._lookup_env("HERMES_HOME")
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
        # v0.5.0: the master password VALUE is enforced by
        # secrets.load_secrets() at registration time (fail closed if the
        # key is missing/empty in secrets.yaml) — nothing to check here.
        if self.placeholder_ttl_seconds <= 0:
            raise errors.ConfigError("placeholder_ttl_seconds must be > 0.")
        if self.max_placeholders <= 0:
            raise errors.ConfigError("max_placeholders must be > 0.")


def load_config(source: Any = None, *, env: Mapping[str, str] | None = None) -> PluginConfig:
    """Build a PluginConfig from a Hermes PluginContext (see module doc).

    The ``env`` keyword argument is consulted ONLY for non-secret path
    overrides (VW_APPDATA_DIR / BW_CLI_PATH / HERMES_HOME). v0.5.0 BREAKING:
    secret VALUES are never read from any environment mapping — they live in
    secrets.yaml, loaded by secrets.py. When ``env`` is omitted, os.environ
    is used for the remaining path overrides.
    """
    section = _extract_section(source)
    if not section:
        log.warning(
            "Vaultwarden plugin config is EMPTY: no settings found via "
            "PluginContext.get_config(). Add your configuration to "
            "plugins.entries.vaultwarden.settings in config.yaml. "
            "Plugin will use defaults (enabled=false) and will not load.")
    cfg = PluginConfig(section=section)
    cfg._env = env  # non-secret path overrides only (see load_config doc)
    return cfg

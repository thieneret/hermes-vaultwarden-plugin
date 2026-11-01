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
(since v0.2.0; VWP-05 in v0.5.2 removed the former config fallback layers
after diagnostic testing confirmed the native API resolves config values
correctly). Object-style contexts with ``.config`` / ``.plugin_config``
attributes are also accepted and unwrapped until a ``get_config()`` API is
found. There is NO fallback to reading config.yaml directly.
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
    # SEC-03 (v0.5.5): fail-closed policy for the 'local' terminal backend.
    # With backend 'local' (or unset) the LLM-driven terminal executes as the
    # SAME OS user that owns secrets.yaml and could simply `cat` it, so the
    # plugin REFUSES to load unless the operator explicitly opts in by setting
    # this flag to true. Any ambiguity resolves to false — never fail open.
    "allow_insecure_local_backend": False,
    # AUD-01 (v0.6.9): fail-closed HTTPS enforcement for server_url. Default
    # FALSE: validate() rejects any non-https scheme. Setting TRUE permits
    # ONLY http:// (local/testing); ftp/file/ws/missing schemes remain
    # rejected regardless — never fail open.
    "allow_insecure_http": False,
    # v0.5.3: startup-injection mappings consumed by the optional
    # SecretSource adapter (see __init__.py / secret_source.py). Listed in
    # _DEFAULTS so extract_plugin_section() picks them up via the native
    # get_config() API; mapping validation happens in VaultwardenSecretSource.
    "startup_injections": [],
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


def _sanitize_url_for_logging(url: str) -> str:
    """HVA-02 (v0.7.1): return scheme://hostname[:port] only.

    Strips user-info (username/password), path, query, and fragment so a
    server URL can NEVER leak credentials or sensitive parameters into log
    records or diagnostic output. Port is included only when it is not the
    scheme's default (80/443).
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if not parsed.hostname:
        return "<invalid>"
    result = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port and parsed.port not in (80, 443):
        result += f":{parsed.port}"
    return result


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _extract_section(source: Any) -> dict:
    """Extract plugin config — native Hermes API only (VWP-05)."""
    if source is None:
        return {}

    # Hermes-native PluginContext.get_config() — plugin-relative keys.
    # VWP-05: the former config fallback layers (hermes_cli raw-YAML reader,
    # direct YAML file read) are REMOVED; the native API resolves config
    # correctly.
    getter = getattr(source, "get_config", None)
    if callable(getter):
        section = compat.extract_plugin_section(source, plugin_id="vaultwarden")
        if not section:
            log.warning(
                "Vaultwarden plugin config is EMPTY: no settings found via "
                "PluginContext.get_config(). Add your configuration to "
                "plugins.entries.vaultwarden.settings in config.yaml. "
                "Plugin will use defaults (enabled=false) and will not load.")
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
        # Canonical value used by validate(), auth comparison, `bw config
        # server`, and status snapshots. HVA-02 guarantees via fail-closed
        # validate() + log-site sanitization that no user-info / query /
        # fragment material ever reaches logging or diagnostic output.
        return str(self._raw("server_url") or "").rstrip("/")

    @property
    def server_url_sanitized(self) -> str:
        # HVA-02 (v0.7.1): defence-in-depth on the display/log path — a
        # hostile value that somehow survives validate() (e.g. the config
        # section mutated after validation) is reduced to
        # scheme://host[:port] here, so user-info / query / fragment
        # material can NEVER reach a consumer that reads this accessor.
        # Status/diagnostic payloads use this property instead of
        # ``server_url``.  The canonical ``server_url`` stays verbatim on
        # purpose: functional consumers (auth server-match comparison,
        # ``bw config server``) need the exact configured URL, and several
        # tests assert round-trip fidelity of the raw value.
        url = self.server_url
        if not url:
            return url
        sanitized = _sanitize_url_for_logging(url)
        if sanitized == "<invalid>":
            # Unparseable / host-less value: never hand it to a logger.
            return ""
        return sanitized

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

    # SEC-03 (v0.5.5): explicit opt-in for running with a 'local' terminal
    # backend, where the LLM executes as the SAME OS user that owns
    # secrets.yaml and could read it directly (`cat secrets.yaml`). Default
    # FALSE = fail-closed: register() refuses to load on a local/unset
    # backend unless the operator accepts the risk in writing. The value is
    # read ONLY through the native PluginContext.get_config() section
    # (VWP-05) — there is NO .env / OS-environment channel for this flag.
    @property
    def allow_insecure_local_backend(self) -> bool:
        return _as_bool(self._raw("allow_insecure_local_backend"))

    # AUD-01 (v0.6.9): explicit opt-in permitting cleartext http:// server_url
    # for local/testing deployments ONLY. Default FALSE = fail-closed:
    # validate() requires https://. This flag permits ONLY http:// — it never
    # permits any other scheme (ftp/file/ws/missing are always rejected).
    @property
    def allow_insecure_http(self) -> bool:
        return _as_bool(self._raw("allow_insecure_http"))

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
            # VWP-01 (v0.4.7 BREAKING): env override removed — this warning
            # only informs operators that the legacy variable is inert.
            log.warning("BW_CLI_PATH is set but IGNORED: "
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

    def _validate_server_url_scheme(self) -> None:
        """AUD-01 (v0.6.9): strictly enforce https:// server_url.

        Fail-closed: only https:// is accepted by default. The explicit
        ``allow_insecure_http`` override permits ONLY http:// — every other
        scheme (ftp/file/ws/missing/empty) is rejected regardless of the
        flag. The WARNING log contains ONLY the scheme and hostname — never
        credentials, paths, query strings, or session data.

        HVA-02 (v0.7.1): additionally rejects URLs containing user-info
        (username/password), query parameters, or fragments. These
        components could leak sensitive material into logging or diagnostic
        output, so validation is fail-closed: any prohibited component
        present => ConfigError. The path component remains allowed.
        """
        from urllib.parse import urlparse

        parsed = urlparse(self.server_url)
        scheme = parsed.scheme.lower()

        if scheme == "https":
            pass  # accepted (AUD-01)
        elif scheme == "http":
            if self.allow_insecure_http:
                log.warning(
                    "server_url uses insecure scheme 'http' for host %s "
                    "(allow_insecure_http=true). Credentials travel in "
                    "plaintext. Disable in production.",
                    parsed.hostname or "<unknown>",
                )
            else:
                raise errors.ConfigError(
                    "secrets.vaultwarden.server_url must use https://. "
                    "Set allow_insecure_http: true to permit http:// for "
                    "local/testing environments."
                )
        else:
            raise errors.ConfigError(
                "secrets.vaultwarden.server_url has unsupported scheme "
                f"'{scheme}'; only https:// is accepted."
            )

        # HVA-02 (v0.7.1): reject sensitive URL components — fail-closed.
        # Checked AFTER scheme enforcement so AUD-01 rejection messages keep
        # their precedence; every prohibited component raises ConfigError.
        if parsed.username or parsed.password:
            raise errors.ConfigError(
                "secrets.vaultwarden.server_url must not contain user-info "
                "(username/password). Use separate authentication mechanisms."
            )
        if parsed.query:
            raise errors.ConfigError(
                "secrets.vaultwarden.server_url must not contain query "
                "parameters. Sensitive data in query strings may be logged."
            )
        if parsed.fragment:
            raise errors.ConfigError(
                "secrets.vaultwarden.server_url must not contain fragments. "
                "Fragments are not transmitted but may indicate "
                "misconfiguration."
            )

    def validate(self) -> None:
        if not self.server_url:
            raise errors.ConfigError("secrets.vaultwarden.server_url is required.")
        self._validate_server_url_scheme()
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
    # NOTE: _extract_section() logs the "config is EMPTY" warning itself
    # (VWP-05: native API only, no fallback layers).
    section = _extract_section(source)
    cfg = PluginConfig(section=section)
    cfg._env = env  # non-secret path overrides only (see load_config doc)
    return cfg

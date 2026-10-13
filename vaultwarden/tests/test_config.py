"""Unit tests: config loading via the Hermes get_config() API ONLY (v0.2.0).

There is no fallback to config.yaml file reading any more — these tests
verify the get_config() path, defaults for missing config, and that an
unsupported source raises ConfigError.
"""
from __future__ import annotations

import pytest

from vaultwarden.config import load_config, PluginConfig
from vaultwarden.errors import ConfigError


class FakePluginContext:
    """Simulates Hermes PluginContext.get_config() behaviour."""

    def __init__(self, settings: dict):
        self._settings = settings

    def get_config(self, key: str, default=None):
        return self._settings.get(key, default)


def test_get_config_api_path():
    ctx = FakePluginContext({
        "enabled": True,
        "server_url": "https://x",
        "client_id": "user.abc-123",
    })
    cfg = load_config(ctx, env={})
    assert cfg.enabled is True and cfg.server_url == "https://x"


def test_defaults_when_no_settings():
    cfg = load_config(FakePluginContext({}), env={})
    assert cfg.enabled is False
    assert cfg.allow_write is False
    assert cfg.allow_startup_secret_injection is False
    assert cfg.allow_direct_secret_retrieval is False
    assert cfg.auto_sync is True
    assert cfg.sync_interval_seconds == 300
    assert cfg.session_timeout_seconds == 14400
    assert cfg.auto_unlock is True
    assert cfg.placeholder_ttl_seconds == 300
    assert cfg.max_placeholders == 50
    assert cfg.client_secret_env_name == "VW_CLIENT_SECRET"
    assert cfg.master_password_env_name == "VW_MASTER_PASSWORD"


def test_none_source_returns_defaults():
    cfg = load_config(None, env={})
    assert isinstance(cfg, PluginConfig)
    assert cfg.enabled is False


def test_plain_dict_raises_config_error():
    # v0.2.0: raw dicts are NOT a supported source any more — only
    # PluginContext.get_config() (or object-style contexts wrapping one).
    with pytest.raises(ConfigError):
        load_config({"server_url": "https://x"}, env={})


def test_unsupported_object_raises_config_error():
    class NoConfigApi:
        pass

    with pytest.raises(ConfigError):
        load_config(NoConfigApi(), env={})


def test_resolve_secret_uses_snapshot_not_os_environ(monkeypatch):
    monkeypatch.delenv("VW_CLIENT_SECRET", raising=False)
    cfg = load_config(FakePluginContext({}),
                      env={"VW_CLIENT_SECRET": "from-dot-env"})
    assert cfg.resolve_secret("VW_CLIENT_SECRET") == "from-dot-env"
    with pytest.raises(ConfigError):
        cfg.resolve_secret("MISSING_VAR")


def test_appdata_dir_default_and_override(tmp_path):
    cfg = load_config(FakePluginContext({}), env={"HERMES_HOME": str(tmp_path)})
    assert cfg.appdata_dir() == tmp_path / "plugins" / "vaultwarden" / ".bw-data"

    override = tmp_path / "elsewhere"
    cfg2 = load_config(FakePluginContext({}),
                       env={"VW_APPDATA_DIR": str(override)})
    assert cfg2.appdata_dir() == override


def test_validate_catches_missing_fields():
    cfg = load_config(FakePluginContext({"enabled": True}), env={})
    with pytest.raises(ConfigError):
        cfg.validate()
    cfg2 = load_config(FakePluginContext({
        "enabled": True, "server_url": "https://v", "client_id": "org.abc"}), env={})
    with pytest.raises(ConfigError):
        cfg2.validate()  # client id must be user.<uuid>
    cfg3 = load_config(FakePluginContext({
        "enabled": True, "server_url": "https://v", "client_id": "user.abc"}), env={})
    cfg3.validate()  # ok


def test_bool_string_coercion():
    cfg = load_config(FakePluginContext({"enabled": "true",
                                         "allow_write": "yes"}), env={})
    assert cfg.enabled and cfg.allow_write

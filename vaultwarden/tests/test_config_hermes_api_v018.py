"""v0.1.8 regression tests: Hermes-native plugin config via get_config().

v0.2.0 cleanup: fallback config.yaml reading was removed, so only the
get_config() API path (and object-style contexts wrapping it) is tested.
"""
from __future__ import annotations

import pytest
from vaultwarden.config import load_config
from vaultwarden.errors import ConfigError


class FakePluginContext:
    """Simulates Hermes PluginContext.get_config() behaviour."""
    def __init__(self, settings: dict):
        self._settings = settings

    def get_config(self, key: str, default=None):
        return self._settings.get(key, default)


def test_get_config_api_plugin_relative_keys():
    ctx = FakePluginContext({
        "enabled": True,
        "server_url": "https://vault.example.com",
        "client_id": "user.abc-123",
        "client_secret_env": "VW_CLIENT_SECRET",
        "allow_write": True,
        "bw_cli_path": "/opt/data/bin/bw",
    })
    cfg = load_config(ctx, env={})
    assert cfg.enabled is True
    assert cfg.server_url == "https://vault.example.com"
    assert cfg.client_id == "user.abc-123"
    assert cfg.allow_write is True
    assert cfg.bw_cli_path == "/opt/data/bin/bw"
    # unset keys fall back to _DEFAULTS
    assert cfg.auto_sync is True
    assert cfg.sync_interval_seconds == 300


def test_get_config_empty_settings_uses_defaults(no_config_fallback):
    cfg = load_config(FakePluginContext({}), env={})
    assert cfg.enabled is False
    assert cfg.server_url == ""


def test_object_style_context_wrapping_get_config():
    class Wrapper:
        def __init__(self, inner):
            self.config = inner

    inner = FakePluginContext({"enabled": True, "server_url": "https://wrapped"})
    cfg = load_config(Wrapper(inner), env={})
    assert cfg.enabled is True
    assert cfg.server_url == "https://wrapped"


def test_get_config_raising_is_tolerated(no_config_fallback):
    class BrokenCtx:
        def get_config(self, key, default=None):
            raise RuntimeError("no manifest")
    # Must not raise; falls back to defaults.
    cfg = load_config(BrokenCtx(), env={})
    assert cfg.enabled is False


def test_no_file_or_dict_fallback(monkeypatch, tmp_path, no_config_fallback):
    """v0.2.0: raw mappings and file paths are NOT valid sources anymore."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(
        "plugins:\n  entries:\n    vaultwarden:\n      settings:\n"
        "        enabled: true\n        server_url: https://should-not-load\n")
    with pytest.raises(ConfigError):
        load_config(str(tmp_path / "config.yaml"), env={})
    with pytest.raises(ConfigError):
        load_config({"plugins": {"entries": {"vaultwarden": {"settings": {
            "server_url": "https://should-not-load"}}}}}, env={})

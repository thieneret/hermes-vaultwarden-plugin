"""v1.8 regression tests: Hermes-native plugin config via get_config()."""
from __future__ import annotations

import pytest
from vaultwarden.config import load_config


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


def test_get_config_empty_settings_uses_defaults():
    cfg = load_config(FakePluginContext({}), env={})
    assert cfg.enabled is False
    assert cfg.server_url == ""


def test_new_settings_layout_dict():
    source = {
        "plugins": {"entries": {"vaultwarden": {"settings": {
            "enabled": True,
            "server_url": "https://new.example.com",
            "client_id": "user.xyz",
        }}}}
    }
    cfg = load_config(source, env={})
    assert cfg.enabled is True
    assert cfg.server_url == "https://new.example.com"


def test_legacy_secrets_layout_still_works():
    source = {
        "secrets": {"vaultwarden": {
            "enabled": True,
            "server_url": "https://legacy.example.com",
            "client_id": "user.legacy",
        }}
    }
    cfg = load_config(source, env={})
    assert cfg.enabled is True
    assert cfg.server_url == "https://legacy.example.com"


def test_get_config_raising_is_tolerated():
    class BrokenCtx:
        def get_config(self, key, default=None):
            raise RuntimeError("no manifest")
    # Must not raise; falls back to defaults.
    cfg = load_config(BrokenCtx(), env={})
    assert cfg.enabled is False

"""Unit tests: config loading, env-var-name indirection, defaults, validation."""
from __future__ import annotations

import pytest

from vaultwarden.config import load_config, PluginConfig
from vaultwarden.errors import ConfigError


def test_flat_dict_and_nested_forms():
    flat = {"server_url": "https://x", "enabled": True}
    nested = {"secrets": {"vaultwarden": {"server_url": "https://x", "enabled": True}}}
    for src in (flat, nested):
        cfg = load_config(src, env={})
        assert cfg.enabled is True and cfg.server_url == "https://x"


def test_defaults_match_plan():
    cfg = load_config({"secrets": {"vaultwarden": {}}}, env={})
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


def test_resolve_secret_uses_snapshot_not_os_environ(monkeypatch):
    monkeypatch.delenv("VW_CLIENT_SECRET", raising=False)
    cfg = load_config({"secrets": {"vaultwarden": {}}},
                      env={"VW_CLIENT_SECRET": "from-dot-env"})
    assert cfg.resolve_secret("VW_CLIENT_SECRET") == "from-dot-env"
    with pytest.raises(ConfigError):
        cfg.resolve_secret("MISSING_VAR")


def test_appdata_dir_default_and_override(tmp_path):
    cfg = load_config({"secrets": {"vaultwarden": {}}}, env={"HERMES_HOME": str(tmp_path)})
    assert cfg.appdata_dir() == tmp_path / "plugins" / "vaultwarden" / ".bw-data"

    override = tmp_path / "elsewhere"
    cfg2 = load_config({"secrets": {"vaultwarden": {}}},
                       env={"VW_APPDATA_DIR": str(override)})
    assert cfg2.appdata_dir() == override


def test_validate_catches_missing_fields():
    cfg = load_config({"secrets": {"vaultwarden": {"enabled": True}}}, env={})
    with pytest.raises(ConfigError):
        cfg.validate()
    cfg2 = load_config({"secrets": {"vaultwarden": {
        "enabled": True, "server_url": "https://v", "client_id": "org.abc"}}}, env={})
    with pytest.raises(ConfigError):
        cfg2.validate()  # client id must be user.<uuid>
    cfg3 = load_config({"secrets": {"vaultwarden": {
        "enabled": True, "server_url": "https://v", "client_id": "user.abc"}}}, env={})
    cfg3.validate()  # ok


def test_bool_string_coercion():
    cfg = load_config({"secrets": {"vaultwarden": {"enabled": "true",
                                                   "allow_write": "yes"}}}, env={})
    assert cfg.enabled and cfg.allow_write


def test_yaml_file_source(tmp_path):
    f = tmp_path / "config.yaml"
    f.write_text("secrets:\n  vaultwarden:\n    enabled: true\n"
                 "    server_url: https://from-yaml\n")
    cfg = load_config(f, env={})
    assert cfg.enabled and cfg.server_url == "https://from-yaml"

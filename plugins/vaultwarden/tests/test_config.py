"""Unit tests: config loading via the Hermes get_config() API ONLY (v0.2.0).

There is no fallback to config.yaml file reading any more — these tests
verify the get_config() path, defaults for missing config, and that an
unsupported source raises ConfigError.
"""
from __future__ import annotations

import pytest

from vaultwarden.config import PluginConfig, load_config
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


def test_defaults_when_no_settings(no_config_fallback):
    cfg = load_config(FakePluginContext({}), env={})
    assert cfg.enabled is False
    assert cfg.allow_write is False
    assert cfg.allow_startup_secret_injection is False
    # v0.3.7 (VWP-14): allow_direct_secret_retrieval removed entirely —
    # the escape hatch no longer exists on PluginConfig.
    assert not hasattr(cfg, "allow_direct_secret_retrieval")
    assert cfg.auto_sync is True
    assert cfg.sync_interval_seconds == 300
    assert cfg.session_timeout_seconds == 14400
    # v0.2.3 (BREAKING): auto_unlock removed — vault is ALWAYS auto-unlocked.
    assert not hasattr(cfg, "auto_unlock")
    assert cfg.placeholder_ttl_seconds == 300
    assert cfg.max_placeholders == 50
    # v0.5.0 (BREAKING): env-based secret accessors are gone entirely.
    assert not hasattr(cfg, "client_secret_env_name")
    assert not hasattr(cfg, "master_password_env_name")
    assert not hasattr(cfg, "resolve_secret")
    assert not hasattr(cfg, "env_snapshot")


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


def test_resolve_secret_removed_in_breaking_release(monkeypatch, no_config_fallback):
    """v0.5.0 BREAKING: the .env/secret_scope resolution channel is gone."""
    from vaultwarden import config as vw_config
    cfg = load_config(FakePluginContext({}))
    assert not hasattr(cfg, "resolve_secret")
    assert not hasattr(vw_config, "_hermes_get_secret")


def test_appdata_dir_default_and_override(tmp_path, no_config_fallback):
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


def test_validate_no_longer_references_env_secret_keys():
    # v0.5.0: validate() has nothing to say about *_env keys any more — the
    # secret VALUES are enforced by secrets.load_secrets() at registration.
    cfg = load_config(FakePluginContext({
        "enabled": True, "server_url": "https://v", "client_id": "user.abc"}))
    cfg.validate()  # ok


def test_bool_string_coercion():
    cfg = load_config(FakePluginContext({"enabled": "true",
                                         "allow_write": "yes"}), env={})
    assert cfg.enabled and cfg.allow_write


# ---------------------------------------------------------------------------
# Consolidated from test_config_hermes_api_v018.py (v0.2.9 test restructure)
# ---------------------------------------------------------------------------

def test_get_config_api_plugin_relative_keys():
    ctx = FakePluginContext({
        "enabled": True,
        "server_url": "https://vault.example.com",
        "client_id": "user.abc-123",
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


# ---------------------------------------------------------------------------
# Consolidated from test_cleanup_hardening_v023.py (config parts)
# ---------------------------------------------------------------------------

def test_auto_unlock_removed():
    """v0.2.3: auto_unlock key must not exist in config defaults or plugin.yaml."""
    from vaultwarden.config import _DEFAULTS
    assert "auto_unlock" not in _DEFAULTS

    from pathlib import Path

    import vaultwarden
    yaml_path = Path(vaultwarden.__file__).resolve().parent / "plugin.yaml"
    text = yaml_path.read_text()
    assert "auto_unlock" not in text


def test_master_password_mandatory_via_secrets_yaml(tmp_path):
    """v0.5.0: missing master password VALUE must fail at load_secrets()."""
    from vaultwarden import errors
    from vaultwarden.secrets import load_secrets

    home = tmp_path / "hh"
    plug = home / "plugins" / "vaultwarden"
    plug.mkdir(parents=True)
    f = plug / "secrets.yaml"
    f.write_text("client_secret: cs\nmaster_password: \"\"\n")
    f.chmod(0o600)
    with pytest.raises(errors.ConfigError) as ei:
        load_secrets(str(home))
    assert "master_password" in str(ei.value.message)


# ---------------------------------------------------------------------------
# Consolidated from test_bugfixes_v12.py (BUG-6/7 config & misc parts)
# ---------------------------------------------------------------------------

def test_config_dict_source_needs_no_yaml(monkeypatch):
    """Plugin config loads from a plain dict even when PyYAML is missing."""
    import builtins
    import sys
    real_import = builtins.__import__

    def blocked(name, *a, **k):
        if name == "yaml" or name.startswith("yaml."):
            raise ImportError("No module named 'yaml'")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", blocked)
    monkeypatch.delitem(sys.modules, "yaml", raising=False)
    from vaultwarden.tests.conftest import make_config
    cfg = make_config(section={"server_url": "https://vw.example"})
    assert cfg.server_url == "https://vw.example"     # no crash, no yaml import


def test_config_file_source_rejected_without_yaml(tmp_path, monkeypatch):
    """v0.2.0: file-path sources are no longer supported at all — the plugin
    reads config ONLY via PluginContext.get_config(), so no YAML parsing is
    required and a path source raises ConfigError even without PyYAML."""
    import builtins
    import sys
    real_import = builtins.__import__

    def blocked(name, *a, **k):
        if name == "yaml" or name.startswith("yaml."):
            raise ImportError("No module named 'yaml'")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", blocked)
    monkeypatch.delitem(sys.modules, "yaml", raising=False)

    f = tmp_path / "flat.yaml"
    f.write_text("enabled: true\nserver_url: https://from-fallback\n")
    with pytest.raises(ConfigError):
        load_config(str(f), env={})


def test_plugin_yaml_documents_full_binary_path():
    text = open(str(__import__("pathlib").Path(
        __file__).resolve().parents[1] / "plugin.yaml"), encoding="utf-8").read()
    assert "FULL path" in text
    assert "directory path alone is NOT sufficient" in text


# ---------------------------------------------------------------------------
# VWP-10 (v0.3.8): retry / backoff config options. Exactly three new keys —
# the minimum bw version stays NON-configurable (VWP-11 design decision).
# ---------------------------------------------------------------------------

class TestRetryBackoffConfig:
    def test_defaults(self, plugin_config):
        assert plugin_config.bw_max_retries == 3
        assert plugin_config.bw_backoff_base == 1.0
        assert plugin_config.bw_max_delay == 10.0

    def test_overrides_parsed(self):
        from vaultwarden.tests.conftest import make_config
        cfg = make_config(section={
            "bw_max_retries": 5,
            "bw_backoff_base": 0.5,
            "bw_max_delay": 30,
        })
        assert cfg.bw_max_retries == 5
        assert cfg.bw_backoff_base == 0.5
        assert cfg.bw_max_delay == 30.0

    def test_bad_values_fall_back_to_defaults(self):
        from vaultwarden.tests.conftest import make_config
        cfg = make_config(section={
            "bw_max_retries": "not-an-int",
            "bw_backoff_base": "nan-ish",
            "bw_max_delay": None,
        })
        assert cfg.bw_max_retries == 3
        assert cfg.bw_backoff_base == 1.0
        assert cfg.bw_max_delay == 10.0

    def test_no_version_options_regression_guard(self):
        # Step-1 invariant: bw version enforcement is fail-closed with NO
        # override and must NEVER become a configuration option.
        from vaultwarden.config import _DEFAULTS, PluginConfig
        assert "min_bw_version" not in _DEFAULTS
        assert "allow_untested_bw_version" not in _DEFAULTS
        assert not hasattr(PluginConfig, "min_bw_version")
        assert not hasattr(PluginConfig, "allow_untested_bw_version")


class TestMetadataMaskingConfig:
    """VWP-13 (v0.4.3): metadata_masking config option."""

    def test_default_is_false(self):
        from vaultwarden.tests.conftest import make_config
        assert make_config().metadata_masking is False

    def test_parses_true(self):
        from vaultwarden.tests.conftest import make_config
        cfg = make_config(section={"metadata_masking": True})
        assert cfg.metadata_masking is True

    def test_parses_string_true_false(self):
        from vaultwarden.tests.conftest import make_config
        assert make_config(section={"metadata_masking": "true"}).metadata_masking is True
        assert make_config(section={"metadata_masking": "false"}).metadata_masking is False

    def test_in_defaults_registry(self):
        from vaultwarden.config import _DEFAULTS
        assert "metadata_masking" in _DEFAULTS
        assert _DEFAULTS["metadata_masking"] is False

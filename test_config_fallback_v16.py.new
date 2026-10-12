"""v1.6 regression tests: nested-YAML fallback section extraction (no PyYAML)."""
from __future__ import annotations

import builtins
import sys

import pytest

from vaultwarden.config import load_config, _extract_nested_section


@pytest.fixture
def no_yaml(monkeypatch):
    real_import = builtins.__import__

    def blocked(name, *a, **k):
        if name == "yaml" or name.startswith("yaml."):
            raise ImportError("No module named 'yaml'")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", blocked)
    monkeypatch.delitem(sys.modules, "yaml", raising=False)


def test_extract_full_real_world_config(tmp_path, no_yaml):
    """Reproduces the actual Hermes config.yaml shape with sibling sections."""
    text = (
        "plugins:\n"
        "  enabled:\n"
        "    - vaultwarden\n"
        "secrets:\n"
        "  vaultwarden:\n"
        "    enabled: true\n"
        "    server_url: \"https://vault.example.com\"\n"
        "    client_id: \"user.abc-123\"\n"
        "    client_secret_env: VW_CLIENT_SECRET\n"
        "    allow_write: true\n"
        "    sync_interval_seconds: 300\n"
        "    bw_cli_path: \"/opt/data/bin/bw\"\n"
        "platform_toolsets:\n"
        "  cli:\n"
        "    - terminal\n"
        "    - vaultwarden\n"
    )
    f = tmp_path / "config.yaml"
    f.write_text(text)
    cfg = load_config(str(f), env={})
    assert cfg.enabled is True
    assert cfg.server_url == "https://vault.example.com"
    assert cfg.client_id == "user.abc-123"
    assert cfg.client_secret_env_name == "VW_CLIENT_SECRET"
    assert cfg.allow_write is True
    assert cfg.sync_interval_seconds == 300
    assert cfg.bw_cli_path == "/opt/data/bin/bw"


def test_extract_ignores_sibling_sections(tmp_path, no_yaml):
    text = (
        "secrets:\n"
        "  other_plugin:\n"
        "    server_url: https://wrong\n"
        "  vaultwarden:\n"
        "    server_url: https://right\n"
    )
    f = tmp_path / "config.yaml"
    f.write_text(text)
    cfg = load_config(str(f), env={})
    assert cfg.server_url == "https://right"


def test_url_with_colon_preserved(tmp_path, no_yaml):
    text = "secrets:\n  vaultwarden:\n    server_url: \"https://vault.example.com:8443/path\"\n"
    f = tmp_path / "config.yaml"
    f.write_text(text)
    cfg = load_config(str(f), env={})
    assert cfg.server_url == "https://vault.example.com:8443/path"


def test_extract_nested_section_missing_path_returns_empty():
    assert _extract_nested_section("foo:\n  bar: 1\n", ("secrets", "vaultwarden")) == {}
    assert _extract_nested_section("", ("secrets", "vaultwarden")) == {}


def test_pyyaml_path_still_used_when_available(tmp_path):
    """When PyYAML IS importable, the normal yaml.safe_load path is used."""
    pytest.importorskip("yaml")
    text = "secrets:\n  vaultwarden:\n    server_url: https://via-pyyaml\n"
    f = tmp_path / "config.yaml"
    f.write_text(text)
    cfg = load_config(str(f), env={})
    assert cfg.server_url == "https://via-pyyaml"

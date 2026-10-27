"""Unit tests for the v0.5.0 bootstrap-secret loader (secrets.py).

Covers:
  - load_secrets(): missing file, wrong permissions, valid file, empty keys
  - check_terminal_backend(): TERMINAL_ENV override and config.yaml fallback
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest

from vaultwarden import errors
from vaultwarden import secrets as secrets_mod


def _make_secrets_home(tmp_path: Path, client_secret: str = "cs-value",
                       master_password: str = "mp-value",
                       mode: int = 0o600) -> Path:
    """Create $HERMES_HOME/plugins/vaultwarden/secrets.yaml with given perms."""
    d = tmp_path / "plugins" / "vaultwarden"
    d.mkdir(parents=True)
    p = d / "secrets.yaml"
    p.write_text(
        "# test secrets\n"
        f"client_secret: \"{client_secret}\"\n"
        f"master_password: \"{master_password}\"\n",
        encoding="utf-8",
    )
    p.chmod(mode)
    return tmp_path


# ── load_secrets ─────────────────────────────────────────────────────────────

def test_load_secrets_missing_file_raises_config_error(tmp_path):
    with pytest.raises(errors.ConfigError) as exc:
        secrets_mod.load_secrets(str(tmp_path))
    msg = str(exc.value).lower()
    assert "not found" in msg or "secrets.yaml" in msg
    # migration instructions present in the suggestion
    assert "secret.yaml.template" in (exc.value.suggestion or "")


def test_load_secrets_wrong_permissions_raises_config_error(tmp_path):
    home = _make_secrets_home(tmp_path, mode=0o644)
    with pytest.raises(errors.ConfigError) as exc:
        secrets_mod.load_secrets(str(home))
    assert "chmod 600" in (exc.value.suggestion or "")


def test_load_secrets_valid_returns_tuple(tmp_path):
    home = _make_secrets_home(tmp_path, client_secret="s3cr3t-cs",
                              master_password="s3cr3t-mp")
    result = secrets_mod.load_secrets(str(home))
    assert result == ("s3cr3t-cs", "s3cr3t-mp")
    assert isinstance(result, tuple) and len(result) == 2


def test_load_secrets_empty_client_secret_raises(tmp_path):
    home = _make_secrets_home(tmp_path, client_secret="", master_password="mp")
    with pytest.raises(errors.ConfigError) as exc:
        secrets_mod.load_secrets(str(home))
    assert "client_secret" in str(exc.value)


def test_load_secrets_empty_master_password_raises(tmp_path):
    home = _make_secrets_home(tmp_path, client_secret="cs", master_password="")
    with pytest.raises(errors.ConfigError) as exc:
        secrets_mod.load_secrets(str(home))
    assert "master_password" in str(exc.value)


def test_load_secrets_missing_key_raises(tmp_path):
    d = tmp_path / "plugins" / "vaultwarden"
    d.mkdir(parents=True)
    p = d / "secrets.yaml"
    p.write_text('client_secret: "cs-only"\n', encoding="utf-8")
    p.chmod(0o600)
    with pytest.raises(errors.ConfigError) as exc:
        secrets_mod.load_secrets(str(tmp_path))
    assert "master_password" in str(exc.value)


def test_load_secrets_never_touches_environ(tmp_path):
    """Regression guard: loaded values must NOT appear in os.environ."""
    import os
    home = _make_secrets_home(tmp_path, client_secret="UNIQUE-CS-XYZ",
                              master_password="UNIQUE-MP-XYZ")
    cs, mp = secrets_mod.load_secrets(str(home))
    assert cs == "UNIQUE-CS-XYZ"
    assert "UNIQUE-CS-XYZ" not in os.environ.values()
    assert "UNIQUE-MP-XYZ" not in os.environ.values()


# ── check_terminal_backend ───────────────────────────────────────────────────

def test_check_terminal_backend_local_warns(monkeypatch, caplog):
    monkeypatch.setenv("TERMINAL_ENV", "local")
    with caplog.at_level(logging.WARNING,
                         logger="hermes.plugins.vaultwarden.secrets"):
        backend = secrets_mod.check_terminal_backend()
    assert backend == "local"
    assert any(r.levelno == logging.WARNING and "secrets.yaml" in r.getMessage()
               for r in caplog.records)


def test_check_terminal_backend_docker_info_no_warning(monkeypatch, caplog):
    monkeypatch.setenv("TERMINAL_ENV", "docker")
    with caplog.at_level(logging.INFO,
                         logger="hermes.plugins.vaultwarden.secrets"):
        backend = secrets_mod.check_terminal_backend()
    assert backend == "docker"
    assert not any(r.levelno >= logging.WARNING for r in caplog.records)
    assert any(r.levelno == logging.INFO for r in caplog.records)


def test_check_terminal_backend_ssh_info(monkeypatch, caplog):
    monkeypatch.setenv("TERMINAL_ENV", "ssh")
    with caplog.at_level(logging.INFO,
                         logger="hermes.plugins.vaultwarden.secrets"):
        backend = secrets_mod.check_terminal_backend()
    assert backend == "ssh"
    assert not any(r.levelno >= logging.WARNING for r in caplog.records)


def test_check_terminal_backend_unset_warns(monkeypatch, tmp_path, caplog):
    monkeypatch.delenv("TERMINAL_ENV", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("HERMES_HOME", raising=False)
    with caplog.at_level(logging.WARNING,
                         logger="hermes.plugins.vaultwarden.secrets"):
        backend = secrets_mod.check_terminal_backend()
    assert backend == ""
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def test_check_terminal_backend_from_config_yaml_local(monkeypatch, tmp_path,
                                                       caplog):
    monkeypatch.delenv("TERMINAL_ENV", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    cfg = tmp_path / "config.yaml"
    cfg.write_text("terminal:\n  backend: local\n", encoding="utf-8")
    with caplog.at_level(logging.WARNING,
                         logger="hermes.plugins.vaultwarden.secrets"):
        backend = secrets_mod.check_terminal_backend()
    assert backend == "local"
    assert any(r.levelno == logging.WARNING and "terminal backend" in
               r.getMessage().lower() for r in caplog.records)


def test_check_terminal_backend_from_config_yaml_docker(monkeypatch, tmp_path,
                                                        caplog):
    monkeypatch.delenv("TERMINAL_ENV", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    cfg = tmp_path / "config.yaml"
    cfg.write_text("terminal:\n  backend: docker\n", encoding="utf-8")
    with caplog.at_level(logging.INFO,
                         logger="hermes.plugins.vaultwarden.secrets"):
        backend = secrets_mod.check_terminal_backend()
    assert backend == "docker"
    assert not any(r.levelno >= logging.WARNING for r in caplog.records)


# ── template file ────────────────────────────────────────────────────────────

def test_secret_yaml_template_exists_with_expected_keys():
    tpl = Path(secrets_mod.__file__).parent / "secret.yaml.template"
    assert tpl.is_file()
    text = tpl.read_text(encoding="utf-8")
    assert "client_secret:" in text
    assert "master_password:" in text


# ── stdlib fallback parser (no PyYAML — CI venvs have zero runtime deps) ────

def test_backend_from_config_yaml_without_pyyaml(monkeypatch, tmp_path):
    """CI has no PyYAML installed; the stdlib fallback must still read the
    nested ``terminal: {backend: ...}`` mapping from config.yaml."""
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("simulated: PyYAML not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.delenv("TERMINAL_ENV", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(builtins, "__import__", fake_import)
    cfg = tmp_path / "config.yaml"
    cfg.write_text("# comment\nterminal:\n  backend: docker\n", encoding="utf-8")
    assert secrets_mod._backend_from_hermes_config() == "docker"


def test_load_secrets_without_pyyaml(monkeypatch, tmp_path):
    """The flat secrets.yaml shape must load via the stdlib fallback too."""
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("simulated: PyYAML not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    plugin_dir = tmp_path / "plugins" / "vaultwarden"
    plugin_dir.mkdir(parents=True)
    f = plugin_dir / "secrets.yaml"
    f.write_text('# c\nclient_secret: "cs-val"\nmaster_password: mp-val\n',
                 encoding="utf-8")
    os.chmod(f, 0o600)
    assert secrets_mod.load_secrets(str(tmp_path)) == ("cs-val", "mp-val")

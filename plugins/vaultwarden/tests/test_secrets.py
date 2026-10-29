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
    """AUD-08 (v0.6.2): an existing-but-insecure secrets.yaml fails CLOSED
    with FilesystemSecurityError BEFORE any YAML parsing — and the file is
    never silently repaired."""
    home = _make_secrets_home(tmp_path, mode=0o644)
    from vaultwarden.secure_fs import FilesystemSecurityError
    with pytest.raises(FilesystemSecurityError) as exc:
        secrets_mod.load_secrets(str(home))
    assert "chmod 600" in str(exc.value)
    # permissions untouched — no silent repair
    path = home / "plugins" / "vaultwarden" / "secrets.yaml"
    assert path.stat().st_mode & 0o777 == 0o644


def test_load_secrets_symlink_never_parsed(tmp_path):
    """AUD-08 (v0.6.2): a symlinked secrets.yaml is rejected via lstat() and
    NEVER read/parsed."""
    from vaultwarden.secure_fs import FilesystemSecurityError
    target = tmp_path / "elsewhere.yaml"
    target.write_text("client_secret: s3cr3t-cs\nmaster_password: s3cr3t-mp\n")
    os.chmod(target, 0o600)
    plugin_dir = tmp_path / "plugins" / "vaultwarden"
    plugin_dir.mkdir(parents=True)
    link = plugin_dir / "secrets.yaml"
    link.symlink_to(target)
    with pytest.raises(FilesystemSecurityError):
        secrets_mod.load_secrets(str(tmp_path))


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


# ── SEC-03 (v0.5.5): backend classification helpers ─────────────────────────

@pytest.mark.parametrize("backend,expected", [
    ("docker", True),
    ("ssh", True),
    ("modal", True),
    ("DOCKER", True),          # case-insensitive
    (" ssh ", True),           # whitespace-tolerant
    ("local", False),
    ("", False),               # unset => NOT sandboxed (fail-closed)
    ("kubernetes", False),     # unknown backends are NOT trusted (fail-closed)
])
def test_is_sandboxed_backend_classification(backend, expected):
    assert secrets_mod.is_sandboxed_backend(backend) is expected


def test_check_terminal_backend_modal_info(monkeypatch, caplog):
    """SEC-03: 'modal' is a recognized sandboxed backend — INFO, no warning."""
    monkeypatch.setenv("TERMINAL_ENV", "modal")
    with caplog.at_level(logging.INFO,
                         logger="hermes.plugins.vaultwarden.secrets"):
        backend = secrets_mod.check_terminal_backend()
    assert backend == "modal"
    assert not any(r.levelno >= logging.WARNING for r in caplog.records)
    assert any(r.levelno == logging.INFO for r in caplog.records)


# ── template file ────────────────────────────────────────────────────────────

def test_secret_yaml_template_exists_with_expected_keys():
    tpl = Path(secrets_mod.__file__).parent / "secret.yaml.template"
    assert tpl.is_file()
    text = tpl.read_text(encoding="utf-8")
    assert "client_secret:" in text
    assert "master_password:" in text


# ── stdlib fallback parser (no PyYAML — CI venvs have zero runtime deps) ────

def _force_no_pyyaml(monkeypatch):
    """Make ``import yaml`` fail inside secrets.py regardless of the
    interpreter's meta_path API (legacy finders are ignored on 3.12)."""
    import sys

    monkeypatch.setitem(sys.modules, "yaml", None)


def test_backend_from_config_yaml_without_pyyaml(monkeypatch, tmp_path):
    """CI has no PyYAML installed; the stdlib fallback must still read the
    nested ``terminal: {backend: ...}`` mapping from config.yaml."""
    _force_no_pyyaml(monkeypatch)
    monkeypatch.delenv("TERMINAL_ENV", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    cfg = tmp_path / "config.yaml"
    cfg.write_text("# comment\nterminal:\n  backend: docker\n", encoding="utf-8")
    assert secrets_mod._backend_from_hermes_config() == "docker"


def test_load_secrets_without_pyyaml(monkeypatch, tmp_path):
    """The flat secrets.yaml shape must load via the stdlib fallback too."""
    _force_no_pyyaml(monkeypatch)
    plugin_dir = tmp_path / "plugins" / "vaultwarden"
    plugin_dir.mkdir(parents=True)
    f = plugin_dir / "secrets.yaml"
    f.write_text('# c\nclient_secret: "cs-val"\nmaster_password: mp-val\n',
                 encoding="utf-8")
    os.chmod(f, 0o600)
    assert secrets_mod.load_secrets(str(tmp_path)) == ("cs-val", "mp-val")


def test_empty_quoted_secret_raises_without_pyyaml(monkeypatch, tmp_path):
    """CI regression guard: with PyYAML absent, ``client_secret: ""`` must
    parse to an EMPTY STRING (not a nested {}) and still raise ConfigError.

    The old fallback treated any valueless-looking line as a parent mapping
    key, silently turning quoted-empty secrets into {} and bypassing the
    empty-value validation whenever PyYAML was missing.
    """
    _force_no_pyyaml(monkeypatch)
    home = _make_secrets_home(tmp_path, client_secret="", master_password="mp")
    with pytest.raises(errors.ConfigError) as exc:
        secrets_mod.load_secrets(str(home))
    assert "client_secret" in str(exc.value)


def test_hash_inside_quoted_value_without_pyyaml(monkeypatch, tmp_path):
    """A '#' inside quotes is part of the value, not a comment."""
    _force_no_pyyaml(monkeypatch)
    home = _make_secrets_home(tmp_path, client_secret="p#ss#w0rd",
                              master_password="mp")
    assert secrets_mod.load_secrets(str(home)) == ("p#ss#w0rd", "mp")

"""Unit tests for the shared filesystem-hardening layer (v0.6.2).

Covers AUD-03 / AUD-04 / AUD-08 validators: symlink rejection via
os.lstat(), ownership by the current effective UID, exact 0700 directory
mode, no group/other access on secret files, creation semantics and the
fail-closed contract (no silent repair, error messages never contain
secret values).
"""
from __future__ import annotations

import os

import pytest

from vaultwarden.secure_fs import (
    FilesystemSecurityError,
    ensure_hardened_directory,
    ensure_hardened_secret_file,
)

# ---------------------------------------------------------------------------
# ensure_hardened_directory
# ---------------------------------------------------------------------------

def test_dir_accepts_valid_0700(tmp_path):
    d = tmp_path / "secrets"
    d.mkdir(mode=0o700)
    assert ensure_hardened_directory(d) == d


def test_dir_creates_missing_with_0700_even_under_hostile_umask(tmp_path):
    d = tmp_path / "created"
    old = os.umask(0o022)
    try:
        assert ensure_hardened_directory(d, create_if_missing=True) == d
    finally:
        os.umask(old)
    assert d.is_dir()
    assert d.stat().st_mode & 0o777 == 0o700


def test_dir_missing_and_creation_disabled_raises(tmp_path):
    d = tmp_path / "absent"
    with pytest.raises(FilesystemSecurityError):
        ensure_hardened_directory(d, create_if_missing=False)
    assert not d.exists()


def test_dir_rejects_relative_path():
    with pytest.raises(FilesystemSecurityError):
        ensure_hardened_directory("relative/dir")


def test_dir_rejects_symlink(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    # lstat sees the SYMLINK — must fail closed even though the target is
    # perfectly hardened.
    with pytest.raises(FilesystemSecurityError) as exc:
        ensure_hardened_directory(link)
    assert "symlink" in str(exc.value)


def test_dir_rejects_regular_file(tmp_path):
    f = tmp_path / "not-a-dir"
    f.write_text("x")
    with pytest.raises(FilesystemSecurityError):
        ensure_hardened_directory(f)


@pytest.mark.parametrize("bad_mode", [0o755, 0o777, 0o701, 0o600, 0o750])
def test_dir_requires_exactly_0700(tmp_path, bad_mode):
    d = tmp_path / f"d{bad_mode:o}"
    d.mkdir(mode=bad_mode)
    os.chmod(d, bad_mode)
    with pytest.raises(FilesystemSecurityError):
        ensure_hardened_directory(d)
    # NEVER silently repaired:
    assert d.stat().st_mode & 0o777 == bad_mode


@pytest.mark.skipif(os.geteuid() != 0, reason="needs root to chown away")
def test_dir_rejects_foreign_owner(tmp_path):
    d = tmp_path / "foreign"
    d.mkdir(mode=0o700)
    os.chown(d, 65534, 65534)  # nobody
    try:
        with pytest.raises(FilesystemSecurityError) as exc:
            ensure_hardened_directory(d)
        assert "owned by uid" in str(exc.value)
    finally:
        os.chown(d, os.geteuid(), os.getegid())


def test_dir_error_message_contains_path_not_secrets(tmp_path):
    d = tmp_path / "open-dir"
    d.mkdir(mode=0o755)
    with pytest.raises(FilesystemSecurityError) as exc:
        ensure_hardened_directory(d)
    assert str(d) in str(exc.value)


# ---------------------------------------------------------------------------
# ensure_hardened_secret_file
# ---------------------------------------------------------------------------

def test_file_accepts_valid_0600(tmp_path):
    f = tmp_path / "secrets.yaml"
    f.write_text("client_secret: redacted-in-test\n")
    os.chmod(f, 0o600)
    assert ensure_hardened_secret_file(f) == f
    # validator performs NO read: content untouched
    assert f.read_text() == "client_secret: redacted-in-test\n"


def test_file_accepts_0400_owner_read_only(tmp_path):
    f = tmp_path / "ro"
    f.write_text("x")
    os.chmod(f, 0o400)
    assert ensure_hardened_secret_file(f) == f


def test_file_rejects_relative_path():
    with pytest.raises(FilesystemSecurityError):
        ensure_hardened_secret_file("relative/secrets.yaml")


def test_file_rejects_symlink_never_followed(tmp_path):
    target = tmp_path / "target.yaml"
    target.write_text("client_secret: super-secret-value\n")
    os.chmod(target, 0o600)
    link = tmp_path / "secrets.yaml"
    link.symlink_to(target)
    with pytest.raises(FilesystemSecurityError) as exc:
        ensure_hardened_secret_file(link)
    assert "symlink" in str(exc.value)
    # the secret VALUE must never appear in the error message
    assert "super-secret-value" not in str(exc.value)


def test_file_rejects_directory(tmp_path):
    d = tmp_path / "dir.yaml"
    d.mkdir()
    with pytest.raises(FilesystemSecurityError):
        ensure_hardened_secret_file(d)


# NOTE: 0o700 is deliberately NOT in this list — it has no GROUP/OTHER bits
# (mode & 0o077 == 0), so the file validator's documented rule ("no group or
# other access") accepts it; the executable owner bit is unusual for a secret
# file but does not expose its CONTENTS to other users. Modes that DO grant
# group/other access must all be rejected:
@pytest.mark.parametrize("bad_mode", [0o644, 0o666, 0o604, 0o640, 0o606, 0o660])
def test_file_rejects_group_other_access(tmp_path, bad_mode):
    f = tmp_path / f"f{bad_mode:o}"
    f.write_text("x")
    os.chmod(f, bad_mode)
    with pytest.raises(FilesystemSecurityError):
        ensure_hardened_secret_file(f)
    # NEVER silently repaired:
    assert f.stat().st_mode & 0o777 == bad_mode


def test_file_missing_strict_raises(tmp_path):
    f = tmp_path / "absent.yaml"
    with pytest.raises(FilesystemSecurityError) as exc:
        ensure_hardened_secret_file(f, allow_missing=False)
    assert "does not exist" in str(exc.value)


def test_file_missing_allow_missing_returns_path(tmp_path):
    f = tmp_path / "absent.yaml"
    assert ensure_hardened_secret_file(f, allow_missing=True) == f
    assert not f.exists()


@pytest.mark.skipif(os.geteuid() != 0, reason="needs root to chown away")
def test_file_rejects_foreign_owner(tmp_path):
    f = tmp_path / "foreign.yaml"
    f.write_text("x")
    os.chmod(f, 0o600)
    os.chown(f, 65534, 65534)
    try:
        with pytest.raises(FilesystemSecurityError) as exc:
            ensure_hardened_secret_file(f)
        assert "owned by uid" in str(exc.value)
    finally:
        os.chown(f, os.geteuid(), os.getegid())


def test_file_error_message_has_no_secret_content(tmp_path):
    f = tmp_path / "leak-check.yaml"
    f.write_text("master_password: hunter2TOPSECRET\n")
    os.chmod(f, 0o644)
    with pytest.raises(FilesystemSecurityError) as exc:
        ensure_hardened_secret_file(f)
    msg = str(exc.value)
    assert "hunter2TOPSECRET" not in msg
    assert "master_password" not in msg
    assert str(f) in msg  # path allowed

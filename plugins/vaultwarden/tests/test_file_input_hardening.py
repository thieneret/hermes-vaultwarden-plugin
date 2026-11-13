"""HVA-03 regression tests: fd-based TOCTOU/symlink hardening of the
file-based secret INPUT channel (password_file / pass_file).

v0.7.8 (audit v0.6.9, finding HVA-03). Hermetic: tmp_path fixtures only —
no root, no network, no real bw. The wrong-owner case simulates a foreign
owner by monkeypatching os.geteuid() (the Phase 1 gate compares the fd's
owner against the effective uid), per the phase plan — CI runs unprivileged.
"""
from __future__ import annotations

import os

import pytest

from vaultwarden import errors
from vaultwarden.secure_fs import (
    FilesystemSecurityError,
    read_hardened_secret_file,
)
from vaultwarden.tools import _resolve_secret_input

#: Unique marker that must NEVER surface in any raised message or log.
SECRET = "hva03-super-secret-value-DO-NOT-LOG-4f9c"


def _mkfile(tmp_path, name="secret.txt", mode=0o600):
    f = tmp_path / name
    f.write_bytes(SECRET.encode())
    f.chmod(mode)
    return f


# Case 1: valid owner-only regular file -> read successfully.
def test_hva03_valid_owner_only_file_is_read(tmp_path):
    f = _mkfile(tmp_path, mode=0o600)
    assert read_hardened_secret_file(f) == SECRET.encode()
    val, warning = _resolve_secret_input(
        {"password_file": str(f)}, direct_key="password",
        file_key="password_file", tool_name="vaultwarden_store")
    assert val == SECRET
    assert warning is None


# Case 2: symlink pointing to a valid secret file -> rejected (both the
# fd-level helper and the tool-facing resolver contract).
def test_hva03_symlink_input_rejected(tmp_path):
    real = _mkfile(tmp_path, name="real.txt")
    link = tmp_path / "link.txt"
    link.symlink_to(real)
    with pytest.raises(FilesystemSecurityError) as exc:
        read_hardened_secret_file(link)
    assert "symlink" in str(exc.value)
    assert SECRET not in str(exc.value)
    # target file must remain intact (nothing was followed or consumed)
    assert real.read_bytes() == SECRET.encode()
    with pytest.raises(errors.ConfigError):
        _resolve_secret_input(
            {"password_file": str(link)}, direct_key="password",
            file_key="password_file", tool_name="vaultwarden_store")


# Case 3: group-readable modes -> rejected fail-closed.
def test_hva03_group_readable_rejected(tmp_path):
    for idx, mode in enumerate((0o640, 0o644)):
        f = _mkfile(tmp_path, name=f"grp{idx}.txt", mode=mode)
        with pytest.raises(FilesystemSecurityError) as exc:
            read_hardened_secret_file(f)
        assert SECRET not in str(exc.value)


# Case 4: world-readable modes -> rejected fail-closed (exact-0600 gate).
def test_hva03_world_readable_rejected(tmp_path):
    for idx, mode in enumerate((0o604, 0o644)):
        f = _mkfile(tmp_path, name=f"o{idx}.txt", mode=mode)
        with pytest.raises(FilesystemSecurityError) as exc:
            read_hardened_secret_file(f)
        assert SECRET not in str(exc.value)


# Case 5: non-regular files (directory, FIFO) -> rejected fail-closed.
def test_hva03_nonregular_rejected(tmp_path):
    d = tmp_path / "dir-as-file"
    d.mkdir()
    d.chmod(0o600)
    with pytest.raises(FilesystemSecurityError) as exc:
        read_hardened_secret_file(d)
    assert "not a regular file" in str(exc.value)

    fifo = tmp_path / "fifo"
    os.mkfifo(str(fifo))
    fifo.chmod(0o600)
    # O_NONBLOCK in the helper guarantees open() cannot hang on the FIFO.
    with pytest.raises(FilesystemSecurityError) as exc:
        read_hardened_secret_file(fifo)
    assert "not a regular file" in str(exc.value)


# Case 6: foreign owner -> rejected fail-closed. Non-root simulation: the
# gate calls os.geteuid(); monkeypatch it to a uid that does NOT own the
# file (st_uid stays the real current uid).
def test_hva03_foreign_owner_rejected(tmp_path, monkeypatch):
    f = _mkfile(tmp_path, mode=0o600)
    real_geteuid = os.geteuid
    monkeypatch.setattr(os, "geteuid", lambda: real_geteuid() + 1)
    with pytest.raises(FilesystemSecurityError) as exc:
        read_hardened_secret_file(f)
    assert "owned by uid" in str(exc.value)
    assert SECRET not in str(exc.value)


# Case 7: raised messages carry the path and mode/error code only — never
# the secret content (helper-level AND tool-facing resolver level).
def test_hva03_messages_carry_path_not_secret(tmp_path):
    f = _mkfile(tmp_path, mode=0o644)
    with pytest.raises(FilesystemSecurityError) as exc:
        read_hardened_secret_file(f)
    msg = str(exc.value)
    assert SECRET not in msg
    assert str(f) in msg  # path is present for the operator to fix

    with pytest.raises(errors.ConfigError) as exc2:
        _resolve_secret_input(
            {"password_file": str(f)}, direct_key="password",
            file_key="password_file", tool_name="vaultwarden_store")
    assert SECRET not in exc2.value.message
    assert str(f) in exc2.value.message

"""HVA-04 regression tests: hardened SSH temporary socket cleanup.

v0.7.8 (audit v0.6.9, finding HVA-04). Hermetic: real AF_UNIX socket FILES
under tmp_path; the ssh-add -l staleness probe (and any ssh-agent spawn)
is fully mocked — no real agent, no network, no root.
"""
from __future__ import annotations

import logging
import os
import socket
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from vaultwarden import hooks, tools
from vaultwarden.tests.conftest import write_fake_ssh_binaries

# HVA-079-03: the staleness probe runs ONLY from the pinned ssh-add path.
# subprocess.run is mocked for the probe, so an inert executable stub is
# enough for the probe branch; tests of the DISABLED path call
# _cleanup_stale_sockets() with no pinned path (skip branch).
_SSH_STUB_DIR = tempfile.mkdtemp(prefix="vw_sockclean_stub_bins_")
_SSH_ADD = write_fake_ssh_binaries(_SSH_STUB_DIR)["ssh_add_path"]

#: Marker standing in for passphrase material — must never surface in logs.
PASSPHRASE_MARKER = "hva04-PASSPHRASE-MUST-NEVER-APPEAR-b7d3"


@pytest.fixture(autouse=True)
def _clean_socket_registry():
    """Keep the module-level creation registry hermetic between tests."""
    yield
    with tools._socket_creations_lock:
        tools._socket_creations.clear()


def _mksock(path: str) -> None:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.bind(path)
    finally:
        s.close()  # leaves the socket FILE on disk


def _cleanup(sock_path: str, rc: int = 2) -> None:
    """Startup cleanup with the ssh-add -l probe mocked (rc=2 -> stale)."""
    with patch.dict(os.environ, {"VW_SSH_SOCKET_PATH": sock_path,
                                 "XDG_RUNTIME_DIR": ""}, clear=False):
        with patch("vaultwarden.hooks.subprocess.run",
                   return_value=MagicMock(returncode=rc)):
            hooks._cleanup_stale_sockets(_SSH_ADD)


# Case 1: socket created by the current execution -> unlinked after
# verified identity match; the registry entry is forgotten.
def test_hva04_socket_created_by_this_run_is_unlinked(tmp_path):
    sock = str(tmp_path / "auth.sock")
    _mksock(sock)
    tools._record_created_socket(sock)
    assert tools.socket_creation_identity(sock) is not None
    _cleanup(sock)
    assert not os.path.lexists(sock)
    assert tools.socket_creation_identity(sock) is None


# Case 2: recorded socket path replaced by a SYMLINK -> cleanup skips it,
# the symlink target is NOT unlinked, sanitized warning emitted.
def test_hva04_symlinked_path_skipped_target_intact(tmp_path, caplog):
    target = str(tmp_path / "elsewhere.sock")
    _mksock(target)
    sock = str(tmp_path / "auth.sock")
    _mksock(sock)
    tools._record_created_socket(sock)
    os.unlink(sock)
    os.symlink(target, sock)  # attacker swaps the object under the path
    with caplog.at_level(logging.WARNING):
        _cleanup(sock)
    assert os.path.lexists(sock)     # symlink itself untouched
    assert os.path.lexists(target)   # target NOT unlinked
    assert "symlink" in caplog.text


# Case 3: recorded socket replaced by a regular file (type mismatch)
# -> cleanup skips, warning names the type gate, no unlink attempt.
def test_hva04_type_mismatch_regular_file_skipped(tmp_path, caplog):
    sock = str(tmp_path / "auth.sock")
    _mksock(sock)
    tools._record_created_socket(sock)
    os.unlink(sock)
    with open(sock, "w", encoding="utf-8") as fh:
        fh.write(PASSPHRASE_MARKER)
    os.chmod(sock, 0o600)
    with caplog.at_level(logging.WARNING):
        _cleanup(sock)
    assert os.path.lexists(sock)
    assert "not a socket" in caplog.text


# Case 4: OS error inside the unlink -> never propagates; observable,
# sanitized WARNING (path + error only).
def test_hva04_unlink_failure_never_raises(tmp_path, caplog):
    sock = str(tmp_path / "auth.sock")
    _mksock(sock)
    with caplog.at_level(logging.WARNING):
        with patch("vaultwarden.hooks.os.unlink",
                   side_effect=OSError("simulated cleanup failure")):
            _cleanup(sock)  # must NOT raise
    assert os.path.lexists(sock)
    assert "Failed to remove stale ssh socket" in caplog.text


# Case 5: every warning message is value-free — the passphrase marker
# planted in the replaced file's CONTENT never appears in any log line,
# while the warnings themselves did fire (observable cleanup).
def test_hva04_logs_contain_no_secret_material(tmp_path, caplog):
    sock = str(tmp_path / "auth.sock")
    _mksock(sock)
    tools._record_created_socket(sock)
    os.unlink(sock)
    with open(sock, "w", encoding="utf-8") as fh:
        fh.write(PASSPHRASE_MARKER)
    os.chmod(sock, 0o600)
    with caplog.at_level(logging.WARNING):
        _cleanup(sock)
    text = caplog.text
    assert PASSPHRASE_MARKER not in text
    assert "skipping stale ssh socket" in text  # warnings actually emitted


# Case 6 (HVA-079-03): SSH binaries NOT pinned -> the staleness probe can
# never prove "no agent answers", so the whole cleanup is SKIPPED: the
# socket file survives and a single INFO skip line is logged (no WARNING).
def test_unpinned_ssh_cleanup_skipped_socket_intact(tmp_path, caplog):
    sock = str(tmp_path / "auth.sock")
    _mksock(sock)
    with patch.dict(os.environ, {"VW_SSH_SOCKET_PATH": sock,
                                 "XDG_RUNTIME_DIR": ""}, clear=False):
        with caplog.at_level(logging.DEBUG,
                             logger="hermes.plugins.vaultwarden.hooks"):
            hooks._cleanup_stale_sockets()  # no pinned path -> skip
    assert os.path.lexists(sock)
    assert "skipped" in caplog.text

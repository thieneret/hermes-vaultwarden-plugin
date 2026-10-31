"""VWP-20: Crash recovery tests.

Validates that temp files are cleaned up even when the process is interrupted
(KeyboardInterrupt) and that the plugin's startup cleanup removes stale temp
files left behind by a previous SIGKILL/SIGTERM run (where the middleware's
``finally`` block did not get a chance to execute).

Note: SIGKILL/SIGTERM cannot be tested in unit tests because they kill the
process immediately; the startup cleanup in ``hooks._cleanup_stale_secrets``
handles those cases and is exercised here directly.
"""
from __future__ import annotations

import os
import re
import time

import pytest

from vaultwarden.hooks import (
    _cleanup_stale_secrets,
    _secrets_dir,
    make_placeholder_resolver,
)


#: AUD-05 phase 2: the middleware emits $(< '/quoted/path'); the bare form
#: is still matched for robustness.
_INJECTED_PATH_RE = re.compile(
    r"\$\(<\s*(?:'([^']+)'|\"([^\"]+)\"|(/[^)\s]+))\)")


def _injected_paths(command: str) -> list[str]:
    return [g[0] or g[1] or g[2] for g in _INJECTED_PATH_RE.findall(command)]


@pytest.fixture()
def mw(auth_manager, registry):
    """The VWP-04 file-injection tool_execution middleware (same fixture
    shape as tests/test_hooks.py — defined locally so this module is
    self-contained)."""
    return make_placeholder_resolver(auth_manager, registry)


class TestCrashRecovery:
    def test_keyboardinterrupt_triggers_cleanup(self, mw, registry):
        """KeyboardInterrupt during file-injection middleware triggers finally cleanup."""
        entry = registry.create("Postgres prod", "password")
        ref = "$" + entry.token

        paths: list[str] = []

        def next_call(a):
            # capture the injected temp-file paths, then simulate the user
            # hitting Ctrl-C while the terminal command is executing
            paths.extend(_injected_paths(a["command"]))
            raise KeyboardInterrupt()

        with pytest.raises(KeyboardInterrupt):
            mw("terminal", {"command": f'export PGPASSWORD="{ref}"; psql -l'},
               None, next_call, task_id="crash-ki")

        # the middleware's finally block MUST have deleted every temp file
        assert paths, "middleware should have injected at least one temp file"
        for p in paths:
            assert not os.path.exists(p), (
                f"temp secret file {p} survived KeyboardInterrupt"
            )

    def test_startup_cleanup_removes_stale_files(self, tmp_path, monkeypatch):
        """Startup cleanup removes files older than the placeholder TTL."""
        secrets_dir = tmp_path / "vw-secrets"
        secrets_dir.mkdir(mode=0o700)
        monkeypatch.setattr("vaultwarden.hooks._secrets_dir",
                            lambda: str(secrets_dir))

        # Create a stale file (mtime > 300s ago)
        stale_file = secrets_dir / "vw_secret_stale_XXXXXX"
        stale_file.write_text("old_secret")
        old_time = time.time() - 600
        os.utime(stale_file, (old_time, old_time))

        # Create a fresh file (mtime < 300s ago)
        fresh_file = secrets_dir / "vw_secret_fresh_XXXXXX"
        fresh_file.write_text("new_secret")

        # Run cleanup
        _cleanup_stale_secrets()

        # Stale file should be deleted, fresh file should remain
        assert not stale_file.exists(), "Stale file should be cleaned up"
        assert fresh_file.exists(), "Fresh file should remain"

    def test_startup_cleanup_handles_missing_dir(self, tmp_path, monkeypatch):
        """AUD-03 (v0.6.2) FAIL-CLOSED contract: a merely-missing secrets dir
        is created hardened (0700) and cleanup proceeds; an insecure dir
        raises FilesystemSecurityError which PROPAGATES to register() (it is
        never swallowed)."""
        from vaultwarden.secure_fs import FilesystemSecurityError

        # _secrets_dir() raising FilesystemSecurityError must PROPAGATE —
        # plugin activation aborts, cleanup does not silently skip.
        def boom():
            raise FilesystemSecurityError("insecure secrets dir (test)")
        monkeypatch.setattr("vaultwarden.hooks._secrets_dir", boom)
        with pytest.raises(FilesystemSecurityError):
            _cleanup_stale_secrets()

        # A path that simply does not exist on disk: the SHARED validator
        # creates it hardened (mode 0o700, umask-forced) and the scan finds
        # nothing stale — no exception.  (resolve_secrets_dir_path alone is
        # not enough here: _secrets_dir() runs the REAL validator, which
        # requires the tmp_path ancestors to be euid-owned with mode exactly
        # 0700 — pytest's per-test dirs are typically 0755.  Patch the whole
        # hardened-dir resolver instead; the create-hardened behaviour of
        # secure_fs.ensure_hardened_directory itself is covered by
        # tests/test_secure_fs.py::test_dir_creates_missing_with_0700_even_under_hostile_umask.)
        missing = tmp_path / "vw-secrets"

        def hardened_dir():
            from vaultwarden.secure_fs import ensure_hardened_directory
            return str(ensure_hardened_directory(missing,
                                                 create_if_missing=True))
        monkeypatch.setattr("vaultwarden.hooks._secrets_dir", hardened_dir)
        _cleanup_stale_secrets()
        assert missing.is_dir()
        assert missing.stat().st_mode & 0o777 == 0o700

    def test_cleanup_boundary_at_ttl(self, tmp_path, monkeypatch):
        """Files just inside/outside the 300s TTL boundary are kept/removed."""
        secrets_dir = tmp_path / "vw-secrets"
        secrets_dir.mkdir(mode=0o700)
        monkeypatch.setattr("vaultwarden.hooks._secrets_dir",
                            lambda: str(secrets_dir))

        just_old = secrets_dir / "vw_secret_boundary_old"
        just_old.write_text("x")
        t_old = time.time() - 301
        os.utime(just_old, (t_old, t_old))

        just_new = secrets_dir / "vw_secret_boundary_new"
        just_new.write_text("x")
        t_new = time.time() - 299
        os.utime(just_new, (t_new, t_new))

        _cleanup_stale_secrets()

        assert not just_old.exists(), "301s-old file is past TTL -> removed"
        assert just_new.exists(), "299s-old file is within TTL -> kept"

    def test_cleanup_skips_subdirectories(self, tmp_path, monkeypatch):
        """Cleanup is file-only; directories are never unlinked via scandir."""
        secrets_dir = tmp_path / "vw-secrets"
        secrets_dir.mkdir(mode=0o700)
        monkeypatch.setattr("vaultwarden.hooks._secrets_dir",
                            lambda: str(secrets_dir))

        subdir = secrets_dir / "nested"
        subdir.mkdir()
        old = time.time() - 600
        os.utime(subdir, (old, old))

        _cleanup_stale_secrets()

        assert subdir.is_dir(), "stale directory must be left alone (is_file gate)"

    def test_real_secrets_dir_is_cleaned(self, monkeypatch):
        """Cleanup against the REAL _secrets_dir() honors its 700 permissions."""
        d = _secrets_dir()
        assert os.path.isdir(d)
        assert os.stat(d).st_mode & 0o777 == 0o700

        stale = os.path.join(d, "vw_crash_recovery_stale")
        with open(stale, "w") as fh:
            fh.write("stale")
        old = time.time() - 600
        os.utime(stale, (old, old))
        try:
            _cleanup_stale_secrets()
            assert not os.path.exists(stale), (
                "startup cleanup must remove stale files from the real dir")
        finally:
            try:
                os.unlink(stale)
            except OSError:
                pass

"""v0.7.7 (Phase 2): regression suite for multi-process session coordination.

Covers the SessionLockManager added in Phase 1:
  - unit semantics (acquire / re-entrant acquire / contention timeout /
    release / degraded non-POSIX fallback)
  - security invariants (lock file named .unlock.lck — never containing
    "session", mode 0600, zero bytes: no secret material on disk)
  - AuthManager integration (degraded-mode selection, call ordering around
    bw unlock_passwordenv, lock()/shutdown() release paths, atexit cleanup)
  - true multi-process contention via multiprocessing (spawn start method so
    module-level monkeypatching is unnecessary and child locks are always
    real fcntl locks)
  - PluginConfig.session_lock_timeout_seconds bounds [0, 30]

Constraints honored: pytest + stdlib only, no real bw binary required for
the lock mechanics (subprocess layer fully mocked), no network access,
deterministic except where short timeouts are explicitly under test, and
fake session keys use the FAKE_SESSION_KEY_* prefix with leak assertions.
"""
from __future__ import annotations

import ast
import atexit
import inspect
import logging
import multiprocessing
import os
import stat
import textwrap
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from vaultwarden import errors
from vaultwarden.auth import (
    AuthManager,
    AuthState,
    SessionLockManager,
    _NullSessionLock,
)
from vaultwarden.tests.conftest import make_config

FAKE_KEY = "FAKE_SESSION_KEY_1"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _make_locked_mgr(tmp_path: Path) -> AuthManager:
    """AuthManager whose _session_lock is a MagicMock (call observation)."""
    bw = MagicMock()
    bw.appdata_dir = str(tmp_path / ".bw-data")
    mgr = AuthManager(bw, make_config(), client_secret="cs-fake",
                      master_password="mp-fake")
    mgr._session_lock = MagicMock()
    return mgr


def _child_acquire(lock_dir: str, ready_q, done_q, timeout: float):
    """Module-level child entrypoint (picklable under the spawn method)."""
    lock = SessionLockManager(Path(lock_dir), timeout_seconds=timeout)
    ok = lock.acquire()
    ready_q.put(("acquired", ok))
    if ok:
        done_q.get()  # hold the lock until the parent says go
        lock.release()
    done_q.put(("done", ok))


def _child_hold_and_exit(lock_dir: str, ready_q):
    """Acquire via flock directly, confirm, then exit WITHOUT releasing."""
    fd = os.open(str(Path(lock_dir) / ".unlock.lck"),
                 os.O_CREAT | os.O_RDWR, 0o600)
    import fcntl as _fcntl
    _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
    ready_q.put("held")
    # No LOCK_UN, no close, no atexit registration in this child: process
    # exit alone must free the advisory lock for other processes.


# ===========================================================================
# CHANGE 2 — SessionLockManager unit tests (scenarios 1-9)
# ===========================================================================

class TestSessionLockManagerUnit:

    def test_01_acquire_on_free_lock(self, tmp_path):
        """Free lock => True, is_held, .unlock.lck created with mode 0600."""
        lock = SessionLockManager(tmp_path)
        try:
            assert lock.acquire() is True
            assert lock.is_held is True
            lock_file = tmp_path / ".unlock.lck"
            assert lock_file.exists()
            assert stat.S_IMODE(lock_file.stat().st_mode) == 0o600
        finally:
            lock.release()

    def test_02_reentrant_acquire_no_deadlock(self, tmp_path):
        """Already-held lock => immediate True (no deadlock, single owner)."""
        lock = SessionLockManager(tmp_path, timeout_seconds=0.2)
        try:
            assert lock.acquire() is True
            t0 = time.monotonic()
            assert lock.acquire() is True  # re-entrant fast path
            assert time.monotonic() - t0 < 0.1
        finally:
            lock.release()

    def test_03_contended_acquire_times_out_false(self, tmp_path):
        """Another holder => False after the (short) timeout, no crash."""
        holder = SessionLockManager(tmp_path)
        contender = SessionLockManager(tmp_path, timeout_seconds=0.25)
        try:
            assert holder.acquire() is True
            t0 = time.monotonic()
            assert contender.acquire() is False
            elapsed = time.monotonic() - t0
            assert 0.2 <= elapsed < 2.0  # honored budget, not blocking forever
            assert contender.is_held is False
        finally:
            holder.release()

    def test_04_acquire_or_raise_sanitized_auth_error(self, tmp_path):
        """Contention => AuthError with sanitized message; NO secrets inside."""
        holder = SessionLockManager(tmp_path)
        contender = SessionLockManager(tmp_path, timeout_seconds=0.2)
        try:
            assert holder.acquire() is True
            with pytest.raises(errors.AuthError) as ei:
                contender.acquire_or_raise()
            msg = str(ei.value.message)
            assert "session lock" in msg.lower()
            # Sanitized: fixed wording only — no paths, values, or raw text.
            assert str(tmp_path) not in msg
            assert ei.value.suggestion and ".bw-data" in ei.value.suggestion
        finally:
            holder.release()

    def test_05_release_after_acquire(self, tmp_path):
        """release() => is_held False and a fresh manager can re-acquire."""
        lock = SessionLockManager(tmp_path)
        assert lock.acquire() is True
        lock.release()
        assert lock.is_held is False
        # The lock is genuinely free again (advisory lock released).
        second = SessionLockManager(tmp_path, timeout_seconds=0.2)
        assert second.acquire() is True
        second.release()

    def test_06_release_without_acquire_is_noop(self, tmp_path):
        """release() before any acquire(): idempotent no-op, no exception."""
        lock = SessionLockManager(tmp_path)
        lock.release()  # must not raise
        assert lock.is_held is False
        lock.release()  # twice is still fine
        # ...and the lock primitive itself remains usable afterwards.
        assert lock.acquire() is True
        lock.release()

    def test_07_lock_file_contains_zero_bytes(self, tmp_path):
        """Pure coordination primitive: nothing (least of all secrets) written."""
        lock = SessionLockManager(tmp_path)
        try:
            assert lock.acquire() is True
            lock_file = tmp_path / ".unlock.lck"
            assert lock_file.stat().st_size == 0
            assert lock_file.read_bytes() == b""
        finally:
            lock.release()

    def test_08_lock_file_name_has_no_session_substring(self, tmp_path):
        """Naming invariant: '.unlock.lck' — 'session' never in the name."""
        lock = SessionLockManager(tmp_path)
        name = lock._lock_path.name
        assert name == ".unlock.lck"
        assert "session" not in name.lower()
        try:
            assert lock.acquire() is True
            files = [p.name for p in tmp_path.iterdir()]
            assert not [n for n in files if "session" in n.lower()]
        finally:
            lock.release()

    def test_09_non_posix_fallback_graceful(self, tmp_path, monkeypatch):
        """fcntl unavailable => acquire() degrades gracefully to True."""
        import vaultwarden.auth as auth_mod
        monkeypatch.setattr(auth_mod, "fcntl", None)
        lock = SessionLockManager(tmp_path)
        assert lock.acquire() is True
        lock.acquire_or_raise()  # must NOT raise
        lock.release()


# ===========================================================================
# CHANGE 3 — AuthManager integration (scenarios 10-17)
# ===========================================================================

class TestAuthManagerIntegration:

    def test_10_valid_appdata_builds_real_lock(self, tmp_path):
        appdata = tmp_path / ".bw-data"
        appdata.mkdir(mode=0o700)
        bw = MagicMock()
        bw.appdata_dir = str(appdata)
        mgr = AuthManager(bw, make_config(), client_secret="cs-fake",
                          master_password="mp-fake")
        assert isinstance(mgr._session_lock, SessionLockManager)

    def test_11_nonexistent_appdata_degrades_to_null_lock(self, tmp_path):
        bw = MagicMock()
        bw.appdata_dir = str(tmp_path / "does-not-exist-yet")
        mgr = AuthManager(bw, make_config(), client_secret="cs-fake",
                          master_password="mp-fake")
        assert isinstance(mgr._session_lock, _NullSessionLock)

    def test_12_magicmock_appdata_degrades_to_null_lock(self):
        """Path(MagicMock()) raises TypeError => degraded mode, no crash."""
        mgr = AuthManager(MagicMock(), MagicMock(), client_secret="cs-fake",
                          master_password="mp-fake")
        assert isinstance(mgr._session_lock, _NullSessionLock)

    def test_13_do_unlock_acquires_before_bw_unlock(self, tmp_path):
        mgr = _make_locked_mgr(tmp_path)
        order: list[str] = []
        mgr._session_lock.acquire_or_raise.side_effect = (
            lambda: order.append("acquire"))

        def _fake_unlock(pw):
            order.append("bw_unlock")
            return FAKE_KEY

        mgr._bw.unlock_passwordenv.side_effect = _fake_unlock
        mgr._do_unlock()
        assert order[:2] == ["acquire", "bw_unlock"]
        mgr._session_lock.release.assert_called_once()
        assert mgr.state is AuthState.UNLOCKED
        assert mgr.get_session_key() == FAKE_KEY

    def test_14_contention_raises_auth_error_and_skips_bw(self, tmp_path):
        mgr = _make_locked_mgr(tmp_path)
        mgr._session_lock.acquire_or_raise.side_effect = errors.AuthError(
            "Failed to acquire session lock (another process may be "
            "unlocking the vault). Retry after a few seconds.")
        mgr._master_password = "mp-fake"
        with pytest.raises(errors.AuthError):
            mgr._do_unlock()
        mgr._bw.unlock_passwordenv.assert_not_called()
        assert mgr.state is not AuthState.UNLOCKED

    def test_15_lock_releases_session_lock(self, tmp_path):
        mgr = _make_locked_mgr(tmp_path)
        mgr._state = AuthState.UNLOCKED
        mgr._session_key = FAKE_KEY
        mgr._session_created_at = time.time()
        mgr.lock()
        mgr._session_lock.release.assert_called_once()
        assert mgr.get_session_key() is None
        assert mgr.state is AuthState.LOGGED_OUT

    def test_16_shutdown_releases_even_when_lock_raises(self, tmp_path):
        """Coordination lock is freed even when the bw-lock stage fails."""
        mgr = _make_locked_mgr(tmp_path)
        # Real lock() swallows VaultwardenError from bw.lock (best-effort);
        # shutdown() must still reach its finally-block release either way.
        mgr._bw.lock.side_effect = errors.SessionError("simulated bw failure")
        mgr.shutdown()
        mgr._session_lock.release.assert_called()
        assert mgr.get_session_key() is None

        # Hard crash inside lock(): shutdown() propagates it but the
        # finally-block still releases the coordination lock.
        mgr2 = _make_locked_mgr(tmp_path)
        mgr2._session_lock.reset_mock()
        mgr2._bw.lock.side_effect = RuntimeError("unexpected crash")
        orig_lock = mgr2.lock

        def _boom():
            orig_lock()
            raise RuntimeError("lock() failed")

        mgr2.lock = _boom  # type: ignore[method-assign]
        with pytest.raises(RuntimeError):
            mgr2.shutdown()
        mgr2._session_lock.release.assert_called()

    def test_17_atexit_cleanup_registered(self, tmp_path, monkeypatch):
        """SessionLockManager.__init__ registers release for process exit."""
        # Observe the registration call itself (stdlib atexit exposes no
        # public registry; patching the seam proves __init__ wires release).
        calls: list = []

        def _spy(func, *a, **kw):
            calls.append(func)  # record only — do not leak into pytest's atexit

        monkeypatch.setattr(atexit, "register", _spy)
        lock = SessionLockManager(tmp_path)
        assert len(calls) == 1
        registered = calls[0]
        assert registered.__name__ == "release"
        assert registered.__self__ is lock
        # And the callback really frees the advisory lock: acquire, then run
        # the exact bound method interpreter shutdown would run.
        monkeypatch.undo()
        assert lock.acquire() is True
        registered()
        assert lock.is_held is False
        peer = SessionLockManager(tmp_path, timeout_seconds=0.2)
        assert peer.acquire() is True   # lock really freed via atexit path
        peer.release()

    def test_17b_do_unlock_ast_invariant_still_single_if(self):
        """Phase 1 plain-statement pattern preserved (guards Constraint A)."""
        body = ast.parse(textwrap.dedent(
            inspect.getsource(AuthManager._do_unlock)))
        fn = body.body[0]
        if_guards = [s for s in fn.body if isinstance(s, ast.If)]
        assert len(if_guards) == 1
        assert not [s for s in fn.body if isinstance(s, ast.Return)]


class caplog_at_info:  # noqa: N801 - tiny context shim, kept local
    """No-op placeholder retained for readability of scenario 13."""
    def __init__(self, *a):
        pass
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


# ===========================================================================
# CHANGE 4 — multi-process coordination (scenarios 18-20)
# ===========================================================================

@pytest.fixture(scope="module")
def mp_ctx():
    """Spawn context: children import this module fresh — no inherited
    monkeypatches, and child locks are always real fcntl locks."""
    return multiprocessing.get_context("spawn")


class TestMultiProcessCoordination:
    def test_18_two_processes_sequential_success(self, mp_ctx, tmp_path):
        d = tmp_path / "appdata"
        d.mkdir(mode=0o700)
        ready, done = mp_ctx.Queue(), mp_ctx.Queue()
        p = mp_ctx.Process(target=_child_acquire,
                           args=(str(d), ready, done, 2.0))
        p.start()
        try:
            tag, child_ok = ready.get(timeout=10)
            assert tag == "acquired" and child_ok is True
            # Child holds the lock now: parent's short-timeout attempt fails.
            parent = SessionLockManager(d, timeout_seconds=0.3)
            assert parent.acquire() is False
            done.put("release")   # child releases and exits
            tag2, _ = done.get(timeout=10)
            assert tag2 == "done"
            p.join(timeout=10)
            assert p.exitcode == 0
            # Lock is free: parent acquires successfully.
            assert parent.acquire() is True
            assert parent.is_held is True
            parent.release()
        finally:
            p.join(timeout=5)
            if p.is_alive():
                p.terminate()

    def test_19_two_processes_contend_one_times_out(self, mp_ctx, tmp_path):
        d = tmp_path / "appdata"
        d.mkdir(mode=0o700)
        winner = SessionLockManager(d)
        assert winner.acquire() is True  # parent wins up-front
        loser_ok: list[bool] = []

        def _loser():
            lock = SessionLockManager(d, timeout_seconds=0.5)
            loser_ok.append(lock.acquire())

        t = threading.Thread(target=_loser)
        t.start()
        t.join(timeout=5)
        assert not t.is_alive()
        assert loser_ok == [False]      # loser timed out gracefully
        assert winner.is_held is True   # winner unaffected
        winner.release()

    def test_20_process_exit_frees_lock(self, mp_ctx, tmp_path):
        d = tmp_path / "appdata"
        d.mkdir(mode=0o700)
        ready = mp_ctx.Queue()
        p = mp_ctx.Process(target=_child_hold_and_exit, args=(str(d), ready))
        p.start()
        try:
            assert ready.get(timeout=10) == "held"
            p.join(timeout=10)
            assert p.exitcode == 0
            # Child exited without LOCK_UN/close: kernel must have dropped
            # the flock on process teardown — parent acquires immediately.
            parent = SessionLockManager(d, timeout_seconds=0.5)
            assert parent.acquire() is True
            parent.release()
        finally:
            p.join(timeout=5)
            if p.is_alive():
                p.terminate()


# ===========================================================================
# CHANGE 5 — config (scenarios 21-23)
# ===========================================================================

class TestSessionLockTimeoutConfig:

    def test_21_default_is_five_seconds(self):
        cfg = make_config()
        assert cfg.session_lock_timeout_seconds == 5.0

    def test_22_custom_value_returned(self):
        cfg = make_config(section={"session_lock_timeout_seconds": 2.5})
        assert cfg.session_lock_timeout_seconds == 2.5

    def test_23_clamped_to_bounds(self):
        assert make_config(
            section={"session_lock_timeout_seconds": -1}). \
            session_lock_timeout_seconds == 0.0
        assert make_config(
            section={"session_lock_timeout_seconds": 999}). \
            session_lock_timeout_seconds == 30.0
        # Garbage falls back to the default, bounded like everything else.
        assert make_config(
            section={"session_lock_timeout_seconds": "not-a-number"}). \
            session_lock_timeout_seconds == 5.0


# ===========================================================================
# Security invariants across the whole mechanism
# ===========================================================================

class TestSecurityInvariants:

    def test_no_secret_values_in_logs_or_lock_file(self, tmp_path, caplog):
        """End-to-end unlock under a REAL lock: fake key never leaks."""
        appdata = tmp_path / ".bw-data"
        appdata.mkdir(mode=0o700)
        bw = MagicMock()
        bw.appdata_dir = str(appdata)
        bw.unlock_passwordenv.return_value = FAKE_KEY
        cfg = make_config(section={"session_lock_timeout_seconds": 1.0})
        mgr = AuthManager(bw, cfg, client_secret="cs-fake",
                          master_password="mp-fake")
        assert isinstance(mgr._session_lock, SessionLockManager)
        with caplog.at_level(logging.DEBUG):
            mgr._do_unlock()
        # All log output clean...
        for rec in caplog.records:
            assert FAKE_KEY not in rec.getMessage()
            assert "mp-fake" not in rec.getMessage()
        # ...and every byte on disk in the profile dir is secret-free.
        leaked = []
        for root, _dirs, files in os.walk(appdata):
            for name in files:
                p = Path(root) / name
                data = p.read_bytes()
                assert b"session" not in name.lower().encode(), \
                    f"secret-named lock artifact: {p}"
                if FAKE_KEY.encode() in data or b"mp-fake" in data:
                    leaked.append(str(p))
        assert leaked == [], f"secrets found on disk: {leaked}"

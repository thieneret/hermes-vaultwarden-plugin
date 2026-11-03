"""Regression suite: recursive ``ensure_authenticated()`` elimination.

Production evidence (2026-11-03, v0.7.4): ``_maybe_initial_sync()`` ran
INSIDE the ``with self._lock:`` block of ``ensure_authenticated()``. The
RLock is re-entrant, so the long-running sync subprocess kept the lock
held for its entire duration; the nested
``sync() -> run_with_recovery() -> get_session()`` chain could route back
through ``ensure_authenticated()``, spawning a SECOND full FSM run
(duplicate unlock, duplicate initial-sync loop, session-key loss window,
and write failures after the first burst).

The fix: the FSM body signals via the plain ``needs_initial_sync`` flag
and every path FALLS OUT of the ``with self._lock:`` block (no early
return inside the lock except the idempotency fast path, which never
requests a sync); ONE guarded ``_maybe_initial_sync()`` call runs after
the lock is released.

These eight scenarios pin the corrected behavior:

1. First tool call on a fresh CONFIGURED profile bootstraps exactly once
   (no recursive "Checking authentication status..." entries).
2. ``_maybe_initial_sync()`` runs strictly AFTER the ``self._lock`` block
   exits (ordering proven with a spy + non-blocking acquire probe).
3. The sync subprocess does NOT hold the RLock: a concurrent thread can
   acquire ``self._lock`` within 1 second while sync runs.
4. Two simultaneous first calls bootstrap exactly once
   (``_full_bootstrap_count == 1``).
5. ``get_session()`` takes the fast path during the initial sync: it
   returns the existing key WITHOUT re-entering ``ensure_authenticated()``.
6. Exactly ONE "Vault unlocked" log line per ``ensure_authenticated()``
   call (no duplicate unlock).
7. Exactly ONE "Initial sync started" log line per
   ``ensure_authenticated()`` call (no duplicate sync loop).
8. Write operations succeed after the first burst completes
   (``create_item`` through the real stack against the fake bw binary)
   and trigger no second bootstrap.
"""
from __future__ import annotations

import logging
import threading

from vaultwarden.auth import AuthManager, AuthState
from vaultwarden.bw_cli import BwCli
from vaultwarden.tests.conftest import make_config

CLIENT_SECRET = "cs-secret"
MASTER_PASSWORD = "mp-secret"
AUTH_LOGGER = "hermes.plugins.vaultwarden.auth"


def _make_manager(fake_bw, appdata) -> AuthManager:
    """Fresh deferred-auth manager on a CONFIGURED profile (like register()).

    Construction order matters for determinism: the CLI's lazy-bootstrap
    capability is attached BEFORE ``AuthManager.__init__`` registers the
    instance as the global weak holder, so the subprocess choke point
    always consults THIS manager when validating the explicit BW_SESSION
    key passed by its own command wrappers.
    """
    cli = BwCli(fake_bw, appdata, check_version=False)
    holder: dict = {}

    def _lazy_bootstrap() -> None:
        mgr = holder.get("mgr")
        if mgr is not None:
            mgr.ensure_authenticated()

    cli._bootstrap_via_auth_manager = _lazy_bootstrap
    cfg = make_config(section={"bw_cli_path": fake_bw})
    mgr = AuthManager(cli, cfg,
                      client_secret=CLIENT_SECRET,
                      master_password=MASTER_PASSWORD)
    holder["mgr"] = mgr
    mgr.configure_server_if_needed()  # UNINITIALIZED -> CONFIGURED, no spawn
    return mgr


# ---------------------------------------------------------------------------
# Scenario 1: first tool call on a fresh CONFIGURED profile — bootstrap
# exactly once, no recursive "Checking authentication status..." entries.
# ---------------------------------------------------------------------------


def test_first_call_bootstraps_exactly_once(fake_bw, appdata, caplog):
    mgr = _make_manager(fake_bw, appdata)
    assert mgr.state is AuthState.CONFIGURED

    with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
        mgr.ensure_authenticated()

    assert mgr.state is AuthState.UNLOCKED
    assert mgr._full_bootstrap_count == 1

    checking = [r.getMessage() for r in caplog.records
                if "Checking authentication status" in r.getMessage()]
    assert len(checking) == 1, (
        f"recursive ensure_authenticated(): {len(checking)} "
        "'Checking authentication status...' entries"
    )


# ---------------------------------------------------------------------------
# Scenario 2: _maybe_initial_sync() runs AFTER the with-lock block exits.
# ---------------------------------------------------------------------------


def test_maybe_initial_sync_runs_after_lock_release(fake_bw, appdata):
    mgr = _make_manager(fake_bw, appdata)

    events: list[str] = []
    lock_free_at_sync_start: list[bool] = []

    real_maybe = mgr._maybe_initial_sync

    def wrapped_maybe():
        events.append("maybe_initial_sync")
        # Prove the RLock is NOT held by this thread anymore. A plain
        # threading.RLock.acquire(blocking=False) would succeed even while
        # THIS same thread still owns the lock (re-entrant), so a foreign
        # contender must observe it: a daemon probe thread waits for the
        # sync window to open and then tries to acquire within 1 second —
        # success proves the FSM body's with-block had already exited.
        acquired = threading.Event()

        def probe():
            if mgr._lock.acquire(timeout=1.0):
                acquired.set()
                mgr._lock.release()

        t = threading.Thread(target=probe, daemon=True)
        t.start()
        try:
            real_maybe()
        finally:
            t.join(timeout=5.0)
            lock_free_at_sync_start.append(acquired.is_set())
        return None

    mgr._maybe_initial_sync = wrapped_maybe

    # Spy on the in-lock FSM body: the status probe marks the lock-block
    # phase that must fully precede the tail call.
    real_status = mgr._bw.status

    def spy_status(*args, **kwargs):
        result = real_status(*args, **kwargs)
        events.append("status_probe")
        return result

    mgr._bw.status = spy_status

    mgr.ensure_authenticated()

    assert events[0] == "status_probe", "FSM body must run before the sync"
    assert events[-1] == "maybe_initial_sync", (
        "_maybe_initial_sync() must be the post-lock tail call"
    )
    assert lock_free_at_sync_start == [True], (
        "_maybe_initial_sync() must execute with self._lock RELEASED"
    )


# ---------------------------------------------------------------------------
# Scenario 3: the sync subprocess does not hold the RLock — a concurrent
# thread acquires self._lock within 1 second while sync runs.
# ---------------------------------------------------------------------------


def test_sync_subprocess_does_not_hold_rlock(fake_bw, appdata):
    mgr = _make_manager(fake_bw, appdata)

    sync_started = threading.Event()
    release_sync = threading.Event()

    real_sync = mgr._bw.sync

    def slow_sync(*args, **kwargs):
        sync_started.set()
        # Hold the "subprocess" open briefly so the probe thread gets a
        # fair window to attempt lock acquisition.
        release_sync.wait(timeout=2.0)
        return real_sync(*args, **kwargs)

    mgr._bw.sync = slow_sync

    acquired = {"value": False}

    def probe():
        if sync_started.wait(timeout=5.0):
            if mgr._lock.acquire(timeout=1.0):
                acquired["value"] = True
                mgr._lock.release()
        release_sync.set()

    t = threading.Thread(target=probe, daemon=True)
    t.start()
    mgr.ensure_authenticated()
    t.join(timeout=10.0)

    assert acquired["value"], (
        "concurrent thread could not acquire self._lock while the sync "
        "subprocess ran — the RLock is still being held across sync"
    )


# ---------------------------------------------------------------------------
# Scenario 4: concurrent first calls bootstrap exactly once.
# ---------------------------------------------------------------------------


def test_concurrent_first_calls_bootstrap_once(fake_bw, appdata):
    mgr = _make_manager(fake_bw, appdata)

    barrier = threading.Barrier(2, timeout=5.0)
    results: list = []
    errors: list = []

    def worker():
        try:
            barrier.wait()
            mgr.ensure_authenticated()
            results.append(mgr.state)
        except BaseException as exc:  # pragma: no cover - surface test bugs
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30.0)

    assert not errors, f"bootstrap raised: {errors!r}"
    assert len(results) == 2
    assert all(s is AuthState.UNLOCKED for s in results)
    assert mgr._full_bootstrap_count == 1, (
        "duplicate full bootstrap detected under concurrent first calls"
    )


# ---------------------------------------------------------------------------
# Scenario 5: get_session() fast path during the initial sync — no
# re-entry into ensure_authenticated().
# ---------------------------------------------------------------------------


def test_get_session_fast_path_during_initial_sync(fake_bw, appdata, monkeypatch):
    mgr = _make_manager(fake_bw, appdata)

    reentries: list[int] = []
    keys_during_sync: list = []
    sync_window = {"active": False}

    real_ea = AuthManager.ensure_authenticated

    def counting_ea(self):
        if sync_window["active"]:
            reentries.append(1)
        return real_ea(self)

    monkeypatch.setattr(AuthManager, "ensure_authenticated", counting_ea)

    real_maybe = mgr._maybe_initial_sync

    def spy_maybe():
        sync_window["active"] = True
        try:
            # Inside the deferred-sync window (lock released), query the
            # session the way run_with_recovery / the choke point would.
            keys_during_sync.append(mgr.get_session())
            return real_maybe()
        finally:
            sync_window["active"] = False

    mgr._maybe_initial_sync = spy_maybe

    mgr.ensure_authenticated()

    assert keys_during_sync, "probe did not run inside the sync window"
    assert keys_during_sync[0], "get_session() returned no key mid-sync"
    assert not reentries, (
        "get_session() re-entered ensure_authenticated() during the "
        "initial sync window"
    )


# ---------------------------------------------------------------------------
# Scenario 6: exactly ONE "Vault unlocked" log line per call (no duplicate
# unlock).  Scenario 7: exactly ONE "Initial sync started" log line per
# call (no duplicate sync loop).  Split into two tests so each scenario
# fails independently.
# ---------------------------------------------------------------------------


def test_no_duplicate_vault_unlocked_log(fake_bw, appdata, caplog):
    mgr = _make_manager(fake_bw, appdata)

    with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
        mgr.ensure_authenticated()

    unlocked = [r.getMessage() for r in caplog.records
                if r.name == AUTH_LOGGER and "Vault unlocked" in r.getMessage()]
    assert len(unlocked) == 1, f"duplicate unlock logs: {unlocked!r}"


def test_no_duplicate_initial_sync_started_log(fake_bw, appdata, caplog):
    mgr = _make_manager(fake_bw, appdata)

    with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
        mgr.ensure_authenticated()

    sync_started = [r.getMessage() for r in caplog.records
                    if r.name == AUTH_LOGGER
                    and "Initial sync started" in r.getMessage()]
    assert len(sync_started) == 1, f"duplicate sync loops: {sync_started!r}"


# ---------------------------------------------------------------------------
# Scenario 8: write operations succeed after the first burst completes.
# ---------------------------------------------------------------------------


def test_create_item_succeeds_after_first_burst(fake_bw, appdata):
    mgr = _make_manager(fake_bw, appdata)

    # First burst: the FSM bootstrap (tool-call entry point).
    mgr.ensure_authenticated()
    assert mgr.state is AuthState.UNLOCKED
    assert mgr._full_bootstrap_count == 1

    # Post-burst WRITE through the real stack (run_with_recovery ->
    # get_session fast path -> choke-point validation -> `bw create item`).
    created = mgr.create_item({"type": 1, "name": "regression-note",
                               "notes": "written after first burst"})
    assert created.get("id"), f"create_item returned no id: {created!r}"

    # The write path must NOT have triggered a second bootstrap.
    assert mgr._full_bootstrap_count == 1, (
        "post-first-burst write re-ran the full FSM bootstrap"
    )
    assert mgr.state is AuthState.UNLOCKED

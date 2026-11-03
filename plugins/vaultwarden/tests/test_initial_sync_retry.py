"""v0.7.3 Phase 2 regression tests: bounded initial-sync retry + state tracking.

Covers the seven required scenarios:
  1. Initial sync succeeds on first attempt   -> _initial_sync_completed=True,
     no retry INFO logs
  2. Fails twice, succeeds on third           -> _initial_sync_completed=True,
     2 retry INFO lines + success INFO
  3. Fails all 3 attempts                     -> completed=False, failed=True,
     exhaustion WARNING (and per-attempt failures are INFO, not WARNING)
  4. AuthError during initial sync            -> NO retry, immediate WARNING
  5. SessionError during initial sync         -> NO retry, immediate WARNING
  6. Retry loop wall time < 30s (mocked sleep)
  7. No secret values in ANY log record

Hardening context (production incident 2026-11-02): a transient NetworkError
during the container's network cold-start window was swallowed by the old
single-shot _maybe_initial_sync(), leaving _last_sync=0.0 and an empty cache
for the whole process lifetime ("first-burst empty vault").
"""
from __future__ import annotations

import logging
import threading
import time

import pytest

from vaultwarden import errors
from vaultwarden.auth import AuthManager, AuthState
from vaultwarden.bw_cli import BwCli
from vaultwarden.tests.conftest import make_config

CLIENT_SECRET = "cs-secret"
MASTER_PASSWORD = "mp-secret"
SESSION_MARKER = "sessionkey"          # substring of the fake bw session key
AUTH_LOGGER = "hermes.plugins.vaultwarden.auth"


@pytest.fixture()
def mgr(fake_bw, appdata, plugin_config) -> AuthManager:
    """AuthManager with an UNLOCKED session but NO completed bootstrap yet.

    The full ``ensure_authenticated()`` bootstrap already performs the real
    initial sync (and would mark it complete), so Phase 2 tests need the
    retry loop itself to be the FIRST sync of the process. We therefore run
    the genuine bootstrap once against the fake bw binary, then construct a
    fresh manager sharing the same profile/config and adopt only the unlocked
    session state — exactly like the v0.7.3 Phase 1 suite does end-to-end.
    """
    warmer = AuthManager(BwCli(fake_bw, appdata, max_retries=0), plugin_config,
                         client_secret=CLIENT_SECRET,
                         master_password=MASTER_PASSWORD)
    warmer.ensure_authenticated()
    key = warmer.session_key
    assert key  # sanity: fake unlock produced a session key

    m = AuthManager.__new__(AuthManager)
    m._bw = BwCli(fake_bw, appdata, max_retries=0)
    m._config = plugin_config
    m._client_id = "user.11111111-2222-3333-4444-555555555555"
    m._client_secret = CLIENT_SECRET
    m._master_password = MASTER_PASSWORD
    m._session_key = key
    m._session_created_at = time.time()
    m._state = AuthState.UNLOCKED
    m._lock = threading.RLock()
    m._last_sync = 0.0
    m._initial_sync_completed = False
    m._initial_sync_failed = False
    return m


def _auth_messages(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == AUTH_LOGGER]


def _auth_records(caplog, level: int) -> list[logging.LogRecord]:
    return [r for r in caplog.records
            if r.name == AUTH_LOGGER and r.levelno == level]


def _install_outcomes(mgr: AuthManager, monkeypatch, outcomes: list,
                      sleeps: list[float]) -> None:
    """Make the next len(outcomes) sync subprocess calls yield outcomes.

    Each entry is either an Exception instance (raised) or a value returned
    by ``BwCli.sync``. ``time.sleep`` is captured into ``sleeps`` so retry
    delays never actually block the test.

    NOTE: exceptions must be raised from OUTSIDE run_with_recovery's wrapped
    callable — SessionError is caught there and triggers a real re-unlock
    recovery path (which would consume script entries out of order). So we
    patch AuthManager.run_with_recovery itself: every operation call maps to
    exactly ONE scripted outcome, keeping attempt accounting 1:1 with the
    retry loop.
    """
    remaining = list(outcomes)

    def fake_rwr(fn):
        if not remaining:
            raise AssertionError("fake bw sync called more times than scripted")
        outcome = remaining.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(mgr, "run_with_recovery", fake_rwr)
    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))


# ---------------------------------------------------------------------------
# Scenario 1: success on first attempt
# ---------------------------------------------------------------------------

class TestFirstAttemptSuccess:

    def test_completed_true_and_no_retry_logs(self, mgr, monkeypatch, caplog):
        sleeps: list[float] = []
        _install_outcomes(mgr, monkeypatch, [[{"id": "a"}, {"id": "b"}]], sleeps)

        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            mgr._maybe_initial_sync()

        assert mgr.initial_sync_completed is True
        assert mgr._initial_sync_completed is True
        assert mgr.initial_sync_failed is False
        assert mgr.last_sync > 0.0
        assert sleeps == []  # no retry delay consumed

        msgs = _auth_messages(caplog)
        assert any(m == "Initial sync started" for m in msgs), msgs
        assert any(m.startswith("Initial sync completed (2 items, ")
                   for m in msgs), msgs
        # No retry lifecycle noise on the happy path.
        assert not any("retrying in" in m for m in msgs), msgs
        assert not any("succeeded on attempt" in m for m in msgs), msgs
        assert not any("failed after" in m.lower() for m in msgs), msgs
        # No WARNING records at all on the success path.
        assert _auth_records(caplog, logging.WARNING) == []

    def test_second_call_is_idempotent(self, mgr, monkeypatch, caplog):
        # After completion, _maybe_initial_sync must not re-run the loop even
        # if _last_sync were somehow reset externally... it simply returns
        # because auto_sync gating + completed guard short-circuit.
        sleeps: list[float] = []
        _install_outcomes(mgr, monkeypatch, ["Syncing complete."], sleeps)
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            mgr._maybe_initial_sync()
        assert mgr.initial_sync_completed is True
        caplog.clear()
        mgr._last_sync = 0.0
        mgr._initial_sync_completed = True  # simulate sticky completion
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            mgr._maybe_initial_sync()
        assert not _auth_messages(caplog)


# ---------------------------------------------------------------------------
# Scenario 2: fail twice, succeed on third
# ---------------------------------------------------------------------------

class TestRetryThenSuccess:

    def test_two_retry_infos_then_success(self, mgr, monkeypatch, caplog):
        net1 = errors.NetworkError("transient DNS failure (cold start)")
        net2 = errors.NetworkError("transient TLS handshake failure")
        sleeps: list[float] = []
        _install_outcomes(mgr, monkeypatch,
                          [net1, net2, [{"id": "x"}]], sleeps)

        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            mgr._maybe_initial_sync()

        assert mgr.initial_sync_completed is True
        assert mgr.initial_sync_failed is False
        assert mgr.last_sync > 0.0
        # Exactly two inter-attempt sleeps, default config delay = 10s.
        assert sleeps == [10.0, 10.0]

        infos = _auth_messages(caplog)
        retries = [m for m in infos if "retrying in" in m]
        assert len(retries) == 2, infos
        assert retries[0].startswith(
            "Initial sync attempt 1/3 failed (NETWORK_ERROR), retrying in ")
        assert retries[1].startswith(
            "Initial sync attempt 2/3 failed (NETWORK_ERROR), retrying in ")
        assert any(m == "Initial sync retry loop started "
                        "(max 3 attempts, 10.0s interval)" for m in infos), infos
        assert any(m == "Initial sync succeeded on attempt 3 (1 items)"
                   for m in infos), infos
        assert any(m.startswith("Initial sync completed (1 items, ")
                   for m in infos), infos
        # Per-attempt failures are INFO only — no WARNING before success.
        assert _auth_records(caplog, logging.WARNING) == []


# ---------------------------------------------------------------------------
# Scenario 3: all 3 attempts fail (NetworkError) -> exhaustion WARNING
# ---------------------------------------------------------------------------

class TestRetryExhaustion:

    def test_exhaustion_sets_failed_and_warns_once(self, mgr, monkeypatch,
                                                   caplog):
        boom = errors.NetworkError("Vaultwarden server appears unreachable.")
        sleeps: list[float] = []
        _install_outcomes(mgr, monkeypatch, [boom, boom, boom], sleeps)

        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            mgr._maybe_initial_sync()   # best-effort: must NOT raise

        assert mgr.initial_sync_completed is False
        assert mgr.initial_sync_failed is True
        assert mgr._initial_sync_failed is True
        assert mgr.last_sync == 0.0
        # Sleep between attempts 1->2 and 2->3 only (bounded: 2 x 10s).
        assert sleeps == [10.0, 10.0]

        infos = _auth_messages(caplog)
        assert sum(1 for m in infos if "retrying in" in m) == 2, infos
        warns = [r.getMessage() for r in _auth_records(caplog, logging.WARNING)]
        assert any(m.startswith("Initial sync failed after 3 attempts; "
                                "cache unpopulated, will retry on first read")
                   for m in warns), warns
        # Only ONE WARNING record on the exhaustion path (the per-attempt
        # failures were INFO); the sanitized-code line doubles as the
        # Phase 1-compat final-failure WARNING.
        assert len(warns) == 1, warns
        assert "NETWORK_ERROR" in warns[0], warns[0]


# ---------------------------------------------------------------------------
# Scenarios 4 & 5: non-retryable error classes abort immediately
# ---------------------------------------------------------------------------

class TestNoRetryOnNonNetworkErrors:

    @pytest.mark.parametrize("exc_cls,code", [
        (errors.AuthError, "AUTH_ERROR"),
        (errors.SessionError, "SESSION_ERROR"),
    ])
    def test_immediate_warning_without_retry(self, mgr, monkeypatch, caplog,
                                             exc_cls, code):
        boom = exc_cls("non-transient failure")
        sleeps: list[float] = []
        _install_outcomes(mgr, monkeypatch, [boom], sleeps)

        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            mgr._maybe_initial_sync()   # swallows, logs WARNING

        # Exactly one sync subprocess attempt — NO retry.
        assert sleeps == []
        assert mgr.initial_sync_completed is False
        assert mgr.initial_sync_failed is True
        assert mgr.last_sync == 0.0

        infos = _auth_messages(caplog)
        assert not any("retrying in" in m for m in infos), infos
        warns = [r.getMessage() for r in _auth_records(caplog, logging.WARNING)]
        assert len(warns) == 1, warns
        assert f"Initial sync failed ({code}); cache unpopulated, " \
               "will retry on first read" in warns[0], warns[0]


# ---------------------------------------------------------------------------
# Scenario 6: total retry-loop wall time stays under 30s
# ---------------------------------------------------------------------------

class TestBoundedDuration:

    def test_wall_time_under_30_seconds(self, mgr, monkeypatch):
        boom = errors.NetworkError("always unreachable")
        sleeps: list[float] = []
        _install_outcomes(mgr, monkeypatch, [boom, boom, boom], sleeps)

        t0 = time.monotonic()
        with caplog_guard():
            mgr._maybe_initial_sync()
        elapsed = time.monotonic() - t0

        # Mocked sleep: recorded budget is 2 x 10s = 20s; real wall time is
        # milliseconds. Both must stay far below the 30s plugin-load ceiling.
        assert sum(sleeps) <= 20.0
        assert elapsed < 30.0

    def test_config_defaults_are_bounded(self, mgr):
        cfg = mgr._config
        assert cfg.initial_sync_max_attempts == 3
        assert cfg.initial_sync_retry_delay_seconds == 10.0
        # Worst-case sleep budget must fit inside the 30s load timeout.
        worst = (cfg.initial_sync_max_attempts - 1) * \
            cfg.initial_sync_retry_delay_seconds
        assert worst < 30.0

    def test_hostile_config_clamped(self):
        # A typo/malicious section can never push the loop past the budget:
        # attempts clamp to <= 3, delay clamps to <= 10s.
        cfg = make_config(section={"initial_sync_max_attempts": 999,
                                   "initial_sync_retry_delay_seconds": 3600})
        assert cfg.initial_sync_max_attempts == 3
        assert cfg.initial_sync_retry_delay_seconds == 10.0
        worst = (cfg.initial_sync_max_attempts - 1) * \
            cfg.initial_sync_retry_delay_seconds
        assert worst < 30.0


class caplog_guard:
    """Context manager placeholder: keeps the duration test readable."""

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


# ---------------------------------------------------------------------------
# Scenario 7: no secret values anywhere in the log output
# ---------------------------------------------------------------------------

class TestNoSecretsInLogs:

    def test_retry_paths_never_log_secrets(self, mgr, monkeypatch, caplog):
        boom = errors.NetworkError(
            f"unreachable; session={mgr.session_key} "
            f"secret={CLIENT_SECRET} mp={MASTER_PASSWORD}")
        sleeps: list[float] = []
        # Two transient failures carrying secret-bearing messages, then OK.
        _install_outcomes(mgr, monkeypatch,
                          [boom, boom, [{"id": "x"}]], sleeps)

        with caplog.at_level(logging.DEBUG, logger=AUTH_LOGGER):
            mgr._maybe_initial_sync()

        blob = "\n".join(r.getMessage() for r in caplog.records)
        assert CLIENT_SECRET not in blob
        assert MASTER_PASSWORD not in blob
        assert SESSION_MARKER not in blob
        if mgr.session_key:
            assert mgr.session_key not in blob
        # Positive control: the retry lifecycle really was logged.
        assert "Initial sync attempt 1/2" not in blob  # sanity: N=3 used
        assert "retrying in" in blob
        assert "NETWORK_ERROR" in blob

    def test_exhaustion_path_never_logs_secrets(self, mgr, monkeypatch, caplog):
        boom = errors.NetworkError(
            f"down; secret={CLIENT_SECRET} mp={MASTER_PASSWORD}")
        sleeps: list[float] = []
        _install_outcomes(mgr, monkeypatch, [boom, boom, boom], sleeps)

        with caplog.at_level(logging.DEBUG, logger=AUTH_LOGGER):
            mgr._maybe_initial_sync()

        blob = "\n".join(r.getMessage() for r in caplog.records)
        assert CLIENT_SECRET not in blob
        assert MASTER_PASSWORD not in blob
        assert SESSION_MARKER not in blob
        assert "failed after 3 attempts" in blob

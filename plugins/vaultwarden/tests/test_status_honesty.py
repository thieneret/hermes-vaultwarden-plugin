"""v0.7.3 Phase 4 regression tests: status honesty (cache-aware operational).

Covers the eight required scenarios:
  1. Valid session + populated cache   -> operational=True, cache_populated=True,
     no WARNING
  2. Valid session + unpopulated cache -> operational=False, cache_populated=False,
     contradiction WARNING logged
  3. No session + unpopulated cache    -> operational=False, cache_populated=False,
     no WARNING
  4. No session + populated cache      -> operational=False, cache_populated=True,
     no WARNING
  5. session_active unchanged          -> session-key-only predicate, not cache
  6. session_key_available unchanged   -> session-key-only predicate, not cache
  7. New fields present                -> cache_populated + initial_sync_completed
  8. No secret values in any log       -> distinctive fake secrets never appear

Hardening context (production incident 2026-11-02): vaultwarden_status
reported operational=true while the cache was never populated and every
read returned empty — the contradictory state behind the first-burst
empty-vault symptom. Phase 4 makes `operational` require BOTH a usable
session AND at least one completed sync.
"""
from __future__ import annotations

import logging
import threading
import time

import pytest

from vaultwarden.auth import AuthManager, AuthState
from vaultwarden.bw_cli import BwCli

CLIENT_SECRET = "cs-secret"
MASTER_PASSWORD = "mp-secret"
SESSION_MARKER = "sessionkey"          # substring of the fake bw session key
AUTH_LOGGER = "hermes.plugins.vaultwarden.auth"


def _make_manager(plugin_config, appdata, fake_bw, *, unlocked: bool,
                  last_sync: float) -> AuthManager:
    """Hand-built AuthManager sharing the isolated test profile.

    Mirrors the Phase 1/2 suites: real bootstrap once via a warmer manager,
    then adopt only the session state we need for the snapshot under test.
    """
    m = AuthManager.__new__(AuthManager)
    m._bw = BwCli(fake_bw, appdata, max_retries=0)
    m._config = plugin_config
    m._client_id = "user.11111111-2222-3333-4444-555555555555"
    m._client_secret = CLIENT_SECRET
    m._master_password = MASTER_PASSWORD
    m._lock = threading.RLock()
    m._last_sync = last_sync
    m._initial_sync_completed = last_sync > 0.0
    m._initial_sync_failed = False
    m._sync_warn_suppressed = False
    if unlocked:
        warmer = AuthManager(BwCli(fake_bw, appdata, max_retries=0),
                             plugin_config,
                             client_secret=CLIENT_SECRET,
                             master_password=MASTER_PASSWORD)
        warmer._client_id = m._client_id
        warmer.ensure_authenticated()
        key = warmer.session_key
        assert key  # sanity: fake unlock produced a session key
        m._session_key = key
        m._session_created_at = time.time()
        m._state = AuthState.UNLOCKED
    else:
        m._session_key = None
        m._session_created_at = None
        m._state = AuthState.LOGGED_IN
    return m


@pytest.fixture()
def mgr_factory(plugin_config, appdata, fake_bw):
    def factory(*, unlocked: bool, last_sync: float) -> AuthManager:
        return _make_manager(plugin_config, appdata, fake_bw,
                             unlocked=unlocked, last_sync=last_sync)
    return factory


def _auth_messages(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == AUTH_LOGGER]


def _warnings(caplog) -> list[logging.LogRecord]:
    return [r for r in caplog.records
            if r.name == AUTH_LOGGER and r.levelno == logging.WARNING]


CONTRADICTION = "Status inconsistency: session active but cache never populated"


# ---------------------------------------------------------------------------
# Scenario 1: valid session + populated cache
# ---------------------------------------------------------------------------
class TestOperationalWithPopulatedCache:
    def test_operational_true_and_no_warning(self, mgr_factory, caplog):
        mgr = mgr_factory(unlocked=True, last_sync=time.time() - 5.0)
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            snap = mgr.status_snapshot()
        assert snap["operational"] is True
        assert snap["cache_populated"] is True
        assert snap["initial_sync_completed"] is True
        assert CONTRADICTION not in _auth_messages(caplog)


# ---------------------------------------------------------------------------
# Scenario 2: valid session + unpopulated cache (the contradiction)
# ---------------------------------------------------------------------------
class TestContradiction:
    def test_operational_false_and_warning(self, mgr_factory, caplog):
        mgr = mgr_factory(unlocked=True, last_sync=0.0)
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            snap = mgr.status_snapshot()
        assert snap["operational"] is False
        assert snap["cache_populated"] is False
        msgs = _auth_messages(caplog)
        assert CONTRADICTION in msgs

    def test_warning_fires_exactly_once_per_call(self, mgr_factory, caplog):
        mgr = mgr_factory(unlocked=True, last_sync=0.0)
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            mgr.status_snapshot()
            mgr.status_snapshot()
        hits = [m for m in _auth_messages(caplog) if m == CONTRADICTION]
        assert len(hits) == 2  # one per explicit status call, nothing more

    def test_session_predicates_still_true_in_contradiction(
        self, mgr_factory, caplog
    ):
        # The WARNING must not change session-key-only semantics.
        mgr = mgr_factory(unlocked=True, last_sync=0.0)
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            snap = mgr.status_snapshot()
        assert snap["session_active"] is True
        assert snap["session_key_available"] is True
        assert snap["operational"] is False


# ---------------------------------------------------------------------------
# Scenarios 3 & 4: no session
# ---------------------------------------------------------------------------
class TestNoSession:
    def test_unpopulated_cache_no_warning(self, mgr_factory, caplog):
        mgr = mgr_factory(unlocked=False, last_sync=0.0)
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            snap = mgr.status_snapshot()
        assert snap["operational"] is False
        assert snap["cache_populated"] is False
        assert snap["session_active"] is False
        assert snap["session_key_available"] is False
        assert CONTRADICTION not in _auth_messages(caplog)

    def test_populated_cache_no_warning(self, mgr_factory, caplog):
        mgr = mgr_factory(unlocked=False, last_sync=time.time() - 5.0)
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            snap = mgr.status_snapshot()
        assert snap["operational"] is False
        assert snap["cache_populated"] is True
        assert snap["session_active"] is False
        assert CONTRADICTION not in _auth_messages(caplog)


# ---------------------------------------------------------------------------
# Scenarios 5 & 6: unchanged session predicates across cache states
# ---------------------------------------------------------------------------
class TestSessionSemanticsUnchanged:
    @pytest.mark.parametrize("last_sync", [0.0, 12345.0])
    def test_session_fields_track_key_only(self, mgr_factory, last_sync):
        mgr = mgr_factory(unlocked=True, last_sync=last_sync)
        snap = mgr.status_snapshot()
        assert snap["session_active"] is True
        assert snap["session_key_available"] is True


# ---------------------------------------------------------------------------
# Scenario 7: new fields present, additive, backward compatible
# ---------------------------------------------------------------------------
class TestNewFieldsPresent:
    def test_fields_exist_with_bool_type(self, mgr_factory):
        mgr = mgr_factory(unlocked=True, last_sync=0.0)
        snap = mgr.status_snapshot()
        assert "cache_populated" in snap
        assert "initial_sync_completed" in snap
        assert isinstance(snap["cache_populated"], bool)
        assert isinstance(snap["initial_sync_completed"], bool)
        assert isinstance(snap["operational"], bool)

    def test_existing_keys_not_removed(self, mgr_factory):
        mgr = mgr_factory(unlocked=True, last_sync=0.0)
        snap = mgr.status_snapshot()
        for key in ("plugin", "enabled", "auth_state", "session_active",
                    "session_age_seconds", "session_timeout_seconds",
                    "server_configured", "session_key_available",
                    "operational", "bw_profile_state", "server_status",
                    "appdata_dir", "allow_write", "last_sync"):
            assert key in snap, f"regression: field {key!r} missing"

    def test_initial_sync_completed_property_backed(self, mgr_factory):
        mgr = mgr_factory(unlocked=True, last_sync=time.time() - 1.0)
        mgr._initial_sync_completed = False
        snap = mgr.status_snapshot()
        assert snap["initial_sync_completed"] is False
        assert snap["cache_populated"] is True  # independent of loop flag


# ---------------------------------------------------------------------------
# Scenario 8: no secrets in logs
# ---------------------------------------------------------------------------
class TestNoSecretsInLogs:
    def test_contradiction_path_logs_no_secrets(self, mgr_factory, caplog):
        mgr = mgr_factory(unlocked=True, last_sync=0.0)
        key = mgr.session_key
        assert key and SESSION_MARKER in key
        with caplog.at_level(logging.DEBUG, logger=AUTH_LOGGER):
            mgr.status_snapshot()
        blob = "\n".join(r.getMessage() for r in caplog.records)
        for secret in (key, MASTER_PASSWORD, CLIENT_SECRET):
            assert secret not in blob

    def test_all_four_states_log_no_secrets(self, mgr_factory, caplog):
        for unlocked in (True, False):
            for last_sync in (0.0, time.time() - 2.0):
                mgr = mgr_factory(unlocked=unlocked, last_sync=last_sync)
                with caplog.at_level(logging.DEBUG, logger=AUTH_LOGGER):
                    mgr.status_snapshot()
        blob = "\n".join(r.getMessage() for r in caplog.records)
        key = mgr.session_key or ""
        for secret in (key, MASTER_PASSWORD, CLIENT_SECRET):
            if secret:
                assert secret not in blob

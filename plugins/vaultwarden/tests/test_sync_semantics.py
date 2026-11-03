"""v0.7.3 Phase 1 regression tests: sync verb semantics + sync observability.

Covers the eight required scenarios:
  1. sync() with _last_sync == 0.0   -> FULL `bw sync` (no --last) + INFO decision log
  2. sync() with _last_sync  > 0.0   -> DELTA `bw sync --last` + INFO decision log
  3. sync() success                  -> INFO "Sync completed" (item count when parseable)
  4. sync() failure                  -> WARNING with sanitized error code + cache state
  5. sync() skip (cache fresh)       -> INFO "Sync skipped" with age
  6. _maybe_initial_sync() success   -> INFO "Initial sync completed"
  7. _maybe_initial_sync() failure   -> WARNING "Initial sync failed"
  8. no secret values in ANY log record

Hardening context (production incident 2026-11-02): a failed initial sync
left _last_sync=0.0 with zero log evidence, and sync(force=True) on a fresh
process issued `bw sync --last` — a delta pull keyed to the CLI's own sync
timestamp that can report success while pulling NOTHING on a profile whose
full snapshot was never taken (empty vault, {"synced": true}).
"""
from __future__ import annotations

import logging

import pytest

from vaultwarden import errors
from vaultwarden.auth import AuthManager, AuthState
from vaultwarden.tests.conftest import make_config

CLIENT_SECRET = "cs-secret"
MASTER_PASSWORD = "mp-secret"
SESSION_MARKER = "sessionkey"          # substring of the fake bw session key
AUTH_LOGGER = "hermes.plugins.vaultwarden.auth"


@pytest.fixture()
def mgr(bw_cli, plugin_config) -> AuthManager:
    """Unlocked AuthManager over the fake bw binary; _last_sync reset to 0.0."""
    m = AuthManager(bw_cli, plugin_config,
                    client_secret=CLIENT_SECRET, master_password=MASTER_PASSWORD)
    m.ensure_authenticated()
    m._last_sync = 0.0
    return m


def _auth_messages(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == AUTH_LOGGER]


def _auth_records(caplog, level: int) -> list[logging.LogRecord]:
    return [r for r in caplog.records
            if r.name == AUTH_LOGGER and r.levelno == level]


# ---------------------------------------------------------------------------
# Scenario 1: fresh process (_last_sync == 0.0) => FULL sync, never --last
# ---------------------------------------------------------------------------

class TestSyncVerbSelection:

    def test_fresh_process_uses_full_sync(self, mgr, monkeypatch, caplog):
        seen: list[dict] = []

        def fake_sync(session_key, force=False, *, full=None):
            seen.append({"force": force, "full": full})
            return "Syncing complete."

        monkeypatch.setattr(mgr._bw, "sync", fake_sync)
        assert mgr.last_sync == 0.0
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            result = mgr.sync(force=True)

        assert result["synced"] is True
        assert len(seen) == 1
        # CHANGE 1 contract: full pull explicitly requested, no delta flag.
        assert seen[0]["full"] is True
        msgs = _auth_messages(caplog)
        assert any("Running full sync (no prior sync in this process)" in m
                   for m in msgs), msgs

    def test_fresh_process_forced_sync_still_full(self, mgr, caplog):
        """The exact v0.7.2 bug: force=True on _last_sync==0.0 must NOT be --last."""
        recorded: list[list[str]] = []
        real_run = mgr._bw.run

        def spy_run(args, **kw):
            recorded.append(list(args))
            return real_run(args, **kw)

        mgr._bw.run = spy_run
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            mgr.sync(force=True)

        assert recorded, "no bw invocation recorded"
        assert recorded[-1] == ["sync"], \
            f"fresh process must run plain 'bw sync', got {recorded[-1]}"
        assert "--last" not in recorded[-1]

    def test_prior_sync_uses_delta_last(self, mgr, monkeypatch, caplog):
        seen: list[dict] = []

        def fake_sync(session_key, force=False, *, full=None):
            seen.append({"force": force, "full": full})
            return "Syncing complete."

        monkeypatch.setattr(mgr._bw, "sync", fake_sync)
        mgr._last_sync = 1234.5
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            result = mgr.sync(force=True)

        assert result["synced"] is True
        assert len(seen) == 1
        assert seen[0]["full"] is False
        msgs = _auth_messages(caplog)
        assert any("Running delta sync --last (last_sync=1234.5)" in m
                   for m in msgs), msgs

    def test_bw_cli_sync_verb_mapping(self, bw_cli, monkeypatch):
        """BwCli.sync(): full=True -> ['sync']; full=False -> ['sync','--last'].

        Legacy force mapping preserved (v0.4.8 permanent-delete recovery calls
        bare sync(session_key) and needs the FULL pull).
        """
        recorded: list[list[str]] = []

        def fake_run(args, **kw):
            recorded.append(list(args))
            return "ok"

        bw_cli.run = fake_run

        bw_cli.sync("sess", full=True)
        assert recorded[-1] == ["sync"]
        bw_cli.sync("sess", full=False)
        assert recorded[-1] == ["sync", "--last"]
        bw_cli.sync("sess")                 # legacy default -> full pull
        assert recorded[-1] == ["sync"]
        bw_cli.sync("sess", force=True)     # legacy force -> delta
        assert recorded[-1] == ["sync", "--last"]


# ---------------------------------------------------------------------------
# Scenario 3: success path logged at INFO (with item count when parseable)
# ---------------------------------------------------------------------------

class TestSyncSuccessLogging:

    def test_success_logs_completed_with_item_count(self, mgr, monkeypatch, caplog):
        items = [{"id": "a"}, {"id": "b"}, {"id": "c"}]
        monkeypatch.setattr(mgr._bw, "sync", lambda s, **kw: items)
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            result = mgr.sync(force=True)

        assert result["synced"] is True
        assert result["timestamp"] > 0.0
        assert mgr.last_sync > 0.0
        msgs = _auth_messages(caplog)
        assert any(m.startswith("Sync completed (3 items, ") and m.endswith("s)")
                   for m in msgs), msgs

    def test_success_omits_count_when_unparseable(self, mgr, monkeypatch, caplog):
        monkeypatch.setattr(mgr._bw, "sync",
                            lambda s, **kw: "Encoding complete.")
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            mgr.sync(force=True)

        msgs = _auth_messages(caplog)
        completions = [m for m in msgs if m.startswith("Sync completed")]
        assert completions, msgs
        # No item count available -> count omitted entirely (spec rule).
        assert "items" not in completions[0], completions[0]
        # Duration rendered with one decimal place + trailing 's'.
        body = completions[len(completions) - 1][len("Sync completed ("):]
        assert body.endswith("s)")
        float(body[:-2])  # raises ValueError if not "<n>.<d>"

    def test_duration_measured_with_monotonic(self, mgr, monkeypatch, caplog):
        """Duration uses time.monotonic(), not wall-clock time.time()."""
        ticks = iter([100.0, 103.0])
        real_monotonic = __import__("time").monotonic

        def fake_monotonic():
            try:
                return next(ticks)
            except StopIteration:
                return real_monotonic()

        monkeypatch.setattr("vaultwarden.auth.time.monotonic", fake_monotonic)
        monkeypatch.setattr(mgr._bw, "sync", lambda s, **kw: "ok")
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            mgr.sync(force=True)

        msgs = _auth_messages(caplog)
        assert any("Sync completed (3.0s)" in m for m in msgs), msgs


# ---------------------------------------------------------------------------
# Scenario 4: failure path logged at WARNING (sanitized code + cache state)
# ---------------------------------------------------------------------------

class TestSyncFailureLogging:

    def test_failure_unpopulated_logs_warning_with_code(self, mgr, monkeypatch, caplog):
        boom = errors.NetworkError("Vaultwarden server appears unreachable.")

        def fake_sync(session_key, force=False, *, full=None):
            raise boom

        monkeypatch.setattr(mgr._bw, "sync", fake_sync)
        assert mgr.last_sync == 0.0
        with caplog.at_level(logging.WARNING, logger=AUTH_LOGGER):
            with pytest.raises(errors.NetworkError):
                mgr.sync(force=True)

        warns = [r.getMessage() for r in _auth_records(caplog, logging.WARNING)]
        assert any("Sync failed (NETWORK_ERROR); cache state: unpopulated" in w
                   for w in warns), warns
        # Cache stays unpopulated after a failed first sync.
        assert mgr.last_sync == 0.0

    def test_failure_populated_cache_state(self, mgr, monkeypatch, caplog):
        mgr._last_sync = 999.0
        boom = errors.RateLimitError("rate limited")
        monkeypatch.setattr(mgr._bw, "sync",
                            lambda s, force=False, *, full=None: (_ for _ in ()).throw(boom))
        # Skip the real backoff sleeps inside _rate_limited.
        monkeypatch.setattr("vaultwarden.auth.time.sleep", lambda *_: None)
        with caplog.at_level(logging.WARNING, logger=AUTH_LOGGER):
            with pytest.raises(errors.RateLimitError):
                mgr.sync(force=True)

        warns = [r.getMessage() for r in _auth_records(caplog, logging.WARNING)]
        assert any("Sync failed (RATE_LIMIT); cache state: populated" in w
                   for w in warns), warns

    def test_failure_message_is_sanitized(self, mgr, monkeypatch, caplog):
        """Only the constant error code appears — never raw exception text."""
        boom = errors.SessionError(
            f"vault is locked; key={CLIENT_SECRET}{MASTER_PASSWORD}")
        monkeypatch.setattr(mgr._bw, "sync",
                            lambda s, force=False, *, full=None: (_ for _ in ()).throw(boom))
        with caplog.at_level(logging.WARNING, logger=AUTH_LOGGER):
            with pytest.raises(errors.SessionError):
                mgr.sync(force=True)

        joined = "\n".join(_auth_messages(caplog))
        assert "Sync failed (SESSION_ERROR)" in joined
        assert "vault is locked" not in joined


# ---------------------------------------------------------------------------
# Scenario 5: skip path logged at INFO with last_sync + age
# ---------------------------------------------------------------------------

class TestSyncSkipLogging:

    def test_skip_logs_age_and_last_sync(self, mgr, monkeypatch, caplog):
        called: list[int] = []
        monkeypatch.setattr(mgr._bw, "sync",
                            lambda s, **kw: called.append(1) or "ok")
        mgr._last_sync = __import__("time").time() - 42.0
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            result = mgr.sync(force=False)

        assert result["synced"] is False
        assert result.get("skipped") == "cache fresh"
        assert not called, "skip path must not spawn bw sync"
        msgs = _auth_messages(caplog)
        matching = [m for m in msgs if m.startswith("Sync skipped: cache fresh")]
        assert matching, msgs
        assert "age=42.0s" in matching[0], matching[0]
        assert f"last_sync={mgr._last_sync:.1f}" in matching[0]


# ---------------------------------------------------------------------------
# Scenarios 6 & 7: _maybe_initial_sync() observability
# ---------------------------------------------------------------------------

class TestInitialSyncLogging:

    def test_initial_sync_success_logged(self, mgr, monkeypatch, caplog):
        monkeypatch.setattr(mgr._bw, "sync",
                            lambda s, **kw: [{"id": "x"}, {"id": "y"}])
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            mgr._maybe_initial_sync()

        msgs = _auth_messages(caplog)
        assert any(m == "Initial sync started" for m in msgs), msgs
        assert any(m.startswith("Initial sync completed (2 items, ")
                   and m.endswith("s)") for m in msgs), msgs
        assert mgr.last_sync > 0.0
        # Failure wording must NOT appear on the success path.
        assert not any("failed" in m.lower() for m in msgs), msgs

    def test_initial_sync_failure_logged(self, mgr, monkeypatch, caplog):
        boom = errors.NetworkError("Vaultwarden server appears unreachable.")

        def fake_sync(session_key, force=False, *, full=None):
            raise boom

        monkeypatch.setattr(mgr._bw, "sync", fake_sync)
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            mgr._maybe_initial_sync()   # best-effort: must NOT raise

        msgs = _auth_messages(caplog)
        assert any(m == "Initial sync started" for m in msgs), msgs
        warns = [r.getMessage() for r in _auth_records(caplog, logging.WARNING)]
        assert any("Initial sync failed (NETWORK_ERROR); cache unpopulated, "
                   "will retry on first read" in w for w in warns), warns
        assert mgr.last_sync == 0.0

    def test_initial_sync_skips_when_already_synced(self, mgr, monkeypatch, caplog):
        called: list[int] = []
        monkeypatch.setattr(mgr._bw, "sync",
                            lambda s, **kw: called.append(1) or "ok")
        mgr._last_sync = 1234.5
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            mgr._maybe_initial_sync()

        assert not called
        assert not _auth_messages(caplog)


# ---------------------------------------------------------------------------
# End-to-end through the FSM bootstrap (fake bw binary)
# ---------------------------------------------------------------------------

class TestBootstrapIntegration:

    def test_bootstrap_runs_full_initial_sync_and_logs(self, fake_bw, appdata, caplog):
        from vaultwarden.bw_cli import BwCli

        recorded: list[list[str]] = []
        cli = BwCli(fake_bw, appdata)
        real_run = cli.run

        def spy_run(args, **kw):
            recorded.append(list(args))
            return real_run(args, **kw)

        cli.run = spy_run
        cfg = make_config(section={"bw_cli_path": fake_bw})
        mgr = AuthManager(cli, cfg,
                          client_secret=CLIENT_SECRET, master_password=MASTER_PASSWORD)
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            mgr.ensure_authenticated()

        sync_calls = [a for a in recorded if a and a[0] == "sync"]
        assert sync_calls, f"initial sync never ran; cmds={recorded}"
        # Fresh process: the FIRST sync of the bootstrap must be a FULL pull.
        assert sync_calls[0] == ["sync"], sync_calls
        assert "--last" not in sync_calls[0]

        msgs = _auth_messages(caplog)
        assert any(m == "Initial sync started" for m in msgs), msgs
        assert any("Running full sync (no prior sync in this process)" in m
                   for m in msgs), msgs
        assert any(m.startswith("Sync completed") for m in msgs), msgs
        assert any(m.startswith("Initial sync completed") for m in msgs), msgs
        assert mgr.last_sync > 0.0

        # Second bootstrap-phase sync (if forced) now takes the delta path.
        recorded.clear()
        with caplog.at_level(logging.INFO, logger=AUTH_LOGGER):
            mgr.sync(force=True)
        sync_calls = [a for a in recorded if a and a[0] == "sync"]
        assert sync_calls[-1] == ["sync", "--last"]


# ---------------------------------------------------------------------------
# Scenario 8: no secret values anywhere in the emitted log records
# ---------------------------------------------------------------------------

class TestNoSecretsInLogs:

    def test_all_sync_paths_free_of_secrets(self, mgr, caplog):
        key = mgr.get_session()
        assert SESSION_MARKER in key  # sanity: fake unlock produced a key

        # Success path (fake bw prints "Encoding complete.").
        with caplog.at_level(logging.DEBUG, logger=AUTH_LOGGER):
            mgr.sync(force=True)
            # Delta path with a prior sync.
            mgr.sync(force=True)
            # Skip path (cache is fresh right after the two syncs above).
            mgr.sync(force=False)
            # Initial-sync success path.
            mgr._last_sync = 0.0
            mgr._maybe_initial_sync()

        # Failure paths (in-memory manager; subprocesses never spawned).
        failing = AuthManager.__new__(AuthManager)
        import threading
        failing._lock = threading.RLock()
        failing._state = AuthState.UNLOCKED
        failing._session_key = key
        failing._session_created_at = __import__("time").time()
        failing._last_sync = 0.0
        failing._client_id = "user.11111111-2222-3333-4444-555555555555"

        class _Cfg:
            auto_sync = True
            sync_interval_seconds = 300
            session_timeout_seconds = 14400
            # Phase 2: single attempt so the manual-state test exercises the
            # exhaustion WARNING without sleeping between retries.
            initial_sync_max_attempts = 1
            initial_sync_retry_delay_seconds = 0.0

        failing._config = _Cfg()
        # The manually-assembled manager bypasses AuthManager.__init__'s
        # Phase 2 state fields; restore them so _maybe_initial_sync() works.
        failing._initial_sync_completed = False
        failing._initial_sync_failed = False
        failing._sync_warn_suppressed = False

        class _FailingBw:
            def sync(self, session_key, force=False, *, full=None):
                raise errors.NetworkError(
                    f"unreachable; session={session_key} "
                    f"secret={CLIENT_SECRET} mp={MASTER_PASSWORD}")

        failing._bw = _FailingBw()
        with caplog.at_level(logging.DEBUG, logger=AUTH_LOGGER):
            with pytest.raises(errors.VaultwardenError):
                failing.sync(force=True)
            failing._maybe_initial_sync()   # swallows, logs WARNING

        blob = "\n".join(r.getMessage() for r in caplog.records)
        assert CLIENT_SECRET not in blob
        assert MASTER_PASSWORD not in blob
        assert SESSION_MARKER not in blob
        assert key not in blob
        # Positive control: the sync-path logs really were emitted.
        assert "Sync failed (NETWORK_ERROR)" in blob
        assert "Initial sync failed (NETWORK_ERROR)" in blob

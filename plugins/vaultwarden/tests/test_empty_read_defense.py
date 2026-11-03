"""v0.7.3 Phase 3 regression suite: empty-read defense EXTENSION.

Second leg of the first-burst empty vault bug (production 2026-11-02):
the v0.7.2 CHANGE 5 blind-spot defense only fired when
``get_session_key()`` returned None (non-UNLOCKED state). When the session
WAS valid but this process never completed a sync (``last_sync == 0.0``),
``bw list items`` legitimately answers exit 0 + ``[]`` against an
unpopulated local cache — and the empty result was silently accepted as a
"genuinely empty vault".

Fixes pinned by this file:
  CHANGE 1  second suspect condition: items == [] AND last_sync == 0.0
            (while UNLOCKED) -> forced FULL sync + exactly ONE read retry,
            with WARNING on suspicion and INFO on trigger/result lines.
  CHANGE 2  the forced sync uses the FULL verb — v0.7.4 correction:
            ``bw sync --force`` (the old ``--last`` "delta" verb is a
            read-only date query that never synced) — consistent with the
            Phase 1 verb selection; routed through AuthManager.sync(force=True).
  CHANGE 3  this regression suite (8 mandated scenarios).

v0.7.6 (Phase 1, session invalidation defense) EXTENSION pinned here too:
  CHANGE 1  BwCli.verify_session(): asks ``bw status`` WITH BW_SESSION
            whether a key still authenticates (the persistent profile
            always reports "locked", so only the key answers honestly);
            SessionError -> "locked", other VaultwardenError -> "unknown".
  CHANGE 2  THIRD suspect condition: items == [] AND key_valid AND
            last_sync > 0.0 -> verify the key; on "locked"/
            "unauthenticated" force ONE re-unlock + ONE retry (multi-
            AuthManager scenario: another process's unlock invalidated
            our key). "unlocked" -> genuinely empty vault, accepted.

Hard boundaries pinned here too:
  * NO false positives: last_sync > 0.0 (populated cache) or non-empty
    reads never spawn extra subprocesses;
  * graceful degradation: sync failure returns the original empty list;
    a still-empty retry is accepted (no infinite loop);
  * write operations are NOT reconciled (defense is read-path only);
  * no secret value ever appears in any log line.

All managers are duck-typed stubs registered via
``register_auth_manager()`` (weakref holders clear between registrations,
so tests that must see "no manager" simply construct a fresh BwCli AFTER
registering a throwaway double).
"""
from __future__ import annotations

import pytest

from vaultwarden import errors
from vaultwarden.bw_cli import BwCli, get_auth_manager, register_auth_manager

SESSION_KEY = "abcdef0123456789-sessionkey-FEEDFACE"
CS_SECRET = "cs-secret-value-XYZ"      # fixture client secret (fake)
MP_SECRET = "mp-secret-value-ABC"      # fixture master password (fake)

ITEM_A = {"id": "aaaa1111-0000-0000-0000-000000000001", "name": "Postgres prod"}
ITEM_B = {"id": "aaaa1111-0000-0000-0000-000000000002", "name": "Grafana"}


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class StubAuth:
    """Duck-typed AuthManager stand-in for the bw_cli-side defense.

    ``session_key`` models get_session_key(): None means the NON-UNLOCKED
    leg (v0.7.2 CHANGE 5 reconcile path); a value means UNLOCKED, where the
    Phase 3 second suspect condition (last_sync == 0.0) applies.
    """

    def __init__(self, *, session_key=None, last_sync=0.0,
                 sync_result=None, sync_exc=None, fresh_key=None,
                 get_session_exc=None):
        self._session_key = session_key
        self.last_sync = last_sync
        self.sync_payload = sync_result
        self._sync_exc = sync_exc
        self.sync_calls: list[bool] = []
        # v0.7.6 (Phase 1) third-condition plumbing: get_session() models
        # AuthManager.get_session() — by default it hands back the CURRENT
        # key (the fast path), which the defense treats as "re-unlock
        # produced nothing new". ``fresh_key`` scripts a successful
        # re-unlock; ``get_session_exc`` scripts a failed one.
        self._fresh_key = fresh_key
        self._get_session_exc = get_session_exc
        self.get_session_calls = 0
        self.invalidate_calls = 0
        self.cli = None  # test wires a SpyCli to observe the verb

    def get_session_key(self):
        return self._session_key

    def ensure_authenticated(self):
        pass

    def invalidate_session(self):
        # Models the local-state demotion the defense performs BEFORE
        # re-unlocking (a real AuthManager clears its stale key so the
        # FSM fast path cannot hand the dead key back).
        self.invalidate_calls += 1
        self._session_key = None

    def get_session(self):
        self.get_session_calls += 1
        if self._get_session_exc is not None:
            raise self._get_session_exc
        if self._fresh_key is not None:
            self._session_key = self._fresh_key
            return self._fresh_key
        return self._session_key

    def sync(self, force=False):
        self.sync_calls.append(bool(force))
        # Mirror AuthManager.sync(): after Phase 1 the manager owns the verb
        # selection (FULL while _last_sync == 0.0, delta afterwards) and the
        # _last_sync transition. Delegation to the CLI records the actual
        # subprocess plan; a failed sync NEVER advances last_sync.
        if self.cli is not None:
            result = self.cli.sync(self._session_key or "",
                                   full=self.last_sync == 0.0)
        else:
            if self._sync_exc is not None:
                raise self._sync_exc
            result = self.sync_payload
        self.last_sync = 1.0
        # Real AuthManager.sync() returns the RAW bw sync payload (via
        # run_with_recovery); the count extractor runs over that shape.
        return result

    @property
    def last_sync_result(self):
        # Real AuthManager exposes a bounded int/None here; the stub returns
        # the raw sync payload so BOTH extractor paths stay under test.
        return self.sync_payload


class SpyCli(BwCli):
    """BwCli whose run() NEVER spawns: scripted payloads + full call log.

    Records every run() invocation (args + env) so tests can assert the
    exact subprocess plan the defense would have executed — including the
    sync VERB (full ``--force`` vs incremental) and the BW_SESSION header
    contents.
    """

    def __init__(self, list_payloads, sync_exc=None, owner=None,
                 sync_result=None, status_payload=None):
        # Intentionally skip BwCli.__init__: no binary, no version probe.
        self.bw_path = "/nonexistent/bw"
        self.appdata_dir = "/nonexistent/appdata"
        self.timeout = 30
        self.list_payloads = list(list_payloads)
        self.sync_exc = sync_exc
        # Scripted bw-sync payload; None -> [] like the real "no changes"
        # JSON answer. Tests pass a non-list (e.g. a bare string) to pin
        # the item-count-omitted logging path.
        self.sync_result = [] if sync_result is None else sync_result
        # v0.7.6 (Phase 1): scripted `bw status` payload for the third
        # suspect condition's verify_session() probe. The default models
        # the production invalidation scenario: the key under test NO
        # LONGER authenticates (bw exits non-zero with a locked-status
        # payload). Pass a dict ({"status": "unlocked", ...}) to script
        # a still-valid key.
        self.status_payload = ({"status": "locked"}
                               if status_payload is None else status_payload)
        self.calls: list[tuple[list, dict]] = []
        if owner is not None:
            owner.cli = self  # let the stub record its verb at this layer

    def _ensure_version_checked(self):
        pass

    def run(self, args, *, env=None, raw=False, timeout=None,
            _retry_count=0, retryable=True):
        # NOTE: BwCli.run()'s real body routes through _ensure_session_env
        # (the v0.7.2 pre-flight lock check), which lazy-unlocks via the
        # registered manager BEFORE spawning. The defense is tested at the
        # SUBPROCESS-PLAN level here: args + caller-supplied env only.
        args = list(args)
        self.calls.append((args, dict(env or {})))
        if args[:2] == ["list", "items"]:
            if self.list_payloads:
                return self.list_payloads.pop(0)
            return []
        if args[:1] == ["status"]:
            if isinstance(self.status_payload, Exception):
                raise self.status_payload
            return self.status_payload
        return []

    def sync(self, session_key, force=False, full=None):
        """Record the VERB decision without spawning.

        Mirrors BwCli.sync()'s v0.7.4 arg construction exactly (full ->
        ``bw sync --force``; incremental -> plain ``bw sync``; the no-op
        ``--last`` verb is gone), so tests can assert the real subprocess
        plan even when the defense delegates the sync to an AuthManager
        stub whose own sync() never reaches this layer.
        """
        if full is None:
            full = force
        args = ["sync", "--force"] if full else ["sync"]
        self.calls.append((args, {"BW_SESSION": session_key}))
        if self.sync_exc is not None:
            raise self.sync_exc
        return self.sync_result

    def synced_args(self):
        return [c[0] for c in self.calls if c[0][:1] == ["sync"]]

    def list_args(self):
        return [c[0] for c in self.calls if c[0][:2] == ["list", "items"]]

    def status_calls(self):
        """Every (args, env) pair of recorded ``bw status`` invocations."""
        return [(c[0], c[1]) for c in self.calls if c[0][:1] == ["status"]]


def _messages(caplog):
    return [r.getMessage() for r in caplog.records]


@pytest.fixture(autouse=True)
def _clear_registry():
    yield
    register_auth_manager(None)


# ---------------------------------------------------------------------------
# Scenario 1: empty read + last_sync == 0.0 -> forced full sync + retry
# ---------------------------------------------------------------------------

class TestSecondSuspectConditionFires:

    def test_forced_full_sync_and_retry_with_warning(self, caplog):
        # UNLOCKED session with a valid key + last_sync == 0.0 -> the Phase 3
        # SECOND suspect condition (session_key=None would take the v0.7.2
        # non-UNLOCKED reconcile leg instead).
        auth = StubAuth(session_key=SESSION_KEY, last_sync=0.0)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], [dict(ITEM_A)]], owner=auth)
        auth.cli = cli

        with caplog.at_level("INFO"):
            items = cli.list_items(SESSION_KEY)

        assert items == [ITEM_A], "retry result must be returned"
        # WARNING on suspicion (intentional per spec — operators must see it)
        warns = [m for m in _messages(caplog)
                 if "Empty read detected with unpopulated cache" in m]
        assert len(warns) == 1 and warns[0].endswith("(last_sync=0.0)")
        assert any(r.levelname == "WARNING" for r in caplog.records
                   if "Empty read detected" in r.getMessage())
        # INFO on trigger and outcome
        msgs = _messages(caplog)
        assert any("Triggering forced full sync (prior sync never completed)"
                   in m for m in msgs)
        assert any("Forced full sync completed" in m for m in msgs)
        assert any("Read retry after forced sync returned 1 items" in m
                   for m in msgs)
        # exactly ONE sync + TWO list calls (original + single retry)
        assert len(cli.synced_args()) == 1
        assert len(cli.list_args()) == 2

    def test_forced_sync_uses_full_verb_never_last(self, caplog):
        """CHANGE 2 (v0.7.4): the forced sync MUST be `bw sync --force`."""
        auth = StubAuth(session_key=SESSION_KEY, last_sync=0.0)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], [dict(ITEM_A)]], owner=auth)
        auth.cli = cli

        with caplog.at_level("INFO"):
            cli.list_items(SESSION_KEY)

        sync_call = cli.synced_args()[0]
        assert sync_call == ["sync", "--force"], \
            "full sync must use --force; --last never synced at all"
        assert "--last" not in sync_call

    def test_routed_through_auth_manager_sync_force_true(self, caplog):
        """The defense delegates to AuthManager.sync(force=True), which after
        Phase 1 owns the verb selection (full while _last_sync == 0.0)."""
        auth = StubAuth(session_key=SESSION_KEY, last_sync=0.0)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], [dict(ITEM_A)]], owner=auth)
        auth.cli = cli

        with caplog.at_level("INFO"):
            cli.list_items(SESSION_KEY)

        assert auth.sync_calls == [True], "must force=True (skip freshness gate)"

    def test_item_count_included_when_available(self, caplog):
        # sync_result models the bw sync PAYLOAD: a list of items (the
        # count extractor mirrors AuthManager._parse_sync_item_count and
        # only accepts list / {"data": [...]} shapes).
        auth = StubAuth(session_key=SESSION_KEY, last_sync=0.0,
                        sync_result=[dict(ITEM_A), dict(ITEM_B)])
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], [dict(ITEM_A), dict(ITEM_B)]], owner=auth)
        auth.cli = cli

        with caplog.at_level("INFO"):
            items = cli.list_items(SESSION_KEY)

        assert len(items) == 2
        assert any("Forced full sync completed (2 items)" in m
                   for m in _messages(caplog))

    def test_item_count_omitted_when_unparseable(self, caplog):
        # NOTE: no sync_result — with an owner-wired cli, StubAuth.sync()
        # delegates to SpyCli.sync(), which returns the unparseable string
        # payload (a plain list of items would parse as a count).
        auth = StubAuth(session_key=SESSION_KEY, last_sync=0.0)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], []], sync_result="No sync needed",
                     owner=auth)
        auth.cli = cli

        with caplog.at_level("INFO"):
            cli.list_items(SESSION_KEY)

        msgs = _messages(caplog)
        assert any(m.startswith("Forced full sync completed") and
                   "items" not in m for m in msgs)


# ---------------------------------------------------------------------------
# Scenario 2: empty read + last_sync > 0.0 -> genuinely empty, NO subprocess
# ---------------------------------------------------------------------------

class TestNoFalsePositives:

    def test_populated_cache_accepts_empty_without_sync(self, caplog):
        auth = StubAuth(session_key=None, last_sync=1234.5)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[]], owner=auth)
        auth.cli = cli

        with caplog.at_level("INFO"):
            items = cli.list_items(SESSION_KEY)

        assert items == []
        assert cli.synced_args() == [], "defense must NOT fire when populated"
        assert len(cli.list_args()) == 1, "no retry read"
        assert _messages(caplog) == [], "healthy path stays silent"

    def test_scenario_6_nonempty_read_with_zero_last_sync_no_sync(self, caplog):
        """Non-empty read + last_sync==0.0 -> nothing suspect, no subprocess."""
        auth = StubAuth(session_key=SESSION_KEY, last_sync=0.0)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[dict(ITEM_A), dict(ITEM_B)]], owner=auth)
        auth.cli = cli

        with caplog.at_level("INFO"):
            items = cli.list_items(SESSION_KEY)

        assert len(items) == 2
        assert cli.synced_args() == []
        assert len(cli.list_args()) == 1
        assert _messages(caplog) == []

    def test_duck_typed_manager_without_last_sync_skips_defense(self, caplog):
        """Managers lacking the last_sync attribute degrade silently (the
        defense must not crash or spawn on unknown shapes)."""
        class LegacyStub:
            def get_session_key(self):
                return SESSION_KEY

        register_auth_manager(LegacyStub())
        cli = SpyCli(list_payloads=[[]])

        with caplog.at_level("INFO"):
            items = cli.list_items(SESSION_KEY)

        assert items == []
        assert cli.synced_args() == []
        assert _messages(caplog) == []

    def test_no_manager_registered_returns_empty_quietly(self, caplog):
        cli = SpyCli(list_payloads=[[]])
        assert get_auth_manager() is None

        with caplog.at_level("INFO"):
            items = cli.list_items(SESSION_KEY)

        assert items == []
        assert cli.synced_args() == []
        assert _messages(caplog) == []


# ---------------------------------------------------------------------------
# Scenarios 4 & 5: graceful degradation
# ---------------------------------------------------------------------------

class TestGracefulDegradation:

    def test_forced_sync_failure_returns_empty_with_warning(self, caplog):
        exc = errors.NetworkError("connection refused")
        auth = StubAuth(session_key=SESSION_KEY, last_sync=0.0)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[]], sync_exc=exc, owner=auth)
        auth.cli = cli

        with caplog.at_level("INFO"):
            items = cli.list_items(SESSION_KEY)

        assert items == [], "sync failure degrades to the original empty read"
        assert len(cli.list_args()) == 1, "no retry read after failed sync"
        msgs = _messages(caplog)
        fail = [m for m in msgs if "Forced full sync failed" in m]
        assert len(fail) == 1
        assert "NETWORK_ERROR" in fail[0], "sanitized code required"
        assert "returning empty list" in fail[0]
        assert all(r.levelname == "WARNING" for r in caplog.records
                   if "Forced full sync failed" in r.getMessage())

    def test_generic_exception_logs_code_not_raw_text(self, caplog):
        """No raw exception text — only the sanitized code from errors.py."""
        auth = StubAuth(session_key=SESSION_KEY, last_sync=0.0)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[]],
                    sync_exc=ValueError("secret-ish raw text"), owner=auth)
        auth.cli = cli

        with caplog.at_level("INFO"):
            items = cli.list_items(SESSION_KEY)

        assert items == []
        joined = " | ".join(_messages(caplog))
        assert "ValueError" in joined  # class-name fallback IS the sanitized code
        assert "secret-ish raw text" not in joined

    def test_retry_still_empty_accepted_no_loop(self, caplog):
        """Retry also empty -> accept as genuinely empty; EXACTLY one retry."""
        auth = StubAuth(session_key=SESSION_KEY, last_sync=0.0,
                        sync_result=[])
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], []], owner=auth)
        auth.cli = cli

        with caplog.at_level("INFO"):
            items = cli.list_items(SESSION_KEY)

        assert items == []
        assert len(cli.list_args()) == 2, "one original + one retry, no more"
        assert len(cli.synced_args()) == 1, "one forced sync only"
        assert any("Read retry after forced sync returned 0 items" in m
                   for m in _messages(caplog))


# ---------------------------------------------------------------------------
# Scenario 7: write operations are NOT reconciled
# ---------------------------------------------------------------------------

class TestWritesUnaffected:

    def test_delete_recovery_uses_full_sync_not_the_read_defense(self):
        """Permanent-delete not_found recovery (v0.4.8) keeps its own FULL
        `bw sync` path; the empty-read defense is read-only."""

        class WriteCli(SpyCli):
            # delete_item() calls run(..., raw=True, retryable=False); the
            # v0.4.8 not_found recovery calls self.sync(session_key). Record
            # EVERY plan in self.calls (SpyCli.sync override + SpyCli.run)
            # plus a local delete log; assert on both views.
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.delete_log: list[list] = []

            def run(self, args, *, env=None, raw=False, timeout=None,
                    _retry_count=0, retryable=True):
                args = list(args)
                if args[:1] == ["delete"]:
                    self.delete_log.append(args)
                    if not any(c[0][:1] == ["sync"] for c in self.calls):
                        # First attempt fails against the stale cache; the
                        # v0.4.8 not_found recovery syncs and retries once.
                        raise errors.NotFoundError("not in stale cache")
                    return "deleted"
                return super().run(args, env=env, raw=raw, timeout=timeout,
                                   _retry_count=_retry_count,
                                   retryable=retryable)

        auth = StubAuth(session_key=None, last_sync=0.0)
        register_auth_manager(auth)
        # owner NOT wired: write-recovery sync must hit this cli's run()/
        # sync() directly (StubAuth.sync delegating to a cli would consult
        # the read-defense layer instead of the delete path under test).
        cli = WriteCli(list_payloads=[])

        out = cli.delete_item(SESSION_KEY, "item-1", permanent=True)

        assert "deleted" in out
        syncs = [c[0] for c in cli.calls if c[0][:1] == ["sync"]]
        assert syncs == [["sync", "--force"]], \
            "write recovery: full sync via --force, never the no-op --last"
        lists = cli.list_args()
        assert lists == [], "write path must never hit the read defense"

    def test_reconcile_hook_is_only_wired_into_list_items(self):
        """Structural pin: create/edit/delete/get_password bodies contain no
        _reconcile_empty_read call — the defense cannot fire for writes."""
        import inspect

        for name in ("create_item", "edit_item", "delete_item",
                     "get_password", "item_get"):
            src = inspect.getsource(getattr(BwCli, name))
            assert "_reconcile_empty_read" not in src, name
        assert "_reconcile_empty_read" in inspect.getsource(BwCli.list_items)


# ---------------------------------------------------------------------------
# Scenario 8: no secret values in any log
# ---------------------------------------------------------------------------

class TestNoSecretsInLogs:

    def test_all_defense_paths_log_no_secrets(self, caplog):
        secrets = (SESSION_KEY, CS_SECRET, MP_SECRET, "sup3r-s3cret-pg!")

        # Path A: success + retry with items
        auth_ok = StubAuth(session_key=SESSION_KEY, last_sync=0.0,
                           sync_result=[dict(ITEM_A), dict(ITEM_B)])
        register_auth_manager(auth_ok)
        cli_ok = SpyCli(list_payloads=[[], [dict(ITEM_A)]], owner=auth_ok)
        auth_ok.cli = cli_ok
        with caplog.at_level("INFO"):
            cli_ok.list_items(SESSION_KEY)

        # Path B: forced sync failure
        auth_bad = StubAuth(session_key=SESSION_KEY, last_sync=0.0)
        register_auth_manager(auth_bad)
        cli_bad = SpyCli(list_payloads=[[]],
                         sync_exc=errors.NetworkError("dns warm-up failed"), owner=auth_bad)
        auth_bad.cli = cli_bad
        with caplog.at_level("INFO"):
            cli_bad.list_items(SESSION_KEY)

        joined = "\n".join(_messages(caplog))
        for s in secrets:
            assert s not in joined
        # positive control: the defense actually logged
        assert "Empty read detected" in joined
        assert "NETWORK_ERROR" in joined

    def test_subprocess_env_carries_session_but_logs_do_not(self, caplog):
        auth = StubAuth(session_key=SESSION_KEY, last_sync=0.0)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], [dict(ITEM_A)]], owner=auth)
        auth.cli = cli

        with caplog.at_level("INFO"):
            cli.list_items(SESSION_KEY)

        # The retry read DOES receive BW_SESSION at the subprocess boundary...
        retry_env = cli.calls[-1][1]
        assert retry_env.get("BW_SESSION") == SESSION_KEY
        # ...but no log line may echo it.
        joined = "\n".join(_messages(caplog))
        assert SESSION_KEY not in joined


# ===========================================================================
# v0.7.6 (Phase 1, session invalidation defense) — CHANGE 1: verify_session()
# ===========================================================================

FRESH_KEY = "ffffffff99998888-externally-invalidated-FRESHKEY"


class TestVerifySessionUnit:
    """BwCli.verify_session(): one `bw status` call carrying BW_SESSION."""

    def test_unlocked_payload_returns_unlocked(self):
        cli = SpyCli(list_payloads=[],
                     status_payload={"status": "unlocked", "hasMasterPassword": True})
        assert cli.verify_session(SESSION_KEY) == "unlocked"
        # exactly ONE subprocess plan, with the key under test in env
        assert cli.calls == [(["status"], {"BW_SESSION": SESSION_KEY})]

    def test_locked_payload_returns_locked(self):
        cli = SpyCli(list_payloads=[], status_payload={"status": "locked"})
        assert cli.verify_session(SESSION_KEY) == "locked"

    def test_state_key_fallback_supported(self):
        # defensive shape: some payloads report the state under "state"
        cli = SpyCli(list_payloads=[], status_payload={"state": "unlocked"})
        assert cli.verify_session(SESSION_KEY) == "unlocked"

    def test_non_dict_payload_returns_unknown(self):
        cli = SpyCli(list_payloads=[], status_payload="not-a-dict")
        assert cli.verify_session(SESSION_KEY) == "unknown"

    def test_session_error_maps_to_locked(self):
        # bw exits non-zero on an invalid key -> SessionError -> "locked"
        # (conservative: triggers the re-unlock path).
        cli = SpyCli(list_payloads=[],
                     status_payload=errors.SessionError("vault is locked"))
        assert cli.verify_session(SESSION_KEY) == "locked"

    def test_network_error_maps_to_unknown(self):
        # transport-level failure must NOT be misread as invalidation;
        # "unknown" keeps the caller's conservative branch honest.
        cli = SpyCli(list_payloads=[],
                     status_payload=errors.NetworkError("connection refused"))
        assert cli.verify_session(SESSION_KEY) == "unknown"

    def test_verify_session_never_logs_the_key(self, caplog):
        cli = SpyCli(list_payloads=[], status_payload={"status": "locked"})
        with caplog.at_level("DEBUG"):
            cli.verify_session(SESSION_KEY)
        assert SESSION_KEY not in "\n".join(_messages(caplog))


# ===========================================================================
# v0.7.6 Phase 1 — CHANGE 2/3: third suspect condition in the read defense
# ===========================================================================

class TestThirdSuspectConditionFires:
    """items == [] AND key_valid AND last_sync > 0.0 -> verify the key.

    Production scenario (2026-11-03 17:41): two AuthManagers load the plugin
    twice; the second unlock invalidates the first manager's BW_SESSION
    EXTERNALLY while its local state still reports UNLOCKED with a populated
    cache. Neither condition 1 nor 2 can see it — only `bw status` can.
    """

    def test_invalidated_key_reunlocks_and_retries_once(self, caplog):
        auth = StubAuth(session_key=SESSION_KEY, last_sync=1234.5,
                        fresh_key=FRESH_KEY)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], [dict(ITEM_A), dict(ITEM_B)]],
                     status_payload={"status": "locked"}, owner=auth)
        auth.cli = cli

        with caplog.at_level("INFO"):
            items = cli.list_items(SESSION_KEY)

        assert items == [ITEM_A, ITEM_B], "retry result must be returned"
        # exactly ONE verification + ONE retry, NO sync (cache was populated)
        assert len(cli.status_calls()) == 1
        assert len(cli.list_args()) == 2
        assert cli.synced_args() == [], "condition 3 never forces a sync"
        # re-unlock went through the manager exactly once
        assert auth.get_session_calls == 1
        # CHANGE 3 logging spec: WARNING detection + INFO recovery
        msgs = _messages(caplog)
        warn = [m for m in msgs
                if "Empty read with externally invalidated session key" in m]
        assert len(warn) == 1
        assert warn[0].endswith("(bw status=locked); forcing re-unlock")
        assert any(r.levelname == "WARNING" for r in caplog.records
                   if "externally invalidated" in r.getMessage())
        assert any("Session re-established after external invalidation; "
                   "retrying read once" in m for m in msgs)
        assert any(r.levelname == "INFO" for r in caplog.records
                   if "Session re-established" in r.getMessage())

    def test_verification_carries_bw_session_env(self):
        auth = StubAuth(session_key=SESSION_KEY, last_sync=1234.5,
                        fresh_key=FRESH_KEY)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], [dict(ITEM_A)]],
                    status_payload={"status": "locked"}, owner=auth)
        auth.cli = cli

        cli.list_items(SESSION_KEY)

        # the probe MUST use BW_SESSION (the persistent profile always
        # reports "locked" by design and could never detect this)
        status_args, status_env = cli.status_calls()[0]
        assert status_args == ["status"]
        assert status_env.get("BW_SESSION") == SESSION_KEY
        # the retry read runs with the FRESH key, not the dead one
        retry_env = cli.calls[-1][1]
        assert retry_env.get("BW_SESSION") == FRESH_KEY

    def test_unauthenticated_status_also_triggers_reunlock(self, caplog):
        auth = StubAuth(session_key=SESSION_KEY, last_sync=1234.5,
                        fresh_key=FRESH_KEY)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], [dict(ITEM_A)]],
                    status_payload={"status": "unauthenticated"}, owner=auth)
        auth.cli = cli

        with caplog.at_level("INFO"):
            items = cli.list_items(SESSION_KEY)

        assert items == [ITEM_A]
        assert any("(bw status=unauthenticated)" in m for m in _messages(caplog))

    def test_local_state_demoted_before_reunlock(self):
        # get_session()'s UNLOCKED fast path would hand back the SAME dead
        # key unless the defense demotes local state first — pin the order.
        auth = StubAuth(session_key=SESSION_KEY, last_sync=1234.5,
                        fresh_key=FRESH_KEY)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], [dict(ITEM_A)]],
                    status_payload={"status": "locked"}, owner=auth)
        auth.cli = cli

        cli.list_items(SESSION_KEY)

        assert auth.invalidate_calls == 1
        assert auth.get_session_calls == 1

    def test_retry_still_empty_accepted_no_loop(self, caplog):
        """Retry also empty -> accept; EXACTLY one verification + one retry."""
        auth = StubAuth(session_key=SESSION_KEY, last_sync=1234.5,
                        fresh_key=FRESH_KEY)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], []],
                    status_payload={"status": "locked"}, owner=auth)
        auth.cli = cli

        with caplog.at_level("INFO"):
            items = cli.list_items(SESSION_KEY)

        assert items == []
        assert len(cli.list_args()) == 2, "one original + one retry, no more"
        assert len(cli.status_calls()) == 1, "no second verification"
        assert auth.get_session_calls == 1, "no second re-unlock"


class TestThirdConditionAcceptanceAndDegradation:

    def test_valid_key_empty_vault_accepted_quietly(self, caplog):
        """status == "unlocked" -> genuinely empty vault: accept, no re-unlock."""
        auth = StubAuth(session_key=SESSION_KEY, last_sync=1234.5)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[]],
                    status_payload={"status": "unlocked"}, owner=auth)
        auth.cli = cli

        with caplog.at_level("INFO"):
            items = cli.list_items(SESSION_KEY)

        assert items == []
        assert len(cli.status_calls()) == 1, "verification DID run"
        assert len(cli.list_args()) == 1, "no retry read"
        assert auth.get_session_calls == 0, "no re-unlock"
        assert _messages(caplog) == [], "healthy empty vault stays silent"

    def test_reunlock_failure_degrades_to_empty_with_warning(self, caplog):
        exc = errors.AuthError("master password unavailable")
        auth = StubAuth(session_key=SESSION_KEY, last_sync=1234.5,
                        get_session_exc=exc)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[]],
                    status_payload={"status": "locked"}, owner=auth)
        auth.cli = cli

        with caplog.at_level("INFO"):
            items = cli.list_items(SESSION_KEY)

        assert items == [], "re-unlock failure degrades to the empty read"
        assert len(cli.list_args()) == 1, "no retry without a fresh key"
        msgs = _messages(caplog)
        fail = [m for m in msgs
                if "Re-unlock after external invalidation failed" in m]
        assert len(fail) == 1
        assert "AUTH_ERROR" in fail[0], "sanitized code required"
        assert "returning empty list" in fail[0]
        assert all(r.levelname == "WARNING" for r in caplog.records
                   if "Re-unlock after external invalidation failed"
                   in r.getMessage())

    def test_same_key_after_reunlock_gives_up_without_retry(self):
        """Re-unlock handing back the SAME key -> nothing left to retry."""
        auth = StubAuth(session_key=SESSION_KEY, last_sync=1234.5)  # no fresh_key
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[]],
                    status_payload={"status": "locked"}, owner=auth)
        auth.cli = cli

        items = cli.list_items(SESSION_KEY)

        assert items == []
        assert auth.get_session_calls == 1
        assert len(cli.list_args()) == 1, "no retry with the dead key"

    def test_unknown_status_still_forces_reunlock_conservatively(self, caplog):
        """Non-"unlocked" statuses (incl. "unknown") take the recovery leg."""
        auth = StubAuth(session_key=SESSION_KEY, last_sync=1234.5,
                        fresh_key=FRESH_KEY)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], [dict(ITEM_A)]],
                    status_payload="garbage-not-json", owner=auth)
        auth.cli = cli

        with caplog.at_level("INFO"):
            items = cli.list_items(SESSION_KEY)

        assert items == [ITEM_A]
        assert any("(bw status=unknown)" in m for m in _messages(caplog))

    def test_verify_session_crash_degrades_silently(self, caplog):
        """A broken verify_session never crashes the read path."""
        auth = StubAuth(session_key=SESSION_KEY, last_sync=1234.5)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[]], owner=auth)
        auth.cli = cli

        def boom(_key):
            raise RuntimeError("unexpected internal fault")

        cli.verify_session = boom
        with caplog.at_level("INFO"):
            items = cli.list_items(SESSION_KEY)

        assert items == []
        assert len(cli.list_args()) == 1
        assert _messages(caplog) == [], "silent degrade — no noisy false alarm"


class TestThirdConditionPrecedenceAndBoundaries:

    def test_condition_2_preempts_condition_3_no_status_probe(self, caplog):
        """last_sync == 0.0 (condition 2) is cheaper/more specific: the
        `bw status` probe must NOT run when the forced-sync leg fires."""
        auth = StubAuth(session_key=SESSION_KEY, last_sync=0.0)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], [dict(ITEM_A)]], owner=auth)
        auth.cli = cli

        with caplog.at_level("INFO"):
            items = cli.list_items(SESSION_KEY)

        assert items == [ITEM_A]
        assert len(cli.synced_args()) == 1, "condition 2 fired"
        assert cli.status_calls() == [], "condition 3 must not also fire"

    def test_condition_1_preemption_nonunlocked_skips_probe(self):
        """session_key=None (condition 1) routes to the FSM reconcile leg;
        the third-condition probe never runs."""
        auth = StubAuth(session_key=None, last_sync=1234.5)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[]], owner=auth)
        auth.cli = cli

        items = cli.list_items(SESSION_KEY)

        assert items == []
        assert cli.status_calls() == []
        assert auth.get_session_calls == 0

    def test_nonempty_reads_pay_zero_overhead(self, caplog):
        """The check MUST NOT run on non-empty reads (happy path)."""
        auth = StubAuth(session_key=SESSION_KEY, last_sync=1234.5)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[dict(ITEM_A), dict(ITEM_B)]], owner=auth)
        auth.cli = cli

        with caplog.at_level("INFO"):
            items = cli.list_items(SESSION_KEY)

        assert len(items) == 2
        assert cli.status_calls() == [], "zero extra subprocesses"
        assert len(cli.list_args()) == 1
        assert _messages(caplog) == []

    def test_duck_typed_manager_without_last_sync_skips_probe(self):
        """Managers lacking last_sync stay outside BOTH legs (unchanged)."""
        class LegacyStub:
            def get_session_key(self):
                return SESSION_KEY

        register_auth_manager(LegacyStub())
        cli = SpyCli(list_payloads=[[]])

        items = cli.list_items(SESSION_KEY)

        assert items == []
        assert cli.status_calls() == []

    def test_third_condition_logs_no_secrets(self, caplog):
        secrets = (SESSION_KEY, FRESH_KEY, CS_SECRET, MP_SECRET)

        # Path A: successful recovery
        auth_ok = StubAuth(session_key=SESSION_KEY, last_sync=1234.5,
                           fresh_key=FRESH_KEY)
        register_auth_manager(auth_ok)
        cli_ok = SpyCli(list_payloads=[[], [dict(ITEM_A)]],
                       status_payload={"status": "locked"}, owner=auth_ok)
        auth_ok.cli = cli_ok
        with caplog.at_level("INFO"):
            cli_ok.list_items(SESSION_KEY)

        # Path B: failed re-unlock
        auth_bad = StubAuth(session_key=SESSION_KEY, last_sync=1234.5,
                            get_session_exc=errors.SessionError(
                                "raw text with mp-secret-value-ABC inside"))
        register_auth_manager(auth_bad)
        cli_bad = SpyCli(list_payloads=[[]],
                        status_payload={"status": "locked"}, owner=auth_bad)
        auth_bad.cli = cli_bad
        with caplog.at_level("INFO"):
            cli_bad.list_items(SESSION_KEY)

        joined = "\n".join(_messages(caplog))
        for s in secrets:
            assert s not in joined
        # positive control: both defense legs actually logged
        assert "externally invalidated session key" in joined
        assert "Re-unlock after external invalidation failed" in joined
        assert "SESSION_ERROR" in joined, "sanitized code, never raw text"

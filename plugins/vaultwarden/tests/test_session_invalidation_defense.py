"""v0.7.6 Phase 2 regression suite: SESSION INVALIDATION DEFENSE.

Production root cause (2026-11-03 17:41, v0.7.5): the Hermes Agent loads
the vaultwarden plugin TWICE into two separate AuthManager instances
(dashboard process + gateway process sharing one bw profile). bw supports
exactly ONE session key per profile, so the second ``bw unlock`` silently
INVALIDATES the first manager's BW_SESSION while its local state still
reports UNLOCKED with a populated cache:

    17:41:06 AuthManager #1: bw unlock -> session_key_1
    17:41:25 AuthManager #2: bw unlock -> session_key_2   (kills key_1)
    17:43:47 tool call via #1: bw list items -> locked vault -> [] exit 0

Neither existing suspect condition sees it: condition 1 needs an invalid
key (key_valid == True here) and condition 2 needs last_sync == 0.0 (the
cache WAS populated at 17:41:11). The empty payload was accepted as a
"genuinely empty vault".

Phase 1 fix pinned by this file:
  CHANGE 1  BwCli.verify_session(): asks ``bw status`` WITH BW_SESSION
            whether a key still authenticates (the persistent profile
            always reports "locked" by design — only the key answers
            honestly); SessionError -> "locked", any other
            VaultwardenError -> "unknown", non-dict -> "unknown".
  CHANGE 2  THIRD suspect condition in _reconcile_empty_read():
            items == [] AND key_valid AND last_sync > 0.0 -> verify the
            key; on "locked"/"unauthenticated"/anything non-"unlocked"
            force ONE re-unlock through the FSM + ONE retry read with the
            fresh key. "unlocked" -> genuinely empty vault, accepted.
  CHANGE 3  logging spec: WARNING on invalidation detection and on failed
            recovery (sanitized error codes only), INFO on successful
            recovery. No secret value ever appears in any log line.

Mandated scenarios 1-10 (one test class each is not required; grouped by
leg below, scenario numbers pinned in docstrings):
  1  condition 1: non-UNLOCKED empty read -> FSM reconcile + retry
  2  condition 2: UNLOCKED, never synced -> forced full sync + retry
  3  condition 3: externally invalidated key -> WARNING + re-unlock + retry
  4  condition 3: key valid ("unlocked") -> accept [] (genuinely empty)
  5  condition 3: re-unlock raises -> WARNING + []
  6  condition 3: re-unlock returns the SAME key -> [] (no retry possible)
  7  non-empty read -> zero defense overhead (no probe at all)
  8  condition 3: verification raises NetworkError -> degrade to []
  9  condition 3: "unauthenticated" -> treated as invalid, re-unlock + retry
  10 condition 3: the retry ALSO comes back empty -> accepted, no loop

Hard boundaries honored by every test:
  * mocks only — NO real bw binary, NO network, NO timing assumptions;
  * fake session keys are clearly-fake literals (FAKE_SESSION_KEY_*);
  * every recovery leg is bounded to ONE verification + ONE re-unlock +
    ONE retry per original read (re-entrancy guard consumed exactly once);
  * conditions 1/2 preempt condition 3 (cheaper, more specific legs);
  * no secret values in any log output (asserted per-path and globally).

Test doubles are self-contained (unittest.mock + duck-typed stubs only).
Managers register via ``register_auth_manager()``; the autouse fixture
clears the registry after every test.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from vaultwarden import errors
from vaultwarden.bw_cli import BwCli, register_auth_manager

# Clearly-fake mock credentials (hard constraint: never real-looking).
FAKE_SESSION_KEY_1 = "FAKE_SESSION_KEY_1"          # manager #1's live key
FAKE_SESSION_KEY_2 = "FAKE_SESSION_KEY_2"          # the OTHER process's key
FAKE_MASTER_PASSWORD = "FAKE_MASTER_PASSWORD"      # never used, leak-checked

ITEM_A = {"id": "aaaa1111-0000-0000-0000-000000000001", "name": "Postgres prod"}
ITEM_B = {"id": "aaaa1111-0000-0000-0000-000000000002", "name": "Grafana"}


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class StubAuth:
    """Duck-typed AuthManager stand-in for the bw_cli-side defense.

    Models the three observable facets the defense reads:
      * ``get_session_key()`` — None means NON-UNLOCKED (condition 1 leg);
        a value means the manager BELIEVES it holds a valid key;
      * ``last_sync`` — 0.0 means "never completed a sync" (condition 2
        leg); > 0.0 means the local cache was populated (condition 3 leg);
      * ``get_session()`` — the re-unlock entry point condition 3 uses.
        By default it hands back the CURRENT key (the real UNLOCKED fast
        path), which the defense treats as "nothing new to retry with".
        ``fresh_key`` scripts a successful re-unlock (e.g. the external
        invalidation cleared the fast path after invalidate_session());
        ``get_session_exc`` scripts a failed one.
    """

    def __init__(self, *, session_key=None, last_sync=0.0, fresh_key=None,
                 get_session_exc=None, fsm_key=None, cli=None):
        self._session_key = session_key
        self.last_sync = last_sync
        self._fresh_key = fresh_key
        self._get_session_exc = get_session_exc
        self._fsm_key = fsm_key  # key surfaced AFTER ensure_authenticated()
        self.cli = cli  # SpyCli wiring so sync() records the REAL verb plan
        self.get_session_calls = 0
        self.invalidate_calls = 0
        self.ensure_authenticated_calls = 0

    def get_session_key(self):
        return self._session_key

    def ensure_authenticated(self):
        # Condition 1 leg: run the full FSM; afterwards the confirmed key
        # becomes visible (models login/unlock completing inside the FSM).
        self.ensure_authenticated_calls += 1
        if self._fsm_key is not None:
            self._session_key = self._fsm_key

    def invalidate_session(self):
        # Models the local-state demotion the defense performs BEFORE
        # re-unlocking (a real AuthManager clears its stale key so the
        # UNLOCKED fast path cannot hand the dead key back).
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
        # Mirror the real AuthManager.sync(): delegate to the wired SpyCli
        # so the actual SUBPROCESS PLAN (full ``--force`` vs incremental
        # verb) is recorded at the CLI layer, then advance last_sync — a
        # successful sync always moves it > 0.0.
        if self.cli is not None:
            result = self.cli.sync(self._session_key or "",
                                   full=self.last_sync == 0.0)
        else:
            result = []
        self.last_sync = 1.0
        return result


class SpyCli(BwCli):
    """BwCli whose run() NEVER spawns: scripted payloads + full call log.

    Records every run() invocation (args + env) so tests can assert the
    exact subprocess plan the defense would have executed — including
    which BW_SESSION key each command carried. ``status_payload`` scripts
    the ``bw status`` verification probe: a dict is returned as-is, an
    Exception instance is raised (models run()'s error classification),
    anything else is returned verbatim (models a non-dict payload).
    ``sync_result`` models the sync answer for the condition-2 leg.
    """

    def __init__(self, list_payloads, status_payload=None, sync_result=None):
        # Intentionally skip BwCli.__init__: no binary, no version probe.
        self.bw_path = "/nonexistent/bw"
        self.appdata_dir = "/nonexistent/appdata"
        self.timeout = 30
        self.list_payloads = list(list_payloads)
        # Default models the production invalidation scenario: the key
        # under test NO LONGER authenticates (locked-status payload).
        self.status_payload = ({"status": "locked"}
                               if status_payload is None else status_payload)
        self.sync_result = [] if sync_result is None else sync_result
        self.calls: list[tuple[list, dict]] = []

    def _ensure_version_checked(self):
        pass

    def run(self, args, *, env=None, raw=False, timeout=None,
            _retry_count=0, retryable=True):
        # NOTE: the real run() routes through _ensure_session_env (the
        # v0.7.2 pre-flight lock check). The defense is tested at the
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
        if args[:1] == ["sync"]:
            return self.sync_result
        return []

    def status_calls(self):
        """Every (args, env) pair of recorded ``bw status`` invocations."""
        return [(c[0], c[1]) for c in self.calls if c[0][:1] == ["status"]]

    def list_args(self):
        return [c[0] for c in self.calls if c[0][:2] == ["list", "items"]]

    def list_envs(self):
        return [c[1] for c in self.calls if c[0][:2] == ["list", "items"]]

    def synced_args(self):
        return [c[0] for c in self.calls if c[0][:1] == ["sync"]]


def _messages(caplog):
    return [r.getMessage() for r in caplog.records]


@pytest.fixture(autouse=True)
def _clear_registry():
    yield
    register_auth_manager(None)


# ---------------------------------------------------------------------------
# Scenario 1: condition 1 — non-UNLOCKED state, empty read
# ---------------------------------------------------------------------------

class TestConditionOneNonUnlocked:

    def test_fsm_reconcile_then_retry_with_fresh_key(self, caplog):
        """Key invalid -> full FSM reconciliation + ONE retry (v0.7.2 leg)."""
        auth = StubAuth(session_key=None, last_sync=1234.5,
                        fsm_key=FAKE_SESSION_KEY_2)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], [dict(ITEM_A)]])

        with caplog.at_level("INFO"):
            items = cli.list_items(FAKE_SESSION_KEY_1)

        assert items == [ITEM_A], "retry result must be returned"
        assert auth.ensure_authenticated_calls == 1, "FSM ran exactly once"
        assert len(cli.list_args()) == 2, "original read + exactly one retry"
        assert cli.status_calls() == [], \
            "condition 1 preempts condition 3 — no verification probe"
        # the retry runs with the CONFIRMED fresh key, not the caller's stale one
        assert cli.list_envs()[1].get("BW_SESSION") == FAKE_SESSION_KEY_2
        assert any("Suspect empty read in non-UNLOCKED state" in m
                   for m in _messages(caplog))


# ---------------------------------------------------------------------------
# Scenario 2: condition 2 — unlocked but never synced
# ---------------------------------------------------------------------------

class TestConditionTwoNeverSynced:

    def test_forced_full_sync_and_retry(self, caplog):
        """last_sync == 0.0 -> ONE forced FULL sync + ONE retry (v0.7.3 leg)."""
        auth = StubAuth(session_key=FAKE_SESSION_KEY_1, last_sync=0.0)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], [dict(ITEM_A)]])
        auth.cli = cli

        with caplog.at_level("INFO"):
            items = cli.list_items(FAKE_SESSION_KEY_1)

        assert items == [ITEM_A]
        assert len(cli.synced_args()) == 1, "forced sync fired exactly once"
        assert cli.synced_args()[0] == ["sync", "--force"], \
            "v0.7.4 verb correction: the FULL snapshot pull, never --last"
        assert len(cli.list_args()) == 2, "original read + exactly one retry"
        assert cli.status_calls() == [], \
            "condition 2 preempts condition 3 — no verification probe"
        assert any("Empty read detected with unpopulated cache "
                   "(last_sync=0.0)" in m for m in _messages(caplog))


# ---------------------------------------------------------------------------
# Scenarios 3, 9, 10: condition 3 fires — externally invalidated key
# ---------------------------------------------------------------------------

class TestConditionThreeExternalInvalidation:

    def test_locked_status_warning_reunlock_and_retry_once(self, caplog):
        """Scenario 3: the production multi-AuthManager bug.

        Manager believes its key is valid (key_valid, last_sync > 0.0) but
        another process's unlock invalidated it: bw status says "locked".
        Expect WARNING -> local demotion -> ONE re-unlock -> INFO -> ONE
        retry with the FRESH key. No sync (the cache was populated).
        """
        auth = StubAuth(session_key=FAKE_SESSION_KEY_1, last_sync=1234.5,
                        fresh_key=FAKE_SESSION_KEY_2)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], [dict(ITEM_A), dict(ITEM_B)]],
                     status_payload={"status": "locked"})

        with caplog.at_level("INFO"):
            items = cli.list_items(FAKE_SESSION_KEY_1)

        assert items == [ITEM_A, ITEM_B], "retry result must be returned"
        # EXACTLY one verification probe + one retry read; never a sync
        assert len(cli.status_calls()) == 1
        assert len(cli.list_args()) == 2
        assert cli.synced_args() == [], "condition 3 never forces a sync"
        # re-unlock routed through the AuthManager exactly once
        assert auth.get_session_calls == 1
        # CHANGE 3 logging spec: WARNING detection line...
        warn = [m for m in _messages(caplog)
                if "Empty read with externally invalidated session key" in m]
        assert len(warn) == 1
        assert warn[0].endswith("(bw status=locked); forcing re-unlock")
        assert all(r.levelname == "WARNING" for r in caplog.records
                   if "externally invalidated" in r.getMessage())
        # ...and INFO recovery line
        info = [r for r in caplog.records
                if "Session re-established after external invalidation"
                in r.getMessage()]
        assert len(info) == 1 and info[0].levelname == "INFO"
        assert "retrying read once" in info[0].getMessage()

    def test_verification_carries_bw_session_and_retry_uses_fresh_key(self):
        """Hard constraint: the probe verifies THE KEY, not the profile.

        The persistent profile state always reports "locked" by design, so
        a session-less ``bw status`` could never detect invalidation. The
        probe MUST carry the key under test via BW_SESSION; the retry read
        MUST use the FRESH key (never the dead one).
        """
        auth = StubAuth(session_key=FAKE_SESSION_KEY_1, last_sync=1234.5,
                        fresh_key=FAKE_SESSION_KEY_2)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], [dict(ITEM_A)]],
                    status_payload={"status": "locked"})

        cli.list_items(FAKE_SESSION_KEY_1)

        status_args, status_env = cli.status_calls()[0]
        assert status_args == ["status"]
        assert status_env.get("BW_SESSION") == FAKE_SESSION_KEY_1
        assert cli.list_envs()[0].get("BW_SESSION") == FAKE_SESSION_KEY_1
        assert cli.list_envs()[1].get("BW_SESSION") == FAKE_SESSION_KEY_2

    def test_local_state_demoted_before_reunlock(self):
        """Order pin: invalidate_session() BEFORE get_session().

        Without the demotion, get_session()'s UNLOCKED fast path would hand
        back the very same dead key and recovery could never re-unlock.
        """
        order: list[str] = []
        auth = StubAuth(session_key=FAKE_SESSION_KEY_1, last_sync=1234.5,
                        fresh_key=FAKE_SESSION_KEY_2)
        auth.invalidate_session = lambda: (order.append("invalidate"),
                                           setattr(auth, "_session_key", None),
                                           None)[-1]
        real_get_session = auth.get_session

        def tracked_get_session():
            order.append("get_session")
            return real_get_session()

        auth.get_session = tracked_get_session
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], [dict(ITEM_A)]],
                    status_payload={"status": "locked"})

        items = cli.list_items(FAKE_SESSION_KEY_1)

        assert items == [ITEM_A]
        assert order == ["invalidate", "get_session"]

    def test_unauthenticated_status_also_triggers_recovery(self, caplog):
        """Scenario 9: "unauthenticated" is treated as invalid too."""
        auth = StubAuth(session_key=FAKE_SESSION_KEY_1, last_sync=1234.5,
                        fresh_key=FAKE_SESSION_KEY_2)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], [dict(ITEM_A)]],
                    status_payload={"status": "unauthenticated"})

        with caplog.at_level("INFO"):
            items = cli.list_items(FAKE_SESSION_KEY_1)

        assert items == [ITEM_A]
        assert auth.get_session_calls == 1
        assert any("(bw status=unauthenticated); forcing re-unlock" in m
                   for m in _messages(caplog))

    def test_retry_still_empty_accepted_no_loop(self, caplog):
        """Scenario 10: the retry ALSO comes back empty -> accept.

        The re-entrancy guard must be consumed EXACTLY once: no second
        verification, no second re-unlock, no third read — no infinite loop.
        """
        auth = StubAuth(session_key=FAKE_SESSION_KEY_1, last_sync=1234.5,
                        fresh_key=FAKE_SESSION_KEY_2)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], []],
                     status_payload={"status": "locked"})

        with caplog.at_level("INFO"):
            items = cli.list_items(FAKE_SESSION_KEY_1)

        assert items == []
        assert len(cli.list_args()) == 2, "one original + one retry, no more"
        assert len(cli.status_calls()) == 1, "no second verification"
        assert auth.get_session_calls == 1, "no second re-unlock"


# ---------------------------------------------------------------------------
# Scenarios 4, 5, 6, 8: condition 3 acceptance & degradation legs
# ---------------------------------------------------------------------------

class TestConditionThreeAcceptanceAndDegradation:

    def test_valid_key_genuinely_empty_vault_accepted(self, caplog):
        """Scenario 4: status "unlocked" -> genuinely empty vault.

        Accept [] WITHOUT re-unlock, WITHOUT retry — and without touching
        the healthy path's silence contract beyond the single probe.
        """
        auth = StubAuth(session_key=FAKE_SESSION_KEY_1, last_sync=1234.5)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[]], status_payload={"status": "unlocked"})

        with caplog.at_level("INFO"):
            items = cli.list_items(FAKE_SESSION_KEY_1)

        assert items == []
        assert len(cli.status_calls()) == 1, "verification DID run"
        assert len(cli.list_args()) == 1, "no retry read"
        assert auth.get_session_calls == 0, "no re-unlock"
        assert auth.invalidate_calls == 0
        assert _messages(caplog) == [], "healthy empty vault stays silent"

    def test_reunlock_failure_degrades_to_empty_with_warning(self, caplog):
        """Scenario 5: get_session() raises -> WARNING + [] (no retry)."""
        exc = errors.AuthError("master password unavailable")
        auth = StubAuth(session_key=FAKE_SESSION_KEY_1, last_sync=1234.5,
                        get_session_exc=exc)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[]], status_payload={"status": "locked"})

        with caplog.at_level("INFO"):
            items = cli.list_items(FAKE_SESSION_KEY_1)

        assert items == [], "re-unlock failure degrades to the empty read"
        assert len(cli.list_args()) == 1, "no retry without a fresh key"
        fail = [r for r in caplog.records
                if "Re-unlock after external invalidation failed"
                in r.getMessage()]
        assert len(fail) == 1 and fail[0].levelname == "WARNING"
        msg = fail[0].getMessage()
        assert "(AUTH_ERROR)" in msg, "sanitized error code required"
        assert "returning empty list" in msg
        # raw exception text never surfaces
        assert "master password unavailable" not in "\n".join(_messages(caplog))

    def test_same_key_after_reunlock_gives_up_without_retry(self, caplog):
        """Scenario 6: re-unlock returns the SAME key -> nothing to retry."""
        auth = StubAuth(session_key=FAKE_SESSION_KEY_1, last_sync=1234.5)
        # no fresh_key scripted: get_session() hands back the current key
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[]], status_payload={"status": "locked"})

        with caplog.at_level("INFO"):
            items = cli.list_items(FAKE_SESSION_KEY_1)

        assert items == []
        assert auth.get_session_calls == 1, "re-unlock attempted exactly once"
        assert len(cli.list_args()) == 1, "no retry with the dead key"
        assert len(cli.status_calls()) == 1
        # recovery never announced when it did not happen
        assert not any("Session re-established" in m
                       for m in _messages(caplog))

    def test_network_error_probe_degrades_to_empty_silently(self, caplog):
        """Scenario 8: verification raises NetworkError -> [].

        A crashing probe must never take down the read path. Production
        semantics: run() classifies a network failure into NetworkError,
        verify_session() maps it to "unknown" (never "locked" — a downed
        server must not masquerade as an invalidated key), the conservative
        recovery leg fires but DEGRADES silently: the defense demotes local
        state first and this stub's re-unlock then yields no usable key
        ("nothing left to retry") — no crash, no retry read, no success
        announcement, no raw error text.
        """
        auth = StubAuth(session_key=FAKE_SESSION_KEY_1, last_sync=1234.5)
        # no fresh_key scripted: after demotion get_session() yields None
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[]],
                     status_payload=errors.NetworkError("connection refused"))

        with caplog.at_level("INFO"):
            items = cli.list_items(FAKE_SESSION_KEY_1)

        assert items == []
        assert len(cli.status_calls()) == 1, "probe attempted once"
        assert len(cli.list_args()) == 1, "no retry with the dead key"
        assert auth.invalidate_calls == 1, "local state demoted first"
        assert auth.get_session_calls == 1, "conservative recovery attempted"
        msgs = _messages(caplog)
        assert any("(bw status=unknown)" in m for m in msgs)
        assert not any("Session re-established" in m for m in msgs), \
            "recovery did NOT succeed — no success announcement"
        # the raw network error text never surfaces in any log line
        assert "connection refused" not in "\n".join(msgs)

    def test_unknown_status_from_non_dict_payload_recovers(self, caplog):
        """Conservative boundary: any non-"unlocked" status recovers.

        A garbage (non-dict) bw status payload maps to "unknown" in
        verify_session(); unknown validity is treated as suspect, so the
        recovery leg fires rather than trusting a possibly-dead key.
        """
        auth = StubAuth(session_key=FAKE_SESSION_KEY_1, last_sync=1234.5,
                        fresh_key=FAKE_SESSION_KEY_2)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], [dict(ITEM_A)]],
                     status_payload="garbage-not-json")

        with caplog.at_level("INFO"):
            items = cli.list_items(FAKE_SESSION_KEY_1)

        assert items == [ITEM_A]
        assert auth.get_session_calls == 1
        assert any("(bw status=unknown); forcing re-unlock" in m
                   for m in _messages(caplog))


# ---------------------------------------------------------------------------
# Scenario 7 + precedence: zero overhead and cheaper-leg priority
# ---------------------------------------------------------------------------

class TestZeroOverheadAndPrecedence:

    def test_nonempty_read_never_triggers_defense(self, caplog):
        """Scenario 7: happy path pays NOTHING extra (hard constraint)."""
        auth = StubAuth(session_key=FAKE_SESSION_KEY_1, last_sync=1234.5)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[dict(ITEM_A), dict(ITEM_B)]])

        with caplog.at_level("INFO"):
            items = cli.list_items(FAKE_SESSION_KEY_1)

        assert items == [ITEM_A, ITEM_B]
        assert cli.status_calls() == [], "zero extra subprocesses"
        assert len(cli.list_args()) == 1
        assert cli.synced_args() == []
        assert auth.get_session_calls == 0
        assert auth.invalidate_calls == 0
        assert auth.ensure_authenticated_calls == 0
        assert _messages(caplog) == [], "happy path stays completely silent"

    def test_condition_two_preempts_condition_three(self):
        """last_sync == 0.0 fires the cheap sync leg; no status probe."""
        auth = StubAuth(session_key=FAKE_SESSION_KEY_1, last_sync=0.0)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], [dict(ITEM_A)]])
        auth.cli = cli

        items = cli.list_items(FAKE_SESSION_KEY_1)

        assert items == [ITEM_A]
        assert len(cli.synced_args()) == 1, "condition 2 fired"
        assert cli.status_calls() == [], "condition 3 must not also fire"

    def test_condition_one_preempts_condition_three(self):
        """Non-UNLOCKED (key None) routes to the FSM leg; no status probe."""
        auth = StubAuth(session_key=None, last_sync=1234.5,
                        fsm_key=FAKE_SESSION_KEY_2)
        register_auth_manager(auth)
        cli = SpyCli(list_payloads=[[], []])

        items = cli.list_items(FAKE_SESSION_KEY_1)

        assert items == []
        assert auth.ensure_authenticated_calls == 1, "condition 1 fired"
        assert cli.status_calls() == [], "condition 3 must not also fire"
        assert auth.get_session_calls == 0

    def test_duck_typed_manager_without_last_sync_skips_probe(self):
        """Managers lacking last_sync stay outside ALL legs (unchanged)."""
        class LegacyStub:
            def get_session_key(self):
                return FAKE_SESSION_KEY_1

        register_auth_manager(LegacyStub())
        cli = SpyCli(list_payloads=[[]])

        items = cli.list_items(FAKE_SESSION_KEY_1)

        assert items == []
        assert cli.status_calls() == []

    def test_no_manager_registered_returns_empty_quietly(self):
        """No AuthManager in the registry -> defense skipped entirely."""
        cli = SpyCli(list_payloads=[[]])

        items = cli.list_items(FAKE_SESSION_KEY_1)

        assert items == []
        assert cli.status_calls() == []
        assert len(cli.list_args()) == 1


# ---------------------------------------------------------------------------
# Secret hygiene across every new code path
# ---------------------------------------------------------------------------

class TestNoSecretsInLogs:

    def test_all_condition3_paths_log_no_secret_values(self, caplog):
        """Hard constraint: no fake secret appears in ANY log line.

        Exercises BOTH recovery legs (successful re-unlock and failed
        re-unlock whose raw exception text embeds the master-password
        fixture) and asserts the sanitized-code-only logging contract.
        """
        secrets = (FAKE_SESSION_KEY_1, FAKE_SESSION_KEY_2, FAKE_MASTER_PASSWORD)

        # Path A: successful recovery (logs WARNING + INFO)
        auth_ok = StubAuth(session_key=FAKE_SESSION_KEY_1, last_sync=1234.5,
                           fresh_key=FAKE_SESSION_KEY_2)
        register_auth_manager(auth_ok)
        cli_ok = SpyCli(list_payloads=[[], [dict(ITEM_A)]],
                        status_payload={"status": "locked"})
        with caplog.at_level("INFO"):
            cli_ok.list_items(FAKE_SESSION_KEY_1)

        # Path B: failed re-unlock (raw text contains the MP fixture)
        auth_bad = StubAuth(
            session_key=FAKE_SESSION_KEY_1, last_sync=1234.5,
            get_session_exc=errors.SessionError(
                f"raw text with {FAKE_MASTER_PASSWORD} inside"))
        register_auth_manager(auth_bad)
        cli_bad = SpyCli(list_payloads=[[]],
                         status_payload={"status": "locked"})
        with caplog.at_level("INFO"):
            cli_bad.list_items(FAKE_SESSION_KEY_1)

        joined = "\n".join(_messages(caplog))
        for s in secrets:
            assert s not in joined, "secret value leaked into logs"
        # positive control: both defense legs actually logged
        assert "externally invalidated session key" in joined
        assert "Re-unlock after external invalidation failed" in joined
        # the failure line carries ONLY the sanitized code, never raw text
        assert "SESSION_ERROR" in joined
        assert "raw text with" not in joined


# ---------------------------------------------------------------------------
# CHANGE 1 end-to-end: real verify_session() over a mocked subprocess
# ---------------------------------------------------------------------------

def _mk_run(cmd_results=None, default_rc=0, default_out="", default_err=""):
    """subprocess.run stand-in: --version answers itself, then sequenced.

    Mirrors the harness in test_bw_cli.py: BwCli.run() lazily executes
    ``bw --version`` at the choke point BEFORE the real command; the fake
    answers the probe WITHOUT consuming the cmd_results sequence so callers'
    results map 1:1 onto the commands under test.
    """
    seq = list(cmd_results or [])
    calls: list[list] = []

    def fake_run(cmd, *a, **k):
        calls.append(list(cmd))
        m = MagicMock()
        if list(cmd)[1:] == ["--version"]:
            m.returncode = 0
            m.stdout = "2026.9.1"
            m.stderr = ""
            return m
        spec = seq.pop(0) if seq else {}
        m.returncode = spec.get("rc", default_rc)
        m.stdout = spec.get("out", default_out)
        m.stderr = spec.get("err", default_err)
        return m

    return fake_run, calls


class TestVerifySessionEndToEnd:
    """Pin the REAL verify_session() body (not a double) against a mocked
    subprocess layer: correct argv, key-only-via-env transport, and the
    error taxonomy that decides the recovery leg. Uses the shared conftest
    fixtures (fake_bw script + 0700 appdata) — no real bw, no network."""

    def test_unlocked_answer_over_mocked_subprocess(self, fake_bw, appdata,
                                                    monkeypatch):
        import subprocess as sp

        register_auth_manager(None)
        fake_run, calls = _mk_run(cmd_results=[
            {"rc": 0, "out": '{"status": "unlocked"}', "err": ""}])
        envs: list[dict] = []

        def spy(cmd, *a, **k):
            envs.append(dict(k.get("env") or {}))
            return fake_run(cmd, *a, **k)

        monkeypatch.setattr(sp, "run", spy)
        cli = BwCli(fake_bw, appdata)

        assert cli.verify_session(FAKE_SESSION_KEY_1) == "unlocked"
        # exactly ONE subprocess beyond the lazy version probe: the status call
        assert calls[-1][1:] == ["status"]
        # the key travels ONLY via BW_SESSION env
        assert envs[-1].get("BW_SESSION") == FAKE_SESSION_KEY_1

    def test_locked_stderr_maps_to_locked(self, fake_bw, appdata, monkeypatch):
        """A dead key makes bw exit non-zero with 'Vault is locked.' —
        run() raises SessionError, verify_session() conservatively answers
        "locked" so the defense re-unlocks instead of trusting the key."""
        import subprocess as sp

        register_auth_manager(None)
        fake_run, _calls = _mk_run(cmd_results=[
            {"rc": 1, "out": "", "err": "Vault is locked."}])
        monkeypatch.setattr(sp, "run", fake_run)
        cli = BwCli(fake_bw, appdata)

        assert cli.verify_session(FAKE_SESSION_KEY_1) == "locked"

    def test_network_marker_maps_to_unknown(self, fake_bw, appdata,
                                            monkeypatch):
        """Network failures must NOT masquerade as "locked"."""
        import subprocess as sp

        register_auth_manager(None)
        fake_run, _calls = _mk_run(cmd_results=[
            {"rc": 1, "out": "", "err": "connect ECONNREFUSED 10.0.0.1:443"}])
        monkeypatch.setattr(sp, "run", fake_run)
        cli = BwCli(fake_bw, appdata)

        assert cli.verify_session(FAKE_SESSION_KEY_1) == "unknown"

    def test_verify_session_never_logs_the_key(self, fake_bw, appdata,
                                               monkeypatch, caplog):
        import subprocess as sp

        register_auth_manager(None)
        fake_run, _calls = _mk_run(cmd_results=[
            {"rc": 0, "out": '{"status": "unlocked"}', "err": ""}])
        monkeypatch.setattr(sp, "run", fake_run)
        cli = BwCli(fake_bw, appdata)

        with caplog.at_level("DEBUG"):
            cli.verify_session(FAKE_SESSION_KEY_1)

        joined = "\n".join(_messages(caplog))
        assert FAKE_SESSION_KEY_1 not in joined

"""Phase-2 status-reporting fix: operational capability vs bw CLI persistent state.

vaultwarden_status must clearly distinguish:
  * the plugin's ACTUAL capability to perform operations (session key held in
    AuthManager memory, injectable per-command via BW_SESSION by the v0.6.4
    _ensure_session_env choke point), from
  * the Bitwarden CLI's PERSISTENT-session state for the isolated profile
    (what `bw status` reports — legitimately "locked" because BW_SESSION is
    never persisted to disk/os.environ by security design).

Additive fields introduced: session_key_available, operational,
bw_profile_state. Phase-2B closes the two root-cause bugs: the capability
fields (session_key_available / operational / session_active) now share ONE
authoritative AND-predicate (UNLOCKED ∧ key ∧ unexpired — Bug #1), and the
vaultwarden_status handler reconciles via ensure_authenticated() BEFORE
snapshotting so status reflects post-recovery state (Bug #2). bw_profile_state
stays verbatim. Field names/types are unchanged for backward compatibility.
"""
from __future__ import annotations

import json
import time
from unittest.mock import MagicMock

from vaultwarden.auth import AuthManager, AuthState
from vaultwarden.tests.conftest import make_config

# Every field that existed BEFORE the phase-2 fix — backward-compat pin list.
LEGACY_FIELDS = {
    "plugin", "enabled", "auth_state", "session_active", "session_age_seconds",
    "session_timeout_seconds", "server_configured", "server_status",
    "appdata_dir", "allow_write", "last_sync",
}
LEGACY_SERVER_STATUS_KEYS = {"state", "serverUrl", "userEmail", "userId"}


def _manager_with(bw_cli, state: AuthState, key: str | None) -> AuthManager:
    """Build a bootstrapped manager, then force (state, key) directly."""
    cfg = make_config()
    mgr = AuthManager(bw_cli, cfg, client_secret="cs-secret",
                      master_password="mp-secret")
    mgr.ensure_authenticated()          # real fake-bw profile -> UNLOCKED
    with mgr._lock:                     # simulate any in-memory situation
        mgr._state = state
        mgr._session_key = key
        mgr._session_created_at = time.time() if key else 0.0
    return mgr


# ---------------------------------------------------------------------------
# Scenario 1: session key available in AuthManager -> operational == True
# ---------------------------------------------------------------------------

def test_operational_true_when_session_key_in_memory(bw_cli):
    mgr = _manager_with(bw_cli, AuthState.UNLOCKED, "SKEY-operational-1")
    snap = mgr.status_snapshot()
    assert snap["operational"] is True
    assert snap["session_key_available"] is True
    assert snap["auth_state"] == "unlocked"
    assert snap["session_active"] is True


def test_logged_in_with_stale_key_is_not_operational(bw_cli):
    """Phase-2B Bug #1 (AND-semantics): auth_state='logged_in' with a STALE
    key lingering in memory is NOT capability — get_session_key() gates on
    UNLOCKED, so _ensure_session_env can never inject this key. Presence-only
    used to over-report True here; all three capability fields must be False,
    while session_age_seconds keeps its raw numeric value."""
    mgr = _manager_with(bw_cli, AuthState.LOGGED_IN, "SKEY-stale-window-2")
    snap = mgr.status_snapshot()
    assert snap["auth_state"] == "logged_in"          # unchanged semantics
    assert snap["session_key_available"] is False     # AND-predicate rejects
    assert snap["operational"] is False
    assert snap["session_active"] is False
    assert isinstance(snap["session_age_seconds"], float)  # raw age kept
    # And it matches the authoritative gate itself:
    assert mgr.get_session_key() is None


# ---------------------------------------------------------------------------
# Scenario 2: session key absent / vault locked -> operational == False
# ---------------------------------------------------------------------------

def test_operational_false_when_key_absent(bw_cli):
    mgr = _manager_with(bw_cli, AuthState.LOGGED_IN, None)  # locked vault
    snap = mgr.status_snapshot()
    assert snap["operational"] is False
    assert snap["session_key_available"] is False
    assert snap["session_active"] is False
    assert snap["session_age_seconds"] is None


# ---------------------------------------------------------------------------
# Scenario 3: bw status says "locked" but key available -> top-level shows
#             the plugin is operational (no misleading non-functional view)
# ---------------------------------------------------------------------------

def _mocked_manager(state: AuthState, key: str | None,
                    bw_payload: dict) -> AuthManager:
    config = MagicMock()
    config.server_url = "https://vault.example.com"
    config.session_timeout_seconds = 14400
    config.auto_sync = False
    config.enabled = True
    config.allow_write = True

    bw = MagicMock()
    bw.status.return_value = bw_payload
    bw.appdata_dir = "/tmp/.bw-data"

    mgr = AuthManager(bw, config, client_secret="cs", master_password="mp")
    mgr._state = state
    mgr._session_key = key
    mgr._session_created_at = time.time() if key else 0.0
    return mgr


def test_bw_locked_but_key_available_top_level_is_operational():
    mgr = _mocked_manager(
        AuthState.UNLOCKED, "SKEY-injected-3",
        {"status": "locked", "serverUrl": "https://vault.example.com"})
    snap = mgr.status_snapshot()
    # Top-level capability fields: plugin CAN operate (per-command injection).
    assert snap["operational"] is True
    assert snap["session_key_available"] is True
    assert snap["auth_state"] == "unlocked"
    # bw CLI persistent-profile state kept verbatim for fidelity...
    assert snap["bw_profile_state"] == "locked"
    # ...while the legacy override keeps its v0.2.6 meaning (internal key wins).
    assert snap["server_status"]["state"] == "unlocked"


def test_bw_error_payload_does_not_leak_into_new_fields():
    """probe_status() error dicts must not crash the snapshot and the raw
    profile state falls back sensibly."""
    mgr = _mocked_manager(AuthState.LOGGED_IN, None,
                          {"status": "error", "error_code": "NETWORK_ERROR"})
    snap = mgr.status_snapshot()
    assert snap["operational"] is False
    assert snap["bw_profile_state"] == "error"


# ---------------------------------------------------------------------------
# Scenario 4: existing status fields still present (backward compatibility)
# ---------------------------------------------------------------------------

def test_legacy_fields_all_present_and_typed(bw_cli):
    mgr = _manager_with(bw_cli, AuthState.UNLOCKED, "SKEY-compat-4")
    snap = mgr.status_snapshot()
    missing = LEGACY_FIELDS - set(snap)
    assert not missing, f"legacy status fields removed: {missing}"
    assert set(mgr.status_snapshot()["server_status"]) >= LEGACY_SERVER_STATUS_KEYS
    # Types of the reinterpreted-critical fields are unchanged.
    assert isinstance(snap["session_active"], bool)
    assert isinstance(snap["session_age_seconds"], float)
    assert isinstance(snap["server_status"]["state"], str)
    # New fields are purely additive booleans/strings.
    assert isinstance(snap["session_key_available"], bool)
    assert isinstance(snap["operational"], bool)
    assert isinstance(snap["bw_profile_state"], str)


def test_tool_output_contains_additive_fields(bw_cli):
    """End-to-end through the vaultwarden_status tool handler."""
    from vaultwarden.placeholders import PlaceholderRegistry
    from vaultwarden.tools import get_tools

    mgr = _manager_with(bw_cli, AuthState.UNLOCKED, "SKEY-e2e-5")
    registry = PlaceholderRegistry(ttl_seconds=300, max_entries=50)
    handlers = {schema["name"]: fn
                for schema, fn in get_tools(mgr, make_config(), registry)}
    payload = json.loads(handlers["vaultwarden_status"]({}))
    status = payload["status"]
    assert status["operational"] is True
    assert status["session_key_available"] is True
    assert LEGACY_FIELDS <= set(status)


# ---------------------------------------------------------------------------
# Scenario 5: no secret/session values in status output (redaction preserved)
# ---------------------------------------------------------------------------

def test_status_output_never_contains_secrets(bw_cli):
    key = "SUPERSECRET-session-key-value"
    mgr = _manager_with(bw_cli, AuthState.UNLOCKED, key)
    blob = str(mgr.status_snapshot()) + json.dumps(mgr.status_snapshot())
    assert key not in blob
    assert "cs-secret" not in blob
    assert "mp-secret" not in blob
    # And the same holds in the locked case.
    mgr_locked = _manager_with(bw_cli, AuthState.LOGGED_IN, None)
    assert key not in json.dumps(mgr_locked.status_snapshot())


# ---------------------------------------------------------------------------
# Phase-2B regression tests: AND-predicate edge cases + recovery-on-read
# ---------------------------------------------------------------------------

# Scenario B1: fresh unlock, no timeout -> all capability fields True
def test_fresh_unlock_all_capability_fields_true(bw_cli):
    mgr = _manager_with(bw_cli, AuthState.UNLOCKED, "SKEY-2b-fresh")
    snap = mgr.status_snapshot()
    assert snap["operational"] is True
    assert snap["session_key_available"] is True
    assert snap["session_active"] is True
    assert snap["auth_state"] == "unlocked"


# Scenario B2: session expired (age > timeout) -> all capability fields False,
# raw age still reported (not nulled out)
def test_expired_session_not_operational_but_age_kept():
    mgr = _mocked_manager(AuthState.UNLOCKED, "SKEY-2b-expired",
                          {"status": "locked"})
    # Force the key to look older than the 14400s timeout of _mocked_manager.
    mgr._session_created_at = time.time() - 14401
    snap = mgr.status_snapshot()
    assert snap["operational"] is False
    assert snap["session_key_available"] is False
    assert snap["session_active"] is False
    # Raw age preserved for numeric consumers...
    assert isinstance(snap["session_age_seconds"], float)
    assert snap["session_age_seconds"] >= 14401
    # ...but a stale/expired key no longer falsely flips the v0.2.6 indicator.
    assert snap["server_status"]["state"] == "locked"
    # NB: get_session_key() is deliberately NOT asserted here — it gates on
    # state alone (no expiry check); expiry is enforced by is_unlocked()/
    # get_session(), which is exactly what h_status recovery-on-read uses.


# Scenario B3: h_status recovery-on-read — after expiry, the status TOOL
# reconciles via ensure_authenticated() and reports post-recovery state.
def test_h_status_recovers_expired_session_before_snapshot(bw_cli, monkeypatch):
    from vaultwarden.placeholders import PlaceholderRegistry
    from vaultwarden.tools import get_tools

    cfg = make_config()
    mgr = AuthManager(bw_cli, cfg, client_secret="cs-secret",
                      master_password="mp-secret")
    mgr.ensure_authenticated()                     # real fake-bw -> UNLOCKED
    stale_key = mgr.session_key
    with mgr._lock:                                # simulate expiry window
        mgr._session_created_at = time.time() - (cfg.session_timeout_seconds + 1)
    # Direct snapshot (observational, no mutation): truthfully not operational.
    assert mgr.status_snapshot()["operational"] is False
    assert mgr.status_snapshot()["session_active"] is False

    # Recovery must actually re-unlock (fresh key), not take the remembered-
    # key fast path in _adopt_existing_unlocked_session (that gate checks key
    # PRESENCE only, which is true for an expired-but-lingering key). This
    # mirrors what operations do implicitly via get_session().
    def fake_do_unlock():
        with mgr._lock:
            mgr._session_key = "SKEY-2b-refreshed"
            mgr._session_created_at = time.time()
            mgr._state = AuthState.UNLOCKED
    monkeypatch.setattr(mgr, "_do_unlock", fake_do_unlock)

    registry = PlaceholderRegistry(ttl_seconds=300, max_entries=50)
    handlers = {schema["name"]: fn for schema, fn in get_tools(mgr, cfg, registry)}
    payload = json.loads(handlers["vaultwarden_status"]({}))
    status = payload["status"]
    # Bug #2 fixed: the tool reflects POST-recovery state.
    assert status["operational"] is True
    assert status["session_key_available"] is True
    assert status["session_active"] is True
    assert status["auth_state"] == "unlocked"
    assert status["session_age_seconds"] <= 60     # recovered just now
    assert stale_key != "SKEY-2b-refreshed"


# Scenario B4: recovery fails (network down) -> h_status must NOT raise;
# it degrades to the observational snapshot with operational=false.
def test_h_status_graceful_when_recovery_fails(bw_cli, monkeypatch):
    from vaultwarden.errors import VaultwardenError
    from vaultwarden.placeholders import PlaceholderRegistry
    from vaultwarden.tools import get_tools

    cfg = make_config()   # client_id user.1111... + server https://vault.example.com
    mgr = AuthManager(bw_cli, cfg, client_secret="cs", master_password="mp")
    mgr._state = AuthState.LOGGED_IN               # was up, now network died

    # Profile says locked+correct account -> ensure_authenticated takes the
    # unlock path; the network is down so the unlock attempt fails hard.
    monkeypatch.setattr(mgr, "probe_status", lambda: {
        "status": "locked", "serverUrl": cfg.server_url,
        "userId": cfg.client_id.removeprefix("user."),
        "userEmail": "op@example.com"})

    def failing_unlock():
        raise VaultwardenError("connection refused", code="NETWORK_ERROR")
    monkeypatch.setattr(mgr, "_do_unlock", failing_unlock)
    monkeypatch.setattr(mgr, "_maybe_initial_sync", lambda: None)

    registry = PlaceholderRegistry(ttl_seconds=300, max_entries=50)
    handlers = {schema["name"]: fn for schema, fn in get_tools(mgr, cfg, registry)}
    res = handlers["vaultwarden_status"]({})       # must never hard-fail
    assert isinstance(res, str)
    payload = json.loads(res)
    assert "error" not in payload                  # degraded, not raised
    status = payload["status"]
    assert status["operational"] is False
    assert status["session_key_available"] is False
    assert status["session_active"] is False
    # Observational snapshot kept the pre-recovery truth: still logged_in,
    # and bw_profile_state remains verbatim ("locked").
    assert status["auth_state"] == "logged_in"
    assert status["bw_profile_state"] == "locked"


# Scenario B5: bw_profile_state independence — verbatim even when the
# capability fields say the plugin IS operational.
def test_bw_profile_state_independent_of_capability():
    mgr = _mocked_manager(AuthState.UNLOCKED, "SKEY-2b-independent",
                          {"status": "locked", "serverUrl": "https://vault.example.com"})
    snap = mgr.status_snapshot()
    assert snap["operational"] is True
    assert snap["session_key_available"] is True
    assert snap["session_active"] is True
    # CHANGE 3: bw_profile_state stays the raw bw CLI persistent-profile value.
    assert snap["bw_profile_state"] == "locked"


# Scenario B6: backward compat under the new predicate — every pre-existing
# field present, types unchanged (bool stays bool, str stays str).
def test_backward_compat_types_under_and_predicate(bw_cli):
    for state, key in ((AuthState.UNLOCKED, "SKEY-2b-bool"),
                       (AuthState.LOGGED_IN, None)):
        snap = _manager_with(bw_cli, state, key).status_snapshot()
        assert isinstance(snap["session_active"], bool)
        assert isinstance(snap["session_key_available"], bool)
        assert isinstance(snap["operational"], bool)
        assert isinstance(snap["auth_state"], str)
        assert isinstance(snap["bw_profile_state"], str)
        assert isinstance(snap["server_status"]["state"], str)

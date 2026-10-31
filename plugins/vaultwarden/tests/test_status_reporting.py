"""Phase-2 status-reporting fix: operational capability vs bw CLI persistent state.

vaultwarden_status must clearly distinguish:
  * the plugin's ACTUAL capability to perform operations (session key held in
    AuthManager memory, injectable per-command via BW_SESSION by the v0.6.4
    _ensure_session_env choke point), from
  * the Bitwarden CLI's PERSISTENT-session state for the isolated profile
    (what `bw status` reports — legitimately "locked" because BW_SESSION is
    never persisted to disk/os.environ by security design).

Additive fields introduced: session_key_available, operational,
bw_profile_state. All pre-existing fields keep their exact v0.2.6 semantics.
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


def test_logged_in_with_key_shows_capability_despite_locked_auth_state(bw_cli):
    """The reported symptom triple: auth_state='logged_in' while a key IS
    held in memory. The additive fields must show the plugin is operational;
    legacy fields keep their verbatim values for compatibility."""
    mgr = _manager_with(bw_cli, AuthState.LOGGED_IN, "SKEY-stale-window-2")
    snap = mgr.status_snapshot()
    assert snap["auth_state"] == "logged_in"          # unchanged semantics
    assert snap["session_key_available"] is True      # actual capability
    assert snap["operational"] is True


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

"""Unit tests: AuthManager state machine, recovery rules, session hygiene."""
from __future__ import annotations

import time

import pytest

from vaultwarden import errors
from vaultwarden.auth import AuthManager, AuthState, ensure_appdata_dir
from vaultwarden.tests.conftest import make_config


def test_full_bootstrap_flow(bw_cli):
    cfg = make_config()
    mgr = AuthManager(bw_cli, cfg, client_secret="cs-secret", master_password="mp-secret")
    # v0.1.3/v0.1.4 (plan §5): the manager starts UNINITIALIZED and only becomes
    # CONFIGURED when configure_server_if_needed() runs (register() bootstrap).
    # v0.1.9: ensure_authenticated() itself now performs server config + login
    # + unlock after checking `bw status` — no unconditional config anymore.
    assert mgr.state is AuthState.UNINITIALIZED
    mgr.configure_server_if_needed()
    assert mgr.state is AuthState.CONFIGURED
    mgr.ensure_authenticated()
    assert mgr.state is AuthState.UNLOCKED
    assert mgr.is_unlocked()
    key = mgr.get_session()
    assert "sessionkey" in key  # memory only — never os.environ
    import os
    assert "BW_SESSION" not in os.environ


def test_missing_secrets_raises_auth_error(bw_cli):
    cfg = make_config()
    with pytest.raises(errors.AuthError):
        mgr = AuthManager(bw_cli, cfg, client_secret="WRONG", master_password="mp-secret")
        mgr.ensure_authenticated()


def test_invalid_master_password_no_retry(bw_cli):
    cfg = make_config()
    mgr = AuthManager(bw_cli, cfg, client_secret="cs-secret", master_password="BAD")
    calls = {"n": 0}
    orig = bw_cli.unlock_passwordenv

    def counting(pw):
        calls["n"] += 1
        return orig(pw)

    bw_cli.unlock_passwordenv = counting  # type: ignore[assignment]
    with pytest.raises(errors.AuthError) as ei:
        mgr.ensure_authenticated()
    assert calls["n"] == 1          # NO retry on bad password
    assert "BAD" not in str(ei.value.message)  # value never surfaced


def test_session_expiry_forces_reunlock(bw_cli):
    cfg = make_config(section={"session_timeout_seconds": 1})
    mgr = AuthManager(bw_cli, cfg, client_secret="cs-secret", master_password="mp-secret")
    mgr.ensure_authenticated()
    first = mgr.get_session()
    mgr._session_created_at = time.time() - 5   # simulate expiry
    assert not mgr.is_unlocked()
    second = mgr.get_session()                   # auto re-unlock
    assert second == first                       # stable raw session key


def test_recovery_from_mid_operation_session_error(bw_cli):
    cfg = make_config()
    mgr = AuthManager(bw_cli, cfg, client_secret="cs-secret", master_password="mp-secret")
    mgr.ensure_authenticated()
    seen_sessions = []

    def flaky(session):
        seen_sessions.append(session)
        if len(seen_sessions) == 1:
            raise errors.SessionError("vault is locked")
        return "ok"

    result = mgr.run_with_recovery(flaky)
    assert result == "ok"
    assert len(seen_sessions) == 2   # retried exactly once after re-auth


def test_lock_clears_session(bw_cli):
    cfg = make_config()
    mgr = AuthManager(bw_cli, cfg, client_secret="cs-secret", master_password="mp-secret")
    mgr.ensure_authenticated()
    assert mgr.session_key
    mgr.lock()
    assert mgr.session_key is None
    assert mgr.state is AuthState.LOGGED_IN


def test_status_snapshot_has_no_secrets(bw_cli):
    cfg = make_config()
    mgr = AuthManager(bw_cli, cfg, client_secret="cs-secret", master_password="mp-secret")
    mgr.ensure_authenticated()
    snap = mgr.status_snapshot()
    blob = str(snap)
    assert "cs-secret" not in blob
    assert "mp-secret" not in blob
    assert "sessionkey" not in blob
    assert snap["auth_state"] == "unlocked"


def test_ensure_appdata_dir_chmod700(tmp_path):
    d = ensure_appdata_dir(tmp_path / "sub" / ".bw-data")
    mode = d.stat().st_mode & 0o777
    assert mode == 0o700


def test_unavailable_before_init():
    class Dummy:
        pass
    # fresh manager without ensure_authenticated is still CONFIGURED-capable;
    # UNINITIALIZED gate exercised via check_fn semantics:
    cfg = make_config()
    mgr = AuthManager.__new__(AuthManager)  # bypass init on purpose
    mgr._state = AuthState.UNINITIALIZED
    assert mgr.is_available() is False

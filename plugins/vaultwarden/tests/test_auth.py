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


def test_ensure_appdata_dir_rejects_insecure_dir(tmp_path):
    """AUD-04 (v0.6.2): an existing-but-insecure .bw-data is NEVER silently
    repaired — ensure_appdata_dir fails closed with FilesystemSecurityError."""
    from vaultwarden.secure_fs import FilesystemSecurityError
    d = tmp_path / ".bw-data"
    d.mkdir(mode=0o755)  # group/world readable — insecure
    with pytest.raises(FilesystemSecurityError):
        ensure_appdata_dir(d)
    # still insecure afterwards: no silent chmod repair happened
    assert d.stat().st_mode & 0o777 == 0o755


def test_ensure_appdata_dir_rejects_symlink(tmp_path):
    """AUD-04 (v0.6.2): a symlinked appdata dir is rejected via lstat()."""
    from vaultwarden.secure_fs import FilesystemSecurityError
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / ".bw-data"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(FilesystemSecurityError):
        ensure_appdata_dir(link)


def test_base_env_blocks_bw_on_insecure_appdata(fake_bw, tmp_path):
    """AUD-04 (v0.6.2): the single bw-subprocess choke point re-validates
    the appdata dir BEFORE exporting BITWARDENCLI_APPDATA_DIR — an insecure
    dir raises FilesystemSecurityError and no env (hence no bw run) results."""
    from vaultwarden.bw_cli import BwCli
    from vaultwarden.secure_fs import FilesystemSecurityError
    d = tmp_path / ".bw-data"
    d.mkdir(mode=0o755)  # group/world accessible — insecure
    cli = BwCli(fake_bw, d)
    with pytest.raises(FilesystemSecurityError):
        cli.base_env({"BW_SESSION": "x"})
    # no silent repair: dir keeps its insecure mode
    assert d.stat().st_mode & 0o777 == 0o755


def test_base_env_creates_missing_appdata_hardened(fake_bw, tmp_path):
    """AUD-04 (v0.6.2): a missing .bw-data is created hardened (0700)."""
    from vaultwarden.bw_cli import BwCli
    d = tmp_path / "fresh" / ".bw-data"
    cli = BwCli(fake_bw, str(d))
    env = cli.base_env()
    assert d.is_dir()
    assert d.stat().st_mode & 0o777 == 0o700
    assert env["BITWARDENCLI_APPDATA_DIR"] == str(d)


def test_unavailable_before_init():
    # fresh manager without ensure_authenticated is still CONFIGURED-capable;
    # UNINITIALIZED gate exercised via check_fn semantics:
    mgr = AuthManager.__new__(AuthManager)  # bypass init on purpose
    mgr._state = AuthState.UNINITIALIZED
    assert mgr.is_available() is False


# ---------------------------------------------------------------------------
# Consolidated from test_cleanup_hardening_v026.py (status parts)
# ---------------------------------------------------------------------------

def test_status_snapshot_shows_unlocked_when_session_active():
    """v0.2.6: status_snapshot must show 'unlocked' when session is active."""
    from unittest.mock import MagicMock

    bw = MagicMock()
    bw.status.return_value = {"status": "locked", "serverUrl": "https://vault.example.com"}

    config = MagicMock()
    config.server_url = "https://vault.example.com"
    config.session_timeout_seconds = 14400
    config.auto_sync = False
    config.enabled = True
    config.allow_write = True

    auth = AuthManager(bw, config, client_secret="cs", master_password="mp")
    auth._state = AuthState.UNLOCKED
    auth._session_key = "test-session-key"
    auth._session_created_at = time.time()

    snapshot = auth.status_snapshot()
    assert snapshot["session_active"] is True
    assert snapshot["auth_state"] == "unlocked"
    assert snapshot["server_status"]["state"] == "unlocked", \
        f"Expected 'unlocked', got {snapshot['server_status']['state']}"


def test_status_snapshot_shows_locked_when_no_session():
    """v0.2.6: status_snapshot falls back to bw status when no session."""
    from unittest.mock import MagicMock

    bw = MagicMock()
    bw.status.return_value = {"status": "locked", "serverUrl": "https://vault.example.com"}

    config = MagicMock()
    config.server_url = "https://vault.example.com"
    config.session_timeout_seconds = 14400
    config.auto_sync = False
    config.enabled = True
    config.allow_write = True

    auth = AuthManager(bw, config, client_secret="cs", master_password="mp")
    auth._state = AuthState.LOGGED_IN
    auth._session_key = None

    snapshot = auth.status_snapshot()
    assert snapshot["session_active"] is False
    assert snapshot["server_status"]["state"] == "locked"


# ---------------------------------------------------------------------------
# Consolidated from test_cleanup_hardening_v023.py (unlock guard part)
# ---------------------------------------------------------------------------

def test_do_unlock_has_no_early_return_guard():
    """v0.2.3: _do_unlock() must ALWAYS attempt the unlock (no toggle guard)."""
    import ast
    import inspect
    import textwrap
    body = ast.parse(textwrap.dedent(inspect.getsource(AuthManager._do_unlock)))
    fn = body.body[0]
    # No conditional early-return at the top of the method body.
    for stmt in fn.body:
        assert not isinstance(stmt, ast.If), "unexpected guard in _do_unlock"
        assert not isinstance(stmt, ast.Return), "unexpected early return in _do_unlock"


# ---------------------------------------------------------------------------
# Consolidated from test_security_hardening_v022.py (fail-closed auth part)
# ---------------------------------------------------------------------------

def test_auth_empty_userid_forces_reauth(monkeypatch):
    """SECURITY (integration): bw status WITHOUT userId => re-auth, no adoption."""
    import threading
    from unittest.mock import MagicMock

    auth = AuthManager.__new__(AuthManager)
    auth._lock = threading.RLock()
    auth._state = AuthState.CONFIGURED
    auth._session_key = None
    auth._last_sync = 0.0
    auth._bw = MagicMock()

    class _Cfg:
        server_url = "https://vault.example.com"

    auth._config = _Cfg()
    auth._client_id = "user.1234-5678"

    # bw status reports an UNLOCKED session but NO userId at all.
    monkeypatch.setattr(auth, "probe_status", lambda: {
        "serverUrl": "https://vault.example.com",
        "userId": "",
        "status": "unlocked",
    })
    adopted: list = []
    monkeypatch.setattr(auth, "_adopt_existing_unlocked_session",
                        lambda: adopted.append(True))
    monkeypatch.setattr(auth, "_configure_server", lambda: None)
    monkeypatch.setattr(auth, "_do_login", lambda: None)
    monkeypatch.setattr(auth, "_do_unlock", lambda: None)
    monkeypatch.setattr(auth, "_maybe_initial_sync", lambda: None)

    auth.ensure_authenticated()

    # Fail-closed: unknown session must NOT be adopted; Case B logout ran.
    assert not adopted, "empty userId must not adopt an unknown session"
    auth._bw.logout.assert_called_once()


# ---------------------------------------------------------------------------
# Consolidated from test_bugfixes_v12.py (BUG-9 part)
# ---------------------------------------------------------------------------

def test_check_fn_is_named_closure(fake_bw, appdata):
    from vaultwarden import _make_check_fn
    from vaultwarden.bw_cli import BwCli
    from vaultwarden.tests.conftest import make_config

    cfg = make_config()
    auth = AuthManager(BwCli(fake_bw, appdata), cfg,
                       client_secret="cs-secret", master_password="mp-secret")
    check = _make_check_fn(auth)
    assert callable(check) and check.__name__ == "check"
    assert check() is False                      # uninitialised state
    auth.ensure_authenticated()
    assert check() is True


# ---------------------------------------------------------------------------
# Consolidated from test_store_edit_v027.py (auth forwarding parts)
# ---------------------------------------------------------------------------

def test_auth_edit_item_passes_item_id():
    """v0.2.7: auth.edit_item must forward the item id to bw_cli.edit_item."""
    from unittest.mock import MagicMock
    bw = MagicMock()
    bw.edit_item.return_value = {"id": "abc"}

    config = MagicMock()
    config.session_timeout_seconds = 14400

    auth = AuthManager(bw, config, client_secret="cs", master_password="mp")
    auth._state = AuthState.UNLOCKED
    auth._session_key = "SESSION"

    auth.edit_item({"id": "abc", "name": "n"})
    args, _ = bw.edit_item.call_args
    assert args[1] == "abc", f"edit_item called with args: {args}"


def test_auth_create_item_uses_new_encode_item_signature():
    """v0.2.7: auth.create_item calls encode_item with only the item."""
    import base64
    from unittest.mock import MagicMock
    bw = MagicMock()
    bw.create_item.return_value = {"id": "abc"}

    config = MagicMock()
    config.session_timeout_seconds = 14400

    auth = AuthManager(bw, config, client_secret="cs", master_password="mp")
    auth._state = AuthState.UNLOCKED
    auth._session_key = "SESSION"

    auth.create_item({"name": "n"})
    args, _ = bw.create_item.call_args
    # create_item(session, blob) — 2 args, blob is valid base64
    assert len(args) == 2
    base64.b64decode(args[1])  # must not raise

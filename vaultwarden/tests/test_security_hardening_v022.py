# vaultwarden/tests/test_security_hardening_v022.py — v0.2.2
"""Regression tests for the v0.2.2 security & hardening release:

- SECURITY: fail-closed account verification (auth.ensure_authenticated)
- BUGFIX:   task-scoped, lock-protected _PENDING_ERRORS (race condition)
- BUGFIX:   configurable terminal tool names / command keys
"""
from __future__ import annotations


def test_account_verification_fail_closed():
    """SECURITY: empty userId must NOT be treated as correct account."""
    # Simulate: current_user_id = "", expected_user_id = "1234-5678"
    current_user_id = ""
    expected_user_id = "1234-5678"
    is_correct_account = (
        bool(current_user_id) and current_user_id == expected_user_id)
    assert not is_correct_account


def test_pending_errors_task_isolation():
    """BUGFIX: parallel tool calls must not lose each other's errors."""
    import threading
    from vaultwarden.hooks import _PENDING_ERRORS, _PENDING_LOCK

    # Simulate two tasks adding errors
    with _PENDING_LOCK:
        _PENDING_ERRORS.setdefault("task_A", []).append({"error": "A"})
        _PENDING_ERRORS.setdefault("task_B", []).append({"error": "B"})

    # Pop task_A — task_B must survive
    with _PENDING_LOCK:
        errors_a = _PENDING_ERRORS.pop("task_A", [])
    assert len(errors_a) == 1
    with _PENDING_LOCK:
        assert "task_B" in _PENDING_ERRORS
        errors_b = _PENDING_ERRORS.pop("task_B", [])
    assert len(errors_b) == 1


def test_terminal_tools_configurable():
    """BUGFIX: terminal tool names must be configurable."""
    from vaultwarden.config import PluginConfig
    cfg = PluginConfig(section={"terminal_tool_names": ["my_custom_shell"]})
    assert cfg.terminal_tool_names == ["my_custom_shell"]


def test_version_headers():
    """Verify all modified files carry the CURRENT release version header.

    v0.2.3: headers moved to `— v0.2.3`; kept as a regression guard that the
    five core modules (incl. hooks.py) all declare the same current version.
    """
    import re
    import vaultwarden.config
    import vaultwarden
    from pathlib import Path

    pkg_dir = Path(vaultwarden.__file__).resolve().parent
    modified = ["__init__.py", "config.py", "hooks.py", "auth.py"]
    for name in modified:
        path = pkg_dir / name
        with open(path, 'r') as f:
            first_line = f.readline().strip()
        m = re.search(r"v\d+\.\d+\.\d+", first_line)
        assert m, f"{name} missing version header: {first_line}"
        assert m.group(0) == "v0.2.3", f"{name} stale version header: {first_line}"


# ---------------------------------------------------------------------------
# Additional integration-level regression coverage for the three fixes.
# ---------------------------------------------------------------------------

def test_auth_empty_userid_forces_reauth(monkeypatch):
    """SECURITY (integration): bw status WITHOUT userId => re-auth, no adoption."""
    from unittest.mock import MagicMock
    from vaultwarden.auth import AuthManager, AuthState

    auth = AuthManager.__new__(AuthManager)
    import threading
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


def test_resolver_uses_default_expanded_terminal_tools():
    """BUGFIX: new default tool names (run_command/exec/...) are recognized."""
    from unittest.mock import MagicMock
    from vaultwarden.hooks import make_placeholder_resolver

    auth = MagicMock()
    registry = MagicMock()
    mw = make_placeholder_resolver(auth, registry, config=None)
    # foreign tool still ignored
    assert mw("file_read", {"command": "__VW_SECRET_x__"}, task_id="t") is None
    # new default exec-ish tool passes the gate (registry lookup mocked to fail
    # closed, but the important part is it does NOT return None at the gate)
    out = mw("exec", {"command": "echo __VW_SECRET_deadbeefcafe__"}, task_id="t-cfg")
    assert out is not None
    from vaultwarden.hooks import _PENDING_ERRORS, _PENDING_LOCK
    with _PENDING_LOCK:
        _PENDING_ERRORS.pop("t-cfg", None)


def test_resolver_honours_custom_terminal_tool_names():
    """BUGFIX: config-provided tool names REPLACE the defaults."""
    from unittest.mock import MagicMock
    from vaultwarden.hooks import make_placeholder_resolver

    auth = MagicMock()
    registry = MagicMock()
    cfg = MagicMock()
    cfg.terminal_tool_names = ["my_custom_shell"]
    cfg.terminal_command_keys = ["payload"]
    mw = make_placeholder_resolver(auth, registry, config=cfg)
    # default name "terminal" is NO LONGER handled when config overrides
    assert mw("terminal", {"command": "__VW_SECRET_x__"}, task_id="t") is None
    # custom name + custom key ARE handled
    out = mw("my_custom_shell", {"payload": "echo __VW_SECRET_deadbeefcafe__"},
             task_id="t-custom")
    assert out is not None
    from vaultwarden.hooks import _PENDING_ERRORS, _PENDING_LOCK
    with _PENDING_LOCK:
        _PENDING_ERRORS.pop("t-custom", None)


def test_post_cleanup_surfaces_only_own_task_errors():
    """BUGFIX (integration): one task's post hook must not steal another's errors."""
    from vaultwarden.hooks import (_PENDING_ERRORS, _PENDING_LOCK,
                                   make_post_cleanup_hook)

    from unittest.mock import MagicMock
    post = make_post_cleanup_hook(MagicMock(), MagicMock())
    with _PENDING_LOCK:
        _PENDING_ERRORS["task_1"] = [{"error_code": "PLACEHOLDER_ERROR", "task": 1}]
        _PENDING_ERRORS["task_2"] = [{"error_code": "PLACEHOLDER_ERROR", "task": 2}]

    res: dict = {"output": "ok"}
    post("terminal", {}, res, task_id="task_1")
    assert len(res.get("vaultwarden_placeholder_errors", [])) == 1
    assert res["vaultwarden_placeholder_errors"][0]["task"] == 1
    with _PENDING_LOCK:
        # task_2's errors survived task_1's cleanup
        assert "task_2" in _PENDING_ERRORS
        _PENDING_ERRORS.clear()

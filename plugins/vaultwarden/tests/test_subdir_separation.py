"""v0.7.7 Phase 2 regression suite: SUB DIR SESSION SEPARATION (audit/p2.md).

Scenarios 1-24 of the phase-2 prompt:
  * detect_process_role() correctness, case-insensitivity, priority (1-7)
  * resolve_process_appdata_dir() hardening + hostile-role defense (8-14)
  * BwCli wiring (subdir, not base dir), PLUGIN_STATE and status_snapshot
    process_role reporting incl. the __new__-fallback (15-20)
  * Multi-process isolation: separate subdirs, per-profile session state
    never invalidated across profiles, no on-disk session key (21-24)
  * CHANGE 6: recursive session-key persistence scan applied to the new
    base+subdir layout (the existing test_session_key[SESSION:****] already
    walks tmp_path recursively — this suite pins the same invariant for a
    real resolve_process_appdata_dir() tree).

Constraints honored: pytest + stdlib only, no production code modified,
sys.argv pinned/restored via monkeypatch, fake bw binary only, no network,
fake session/secret values clearly marked, secret-free log assertions.
"""
from __future__ import annotations

import logging
import os
import stat
import sys
import threading
from pathlib import Path

import pytest

from vaultwarden.auth import AuthManager, AuthState, resolve_process_appdata_dir
from vaultwarden.bw_cli import BwCli
from vaultwarden.config import VALID_PROCESS_ROLES, detect_process_role
from vaultwarden.secure_fs import FilesystemSecurityError
from vaultwarden.tests.conftest import RecordingCtx

# ── Deliberately FAKE test values (conftest fake bw fixtures accept them) ──
FAKE_CLIENT_SECRET = "cs-secret"
FAKE_MASTER_PASSWORD = "mp-secret"
FAKE_SESSION_KEY = "abcdef0123456789-sessionkey-FEEDFACE"  # fake bw unlock output
AUTH_LOGGER = "hermes.plugins.vaultwarden.auth"
BWCLI_LOGGER = "hermes.plugins.vaultwarden.bw_cli"


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(str(path)).st_mode)


@pytest.fixture()
def set_argv(monkeypatch):
    """Return a setter that pins sys.argv for one test (auto-restored).

    detect_process_role() reads sys.argv; every test that pins argv must
    leave the real pytest argv untouched afterwards — monkeypatch.setattr
    restores the original object at teardown, so no cross-test pollution.
    """
    def _set(*argv: str) -> None:
        monkeypatch.setattr(sys, "argv", list(argv))
    return _set


# ───────────────────────────────────────────────────────────────────────────
# Scenarios 1-7: detect_process_role()
# ───────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(("argv", "expected"), [
    (("hermes", "dashboard", "--host", "0.0.0.0"), "dashboard"),   # 1
    (("hermes", "gateway", "run", "--replace"), "gateway"),         # 2
    (("hermes", "agent", "run"), "default"),                        # 3
    (("hermes",), "default"),                                       # 4
    (("/usr/bin/hermes-DASHBOARD",), "dashboard"),                  # 5
    (("hermes", "GATEWAY", "run"), "gateway"),                      # 6
    (("hermes", "dashboard", "gateway"), "dashboard"),              # 7
])
def test_detect_process_role_scenarios(set_argv, argv, expected):
    set_argv(*argv)
    assert detect_process_role() == expected


def test_detect_priority_is_dashboard_first(set_argv):
    # Scenario 7 documented priority: config.detect_process_role() checks the
    # "dashboard" substring BEFORE "gateway" — the result is deterministic
    # regardless of the token order in argv.
    set_argv("hermes", "gateway", "dashboard")
    assert detect_process_role() == "dashboard"
    set_argv("hermes", "gateway", "hermes-dashboard", "gateway")
    assert detect_process_role() == "dashboard"


def test_detect_uses_no_environment_variables(monkeypatch, set_argv):
    # Hard constraint (p2 Context): detection depends on sys.argv ONLY —
    # env vars are identical across both Hermes processes.
    set_argv("hermes", "agent", "run")
    for name in ("HERMES_ROLE", "PROCESS_ROLE", "VW_ROLE", "HERMES_MODE"):
        monkeypatch.setenv(name, "dashboard")
    assert detect_process_role() == "default"


# ───────────────────────────────────────────────────────────────────────────
# Scenarios 8-14: resolve_process_appdata_dir()
# ───────────────────────────────────────────────────────────────────────────

def test_valid_role_creates_hardened_subdir(tmp_path):                      # 8
    base = tmp_path / "base"
    resolved = resolve_process_appdata_dir(base, "gateway")
    assert resolved == base / "gateway"
    assert resolved.is_dir()
    assert _mode(resolved) == 0o700
    assert os.stat(resolved).st_uid == os.geteuid()
    # the BASE dir is hardened through the same fail-closed rules first
    assert _mode(base) == 0o700


@pytest.mark.parametrize("hostile_role", [
    "../../etc",       # 9  path traversal
    "/etc/passwd",     # 10 absolute path injection
    "unknown_role",    # 11 arbitrary string
    "dashboard/../gateway",  # smuggled traversal inside a valid-looking role
    "",                # empty role
])
def test_hostile_role_falls_back_to_default_subdir(tmp_path, hostile_role):
    base = tmp_path / "base"
    resolved = resolve_process_appdata_dir(base, hostile_role)
    assert resolved == base / "default"
    assert resolved.is_dir()
    # Nothing was created outside the base subtree, and only the fallback dir.
    assert [p.name for p in base.iterdir()] == ["default"]


def test_insecure_base_dir_propagates_filesystem_security_error(tmp_path):  # 12
    base = tmp_path / "base"
    base.mkdir(mode=0o755)  # pre-existing insecure base: never silently repaired
    with pytest.raises(FilesystemSecurityError):
        resolve_process_appdata_dir(base, "gateway")


def test_symlinked_base_dir_propagates_filesystem_security_error(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "base"
    link.symlink_to(real)
    with pytest.raises(FilesystemSecurityError):
        resolve_process_appdata_dir(link, "gateway")


def test_resolved_subdir_is_not_a_symlink(tmp_path):                        # 13
    resolved = resolve_process_appdata_dir(tmp_path / "base", "dashboard")
    assert not os.path.islink(str(resolved))
    assert stat.S_ISDIR(os.lstat(str(resolved)).st_mode)


def test_preexisting_symlink_subdir_rejected_fail_closed(tmp_path):
    # The whitelist fallback maps the hostile role to "default"; if that
    # subdir was pre-planted as a symlink, hardening must still refuse it.
    base = tmp_path / "base"
    base.mkdir(mode=0o700)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    (base / "default").symlink_to(elsewhere)
    with pytest.raises(FilesystemSecurityError):
        resolve_process_appdata_dir(base, "../../etc")


def test_subdir_mode_exactly_0700(tmp_path):                                # 14
    resolved = resolve_process_appdata_dir(tmp_path / "base", "gateway")
    assert _mode(resolved) == 0o700


def test_insecure_existing_subdir_is_never_repaired(tmp_path):
    base = tmp_path / "base"
    subdir = base / "gateway"
    subdir.mkdir(parents=True, mode=0o700)
    base.chmod(0o700)
    subdir.chmod(0o750)  # group-readable: insecure, must abort
    with pytest.raises(FilesystemSecurityError):
        resolve_process_appdata_dir(base, "gateway")
    assert _mode(subdir) == 0o750  # mode untouched — no implicit chmod


# ───────────────────────────────────────────────────────────────────────────
# Scenarios 15-20: wiring (register() end-to-end) and status_snapshot()
# ───────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def registered_plugin(fake_bw, tmp_path, hermes_home_with_secrets,
                      monkeypatch, caplog):
    """Run the real register() with VW_APPDATA_DIR pinned to a base dir.

    argv is pinned to a dashboard launch shape so role detection is
    deterministic regardless of the pytest invocation argv. PLUGIN_STATE is
    snapshot/restored to keep the global dict uncontaminated.
    """
    import vaultwarden

    base = tmp_path / ".bw-data"
    monkeypatch.setenv("VW_APPDATA_DIR", str(base))
    monkeypatch.setattr(sys, "argv",
                        ["hermes", "dashboard", "--host", "0.0.0.0"])
    ctx = RecordingCtx(settings={
        "enabled": True,
        "server_url": "https://vault.example.com",
        "client_id": "user.11111111-2222-3333-4444-555555555555",
        "bw_cli_path": fake_bw,
    })
    saved = dict(vaultwarden.PLUGIN_STATE)
    with caplog.at_level(logging.INFO, logger="hermes.plugins.vaultwarden"):
        ok = vaultwarden.register(ctx)
    try:
        assert ok is True
        yield vaultwarden, base, ctx
    finally:
        vaultwarden.PLUGIN_STATE.clear()
        vaultwarden.PLUGIN_STATE.update(saved)


def test_bwcli_receives_subdir_not_base_dir(registered_plugin):             # 15
    vaultwarden, base, _ctx = registered_plugin
    state = vaultwarden.PLUGIN_STATE
    handed_to_bwcli = Path(state["bw"].appdata_dir)
    assert handed_to_bwcli == base / "dashboard"
    assert handed_to_bwcli != base
    # the config level keeps exposing the BASE dir for introspection
    assert Path(state["config"].appdata_dir()) == base
    assert _mode(handed_to_bwcli) == 0o700


def test_plugin_state_exposes_process_role(registered_plugin):              # 16
    vaultwarden, _base, _ctx = registered_plugin
    assert vaultwarden.PLUGIN_STATE["process_role"] == "dashboard"


def test_plugin_state_exposes_resolved_appdata_dir(registered_plugin):      # 17
    vaultwarden, base, _ctx = registered_plugin
    assert Path(vaultwarden.PLUGIN_STATE["appdata_dir"]) == base / "dashboard"


def test_register_log_output_contains_no_secrets(registered_plugin, caplog):
    # Hard constraint: no secret value may appear in log output.
    for record in caplog.records:
        msg = record.getMessage()
        for forbidden in (FAKE_CLIENT_SECRET, FAKE_MASTER_PASSWORD,
                          FAKE_SESSION_KEY):
            assert forbidden not in msg


def _bare_manager(bw_cli: BwCli, plugin_config) -> AuthManager:
    """AuthManager built via __new__ (bypasses __init__ on purpose).

    Mirrors the established pattern from test_status_honesty.py so the
    getattr() fallback in status_snapshot() is exercised, not mocked.
    """
    mgr = AuthManager.__new__(AuthManager)
    mgr._bw = bw_cli
    mgr._config = plugin_config
    mgr._client_id = "user.11111111-2222-3333-4444-555555555555"
    mgr._client_secret = FAKE_CLIENT_SECRET
    mgr._master_password = FAKE_MASTER_PASSWORD
    mgr._lock = threading.RLock()
    mgr._last_sync = 0.0
    mgr._initial_sync_completed = False
    mgr._initial_sync_failed = False
    mgr._sync_warn_suppressed = False
    mgr._session_key = None
    mgr._session_created_at = None
    mgr._state = AuthState.LOGGED_IN
    return mgr


def test_status_snapshot_reports_process_role(bw_cli, plugin_config):       # 18
    mgr = AuthManager(bw_cli, plugin_config,
                      client_secret=FAKE_CLIENT_SECRET,
                      master_password=FAKE_MASTER_PASSWORD,
                      process_role="gateway")
    snap = mgr.status_snapshot()
    assert snap["process_role"] == "gateway"


def test_status_snapshot_new_built_manager_falls_back_to_argv(              # 19
        bw_cli, plugin_config, set_argv):
    set_argv("hermes", "gateway", "run")
    mgr = _bare_manager(bw_cli, plugin_config)
    assert not hasattr(mgr, "_process_role")  # __init__ was bypassed
    snap = mgr.status_snapshot()  # must not raise AttributeError
    assert snap["process_role"] == "gateway"  # from detect_process_role()


def test_status_snapshot_new_built_manager_honors_explicit_role(            # 20
        bw_cli, plugin_config, set_argv):
    set_argv("hermes", "gateway", "run")  # argv says gateway...
    mgr = _bare_manager(bw_cli, plugin_config)
    mgr._process_role = "dashboard"       # ...but the explicit role wins
    snap = mgr.status_snapshot()
    assert snap["process_role"] == "dashboard"


def test_authmanager_sanitizes_hostile_process_role(bw_cli, plugin_config):
    # AuthManager.__init__ whitelist-sanitizes the explicit role argument
    # (defense-in-depth mirroring the resolver fallback).
    mgr = AuthManager(bw_cli, plugin_config,
                      client_secret=FAKE_CLIENT_SECRET,
                      master_password=FAKE_MASTER_PASSWORD,
                      process_role="../../etc")
    assert mgr._process_role == "default"
    assert mgr.status_snapshot()["process_role"] == "default"


# ───────────────────────────────────────────────────────────────────────────
# Scenarios 21-24: multi-process isolation
# ───────────────────────────────────────────────────────────────────────────

def test_two_roles_get_separate_subdirs_and_coexist(tmp_path):              # 21+22
    base = tmp_path / "base"
    dash = resolve_process_appdata_dir(base, "dashboard")
    gate = resolve_process_appdata_dir(base, "gateway")
    assert dash != gate
    assert dash == base / "dashboard"
    assert gate == base / "gateway"
    assert dash.is_dir() and gate.is_dir()
    assert {p.name for p in base.iterdir()} == {"dashboard", "gateway"}
    assert _mode(dash) == 0o700 and _mode(gate) == 0o700


def test_no_cross_profile_session_invalidation_between_subdirs(             # 23
        tmp_path, fake_bw, plugin_config, caplog):
    base = tmp_path / "base"
    dash = resolve_process_appdata_dir(base, "dashboard")
    gate = resolve_process_appdata_dir(base, "gateway")
    cli_d, cli_g = BwCli(fake_bw, dash), BwCli(fake_bw, gate)
    mgr_d = AuthManager(cli_d, plugin_config,
                        client_secret=FAKE_CLIENT_SECRET,
                        master_password=FAKE_MASTER_PASSWORD,
                        process_role="dashboard")
    mgr_g = AuthManager(cli_g, plugin_config,
                        client_secret=FAKE_CLIENT_SECRET,
                        master_password=FAKE_MASTER_PASSWORD,
                        process_role="gateway")
    with caplog.at_level(logging.DEBUG, logger=AUTH_LOGGER), \
            caplog.at_level(logging.DEBUG, logger=BWCLI_LOGGER):
        mgr_d.ensure_authenticated()
        mgr_g.ensure_authenticated()
    assert cli_d.status()["status"] == "unlocked"
    assert cli_g.status()["status"] == "unlocked"

    # Simulate the OLD shared-profile failure mode: the profile state of the
    # dashboard process is destroyed. Under sub-dir separation the gateway
    # profile is a DIFFERENT directory and must survive untouched.
    (dash / "fake-unlocked").unlink()
    assert cli_d.status()["status"] == "locked"
    assert cli_g.status()["status"] == "unlocked"

    # No shared session key FILE: the (fake) key value exists in NO file at
    # any level below the base dir — session keys stay in memory only.
    key = mgr_g.get_session()
    assert key == FAKE_SESSION_KEY  # fixture pin: fake bw prints this value
    scanned = [f for f in base.rglob("*") if f.is_file()]
    assert scanned  # sanity: profile state files do exist under the subdirs
    for f in scanned:
        assert key.encode() not in f.read_bytes(), f
    # no secret material in any log line emitted during the flow
    for record in caplog.records:
        msg = record.getMessage()
        for forbidden in (FAKE_CLIENT_SECRET, FAKE_MASTER_PASSWORD, key):
            assert forbidden not in msg


def test_subdir_names_never_contain_session_substring(tmp_path):            # 24
    base = tmp_path / "base"
    for role in VALID_PROCESS_ROLES:
        resolve_process_appdata_dir(base, role)
    for produced in base.rglob("*"):
        assert "session" not in produced.name.lower(), produced
    # the whitelist itself carries the same security invariant
    assert all("session" not in role for role in VALID_PROCESS_ROLES)


# ───────────────────────────────────────────────────────────────────────────
# CHANGE 6: session-key persistence scan across the NEW subdir layout
# ───────────────────────────────────────────────────────────────────────────

def test_session_key_recursive_scan_covers_subdir_layout(tmp_path, fake_bw,
                                                        plugin_config):
    """Recursive variant of test_session_key[SESSION:****] for sub-dirs.

    The existing security test already walks tmp_path recursively (rglob);
    this pins the SAME invariant for a real resolve_process_appdata_dir()
    base+role tree with a full fake unlock performed INSIDE the role subdir.
    """
    base = tmp_path / ".bw-data"
    subdir = resolve_process_appdata_dir(base, "gateway")
    cli = BwCli(fake_bw, subdir)
    mgr = AuthManager(cli, plugin_config,
                      client_secret=FAKE_CLIENT_SECRET,
                      master_password=FAKE_MASTER_PASSWORD,
                      process_role="gateway")
    mgr.ensure_authenticated()
    key = mgr.get_session()
    assert key

    files = [f for f in base.rglob("*") if f.is_file()]
    assert files
    for f in files:
        assert key.encode() not in f.read_bytes(), f
    # session-key FILENAME invariant across every subdir level as well
    assert all("session" not in p.name.lower() for p in base.rglob("*"))

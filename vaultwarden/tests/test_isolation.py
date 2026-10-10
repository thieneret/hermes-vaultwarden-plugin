"""Isolation tests (plan §13): BITWARDENCLI_APPDATA_DIR, host-bw independence,
middleware chain safety across cooperating plugins, .bw-data permissions."""
from __future__ import annotations

import os
import subprocess
import stat

import pytest

from vaultwarden.auth import ensure_appdata_dir
from vaultwarden.bw_cli import BwCli
from vaultwarden.hooks import make_placeholder_resolver


def test_appdata_dir_in_every_subprocess(fake_bw, tmp_path):
    """Run EVERY supported command and assert the env var reached the child."""
    appdata = tmp_path / "bw-state"
    appdata.mkdir(mode=0o700)
    cli = BwCli(fake_bw, appdata)
    cmds = [
        ["status"], ["config", "server", "https://v.example"],
        ["config", "get", "server"],
        ["login", "--apikey", "--nointeraction"],
        ["unlock", "--passwordenv", "BW_MP", "--raw", "--nointeraction"],
        ["sync"], ["list", "items"], ["get", "item", "Postgres prod"],
        ["encode", "x"], ["generate", "16"], ["lock"],
        ["delete", "item", "id"],
    ]
    seen = []
    real_run = subprocess.run

    def spy(cmd, **kw):
        if str(cmd[0]) == fake_bw:
            assert kw["env"]["BITWARDENCLI_APPDATA_DIR"] == str(appdata), cmd
            # and nothing else from the parent env leaked in:
            assert "VW_MASTER_PASSWORD" not in kw["env"]
            assert "VW_CLIENT_SECRET" not in kw["env"]
            seen.append(tuple(cmd[1:2]))
        return real_run(cmd, **kw)

    import vaultwarden.bw_cli as mod
    orig = mod.subprocess.run
    mod.subprocess.run = spy
    try:
        for c in cmds:
            try:
                cli.run(c, env={"BW_CLIENTID": "user.x", "BW_CLIENTSECRET": "cs-secret",
                                "BW_MP": "mp-secret", "BW_SESSION": "sess"})
            except Exception:
                pass  # error mapping is tested elsewhere; here we audit envs
    finally:
        mod.subprocess.run = orig
    assert len(seen) == len(cmds)   # every single invocation was audited


def test_bw_data_permissions_700(tmp_path):
    d = ensure_appdata_dir(tmp_path / "nested" / ".bw-data")
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700


def test_plugin_state_isolated_from_host_profile(fake_bw, tmp_path):
    """A pre-existing 'host' profile must be neither read nor modified."""
    host = tmp_path / "host-profile"
    host.mkdir()
    (host / "data.json").write_text("HOST-PROFILE-DATA")
    plugin = tmp_path / ".bw-data"
    plugin.mkdir(mode=0o700)

    cli = BwCli(fake_bw, plugin)
    cli.login_apikey("user.abc", "cs-secret")
    key = cli.unlock_passwordenv("mp-secret")
    cli.list_items(key)

    assert (host / "data.json").read_text() == "HOST-PROFILE-DATA"  # untouched
    assert (plugin / "fake-logged-in").exists()                     # plugin-only state


def test_no_cross_contamination_between_two_profiles(fake_bw, tmp_path):
    a = tmp_path / "a"; b = tmp_path / "b"
    a.mkdir(); b.mkdir()
    ca, cb = BwCli(fake_bw, a), BwCli(fake_bw, b)
    ca.login_apikey("user.x", "cs-secret")
    assert ca.status()["state"] == "locked"
    assert cb.status()["state"] == "unauthenticated"  # b never saw a's login


def test_middleware_chain_safety_other_plugin_last_word(fake_bw, tmp_path, registry):
    """Simulated Hermes middleware chain: our resolver must not hijack calls
    that contain no placeholders — other plugins' rewrites survive byte-exact."""
    appdata = tmp_path / ".bw-data"; appdata.mkdir(mode=0o700)
    cli = BwCli(fake_bw, appdata)
    from vaultwarden.auth import AuthManager
    from vaultwarden.tests.conftest import make_config
    auth = AuthManager(cli, make_config(), client_secret="cs-secret",
                       master_password="mp-secret")
    auth.configure_server_if_needed(); auth.ensure_authenticated()
    ours = make_placeholder_resolver(auth, registry)

    def other_plugin_mw(tool_name, args):
        return {"args": {**args, "timeout": 45}}  # adds its own field

    # --- call with NO placeholder: both middlewares must see original args,
    # ours returns None, chain keeps other plugin's modification.
    base = {"command": "ls -la"}
    assert ours("terminal", dict(base)) is None
    step = other_plugin_mw("terminal", base)
    assert step["args"] == {"command": "ls -la", "timeout": 45}

    # --- call WITH placeholder: ours runs last and preserves other fields.
    entry = registry.create("Postgres prod", "password")
    mid = other_plugin_mw("terminal", {"command": f"echo {entry.token}"})
    final = ours("terminal", mid["args"])
    assert final["args"]["timeout"] == 45          # other plugin's edit kept
    assert "sup3r-s3cret-pg!" in final["args"]["command"]


def test_register_cleanup_removes_bootstrap_env(monkeypatch, tmp_path, fake_bw):
    """After register(): VW_* gone from os.environ; values live only in memory."""
    import vaultwarden
    monkeypatch.setenv("VW_CLIENT_SECRET", "cs-secret")
    monkeypatch.setenv("VW_MASTER_PASSWORD", "mp-secret")
    monkeypatch.setenv("BW_CLI_PATH", fake_bw)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    from vaultwarden.tests.conftest import RecordingCtx, BASE_SECTION
    ctx = RecordingCtx({"secrets": {"vaultwarden": {**BASE_SECTION, "enabled": True}}})
    ok = vaultwarden.register(ctx)
    assert ok is True
    assert "VW_CLIENT_SECRET" not in os.environ
    assert "VW_MASTER_PASSWORD" not in os.environ
    # ...but the plugin still works (values captured before cleanup):
    status = next(t for t in ctx.tools if t["name"] == "vaultwarden_status")
    res = status["handler"]({})
    assert res["status"]["auth_state"] == "unlocked"
    bwdata = tmp_path / "plugins" / "vaultwarden" / ".bw-data"
    assert bwdata.exists() and stat.S_IMODE(os.stat(bwdata).st_mode) == 0o700

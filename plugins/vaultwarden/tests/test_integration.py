"""Integration tests (plan §13): end-to-end flows against the fake bw binary —
auth flow, placeholder lifecycle through the hook pair, CRUD cycle, graceful
degradation, concurrent tool calls, SecretSource conformance."""
from __future__ import annotations

import logging
import re
import threading

import pytest

import vaultwarden
from vaultwarden.tests.conftest import BASE_SECTION, RecordingCtx

TOKEN_RE = re.compile(r"__VW_SECRET_[0-9a-f]{12}__")


def _dict_tools(raw):
    """v0.2.4: handlers return JSON strings; parse back to dicts for tests."""
    import json as _json
    def wrap(handler):
        def inner(args, **kw):
            r = handler(args, **kw)
            return _json.loads(r) if isinstance(r, str) else r
        return inner
    return {k: wrap(h) for k, h in raw.items()}


def _register_ok(monkeypatch, tmp_path, fake_bw, section_extra=None, env_extra=None):
    monkeypatch.setenv("VW_CLIENT_SECRET", "cs-secret")
    monkeypatch.setenv("VW_MASTER_PASSWORD", "mp-secret")
    monkeypatch.setenv("BW_CLI_PATH", fake_bw)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    for k, v in (env_extra or {}).items():
        monkeypatch.setenv(k, v)
    section = {**BASE_SECTION, **(section_extra or {})}
    ctx = RecordingCtx(section)
    ok = vaultwarden.register(ctx)
    return ok, ctx


# ------------------------------------------------------------- registration
def test_register_full_flow_and_tool_count(monkeypatch, tmp_path, fake_bw):
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    assert ok is True
    # v0.3.7 (VWP-12): 8 base tools + 4 SSH key management tools = 12
    # (vaultwarden_generate_password removed; generation folded into
    # vaultwarden_store / vaultwarden_update via generate=true).
    assert len(ctx.tools) == 12
    names = {t["name"] for t in ctx.tools}
    assert names == {
        "vaultwarden_status", "vaultwarden_sync", "vaultwarden_list",
        "vaultwarden_search", "vaultwarden_get_secret_ref", "vaultwarden_store",
        "vaultwarden_update", "vaultwarden_delete",
        # v0.2.8: SSH key management
        "vaultwarden_store_ssh", "vaultwarden_update_ssh",
        "vaultwarden_delete_ssh", "vaultwarden_use_ssh"}
    assert all(t["toolset"] == "vaultwarden" for t in ctx.tools)
    assert all(t["check_fn"]() for t in ctx.tools)
    assert [k for k, _ in ctx.middleware] == ["tool_execution"]
    hook_kinds = [k for k, _ in ctx.hooks]
    assert hook_kinds == ["post_tool_call", "on_session_end"]
    assert ctx.secret_sources == []          # disabled by default


def test_register_disabled_returns_false(monkeypatch, tmp_path, fake_bw):
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw, {"enabled": False})
    assert ok is False and ctx.tools == []


def test_graceful_degradation_missing_bw(monkeypatch, tmp_path):
    """No bw binary anywhere -> register() returns False, agent continues, no crash."""
    monkeypatch.setenv("VW_CLIENT_SECRET", "cs-secret")
    monkeypatch.setenv("VW_MASTER_PASSWORD", "mp-secret")
    monkeypatch.delenv("BW_CLI_PATH", raising=False)
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    ctx = RecordingCtx({**BASE_SECTION, "enabled": True})
    assert vaultwarden.register(ctx) is False
    assert ctx.tools == []


def test_graceful_degradation_missing_env(monkeypatch, tmp_path, fake_bw):
    monkeypatch.delenv("VW_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("VW_MASTER_PASSWORD", raising=False)
    monkeypatch.setenv("BW_CLI_PATH", fake_bw)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    ctx = RecordingCtx({**BASE_SECTION, "enabled": True})
    assert vaultwarden.register(ctx) is False   # logged, not raised


def test_startup_secret_injection_registers_source(monkeypatch, tmp_path, fake_bw):
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw,
                           {"allow_startup_secret_injection": True})
    assert ok and len(ctx.secret_sources) == 1
    src = ctx.secret_sources[0]
    assert src.name() == "vaultwarden"
    secrets = src.get_secrets()      # no mappings configured -> empty, fail-safe
    assert isinstance(secrets, dict)


# ------------------------------------------------- placeholder e2e via hooks
def test_placeholder_e2e_llm_style_flow(monkeypatch, tmp_path, fake_bw):
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    mw = dict(ctx.middleware)["tool_execution"]
    post = dict(ctx.hooks)["post_tool_call"]

    # LLM asks for a reference, never the secret:
    ref = tools["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001", "field": "password"})
    token = ref["placeholder"]
    assert token.startswith("$")               # VWP-04: $ prefix (user-facing)
    assert TOKEN_RE.match(token[1:])           # registry form stays bare
    assert "sup3r-s3cret-pg!" not in str(ref)

    seen: list[str] = []

    def next_call(a):
        seen.append(a["command"])
        return {"output": "ran"}

    # LLM composes a terminal command with the DOUBLE-QUOTED placeholder:
    llm_args = {"command": f"PGPASSWORD=\"{token}\" psql -h db.internal -U dbadmin -c 'SELECT 1'"}
    mw("terminal", dict(llm_args), dict(llm_args), next_call, task_id="task-1")
    executed = seen[0]
    assert token not in executed               # reference replaced...
    assert "$(<" in executed                   # ...by a file substitution
    assert "sup3r-s3cret-pg!" not in executed  # secret NEVER in the command

    # execution result may echo the secret -> post hook redacts it in place:
    result = {"output": "psql ran with sup3r-s3cret-pg! visible"}
    returned = post("terminal", {"command": executed}, result, task_id="task-1")
    observed = returned if isinstance(returned, dict) else result
    assert "sup3r-s3cret-pg!" not in observed["output"]

    # replay of the same placeholder is left verbatim (fail-safe $ expansion):
    again_seen: list[str] = []
    mw("terminal", {"command": f"echo \"{token}\""}, None,
       lambda a: again_seen.append(a["command"]))
    assert token in again_seen[0]
    assert "$(<" not in again_seen[0]
    assert "sup3r-s3cret-pg!" not in again_seen[0]


def test_crud_cycle_integration(monkeypatch, tmp_path, fake_bw):
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw, {"allow_write": True})
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    created = tools["vaultwarden_store"]({
        "type": "login", "name": "Integration svc", "username": "svc",
        "password": "pw-with-@and$chars", "uri": "https://svc.local",
        "custom_fields": [{"name": "region", "value": "eu-west-1", "field_type": 0}]})
    assert created["created"] and created["item"]["name"] == "Integration svc"
    upd = tools["vaultwarden_update"](
        {"item_id": created["id"], "notes": "rotated weekly"})
    assert upd["updated"]
    lst = tools["vaultwarden_list"]({})
    assert lst["total"] >= 1
    dele = tools["vaultwarden_delete"]({"item_id": created["id"], "confirm": True})
    assert dele["deleted"] and dele["permanent"] is False


def test_session_expiry_recovery_integration(monkeypatch, tmp_path, fake_bw):
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw,
                           {"session_timeout_seconds": 1})
    auth = vaultwarden.PLUGIN_STATE["auth"]
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    first = tools["vaultwarden_list"]({})
    assert "error" not in first
    auth._session_created_at -= 10            # simulate expiry
    second = tools["vaultwarden_list"]({})    # auto re-unlock, transparent
    assert "error" not in second and second["total"] == first["total"]


def test_concurrent_tool_calls(monkeypatch, tmp_path, fake_bw):
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    errors_seen: list[str] = []

    def worker(i):
        for _ in range(5):
            r = tools["vaultwarden_status"]({})
            if "error" in r:
                errors_seen.append(str(r))
            r2 = tools["vaultwarden_get_secret_ref"](
                {"item_id": "Postgres prod", "field": "password"})
            if "error" in r2 and r2["error_code"] != "PLACEHOLDER_ERROR":
                errors_seen.append(str(r2))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors_seen == []
    registry = vaultwarden.PLUGIN_STATE["registry"]
    assert len(registry.snapshot()) <= registry._max   # cap respected under load


def test_on_session_end_hook_locks_vault(monkeypatch, tmp_path, fake_bw):
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    auth = vaultwarden.PLUGIN_STATE["auth"]
    appdata = vaultwarden.PLUGIN_STATE["config"].appdata_dir()
    # v0.1.9 lazy auth: authenticate first so there IS a live session to lock.
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    assert tools["vaultwarden_list"]({})["total"] == 3
    assert (appdata / "fake-logged-in").exists()
    end = dict(ctx.hooks)["on_session_end"]
    end()
    assert auth.session_key is None
    assert not (appdata / "fake-unlocked").exists()    # vault locked on disk too
    assert (appdata / "fake-logged-in").exists()       # login kept, .bw-data retained


def test_logs_never_contain_bootstrap_secrets(monkeypatch, tmp_path, fake_bw, caplog):
    caplog.set_level(logging.DEBUG)
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    tools["vaultwarden_list"]({})
    tools["vaultwarden_get_secret_ref"]({"item_id": "Postgres prod", "field": "password"})
    mw = dict(ctx.middleware)["tool_execution"]
    tok = [t for t in __import__("re").findall(
        r"__VW_SECRET_[0-9a-f]{12}__",
        str(vaultwarden.PLUGIN_STATE["registry"].snapshot()))][0]
    mw("terminal", {"command": f"run --pw \"${tok}\""}, None, lambda a: "ran")
    blob = " ".join(r.getMessage() for r in caplog.records) + caplog.text
    assert "cs-secret" not in blob
    assert "mp-secret" not in blob
    key = vaultwarden.PLUGIN_STATE["auth"].session_key
    assert key not in blob


# ------------------------------------------------------- v0.1.9 lazy auth flow
def test_register_defers_auth_and_completes_fast(monkeypatch, tmp_path, fake_bw):
    """register() must NOT block on authentication (Hermes 10s load timeout).

    The fake bw gets a deliberate 3s delay per invocation; if register()
    still ran status/login/unlock eagerly the total would blow well past
    5s. With v0.1.9 lazy auth it finishes almost instantly instead.
    """
    import time
    slow_bw = tmp_path / "slow-bw"
    slow_bw.write_text("#!/usr/bin/env python3\n"
                       "import os, sys, time\n"
                       "time.sleep(3)\n"
                       "os.execv(%r, %r + sys.argv[1:])\n" % (fake_bw, [fake_bw]))
    slow_bw.chmod(0o755)
    ok, ctx = _register_ok(monkeypatch, tmp_path, str(slow_bw))
    assert ok is True
    auth = vaultwarden.PLUGIN_STATE["auth"]
    # Auth was deferred: nothing has been authenticated yet...
    assert auth.state.value == "configured"
    assert auth.session_key is None
    # ...and registration itself stayed far below the load timeout.
    start = time.monotonic()
    ok2, _ = _register_ok(monkeypatch, tmp_path, fake_bw)
    assert ok2 is True and (time.monotonic() - start) < 5.0


def test_first_tool_call_triggers_lazy_auth(monkeypatch, tmp_path, fake_bw):
    """check_fn()/first tool use drives the full Case A bootstrap."""
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    assert ok is True
    auth = vaultwarden.PLUGIN_STATE["auth"]
    appdata = vaultwarden.PLUGIN_STATE["config"].appdata_dir()
    # Deferred: no server config / login happened during register().
    assert not (appdata / "server.txt").exists()
    assert not (appdata / "fake-logged-in").exists()

    check = next(t for t in ctx.tools if t["name"] == "vaultwarden_status")["check_fn"]
    assert check() is True                      # triggers ensure_authenticated()
    assert auth.state.value == "unlocked"
    assert (appdata / "server.txt").read_text() == "https://vault.example.com"
    assert (appdata / "fake-logged-in").exists()

    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    res = tools["vaultwarden_status"]({})
    assert res["status"]["auth_state"] == "unlocked"


def test_restart_reuses_session_without_reconfig_or_logout(monkeypatch, tmp_path, fake_bw):
    """Case C across plugin restarts: correct server+account already logged
    in -> NO 'bw config server', NO logout, NO login — just unlock."""
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    assert ok is True
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    assert tools["vaultwarden_list"]({})["total"] == 3   # lazy auth completes

    cli = vaultwarden.PLUGIN_STATE["bw"]
    appdata = vaultwarden.PLUGIN_STATE["config"].appdata_dir()
    # Restart realism: the fake bw only persists login/unlock markers; a real
    # bw keeps its server URL in data.json. Seed it so the fresh manager can
    # recognise the correct server from `bw status` alone.
    (appdata / "server.txt").write_text("https://vault.example.com")

    calls = []
    real_run = cli.run

    def spy(args, **kw):
        calls.append(list(args))
        return real_run(args, **kw)
    cli.run = spy

    # Simulate a fresh process against the SAME isolated profile: new
    # AuthManager, same config, same appdata dir (session already unlocked).
    # Drop the in-memory session of the old manager so the profile state —
    # not remembered memory — drives the decision (true restart semantics).
    vaultwarden.PLUGIN_STATE["auth"]._session_key = None   # noqa: SLF001
    from vaultwarden.auth import AuthManager
    cfg = vaultwarden.PLUGIN_STATE["config"]
    mgr2 = AuthManager(cli, cfg, client_secret="cs-secret", master_password="mp-secret")
    mgr2.ensure_authenticated()

    cmds = [" ".join(c) for c in calls]
    assert not any(c.startswith("config server") for c in cmds), cmds
    assert "logout" not in cmds, cmds
    assert not any(c.startswith("login") for c in cmds), cmds
    assert any(c.startswith("unlock") for c in cmds), cmds   # adopt via unlock
    assert mgr2.state.value == "unlocked"


def test_wrong_account_triggers_logout_then_reauth(monkeypatch, tmp_path, fake_bw):
    """Case B: profile logged in with a DIFFERENT userId -> logout first,
    then config + login + unlock (no 'Logout required' failure)."""
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    assert ok is True
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    tools["vaultwarden_list"]({})                # session up as user 1111...

    cli = vaultwarden.PLUGIN_STATE["bw"]
    appdata = vaultwarden.PLUGIN_STATE["config"].appdata_dir()
    # Stale foreign account on the same profile (e.g. manual `bw login`).
    (appdata / "fake-user-id").write_text("deadbeef-0000-0000-0000-000000000000")

    order = []
    real_run = cli.run

    def spy(args, **kw):
        order.append(str(args[0]) if args else "")
        if args[:2] == ["config", "server"]:
            # regression guard: this only ever runs after a logout now
            assert not (appdata / "fake-logged-in").exists(), \
                "Logout required before server config update!"
        return real_run(args, **kw)
    cli.run = spy

    from vaultwarden.auth import AuthManager
    cfg = vaultwarden.PLUGIN_STATE["config"]
    mgr2 = AuthManager(cli, cfg, client_secret="cs-secret", master_password="mp-secret")
    mgr2.ensure_authenticated()

    assert "logout" in order, order
    assert "config" in order, order
    assert "login" in order, order
    assert "unlock" in order, order
    assert order.index("logout") < order.index("config") < order.index("login")
    assert mgr2.state.value == "unlocked"
    # re-login restored OUR account id
    assert (appdata / "fake-user-id").read_text() == "11111111-2222-3333-4444-555555555555"


def test_wrong_server_triggers_logout_then_reconfig(monkeypatch, tmp_path, fake_bw):
    """Case B (server mismatch): stale session on another server URL."""
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    assert ok is True
    vaultwarden.PLUGIN_STATE["auth"].ensure_authenticated()  # idempotent fast path

    appdata = vaultwarden.PLUGIN_STATE["config"].appdata_dir()
    (appdata / "server.txt").write_text("https://old.vault.example.net")

    cli = vaultwarden.PLUGIN_STATE["bw"]
    order = []
    real_run = cli.run

    def spy(args, **kw):
        order.append(str(args[0]) if args else "")
        return real_run(args, **kw)
    cli.run = spy

    from vaultwarden.auth import AuthManager
    cfg = vaultwarden.PLUGIN_STATE["config"]
    mgr2 = AuthManager(cli, cfg, client_secret="cs-secret", master_password="mp-secret")
    mgr2.ensure_authenticated()

    assert "logout" in order and "config" in order and "login" in order
    assert order.index("logout") < order.index("config")
    assert (appdata / "server.txt").read_text() == "https://vault.example.com"
    assert mgr2.state.value == "unlocked"


def test_plugin_yaml_version_matches_pyproject():
    """plugin.yaml version must match pyproject.toml version."""
    import re
    from pathlib import Path

    import vaultwarden

    pkg_dir = Path(vaultwarden.__file__).resolve().parent

    # Find plugin.yaml (may be in package dir or one level up)
    plugin_yaml = pkg_dir / "plugin.yaml"
    if not plugin_yaml.exists():
        plugin_yaml = pkg_dir.parent / "plugin.yaml"
    assert plugin_yaml.exists(), "plugin.yaml not found"
    plugin_content = plugin_yaml.read_text(encoding="utf-8")
    plugin_version = re.search(r"^version:\s*([^\s]+)", plugin_content, re.M)
    assert plugin_version, "version: field not found in plugin.yaml"

    # Find pyproject.toml at the repo root. Repo reorganization (v0.4.4
    # step 1) moved the plugin from vaultwarden/ to plugins/vaultwarden/,
    # so a fixed parent depth is no longer reliable — walk up from the
    # package dir until a pyproject.toml shows up.
    pyproject = next(
        (c for c in (pkg_dir.parent, *pkg_dir.parents)
         if (c / "pyproject.toml").exists()),
        None,
    )
    assert pyproject is not None, "pyproject.toml not found in any parent dir"
    pyproject = pyproject / "pyproject.toml"
    pyproject_content = pyproject.read_text(encoding="utf-8")
    pyproject_version = re.search(r'^version\s*=\s*"([^"]+)"', pyproject_content, re.M)
    assert pyproject_version, "version field not found in pyproject.toml"

    assert plugin_version.group(1) == pyproject_version.group(1), (
        f"Version mismatch: plugin.yaml={plugin_version.group(1)}, "
        f"pyproject.toml={pyproject_version.group(1)}")


# ---------------------------------------------------------------------------
# VWP-03 (v0.4.3): middleware registration is FAIL-CLOSED
# ---------------------------------------------------------------------------


def test_register_raises_when_middleware_registration_fails(monkeypatch, tmp_path, fake_bw):
    """If ctx.register_middleware raises, register() must propagate the
    exception — the plugin MUST NOT load without placeholder injection."""
    ok, _ = _register_ok(monkeypatch, tmp_path, fake_bw)   # sanity: works normally
    assert ok is True

    def _boom(kind, fn):
        raise RuntimeError("Hermes API mismatch")

    monkeypatch.setenv("VW_CLIENT_SECRET", "cs-secret")
    monkeypatch.setenv("VW_MASTER_PASSWORD", "mp-secret")
    monkeypatch.setenv("BW_CLI_PATH", fake_bw)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    ctx = RecordingCtx({**BASE_SECTION, "enabled": True})
    ctx.register_middleware = _boom
    with pytest.raises(RuntimeError, match="Hermes API mismatch"):
        vaultwarden.register(ctx)


def test_register_raises_when_middleware_registration_returns_false(monkeypatch, tmp_path, fake_bw):
    """A False return (instead of an exception) must also abort loading."""
    monkeypatch.setenv("VW_CLIENT_SECRET", "cs-secret")
    monkeypatch.setenv("VW_MASTER_PASSWORD", "mp-secret")
    monkeypatch.setenv("BW_CLI_PATH", fake_bw)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    ctx = RecordingCtx({**BASE_SECTION, "enabled": True})
    ctx.register_middleware = lambda kind, fn: False
    with pytest.raises(RuntimeError, match="fail-closed"):
        vaultwarden.register(ctx)


def test_register_succeeds_when_middleware_registration_works(monkeypatch, tmp_path, fake_bw):
    """Happy path: successful registration loads the plugin with middleware."""
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    assert ok is True
    assert [k for k, _ in ctx.middleware] == ["tool_execution"]

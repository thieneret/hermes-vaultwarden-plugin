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


def _write_secrets_yaml(home, client_secret="cs-secret", master_password="mp-secret"):
    """v0.5.0 (BREAKING): bootstrap secrets come from a plugin-private
    secrets.yaml (chmod 600), never from .env / OS environment."""
    plugdir = home / "plugins" / "vaultwarden"
    plugdir.mkdir(parents=True, exist_ok=True)
    f = plugdir / "secrets.yaml"
    f.write_text(f"client_secret: {client_secret}\nmaster_password: {master_password}\n")
    f.chmod(0o600)
    return f


def _register_ok(monkeypatch, tmp_path, fake_bw, section_extra=None, env_extra=None):
    # v0.5.0: no VW_* env vars any more — write secrets.yaml instead.
    _write_secrets_yaml(tmp_path)
    # VWP-01 (v0.4.7 BREAKING): BW_CLI_PATH env override removed — the path
    # must be pinned via the bw_cli_path setting in config.yaml.
    monkeypatch.delenv("BW_CLI_PATH", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("TERMINAL_ENV", "docker")  # sandboxed backend -> INFO
    for k, v in (env_extra or {}).items():
        monkeypatch.setenv(k, v)
    section = {**BASE_SECTION, "bw_cli_path": fake_bw, **(section_extra or {})}
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
    # SEC-01 (v0.5.4): transform_tool_result is the authoritative redaction
    # hook and must be registered FIRST; post_tool_call stays observer-only.
    assert hook_kinds == ["transform_tool_result", "post_tool_call",
                          "on_session_end"]
    assert ctx.secret_sources == []          # disabled by default


def test_register_disabled_returns_false(monkeypatch, tmp_path, fake_bw):
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw, {"enabled": False})
    assert ok is False and ctx.tools == []


def test_graceful_degradation_missing_bw(monkeypatch, tmp_path):
    """No pinned bw_cli_path -> register() returns False, agent continues, no crash.

    VWP-01 (v0.4.7 BREAKING): even with a valid 'bw' on PATH and BW_CLI_PATH
    set, the plugin must NOT discover it — config.yaml is the only source.
    """
    _write_secrets_yaml(tmp_path)
    planted = tmp_path / "bw"
    planted.write_text("#!/bin/sh\necho ok\n")
    planted.chmod(0o755)
    monkeypatch.setenv("BW_CLI_PATH", str(planted))
    monkeypatch.setenv("PATH", str(tmp_path))
    ctx = RecordingCtx({**BASE_SECTION, "enabled": True})
    assert vaultwarden.register(ctx) is False
    assert ctx.tools == []


def test_register_fails_closed_invalid_bw_cli_path(monkeypatch, tmp_path):
    """Configured but invalid bw_cli_path -> register() returns False."""
    _write_secrets_yaml(tmp_path)
    monkeypatch.delenv("BW_CLI_PATH", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    ctx = RecordingCtx({**BASE_SECTION, "enabled": True,
                        "bw_cli_path": str(tmp_path / "no-such-bw")})
    assert vaultwarden.register(ctx) is False
    assert ctx.tools == []


def test_bw_cli_path_env_no_longer_overrides_config(monkeypatch):
    """VWP-01 BREAKING: BW_CLI_PATH env must NOT override/replace config.yaml."""
    from vaultwarden.config import load_config
    from vaultwarden.tests.conftest import SettingsContext

    monkeypatch.setenv("BW_CLI_PATH", "/from/env/bw")

    # Config value wins; the env snapshot (which contains BW_CLI_PATH) is ignored.
    cfg = load_config(SettingsContext({**BASE_SECTION,
                                       "bw_cli_path": "/from/config/bw"}),
                      env={"BW_CLI_PATH": "/from/env/bw"})
    assert cfg.bw_cli_path == "/from/config/bw"      # env ignored

    # Empty config + BW_CLI_PATH set -> still empty -> register() fails closed.
    cfg2 = load_config(SettingsContext(BASE_SECTION),
                       env={"BW_CLI_PATH": "/from/env/bw"})
    assert cfg2.bw_cli_path == ""


def test_graceful_degradation_missing_secrets_yaml(monkeypatch, tmp_path, fake_bw):
    """v0.5.0: no secrets.yaml under HERMES_HOME -> register() returns False."""
    monkeypatch.delenv("VW_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("VW_MASTER_PASSWORD", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    ctx = RecordingCtx({**BASE_SECTION, "enabled": True,
                           "bw_cli_path": fake_bw})
    assert vaultwarden.register(ctx) is False   # logged, not raised


def test_startup_secret_injection_registers_source(monkeypatch, tmp_path, fake_bw):
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw,
                           {"allow_startup_secret_injection": True})
    assert ok and len(ctx.secret_sources) == 1
    src = ctx.secret_sources[0]
    assert src.name() == "vaultwarden"
    secrets = src.get_secrets()      # no mappings configured -> empty, fail-safe
    assert isinstance(secrets, dict)


def test_startup_secret_injection_with_mappings(monkeypatch, tmp_path, fake_bw):
    """startup_injections mappings -> get_secrets() returns the configured values.

    v0.5.3: mapping validation + INFO logging + redactor registration are
    covered by tests/test_secret_source.py; this test proves the end-to-end
    wiring from config.section["startup_injections"] through register().
    """
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw, {
        "allow_startup_secret_injection": True,
        "startup_injections": [
            {"item_id": "aaaa1111-0000-0000-0000-000000000001",
             "field": "password", "env": "DB_PASS"},
            {"field": "password"},                       # missing item_id -> skipped
            "not-a-dict",                                # wrong type -> skipped
        ],
    })
    assert ok and len(ctx.secret_sources) == 1
    src = ctx.secret_sources[0]
    # v0.5.3 validation: only the one valid mapping survives __init__
    assert len(src._mappings) == 1
    secrets = src.get_secrets()
    assert secrets == {"DB_PASS": "sup3r-s3cret-pg!"}


# ------------------------------------------------- placeholder e2e via hooks
def test_placeholder_e2e_llm_style_flow(monkeypatch, tmp_path, fake_bw):
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    mw = dict(ctx.middleware)["tool_execution"]
    post = dict(ctx.hooks)["post_tool_call"]
    # SEC-01 (v0.5.4): the AUTHORITATIVE redaction hook — its return value is
    # what reaches the model. post_tool_call is observer-only now.
    transform = dict(ctx.hooks)["transform_tool_result"]

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

    # execution result may echo the secret -> SEC-01 (v0.5.4): the
    # authoritative transform_tool_result hook scrubs it BEFORE the model
    # sees it. post_tool_call is observer-only and must NOT mutate results.
    result = {"output": "psql ran with sup3r-s3cret-pg! visible"}
    observed = transform("terminal", result, task_id="task-1")
    assert "sup3r-s3cret-pg!" not in observed["output"]
    assert "[REDACTED]" in observed["output"]
    post("terminal", {"command": executed}, observed, task_id="task-1")

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

    _write_secrets_yaml(tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    ctx = RecordingCtx({**BASE_SECTION, "enabled": True,
                           "bw_cli_path": fake_bw})
    ctx.register_middleware = _boom
    with pytest.raises(RuntimeError, match="Hermes API mismatch"):
        vaultwarden.register(ctx)


def test_register_raises_when_middleware_registration_returns_false(monkeypatch, tmp_path, fake_bw):
    """A False return (instead of an exception) must also abort loading."""
    _write_secrets_yaml(tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    # SEC-03 (v0.5.5): pin a sandboxed backend so the local-backend policy
    # cannot short-circuit register() before the middleware path is reached.
    monkeypatch.setenv("TERMINAL_ENV", "docker")
    ctx = RecordingCtx({**BASE_SECTION, "enabled": True,
                           "bw_cli_path": fake_bw})
    ctx.register_middleware = lambda kind, fn: False
    with pytest.raises(RuntimeError, match="fail-closed"):
        vaultwarden.register(ctx)


def test_register_succeeds_when_middleware_registration_works(monkeypatch, tmp_path, fake_bw):
    """Happy path: successful registration loads the plugin with middleware."""
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    assert ok is True
    assert [k for k, _ in ctx.middleware] == ["tool_execution"]


# ===========================================================================
# AUD-02 (phase 2): execution-scoped secret retention through the FULL
# middleware -> transform_tool_result lifecycle. Assertions use the direct
# redactor observability API (active_secret_count / has_secret) — never
# process-memory measurements, never secret values in logs.
# ===========================================================================

import re as _re_mod  # noqa: E402
import threading  # noqa: E402

from vaultwarden.hooks import (  # noqa: E402
    make_placeholder_resolver,
    make_result_redactor,
)
from vaultwarden.security import RedactingFilter, get_redacting_filter  # noqa: E402


def _isolated_filter(monkeypatch) -> RedactingFilter:
    """Swap the shared filter for a fresh instance (restored by monkeypatch)."""
    filt = RedactingFilter()
    monkeypatch.setattr("vaultwarden.security._shared_filter", filt,
                        raising=True)
    monkeypatch.setattr("vaultwarden.hooks.get_redacting_filter",
                        lambda: filt, raising=True)
    return filt


def _seed_item_password(monkeypatch, item_id: str, value: str) -> None:
    """Make fake-bw item *item_id* carry *value* as its login password."""
    from vaultwarden.auth import AuthManager
    real_get_item = AuthManager.get_item

    def patched_get_item(self, query: str) -> dict:
        item = dict(real_get_item(self, query))
        if item.get("id") == item_id:
            login = dict(item.get("login") or {})
            login["password"] = value
            item["login"] = login
        return item

    monkeypatch.setattr(AuthManager, "get_item", patched_get_item)


PG_ID = "aaaa1111-0000-0000-0000-000000000001"   # "Postgres prod"
GF_ID = "aaaa1111-0000-0000-0000-000000000002"   # "Grafana" (conftest vault)

#: ``$(< /abs/path)`` shell substitution produced by the middleware rewrite.
_AUD02_SUBST_RE = _re_mod.compile(r"\$\(<\s*(/\S+)\)")


def _run_execution(middleware, transform, registry, item_id, secret, task_id,
                   echo_plaintext=True):
    """One full pipeline pass; returns (transformed_output, seen_command)."""
    entry = registry.create(item_id, "password")
    cmd_ref = f"${entry.token}"

    def terminal(args: dict) -> dict:
        m = _AUD02_SUBST_RE.search(args["command"])
        assert m is not None, f"no $(< path) substitution: {args['command']!r}"
        path = m.group(1)
        with open(path, encoding="utf-8") as fh:
            raw = fh.read() + "\n"
        return {"output": raw} if echo_plaintext else {"output": "ok\n"}

    result = middleware("terminal", {"command": f'cat "{cmd_ref}"'}, None,
                        terminal, task_id=task_id)
    transformed = transform("terminal", result, task_id=task_id)
    return transformed["output"]


def test_single_execution_returns_redactor_to_baseline(auth_manager, registry,
                                                       plugin_config,
                                                       monkeypatch, tmp_path):
    filt = _isolated_filter(monkeypatch)
    xdg = tmp_path / "xdg"; xdg.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    secret = "AUD02-ONE-EXEC-SECRET"
    _seed_item_password(monkeypatch, PG_ID, secret)
    mw = make_placeholder_resolver(auth_manager, registry, plugin_config)
    tf = make_result_redactor(auth_manager, registry, plugin_config)

    baseline = filt.active_secret_count()
    out = _run_execution(mw, tf, registry, PG_ID, secret, "aud02-single")
    assert out == "[REDACTED]\n"                       # SEC-01 unchanged
    assert filt.active_secret_count() == baseline      # released after scope


def test_multiple_secrets_all_released_after_execution(auth_manager, registry,
                                                       plugin_config,
                                                       monkeypatch, tmp_path):
    filt = _isolated_filter(monkeypatch)
    xdg = tmp_path / "xdg"; xdg.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    s1, s2 = "AUD02-MULTI-SECRET-A", "AUD02-MULTI-SECRET-B"
    _seed_item_password(monkeypatch, PG_ID, s1)
    _seed_item_password(monkeypatch, GF_ID, s2)
    mw = make_placeholder_resolver(auth_manager, registry, plugin_config)
    tf = make_result_redactor(auth_manager, registry, plugin_config)

    baseline = filt.active_secret_count()
    e1 = registry.create(PG_ID, "password")
    e2 = registry.create(GF_ID, "password")

    def terminal(args: dict) -> dict:
        outs = []
        for p in _AUD02_SUBST_RE.findall(args["command"]):
            with open(p, encoding="utf-8") as fh:
                outs.append(fh.read())
        return {"output": "".join(outs)}

    # Assert the retention DURING the execution (inside next_call): AUD-02
    # phase 2 releases execution-scoped secrets when the middleware frame's
    # scope closes, so post-return has_secret() checks are no longer valid.
    mid_seen: dict[str, bool] = {}

    def terminal_retained(args: dict) -> dict:
        out = terminal(args)
        mid_seen["both"] = filt.has_secret(s1) and filt.has_secret(s2)
        return out

    result = mw("terminal",
                {"command": f'cat "{e1.token}" "{e2.token}"'},
                None, terminal_retained, task_id="aud02-multi")
    # Both plaintexts retained DURING the execution:
    assert mid_seen["both"], "secrets not retained while execution active"
    transformed = tf("terminal", result, task_id="aud02-multi")
    assert s1 not in transformed["output"]
    assert s2 not in transformed["output"]
    assert filt.active_secret_count() == baseline      # all released after


def test_two_executions_different_scopes_release_independently(
        auth_manager, registry, plugin_config, monkeypatch, tmp_path):
    filt = _isolated_filter(monkeypatch)
    xdg = tmp_path / "xdg"; xdg.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    s1, s2 = "AUD02-DIFF-SECRET-A", "AUD02-DIFF-SECRET-B"
    _seed_item_password(monkeypatch, PG_ID, s1)
    _seed_item_password(monkeypatch, GF_ID, s2)
    mw = make_placeholder_resolver(auth_manager, registry, plugin_config)
    tf = make_result_redactor(auth_manager, registry, plugin_config)
    baseline = filt.active_secret_count()

    _run_execution(mw, tf, registry, PG_ID, s1, "aud02-diff-1")
    _run_execution(mw, tf, registry, GF_ID, s2, "aud02-diff-2")
    # Each scope released ONLY its own secret; both gone, back to baseline.
    assert not filt.has_secret(s1) and not filt.has_secret(s2)
    assert filt.active_secret_count() == baseline


def test_overlapping_executions_same_secret_not_removed_prematurely(
        auth_manager, registry, plugin_config, monkeypatch, tmp_path):
    """Two concurrent executions inject the SAME plaintext; the first scope
    closing must not drop the secret while the second still holds it."""
    filt = _isolated_filter(monkeypatch)
    xdg = tmp_path / "xdg"; xdg.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    secret = "AUD02-OVERLAP-SHARED-SECRET"
    _seed_item_password(monkeypatch, PG_ID, secret)
    mw = make_placeholder_resolver(auth_manager, registry, plugin_config)

    barrier = threading.Barrier(2, timeout=10)
    outcomes: dict[str, bool] = {}

    def terminal(args: dict) -> dict:
        # While ANY execution is in flight, the shared secret must be active.
        active_mid = filt.has_secret(secret)
        barrier.wait()                     # force overlap of both scopes
        m = _AUD02_SUBST_RE.search(args["command"])
        assert m is not None, f"no $(< path) substitution: {args['command']!r}"
        path = m.group(1)
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
        outcomes[f"mid_{threading.get_ident()}"] = active_mid
        assert raw == secret               # injection itself works
        return {"output": "done\n"}

    # Pre-create tokens here (registry is thread-safe); each execution gets
    # its own single-use placeholder but resolves the SAME vault secret.
    tokens = [registry.create(PG_ID, "password").token for _ in range(2)]
    threads = [
        threading.Thread(target=mw,
                         args=("terminal", {"command": f'cat "${t}"'},
                               None, terminal),
                         kwargs={"task_id": f"aud02-overlap-{i}"})
        for i, t in enumerate(tokens)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    assert not any(t.is_alive() for t in threads)
    # Both executions observed the secret active mid-flight...
    assert len(outcomes) == 2 and all(outcomes.values())
    # ...and after BOTH scopes closed, refcount hit zero exactly.
    assert not filt.has_secret(secret)


def test_three_overlapping_executions_refcount_tracks_holders_exactly(
        auth_manager, registry, plugin_config, monkeypatch, tmp_path):
    filt = _isolated_filter(monkeypatch)
    xdg = tmp_path / "xdg"; xdg.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    secret = "AUD02-THREE-HOLDER-SECRET"
    _seed_item_password(monkeypatch, PG_ID, secret)
    mw = make_placeholder_resolver(auth_manager, registry, plugin_config)

    order: list[str] = []
    lock = threading.Lock()
    ready = threading.Barrier(3, timeout=10)

    def terminal(args: dict) -> dict:
        tid = threading.get_ident()
        with lock:
            order.append(f"in-{tid}")
        ready.wait()                      # all three scopes are live here
        m = _AUD02_SUBST_RE.search(args["command"])
        assert m is not None, f"no $(< path) substitution: {args['command']!r}"
        path = m.group(1)
        with open(path, encoding="utf-8") as fh:
            assert fh.read() == secret
        return {"output": "ok\n"}

    baseline = filt.active_secret_count()
    tokens = [registry.create(PG_ID, "password").token for _ in range(3)]
    threads = [threading.Thread(target=mw,
                                 args=("terminal", {"command": f'cat "${t}"'},
                                       None, terminal),
                                 kwargs={"task_id": f"aud02-three-{i}"})
               for i, t in enumerate(tokens)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    assert not any(t.is_alive() for t in threads)
    assert len(order) == 3                # every holder entered its tool call
    # The barrier guarantees all three executions overlapped while the
    # shared secret was retained by exactly three holders; refcounting must
    # have dropped it to zero only after ALL scopes closed — back to
    # baseline, no negative counts, no premature removal.
    assert filt.active_secret_count() == baseline
    assert not filt.has_secret(secret)


def test_exception_during_execution_still_releases_secrets(
        auth_manager, registry, plugin_config, monkeypatch, tmp_path):
    filt = _isolated_filter(monkeypatch)
    xdg = tmp_path / "xdg"; xdg.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    secret = "AUD02-EXCEPTION-SECRET"
    _seed_item_password(monkeypatch, PG_ID, secret)
    mw = make_placeholder_resolver(auth_manager, registry, plugin_config)
    baseline = filt.active_secret_count()

    entry = registry.create(PG_ID, "password")

    def boom(args: dict) -> dict:
        assert filt.has_secret(secret)     # retained during the execution
        raise RuntimeError("command timed out")

    with pytest.raises(RuntimeError):
        mw("terminal", {"command": f'cat "${entry.token}"'}, None, boom,
           task_id="aud02-exc")
    # Fail-safe release: exception path closed the scope anyway.
    assert filt.active_secret_count() == baseline
    assert not filt.has_secret(secret)


def test_process_scoped_secret_survives_execution_cleanup(
        auth_manager, registry, plugin_config, monkeypatch, tmp_path):
    filt = _isolated_filter(monkeypatch)
    xdg = tmp_path / "xdg"; xdg.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    startup_secret = "AUD02-PROCESS-SCOPED-VALUE"
    filt.register_process_scoped_secret(startup_secret)
    baseline = filt.active_secret_count()

    # An execution that happens to inject the SAME value must not be able to
    # remove the process-scoped pin when its scope closes.
    _seed_item_password(monkeypatch, PG_ID, startup_secret)
    mw = make_placeholder_resolver(auth_manager, registry, plugin_config)
    tf = make_result_redactor(auth_manager, registry, plugin_config)
    out = _run_execution(mw, tf, registry, PG_ID, startup_secret,
                         "aud02-procscope")
    assert out == "[REDACTED]\n"
    assert filt.has_secret(startup_secret)          # permanence preserved
    assert filt.active_secret_count() == baseline   # no refcount inflation
    assert filt.redact(f"x={startup_secret}") == "x=[REDACTED]"


def test_transform_redacts_when_dispatched_after_middleware_frame(
        auth_manager, registry, plugin_config, monkeypatch, tmp_path):
    """Deferred host ordering (transform AFTER frame return) keeps SEC-01."""
    filt = _isolated_filter(monkeypatch)
    xdg = tmp_path / "xdg"; xdg.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    secret = "AUD02-DEFERRED-TRANSFORM"
    _seed_item_password(monkeypatch, PG_ID, secret)
    mw = make_placeholder_resolver(auth_manager, registry, plugin_config)
    tf = make_result_redactor(auth_manager, registry, plugin_config)
    baseline = filt.active_secret_count()

    entry = registry.create(PG_ID, "password")

    def terminal(args: dict) -> dict:
        m = _AUD02_SUBST_RE.search(args["command"])
        assert m is not None, f"no $(< path) substitution: {args['command']!r}"
        path = m.group(1)
        with open(path, encoding="utf-8") as fh:
            return {"output": fh.read() + "\n"}

    # Middleware call RETURNS first (scope closed)...
    result = mw("terminal", {"command": f'cat "${entry.token}"'}, None,
                terminal, task_id="aud02-deferred")
    assert filt.active_secret_count() == baseline
    # ...and only THEN does this host dispatch the authoritative transformer.
    transformed = tf("terminal", result, task_id="aud02-deferred")
    assert transformed["output"] == "[REDACTED]\n"
    assert secret not in str(transformed)


def test_no_secret_values_appear_in_logs(auth_manager, registry,
                                         plugin_config, monkeypatch, tmp_path,
                                         caplog):
    filt = _isolated_filter(monkeypatch)
    xdg = tmp_path / "xdg"; xdg.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    secret = "AUD02-LOGSAFE-SECRET"
    _seed_item_password(monkeypatch, PG_ID, secret)
    mw = make_placeholder_resolver(auth_manager, registry, plugin_config)
    tf = make_result_redactor(auth_manager, registry, plugin_config)

    with caplog.at_level("DEBUG"):
        _run_execution(mw, tf, registry, PG_ID, secret, "aud02-logsafe")
        # Trigger the missing-parent-scope fallback too (sanitized warning).
        from vaultwarden.hooks import retain_in_execution_scope
        retain_in_execution_scope("AUD02-ORPHAN-FALLBACK-VALUE", filt)
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert secret not in joined
    assert "AUD02-ORPHAN-FALLBACK-VALUE" not in joined

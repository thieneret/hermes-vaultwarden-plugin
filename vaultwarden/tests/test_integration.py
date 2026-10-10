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


def _register_ok(monkeypatch, tmp_path, fake_bw, section_extra=None, env_extra=None):
    monkeypatch.setenv("VW_CLIENT_SECRET", "cs-secret")
    monkeypatch.setenv("VW_MASTER_PASSWORD", "mp-secret")
    monkeypatch.setenv("BW_CLI_PATH", fake_bw)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    for k, v in (env_extra or {}).items():
        monkeypatch.setenv(k, v)
    section = {**BASE_SECTION, **(section_extra or {})}
    ctx = RecordingCtx({"secrets": {"vaultwarden": section}})
    ok = vaultwarden.register(ctx)
    return ok, ctx


# ------------------------------------------------------------- registration
def test_register_full_flow_and_tool_count(monkeypatch, tmp_path, fake_bw):
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    assert ok is True
    assert len(ctx.tools) == 9
    names = {t["name"] for t in ctx.tools}
    assert names == {
        "vaultwarden_status", "vaultwarden_sync", "vaultwarden_list",
        "vaultwarden_search", "vaultwarden_get_secret_ref", "vaultwarden_store",
        "vaultwarden_update", "vaultwarden_delete", "vaultwarden_generate_password"}
    assert all(t["toolset"] == "vaultwarden" for t in ctx.tools)
    assert all(t["check_fn"]() for t in ctx.tools)
    assert [k for k, _ in ctx.middleware] == ["tool_request"]
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
    ctx = RecordingCtx({"secrets": {"vaultwarden": {**BASE_SECTION, "enabled": True}}})
    assert vaultwarden.register(ctx) is False
    assert ctx.tools == []


def test_graceful_degradation_missing_env(monkeypatch, tmp_path, fake_bw):
    monkeypatch.delenv("VW_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("VW_MASTER_PASSWORD", raising=False)
    monkeypatch.setenv("BW_CLI_PATH", fake_bw)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    ctx = RecordingCtx({"secrets": {"vaultwarden": {**BASE_SECTION, "enabled": True}}})
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
    tools = {t["name"]: t["handler"] for t in ctx.tools}
    mw = dict(ctx.middleware)["tool_request"]
    post = dict(ctx.hooks)["post_tool_call"]

    # LLM asks for a reference, never the secret:
    ref = tools["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001", "field": "password"})
    token = ref["placeholder"]
    assert TOKEN_RE.match(token)
    assert "sup3r-s3cret-pg!" not in str(ref)

    # LLM composes a terminal command with the placeholder:
    llm_args = {"command": f"PGPASSWORD={token} psql -h db.internal -U dbadmin -c 'SELECT 1'"}
    rewritten = mw("terminal", dict(llm_args))
    assert rewritten is not None
    executed = rewritten["args"]["command"]
    assert token not in executed and "sup3r-s3cret-pg!" in executed

    # execution result may echo the secret -> post hook redacts it:
    result = {"output": "psql ran with sup3r-s3cret-pg! visible"}
    post("terminal", rewritten["args"], result, task_id="task-1")
    assert "sup3r-s3cret-pg!" not in result["output"]

    # replay of the same placeholder now fails closed:
    again = mw("terminal", {"command": f"echo {token}"})
    assert "__VW_PLACEHOLDER_INVALID__" in again["args"]["command"]
    assert "sup3r-s3cret-pg!" not in again["args"]["command"]


def test_crud_cycle_integration(monkeypatch, tmp_path, fake_bw):
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw, {"allow_write": True})
    tools = {t["name"]: t["handler"] for t in ctx.tools}
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
    tools = {t["name"]: t["handler"] for t in ctx.tools}
    first = tools["vaultwarden_list"]({})
    assert "error" not in first
    auth._session_created_at -= 10            # simulate expiry
    second = tools["vaultwarden_list"]({})    # auto re-unlock, transparent
    assert "error" not in second and second["total"] == first["total"]


def test_concurrent_tool_calls(monkeypatch, tmp_path, fake_bw):
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    tools = {t["name"]: t["handler"] for t in ctx.tools}
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
    for t in threads: t.start()
    for t in threads: t.join()
    assert errors_seen == []
    registry = vaultwarden.PLUGIN_STATE["registry"]
    assert len(registry.snapshot()) <= registry._max   # cap respected under load


def test_on_session_end_hook_locks_vault(monkeypatch, tmp_path, fake_bw):
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    auth = vaultwarden.PLUGIN_STATE["auth"]
    appdata = vaultwarden.PLUGIN_STATE["config"].appdata_dir()
    end = dict(ctx.hooks)["on_session_end"]
    end()
    assert auth.session_key is None
    assert not (appdata / "fake-unlocked").exists()    # vault locked on disk too
    assert (appdata / "fake-logged-in").exists()       # login kept, .bw-data retained


def test_logs_never_contain_bootstrap_secrets(monkeypatch, tmp_path, fake_bw, caplog):
    caplog.set_level(logging.DEBUG)
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    tools = {t["name"]: t["handler"] for t in ctx.tools}
    tools["vaultwarden_list"]({})
    tools["vaultwarden_get_secret_ref"]({"item_id": "Postgres prod", "field": "password"})
    mw = dict(ctx.middleware)["tool_request"]
    tok = [t for t in __import__("re").findall(
        r"__VW_SECRET_[0-9a-f]{12}__",
        str(vaultwarden.PLUGIN_STATE["registry"].snapshot()))][0]
    mw("terminal", {"command": f"run --pw {tok}"})
    blob = " ".join(r.getMessage() for r in caplog.records) + caplog.text
    assert "cs-secret" not in blob
    assert "mp-secret" not in blob
    key = vaultwarden.PLUGIN_STATE["auth"].session_key
    assert key not in blob

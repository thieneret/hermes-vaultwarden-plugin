"""Unit tests: tool handlers — metadata-only outputs, gating, CRUD, generation."""
from __future__ import annotations

import re

TOKEN_RE = re.compile(r"^__VW_SECRET_[0-9a-f]{12}__$")


def test_status_tool(auth_manager, plugin_config, registry, tools_by_name):
    res = tools_by_name["vaultwarden_status"]({})
    assert "error" not in res
    snap = res["status"]
    assert snap["auth_state"] == "unlocked"
    assert snap["server_configured"] == "https://vault.example.com"
    blob = str(res)
    for secret in ("cs-secret", "mp-secret", "sessionkey", "sup3r-s3cret-pg!"):
        assert secret not in blob


def test_sync_tool(tools_by_name):
    res = tools_by_name["vaultwarden_sync"]({"force": True})
    assert res.get("synced") is True
    assert isinstance(res["timestamp"], float)


def test_list_returns_metadata_only(tools_by_name):
    res = tools_by_name["vaultwarden_list"]({})
    assert res["total"] == 3 and len(res["items"]) == 3
    blob = str(res)
    # NO passwords / totp / notes values ever leave this tool:
    for forbidden in ("sup3r-s3cret-pg!", "gr@f-pass", "JBSWY3DPEHPK3PXP",
                      "sk_live_XXXX", "custom-key-value"):
        assert forbidden not in blob
    names = {i["name"] for i in res["items"]}
    assert names == {"Postgres prod", "Grafana", "API keys"}
    pg = next(i for i in res["items"] if i["name"] == "Postgres prod")
    assert pg["type"] == "login" and pg["username"] == "dbadmin"
    assert pg["uris"] == ["postgres://db.internal:5432"]


def test_list_limit_is_honoured_client_side(tools_by_name):
    res2 = tools_by_name["vaultwarden_list"]({"limit": 2})
    assert res2["returned"] == 2 and res2["total"] == 3


def test_search_tool(tools_by_name):
    res = tools_by_name["vaultwarden_search"]({"query": "postgres"})
    assert res["count"] >= 1
    assert res["matches"][0]["id"].startswith("aaaa")
    empty = tools_by_name["vaultwarden_search"]({"query": "zzz-nothing"})
    assert empty["count"] == 0
    byfield = tools_by_name["vaultwarden_search"]({"query": "viz", "field": "username"})
    assert [m["name"] for m in byfield["matches"]] == ["Grafana"]


def test_get_secret_ref_returns_placeholder_not_secret(tools_by_name, registry):
    res = tools_by_name["vaultwarden_get_secret_ref"](
        {"item_id": "Postgres prod", "field": "password"})
    assert TOKEN_RE.match(res["placeholder"])
    assert res["ttl_seconds"] == 300
    assert "sup3r-s3cret-pg!" not in str(res)
    assert "direct_value" not in res          # default OFF
    assert len(registry.snapshot()) == 1


def test_get_secret_ref_custom_field(tools_by_name, registry):
    res = tools_by_name["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001",
         "field": "password", "custom_field_name": "api_key"})
    assert TOKEN_RE.match(res["placeholder"])
    snap = registry.snapshot()[res["placeholder"]]
    assert snap["field"] == "custom:api_key"   # resolved via custom field
    assert "custom-key-value" not in str(res)  # value never returned


def test_get_secret_ref_empty_field_error(tools_by_name):
    res = tools_by_name["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000003", "field": "totp"})
    assert res["error_code"] == "NOT_FOUND"


def test_get_secret_ref_unknown_item(tools_by_name):
    res = tools_by_name["vaultwarden_get_secret_ref"](
        {"item_id": "nope", "field": "password"})
    assert res["error_code"] == "NOT_FOUND"


def test_write_tools_blocked_when_disabled(tools_by_name):
    # v1.5 (FAIL-11): vaultwarden_generate_password is NOT a vault mutation
    # (BUG-2 / v1.2 fix, protected by test_bugfixes_v12) — it must SUCCEED
    # with allow_write=false; only store/update/delete are blocked.
    for name, args in (
        ("vaultwarden_store", {"type": "login", "name": "x"}),
        ("vaultwarden_update", {"item_id": "a", "name": "b"}),
        ("vaultwarden_delete", {"item_id": "a", "confirm": True}),
    ):
        res = tools_by_name[name](args)
        assert res["error_code"] == "PERMISSION_ERROR", name
        assert res["recoverable"] is False
    gen_res = tools_by_name["vaultwarden_generate_password"]({"length": 16})
    assert "error" not in gen_res, \
        "generate_password should work without write permission (BUG-2)"


def test_store_update_delete_cycle(write_tools_by_name):
    res = write_tools_by_name["vaultwarden_store"]({
        "type": "login", "name": "New service", "username": "svc",
        "password": "generated-pw-123", "uri": "https://svc.example.com",
        "custom_fields": [{"name": "token", "value": "tok-abc", "field_type": 1}]})
    assert res["created"] is True and res["id"] == "new-item-id-0001"
    upd = write_tools_by_name["vaultwarden_update"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001", "name": "Renamed"})
    assert upd["updated"] is True and upd["item"]["name"] == "Renamed"
    dny = write_tools_by_name["vaultwarden_delete"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001", "confirm": False})
    assert dny["error_code"] == "PERMISSION_ERROR"   # confirm gate
    ok = write_tools_by_name["vaultwarden_delete"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001", "confirm": True})
    assert ok["deleted"] is True and ok["permanent"] is False
    perm = write_tools_by_name["vaultwarden_delete"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001",
         "confirm": True, "permanent": True})
    assert perm["permanent"] is True


def test_generate_password(write_tools_by_name):
    res = write_tools_by_name["vaultwarden_generate_password"]({"length": 24})
    assert res["generated"] == "Zk9#xQ2vLm8pRt4wYb7n"  # fake bw deterministic
    pass_res = write_tools_by_name["vaultwarden_generate_password"](
        {"mode": "passphrase", "words": 6, "separator": "."})
    assert pass_res["mode"] == "passphrase"


def test_error_envelope_format(tools_by_name):
    res = tools_by_name["vaultwarden_search"]({"query": "x"})  # valid call shape
    assert "error" not in res
    bad = tools_by_name["vaultwarden_get_secret_ref"]({"item_id": "", "field": "password"})
    assert set(bad) >= {"error", "error_code", "recoverable"}


def test_direct_retrieval_escape_hatch(bw_cli, registry):
    from vaultwarden.tools import get_tools
    from vaultwarden.tests.conftest import make_config
    from vaultwarden.auth import AuthManager
    cfg = make_config(section={"allow_direct_secret_retrieval": True})
    mgr = AuthManager(bw_cli, cfg, client_secret="cs-secret", master_password="mp-secret")
    mgr.configure_server_if_needed(); mgr.ensure_authenticated()
    # v1.5 (FAIL-2): get_tools yields (schema_dict, handler) tuples; dict()
    # cannot key by dicts -> build the map by tool name instead.
    tools = {s["name"]: h for s, h in get_tools(mgr, cfg, registry)}
    res = tools["vaultwarden_get_secret_ref"](
        {"item_id": "Postgres prod", "field": "password"})
    assert res.get("direct_value") == "sup3r-s3cret-pg!"

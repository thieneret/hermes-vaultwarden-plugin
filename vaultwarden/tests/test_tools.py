"""Unit tests: tool handlers — metadata-only outputs, gating, CRUD, generation."""
from __future__ import annotations

import re

TOKEN_RE = re.compile(r"^__VW_SECRET_[0-9a-f]{12}__$")


def _dict_tools(raw):
    """v0.2.4: handlers return JSON strings; parse back to dicts for tests."""
    import json as _json
    def wrap(handler):
        def inner(args, **kw):
            r = handler(args, **kw)
            return _json.loads(r) if isinstance(r, str) else r
        return inner
    return {k: wrap(h) for k, h in raw.items()}


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
    # v0.1.5 (FAIL-11): vaultwarden_generate_password is NOT a vault mutation
    # (BUG-2 / v0.1.2 fix, protected by test_bugfixes_v12) — it must SUCCEED
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
    mgr.ensure_authenticated()
    # v0.1.5 (FAIL-2): get_tools yields (schema_dict, handler) tuples; dict()
    # cannot key by dicts -> build the map by tool name instead.
    tools = _dict_tools({s["name"]: h for s, h in get_tools(mgr, cfg, registry)})
    res = tools["vaultwarden_get_secret_ref"](
        {"item_id": "Postgres prod", "field": "password"})
    assert res.get("direct_value") == "sup3r-s3cret-pg!"


# ---------------------------------------------------------------------------
# Consolidated from test_guard_json_string_v024.py — _guard() JSON-string exit
# ---------------------------------------------------------------------------

def test_guard_returns_json_string():
    """v0.2.4: _guard must return str, not dict."""
    import json
    from vaultwarden.tools import _guard

    result = _guard(lambda: {"key": "value", "count": 42})
    assert isinstance(result, str), f"Expected str, got {type(result)}"
    parsed = json.loads(result)
    assert parsed == {"key": "value", "count": 42}


def test_guard_error_returns_json_string():
    """v0.2.4: _guard error paths must also return str."""
    import json
    from vaultwarden.tools import _guard
    from vaultwarden import errors

    def failing():
        raise errors.NotFoundError("Item not found.")

    result = _guard(failing)
    assert isinstance(result, str), f"Expected str, got {type(result)}"
    parsed = json.loads(result)
    assert "error" in parsed
    assert parsed["error_code"] == "NOT_FOUND"


def test_all_handlers_return_str():
    """v0.2.4: every tool handler must return str via _guard."""
    import json
    from unittest.mock import MagicMock
    from vaultwarden.tools import get_tools
    from vaultwarden.placeholders import PlaceholderRegistry

    auth = MagicMock()
    auth.status_snapshot.return_value = {"auth_state": "unlocked"}
    auth.sync.return_value = {"synced": True}
    auth.list_items.return_value = []
    auth.generate_password.return_value = "test-password-123"

    config = MagicMock()
    config.allow_write = True
    config.allow_direct_secret_retrieval = False

    registry = PlaceholderRegistry(ttl_seconds=300, max_entries=50)

    for schema, handler in get_tools(auth, config, registry):
        tool_name = schema["name"]
        try:
            if tool_name == "vaultwarden_status":
                result = handler({})
            elif tool_name == "vaultwarden_sync":
                result = handler({"force": False})
            elif tool_name == "vaultwarden_list":
                result = handler({"limit": 10})
            elif tool_name == "vaultwarden_search":
                result = handler({"query": "test"})
            elif tool_name == "vaultwarden_generate_password":
                result = handler({"mode": "password", "length": 16})
            else:
                continue  # skip tools that need complex mocking

            assert isinstance(result, str), \
                f"{tool_name}: expected str, got {type(result).__name__}"
            json.loads(result)  # must be valid JSON
        except Exception as exc:
            raise AssertionError(f"{tool_name}: handler failed: {exc}")


# ---------------------------------------------------------------------------
# Consolidated from test_bugfixes_v12.py (BUG-1..BUG-5 tool parts)
# ---------------------------------------------------------------------------

def test_generate_password_uses_flag_syntax(monkeypatch):
    """bw generate <len> --uppercase --lowercase --number --special (no 1/0)."""
    import json as _json
    from vaultwarden.auth import AuthManager
    from vaultwarden.tools import get_tools
    from vaultwarden.placeholders import PlaceholderRegistry
    from vaultwarden.tests.conftest import make_config

    captured: list[list[str]] = []

    class FakeBw:
        def generate_password(self, session_key, args):
            captured.append(list(args))
            return "genpw"

    cfg = make_config()
    auth = AuthManager.__new__(AuthManager)          # skip real init
    auth._bw = FakeBw()                              # noqa: SLF001
    auth.run_with_recovery = lambda fn: fn("sess")   # type: ignore[attr-defined]

    def wrap(handler):
        def inner(args, **kw):
            r = handler(args, **kw)
            return _json.loads(r) if isinstance(r, str) else r
        return inner

    tools = {s["name"]: wrap(h) for s, h in get_tools(auth, cfg, PlaceholderRegistry())}

    res = tools["vaultwarden_generate_password"]({"mode": "password", "length": 20})
    assert res["generated"] == "genpw"
    assert captured[-1] == ["20", "--uppercase", "--lowercase", "--number", "--special"]

    res = tools["vaultwarden_generate_password"](
        {"mode": "password", "length": 16, "uppercase": False, "special": False})
    assert captured[-1] == ["16", "--lowercase", "--number"]  # only True flags kept

    res = tools["vaultwarden_generate_password"](
        {"mode": "passphrase", "words": 4, "separator": "-"})
    assert captured[-1] == ["--passphrase", "-w", "4", "--separator", "-"]


def test_generate_password_works_without_write_permission(tools_by_name):
    """BUG-2: generation is not a vault mutation -> allow_write=false is fine."""
    res = tools_by_name["vaultwarden_generate_password"]({"length": 24})
    assert "error" not in res
    assert res["generated"] == "Zk9#xQ2vLm8pRt4wYb7n"  # fake bw deterministic
    pass_res = tools_by_name["vaultwarden_generate_password"](
        {"mode": "passphrase", "words": 6, "separator": "."})
    assert pass_res["mode"] == "passphrase" and "error" not in pass_res


def test_generate_password_via_fake_bw_flags(tools_by_name):
    """End-to-end through the fake bw: unknown positional 1/0 args would be
    rejected by a real CLI; the flag form must succeed in both modes."""
    for args in ({"mode": "password", "length": 20},
                 {"mode": "passphrase", "words": 3}):
        res = tools_by_name["vaultwarden_generate_password"](args)
        assert "error" not in res, res


def test_list_folder_id_uses_folderid_flag(bw_cli, appdata, monkeypatch):
    """vaultwarden_list(folder_id=...) must invoke `bw list items --folderid abc`."""
    import json as _json
    from vaultwarden.auth import AuthManager
    from vaultwarden.tools import get_tools
    from vaultwarden.placeholders import PlaceholderRegistry
    from vaultwarden.tests.conftest import make_config

    seen: list = []
    orig = bw_cli.list_items

    def spy(session_key, filters=None):
        seen.append(list(filters or []))
        return orig(session_key, filters)

    monkeypatch.setattr(bw_cli, "list_items", spy)
    cfg = make_config()
    auth = AuthManager(bw_cli, cfg, client_secret="cs-secret", master_password="mp-secret")
    auth.ensure_authenticated()

    def wrap(handler):
        def inner(args, **kw):
            r = handler(args, **kw)
            return _json.loads(r) if isinstance(r, str) else r
        return inner

    tools = {s["name"]: wrap(h) for s, h in
             get_tools(auth, cfg, PlaceholderRegistry())}

    res = tools["vaultwarden_list"]({"folder_id": "f1"})
    assert seen[-1] == ["--folderid", "f1"]           # exact flag form
    assert res["total"] == 1 and res["items"][0]["name"] == "Postgres prod"

    res_note = tools["vaultwarden_list"]({"type": "note"})
    assert seen[-1] == []                             # no --filter-type passed
    assert [i["name"] for i in res_note["items"]] == ["API keys"]


def test_list_bad_folder_returns_empty(tools_by_name):
    res = tools_by_name["vaultwarden_list"]({"folder_id": "does-not-exist"})
    assert res["total"] == 0 and res["items"] == []


def test_delete_permanent_with_confirm(write_tools_by_name):
    res = write_tools_by_name["vaultwarden_delete"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001",
         "confirm": True, "permanent": True})
    assert res["deleted"] is True and res["permanent"] is True


def test_search_uses_native_search_flag(bw_cli, monkeypatch):
    import json as _json
    from vaultwarden.auth import AuthManager
    from vaultwarden.tools import get_tools
    from vaultwarden.placeholders import PlaceholderRegistry
    from vaultwarden.tests.conftest import make_config

    seen: list = []
    orig = bw_cli.list_items

    def spy(session_key, filters=None):
        seen.append(list(filters or []))
        return orig(session_key, filters)

    monkeypatch.setattr(bw_cli, "list_items", spy)
    cfg = make_config()
    auth = AuthManager(bw_cli, cfg, client_secret="cs-secret", master_password="mp-secret")
    auth.ensure_authenticated()

    def wrap(handler):
        def inner(args, **kw):
            r = handler(args, **kw)
            return _json.loads(r) if isinstance(r, str) else r
        return inner

    tools = {s["name"]: wrap(h) for s, h in
             get_tools(auth, cfg, PlaceholderRegistry())}

    res = tools["vaultwarden_search"]({"query": "github"})
    assert seen[-1] == ["--search", "github"]         # native path used
    assert res["count"] == 0                          # fake bw: no match

    res2 = tools["vaultwarden_search"]({"query": "postgres"})
    assert seen[-1] == ["--search", "postgres"]
    assert res2["count"] >= 1

    # uri field is NOT natively searchable -> full-list fallback expected
    tools["vaultwarden_search"]({"query": "grafana", "field": "uri"})
    assert seen[-1] == []
    # explicit type filter also falls back to client-side filtering
    tools["vaultwarden_search"]({"query": "api", "type": "note"})
    assert seen[-1] == []


# ---------------------------------------------------------------------------
# Consolidated from test_store_edit_v027.py (payload builder parts)
# ---------------------------------------------------------------------------

def test_build_item_has_no_explicit_nulls():
    """v0.2.7: _build_item must not inject match/passwordRevisionDate nulls."""
    from vaultwarden.tools import _build_item
    item = _build_item({"type": "login", "name": "x", "username": "u",
                        "password": "p", "uri": "https://example.com"})
    login = item["login"]
    assert "passwordRevisionDate" not in login
    assert login["uris"][0] == {"uri": "https://example.com"}
    assert "match" not in login["uris"][0]


def test_apply_updates_has_no_explicit_nulls():
    """v0.2.7: _apply_updates must not inject match/passwordRevisionDate nulls."""
    from vaultwarden.tools import _apply_updates
    current = {"id": "abc", "name": "old", "login": {"username": "u"}}
    merged = _apply_updates(current, {"password": "newpw",
                                      "uri": "https://example.com"})
    login = merged["login"]
    assert "passwordRevisionDate" not in login
    assert login["uris"][0] == {"uri": "https://example.com"}
    assert "match" not in login["uris"][0]

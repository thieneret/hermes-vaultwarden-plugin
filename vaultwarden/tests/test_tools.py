"""Unit tests: tool handlers — metadata-only outputs, gating, CRUD, generation."""
from __future__ import annotations

import os
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
    # v0.3.7 (VWP-14): direct retrieval escape hatch removed — a raw value
    # key can never appear in the response, under any configuration.
    assert "direct_value" not in res
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
    # v0.3.7 (VWP-12): vaultwarden_generate_password no longer exists;
    # store/update/delete are blocked with allow_write=false (and this also
    # covers generate=true, which is a vault mutation and must be blocked).
    for name, args in (
        ("vaultwarden_store", {"type": "login", "name": "x"}),
        ("vaultwarden_store", {"type": "login", "name": "x", "generate": True}),
        ("vaultwarden_update", {"item_id": "a", "name": "b"}),
        ("vaultwarden_update", {"item_id": "a", "generate": True}),
        ("vaultwarden_delete", {"item_id": "a", "confirm": True}),
    ):
        res = tools_by_name[name](args)
        assert res["error_code"] == "PERMISSION_ERROR", (name, args)
        assert res["recoverable"] is False


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


FAKE_GEN_PW = "Zk9#xQ2vLm8pRt4wYb7n"   # deterministic fake-bw generate output


def test_store_generate_true(write_tools_by_name, appdata, registry):
    """v0.3.7 (VWP-12): store + generate=true stores pw, returns placeholder."""
    import json as _json

    res = write_tools_by_name["vaultwarden_store"]({
        "type": "login", "name": "Gen service", "username": "svc",
        "generate": True, "generate_options": {"length": 24}})
    assert res["created"] is True and res["id"] == "new-item-id-0001"
    assert res["password_generated"] is True
    assert TOKEN_RE.match(res["password_placeholder"])
    assert res["placeholder_ttl_seconds"] == 300
    # The raw generated password must NEVER appear in the response...
    blob = _json.dumps(res)
    assert FAKE_GEN_PW not in blob
    assert "generated" not in res or res.get("password_generated") is True
    # ...while it IS stored in the vault item (fake bw persists items).
    with open(appdata / "fake_items.json") as f:
        stored = _json.load(f)["new-item-id-0001"]
    assert stored["login"]["password"] == FAKE_GEN_PW
    # Placeholder registered for later command-time injection.
    snap = registry.snapshot()
    assert res["password_placeholder"] in snap
    assert snap[res["password_placeholder"]]["field"] == "password"


def test_update_generate_true(write_tools_by_name, appdata, registry):
    """v0.3.7 (VWP-12): update + generate=true regenerates pw in place."""
    import json as _json

    # Seed an editable item through the fake bw persistence layer.
    write_tools_by_name["vaultwarden_store"]({
        "type": "login", "name": "To regen", "username": "u",
        "password": "old-pw"})
    upd = write_tools_by_name["vaultwarden_update"]({
        "item_id": "new-item-id-0001", "generate": True,
        "generate_options": {"mode": "passphrase", "words": 4, "separator": "-"}})
    assert upd["updated"] is True
    assert upd["password_generated"] is True
    assert TOKEN_RE.match(upd["password_placeholder"])
    assert upd["placeholder_ttl_seconds"] == 300
    blob = _json.dumps(upd)
    assert FAKE_GEN_PW not in blob      # raw value never returned
    assert "old-pw" not in blob         # metadata-only response
    with open(appdata / "fake_items.json") as f:
        stored = _json.load(f)["new-item-id-0001"]
    assert stored["login"]["password"] == FAKE_GEN_PW
    snap = registry.snapshot()
    assert snap[upd["password_placeholder"]]["field"] == "password"


def test_store_without_generate_has_no_placeholder_fields(write_tools_by_name):
    res = write_tools_by_name["vaultwarden_store"]({
        "type": "login", "name": "Plain", "username": "u", "password": "pw1"})
    assert "password_generated" not in res
    assert "password_placeholder" not in res


def test_error_envelope_format(tools_by_name):
    res = tools_by_name["vaultwarden_search"]({"query": "x"})  # valid call shape
    assert "error" not in res
    bad = tools_by_name["vaultwarden_get_secret_ref"]({"item_id": "", "field": "password"})
    assert set(bad) >= {"error", "error_code", "recoverable"}


def test_direct_retrieval_escape_hatch_removed(bw_cli, registry):
    """v0.3.7 (VWP-14): no code path returns a raw secret — even if the
    legacy setting key is present in the config section."""
    from vaultwarden.auth import AuthManager
    from vaultwarden.tests.conftest import make_config
    from vaultwarden.tools import get_tools
    cfg = make_config(section={"allow_direct_secret_retrieval": True})
    assert not hasattr(cfg, "allow_direct_secret_retrieval")  # option gone
    mgr = AuthManager(bw_cli, cfg, client_secret="cs-secret", master_password="mp-secret")
    mgr.ensure_authenticated()
    # v0.1.5 (FAIL-2): get_tools yields (schema_dict, handler) tuples; dict()
    # cannot key by dicts -> build the map by tool name instead.
    tools = _dict_tools({s["name"]: h for s, h in get_tools(mgr, cfg, registry)})
    res = tools["vaultwarden_get_secret_ref"](
        {"item_id": "Postgres prod", "field": "password"})
    assert TOKEN_RE.match(res["placeholder"])
    assert "direct_value" not in res
    assert "sup3r-s3cret-pg!" not in str(res)


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

    from vaultwarden import errors
    from vaultwarden.tools import _guard

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

    from vaultwarden.placeholders import PlaceholderRegistry
    from vaultwarden.tools import get_tools

    auth = MagicMock()
    auth.status_snapshot.return_value = {"auth_state": "unlocked"}
    auth.sync.return_value = {"synced": True}
    auth.list_items.return_value = []

    config = MagicMock()
    config.allow_write = True

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

def test_store_generate_uses_flag_syntax(monkeypatch):
    """v0.3.9 (VWP-12 hotfix): bw generate --length N --uppercase --lowercase
    --number --special (no positional length, no -w alias) — via
    vaultwarden_store(generate=true)."""
    import json as _json

    from vaultwarden.auth import AuthManager
    from vaultwarden.placeholders import PlaceholderRegistry
    from vaultwarden.tests.conftest import make_config
    from vaultwarden.tools import get_tools

    captured: list[list[str]] = []

    class FakeBw:
        def generate_password(self, session_key, args):
            captured.append(list(args))
            return "genpw"

    cfg = make_config(section={"allow_write": True})
    auth = AuthManager.__new__(AuthManager)          # skip real init
    auth._bw = FakeBw()                              # noqa: SLF001
    auth.run_with_recovery = lambda fn: fn("sess")   # type: ignore[attr-defined]
    auth.create_item = lambda item: dict(item, id="gen-id-1")
    auth.get_item = lambda iid: {"id": iid, "name": "n", "login": {}}
    auth.edit_item = lambda item: item

    def wrap(handler):
        def inner(args, **kw):
            r = handler(args, **kw)
            return _json.loads(r) if isinstance(r, str) else r
        return inner

    tools = {s["name"]: wrap(h) for s, h in get_tools(auth, cfg, PlaceholderRegistry())}

    res = tools["vaultwarden_store"]({
        "type": "login", "name": "x", "generate": True,
        "generate_options": {"mode": "password", "length": 20}})
    assert res["password_generated"] is True
    assert "genpw" not in _json.dumps(res)           # raw value never returned
    assert captured[-1] == ["--length", "20", "--uppercase", "--lowercase",
                            "--number", "--special"]
    # bw generate accepts NO positional args: the length must follow the
    # --length flag, never appear as a leading bare numeric token
    assert captured[-1][0] == "--length"

    tools["vaultwarden_store"]({
        "type": "login", "name": "x", "generate": True,
        "generate_options": {"length": 16, "uppercase": False, "special": False}})
    assert captured[-1] == ["--length", "16", "--lowercase", "--number"]  # only True flags kept
    assert captured[-1][0] == "--length"

    tools["vaultwarden_update"]({
        "item_id": "abc", "generate": True,
        "generate_options": {"mode": "passphrase", "words": 4, "separator": "-"}})
    assert captured[-1] == ["--passphrase", "--words", "4", "--separator", "-"]
    assert "-w" not in captured[-1]                  # no short alias in bw


# ---------------------------------------------------------------------------
# VWP-12 hotfix (v0.3.9): structural assertions on the bw_args list produced
# by _generate_password() directly, via a recording mock auth. This closes
# the fake-bw blind spot: it does not depend on any fake bw behavior.
# ---------------------------------------------------------------------------

from vaultwarden.tools import _generate_password  # noqa: E402


class _RecordingAuth:
    """Captures the bw_args passed to generate_password, returns a dummy."""
    def __init__(self):
        self.captured = None
    def generate_password(self, bw_args):
        self.captured = list(bw_args)
        return "DUMMY-PW"


def test_generate_password_length_is_flag_not_positional():
    auth = _RecordingAuth()
    _generate_password(auth, {"mode": "password", "length": 20})
    args = auth.captured
    # bw generate accepts NO positional args — first element must be a flag
    assert args[0] == "--length", f"expected --length flag, got {args[0]!r}"
    assert args[1] == "20"
    # No bare numeric token in argument position (i.e. directly after a
    # value-taking flag or at the head of the list). The only numeric token
    # allowed is the value consumed by --length itself.
    numeric_positions = [i for i, a in enumerate(args) if a.isdigit()]
    assert numeric_positions == [1], \
        f"positional numeric arg present: {args}"
    # Character-class flags preserved (long forms)
    assert "--uppercase" in args and "--number" in args and "--special" in args


def test_generate_password_words_is_long_flag_no_short_alias():
    auth = _RecordingAuth()
    _generate_password(auth, {"mode": "passphrase", "words": 4, "separator": "-"})
    args = auth.captured
    assert "--passphrase" in args
    assert "--words" in args, "must use --words, not -w"
    assert "-w" not in args, "-w short alias does not exist in bw"
    idx = args.index("--words")
    assert args[idx + 1] == "4"
    assert "--separator" in args
    sidx = args.index("--separator")
    assert args[sidx + 1] == "-"


def test_generate_password_default_mode_is_password():
    auth = _RecordingAuth()
    _generate_password(auth, {})  # no mode → password branch
    args = auth.captured
    assert args[0] == "--length"
    assert args[1] == "20"  # default length
    assert "--passphrase" not in args


def test_generate_requires_write_permission(tools_by_name):
    """v0.3.7 (VWP-12): generate=true is a vault mutation -> blocked when
    allow_write=false (replaces the old BUG-2 exemption of the removed tool)."""
    res = tools_by_name["vaultwarden_store"](
        {"type": "login", "name": "x", "generate": True})
    assert res["error_code"] == "PERMISSION_ERROR"


def test_generate_via_fake_bw_flags(write_tools_by_name):
    """End-to-end through the fake bw: unknown positional 1/0 args would be
    rejected by a real CLI; the flag form must succeed in both modes."""
    for opts in ({"mode": "password", "length": 20},
                 {"mode": "passphrase", "words": 3}):
        res = write_tools_by_name["vaultwarden_store"](
            {"type": "login", "name": f"svc-{opts['mode']}", "generate": True,
             "generate_options": opts})
        assert "error" not in res, res
        assert res["password_generated"] is True


# ---------------------------------------------------------------------------
# VWP-08 (v0.3.7): SSH subprocess environment isolation
# ---------------------------------------------------------------------------

def test_ssh_base_env_allowlist_only(monkeypatch):
    """_ssh_base_env returns ONLY PATH/HOME/LC_ALL plus filtered extras."""
    from vaultwarden.tools import _ssh_base_env

    monkeypatch.setenv("SECRET_TEST_VAR", "should_not_leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "should_not_leak_either")
    env = _ssh_base_env()
    assert set(env) == {"PATH", "HOME", "LC_ALL"}
    assert "SECRET_TEST_VAR" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert env["LC_ALL"] == "C"


def test_ssh_base_env_extras_and_falsy_filtering(monkeypatch):
    """Extras are merged; falsy extra values are dropped entirely."""
    from vaultwarden.tools import _ssh_base_env

    monkeypatch.setenv("SSH_AUTH_SOCK", "/parent/leaky/sock")
    env = _ssh_base_env({"SSH_AUTH_SOCK": "/tmp/test", "SSH_ASKPASS": "",
                         "VW_SSH_PASS": None})
    assert env["SSH_AUTH_SOCK"] == "/tmp/test"      # explicit override wins
    assert "SSH_ASKPASS" not in env                 # falsy -> dropped
    assert "VW_SSH_PASS" not in env                 # None -> dropped
    assert "SECRET_TEST_VAR" not in env
    assert set(env) <= {"PATH", "HOME", "LC_ALL", "SSH_AUTH_SOCK"}


def test_ssh_base_env_never_inherits_parent(monkeypatch):
    """The parent environment is NEVER inherited wholesale."""
    from vaultwarden.tools import _ssh_base_env

    for k in list(os.environ):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PATH", "/minimal/bin")
    env = _ssh_base_env()
    assert len(env) == 3                            # PATH, HOME, LC_ALL only
    assert env["PATH"] == "/minimal/bin"


def test_list_folder_id_uses_folderid_flag(bw_cli, appdata, monkeypatch):
    """vaultwarden_list(folder_id=...) must invoke `bw list items --folderid abc`."""
    import json as _json

    from vaultwarden.auth import AuthManager
    from vaultwarden.placeholders import PlaceholderRegistry
    from vaultwarden.tests.conftest import make_config
    from vaultwarden.tools import get_tools

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
    from vaultwarden.placeholders import PlaceholderRegistry
    from vaultwarden.tests.conftest import make_config
    from vaultwarden.tools import get_tools

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

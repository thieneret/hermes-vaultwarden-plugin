"""v0.1.2 regression tests for the code-review bug fixes (BUG-1..BUG-10).

Each test maps to one identified bug; see the plan review notes.
"""
from __future__ import annotations

import builtins
import sys

import pytest

from vaultwarden.config import load_config
from vaultwarden.tests.conftest import make_config


# --------------------------------------------------------------- BUG-1/2
def _dict_tools(raw):
    """v0.2.4: handlers return JSON strings; parse back to dicts for tests."""
    import json as _json
    def wrap(handler):
        def inner(args, **kw):
            r = handler(args, **kw)
            return _json.loads(r) if isinstance(r, str) else r
        return inner
    return {k: wrap(h) for k, h in raw.items()}


def test_generate_password_uses_flag_syntax(monkeypatch):
    """bw generate <len> --uppercase --lowercase --number --special (no 1/0)."""
    from vaultwarden.auth import AuthManager
    from vaultwarden.tools import get_tools
    from vaultwarden.placeholders import PlaceholderRegistry

    captured: list[list[str]] = []

    class FakeBw:
        def generate_password(self, session_key, args):
            captured.append(list(args))
            return "genpw"

    cfg = make_config()
    auth = AuthManager.__new__(AuthManager)          # skip real init
    auth._bw = FakeBw()                              # noqa: SLF001
    auth.run_with_recovery = lambda fn: fn("sess")   # type: ignore[attr-defined]
    tools = _dict_tools({s["name"]: h for s, h in get_tools(auth, cfg, PlaceholderRegistry())})

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


# --------------------------------------------------------------- BUG-3
def test_list_folder_id_uses_folderid_flag(bw_cli, appdata, monkeypatch):
    """vaultwarden_list(folder_id=...) must invoke `bw list items --folderid abc`."""
    from vaultwarden.auth import AuthManager
    from vaultwarden.tools import get_tools
    from vaultwarden.placeholders import PlaceholderRegistry

    seen: list = []
    orig = bw_cli.list_items

    def spy(session_key, filters=None):
        seen.append(list(filters or []))
        return orig(session_key, filters)

    monkeypatch.setattr(bw_cli, "list_items", spy)
    cfg = make_config()
    auth = AuthManager(bw_cli, cfg, client_secret="cs-secret", master_password="mp-secret")
    auth.ensure_authenticated()
    tools = _dict_tools({s["name"]: h for s, h in
             get_tools(auth, cfg, PlaceholderRegistry())})

    res = tools["vaultwarden_list"]({"folder_id": "f1"})
    assert seen[-1] == ["--folderid", "f1"]           # exact flag form
    assert res["total"] == 1 and res["items"][0]["name"] == "Postgres prod"

    res_note = tools["vaultwarden_list"]({"type": "note"})
    assert seen[-1] == []                             # no --filter-type passed
    assert [i["name"] for i in res_note["items"]] == ["API keys"]


def test_list_bad_folder_returns_empty(tools_by_name):
    res = tools_by_name["vaultwarden_list"]({"folder_id": "does-not-exist"})
    assert res["total"] == 0 and res["items"] == []


# --------------------------------------------------------------- BUG-4
def test_delete_permanent_with_confirm(write_tools_by_name):
    res = write_tools_by_name["vaultwarden_delete"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001",
         "confirm": True, "permanent": True})
    assert res["deleted"] is True and res["permanent"] is True


# --------------------------------------------------------------- BUG-5
def test_search_uses_native_search_flag(bw_cli, monkeypatch):
    from vaultwarden.auth import AuthManager
    from vaultwarden.tools import get_tools
    from vaultwarden.placeholders import PlaceholderRegistry

    seen: list = []
    orig = bw_cli.list_items

    def spy(session_key, filters=None):
        seen.append(list(filters or []))
        return orig(session_key, filters)

    monkeypatch.setattr(bw_cli, "list_items", spy)
    cfg = make_config()
    auth = AuthManager(bw_cli, cfg, client_secret="cs-secret", master_password="mp-secret")
    auth.ensure_authenticated()
    tools = _dict_tools({s["name"]: h for s, h in
             get_tools(auth, cfg, PlaceholderRegistry())})

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


# --------------------------------------------------------------- BUG-6
def test_list_limit_schema_default():
    from vaultwarden import schemas
    limit_prop = (schemas.VAULTWARDEN_LIST["input_schema"]
                  ["properties"]["limit"])
    assert limit_prop.get("default") == 100


# --------------------------------------------------------------- BUG-7
def test_config_dict_source_needs_no_yaml(monkeypatch):
    """Plugin config loads from a plain dict even when PyYAML is missing."""
    real_import = builtins.__import__

    def blocked(name, *a, **k):
        if name == "yaml" or name.startswith("yaml."):
            raise ImportError("No module named 'yaml'")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", blocked)
    monkeypatch.delitem(sys.modules, "yaml", raising=False)
    cfg = make_config(section={"server_url": "https://vw.example"})
    assert cfg.server_url == "https://vw.example"     # no crash, no yaml import


def test_config_file_source_rejected_without_yaml(tmp_path, monkeypatch):
    """v0.2.0: file-path sources are no longer supported at all — the plugin
    reads config ONLY via PluginContext.get_config(), so no YAML parsing is
    required and a path source raises ConfigError even without PyYAML."""
    real_import = builtins.__import__

    def blocked(name, *a, **k):
        if name == "yaml" or name.startswith("yaml."):
            raise ImportError("No module named 'yaml'")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", blocked)
    monkeypatch.delitem(sys.modules, "yaml", raising=False)

    from vaultwarden.errors import ConfigError

    f = tmp_path / "flat.yaml"
    f.write_text("enabled: true\nserver_url: https://from-fallback\n")
    with pytest.raises(ConfigError):
        load_config(str(f), env={})


# --------------------------------------------------------------- BUG-8
def test_schema_key_consistency():
    from vaultwarden import schemas
    for s in schemas.TOOL_SCHEMAS:
        assert "name" in s
        assert schemas.SCHEMA_KEY in s
        assert s[schemas.SCHEMA_KEY]["type"] == "object"


# --------------------------------------------------------------- BUG-9
def test_check_fn_is_named_closure(fake_bw, appdata):
    import os
    from vaultwarden import _make_check_fn
    from vaultwarden.auth import AuthManager
    from vaultwarden.bw_cli import BwCli

    cfg = make_config()
    auth = AuthManager(BwCli(fake_bw, appdata), cfg,
                       client_secret="cs-secret", master_password="mp-secret")
    check = _make_check_fn(auth)
    assert callable(check) and check.__name__ == "check"
    assert check() is False                      # uninitialised state
    auth.ensure_authenticated()
    assert check() is True


# -------------------------------------------------------------- BUG-10
def test_plugin_yaml_documents_full_binary_path():
    text = open(str(__import__("pathlib").Path(
        __file__).resolve().parents[1] / "plugin.yaml"), encoding="utf-8").read()
    assert "FULL path" in text
    assert "directory path alone is NOT sufficient" in text

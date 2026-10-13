"""Shared pytest fixtures: fake bw binary, mock BwCli, config builders."""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from vaultwarden.auth import AuthManager            # noqa: E402
from vaultwarden.config import PluginConfig, load_config  # noqa: E402
from vaultwarden.placeholders import PlaceholderRegistry  # noqa: E402

FAKE_BW_SCRIPT = r"""#!/usr/bin/env python3
import base64, json, os, sys

argv = sys.argv[1:]
appdata = os.environ.get("BITWARDENCLI_APPDATA_DIR", "")

def out(s=""):
    print(s)

ITEMS = {
  "aaaa1111-0000-0000-0000-000000000001": {
      "id": "aaaa1111-0000-0000-0000-000000000001", "name": "Postgres prod", "type": 1,
      "login": {"username": "dbadmin", "password": "sup3r-s3cret-pg!",
                "uris": [{"uri": "postgres://db.internal:5432"}]},
      "folderId": "f1",
      "fields": [{"name": "api_key", "value": "custom-key-value", "type": 1}]},
  "aaaa1111-0000-0000-0000-000000000002": {
      "id": "aaaa1111-0000-0000-0000-000000000002", "name": "Grafana", "type": 1,
      "login": {"username": "viz", "password": "gr@f-pass", "totp": "JBSWY3DPEHPK3PXP",
                "uris": [{"uri": "https://grafana.example.com"}]}},
  "aaaa1111-0000-0000-0000-000000000003": {
      "id": "aaaa1111-0000-0000-0000-000000000003", "name": "API keys", "type": 2,
      "notes": "stripe key: sk_live_XXXX",
      "fields": [{"name": "api_key", "value": "custom-key-value", "type": 1}]},
}
BY_NAME = {v["name"].lower(): k for k, v in ITEMS.items()}

# v0.1.5 (FAIL-8): created items are persisted in the isolated appdata dir so
# the full CRUD cycle (create -> get -> edit -> delete) works against the
# fake CLI exactly like it would against a real vault.
ITEMS_FILE = os.path.join(appdata, "fake_items.json") if appdata else ""

def _load_created():
    if ITEMS_FILE and os.path.exists(ITEMS_FILE):
        try:
            with open(ITEMS_FILE) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def _save_created(items):
    if ITEMS_FILE:
        with open(ITEMS_FILE, "w") as f:
            json.dump(items, f)

def _all_items():
    merged = dict(ITEMS)
    merged.update(_load_created())
    return merged

def _lookup(q):
    all_items = _all_items()
    if q in all_items:
        return q
    for k, v in all_items.items():
        if str(v.get("name", "")).lower() == str(q).lower():
            return k
    return None

if argv[:1] == ["status"]:
    if not appdata or not os.path.isdir(appdata):
        sys.stderr.write("missing appdata\n"); sys.exit(5)
    logged = os.path.exists(os.path.join(appdata, "fake-logged-in"))
    unlocked = os.path.exists(os.path.join(appdata, "fake-unlocked"))
    serverfile = os.path.join(appdata, "server.txt")
    server = open(serverfile).read().strip() if os.path.exists(serverfile) else ""
    uidfile = os.path.join(appdata, "fake-user-id")
    uid = open(uidfile).read().strip() if os.path.exists(uidfile) else ""
    state = "unlocked" if (logged and unlocked) else ("locked" if logged else "unauthenticated")
    # v0.1.9: mirror the REAL `bw status` contract — the key is "status"
    # (not "state") and the account is reported via "userId".
    out(json.dumps({"serverUrl": server, "lastSync": None,
                    "status": state,
                    "userEmail": "agent@example.com" if logged else None,
                    "userId": uid if logged else None,
                    "vaultVersion": "1"}))
elif argv[:2] == ["config", "server"]:
    if os.path.exists(os.path.join(appdata, "fake-logged-in")):
        sys.stderr.write("Logout required before server config update.\n")
        sys.exit(1)
    with open(os.path.join(appdata, "server.txt"), "w") as f:
        f.write(argv[2])
elif argv[:3] == ["config", "get", "server"]:
    p = os.path.join(appdata, "server.txt")
    out(open(p).read().strip() if os.path.exists(p) else "https://vault.bitwarden.com")
elif argv[:1] == ["logout"]:
    try:
        os.remove(os.path.join(appdata, "fake-logged-in"))
        os.remove(os.path.join(appdata, "fake-unlocked"))
    except OSError:
        pass
    out("You have been logged out!")
elif argv[:1] == ["login"]:
    cid = os.environ.get("BW_CLIENTID", "")
    csec = os.environ.get("BW_CLIENTSECRET", "")
    if cid.startswith("user.") and csec == "cs-secret":
        open(os.path.join(appdata, "fake-logged-in"), "w").close()
        # v0.1.9: persist the account uuid so `bw status` can report userId
        # (real bw derives it from the authenticated session).
        with open(os.path.join(appdata, "fake-user-id"), "w") as f:
            f.write(cid[len("user."):])
        out("You are logged in as agent@example.com")
    else:
        sys.stderr.write("Username or password is incorrect. Try again.\n"); sys.exit(1)
elif argv[:1] == ["unlock"]:
    if os.environ.get("BW_MP") == "mp-secret":
        open(os.path.join(appdata, "fake-unlocked"), "w").close()
        out("abcdef0123456789-sessionkey-FEEDFACE")
    else:
        sys.stderr.write("Cannot unlock vault. Username or password is incorrect.\n"); sys.exit(1)
elif argv[:1] == ["lock"]:
    try:
        os.remove(os.path.join(appdata, "fake-unlocked"))
    except OSError:
        pass
    out("Vault locked")
elif argv[:1] == ["sync"]:
    out("Encoding complete.")
elif argv[:2] == ["list", "items"]:
    rest = argv[2:]
    # v0.1.2 (BUG-3/BUG-5): the real bw CLI only understands --folderid /
    # --collectionid / --search here; reject unknown flags like the real one does.
    known = {"--folderid", "--collectionid", "--search", "--pretty"}
    i = 0
    folder = collection = search = None
    while i < len(rest):
        tok = rest[i]
        if tok not in known:
            sys.stderr.write("Unknown option: " + tok + "\\n"); sys.exit(1)
        if tok == "--pretty":
            i += 1; continue
        if tok == "--folderid":
            folder = rest[i + 1]; i += 2; continue
        if tok == "--collectionid":
            collection = rest[i + 1]; i += 2; continue
        if tok == "--search":
            search = rest[i + 1]; i += 2; continue
    items = list(_all_items().values())
    if folder is not None:
        items = [it for it in items if it.get("folderId") == folder]
    if search is not None:
        s = search.lower()
        def _hit(it):
            login = it.get("login") or {}
            return (s in str(it.get("name", "")).lower()
                    or s in str(login.get("username", "")).lower())
        items = [it for it in items if _hit(it)]
    out(json.dumps(items))
elif argv[:2] == ["get", "item"]:
    q = argv[2]
    key = _lookup(q)
    if key:
        out(json.dumps(_all_items()[key]))
    else:
        sys.stderr.write("Cannot find item with the given id or name.\n"); sys.exit(1)
elif argv[:1] == ["encode"]:
    out(base64.b64encode(argv[1].encode()).decode())
elif argv[:2] in (["create", "item"], ["edit", "item"]):
    blob = json.loads(argv[2])
    def dec(v):
        if isinstance(v, str):
            try:
                return base64.b64decode(v.encode()).decode()
            except Exception:
                return v
        if isinstance(v, list):
            return [dec(x) for x in v]
        if isinstance(v, dict):
            return {k: dec(x) for k, x in v.items()}
        return v
    res = {k: dec(v) for k, v in blob.items()}
    # v0.1.5 (FAIL-8): persist mutations so later get/list/edit/delete see them.
    created_map = _load_created()
    if argv[:2] == ["create", "item"]:
        res["id"] = "new-item-id-0001"
        created_map[res["id"]] = res
    else:
        eid = res.get("id")
        if eid and eid in created_map:
            created_map[eid] = res
    _save_created(created_map)
    out(json.dumps(res))
elif argv[:2] == ["delete", "item"]:
    created_map = _load_created()
    created_map.pop(argv[2], None)
    _save_created(created_map)
    out("Item " + argv[2] + " has been deleted.")
elif argv[:1] == ["generate"]:
    out("Zk9#xQ2vLm8pRt4wYb7n")
elif os.environ.get("BW_FORCE_LOCKED") == "1":
    sys.stderr.write("vault is locked\n"); sys.exit(1)
else:
    sys.stderr.write("Unknown command: " + " ".join(argv[:2]) + "\n"); sys.exit(2)
"""


@pytest.fixture()
def fake_bw(tmp_path: Path) -> str:
    script = tmp_path / "bw"
    script.write_text(FAKE_BW_SCRIPT)
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP)
    return str(script)


@pytest.fixture()
def appdata(tmp_path: Path) -> Path:
    d = tmp_path / ".bw-data"
    d.mkdir(mode=0o700)
    return d


BASE_SECTION = {
    "enabled": True,
    "server_url": "https://vault.example.com",
    "client_id": "user.11111111-2222-3333-4444-555555555555",
    "allow_write": False,
}

BASE_ENV = {
    "VW_CLIENT_SECRET": "cs-secret",
    "VW_MASTER_PASSWORD": "mp-secret",
}


class SettingsContext:
    """Simulates the Hermes-native PluginContext.get_config() API (v0.2.0).

    The plugin reads configuration EXCLUSIVELY through get_config(); there
    is no fallback to config.yaml file reading any more.
    """

    def __init__(self, settings: dict):
        self._settings = dict(settings)

    def get_config(self, key: str, default=None):
        return self._settings.get(key, default)


def make_config(**overrides) -> PluginConfig:
    section = {**BASE_SECTION, **overrides.pop("section", {})}
    env = {**BASE_ENV, **overrides.pop("env", {})}
    cfg = load_config(SettingsContext(section), env=env)
    return cfg


@pytest.fixture()
def plugin_config() -> PluginConfig:
    return make_config()


@pytest.fixture()
def bw_cli(fake_bw, appdata):
    from vaultwarden.bw_cli import BwCli
    return BwCli(fake_bw, appdata)


@pytest.fixture()
def auth_manager(bw_cli, plugin_config) -> AuthManager:
    mgr = AuthManager(bw_cli, plugin_config,
                      client_secret="cs-secret", master_password="mp-secret")
    mgr.ensure_authenticated()
    return mgr


@pytest.fixture()
def registry() -> PlaceholderRegistry:
    return PlaceholderRegistry(ttl_seconds=300, max_entries=50)


@pytest.fixture()
def tools_by_name(auth_manager, plugin_config, registry):
    from vaultwarden.tools import get_tools
    return {schema["name"]: handler for schema, handler in
            get_tools(auth_manager, plugin_config, registry)}


class RecordingCtx:
    """Minimal stand-in for the Hermes plugin context.

    v0.2.0: exposes the native get_config() API (plugin-relative keys) —
    the ONLY configuration path the plugin supports now.
    """

    def __init__(self, settings=None):
        self._settings = dict(settings if settings is not None else BASE_SECTION)
        self.tools: list[dict] = []
        self.middleware: list[tuple[str, object]] = []
        self.hooks: list[tuple[str, object]] = []
        self.secret_sources: list[object] = []

    def get_config(self, key, default=None):
        return self._settings.get(key, default)

    def register_tool(self, *, name, toolset, schema, handler, check_fn=None):
        self.tools.append({"name": name, "toolset": toolset, "schema": schema,
                           "handler": handler, "check_fn": check_fn})

    def register_middleware(self, kind, fn):
        self.middleware.append((kind, fn))

    def register_hook(self, kind, fn):
        self.hooks.append((kind, fn))

    def register_secret_source(self, source):
        self.secret_sources.append(source)


@pytest.fixture()
def write_auth_manager(bw_cli):
    """AuthManager wired to a config that allows write operations."""
    cfg = make_config(section={"allow_write": True})
    mgr = AuthManager(bw_cli, cfg, client_secret="cs-secret", master_password="mp-secret")
    mgr.ensure_authenticated()
    return mgr


@pytest.fixture()
def write_tools_by_name(write_auth_manager, registry):
    from vaultwarden.tools import get_tools
    cfg = write_auth_manager._config
    return {schema["name"]: handler for schema, handler in
            get_tools(write_auth_manager, cfg, registry)}

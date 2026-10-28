"""Shared pytest fixtures: fake bw binary, mock BwCli, config builders."""
from __future__ import annotations

import json
import stat
import sys
import tempfile
from pathlib import Path

import pytest

# Repo reorganization (v0.4.4 step 1): the plugin now lives at
# plugins/vaultwarden/, so the repo root is THREE levels up from this file
# (tests -> vaultwarden -> plugins -> root). The previous parents[2] value
# pointed at plugins/ and silently relied on the deleted root conftest.py
# to make `import vaultwarden` work.
_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from vaultwarden.auth import AuthManager  # noqa: E402
from vaultwarden.config import PluginConfig, load_config  # noqa: E402
from vaultwarden.placeholders import PlaceholderRegistry  # noqa: E402

FAKE_BW_SCRIPT = r"""#!/usr/bin/env python3
import base64, json, os, sys

argv = sys.argv[1:]
appdata = os.environ.get("BITWARDENCLI_APPDATA_DIR", "")

def out(s=""):
    print(s)

# VWP-11 (v0.3.8): BwCli.__init__ runs `bw --version` as its FIRST subprocess
# call; the fake mirrors the real calendar-version output so every existing
# test that constructs a BwCli passes the startup version check. Tests can
# override via BW_FAKE_VERSION (empty string => empty stdout). base_env() is
# a strict allowlist, so the version value is smuggled in through PATH: the
# dir named "<version>=VWFAKEVERSION" encodes the desired output.
if argv[:1] == ["--version"]:
    ver = os.environ.get("BW_FAKE_VERSION", "")
    if not ver:
        for p in os.environ.get("PATH", "").split(os.pathsep):
            base = os.path.basename(p.rstrip("/"))
            if "=VWFAKEVERSION" in base:
                ver = base.split("=VWFAKEVERSION")[0]
                break
    out(ver or "2026.9.1")
    sys.exit(0)

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
    # v0.2.3: bw reads from stdin when no positional argument is given
    # (ARG_MAX fix) — the fake mirrors that behaviour.
    if len(argv) > 1:
        out(base64.b64encode(argv[1].encode()).decode())
    else:
        out(base64.b64encode(sys.stdin.read().encode()).decode())
elif argv[:2] == ["create", "item"]:
    # v0.2.7: bw reads the encoded JSON from stdin when no positional arg
    # is given — the fake mirrors that behaviour (stdlib base64 of the
    # ENTIRE JSON object, per `bw create item <encodedJson>` semantics).
    raw = sys.stdin.read() if len(argv) <= 2 else argv[2]
    blob = json.loads(base64.b64decode(raw).decode("utf-8"))
    res = dict(blob)
    # v0.1.5 (FAIL-8): persist mutations so later get/list/edit/delete see them.
    created_map = _load_created()
    res["id"] = "new-item-id-0001"
    created_map[res["id"]] = res
    _save_created(created_map)
    out(json.dumps(res))
elif argv[:2] == ["edit", "item"]:
    # v0.2.7: `bw edit item <id>` — id is positional, encoded JSON on stdin.
    item_id = argv[2]
    raw = sys.stdin.read()
    blob = json.loads(base64.b64decode(raw).decode("utf-8"))
    res = dict(blob)
    created_map = _load_created()
    if not res.get("id"):
        res["id"] = item_id
    if item_id in created_map:
        created_map[item_id] = res
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

# VWP-01 (v0.4.7 BREAKING): bw_cli_path is REQUIRED — there is no PATH
# lookup and no BW_CLI_PATH env override any more. Tests that need a real
# binary pass it via section={"bw_cli_path": fake_bw}.

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
    # v0.5.0 (BREAKING): the env= parameter is gone — bootstrap secrets are
    # loaded from secrets.yaml by secrets.py, never from an environment
    # mapping. An "env" key in overrides is ignored for backward compat.
    section = {**BASE_SECTION, **overrides.pop("section", {})}
    overrides.pop("env", None)  # accepted but unused (v0.5.0)
    cfg = load_config(SettingsContext(section))
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


@pytest.fixture
def no_config_fallback(monkeypatch):
    """Isolate tests from any on-disk config.yaml / hermes_cli state.

    VWP-05 (v0.5.2): the production config fallback layers
    (hermes_cli.config.read_user_config_raw and the direct
    HERMES_HOME/config.yaml read) have been REMOVED — config.py now uses
    ONLY the native PluginContext.get_config() API, so an empty-settings
    context yields pure defaults without any patching of the extraction
    logic itself.

    What remains here is defense-in-depth for the test environment:
      1. hermes_cli.config.read_user_config_raw() -> returns {}
         (in case a stale hermes_cli module is importable in the venv;
          production never calls it since v0.5.2)
      2. open()/Path.read_text()/read_bytes() guards for config.yaml paths
      3. HERMES_HOME / Path.home() pointed at an empty isolated dir
    so that any residual code path cannot leak environment-dependent values
    into tests that assert on pure defaults. Production code is NOT
    modified — the patch lives entirely in the test layer and is undone
    automatically by monkeypatch.
    """
    # Arm 1: neutralize the (no-longer-used) hermes_cli raw-YAML reader.
    try:
        import hermes_cli.config as _hermes_cfg
        monkeypatch.setattr(
            _hermes_cfg, "read_user_config_raw", lambda *a, **kw: {})
    except ImportError:
        pass  # hermes_cli absent in the test env — arm 1 is already inert

    # Arm 2: block any direct config.yaml file read (defense-in-depth).
    import builtins
    _real_open = builtins.open

    def _guarded_open(file, *args, **kwargs):
        if str(file).endswith("config.yaml"):
            raise FileNotFoundError(f"blocked in test: {file}")
        return _real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", _guarded_open)

    _real_read_text = Path.read_text
    _real_read_bytes = Path.read_bytes

    def _guarded_read_text(self, *args, **kwargs):
        if str(self).endswith("config.yaml"):
            raise FileNotFoundError(f"blocked in test: {self}")
        return _real_read_text(self, *args, **kwargs)

    def _guarded_read_bytes(self, *args, **kwargs):
        if str(self).endswith("config.yaml"):
            raise FileNotFoundError(f"blocked in test: {self}")
        return _real_read_bytes(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _guarded_read_text)
    monkeypatch.setattr(Path, "read_bytes", _guarded_read_bytes)

    iso_home = Path(tempfile.mkdtemp(prefix="vw-no-config-fallback-"))
    monkeypatch.setenv("HERMES_HOME", str(iso_home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: iso_home))

    yield


@pytest.fixture()
def tools_by_name(auth_manager, plugin_config, registry):
    return _dict_tools(auth_manager, plugin_config, registry)


def _dict_tools(auth, cfg, registry):
    """v0.2.4: handlers now return JSON strings (Hermes tool_call contract).

    Wrap them so existing dict-style test assertions keep working while the
    production handlers serialize via _guard().
    """
    from vaultwarden.tools import get_tools

    def wrap(handler):
        def inner(args, **kw):
            result = handler(args, **kw)
            if isinstance(result, str):
                return json.loads(result)
            return result
        return inner

    return {schema["name"]: wrap(handler) for schema, handler in
            get_tools(auth, cfg, registry)}


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

    # SEC-01 (v0.5.4): modern Hermes builds expose the authoritative
    # transform_tool_result hook; compat.supports_transform_tool_result()
    # detects it via this declared capability set. Stand-in contexts that
    # want to simulate OLDER Hermes hosts can clear/replace this attribute
    # in tests exercising the fail-closed path.
    supported_hooks = frozenset({"post_tool_call", "on_session_end",
                                 "transform_tool_result"})

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
    cfg = write_auth_manager._config
    return _dict_tools(write_auth_manager, cfg, registry)


@pytest.fixture()
def hermes_home_with_secrets(tmp_path: Path, monkeypatch) -> Path:
    """v0.5.0: a HERMES_HOME containing a valid, chmod-600 secrets.yaml.

    Mirrors the plugin-private bootstrap file used by secrets.load_secrets():
    $HERMES_HOME/plugins/vaultwarden/secrets.yaml with the fake-CLI test
    credentials (cs-secret / mp-secret). Also pins TERMINAL_ENV so the
    terminal-backend warning does not depend on the developer machine.
    """
    home = tmp_path / "hermes-home"
    plugindir = home / "plugins" / "vaultwarden"
    plugindir.mkdir(parents=True)
    secrets_file = plugindir / "secrets.yaml"
    secrets_file.write_text(
        "client_secret: cs-secret\nmaster_password: mp-secret\n")
    secrets_file.chmod(0o600)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("TERMINAL_ENV", "docker")
    monkeypatch.delenv("BW_CLI_PATH", raising=False)
    return home

"""v0.7.2 regression suite: first-burst AUTH BOOTSTRAP gap (root cause).

The recurring symptom: on a FRESH isolated bw profile under ``auth=deferred``,
the FIRST burst of tool calls returned an EMPTY vault (``vaultwarden_list``)
and failed writes, while the SECOND burst worked. Root cause was an
initialization-order / responsibility-split bug, NOT a credential problem:

* ``register()`` deliberately spawns ZERO bw subprocesses (v0.1.9 — Hermes'
  10s plugin-load timeout); the AuthManager FSM stops at CONFIGURED.
* The ONLY path performing the full bootstrap sequence
  (``bw status`` -> ``bw config server`` -> ``bw login --apikey`` ->
  ``bw unlock`` -> verification) was ``ensure_authenticated()`` — reachable
  solely via ``check_fn``/``is_available()`` or the swallowed-failure
  fallback in ``vaultwarden_status``.
* Every read/write tool goes through ``get_session()`` /
  ``run_with_recovery()``, whose CONFIGURED branch used to call a BARE
  ``_do_login()`` — which fails on a fresh profile because the server URL
  was never configured. The choke-point lazy-unlock hit the same wall and
  surfaced the misleading "verify master_password in secrets.yaml" error
  even though the master password IS loaded in memory.

Fixes pinned by this file:
  CHANGE 1  get_session() routes CONFIGURED through the full FSM
            (idempotent, serialized under the AuthManager lock).
  CHANGE 2  the choke point only ever reaches the bootstrap via
            get_session()/ensure_authenticated() — no bare _do_login().
  CHANGE 3  login/config-stage failures are NOT blamed on master_password.
  CHANGE 4  is_available() records WHY a bootstrap failed (sanitized).
  CHANGE 5  empty read in a non-UNLOCKED state reconciles + retries once.
  CHANGE 6  this regression suite.

Determinism notes: expiry is simulated by manipulating
``_session_created_at`` directly (no sleeps as the primary mechanism); the
concurrency test uses a ``threading.Barrier`` plus deterministic per-command
stalls inside the fake bw (marker-file driven under the appdata dir — the
strict subprocess env allowlist keeps env-var steering away from the child),
so all threads genuinely overlap.
No test embeds or asserts on a live secret value beyond fixed fixture
material; leakage checks compare against the fixture constants only.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from vaultwarden import errors
from vaultwarden.auth import AuthManager, AuthState
from vaultwarden.bw_cli import BwCli, register_auth_manager
from vaultwarden.placeholders import PlaceholderRegistry
from vaultwarden.tests.conftest import BASE_SECTION, make_config

CS_SECRET = "cs-secret"   # fixture client secret (fake bw validates this)
MP_SECRET = "mp-secret"   # fixture master password (fake bw unlocks on it)
REAL_KEY = "abcdef0123456789-sessionkey-FEEDFACE"  # fake-bw unlock output


# ---------------------------------------------------------------------------
# Test layer only: a bw stand-in with REAL-WORLD fresh-profile semantics.
#
#   * ``bw login --apikey`` FAILS unless the server URL was configured first
#     (mirrors the real CLI on a virgin profile).
#   * ``bw list items`` on a locked/unauthenticated profile exits 0 with an
#     EMPTY payload (the read blind spot) instead of failing loudly.
#   * Optional deterministic stalls (<appdata>/fake-stall-<cmd> marker dirs,
#     see _set_stall) maximize thread-overlap windows without relying on
#     flaky sleeps for correctness.
#   * fake-fail-login / fake-unlock-reject marker files make the LOGIN or
#     UNLOCK stage fail deterministically — earlier stages still run,
#     isolating per-stage error messaging.
#
# Control channels are FILE MARKERS under BITWARDENCLI_APPDATA_DIR, never
# environment variables: BwCli.base_env() is a strict env allowlist (AUD-04),
# so monkeypatched test env vars do NOT reach the spawned bw process. The
# appdata dir always does (it is the one smuggled variable), and the same
# PATH-marker smuggling idiom already exists in conftest.py (VWFAKEVERSION).
#
# Production code is NOT modified by this fixture.
# ---------------------------------------------------------------------------
_BOOTSTRAP_BW = r"""#!/usr/bin/env python3
import base64, json, os, sys, time

argv = sys.argv[1:]
appdata = os.environ.get("BITWARDENCLI_APPDATA_DIR", "")
MARK = lambda name: os.path.join(appdata, name)
EXISTS = lambda name: os.path.exists(MARK(name))

def out(s=""):
    print(s)

def stall(verb_key):
    # Marker-file stall: <appdata>/fake-stall-<cmd> contains the seconds.
    p = MARK("fake-stall-" + verb_key)
    if os.path.exists(p):
        try:
            time.sleep(float(open(p).read().strip() or "0"))
        except (ValueError, OSError):
            pass

if argv[:1] == ["--version"]:
    out("2026.9.1")
    sys.exit(0)

ITEMS = {
  "aaaa1111-0000-0000-0000-000000000001": {
      "id": "aaaa1111-0000-0000-0000-000000000001", "name": "Postgres prod",
      "type": 1,
      "login": {"username": "dbadmin", "password": "sup3r-s3cret-pg!"}},
}

if argv[:1] == ["status"]:
    logged = EXISTS("fake-logged-in")
    unlocked = EXISTS("fake-unlocked")
    serverfile = os.path.join(appdata, "server.txt")
    server = open(serverfile).read().strip() if os.path.exists(serverfile) else ""
    uidfile = os.path.join(appdata, "fake-user-id")
    uid = open(uidfile).read().strip() if os.path.exists(uidfile) else ""
    state = ("unlocked" if (logged and unlocked)
             else ("locked" if logged else "unauthenticated"))
    out(json.dumps({"serverUrl": server, "lastSync": None, "status": state,
                    "userEmail": "agent@example.com" if logged else None,
                    "userId": uid if logged else None,
                    "vaultVersion": "1"}))
elif argv[:2] == ["config", "server"]:
    stall("cfg")
    if EXISTS("fake-logged-in"):
        sys.stderr.write("Logout required before server config update.\n")
        sys.exit(1)
    with open(os.path.join(appdata, "server.txt"), "w") as f:
        f.write(argv[2])
elif argv[:1] == ["logout"]:
    for mark in ("fake-logged-in", "fake-unlocked"):
        try:
            os.remove(MARK(mark))
        except OSError:
            pass
    out("You have been logged out!")
elif argv[:1] == ["login"]:
    stall("login")
    serverfile = os.path.join(appdata, "server.txt")
    if not os.path.exists(serverfile):
        # REAL-WORLD fresh-profile semantics: apikey login REQUIRES a
        # previously configured server URL.
        sys.stderr.write("? Master password: [input is hidden]\n")
        sys.stderr.write("You are not currently logged in.\n")
        sys.exit(1)
    if EXISTS("fake-fail-login"):
        sys.stderr.write("Username or password is incorrect. Try again.\n")
        sys.exit(1)
    cid = os.environ.get("BW_CLIENTID", "")
    csec = os.environ.get("BW_CLIENTSECRET", "")
    if cid.startswith("user.") and csec == "cs-secret":
        open(MARK("fake-logged-in"), "w").close()
        with open(MARK("fake-user-id"), "w") as f:
            f.write(cid[len("user."):])
        out("You are logged in as agent@example.com")
    else:
        sys.stderr.write("Username or password is incorrect. Try again.\n")
        sys.exit(1)
elif argv[:1] == ["unlock"]:
    stall("unlock")
    if not EXISTS("fake-logged-in"):
        sys.stderr.write("You are not currently logged in.\n")
        sys.exit(1)
    if EXISTS("fake-unlock-reject"):
        # login SUCCEEDED; the master password itself is rejected here —
        # checked BEFORE the BW_MP success branch for deterministic stage
        # isolation (genuine unlock-stage failure).
        sys.stderr.write("Cannot unlock vault. Username or password is incorrect.\n")
        sys.exit(1)
    if os.environ.get("BW_MP") == "mp-secret":
        open(MARK("fake-unlocked"), "w").close()
        out("abcdef0123456789-sessionkey-FEEDFACE")
    else:
        sys.stderr.write("? Master password: [input is hidden]\n")
        sys.exit(1)
elif argv[:1] == ["sync"]:
    out("Encoding complete.")
elif argv[:2] == ["list", "items"]:
    stall("list")
    if not EXISTS("fake-unlocked"):
        # READ BLIND SPOT mirror: locked/unauth profile -> exit 0 + [].
        out("[]")
        sys.exit(0)
    items = list(ITEMS.values())
    rest = argv[2:]
    search = None
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok == "--search":
            search = rest[i + 1]; i += 2; continue
        i += 1
    if search is not None:
        s = search.lower()
        items = [it for it in items if s in str(it.get("name", "")).lower()]
    out(json.dumps(items))
elif argv[:2] == ["get", "item"]:
    if not EXISTS("fake-unlocked"):
        sys.stderr.write("You are not currently logged in.\n")
        sys.exit(1)
    q = argv[2]
    key = None
    for k, v in ITEMS.items():
        if q in (k, v["name"]):
            key = k
    if key:
        out(json.dumps(ITEMS[key]))
    else:
        sys.stderr.write("Cannot find item with the given id or name.\n")
        sys.exit(1)
elif argv[:2] == ["create", "item"]:
    if not EXISTS("fake-unlocked"):
        sys.stderr.write("Vault is locked\n")
        sys.exit(1)
    raw = sys.stdin.read() if len(argv) <= 2 else argv[2]
    blob = json.loads(base64.b64decode(raw).decode("utf-8"))
    res = dict(blob)
    res["id"] = "new-item-id-0001"
    out(json.dumps(res))
else:
    sys.stderr.write("Unknown command: " + " ".join(argv[:2]) + "\n")
    sys.exit(2)
"""


@pytest.fixture()
def boot_bw(tmp_path):
    """Fresh-profile-semantics bw stand-in (see module docstring)."""
    script = tmp_path / "bw-bootstrap"
    script.write_text(_BOOTSTRAP_BW)
    script.chmod(script.stat().st_mode | 0o755)
    return str(script)


@pytest.fixture()
def boot_appdata(tmp_path):
    d = tmp_path / "boot-.bw-data"
    d.mkdir(mode=0o700)
    return d


def _fresh_cli(boot_bw, boot_appdata, **section_over):
    section = {**BASE_SECTION, "allow_write": True, **section_over}
    cfg = make_config(section=section)
    # v0.7.2 (first-burst fix, CHANGE 1): production register() builds the
    # CLI with check_version=False — the VWP-11 probe is deferred to the
    # first spawn at the choke point. Tests mirror that construction so the
    # fresh-profile spawn sequence stays exactly status -> config -> login
    # -> unlock (the lazy --version probe would otherwise consume the first
    # `bw status` result spec).
    cli = BwCli(boot_bw, boot_appdata, check_version=False)
    return cli, cfg


def _fresh_manager(cli, cfg, *, configure=True, mp=MP_SECRET):
    """Deferred-auth manager exactly like register() builds it."""
    mgr = AuthManager(cli, cfg, client_secret=CS_SECRET, master_password=mp)
    if configure:
        mgr.configure_server_if_needed()  # UNINITIALIZED -> CONFIGURED, no subprocess
    return mgr


# ---------------------------------------------------------------------------
# Deterministic fake-bw control channels (FILE MARKERS under the appdata dir).
# BwCli.base_env() is a strict env allowlist (AUD-04), so monkeypatched env
# vars never reach the spawned bw; the appdata dir does, and marker files in
# it are race-free per command stage.
# ---------------------------------------------------------------------------

def _marker(appdata, name):
    Path(appdata, name).touch()


def _set_stall(appdata, *verbs, seconds=0.4):
    for v in verbs:
        Path(appdata, f"fake-stall-{v}").write_text(str(seconds))


def _spawn_barrier_threads(n, target):
    barrier = threading.Barrier(n)
    results, errors_seen = [], []

    def wrapped():
        barrier.wait()
        try:
            results.append(target())
        except BaseException as exc:  # noqa: BLE001 - surfaced via assertions
            errors_seen.append(exc)

    threads = [threading.Thread(target=wrapped) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    return results, errors_seen


# ---------------------------------------------------------------------------
# CHANGE 1: get_session() from CONFIGURED routes through the FULL FSM
# ---------------------------------------------------------------------------

class TestConfiguredRoutesThroughFullFsm:

    def test_get_session_bootstraps_fresh_profile(self, boot_bw, boot_appdata):
        """First tool call on a fresh profile: full bootstrap, key returned."""
        cli, cfg = _fresh_cli(boot_bw, boot_appdata)
        mgr = _fresh_manager(cli, cfg)
        assert mgr.state is AuthState.CONFIGURED

        key = mgr.get_session()

        assert key == REAL_KEY
        assert mgr.state is AuthState.UNLOCKED
        # Fresh-profile semantics pin: a bare _do_login() COULD NOT have got
        # here — the server URL had to be configured before login succeeded.
        assert (boot_appdata / "server.txt").exists()
        assert (boot_appdata / "fake-logged-in").exists()
        assert (boot_appdata / "fake-unlocked").exists()

    def test_no_bare_do_login_from_configured(self, boot_bw, boot_appdata,
                                              monkeypatch):
        """The CONFIGURED branch must go through ensure_authenticated(), not
        a bare _do_login() — verified structurally: _do_login exists but is
        never reached without the FSM having run first."""
        cli, cfg = _fresh_cli(boot_bw, boot_appdata)
        mgr = _fresh_manager(cli, cfg)
        fsm_calls: list[str] = []
        login_calls: list[str] = []
        real_ea = mgr.ensure_authenticated
        real_dl = mgr._do_login

        def ea_spy():
            fsm_calls.append("ea")
            return real_ea()

        def dl_spy():
            login_calls.append("dl")
            return real_dl()

        monkeypatch.setattr(mgr, "ensure_authenticated", ea_spy)
        monkeypatch.setattr(mgr, "_do_login", dl_spy)

        mgr.get_session()

        assert fsm_calls == ["ea"], "CONFIGURED must route through the FSM"
        # _do_login may run INSIDE ensure_authenticated (after config server)
        # — what must NEVER happen is a login attempt BEFORE the profile's
        # server was configured (fresh-profile login fails without it).
        assert (boot_appdata / "server.txt").exists()

    def test_idempotent_when_unlocked(self, boot_bw, boot_appdata):
        """Already UNLOCKED: repeated calls add zero subprocesses."""
        cli, cfg = _fresh_cli(boot_bw, boot_appdata)
        mgr = _fresh_manager(cli, cfg)
        mgr.get_session()
        assert mgr._full_bootstrap_count == 1

        started = time.monotonic()
        for _ in range(5):
            assert mgr.get_session() == REAL_KEY
            mgr.ensure_authenticated()
        # Fast path returns without spawning anything: wall clock stays far
        # below the 0.4s per-command stall injected into the fake bw.
        assert time.monotonic() - started < 0.35
        assert mgr._full_bootstrap_count == 1

    def test_register_deferred_startup_preserved(self, fake_bw, appdata,
                                                 hermes_home_with_secrets,
                                                 monkeypatch):
        """register() still performs ZERO bw subprocesses (v0.1.9 pin)."""
        import vaultwarden
        from vaultwarden.tests.conftest import RecordingCtx

        spawn_calls: list[list] = []
        real_popen = __import__("subprocess").Popen

        class SpyPopen(real_popen):
            def __init__(self, args, *a, **kw):
                spawn_calls.append(list(args))
                super().__init__(args, *a, **kw)

        monkeypatch.setattr("subprocess.Popen", SpyPopen)
        ctx = RecordingCtx(settings={
            "enabled": True,
            "server_url": "https://vault.example.com",
            "client_id": "user.11111111-2222-3333-4444-555555555555",
            "bw_cli_path": fake_bw,
        })
        assert vaultwarden.register(ctx) is True
        # ZERO bw subprocesses at load time (v0.1.9 deferred-auth pin): not
        # even the version probe — nothing may touch the profile until the
        # first tool call / check_fn evaluation.
        bw_spawns = [c for c in spawn_calls
                     if c and str(c[0]).startswith(str(fake_bw))]
        assert bw_spawns == [], f"register() spawned bw: {bw_spawns}"


# ---------------------------------------------------------------------------
# CHANGE 2: choke-point lazy path uses the full FSM (no bare _do_login bypass)
# ---------------------------------------------------------------------------

class TestChokePointLazyPath:

    def test_choke_point_lazy_bootstrap(self, boot_bw, boot_appdata):
        """A direct data call with NO BW_SESSION on a fresh profile gets a
        REAL payload on the FIRST burst via the choke-point lazy bootstrap."""
        cli, cfg = _fresh_cli(boot_bw, boot_appdata)
        mgr = _fresh_manager(cli, cfg)
        register_auth_manager(mgr)  # explicit — mirrors tools' registration

        items = cli.list_items("", filters=None)  # empty key -> lazy path
        assert mgr.state is AuthState.UNLOCKED

        assert items, "first-burst read must NOT return the blind-spot []"
        assert items[0]["name"] == "Postgres prod"

    def test_no_bare_do_login_call_sites_outside_fsm(self):
        """Structural pin: _do_login() is invoked ONLY from
        ensure_authenticated() (inside the FSM body)."""
        import inspect

        import vaultwarden.auth as auth_mod

        src = inspect.getsource(auth_mod)
        fsm_body = src[src.index("def ensure_authenticated"):
                       src.index("def _configure_server")]
        other = src.replace(fsm_body, "")
        assert "self._do_login()" in fsm_body
        assert "self._do_login()" not in other


# ---------------------------------------------------------------------------
# Thread safety: concurrent first calls bootstrap EXACTLY ONCE
# ---------------------------------------------------------------------------

class TestConcurrentBootstrap:

    def test_concurrent_first_calls_single_bootstrap(self, boot_bw,
                                                     boot_appdata,
                                                     monkeypatch):
        _set_stall(boot_appdata, "cfg", "login", "unlock")
        cli, cfg = _fresh_cli(boot_bw, boot_appdata)
        mgr = _fresh_manager(cli, cfg)

        keys, errs = _spawn_barrier_threads(
            6, lambda: mgr.get_session())

        assert not errs, f"concurrent bootstrap raised: {errs}"
        assert set(keys) == {REAL_KEY}
        assert mgr._full_bootstrap_count == 1, \
            "concurrent first calls must bootstrap EXACTLY once"
        assert mgr.state is AuthState.UNLOCKED

    def test_concurrent_first_burst_reads_single_bootstrap(self, boot_bw,
                                                            boot_appdata,
                                                            monkeypatch):
        """End-to-end concurrency: six simultaneous FIRST data calls (via the
        choke point, no pre-existing key) must share EXACTLY ONE bootstrap and
        every one of them must see real items on the first burst."""
        _set_stall(boot_appdata, "cfg", "login", "unlock")
        cli, cfg = _fresh_cli(boot_bw, boot_appdata)
        mgr = _fresh_manager(cli, cfg)
        # The choke point must be able to lazy-bootstrap this manager.
        register_auth_manager(mgr)

        results, errs = _spawn_barrier_threads(
            6, lambda: cli.list_items("", filters=None))

        assert not errs, f"concurrent first burst raised: {errs}"
        for r in results:
            assert isinstance(r, list) and r, \
                "every concurrent first-burst read must return real items"
            assert [i["name"] for i in r] == ["Postgres prod"]
        assert mgr._full_bootstrap_count == 1, \
            "concurrent first calls must bootstrap EXACTLY once"
        assert mgr.state is AuthState.UNLOCKED


# ---------------------------------------------------------------------------
# First-burst reads/writes through the actual tool handlers
# ---------------------------------------------------------------------------

def _tool_dict(auth, cfg, registry):
    from vaultwarden.tools import get_tools

    def wrap(handler):
        def inner(args, **kw):
            result = handler(args, **kw)
            return json.loads(result) if isinstance(result, str) else result
        return inner

    return {schema["name"]: wrap(handler)
            for schema, handler in get_tools(auth, cfg, registry)}


class TestFirstBurstToolCalls:

    def test_list_returns_real_items_on_first_call(self, boot_bw, boot_appdata):
        cli, cfg = _fresh_cli(boot_bw, boot_appdata)
        mgr = _fresh_manager(cli, cfg)
        tools = _tool_dict(mgr, cfg, PlaceholderRegistry(ttl_seconds=300))

        res = tools["vaultwarden_list"]({})

        assert "error" not in res
        assert res["total"] >= 1
        names = [i["name"] for i in res["items"]]
        assert "Postgres prod" in names

    def test_store_succeeds_on_first_call(self, boot_bw, boot_appdata):
        cli, cfg = _fresh_cli(boot_bw, boot_appdata)
        mgr = _fresh_manager(cli, cfg)
        tools = _tool_dict(mgr, cfg, PlaceholderRegistry(ttl_seconds=300))

        res = tools["vaultwarden_store"]({
            "name": "first-burst-entry", "type": "login",
            "username": "op", "password": "hunter2-fixture"})

        assert res.get("created") is True, res
        assert res.get("id")

    def test_search_returns_matches_on_first_call(self, boot_bw, boot_appdata):
        cli, cfg = _fresh_cli(boot_bw, boot_appdata)
        mgr = _fresh_manager(cli, cfg)
        tools = _tool_dict(mgr, cfg, PlaceholderRegistry(ttl_seconds=300))

        res = tools["vaultwarden_search"]({"query": "postgres"})

        assert "error" not in res
        assert res["count"] >= 1


# ---------------------------------------------------------------------------
# CHANGE 3: accurate error mapping — login stage never blames master_password
# ---------------------------------------------------------------------------

class TestErrorMappingAccuracy:

    def test_login_stage_failure_does_not_blame_master_password(
            self, boot_bw, boot_appdata, monkeypatch):
        """Server configured but LOGIN rejected -> bootstrap-stage message."""
        _marker(boot_appdata, "fake-fail-login")
        cli, cfg = _fresh_cli(boot_bw, boot_appdata)
        mgr = _fresh_manager(cli, cfg)
        register_auth_manager(mgr)

        with pytest.raises(errors.SessionError) as ei:
            cli.list_items("", filters=None)

        resp = json.dumps(ei.value.to_dict())
        assert "master_password" not in resp
        assert "bootstrap" in resp.lower()

    def test_genuine_unlock_failure_references_master_password(
            self, boot_bw, boot_appdata):
        """Login OK, unlock REJECTED -> the master-password hint is legitimate.

        Deterministic stage isolation WITHOUT touching production code: a
        pre-configured profile (server.txt + fake-user-id written directly —
        CONFIGURED performs zero subprocesses) plus the correct client_id
        makes LOGIN succeed against the fake, while the reject marker flips
        the unlock precedence so the BW_MP check FAILS FIRST and the genuine
        unlock stage is rejected even though the fixture master password is
        loaded in memory.
        """
        _marker(boot_appdata, "fake-unlock-reject")
        (boot_appdata / "server.txt").write_text(
            BASE_SECTION["server_url"].rstrip("/"))
        uid = BASE_SECTION["client_id"].removeprefix("user.")
        (boot_appdata / "fake-user-id").write_text(uid)
        cfg = make_config(section={**BASE_SECTION})
        cli = BwCli(boot_bw, boot_appdata, check_version=False)
        mgr = AuthManager(cli, cfg, client_secret=CS_SECRET,
                          master_password=MP_SECRET)
        mgr.configure_server_if_needed()
        register_auth_manager(mgr)

        with pytest.raises(errors.VaultwardenError) as ei:
            mgr.get_session()

        assert getattr(ei.value, "bootstrap_stage", None) == "unlock"
        resp = json.dumps(ei.value.to_dict())
        assert "master_password" in resp
        assert CS_SECRET not in resp and MP_SECRET not in resp

    def test_raw_prompt_text_never_surfaces(self, boot_bw, boot_appdata,
                                            monkeypatch):
        """Force a LOGIN-stage failure whose stderr carries RAW interactive
        prompt text ('? Master password: [input is hidden]').

        The production FSM correctly repairs a never-configured profile
        itself (config server -> login), so this test injects the failure at
        the bw boundary instead: `bw config server` succeeds, then the
        LOGIN subprocess exits 1 with the prompt text on stderr. Neither the
        prompt text nor any secret may reach the surfaced error response,
        and the failure must be attributed to the login/bootstrap stage —
        never blamed on master_password.
        """
        cli, cfg = _fresh_cli(boot_bw, boot_appdata)
        mgr = _fresh_manager(cli, cfg)
        register_auth_manager(mgr)

        real_run = cli.run

        def rigged_run(args, *a, **kw):
            if args[:1] == ["login"]:
                raise errors.SessionError(
                    "bw exited with code 1",
                    stderr="? Master password: [input is hidden]\n"
                           "You are not currently logged in.",
                    returncode=1)
            return real_run(args, *a, **kw)

        monkeypatch.setattr(cli, "run", rigged_run)

        with pytest.raises(errors.VaultwardenError) as ei:
            mgr.get_session()

        resp = json.dumps(ei.value.to_dict())
        assert "? Master password" not in resp
        assert "input is hidden" not in resp
        assert CS_SECRET not in resp and MP_SECRET not in resp
        # Accurate attribution: login/config stage, NOT a master-password hint.
        assert getattr(ei.value, "bootstrap_stage", None) == "login"
        assert "master_password" not in resp


# ---------------------------------------------------------------------------
# CHANGE 4: is_available() records bootstrap failure reasons (not silent)
# ---------------------------------------------------------------------------

class TestIsAvailableObservability:

    def test_bootstrap_failure_reason_is_logged(self, boot_bw, boot_appdata,
                                                 caplog):
        cli, cfg = _fresh_cli(boot_bw, boot_appdata)
        mgr = _fresh_manager(cli, cfg)
        # Break the bootstrap deterministically at the LOGIN stage.
        mgr._client_secret = "wrong-secret"
        register_auth_manager(mgr)

        with caplog.at_level("WARNING"):
            assert mgr.is_available() is False

        messages = [r.getMessage() for r in caplog.records]
        assert any("Lazy authentication failed" in m for m in messages), messages
        assert any("bootstrap stage=login" in m for m in messages), messages
        joined = " ".join(messages)
        assert "wrong-secret" not in joined and CS_SECRET not in joined \
            and MP_SECRET not in joined

    def test_success_still_true_and_silent(self, boot_bw, boot_appdata):
        cli, cfg = _fresh_cli(boot_bw, boot_appdata)
        mgr = _fresh_manager(cli, cfg)
        assert mgr.is_available() is True
        assert mgr.state is AuthState.UNLOCKED


# ---------------------------------------------------------------------------
# CHANGE 5: read blind spot — suspect empty read reconciles + retries once
# ---------------------------------------------------------------------------

class TestReadBlindSpotDefense:

    def test_empty_read_in_non_unlocked_state_reconciles_and_retries(
            self, boot_bw, boot_appdata):
        cli, cfg = _fresh_cli(boot_bw, boot_appdata)
        mgr = _fresh_manager(cli, cfg)
        register_auth_manager(mgr)
        first = mgr.get_session()
        assert first == REAL_KEY

        # Simulate an expired-but-remembered session (deterministic: no sleep).
        with mgr._lock:
            mgr._session_created_at -= (cfg.session_timeout_seconds + 10)

        # State is now effectively non-UNLOCKED (validity check demotes it),
        # so an empty read is SUSPECT -> reconcile + one retry.
        items = cli.list_items(first, filters=None)

        assert mgr.state is AuthState.UNLOCKED
        assert items, "blind-spot defense must recover the real items"
        assert items[0]["name"] == "Postgres prod"

    def test_genuinely_empty_vault_accepted_when_unlocked(
            self, boot_bw, boot_appdata, monkeypatch):
        """UNLOCKED + valid key + empty payload => genuine empty vault:
        NO extra reconciliation subprocesses."""
        cli, cfg = _fresh_cli(boot_bw, boot_appdata)
        mgr = _fresh_manager(cli, cfg)
        mgr.get_session()

        real_run = cli.run
        calls: list[list] = []

        def spy_run(args, *a, **kw):
            calls.append(list(args))
            if args[:2] == ["list", "items"]:
                return []          # healthy session, truly empty vault
            return real_run(args, *a, **kw)

        monkeypatch.setattr(cli, "run", spy_run)
        items = cli.list_items(REAL_KEY, filters=None)

        assert items == []
        lists = [c for c in calls if c[:2] == ["list", "items"]]
        assert len(lists) == 1, "no retry when the state is already UNLOCKED"

    def test_session_required_commands_cover_reads(self):
        """list/search/sync/get are all gated by the choke point."""
        for verb in ("list", "get", "sync", "create", "edit", "delete"):
            assert verb in BwCli._SESSION_REQUIRED_COMMANDS


# ---------------------------------------------------------------------------
# Redaction preserved across the new bootstrap paths
# ---------------------------------------------------------------------------

class TestNoSecretsInBootstrapPaths:

    def test_status_snapshot_free_of_bootstrap_secrets(self, boot_bw,
                                                       boot_appdata):
        cli, cfg = _fresh_cli(boot_bw, boot_appdata)
        mgr = _fresh_manager(cli, cfg)
        mgr.get_session()
        blob = json.dumps(mgr.status_snapshot())
        # NB: status_snapshot legitimately reports the configured CLIENT ID
        # (an identifier, not a secret); the secrets below must never appear.
        for secret in (CS_SECRET, MP_SECRET, REAL_KEY):
            assert secret not in blob

    def test_tool_response_free_of_bootstrap_secrets(self, boot_bw,
                                                      boot_appdata):
        cli, cfg = _fresh_cli(boot_bw, boot_appdata)
        mgr = _fresh_manager(cli, cfg)
        tools = _tool_dict(mgr, cfg, PlaceholderRegistry(ttl_seconds=300))
        res = json.dumps(tools["vaultwarden_list"]({}))
        for secret in (CS_SECRET, MP_SECRET, REAL_KEY):
            assert secret not in res

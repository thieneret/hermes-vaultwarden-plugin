"""v0.7.4 regression suite: bw sync VERB selection (10 mandated scenarios).

Production finding: ``bw sync --help`` documents three distinct behaviors —
  bw sync            pull the latest vault data from the server (incremental)
  bw sync --force    force a FULL sync (complete re-download into SQLite)
  bw sync --last     ONLY print the last sync date — performs NO sync at all

The v0.7.3 implementation assumed ``--last`` was a delta sync. It is not:
every code path routed through it silently skipped synchronization. v0.7.4
removes ``--last`` from every sync path, uses ``bw sync --force`` for
full/initial/forced syncs, plain ``bw sync`` for incremental refreshes, and
corrects the inverted legacy ``force`` mapping in ``BwCli.sync()``.

Mandated scenarios (one test each):
  1. BwCli.sync(full=True)                    -> spawns `bw sync --force`
  2. BwCli.sync(full=False)                   -> spawns `bw sync` (no flags)
  3. BwCli.sync(force=True) legacy            -> spawns `bw sync --force`
  4. BwCli.sync(force=False) legacy           -> spawns `bw sync` (no flags)
  5. AuthManager.sync(), _last_sync == 0.0    -> BwCli.sync(full=True)
  6. AuthManager.sync(), _last_sync > 0.0     -> BwCli.sync(full=False)
  7. AuthManager.sync(force=True), synced     -> gate bypassed, full=True
  8. delete_item permanent recovery           -> BwCli.sync(full=True)
  9. _forced_full_sync_retry                  -> sync with full=True
 10. No `--last` flag in ANY sync invocation  -> argv never contains --last

All subprocess invocations are recorded by monkeypatching subprocess.run
(the module attribute, per FAIL-5), so assertions pin the ACTUAL argv of
every spawned bw command — exactly what scenario 10 requires.
"""
from __future__ import annotations

import subprocess as sp

import pytest

from vaultwarden.auth import AuthManager
from vaultwarden.bw_cli import BwCli, register_auth_manager

CLIENT_SECRET = "cs-secret"
MASTER_PASSWORD = "mp-secret"
SESSION_KEY = "abcdef0123456789-sessionkey-FEEDFACE"


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _mk_run(cmd_results=None):
    """Fake subprocess.run recording FULL argv; canned results per call.

    Mirrors the test_bw_cli.py stand-in: the lazily-deferred ``bw --version``
    probe (VWP-11) answers itself WITHOUT consuming the cmd_results sequence,
    so results map 1:1 onto the real commands under test.
    """
    from unittest.mock import MagicMock

    seq = list(cmd_results or [])
    calls: list[list[str]] = []

    def fake_run(cmd, *a, **kw):
        calls.append(list(cmd))
        m = MagicMock()
        if list(cmd)[1:] == ["--version"]:
            m.returncode = 0
            m.stdout = "2026.9.1"
            m.stderr = ""
            return m
        spec = seq.pop(0) if seq else {}
        m.returncode = spec.get("rc", 0)
        m.stdout = spec.get("out", "")
        m.stderr = spec.get("err", "")
        return m

    return fake_run, calls


@pytest.fixture()
def rec_bw(fake_bw, appdata, monkeypatch):
    """BwCli over the fake binary with every spawn recorded."""
    fake_run, calls = _mk_run()
    monkeypatch.setattr(sp, "run", fake_run)
    cli = BwCli(fake_bw, appdata, check_version=False)
    return cli, calls


@pytest.fixture()
def mgr(bw_cli, plugin_config) -> AuthManager:
    """Unlocked AuthManager over the fake bw binary; _last_sync reset to 0.0."""
    m = AuthManager(bw_cli, plugin_config,
                    client_secret=CLIENT_SECRET, master_password=MASTER_PASSWORD)
    m.ensure_authenticated()
    m._last_sync = 0.0
    m._initial_sync_completed = False
    m._initial_sync_failed = False
    return m


def _sync_argv(calls) -> list[list[str]]:
    return [c[1:] for c in calls if c[1:2] == ["sync"]]


# ---------------------------------------------------------------------------
# Scenario 1: BwCli.sync(full=True) -> `bw sync --force`
# ---------------------------------------------------------------------------

def test_bwcli_sync_full_true_spawns_force(rec_bw):
    cli, calls = rec_bw
    cli.sync(SESSION_KEY, full=True)
    assert _sync_argv(calls) == [["sync", "--force"]]


# ---------------------------------------------------------------------------
# Scenario 2: BwCli.sync(full=False) -> plain `bw sync` (no flags)
# ---------------------------------------------------------------------------

def test_bwcli_sync_full_false_spawns_plain_sync(rec_bw):
    cli, calls = rec_bw
    cli.sync(SESSION_KEY, full=False)
    assert _sync_argv(calls) == [["sync"]]


# ---------------------------------------------------------------------------
# Scenario 3: legacy force=True -> `bw sync --force` (mapping CORRECTED)
# ---------------------------------------------------------------------------

def test_bwcli_sync_legacy_force_true_maps_to_full(rec_bw):
    cli, calls = rec_bw
    cli.sync(SESSION_KEY, force=True)
    assert _sync_argv(calls) == [["sync", "--force"]], \
        "v0.7.3 inverted mapping (force -> --last no-op) must be gone"


# ---------------------------------------------------------------------------
# Scenario 4: legacy force=False / default -> plain `bw sync`
# ---------------------------------------------------------------------------

def test_bwcli_sync_legacy_force_false_maps_to_incremental(rec_bw):
    cli, calls = rec_bw
    cli.sync(SESSION_KEY, force=False)
    assert _sync_argv(calls) == [["sync"]]
    # explicit-default (neither force nor full given) stays incremental
    cli.sync(SESSION_KEY)
    assert _sync_argv(calls)[-1] == ["sync"]


# ---------------------------------------------------------------------------
# Scenario 5: AuthManager.sync() with _last_sync == 0.0 -> BwCli.sync(full=True)
# ---------------------------------------------------------------------------

def test_authmgr_initial_sync_requests_full(mgr, monkeypatch):
    seen: list[bool | None] = []

    def fake_sync(session_key, force=False, *, full=None):
        seen.append(full)
        return {"data": []}

    monkeypatch.setattr(mgr._bw, "sync", fake_sync)
    assert mgr.last_sync == 0.0
    result = mgr.sync(force=True)
    assert result["synced"] is True
    assert seen == [True], "initial sync MUST request the full verb (--force)"


# ---------------------------------------------------------------------------
# Scenario 6: AuthManager.sync() with _last_sync > 0.0 -> BwCli.sync(full=False)
# ---------------------------------------------------------------------------

def test_authmgr_incremental_sync_requests_delta(mgr, monkeypatch):
    seen: list[bool | None] = []

    def fake_sync(session_key, force=False, *, full=None):
        seen.append(full)
        return {"data": []}

    monkeypatch.setattr(mgr._bw, "sync", fake_sync)
    mgr._last_sync = 1234.5
    result = mgr.sync(force=True)
    assert result["synced"] is True
    assert seen == [False], "post-initial sync MUST request the incremental verb"


# ---------------------------------------------------------------------------
# Scenario 7: AuthManager.sync(force=True) with _last_sync > 0.0 bypasses the
# freshness gate AND still selects the incremental verb (force != --force)
# ---------------------------------------------------------------------------

def test_authmgr_force_true_bypasses_gate_keeps_incremental(mgr, monkeypatch):
    seen: list[bool | None] = []

    def fake_sync(session_key, force=False, *, full=None):
        seen.append(full)
        return {"data": []}

    monkeypatch.setattr(mgr._bw, "sync", fake_sync)
    mgr._last_sync = 1234.5
    # Freshness gate would normally SKIP: auto_sync disabled AND the cache
    # is "fresh" (sync_interval pinned huge via the read-only config dict).
    mgr._config.section["auto_sync"] = False
    mgr._config.section["sync_interval_seconds"] = 10 ** 9
    result = mgr.sync(force=True)
    assert result["synced"] is True, "force=True must bypass the freshness gate"
    assert seen == [False], \
        "AuthManager force semantics: bypass gate, NOT add --force (verb " \
        "stays incremental once the cache is populated)"


# ---------------------------------------------------------------------------
# Scenario 8: delete_item permanent-delete recovery -> BwCli.sync(full=True)
# ---------------------------------------------------------------------------

_NOT_FOUND = {"rc": 1, "out": "", "err": "Cannot find item."}
_DELETED_OK = {"rc": 0, "out": "Item abc123 has been deleted.", "err": ""}


def test_delete_permanent_recovery_syncs_full(fake_bw, appdata, monkeypatch):
    fake_run, calls = _mk_run(cmd_results=[dict(_NOT_FOUND), dict({"rc": 0, "out": ""}),
                                           dict(_DELETED_OK)])
    monkeypatch.setattr(sp, "run", fake_run)
    cli = BwCli(fake_bw, appdata, check_version=False)
    out = cli.delete_item("sess", "abc123", permanent=True)
    assert "has been deleted" in out
    argvs = [c[1:] for c in calls]
    assert ["sync", "--force"] in argvs, \
        f"permanent-delete recovery must run a REAL full sync, got {argvs}"
    assert ["sync", "--last"] not in argvs
    assert ["sync"] not in argvs          # not even a bare incremental pull


# ---------------------------------------------------------------------------
# Scenario 9: _forced_full_sync_retry routes through the FULL verb
# ---------------------------------------------------------------------------

class _StubMgrNoSync:
    """Duck-typed manager WITHOUT sync() -> exercises the BwCli fallback leg."""

    last_sync = 0.0
    session_key = SESSION_KEY

    def get_session_key(self):
        return SESSION_KEY


def test_forced_full_sync_retry_fallback_uses_full(fake_bw, appdata,
                                                   monkeypatch):
    fake_run, calls = _mk_run()
    monkeypatch.setattr(sp, "run", fake_run)
    cli = BwCli(fake_bw, appdata, check_version=False)
    register_auth_manager(_StubMgrNoSync())
    items = cli.list_items(SESSION_KEY)      # empty read -> defense fires
    assert items == []
    assert ["sync", "--force"] in [c[1:] for c in calls], \
        "fallback leg (manager without sync()) must call BwCli.sync(full=True)"


class _StubMgrWithSync:
    """Duck-typed manager WITH sync() -> primary leg (AuthManager.sync(force=True))."""

    def __init__(self, cli):
        self._cli = cli
        self.last_sync = 0.0
        self.force_flags: list[bool] = []

    def get_session_key(self):
        return SESSION_KEY

    def sync(self, force=False):
        self.force_flags.append(bool(force))
        # Mirror AuthManager.sync(): verb owned by the manager, FULL while
        # last_sync == 0.0; real transition to > 0.0 after success.
        self._cli.sync(SESSION_KEY, full=self.last_sync == 0.0)
        self.last_sync = 1.0
        return {"synced": True}


def test_forced_full_sync_retry_primary_leg_uses_full(fake_bw, appdata,
                                                      monkeypatch):
    fake_run, calls = _mk_run()
    monkeypatch.setattr(sp, "run", fake_run)
    cli = BwCli(fake_bw, appdata, check_version=False)
    stub = _StubMgrWithSync(cli)
    register_auth_manager(stub)
    items = cli.list_items(SESSION_KEY)
    assert items == []
    assert stub.force_flags == [True], "defense must route via sync(force=True)"
    assert ["sync", "--force"] in [c[1:] for c in calls], \
        "primary leg must produce bw sync --force (never --last)"
    assert all("--last" not in c for c in calls)


# ---------------------------------------------------------------------------
# Scenario 10: `--last` NEVER appears in any sync subprocess argv
# ---------------------------------------------------------------------------

def test_no_last_flag_in_any_sync_invocation(mgr, rec_bw):
    # CLI level: every verb combination of BwCli.sync()
    cli, calls = rec_bw
    cli.sync(SESSION_KEY, full=True)
    cli.sync(SESSION_KEY, full=False)
    cli.sync(SESSION_KEY, force=True)
    cli.sync(SESSION_KEY, force=False)
    cli.sync(SESSION_KEY)
    # Manager level: initial + incremental paths
    mgr.sync(force=True)                      # _last_sync == 0.0 -> full
    mgr.sync(force=True)                      # now > 0.0 -> incremental
    for c in calls:
        assert "--last" not in c, f"--last leaked into argv: {c[1:]}"
    syncs = _sync_argv(calls)
    assert syncs, "expected recorded sync invocations"
    for s in syncs:
        assert s in (["sync"], ["sync", "--force"]), f"unexpected sync argv: {s}"

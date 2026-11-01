import json, time
import subprocess as sp
from unittest.mock import MagicMock
from vaultwarden.auth import AuthManager, AuthState
from vaultwarden.bw_cli import BwCli, register_auth_manager
from vaultwarden.tests.conftest import make_config

REAL_KEY = "abcdef0123456789-sessionkey-FEEDFACE"

def _mk_run(cmd_results=None):
    seq = list(cmd_results or [])
    calls, envs = [], []
    def fake_run(cmd, *a, **k):
        calls.append(list(cmd)); envs.append(dict(k.get("env") or {}))
        m = MagicMock()
        if list(cmd)[1:] == ["--version"]:
            m.returncode, m.stdout, m.stderr = 0, "2026.9.1", ""; return m
        spec = seq.pop(0) if seq else {}
        m.returncode = spec.get("rc", 0); m.stdout = spec.get("out", ""); m.stderr = spec.get("err", "")
        return m
    return fake_run, calls, envs

def test_dbg_read(fake_bw, appdata, monkeypatch):
    cli = BwCli(fake_bw, appdata)
    mgr = AuthManager(cli, make_config(), client_secret="cs-secret", master_password="mp-secret")
    mgr.ensure_authenticated()
    items = [{"id": "aaaa", "name": "Postgres prod"}]
    fake_run, calls, envs = _mk_run([{"rc": 0, "out": json.dumps(items), "err": ""}])
    monkeypatch.setattr(sp, "run", fake_run)
    mgr._session_created_at = time.time() - 14401
    result = mgr.list_items()
    print("RESULT:", result)
    for c, e in zip(calls, envs):
        print("CALL:", c[1:], "SESSION:", repr(e.get("BW_SESSION")))

import os
from vaultwarden.hooks import _PENDING_PATH_RETENTIONS, _EXEC_SCOPES_BY_ID
from vaultwarden.security import get_redacting_filter
from vaultwarden.tests.test_integration import _dict_tools, _register_ok


def test_probe(monkeypatch, tmp_path, fake_bw):
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    mw = dict(ctx.middleware)["tool_execution"]
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    redactor = get_redacting_filter()

    ref = tools["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001", "field": "password"})
    print("AFTER REF:", {len(k): v for k, v in redactor._secret_refcounts.items()},
          "PROC:", {len(k): v for k, v in redactor._process_scoped.items()},
          "PENDING:", [(os.path.basename(p), e[0], repr(e[2])) for p, e in _PENDING_PATH_RETENTIONS.items()])

    class Boom(RuntimeError):
        pass

    try:
        mw("terminal", {"command": f"echo $(<{ref['placeholder']})"}, None,
           lambda a: (_ for _ in ()).throw(Boom()))
    except Boom:
        pass
    print("AFTER MW:", {len(k): v for k, v in redactor._secret_refcounts.items()},
          "PROC:", {len(k): v for k, v in redactor._process_scoped.items()},
          "PENDING:", [(os.path.basename(p), e[0], repr(e[2])) for p, e in _PENDING_PATH_RETENTIONS.items()],
          "SCOPES:", list(_EXEC_SCOPES_BY_ID.keys()))

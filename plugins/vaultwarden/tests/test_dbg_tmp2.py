from vaultwarden.security import get_redacting_filter
from vaultwarden.tests.test_integration import _dict_tools, _register_ok

def test_dbg_exception(monkeypatch, tmp_path, fake_bw):
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    mw = dict(ctx.middleware)["tool_execution"]
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    redactor = get_redacting_filter()
    baseline = redactor.scoped_secret_count()
    ref = tools["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001", "field": "password"})

    class Boom(RuntimeError):
        pass

    try:
        mw("terminal", {"command": f"echo $(<{ref['placeholder']})"}, None,
           lambda a: (_ for _ in ()).throw(Boom()))
    except Boom:
        pass
    print("scoped after:", redactor.scoped_secret_count(), "baseline:", baseline)
    from vaultwarden import hooks
    print("registry left:", {k: v.closed for k, v in hooks._EXEC_SCOPES_BY_ID.items()})
    print("pending paths:", [(p, e[0]) for p, e in hooks._PENDING_PATH_RETENTIONS.items()])
    cur = hooks.current_execution_scope()
    print("cur scope:", cur, "closed?" , cur.closed if cur else None,
          "retained:", cur.retained_count() if cur else None)
    print("refcounts:", {len(k): v for k, v in redactor._secret_refcounts.items()})
    print("process:", {len(k): v for k, v in redactor._process_scoped.items()})

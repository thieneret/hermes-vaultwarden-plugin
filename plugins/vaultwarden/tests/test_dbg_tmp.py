def test_dbg(monkeypatch, tmp_path, fake_bw):
    from vaultwarden.security import get_redacting_filter
    from vaultwarden.tests.test_integration import _dict_tools, _register_ok

    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    mw = dict(ctx.middleware)["tool_execution"]
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    redactor = get_redacting_filter()

    ref = tools["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001", "field": "password"})

    class Boom(RuntimeError):
        pass

    import traceback
    orig_release = redactor.release_secret
    def traced_release(v):
        print("RELEASE len=", len(v), "".join(traceback.format_stack()[-4:-1]))
        return orig_release(v)
    redactor.release_secret = traced_release
    orig_retain = redactor.retain_secret
    def traced_retain(v):
        print("RETAIN len=", len(v), "".join(traceback.format_stack()[-4:-1]))
        return orig_retain(v)
    redactor.retain_secret = traced_retain

    try:
        mw("terminal", {"command": f"echo $(<{ref['placeholder']})"}, None,
           lambda a: (_ for _ in ()).throw(Boom()))
    except Boom:
        pass
    print("after mw raise scoped=", redactor.scoped_secret_count())

def test_probe2(monkeypatch, tmp_path, fake_bw):
    from vaultwarden.security import get_redacting_filter
    from vaultwarden.tests.test_integration import _dict_tools, _register_ok
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    r = get_redacting_filter()
    print("BASELINE", r.active_secret_count())
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    ref = tools["vaultwarden_get_secret_ref"]({"item_id": "aaaa1111-0000-0000-0000-000000000001", "field": "password"})
    mw = dict(ctx.middleware)["tool_execution"]
    post = dict(ctx.hooks)["post_tool_call"]
    def nc(a): return {"output":"ok"}
    res = mw("terminal", {"command": f"printf x \"$(<{ref['placeholder']})\""}, None, nc, task_id="probe2")
    print("AFTER MW", r.active_secret_count(), dict(r._secret_refcounts))
    post("terminal", {}, res, task_id="probe2")
    print("AFTER POST", r.active_secret_count(), dict(r._secret_refcounts), dict(r._process_scoped))
    assert False

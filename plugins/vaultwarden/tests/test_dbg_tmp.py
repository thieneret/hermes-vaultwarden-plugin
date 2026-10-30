def test_dbg(monkeypatch, tmp_path, fake_bw):
    from vaultwarden.security import get_redacting_filter
    from vaultwarden.tests.test_integration import _dict_tools, _register_ok

    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    mw = dict(ctx.middleware)["tool_execution"]
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    redactor = get_redacting_filter()

    rf = type(redactor)
    events = []
    orig_retain = rf.retain_secret
    orig_release = rf.release_secret
    orig_reg = rf.register_process_scoped_secret
    orig_rel_proc = rf.release_process_scoped_secret

    def patched_retain(self, v):
        events.append(("retain", len(v)))
        return orig_retain(self, v)
    def patched_release(self, v):
        import traceback
        st = traceback.extract_stack()
        caller = [f"{f.filename.split('/')[-1]}:{f.lineno}" for f in st[-4:-1]]
        events.append(("release", len(v), caller))
        return orig_release(self, v)
    def patched_reg(self, v):
        events.append(("regproc", len(v)))
        return orig_reg(self, v)
    def patched_relproc(self, v):
        events.append(("relproc", len(v)))
        return orig_relproc(self, v)
    monkeypatch.setattr(rf, "retain_secret", patched_retain)
    monkeypatch.setattr(rf, "release_secret", patched_release)
    monkeypatch.setattr(rf, "register_process_scoped_secret", patched_reg)
    monkeypatch.setattr(rf, "release_process_scoped_secret", patched_relproc)

    ref = tools["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001", "field": "password"})

    class Boom(RuntimeError):
        pass

    try:
        mw("terminal", {"command": f"echo $(<{ref['placeholder']})"}, None,
           lambda a: (_ for _ in ()).throw(Boom()))
    except Boom:
        pass
    print("EVENTS:")
    for e in events:
        print("  ", e)
    print("scoped count:", redactor.scoped_secret_count())
    print("active count:", redactor.active_secret_count())

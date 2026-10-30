def test_probe(monkeypatch, tmp_path, fake_bw):
    import vaultwarden.hooks as hooks
    from vaultwarden.security import get_redacting_filter
    from vaultwarden.tests.test_integration import _dict_tools, _register_ok

    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    mw = dict(ctx.middleware)["tool_execution"]
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    redactor = get_redacting_filter()
    ref = tools["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001", "field": "password"})

    orig_close = hooks.ExecutionSecretScope.close
    def tr(self):
        print("SCOPE.CLOSE called; closed=", self._closed)
        import traceback; traceback.print_stack(limit=5)
        return orig_close(self)
    hooks.ExecutionSecretScope.close = tr

    class Boom(RuntimeError):
        pass

    try:
        mw("terminal", {"command": f"echo $(<{ref['placeholder']})"}, None,
           lambda a: (_ for _ in ()).throw(Boom()))
    except Boom:
        pass
    hooks.ExecutionSecretScope.close = orig_close
    print("FINAL scoped count:", redactor.scoped_secret_count())

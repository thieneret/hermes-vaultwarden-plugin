import traceback
from vaultwarden import hooks
from vaultwarden.security import get_redacting_filter
from vaultwarden.tests.test_integration import _dict_tools, _register_ok


def test_probe(monkeypatch, tmp_path, fake_bw):
    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    mw = dict(ctx.middleware)["tool_execution"]
    tools_ = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    redactor = get_redacting_filter()

    orig_retain = type(redactor).retain_secret

    def tr(self, value):
        print(f"REDACTOR.RETAIN len={len(value)}")
        stack = "".join(traceback.format_stack(limit=12)[:-1])
        print(stack)
        return orig_retain(self, value)
    monkeypatch.setattr(type(redactor), "retain_secret", tr)

    ref = tools_["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001", "field": "password"})
    print("=== after get_secret_ref, scoped:", redactor.scoped_secret_count())

    class Boom(RuntimeError):
        pass

    try:
        mw("terminal", {"command": f"echo $(<{ref['placeholder']})"}, None,
           lambda a: (_ for _ in ()).throw(Boom()))
    except Boom:
        pass
    print("FINAL scoped count:", redactor.scoped_secret_count())

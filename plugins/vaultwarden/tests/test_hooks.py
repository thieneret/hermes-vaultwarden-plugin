"""Unit tests: VWP-04 tool_execution middleware & post_tool_call hook.

Covers the full placeholder lifecycle (file-based injection) and, above all,
MIDDLEWARE CHAIN SAFETY: calls without anything to inject are passed straight
through to next_call with byte-identical args.
"""
from __future__ import annotations

import os

import pytest

from vaultwarden.hooks import (
    _PENDING_ERRORS,
    _secrets_dir,
    make_placeholder_resolver,
    make_post_cleanup_hook,
    make_session_end_hook,
)


@pytest.fixture()
def mw(auth_manager, registry):
    return make_placeholder_resolver(auth_manager, registry)


@pytest.fixture()
def post(auth_manager, registry):
    return make_post_cleanup_hook(auth_manager, registry)


def token_for(registry, item="Postgres prod", field="password"):
    """Create a token; return the USER-FACING $-prefixed reference (VWP-04)."""
    entry = registry.create(item, field)
    return "$" + entry.token   # t[1:] == bare registry form


def bare_for(registry, item="Postgres prod", field="password"):
    """Return the BARE registry token (old v0.4.3 command-string form)."""
    entry = registry.create(item, field)
    return entry.token


def run_mw(mw, tool_name, args, **kw):
    """Invoke the tool_execution middleware; return (result, seen_args)."""
    seen: list[dict] = []

    def next_call(a):
        seen.append(a)
        return {"output": "ran"}

    result = mw(tool_name, args, dict(args), next_call, **kw)
    return result, (seen[0] if seen else None)


# ------------------------------------------------------------ chain safety
def test_middleware_passes_through_non_terminal(mw):
    res, seen = run_mw(mw, "file_read", {"path": "/x"})
    assert res == {"output": "ran"}
    assert seen == {"path": "/x"}
    run_mw(mw, "", {})  # must not raise


def test_middleware_passes_through_without_placeholders(mw):
    args = {"command": "echo hello && ls -la"}
    res, seen = run_mw(mw, "terminal", args)
    assert res == {"output": "ran"}
    assert seen == args                       # byte-identical passthrough
    assert args == {"command": "echo hello && ls -la"}


def test_middleware_passes_through_non_dict_args(mw):
    calls: list = []
    nc = lambda a: calls.append(a) or "ok"  # noqa: E731
    assert mw("terminal", None, None, nc) == "ok"
    assert mw("terminal", "string-args", "string-args", nc) == "ok"
    assert calls == [None, "string-args"]


def test_middleware_only_modifies_when_change_made(mw, registry):
    t = token_for(registry)
    res, seen = run_mw(mw, "terminal", {"command": f"psql -c 'SELECT 1' --pw {t}"})
    assert res == {"output": "ran"}
    assert "$(<" in seen["command"]


# ------------------------------------------------------------ resolution
def test_full_lifecycle_file_injection(mw, post, registry):
    t = token_for(registry)
    paths: list[str] = []

    def next_call(a):
        paths.extend(_injected_paths(a["command"]))
        # secret must NOT be in the command string — only $(< path)
        assert "sup3r-s3cret-pg!" not in a["command"]
        # but the shell can read it from the temp file at execution time
        contents = "".join(open(p).read() for p in paths)
        assert "sup3r-s3cret-pg!" in contents
        mode = os.stat(paths[0]).st_mode & 0o777
        assert mode == 0o600
        return {"output": "ok"}

    mw("terminal", {"command": f"export PGPASSWORD=\"{t}\"; psql -l"},
       None, next_call, task_id="t1")
    snap = registry.snapshot()
    # VWP-04: consume() marks the token used but keeps the entry until the
    # post_tool_call hook purges it via cleanup_used(). Single-use is already
    # enforced at this point — a second consume() raises PLACEHOLDER_ERROR.
    assert snap[t[1:]]["used"] is True        # consumed (single use)
    # finally block deleted every temp file after the call returned
    assert paths and all(not os.path.exists(p) for p in paths)
    res_obj = {"output": "ok"}
    post("terminal", {}, res_obj, task_id="t1")
    assert t[1:] not in registry.snapshot()   # post_tool_call purged it


def _injected_paths(command: str) -> list[str]:
    import re
    return re.findall(r"\$\(\< (/[^)]+)", command)


def test_single_use_second_pass_left_verbatim(mw, registry):
    t = token_for(registry)
    _PENDING_ERRORS.clear()
    first, _ = run_mw(mw, "terminal", {"command": f"run --secret \"{t}\""})
    assert first == {"output": "ran"}
    second, seen2 = run_mw(mw, "terminal", {"command": f"run --secret \"{t}\""})
    # fail-safe: unresolved reference stays verbatim ($ expands to empty)
    assert t in seen2["command"]
    assert "$(<" not in seen2["command"]
    pending = [e for errs in _PENDING_ERRORS.values() for e in errs]
    assert any(e["error_code"] == "PLACEHOLDER_ERROR" for e in pending)
    _PENDING_ERRORS.clear()


def test_unknown_placeholder_left_verbatim(mw):
    _PENDING_ERRORS.clear()
    bogus = "$__VW_SECRET_deadbeefcafe__"
    res, seen = run_mw(mw, "terminal", {"command": f"echo {bogus}"})
    assert res == {"output": "ran"}           # no crash
    assert seen["command"] == f"echo {bogus}" # left as-is
    pending = [e for errs in _PENDING_ERRORS.values() for e in errs]
    assert any(e["error_code"] == "PLACEHOLDER_ERROR" for e in pending)
    _PENDING_ERRORS.clear()


def test_bare_token_without_dollar_not_injected(mw, registry):
    """VWP-04 breaking change: the old bare form is NO LONGER supported."""
    t = bare_for(registry)
    res, seen = run_mw(mw, "terminal", {"command": f"echo {t}"})
    assert seen["command"] == f"echo {t}"     # untouched
    assert t in registry.snapshot()           # not even consumed


def test_secret_never_in_command_multiple_tokens(mw, registry):
    a = token_for(registry, "Postgres prod", "password")
    b = token_for(registry, "Grafana", "password")
    paths: list[str] = []

    def next_call(cmd_args):
        paths.extend(_injected_paths(cmd_args["command"]))
        assert len(paths) == 2                # each placeholder its own file
        assert "sup3r-s3cret-pg!" not in cmd_args["command"]
        assert "gr@f-pass" not in cmd_args["command"]
        vals = sorted(open(p).read() for p in paths)
        assert vals == ["gr@f-pass", "sup3r-s3cret-pg!"]
        return "done"

    out = mw("terminal", {"command": f"echo \"{a}\" \"{b}\""}, None, next_call)
    assert out == "done"
    assert all(not os.path.exists(p) for p in paths)


def test_redacting_filter_registered(mw, registry):
    from vaultwarden.security import get_redacting_filter
    t = token_for(registry)
    run_mw(mw, "terminal", {"command": f"curl -H \"X-Token: {t}\" https://api"})
    assert get_redacting_filter().redact("leak: sup3r-s3cret-pg!") \
        != "leak: sup3r-s3cret-pg!"


def test_other_arg_keys_supported(mw, registry):
    t = token_for(registry)
    _, seen = run_mw(mw, "terminal", {"cmd": f"ls; echo \"{t}\""})
    assert "$(<" in seen["cmd"]


def test_cleanup_runs_even_when_next_call_raises(mw, registry):
    t = token_for(registry)
    paths: list[str] = []

    def boom(a):
        paths.extend(_injected_paths(a["command"]))
        raise RuntimeError("command timed out")

    with pytest.raises(RuntimeError):
        mw("terminal", {"command": f"run \"{t}\""}, None, boom)
    assert paths                              # file WAS created...
    assert all(not os.path.exists(p) for p in paths)   # ...and cleaned up


# ------------------------------------------------------------- _secrets_dir
def test_secrets_dir_prefers_xdg_runtime(tmp_path, monkeypatch):
    xdg = tmp_path / "xdg"
    xdg.mkdir()
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    d = _secrets_dir()
    assert d == os.path.join(str(xdg), "vw-secrets")
    assert os.stat(d).st_mode & 0o777 == 0o700


def test_secrets_dir_falls_back_to_tmp(monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    d = _secrets_dir()
    assert d == os.path.join(str(tmp_path), f"vw-secrets-{os.getuid()}")
    assert os.stat(d).st_mode & 0o777 == 0o700


def test_secrets_dir_falls_back_when_xdg_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "nonexistent"))
    d = _secrets_dir()
    assert d.endswith(f"vw-secrets-{os.getuid()}")
    assert os.path.isdir(d)


# ------------------------------------------------------------- post hook
def test_post_hook_redacts_secret_from_output(mw, post, registry, auth_manager):
    """SEC-01 (v0.5.4): redaction is AUTHORITATIVE in transform_tool_result.

    The post_tool_call observer must no longer mutate the result for
    confidentiality reasons; the transformer returned by make_result_redactor
    is what scrubs echoes of injected secrets before the model sees them.
    """
    from vaultwarden.hooks import make_result_redactor

    redact = make_result_redactor(auth_manager, registry)
    t = token_for(registry)
    leaked = {"output": "Zs: sup3r-s3cret-pg! done"}

    def next_call(a):
        return leaked

    mw("terminal", {"command": f"echo \"{t}\""}, dict({"command": f"echo \"{t}\""}),
       next_call, task_id="x")
    # Hermes pipeline: middleware returns -> transform_tool_result replaces.
    observed = redact("terminal", leaked, task_id="x")
    assert "sup3r-s3cret-pg!" not in observed["output"]
    assert "[REDACTED]" in observed["output"]

    # Observer-only guarantee: post_tool_call never redacts anymore.
    t2 = token_for(registry)

    def next_call2(a):
        return {"output": "again sup3r-s3cret-pg!"}

    res2 = mw("terminal", {"command": f"echo \"{t2}\""}, None, next_call2,
              task_id="x2")
    post("terminal", {}, res2, task_id="x2")
    assert "sup3r-s3cret-pg!" in res2["output"]  # observer does NOT mutate
    res2b = {"output": "again sup3r-s3cret-pg!"}
    out2 = redact("terminal", res2b, task_id="x2")
    assert "sup3r-s3cret-pg!" not in out2["output"]


def test_post_hook_surfaces_placeholder_errors(mw, post, registry):
    _PENDING_ERRORS.clear()
    # v0.2.2: errors are stored per task_id — middleware and post hook must
    # use the SAME task id for the errors to be surfaced to this call's result.
    run_mw(mw, "terminal", {"command": "echo $__VW_SECRET_000000000000__"},
           task_id="y")
    res = {"output": "done"}
    post("terminal", {}, res, task_id="y")
    assert res["vaultwarden_placeholder_errors"][0]["error_code"] == "PLACEHOLDER_ERROR"
    assert _PENDING_ERRORS == {}


def test_post_hook_noop_for_other_tools(post, registry):
    t = bare_for(registry)
    registry.consume(t)
    before = set(registry.snapshot())
    post("web_search", {}, {"output": str(before)}, task_id="z")
    assert set(registry.snapshot()) == before   # untouched by foreign tools


def test_session_end_clears_everything(auth_manager, registry, post):
    token_for(registry)
    end = make_session_end_hook(auth_manager, registry)
    end()
    assert registry.snapshot() == {}
    assert auth_manager.session_key is None

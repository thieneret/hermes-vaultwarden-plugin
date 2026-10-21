"""Unit tests: tool_request env-injection middleware & post_tool_call hook.

VWP-04 (v0.4.4): the middleware injects resolved secrets into the terminal
tool's ``env`` argument as VW_TOKEN_<suffix> variables and rewrites the
``$__VW_SECRET_<suffix>__`` reference to ``$VW_TOKEN_<suffix>`` — the raw
secret must NEVER appear in the rewritten command string.

Covers the full placeholder lifecycle and, above all, MIDDLEWARE CHAIN SAFETY:
the injector must return None whenever it has nothing to change.
"""
from __future__ import annotations

import pytest

from vaultwarden.hooks import (
    _PENDING_ERRORS,
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
    entry = registry.create(item, field)
    return entry.token


def ref_for(registry, item="Postgres prod", field="password"):
    """User-facing $-prefixed placeholder reference + its 12-hex suffix."""
    entry = registry.create(item, field)
    return f"${entry.token}", entry.token[12:-2]   # strip $__VW_SECRET_ ... __


# ------------------------------------------------------------ chain safety
def test_middleware_returns_none_for_non_terminal(mw):
    assert mw("file_read", {"path": "/x"}) is None
    assert mw("", {}) is None


def test_middleware_returns_none_without_placeholders(mw):
    args = {"command": "echo hello && ls -la"}
    assert mw("terminal", args) is None
    # original dict untouched (identity of values preserved)
    assert args == {"command": "echo hello && ls -la"}


def test_middleware_returns_none_for_non_dict_args(mw):
    assert mw("terminal", None) is None
    assert mw("terminal", "string-args") is None


def test_bare_placeholder_no_longer_supported(mw, registry):
    """BREAKING (VWP-04): the old bare form without '$' is NOT resolved."""
    t = token_for(registry)
    out = mw("terminal", {"command": f"psql --pw {t}"})
    assert out is None                       # no injection happens at all
    assert t in registry.active_tokens()     # placeholder stays unconsumed


def test_middleware_only_modifies_when_change_made(mw, registry):
    ref, suffix = ref_for(registry)
    out = mw("terminal", {"command": f"psql -c \"SELECT 1\" --pw \"{ref}\""})
    assert out is not None and "args" in out
    assert ref not in out["args"]["command"]
    assert f"$VW_TOKEN_{suffix}" in out["args"]["command"]


# ------------------------------------------------------------ env injection
def test_full_lifecycle_resolve_use_cleanup(mw, post, registry):
    ref, suffix = ref_for(registry)
    result = mw("terminal", {"command": f"psql -h db.internal -U dbadmin -c \"run '{ref}'\""})
    assert result is not None
    cmd = result["args"]["command"]
    env = result["args"]["env"]
    assert env[f"VW_TOKEN_{suffix}"] == "sup3r-s3cret-pg!"   # secret -> env ONLY
    assert ref not in cmd
    assert f"$VW_TOKEN_{suffix}" in cmd
    assert "sup3r-s3cret-pg!" not in cmd                     # never in command
    assert registry.snapshot()[f"__VW_SECRET_{suffix}__"]["used"] is True
    res_obj = {"output": "ok"}
    post("terminal", {"command": cmd}, res_obj, task_id="t1")
    assert "__VW_SECRET_%s__" % suffix not in registry.snapshot()  # cleaned up


def test_existing_env_merged_not_replaced(mw, registry):
    ref, suffix = ref_for(registry)
    out = mw("terminal", {"command": f"curl -H \"X: {ref}\"",
                          "env": {"KEEP_ME": "yes"}, "timeout": 30})
    args = out["args"]
    assert args["env"]["KEEP_ME"] == "yes"                  # caller env kept
    assert args["env"][f"VW_TOKEN_{suffix}"] == "sup3r-s3cret-pg!"
    assert args["timeout"] == 30                            # other fields kept


def test_single_use_second_pass_fails_closed(mw, registry):
    ref, suffix = ref_for(registry)
    first = mw("terminal", {"command": f"run \"--secret {ref}\""})
    assert first and first["args"]["env"][f"VW_TOKEN_{suffix}"] == "sup3r-s3cret-pg!"
    _PENDING_ERRORS.clear()
    second = mw("terminal", {"command": f"run \"--secret {ref}\""})
    # fail closed: already-used placeholder is left untouched, nothing injected
    assert second is None
    assert "sup3r-s3cret-pg!" not in str(_PENDING_ERRORS)
    # v0.2.2: task-scoped dict store — errors live under the (empty) task key
    assert sum(len(v) for v in _PENDING_ERRORS.values()) >= 1   # surfaced later


def test_unknown_placeholder_left_as_is_with_error(mw):
    _PENDING_ERRORS.clear()
    bogus = "$__VW_SECRET_deadbeefcafe__"
    out = mw("terminal", {"command": f"echo \"{bogus}\""})
    assert out is None                                     # no injection
    pending = [e for errs in _PENDING_ERRORS.values() for e in errs]
    assert any(e["error_code"] == "PLACEHOLDER_ERROR" for e in pending)
    _PENDING_ERRORS.clear()


def test_multiple_placeholders_one_command(mw, registry):
    a_ref, a_sfx = ref_for(registry, "Postgres prod", "password")
    b_ref, b_sfx = ref_for(registry, "Grafana", "password")
    out = mw("terminal", {"command": f"echo \"{a_ref}\" then \"{b_ref}\""})
    cmd = out["args"]["command"]
    env = out["args"]["env"]
    assert env[f"VW_TOKEN_{a_sfx}"] == "sup3r-s3cret-pg!"
    assert env[f"VW_TOKEN_{b_sfx}"] == "gr@f-pass"
    assert a_ref not in cmd and b_ref not in cmd
    assert "sup3r-s3cret-pg!" not in cmd and "gr@f-pass" not in cmd
    assert f"$VW_TOKEN_{a_sfx}" in cmd and f"$VW_TOKEN_{b_sfx}" in cmd


def test_other_arg_keys_supported(mw, registry):
    ref, suffix = ref_for(registry)
    out = mw("terminal", {"cmd": f"ls; echo \"{ref}\""})
    assert out and out["args"]["env"][f"VW_TOKEN_{suffix}"] == "sup3r-s3cret-pg!"


def test_secret_registered_with_redacting_filter(mw, registry):
    from vaultwarden.security import get_redacting_filter

    ref, suffix = ref_for(registry)
    out = mw("terminal", {"command": f"echo \"{ref}\""})
    assert out["args"]["env"][f"VW_TOKEN_{suffix}"] == "sup3r-s3cret-pg!"
    # RedactingFilter must scrub the injected secret from any log/output echo.
    assert "sup3r-s3cret-pg!" not in get_redacting_filter().redact(
        "leaked line: sup3r-s3cret-pg!")


# ------------------------------------------------------------- post hook
def test_post_hook_redacts_secret_from_output(mw, post, registry):
    ref, _sfx = ref_for(registry)
    mw("terminal", {"command": f"echo \"{ref}\""}, task_id="x")
    leaked = {"output": "Zs: sup3r-s3cret-pg! done"}
    post("terminal", {}, leaked, task_id="x")
    assert "sup3r-s3cret-pg!" not in leaked["output"]
    assert "[REDACTED]" in leaked["output"]


def test_post_hook_surfaces_placeholder_errors(mw, post, registry):
    _PENDING_ERRORS.clear()
    # v0.2.2: errors are stored per task_id — middleware and post hook must
    # use the SAME task id for the errors to be surfaced to this call's result.
    out = mw("terminal", {"command": "echo unknown $__VW_SECRET_000000000000__ here"},
             task_id="y")
    # only an unknown placeholder -> nothing resolved -> original args returned
    assert out is None or out["args"]["command"] == \
        "echo unknown $__VW_SECRET_000000000000__ here"
    res = {"output": "done"}
    post("terminal", {"command": "echo done"}, res, task_id="y")
    assert res["vaultwarden_placeholder_errors"][0]["error_code"] == "PLACEHOLDER_ERROR"
    assert _PENDING_ERRORS == {}


def test_post_hook_noop_for_other_tools(post, registry):
    t = token_for(registry)
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

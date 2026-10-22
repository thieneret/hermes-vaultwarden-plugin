"""Unit tests: tool_request middleware & post_tool_call hook (plan §7).

Covers the full placeholder lifecycle and, above all, MIDDLEWARE CHAIN SAFETY:
the resolver must return None whenever it has nothing to change.
"""
from __future__ import annotations

import pytest

from vaultwarden.hooks import (
    _PENDING_ERRORS,
    INVALID_SENTINEL,
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


def test_middleware_only_modifies_when_change_made(mw, registry):
    t = token_for(registry)
    out = mw("terminal", {"command": f"psql -c 'SELECT 1' --pw {t}"})
    assert out is not None and "args" in out
    assert t not in out["args"]["command"]


# ------------------------------------------------------------ resolution
def test_full_lifecycle_resolve_use_cleanup(mw, post, registry):
    t = token_for(registry)
    result = mw("terminal", {"command": f"export PGPASSWORD={t}; psql -l"})
    assert result is not None
    cmd = result["args"]["command"]
    assert t not in cmd
    assert "sup3r-s3cret-pg!" in cmd          # resolved for execution only
    assert registry.snapshot()[t]["used"] is True
    res_obj = {"output": "ok"}
    post("terminal", {"command": cmd}, res_obj, task_id="t1")
    assert t not in registry.snapshot()       # cleaned up after use


def test_single_use_second_pass_fails_closed(mw, post, registry):
    t = token_for(registry)
    first = mw("terminal", {"command": f"run --secret {t}"})
    assert first and "sup3r-s3cret-pg!" in first["args"]["command"]
    _PENDING_ERRORS.clear()
    second = mw("terminal", {"command": f"run --secret {t}"})
    assert second is not None
    assert INVALID_SENTINEL in second["args"]["command"]   # fail closed
    assert "sup3r-s3cret-pg!" not in second["args"]["command"]
    # v0.2.2: task-scoped dict store — errors live under the (empty) task key
    assert sum(len(v) for v in _PENDING_ERRORS.values()) >= 1   # surfaced later


def test_unknown_placeholder_passes_through_with_warning(mw):
    _PENDING_ERRORS.clear()
    bogus = "__VW_SECRET_deadbeefcafe__"
    out = mw("terminal", {"command": f"echo {bogus}"})
    assert out is not None
    assert INVALID_SENTINEL in out["args"]["command"]
    pending = [e for errs in _PENDING_ERRORS.values() for e in errs]
    assert any(e["error_code"] == "PLACEHOLDER_ERROR" for e in pending)
    _PENDING_ERRORS.clear()


def test_shell_escaping_prevents_injection(mw, registry):
    evil_item = "evil"
    entry = registry.create(evil_item, "password")
    # registry maps to fake-bw item lookup; use real item but crafted command:
    entry.item_id = "aaaa1111-0000-0000-0000-000000000001"
    out = mw("terminal", {"command": f"curl -H 'X-Token: {entry.token}' https://api"})
    cmd = out["args"]["command"]
    # value has no shell metachars here, but must be quoted (shlex.quote wraps)
    assert "sup3r-s3cret-pg!" in cmd


def test_url_context_percent_escapes(mw, registry):
    entry = registry.create("Grafana", "password")   # gr@f-pass contains '@'
    out = mw("terminal", {"command": f"psql 'postgres://user:{entry.token}@db/prod'"})
    cmd = out["args"]["command"]
    assert "gr%40f-pass" in cmd      # '@' percent-encoded -> URL-safe
    assert "gr@f-pass" not in cmd


def test_multiple_tokens_one_command(mw, registry):
    a = token_for(registry, "Postgres prod", "password")
    b = token_for(registry, "Grafana", "password")
    out = mw("terminal", {"command": f"echo {a} {b}"})
    cmd = out["args"]["command"]
    assert a not in cmd and b not in cmd
    assert "sup3r-s3cret-pg!" in cmd and "gr@f-pass" in cmd


def test_other_arg_keys_supported(mw, registry):
    t = token_for(registry)
    out = mw("terminal", {"cmd": f"ls; echo {t}"})
    assert out and "sup3r-s3cret-pg!" in out["args"]["cmd"]


# ------------------------------------------------------------- post hook
def test_post_hook_redacts_secret_from_output(mw, post, registry):
    t = token_for(registry)
    mw("terminal", {"command": f"echo {t}"})
    leaked = {"output": "Zs: sup3r-s3cret-pg! done"}
    post("terminal", {}, leaked, task_id="x")
    assert "sup3r-s3cret-pg!" not in leaked["output"]
    assert "[REDACTED]" in leaked["output"]


def test_post_hook_surfaces_placeholder_errors(mw, post, registry):
    _PENDING_ERRORS.clear()
    # v0.2.2: errors are stored per task_id — middleware and post hook must
    # use the SAME task id for the errors to be surfaced to this call's result.
    out = mw("terminal", {"command": "echo __VW_SECRET_000000000000__"},
             task_id="y")
    assert out is not None
    res = {"output": "done"}
    post("terminal", {"command": out["args"]["command"]}, res, task_id="y")
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

"""AUD-02 (v0.6.5): scoped redaction lifecycle tests.

Covers the three layers of the fix:

1. RedactingFilter reference counting (unit, incl. concurrency stress),
2. ExecutionSecretScope lifecycle semantics (release-once, dedupe,
   process-scoped baseline protection),
3. middleware integration: runtime secrets return the redactor to its
   baseline after an execution, overlapping executions sharing a secret
   are protected from premature removal, and SEC-01 authoritative
   transform_tool_result redaction is unchanged.

NEVER assert on or print secret values in failure diagnostics beyond what
is required for the test itself; helpers expose counts only.
"""
from __future__ import annotations

import logging
import threading

from vaultwarden.hooks import (
    ExecutionSecretScope,
    close_execution_scope,
    current_execution_scope,
    open_execution_scope,
)
import pytest

from vaultwarden.security import RedactingFilter


# ------------------------------------------------------- redactor refcounting
def test_retain_then_release_once_removes_secret():
    f = RedactingFilter()
    base = f.active_secret_count()
    f.retain_secret("runtime-secret-A")
    assert f.has_secret("runtime-secret-A")
    f.release_secret("runtime-secret-A")
    assert not f.has_secret("runtime-secret-A")
    assert f.active_secret_count() == base


def test_retain_twice_release_once_keeps_secret():
    f = RedactingFilter()
    f.retain_secret("runtime-secret-B")
    f.retain_secret("runtime-secret-B")
    f.release_secret("runtime-secret-B")
    assert f.has_secret("runtime-secret-B")
    f.release_secret("runtime-secret-B")
    assert not f.has_secret("runtime-secret-B")


def test_release_unknown_value_warns_sanitized_no_crash():
    f = RedactingFilter()
    # security.py logs unknown-release diagnostics through its module
    # logger (hermes.plugins.vaultwarden.security).
    logger_name = "hermes.plugins.vaultwarden.security"
    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record):
            records.append(record)

    lg = logging.getLogger(logger_name)
    handler = _Capture()
    old_level = lg.level
    lg.addHandler(handler)
    lg.setLevel(logging.WARNING)
    try:
        f.release_secret("never-retained-value")  # must not raise
        f.release_secret("")                      # empty: silent no-op
    finally:
        lg.removeHandler(handler)
        lg.setLevel(old_level)
    assert records, "expected a sanitized warning for unknown release"
    joined = " ".join(r.getMessage() for r in records)
    # Sanitized: length only, NEVER the value.
    assert "never-retained-value" not in joined
    assert "len=" in joined
    # No negative counts: subsequent retain/release still behaves normally.
    f.retain_secret("after-unknown")
    f.release_secret("after-unknown")
    assert not f.has_secret("after-unknown")


def test_process_scoped_survives_execution_release():
    f = RedactingFilter()
    f.register_process_scoped_secret("startup-injection-secret")
    f.retain_secret("startup-injection-secret")   # one execution also uses it
    f.release_secret("startup-injection-secret")  # execution ends
    assert f.has_secret("startup-injection-secret")  # baseline survives
    f.release_process_scoped_secret("startup-injection-secret")
    assert not f.has_secret("startup-injection-secret")


def test_register_secret_maps_to_process_baseline():
    f = RedactingFilter()
    f.register_secret("legacy-bootstrap-secret")
    f.release_secret("legacy-bootstrap-secret")  # stray exec release
    assert f.has_secret("legacy-bootstrap-secret")


def test_overlapping_threaded_retains_final_count_correct():
    f = RedactingFilter()
    n_threads = 16
    barrier = threading.Barrier(n_threads)

    def worker():
        barrier.wait()
        f.retain_secret("shared-thread-secret")

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert f.has_secret("shared-thread-secret")
    for _ in range(n_threads - 1):
        f.release_secret("shared-thread-secret")
        assert f.has_secret("shared-thread-secret")  # never premature
    f.release_secret("shared-thread-secret")
    assert not f.has_secret("shared-thread-secret")


def test_concurrent_retain_release_stress_no_race():
    f = RedactingFilter()
    value = "stress-secret-value"
    ops_per_thread = 200
    errors: list[BaseException] = []

    def worker():
        try:
            for _ in range(ops_per_thread):
                f.retain_secret(value)
                f.release_secret(value)
        except BaseException as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # Balanced retain/release pairs leave NO residue and no negative count:
    assert not f.has_secret(value)
    assert f.active_secret_count() == 0


# ------------------------------------------------------------ scope lifecycle
def test_scope_releases_each_distinct_value_once():
    from vaultwarden.security import get_redacting_filter
    f = get_redacting_filter()
    base = f.active_secret_count()
    scope = ExecutionSecretScope(f)
    scope.retain("scope-secret-X")
    scope.retain("scope-secret-X")  # same value twice -> ONE reference
    f.retain_secret("scope-secret-X")  # another execution's reference
    scope.close()
    assert f.has_secret("scope-secret-X")  # other execution still active
    f.release_secret("scope-secret-X")
    assert not f.has_secret("scope-secret-X")
    assert f.active_secret_count() == base


def test_scope_close_is_release_once_idempotent():
    from vaultwarden.security import get_redacting_filter
    f = get_redacting_filter()
    scope = ExecutionSecretScope(f)
    scope.retain("scope-secret-Y")
    scope.close()
    scope.close()  # no-op: must NOT double-decrement (would warn/leak)
    assert not f.has_secret("scope-secret-Y")
    f.retain_secret("scope-secret-Y")
    f.release_secret("scope-secret-Y")
    assert not f.has_secret("scope-secret-Y")


def test_scope_retain_after_close_is_noop():
    from vaultwarden.security import get_redacting_filter
    f = get_redacting_filter()
    scope = ExecutionSecretScope(f)
    scope.close()
    scope.retain("late-secret-value")
    assert not f.has_secret("late-secret-value")


def test_scope_close_does_not_remove_process_baseline():
    f = RedactingFilter()
    f.register_process_scoped_secret("bootstrap-master-secret")
    scope = ExecutionSecretScope(f)
    scope.retain("bootstrap-master-secret")
    scope.close()
    assert f.has_secret("bootstrap-master-secret")


def test_open_close_contextvar_scope_roundtrip():
    from vaultwarden.security import get_redacting_filter
    f = get_redacting_filter()
    assert current_execution_scope() is None
    scope, token = open_execution_scope("exec-roundtrip-1")
    try:
        assert current_execution_scope() is scope
        scope.retain("ctxvar-secret-1")
        assert f.has_secret("ctxvar-secret-1")
    finally:
        closed = close_execution_scope(token, "exec-roundtrip-1")
    assert closed
    assert scope.closed
    assert not f.has_secret("ctxvar-secret-1")
    assert current_execution_scope() is None


def test_close_by_exec_id_deferred_release():
    scope, token = open_execution_scope("exec-defer-9")
    assert current_execution_scope() is scope
    scope.retain("deferred-release-secret")
    # Simulate post_tool_call running on a DIFFERENT context: id-keyed
    # registry lookup must still find and close the scope exactly once.
    found = close_execution_scope(exec_id="exec-defer-9")
    assert found
    assert scope.closed
    # Host-side ContextVar token reset AFTER the lifecycle completes.
    close_execution_scope(token, "exec-defer-9")
    assert current_execution_scope() is None
    from vaultwarden.security import get_redacting_filter
    assert not get_redacting_filter().has_secret("deferred-release-secret")
    # Scope fully consumed: a second close finds nothing to release.
    assert close_execution_scope(exec_id="exec-defer-9") is False


def test_three_overlapping_executions_same_secret_exact_refcount():
    """Three active scopes retaining ONE shared secret keep it redactable
    until the LAST execution closes (refcount tracks executions exactly)."""
    from vaultwarden.security import get_redacting_filter
    f = get_redacting_filter()
    base = f.active_secret_count()
    scopes = []
    for i in range(3):
        scope, _tok = open_execution_scope(f"exec-overlap-{i}")
        scope.retain("triple-shared-secret")
        scopes.append(scope)
    assert f.has_secret("triple-shared-secret")
    close_execution_scope(exec_id="exec-overlap-0")
    assert f.has_secret("triple-shared-secret")   # two still active
    close_execution_scope(exec_id="exec-overlap-1")
    assert f.has_secret("triple-shared-secret")   # one still active
    close_execution_scope(exec_id="exec-overlap-2")
    assert not f.has_secret("triple-shared-secret")  # last one released
    assert f.active_secret_count() == base


# ------------------------------------------------- middleware integration
def _run_execution(mw, post, token, task_id):
    """Run one full simulated execution lifecycle: middleware injection ->
    transform-equivalent consumption happens inside the host; here we run
    next_call then post_tool_call (the safe final lifecycle point)."""
    def next_call(args):
        return {"output": "ran ok"}
    result = mw("terminal", {"command": f"printf '%s\\n' \"$(<{token})\""},
                None, next_call, task_id=task_id)
    # AUD-02 deferred-release contract: when an execution CAN be attributed
    # to a task/execution id, post_tool_call only CLOSES the scope if it
    # finds it via the id-keyed registry. The middleware keeps publishing
    # its scope in BOTH channels (ContextVar + registry); the host-side
    # completion step below mirrors what the Hermes dispatcher does after
    # the whole lifecycle (middleware -> transform_tool_result ->
    # post_tool_call) finished: it hands the middleware's ContextVar token
    # back, which performs the single deferred release and consumes the
    # registry entry. close() is release-once, so calling both paths can
    # never double-decrement.
    close_execution_scope(exec_id=task_id)
    # Host-side ContextVar cleanup (the middleware's own token belongs to
    # its frame; from the outside the dispatcher simply clears the slot
    # once the turn completes).
    import vaultwarden.hooks as _hooks
    _hooks._execution_secret_scope.set(None)
    return result


def test_single_execution_returns_redactor_to_baseline(monkeypatch, tmp_path,
                                                       fake_bw):
    from vaultwarden.security import get_redacting_filter
    from vaultwarden.tests.test_integration import _dict_tools, _register_ok

    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    assert ok is True
    mw = dict(ctx.middleware)["tool_execution"]
    post = dict(ctx.hooks)["post_tool_call"]
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    redactor = get_redacting_filter()
    baseline = redactor.active_secret_count()

    ref = tools["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001", "field": "password"})
    _run_execution(mw, post, ref["placeholder"], "scoped-task-1")

    # AUD-02 memory assertion: NO indefinite growth -- back to baseline.
    assert redactor.active_secret_count() == baseline
    assert not redactor.has_secret("sup3r-s3cret-pg!")


def test_multi_secret_execution_releases_all(monkeypatch, tmp_path, fake_bw):
    from vaultwarden.security import get_redacting_filter
    from vaultwarden.tests.test_integration import _dict_tools, _register_ok

    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    mw = dict(ctx.middleware)["tool_execution"]
    post = dict(ctx.hooks)["post_tool_call"]
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    redactor = get_redacting_filter()
    baseline = redactor.active_secret_count()

    r1 = tools["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001", "field": "password"})
    r2 = tools["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000002", "field": "password"})
    cmd = f"echo \"$(<{r1['placeholder']})\" \"$(<{r2['placeholder']})\""
    mw("terminal", {"command": cmd}, None, lambda a: {"output": "ok"},
       task_id="scoped-task-2")
    post("terminal", {}, {"output": "ok"}, task_id="scoped-task-2")

    assert redactor.active_secret_count() == baseline
    assert not redactor.has_secret("sup3r-s3cret-pg!")
    assert not redactor.has_secret("gr@f-pass")


def test_two_executions_different_secret_release_own_only(
        monkeypatch, tmp_path, fake_bw):
    from vaultwarden.security import get_redacting_filter
    from vaultwarden.tests.test_integration import _dict_tools, _register_ok

    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    mw = dict(ctx.middleware)["tool_execution"]
    post = dict(ctx.hooks)["post_tool_call"]
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    redactor = get_redacting_filter()

    r1 = tools["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001", "field": "password"})
    r2 = tools["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000002", "field": "password"})
    # Execution A runs fully; execution B's scope is still open when A ends.
    mw("terminal", {"command": f"echo $(<{r1['placeholder']})"}, None,
       lambda a: {"output": "A"}, task_id="overlap-A")
    res_b = mw("terminal", {"command": f"echo $(<{r2['placeholder']})"}, None,
               lambda a: {"output": "B"}, task_id="overlap-B")
    post("terminal", {}, {"output": "A"}, task_id="overlap-A")
    assert not redactor.has_secret("sup3r-s3cret-pg!")  # A released its own
    assert redactor.has_secret("gr@f-pass")             # B still active
    post("terminal", {}, res_b, task_id="overlap-B")
    assert not redactor.has_secret("gr@f-pass")


def test_overlapping_same_secret_not_removed_prematurely(
        monkeypatch, tmp_path, fake_bw):
    from vaultwarden.security import get_redacting_filter
    from vaultwarden.tests.test_integration import _dict_tools, _register_ok

    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    mw = dict(ctx.middleware)["tool_execution"]
    post = dict(ctx.hooks)["post_tool_call"]
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    redactor = get_redacting_filter()

    ref_args = {"item_id": "aaaa1111-0000-0000-0000-000000000001",
                "field": "password"}
    t1 = tools["vaultwarden_get_secret_ref"](ref_args)["placeholder"]
    t2 = tools["vaultwarden_get_secret_ref"](ref_args)["placeholder"]
    res1 = mw("terminal", {"command": f"echo $(<{t1})"}, None,
              lambda a: {"output": "X"}, task_id="same-secret-1")
    res2 = mw("terminal", {"command": f"echo $(<{t2})"}, None,
              lambda a: {"output": "Y"}, task_id="same-secret-2")
    post("terminal", {}, res1, task_id="same-secret-1")
    # Second overlapping execution still needs it -> retained.
    assert redactor.has_secret("sup3r-s3cret-pg!")
    post("terminal", {}, res2, task_id="same-secret-2")
    assert not redactor.has_secret("sup3r-s3cret-pg!")


def test_exception_still_releases_via_failsafe(monkeypatch, tmp_path, fake_bw):
    from vaultwarden.security import get_redacting_filter
    from vaultwarden.tests.test_integration import _dict_tools, _register_ok

    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    mw = dict(ctx.middleware)["tool_execution"]
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})
    redactor = get_redacting_filter()
    baseline = redactor.active_secret_count()

    ref = tools["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001", "field": "password"})

    class Boom(RuntimeError):
        pass

    try:
        # No task id -> the middleware finally block IS the guaranteed
        # fail-safe release point even when next_call raises.
        mw("terminal", {"command": f"echo $(<{ref['placeholder']})"}, None,
           lambda a: (_ for _ in ()).throw(Boom()))
    except Boom:
        pass
    else:  # pragma: no cover - fail-safe path must re-raise
        pytest.fail("exception from next_call must propagate")
    assert redactor.active_secret_count() == baseline
    assert not redactor.has_secret("sup3r-s3cret-pg!")


def test_startup_injection_secret_survives_execution_cleanup(
        monkeypatch, tmp_path, fake_bw):
    from vaultwarden.security import get_redacting_filter
    from vaultwarden.tests.test_integration import _dict_tools, _register_ok

    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    redactor = get_redacting_filter()
    # Simulate a startup-injection secret (process-scoped retention).
    redactor.register_process_scoped_secret("startup-injected-longsecret")
    mw = dict(ctx.middleware)["tool_execution"]
    post = dict(ctx.hooks)["post_tool_call"]
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})

    ref = tools["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001", "field": "password"})
    _run_execution(mw, post, ref["placeholder"], "startup-survive")
    # Execution cleanup must NEVER remove process-scoped secrets.
    assert redactor.has_secret("startup-injected-longsecret")
    redactor.forget_secret("startup-injected-longsecret")


def test_transform_tool_result_redaction_unchanged_after_scope_close(
        monkeypatch, tmp_path, fake_bw):
    """SEC-01 authoritative redaction still works end-to-end with AUD-02."""
    from vaultwarden.tests.test_integration import _dict_tools, _register_ok

    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    hooks = dict(ctx.hooks)
    mw = dict(ctx.middleware)["tool_execution"]
    transform = hooks["transform_tool_result"]
    post = hooks["post_tool_call"]
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})

    ref = tools["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001", "field": "password"})
    echoed = {"output": "printf ran: sup3r-s3cret-pg!\n"}
    result = mw("terminal", {"command": f"printf '%s\\n' \"$(<{ref['placeholder']})\""},
                None, lambda a: echoed, task_id="sec01-aud02")
    # transform runs BEFORE the deferred post_tool_call release (lifecycle
    # order guarantee: middleware -> transform -> post_tool_call).
    final = transform("terminal", result, task_id="sec01-aud02")
    assert "sup3r-s3cret-pg!" not in final["output"]
    assert "[REDACTED]" in final["output"]
    post("terminal", {}, result, task_id="sec01-aud02")


def test_no_secret_values_in_scoped_lifecycle_logs(monkeypatch, tmp_path,
                                                   fake_bw, caplog):
    from vaultwarden.tests.test_integration import _dict_tools, _register_ok

    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    mw = dict(ctx.middleware)["tool_execution"]
    post = dict(ctx.hooks)["post_tool_call"]
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})

    ref = tools["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001", "field": "password"})
    with caplog.at_level(logging.DEBUG):
        _run_execution(mw, post, ref["placeholder"], "nolog-task")
        # Force sanitized warnings: unknown release + retain-after-close.
        from vaultwarden.security import get_redacting_filter
        rf = get_redacting_filter()
        rf.release_secret("never-retained-diagnostic-value")
        scope, tok = open_execution_scope("nolog-closed")
        scope.close()
        scope.retain("late-retain-diagnostic")
        close_execution_scope(tok, "nolog-closed")
    for record in caplog.records:
        msg = record.getMessage()
        assert "sup3r-s3cret-pg!" not in msg
        assert "never-retained-diagnostic-value" not in msg
        assert "late-retain-diagnostic" not in msg

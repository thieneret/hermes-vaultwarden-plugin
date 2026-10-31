"""Unit tests: VWP-04 tool_execution middleware & post_tool_call hook.

Covers the full placeholder lifecycle (file-based injection) and, above all,
MIDDLEWARE CHAIN SAFETY: calls without anything to inject are passed straight
through to next_call with byte-identical args.
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import threading

import pytest

from vaultwarden.hooks import (
    _PENDING_ERRORS,
    _secrets_dir,
    make_placeholder_resolver,
    make_post_cleanup_hook,
    make_session_end_hook,
)
from vaultwarden.security import quote_injected_path

BASH = shutil.which("bash")


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


#: AUD-05 phase 2: the middleware emits $(< '/quoted/path'); the bare form
#: is still matched for robustness.
_INJECTED_PATH_RE = re.compile(
    r"\$\(<\s*(?:'([^']+)'|\"([^\"]+)\"|(/[^)\s]+))\)")


def _injected_paths(command: str) -> list[str]:
    return [g[0] or g[1] or g[2] for g in _INJECTED_PATH_RE.findall(command)]


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
    """AUD-02 (phase 2): the injected secret is redaction-active *during*
    the execution scope and released once the scope closes — assert both
    halves instead of the old post-execution global retention."""
    from vaultwarden.security import get_redacting_filter
    redactor = get_redacting_filter()
    t = token_for(registry)
    baseline = redactor.active_secret_count()

    in_scope: list[bool] = []

    def next_call(a):
        # Authoritative SEC-01 window: while the tool body runs, the
        # runtime secret must scrub plaintext log lines.
        in_scope.append(
            redactor.redact("leak: sup3r-s3cret-pg!") != "leak: sup3r-s3cret-pg!"
        )
        return {"output": "ran"}

    mw("terminal", {"command": f"curl -H \"X-Token: {t}\" https://api"},
       None, next_call)

    assert in_scope == [True]
    # Execution-scoped release: back to baseline after the scope closes.
    assert redactor.active_secret_count() == baseline
    assert redactor.redact("leak: sup3r-s3cret-pg!") \
        == "leak: sup3r-s3cret-pg!"


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


# ------------------------------------------------------- SEC-02 (v0.5.7)
def test_multi_occurrence_single_temp_file(mw, registry, monkeypatch):
    """SEC-02: the SAME placeholder referenced 3x in one command resolves
    atomically — consume_and_resolve runs exactly once per unique token and
    every occurrence maps onto the ONE injected temp file."""
    t = token_for(registry)
    suffix = t[1:][len("__VW_SECRET_"):-len("__")]

    calls: list[str] = []
    real_car = registry.consume_and_resolve

    def spy_car(token):
        calls.append(token)
        return real_car(token)

    monkeypatch.setattr(registry, "consume_and_resolve", spy_car)

    seen: list[dict] = []

    def next_call(a):
        seen.append(a)
        return {"output": "ran"}

    command = f'curl -H "Auth: {t}" -H "Cookie: {t}" -d "pw={t}"'

    created_files: list[str] = []
    from vaultwarden import hooks as _hooks_mod
    real_writer = _hooks_mod._write_secret_file

    def spy_writer(token, value, secrets_dir, temp_files):
        path = real_writer(token, value, secrets_dir, temp_files)
        # snapshot the directory contents at creation time (the finally
        # block unlinks the file after next_call returns, so we cannot
        # list it afterwards).
        created_files.append(path)
        return path

    monkeypatch.setattr("vaultwarden.hooks._write_secret_file", spy_writer)

    mw("terminal", {"command": command}, dict(command=command), next_call,
       task_id="sec02-multi")

    # 1. Atomic consumption: exactly ONE resolve call for the unique token.
    assert calls == [f"__VW_SECRET_{suffix}__"]
    # 2. Exactly ONE temp file created for that token in _secrets_dir().
    assert len(created_files) == 1
    assert os.path.dirname(created_files[0]) == _secrets_dir()
    assert os.path.basename(created_files[0]).startswith(
        f"vw_{suffix}_")
    # 3. ALL THREE occurrences rewritten to the same $(< path) reference.
    out_cmd = seen[0]["command"]
    assert out_cmd.count("$(< ") == 3
    paths = set(_injected_paths(out_cmd))
    assert len(paths) == 1
    assert paths == {created_files[0]}
    assert t not in out_cmd                       # no unresolved leftovers
    assert "sup3r-s3cret-pg!" not in out_cmd      # secret never inlined


def test_reuse_rejection_logs_warning(mw, registry, caplog):
    """SEC-02: replaying a consumed token in a LATER tool call fails safe —
    nothing is injected, a warning is logged, and consume_and_resolve returns
    None on the second pass (never raises)."""
    t = token_for(registry)
    _PENDING_ERRORS.clear()

    first, seen1 = run_mw(mw, "terminal", {"command": f"run --secret \"{t}\""},
                          task_id="sec02-reuse")
    assert first == {"output": "ran"}
    assert "$(< " in seen1["command"]             # first pass injects

    with caplog.at_level("WARNING"):
        second, seen2 = run_mw(mw, "terminal", {"command": f"run --secret \"{t}\""},
                               task_id="sec02-reuse")
    assert second == {"output": "ran"}
    assert "$(< " not in seen2["command"]         # reuse NOT injected
    assert t in seen2["command"]                  # stays verbatim (fail-safe)
    # atomic primitive: already-used token -> None, no exception
    assert registry.consume_and_resolve(t[1:]) is None
    # warning surfaced for operators/LLM via logs AND pending error store
    assert any("already used" in r.getMessage() or "cannot be resolved" in r.getMessage()
               for r in caplog.records if r.levelname == "WARNING")
    errs = _PENDING_ERRORS.get("sec02-reuse", [])
    assert any(e.get("error_code") == "PLACEHOLDER_ERROR" for e in errs)
    _PENDING_ERRORS.clear()


# ------------------------------------------------- AUD-02 phase 2: scope unit
from vaultwarden.hooks import (  # noqa: E402
    _DEFERRED_MAX_ENTRIES,
    ExecutionSecretScope,
    _stash_deferred_injected,
    clear_deferred_injected,
    consume_deferred_injected,
    current_execution_scope,
    retain_in_execution_scope,
)


def _fresh_filter():
    from vaultwarden.security import RedactingFilter
    return RedactingFilter()


def test_scope_retain_once_per_unique_value(monkeypatch):
    from vaultwarden import security as sec_mod
    filt = _fresh_filter()
    monkeypatch.setattr(sec_mod, "_shared_filter", filt)
    scope = ExecutionSecretScope(filt)
    try:
        scope.retain("aaaa-unique-value")
        scope.retain("aaaa-unique-value")   # duplicate within one scope
        assert scope.retained_count() == 1
        assert filt.active_secret_count() == 1
        # refcount must be exactly 1: a single release removes it.
    finally:
        scope.close()
    assert filt.active_secret_count() == 0


def test_scope_release_once_removes_after_single_retain():
    filt = _fresh_filter()
    scope = ExecutionSecretScope(filt)
    scope.retain("bbbb-secret-value")
    scope.close()
    assert not filt.has_secret("bbbb-secret-value")


def test_scope_two_retains_one_close_keeps_until_second_release(monkeypatch):
    """Overlapping holders: two scopes, same secret -> removed only after both."""
    from vaultwarden import security as sec_mod
    filt = _fresh_filter()
    monkeypatch.setattr(sec_mod, "_shared_filter", filt)
    s1 = ExecutionSecretScope(filt)
    s2 = ExecutionSecretScope(filt)
    s1.retain("cccc-shared-secret")
    s2.retain("cccc-shared-secret")
    s1.close()
    assert filt.has_secret("cccc-shared-secret")   # s2 still holds it
    s2.close()
    assert not filt.has_secret("cccc-shared-secret")


def test_scope_close_is_idempotent_and_never_raises():
    filt = _fresh_filter()
    scope = ExecutionSecretScope(filt)
    scope.retain("dddd-secret-value")
    scope.close()
    scope.close()                                   # second close: no-op
    assert filt.active_secret_count() == 0


def test_scope_close_releases_each_value_exactly_once(caplog):
    filt = _fresh_filter()
    scope = ExecutionSecretScope(filt)
    scope.retain("eeee-secret-one")
    scope.retain("ffff-secret-two")
    with caplog.at_level("WARNING"):
        scope.close()
    # Exactly-once release => zero "unknown secret" sanitized warnings.
    assert not [r for r in caplog.records
                if "unknown secret" in r.getMessage()]
    assert filt.active_secret_count() == 0


def test_scope_early_release_no_double_release_on_close():
    filt = _fresh_filter()
    scope = ExecutionSecretScope(filt)
    scope.retain("gggg-secret-value")
    scope.early_release("gggg-secret-value")
    assert not filt.has_secret("gggg-secret-value")
    scope.close()                                    # must NOT double-release
    assert filt.active_secret_count() == 0


def test_scope_concurrent_retain_close_final_state_consistent():
    filt = _fresh_filter()
    values = [f"h{i:03d}-concurrent-secret" for i in range(50)]
    scopes = [ExecutionSecretScope(filt) for _ in range(4)]

    def worker(scope, chunk):
        for v in chunk:
            scope.retain(v)
        scope.close()

    threads = [threading.Thread(target=worker,
                                args=(scopes[i], values[i::4]))
               for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Every value retained by exactly one scope; all scopes closed.
    assert filt.active_secret_count() == 0
    assert not any(sc.retained_count() for sc in scopes)


def test_scope_retain_after_close_does_not_leak():
    filt = _fresh_filter()
    scope = ExecutionSecretScope(filt)
    scope.close()
    scope.retain("iiii-late-secret")                 # fail-safe immediate release
    assert filt.active_secret_count() == 0


def test_scope_close_stashes_deferred_snapshot_for_transform():
    """Hosts dispatching transform AFTER the frame still get the snapshot."""
    filt = _fresh_filter()
    scope = ExecutionSecretScope(filt)
    scope._task_id = "exec-deferred-1"
    scope.retain("jjjj-deferred-secret")
    scope.close()
    got = consume_deferred_injected("exec-deferred-1")
    assert got == ["jjjj-deferred-secret"]
    # One-shot: consumed exactly once, then gone.
    assert consume_deferred_injected("exec-deferred-1") == []
    # Refcounts were already released at close — no redactor leak.
    assert filt.active_secret_count() == 0


def test_deferred_store_bounded_and_cleared():
    try:
        for i in range(_DEFERRED_MAX_ENTRIES + 20):
            _stash_deferred_injected(f"exec-{i}", frozenset({f"k{i:03d}-value"}))
        from vaultwarden.hooks import _DEFERRED_INJECTED, _DEFERRED_LOCK
        with _DEFERRED_LOCK:
            assert len(_DEFERRED_INJECTED) <= _DEFERRED_MAX_ENTRIES
        clear_deferred_injected()
        assert consume_deferred_injected("exec-0") == []
    finally:
        clear_deferred_injected()


def test_retain_without_parent_scope_fails_safe(caplog):
    """Missing parent scope: sanitized warning, temporary local scope, no leak."""
    from vaultwarden.security import get_redacting_filter
    filt = get_redacting_filter()
    baseline = filt.active_secret_count()
    with caplog.at_level("WARNING"):
        retain_in_execution_scope("llll-orphan-secret", filt)
    assert filt.active_secret_count() == baseline     # nothing leaked globally
    msgs = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert any("execution secret scope" in m for m in msgs)
    # Sanitized: the value itself never appears in ANY log record.
    assert all("llll-orphan-secret" not in m for m in msgs)


# ---------------------------------------------------- AUD-05 phase 2 wiring
#: The middleware must embed every injected temp path through the shell-safe
#: quoting helper: $(< '/quoted/path') — never the raw $(< /raw/path) form.


def _quoted_frag(path: str) -> str:
    """Expected quoted fragment for *path* (canonical POSIX single-quoting)."""
    return "$(< '" + path.replace("'", "'\\''") + "')"


@pytest.fixture()
def hostile_dir(tmp_path):
    """A hardened (0700, owned) runtime dir whose NAME carries metachars."""
    d = tmp_path / "vw run;dir"
    d.mkdir(mode=0o700)
    yield str(d)
    # best-effort cleanup of any leftover temp files
    for f in os.listdir(d):
        try:
            os.unlink(os.path.join(d, f))
        except OSError:
            pass
    try:
        os.rmdir(d)
    except OSError:
        pass


def _point_secrets_dir_at(monkeypatch, directory: str):
    """Pin BOTH creation and basename checks to a hostile-but-valid dir."""
    monkeypatch.setattr("vaultwarden.hooks.resolve_secrets_dir_path",
                        lambda: __import__("pathlib").Path(directory))
    real_check = __import__("vaultwarden.secure_fs", fromlist=["x"])

    def patched(p, **kw):
        return real_check.ensure_hardened_directory(
            __import__("pathlib").Path(directory), **kw)

    monkeypatch.setattr("vaultwarden.hooks.ensure_hardened_directory",
                        patched)


def test_substitution_emits_quoted_fragment(mw, registry, hostile_dir,
                                            monkeypatch):
    """Normal substitution: rewritten command uses $(< 'quoted-path')."""
    _point_secrets_dir_at(monkeypatch, hostile_dir)
    t = token_for(registry)
    res, seen = run_mw(mw, "terminal", {"command": f'run --secret "{t}"'})
    assert res == {"output": "ran"}
    paths = _injected_paths(seen["command"])
    assert len(paths) == 1
    assert _quoted_frag(paths[0]) in seen["command"]
    assert t not in seen["command"]          # no unresolved leftovers
    assert "sup3r-s3cret-pg!" not in seen["command"]


def test_multi_occurrence_same_quoted_fragment(mw, registry, hostile_dir,
                                               monkeypatch):
    """SEC-02 preserved under AUD-05: ONE resolve call, ONE temp file,
    ALL occurrences rewritten to the SAME quoted fragment."""
    _point_secrets_dir_at(monkeypatch, hostile_dir)
    t = token_for(registry)
    suffix = t[1:][len("__VW_SECRET_"):-len("__")]

    calls: list[str] = []
    real_car = registry.consume_and_resolve

    def spy_car(token):
        calls.append(token)
        return real_car(token)

    monkeypatch.setattr(registry, "consume_and_resolve", spy_car)

    created: list[str] = []
    from vaultwarden import hooks as _hooks_mod
    real_writer = _hooks_mod._write_secret_file

    def spy_writer(token, value, secrets_dir, temp_files):
        path = real_writer(token, value, secrets_dir, temp_files)
        created.append(path)
        return path

    monkeypatch.setattr("vaultwarden.hooks._write_secret_file", spy_writer)

    command = f'curl -H "Auth: {t}" -H "Cookie: {t}" -d "pw={t}"'
    _, seen = run_mw(mw, "terminal", {"command": command})
    out_cmd = seen["command"]

    assert calls == [f"__VW_SECRET_{suffix}__"]   # exactly ONE resolve
    assert len(created) == 1                      # exactly ONE temp file
    frags = set(re.findall(r"\$\(<\s*'[^']*(?:'\\''[^']*)*'\s*\)", out_cmd))
    assert len(frags) == 1                        # ONE distinct fragment
    assert out_cmd.count(frags.pop()) == 3        # reused for all 3 spots
    assert set(_injected_paths(out_cmd)) == {created[0]}
    assert t not in out_cmd
    assert "sup3r-s3cret-pg!" not in out_cmd


def test_runtime_dir_with_space_stays_isolated(mw, registry, hostile_dir,
                                               monkeypatch):
    """Runtime dir containing a SPACE: path is fully quoted, one arg."""
    _point_secrets_dir_at(monkeypatch, hostile_dir)  # dir name has a space
    t = token_for(registry)
    _, seen = run_mw(mw, "terminal", {"command": f"cat {t}"})
    frag = _quoted_frag(_injected_paths(seen["command"])[0])
    assert frag in seen["command"]
    assert " " in frag                            # space lives INSIDE quotes
    # The inner path word is ONE single-quoted token -> the shell never
    # word-splits it.  (shlex.split on the RAW command cannot model the
    # nested single quotes inside $( ... ) -- that is a Python-shlex
    # limitation, already covered by the bash -n tests; here we verify the
    # quoting structure itself: exactly two quote chars and no bare space.)
    inner = frag[len("$(< '"):-2]               # strip "$(< '" and trailing "')"
    assert inner.count("'") == 0                  # nothing closes the quote early
    assert " " in inner                           # space is INSIDE the quotes
    assert seen["command"].count("'") == 2        # only our open/close pair


@pytest.mark.parametrize("meta", [";", "`id`", "$(pwd)", "|", "&", "$HOME"])
def test_runtime_dir_metacharacters_neutralised(mw, registry, tmp_path,
                                                monkeypatch, meta):
    """Runtime dir with ; / backtick / $() / pipe / & : quoted, inert."""
    d = tmp_path / f"vw run{meta}dir"
    d.mkdir(mode=0o700)
    _point_secrets_dir_at(monkeypatch, str(d))
    t = token_for(registry)
    _, seen = run_mw(mw, "terminal", {"command": f"cat {t}"})
    cmd = seen["command"]
    paths = _injected_paths(cmd)
    assert len(paths) == 1 and d.name in paths[0]
    frag = _quoted_frag(paths[0])
    assert frag in cmd                            # properly quoted form
    assert cmd.count("$(") == 1 or meta in ("$(pwd)",)  # $( only inside our op or quoted body
    if BASH:
        chk = subprocess.run([BASH, "-n", "-c", cmd], capture_output=True)
        assert chk.returncode == 0, chk.stderr.decode()


def test_runtime_dir_newline_fails_closed(mw, registry, tmp_path, caplog,
                                          monkeypatch):
    """Control-character runtime dir: fail closed, NO unsafe substitution."""
    d = tmp_path / ("vw bad\ndir")
    d.mkdir(mode=0o700)
    _point_secrets_dir_at(monkeypatch, str(d))
    t = token_for(registry)
    command = f"cat {t}"
    _PENDING_ERRORS.clear()
    with caplog.at_level("ERROR"):
        res, seen = run_mw(mw, "terminal", {"command": command})
    assert res == {"output": "ran"}
    # untouched command passed on: token verbatim ($ expands to empty string)
    assert seen["command"] == command
    assert "$(<" not in seen["command"]           # no substitution emitted
    pending = [e for errs in _PENDING_ERRORS.values() for e in errs]
    assert any(e["error_code"] == "PLACEHOLDER_ERROR" for e in pending)
    # sanitized logging only: secret value never appears anywhere
    joined = " ".join(r.getMessage() for r in caplog.records)
    assert "sup3r-s3cret-pg!" not in joined
    _PENDING_ERRORS.clear()


def test_middleware_not_run_fallback_expands_empty(hostile_dir):
    """$-prefix fail-safe: without the middleware the shell still runs the
    command and $__VW_SECRET_x__ expands to an EMPTY string (no error)."""
    if not BASH:
        pytest.skip("bash not available")
    probe = os.path.join(hostile_dir, "probe.txt")
    cmd = f'printf %s "${{__VW_SECRET_deadbeefcafe__}}" > {shlex.quote(probe)}'
    rc = subprocess.run([BASH, "-c", cmd], capture_output=True)
    assert rc.returncode == 0                     # valid shell syntax
    with open(probe) as fh:
        assert fh.read() == ""                    # empty expansion


def test_redaction_still_applied_after_quoting(mw, registry, auth_manager,
                                               hostile_dir, monkeypatch):
    """SEC-01 unchanged: the authoritative transform_tool_result redactor
    still scrubs echoes even though the injected fragment is now quoted."""
    from vaultwarden.hooks import make_result_redactor

    _point_secrets_dir_at(monkeypatch, hostile_dir)
    redact = make_result_redactor(auth_manager, registry)
    t = token_for(registry)
    _, seen = run_mw(mw, "terminal", {"command": f"cat {t}"},
                     task_id="aud05-red")
    frag = _quoted_frag(_injected_paths(seen["command"])[0])
    leaked = {"output": f"leaked sup3r-s3cret-pg! via {frag} done"}
    observed = redact("terminal", leaked, task_id="aud05-red")
    assert "sup3r-s3cret-pg!" not in observed["output"]
    assert "[REDACTED]" in observed["output"]
    assert frag in observed["output"]          # path itself stays visible


def test_executed_expansion_reads_dummy_file(tmp_path):
    """Execute (synthetic dummy, NOT a real secret): bash expands the
    quoted fragment to the exact file content, spaces included."""
    if not BASH:
        pytest.skip("bash not available")
    d = tmp_path / "dummy run dir"
    d.mkdir()
    dummy = d / "secretfile"
    dummy.write_text("DUMMY-NOT-A-SECRET\n")
    frag = quote_injected_path(str(dummy))
    rc = subprocess.run([BASH, "-c", f'echo "value={frag}"'],
                        capture_output=True)
    assert rc.returncode == 0
    assert rc.stdout.decode().strip() == "value=DUMMY-NOT-A-SECRET"


def test_current_execution_scope_none_outside_execution():
    assert current_execution_scope() is None

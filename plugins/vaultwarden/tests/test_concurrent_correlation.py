"""Concurrent secret-correlation regression tests (execution-scoped handoff).

The redaction handoff (ContextVar -> active-scope registry -> deferred grace
store -> correlation-keyed task store) must key EVERY stage by the unique
per-tool-call id (Hermes ``tool_call_id``), not by the shared ``task_id``.
Keying by task_id let two concurrent tool calls of the same task overwrite
each other's snapshots: the authoritative ``transform_tool_result`` redactor
could then scrub a result with the WRONG secret set and leave this call's
own plaintext secret in the model context.

These tests drive the real middleware + transformer pair (same construction
the SEC-01 E2E suite uses) with genuinely overlapping executions and prove:

1. two overlapping calls sharing ONE task_id but with different tool_call_ids
   keep completely separate secret sets;
2. both completion orders (A finishes first / B finishes first) preserve each
   call's own snapshot;
3. transformer invocations issued while BOTH scopes are active stay correct;
4. repeated result transformation of the same call is idempotent;
5. each call's output is redacted with ITS OWN set (the other call's set is
   never borrowed — the counterpart secret provably survives);
6. cleanup after both executions finish leaves no stale deferred / task
   entries, and closing one scope never corrupts the concurrent one;
7. when the host provides no tool_call_id the task_id fallback still
   functions, warning exactly once per process (sanitized).
"""
from __future__ import annotations

import logging
import re
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from vaultwarden.auth import AuthManager
from vaultwarden.config import PluginConfig
from vaultwarden.hooks import (
    _ACTIVE_SCOPES,
    _ACTIVE_SCOPES_LOCK,
    _DEFERRED_INJECTED,
    _DEFERRED_LOCK,
    _INJECTED_LOCK,
    _INJECTED_SECRETS,
    _PENDING_ERRORS,
    _PENDING_LOCK,
    ExecutionSecretScope,
    active_scope_count,
    clear_deferred_injected,
    clear_task_secrets,
    consume_deferred_injected,
    get_redacting_filter,
    make_placeholder_resolver,
    make_result_redactor,
    peek_scope_injected_secrets,
    peek_task_secrets,
    take_task_secrets,
)
from vaultwarden.placeholders import PlaceholderRegistry
from vaultwarden.security import RedactingFilter

# ---------------------------------------------------------------------------
# Scenario constants. Two DISTINCT vault items -> two distinct plaintext
# secrets; both calls share ONE task_id but carry distinct tool_call_ids.
# ---------------------------------------------------------------------------

TASK = "task-shared-by-both-calls"
CALL_A = "call-aaaa-0001"
CALL_B = "call-bbbb-0002"

ITEM_A = "aaaa1111-0000-0000-0000-000000000001"   # seeded fake item (Postgres)
ITEM_B = "aaaa1111-0000-0000-0000-000000000002"   # seeded fake item (Grafana)

SECRET_A = "conc-ALPHA-9f3a-PLAINTEXT-DO-NOT-LEAK"
SECRET_B = "conc-BETA-7c1d-PLAINTEXT-DO-NOT-LEAK"

SUBST_RE = re.compile(r"\$\(<\s*(?:'([^']+)'|\"([^\"]+)\"|(/[^)\s]+))\)")

_TIMEOUT = 15.0  # barrier/event safety net: failing tests surface, never hang


def _subst_path(command: str) -> str | None:
    m = SUBST_RE.search(command)
    if m is None:
        return None
    return m.group(1) or m.group(2) or m.group(3)


@pytest.fixture(autouse=True)
def _isolate_global_handoff_state():
    """Keep the module-level handoff stores test-to-test sterile.

    Deferred/task/pending stores and the active-scope registry are process
    globals; a leaked entry from one test would let the next one pass on
    someone else's snapshot. Cleared before AND after every test here.
    """
    def _reset() -> None:
        clear_deferred_injected()
        clear_task_secrets()
        with _ACTIVE_SCOPES_LOCK:
            _ACTIVE_SCOPES.clear()
        with _INJECTED_LOCK:
            _INJECTED_SECRETS.clear()
        with _PENDING_LOCK:
            _PENDING_ERRORS.clear()

    _reset()
    yield
    _reset()


def _wait_until(predicate: Any, timeout: float, what: str) -> None:
    """Deterministic wait for an in-flight condition (no sleeps-of-doom)."""
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            pytest.fail(f"condition never became true: {what}")
        time.sleep(0.01)


class _Harness:
    """Wires the real middleware/transformer pair over an isolated filter,
    an isolated secrets dir and seeded vault items. Placeholder tokens are
    SINGLE-USE, so every simulated call must mint its own via new_entry()."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
                 auth: AuthManager, registry: PlaceholderRegistry,
                 config: PluginConfig) -> None:
        # Isolate the global RedactingFilter (same pattern as the SEC-01 E2E
        # suite): injected plaintexts must never leak into other suites and
        # the deferred-channel tests below assert against a clean filter.
        self.isolated = RedactingFilter()
        monkeypatch.setattr("vaultwarden.security._shared_filter",
                            self.isolated, raising=True)
        monkeypatch.setattr("vaultwarden.hooks.get_redacting_filter",
                            lambda: self.isolated, raising=True)

        xdg = tmp_path / "xdg-runtime"
        xdg.mkdir(mode=0o700)
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))

        # Serve the two known plaintexts from the two seeded fake items.
        real_get_item = AuthManager.get_item
        passwords = {ITEM_A: SECRET_A, ITEM_B: SECRET_B}

        def patched_get_item(self: AuthManager, query: str) -> dict:
            item = dict(real_get_item(self, query))
            if item.get("id") in passwords:
                login = dict(item.get("login") or {})
                login["password"] = passwords[item["id"]]
                item["login"] = login
            return item

        monkeypatch.setattr(AuthManager, "get_item", patched_get_item)

        self.auth = auth
        self.registry = registry
        self.middleware = make_placeholder_resolver(auth, registry, config)
        self.transform = make_result_redactor(auth, registry, config)

    def new_entry(self, item_id: str) -> Any:
        """Fresh single-use placeholder for one simulated tool call."""
        return self.registry.create(item_id, "password")

    def read_temp(self, command: str) -> str:
        path = _subst_path(command)
        assert path is not None, f"no $(< path) in rewritten command: {command!r}"
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def run_call(self, *, entry: Any, tool_call_id: str | None,
                 task_id: str = TASK, hook: Any = None) -> dict:
        """One full middleware frame. ``hook`` replaces the simulated shell:
        it receives the rewritten command and must return the raw result."""

        def default_hook(args: dict) -> dict:
            return {"output": self.read_temp(args["command"]) + "\n"}

        kwargs: dict[str, Any] = {"task_id": task_id}
        if tool_call_id is not None:
            kwargs["tool_call_id"] = tool_call_id
        return self.middleware(
            "terminal",
            {"command": f'cat "${entry.token}"'},
            None,
            hook or default_hook,
            **kwargs,
        )


@pytest.fixture()
def harness(monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
            auth_manager: AuthManager, registry: PlaceholderRegistry,
            plugin_config: PluginConfig) -> _Harness:
    return _Harness(monkeypatch, tmp_path, auth_manager, registry,
                    plugin_config)


def _join_threads(threads: list[threading.Thread],
                  failures: dict[str, str]) -> None:
    for t in threads:
        t.join(timeout=_TIMEOUT)
        assert not t.is_alive(), "worker thread deadlocked"
    assert not failures, f"assertions failed inside worker threads: {failures}"


# ---------------------------------------------------------------------------
# 1. Overlapping calls, ONE task_id, different tool_call_ids: the active-
#    scope lookup resolves each call's OWN set; the deferred snapshots stay
#    independent (a second close must not overwrite the first entry).
# ---------------------------------------------------------------------------

def test_overlapping_same_task_id_scopes_resolve_secret_sets_independently(
        harness: _Harness) -> None:
    failures: dict[str, str] = {}
    inside = threading.Barrier(2, timeout=_TIMEOUT)
    peeked = threading.Barrier(2, timeout=_TIMEOUT)
    peeks: dict[str, list[str]] = {}
    raws: dict[str, dict] = {}

    def worker(name: str, entry: Any, call_id: str) -> None:
        try:
            def hook(args: dict) -> dict:
                raw = harness.read_temp(args["command"]) + "\n"
                # Both scopes are now open simultaneously: the EXACT-match
                # lookup must return THIS call's set and never the other's.
                inside.wait(timeout=_TIMEOUT)
                mine = peek_scope_injected_secrets(call_id)
                other = peek_scope_injected_secrets(
                    CALL_B if call_id == CALL_A else CALL_A)
                peeks[call_id] = mine
                want_mine = SECRET_A if call_id == CALL_A else SECRET_B
                want_other = SECRET_B if call_id == CALL_A else SECRET_A
                if mine != [want_mine]:
                    failures[f"peek-{call_id}"] = f"wrong own set: {mine!r}"
                if other != [want_other]:
                    failures[f"peek-other-{call_id}"] = (
                        f"other call resolved wrong: {other!r}")
                # Do NOT return before the peer finished its peeks: a fast
                # worker closing its frame would make the peer's cross-
                # lookup race-free-impossible (scope already gone).
                peeked.wait(timeout=_TIMEOUT)
                raws[call_id] = {"output": raw}
                return raws[call_id]

            harness.run_call(entry=entry, tool_call_id=call_id, hook=hook)
        except Exception as exc:  # pragma: no cover - failure path
            failures[name] = repr(exc)

    threads = [threading.Thread(target=worker,
                                args=("A", harness.new_entry(ITEM_A), CALL_A)),
               threading.Thread(target=worker,
                                args=("B", harness.new_entry(ITEM_B), CALL_B))]
    for t in threads:
        t.start()
    _join_threads(threads, failures)

    assert len(peeks) == 2
    assert peeks[CALL_A] == [SECRET_A]
    assert peeks[CALL_B] == [SECRET_B]

    # Frames are closed now: the transformer must find EACH call's own
    # deferred snapshot keyed by its tool_call_id — with the pre-fix
    # task_id keying exactly one of these two asserts would necessarily
    # fail, because the second scope close overwrote the first entry.
    out_a = harness.transform("terminal", raws[CALL_A], task_id=TASK,
                              tool_call_id=CALL_A)
    out_b = harness.transform("terminal", raws[CALL_B], task_id=TASK,
                              tool_call_id=CALL_B)
    assert SECRET_A not in str(out_a) and "[REDACTED]" in out_a["output"]
    assert SECRET_B not in str(out_b) and "[REDACTED]" in out_b["output"]


# ---------------------------------------------------------------------------
# 2. Completion orders: whichever execution closes FIRST must not damage
#    the still-open one's future snapshot, and the closed one's snapshot
#    must survive the other's later close intact.
# ---------------------------------------------------------------------------

def test_both_completion_orders_keep_own_snapshots_intact(
        harness: _Harness) -> None:
    failures: dict[str, str] = {}

    def ordered(tag: str, first_call: str, first_item: str,
                first_secret: str, second_call: str, second_item: str,
                second_secret: str) -> None:
        opened = threading.Event()
        release = threading.Event()

        def slow_hook(args: dict) -> dict:
            harness.read_temp(args["command"])
            opened.set()
            assert release.wait(timeout=_TIMEOUT)
            return {"output": f"out: {second_secret}\n"}

        # SECOND call enters its frame first and blocks inside next_call...
        t2 = threading.Thread(
            target=lambda: harness.run_call(
                entry=harness.new_entry(second_item),
                tool_call_id=second_call, hook=slow_hook),
            name=f"slow-{tag}")
        t2.start()
        assert opened.wait(timeout=_TIMEOUT)

        # ...while the FIRST call runs to FULL completion (frame closed,
        # deferred entry stashed, correlation-keyed task entry popped).
        harness.run_call(entry=harness.new_entry(first_item),
                         tool_call_id=first_call)

        # A closed first frame must NOT have touched the still-open scope:
        # the open execution is still exactly resolvable by its own id.
        assert peek_scope_injected_secrets(second_call) == [second_secret]
        # And it must not have consumed/destroyed the open one's future key.
        assert peek_task_secrets(second_call) == [second_secret]

        release.set()
        t2.join(timeout=_TIMEOUT)
        assert not t2.is_alive()

        # The first call's snapshot survived the second scope's close:
        # exact-key consumption returns FIRST's secret, never SECOND's.
        got = consume_deferred_injected(first_call)
        if got != [first_secret]:
            failures[f"{first_call}->{second_call}"] = (
                f"snapshot corrupted: {got!r}")
        if peek_task_secrets(first_call):
            failures[f"{first_call}-taskstore"] = "stale task-store entry"

    try:
        ordered("1", CALL_A + "-o1", ITEM_A, SECRET_A,
                CALL_B + "-o1", ITEM_B, SECRET_B)
        ordered("2", CALL_B + "-o2", ITEM_B, SECRET_B,
                CALL_A + "-o2", ITEM_A, SECRET_A)
    except Exception as exc:  # pragma: no cover - failure path
        failures["exception"] = repr(exc)
    assert not failures, failures


# ---------------------------------------------------------------------------
# 3. Transformer invocations issued while BOTH scopes are still open must
#    read the active-scope channel with exact correlation matching.
# ---------------------------------------------------------------------------

def test_concurrent_transform_invocations_while_both_scopes_active(
        harness: _Harness) -> None:
    failures: dict[str, str] = {}
    hold = threading.Barrier(3, timeout=_TIMEOUT)  # worker A + B + main
    entered = {"a": threading.Event(), "b": threading.Event()}

    def worker(entry: Any, call_id: str, flag: str) -> None:
        try:
            def hook(args: dict) -> dict:
                harness.read_temp(args["command"])
                # Resolution is complete and retained once the rewritten
                # command ran: enter next_call visibility via this event.
                entered[flag].set()
                hold.wait(timeout=_TIMEOUT)
                return {"output": "not-yet-delivered\n"}
            harness.run_call(entry=entry, tool_call_id=call_id, hook=hook)
        except Exception as exc:  # pragma: no cover - failure path
            failures[f"worker-{call_id}"] = repr(exc)

    threads = [threading.Thread(target=worker,
                                args=(harness.new_entry(ITEM_A), CALL_A, "a")),
               threading.Thread(target=worker,
                                args=(harness.new_entry(ITEM_B), CALL_B, "b"))]
    for t in threads:
        t.start()

    # Both middleware frames are inside next_call AND both placeholders
    # have been resolved (the events fire only after the rewritten command
    # read its temp file): both scopes active with complete injected sets.
    assert entered["a"].wait(timeout=_TIMEOUT)
    assert entered["b"].wait(timeout=_TIMEOUT)
    assert active_scope_count() == 2

    # Exact-match separation at peek level during the overlap: neither call
    # resolves to the other's scope despite the shared task_id.
    assert peek_scope_injected_secrets(CALL_A) == [SECRET_A]
    assert peek_scope_injected_secrets(CALL_B) == [SECRET_B]

    # The main thread carries no ContextVar handoff, so transformer calls
    # made HERE (dispatched concurrently while both scopes live) must come
    # out through the active-scope registry with the RIGHT set per id.
    res_a = {"output": f"echo: {SECRET_A} and {SECRET_B}\n"}
    res_b = {"output": f"echo: {SECRET_B} and {SECRET_A}\n"}

    def transform_in_thread(result: dict, call_id: str,
                            out: dict[str, Any]) -> None:
        out["value"] = harness.transform("terminal", result, task_id=TASK,
                                         tool_call_id=call_id)

    box_a: dict[str, Any] = {}
    box_b: dict[str, Any] = {}
    tx = [threading.Thread(target=transform_in_thread,
                           args=(res_a, CALL_A, box_a)),
          threading.Thread(target=transform_in_thread,
                           args=(res_b, CALL_B, box_b))]
    for t in tx:
        t.start()
    for t in tx:
        t.join(timeout=_TIMEOUT)
        assert not t.is_alive()

    # SECRET_A leaves res_a through call A's EXACT active-scope channel;
    # SECRET_B leaving res_a is the global refcounted filter's doing (call
    # B's scope still retains it) — never call B's snapshot borrowed into
    # call A's handoff. Symmetric for res_b.
    assert SECRET_A not in box_a["value"]["output"]
    assert SECRET_B not in box_a["value"]["output"]
    assert SECRET_B not in box_b["value"]["output"]
    assert SECRET_A not in box_b["value"]["output"]

    # Release the held workers (only now do their scopes close).
    hold.wait(timeout=_TIMEOUT)
    _join_threads(threads, failures)

    # After the frames close, the deferred stores still hold each call's
    # exact snapshot (the synthetic results above never consumed them for
    # the real raws) — consume them once to prove independence of keys.
    assert consume_deferred_injected(CALL_A) == [SECRET_A]
    assert consume_deferred_injected(CALL_B) == [SECRET_B]


# ---------------------------------------------------------------------------
# 4. Repeated result transformation of the SAME call: the first dispatch
#    consumes the one-shot snapshot; a second dispatch must not resurrect
#    plaintext nor crash (idempotent over an already-clean result).
# ---------------------------------------------------------------------------

def test_repeated_transform_of_same_call_is_idempotent(
        harness: _Harness) -> None:
    raw = harness.run_call(entry=harness.new_entry(ITEM_A),
                           tool_call_id=CALL_A)
    assert SECRET_A in raw["output"]  # plaintext reached the result

    once = harness.transform("terminal", raw, task_id=TASK,
                             tool_call_id=CALL_A)
    assert once["output"] == "[REDACTED]\n"

    twice = harness.transform("terminal", once, task_id=TASK,
                              tool_call_id=CALL_A)
    assert twice["output"] == "[REDACTED]\n"
    assert SECRET_A not in str(twice)
    # No stale deferred entry survives the single consumption.
    assert consume_deferred_injected(CALL_A) == []


# ---------------------------------------------------------------------------
# 5. Each call's output is redacted with ITS OWN secret set — and provably
#    NOT the other call's set: a secret only the OTHER call knows must
#    SURVIVE this call's redaction.
# ---------------------------------------------------------------------------

def test_each_result_scrubbed_with_own_secret_set_not_the_others(
        harness: _Harness) -> None:
    # B enters its frame first and blocks; A runs to completion; then B.
    opened = threading.Event()
    release = threading.Event()

    def hook_b(args: dict) -> dict:
        harness.read_temp(args["command"])
        opened.set()
        assert release.wait(timeout=_TIMEOUT)
        return {"output": f"out: {SECRET_B} plus {SECRET_A}\n"}

    t = threading.Thread(target=lambda: harness.run_call(
        entry=harness.new_entry(ITEM_B), tool_call_id=CALL_B, hook=hook_b))
    t.start()
    assert opened.wait(timeout=_TIMEOUT)
    raw_a = harness.run_call(entry=harness.new_entry(ITEM_A),
                             tool_call_id=CALL_A)
    release.set()
    t.join(timeout=_TIMEOUT)
    assert not t.is_alive()

    # A's deferred snapshot carries ONLY SECRET_A: applied to a result
    # containing both secrets, SECRET_B must deliberately SURVIVE (proof
    # the transformer did not consume B's snapshot while handling A).
    raw_a["output"] = f"out: {SECRET_A} plus {SECRET_B}\n"
    out_a = harness.transform("terminal", raw_a, task_id=TASK,
                              tool_call_id=CALL_A)
    assert "[REDACTED]" in out_a["output"] and SECRET_A not in out_a["output"]
    assert SECRET_B in out_a["output"], (
        "A redacted with B's set — correlation leaked: "
        f"{out_a['output']!r}")

    raw_b = {"output": f"out: {SECRET_B} plus {SECRET_A}\n"}
    out_b = harness.transform("terminal", raw_b, task_id=TASK,
                              tool_call_id=CALL_B)
    assert "[REDACTED]" in out_b["output"] and SECRET_B not in out_b["output"]
    assert SECRET_A in out_b["output"], (
        "B redacted with A's set — correlation leaked: "
        f"{out_b['output']!r}")


# ---------------------------------------------------------------------------
# 6. Cleanup correctness: closing one scope never corrupts the concurrent
#    scope's deferred entry or correlation-keyed task entry, and after both
#    executions finish NOTHING stale remains in any store.
# ---------------------------------------------------------------------------

def test_cleanup_after_both_executions_leaves_no_stale_entries(
        harness: _Harness) -> None:
    # ---- store-level close isolation (unit probe over REAL scopes) ----
    filt = get_redacting_filter()
    s1 = ExecutionSecretScope(filt)
    s2 = ExecutionSecretScope(filt)
    s1._correlation_id = "corr-1"
    s2._correlation_id = "corr-2"
    s1.retain("unit-secret-one")
    s2.retain("unit-secret-two")
    with _INJECTED_LOCK:
        _INJECTED_SECRETS["corr-1"] = ["unit-secret-one"]
        _INJECTED_SECRETS["corr-2"] = ["unit-secret-two"]
    s1.close()  # closes while the concurrent scope is still open
    with _DEFERRED_LOCK:
        assert "corr-2" not in _DEFERRED_INJECTED  # close 1 never writes 2
        assert list(_DEFERRED_INJECTED) == ["corr-1"]
    assert consume_deferred_injected("corr-1") == ["unit-secret-one"]
    s2.close()
    with _DEFERRED_LOCK:
        assert list(_DEFERRED_INJECTED) == ["corr-2"]
    assert consume_deferred_injected("corr-2") == ["unit-secret-two"]
    assert take_task_secrets("corr-1") == ["unit-secret-one"]
    assert peek_task_secrets("corr-2") == ["unit-secret-two"]  # untouched
    assert take_task_secrets("corr-2") == ["unit-secret-two"]

    # ---- pipeline level: both real executions fully finish ----
    raw_a = harness.run_call(entry=harness.new_entry(ITEM_A),
                             tool_call_id=CALL_A)
    raw_b = harness.run_call(entry=harness.new_entry(ITEM_B),
                             tool_call_id=CALL_B)
    out_a = harness.transform("terminal", raw_a, task_id=TASK,
                              tool_call_id=CALL_A)
    out_b = harness.transform("terminal", raw_b, task_id=TASK,
                              tool_call_id=CALL_B)
    assert SECRET_A not in str(out_a) and SECRET_B not in str(out_b)

    with _DEFERRED_LOCK:
        assert _DEFERRED_INJECTED == {}          # both snapshots consumed
    with _INJECTED_LOCK:
        assert _INJECTED_SECRETS == {}           # both correlation keys gone
    assert active_scope_count() == 0             # no leaked active scope


# ---------------------------------------------------------------------------
# 7. Fallback: a host that provides NO tool_call_id still correlates on
#    task_id end-to-end, and the degraded mode is logged EXACTLY ONCE per
#    process — sanitized, never carrying secret material.
# ---------------------------------------------------------------------------

def test_fallback_to_task_id_without_tool_call_id(
        harness: _Harness, monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture) -> None:
    import vaultwarden.hooks as hooks_mod
    monkeypatch.setattr(hooks_mod, "_MISSING_TOOL_CALL_ID_WARNED", False,
                        raising=True)

    with caplog.at_level(logging.WARNING,
                         logger="hermes.plugins.vaultwarden.hooks"):
        raw1 = harness.run_call(entry=harness.new_entry(ITEM_A),
                                tool_call_id=None)
        out1 = harness.transform("terminal", raw1, task_id=TASK)
        assert SECRET_A not in str(out1) and "[REDACTED]" in out1["output"]

        # A second legacy-style call: the shared task_id fallback still
        # functions end-to-end for every handoff stage.
        raw2 = harness.run_call(entry=harness.new_entry(ITEM_B),
                                tool_call_id=None)
        out2 = harness.transform("terminal", raw2, task_id=TASK)
        assert SECRET_B not in str(out2) and "[REDACTED]" in out2["output"]

    fallback = [r for r in caplog.records
                if "falling back to" in r.getMessage().lower()]
    assert len(fallback) == 1, (
        f"expected exactly one fallback warning, got {len(fallback)}")
    joined = "\n".join(r.getMessage() for r in caplog.records)
    assert SECRET_A not in joined and SECRET_B not in joined
    assert TASK not in joined  # identifier VALUES are not logged either
    # Nothing stale after the fallback executions either.
    with _DEFERRED_LOCK:
        assert _DEFERRED_INJECTED == {}
    with _INJECTED_LOCK:
        assert _INJECTED_SECRETS == {}

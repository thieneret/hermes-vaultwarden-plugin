"""Pending-error correlation regression tests (diagnostic telemetry).

Follow-up to the concurrent secret-correlation fix: `_PENDING_ERRORS` is
diagnostic telemetry (fail-closed placeholder errors surfaced to the agent
by post_tool_call) — NOT a confidentiality boundary. But while it stayed
keyed by the shared task_id, two concurrent tool calls of one task could
overwrite or steal each other's pending-error entries: a lost diagnostic, or
a misattributed one. It is now keyed by the SAME per-tool-call correlation
id (tool_call_id -> task_id -> turn_id, single shared resolver) used by the
secret-handoff chain, with per-call cleanup in post_tool_call.

Proved here (mirroring the secret-correlation test pattern):

1. two overlapping calls, one task_id, two tool_call_ids, each raising a
   DIFFERENT error — both pending errors are kept and surfaced to the
   correct call;
2. both completion orders (deterministic, event-gated) keep the entries
   isolated while one call is still in flight;
3. cleanup after both calls leaves no stale pending-error entries;
4. the task_id fallback still surfaces errors when tool_call_id is absent
   (and the surfaced text stays sanitized).
"""
from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from vaultwarden.config import PluginConfig
from vaultwarden.hooks import (
    _ACTIVE_SCOPES,
    _ACTIVE_SCOPES_LOCK,
    _PENDING_ERRORS,
    _PENDING_LOCK,
    active_scope_count,
    make_placeholder_resolver,
    make_post_cleanup_hook,
)
from vaultwarden.placeholders import PlaceholderRegistry

TASK = "task-shared-errors"
CALL_A = "call-err-aaaa-01"
CALL_B = "call-err-bbbb-02"

#: Unknown (never-registered) placeholder bodies: consume_and_resolve fails
#: atomically -> a PLACEHOLDER_ERROR whose message names THAT token, which
#: is exactly what makes the two calls' diagnostics distinguishable.
TOK_A = "0badc0ffee01"
TOK_B = "0badf00dcafe"

_TIMEOUT = 15.0  # safety net: failing tests surface, never hang


@pytest.fixture(autouse=True)
def _isolate_pending_state():
    """Sterile pending-error store + scope registry around every test."""
    def _reset() -> None:
        with _PENDING_LOCK:
            _PENDING_ERRORS.clear()
        with _ACTIVE_SCOPES_LOCK:
            _ACTIVE_SCOPES.clear()

    _reset()
    yield
    _reset()


class _Harness:
    """Middleware + observer over a REAL (empty) placeholder registry — the
    unknown-token path fails resolution atomically BEFORE any vault access,
    so auth is never consulted and can stay a MagicMock."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
                 config: PluginConfig) -> None:
        xdg = tmp_path / "xdg-runtime"
        xdg.mkdir(mode=0o700)
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))

        self.registry = PlaceholderRegistry(ttl_seconds=300, max_entries=50)
        self.middleware = make_placeholder_resolver(MagicMock(), self.registry,
                                                    config)
        self.post = make_post_cleanup_hook(MagicMock(), self.registry)

    def run_call(self, *, token: str, tool_call_id: str | None,
                 task_id: str = TASK, hook: Any = None) -> dict:
        kwargs: dict[str, Any] = {"task_id": task_id}
        if tool_call_id is not None:
            kwargs["tool_call_id"] = tool_call_id

        def default_hook(args: dict) -> dict:
            return {"output": "ran"}

        return self.middleware(
            "terminal",
            {"command": f"cat $__VW_SECRET_{token}__"},
            None,
            hook or default_hook,
            **kwargs,
        )

    def surface(self, *, tool_call_id: str | None = None,
                task_id: str = TASK) -> list[dict]:
        res: dict = {"output": "ok"}
        kwargs: dict[str, Any] = {"task_id": task_id}
        if tool_call_id is not None:
            kwargs["tool_call_id"] = tool_call_id
        self.post("terminal", {}, res, **kwargs)
        return res.get("vaultwarden_placeholder_errors", [])


@pytest.fixture()
def harness(monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
            plugin_config: PluginConfig) -> _Harness:
    return _Harness(monkeypatch, tmp_path, plugin_config)


def _join_threads(threads: list[threading.Thread],
                  failures: dict[str, str]) -> None:
    for t in threads:
        t.join(timeout=_TIMEOUT)
        assert not t.is_alive(), "worker thread deadlocked"
    assert not failures, f"assertions failed inside worker threads: {failures}"


def _pending_snapshot() -> dict[str, str]:
    """correlation key -> concatenated error texts (lock-safe copy).
    Error dicts carry 'error' (message), 'error_code', 'suggestion'."""
    with _PENDING_LOCK:
        return {k: " | ".join(e.get("error", "") for e in v)
                for k, v in _PENDING_ERRORS.items()}


def _assert_sanitized(errors: list[dict]) -> None:
    """Surfaced diagnostics carry no version numbers and no audit IDs
    (standing rule); only codes / placeholder tokens / suggestions."""
    joined = " ".join(str(e) for e in errors)
    assert not re.search(r"\bv\d+\.\d+", joined), f"version in error text: {joined!r}"
    assert not re.search(r"(?i)\b(hva|vwp|aud|sec)[-_]?[0-9]", joined), \
        f"audit ID in error text: {joined!r}"


# ---------------------------------------------------------------------------
# 1. Overlapping calls, one task_id, two tool_call_ids: each call's
#    PLACEHOLDER_ERROR lands under ITS OWN key and is surfaced to the
#    matching post_tool_call only.
# ---------------------------------------------------------------------------

def test_overlapping_calls_keep_separate_pending_error_entries(
        harness: _Harness) -> None:
    failures: dict[str, str] = {}
    inside = threading.Barrier(2, timeout=_TIMEOUT)
    verified = threading.Barrier(2, timeout=_TIMEOUT)

    def worker(name: str, token: str, call_id: str) -> None:
        try:
            def hook(args: dict) -> dict:
                # The middleware stashed THIS call's error before entering
                # next_call; both frames are open past the barrier, so the
                # store must show two INDEPENDENT, correctly keyed entries.
                inside.wait(timeout=_TIMEOUT)
                snap = _pending_snapshot()
                mine = snap.get(call_id, "")
                other = snap.get(CALL_B if call_id == CALL_A else CALL_A, "")
                want = TOK_A if call_id == CALL_A else TOK_B
                unwanted = TOK_B if call_id == CALL_A else TOK_A
                if want not in mine or unwanted in mine:
                    failures[f"store-{call_id}"] = f"wrong entry: {mine!r}"
                if unwanted not in other or want in other:
                    failures[f"store-other-{call_id}"] = (
                        f"other call's entry wrong: {other!r}")
                # Hold until the peer finished inspecting the store: a fast
                # worker returning early would race the peer's snapshot.
                verified.wait(timeout=_TIMEOUT)
                return {"output": "ran"}

            harness.run_call(token=token, tool_call_id=call_id, hook=hook)
        except Exception as exc:  # pragma: no cover - failure path
            failures[name] = repr(exc)

    threads = [threading.Thread(target=worker, args=("A", TOK_A, CALL_A)),
               threading.Thread(target=worker, args=("B", TOK_B, CALL_B))]
    for t in threads:
        t.start()
    _join_threads(threads, failures)

    # post_tool_call surfacing: each call gets exactly ITS OWN diagnostic.
    errs_a = harness.surface(tool_call_id=CALL_A)
    errs_b = harness.surface(tool_call_id=CALL_B)
    assert len(errs_a) == 1 and TOK_A in errs_a[0]["error"]
    assert TOK_B not in errs_a[0]["error"]
    assert len(errs_b) == 1 and TOK_B in errs_b[0]["error"]
    assert TOK_A not in errs_b[0]["error"]
    for e in errs_a + errs_b:
        assert e["error_code"] == "PLACEHOLDER_ERROR"
        _assert_sanitized([e])


# ---------------------------------------------------------------------------
# 2. Both completion orders: a fully-finished call's post surfacing must
#    leave the still-open call's future entry untouched (and vice versa).
# ---------------------------------------------------------------------------

def test_both_completion_orders_keep_entries_isolated(
        harness: _Harness) -> None:
    failures: dict[str, str] = {}

    def ordered(tag: str, first_call: str, first_tok: str,
                second_call: str, second_tok: str) -> None:
        opened = threading.Event()
        release = threading.Event()

        def slow_hook(args: dict) -> dict:
            opened.set()
            assert release.wait(timeout=_TIMEOUT)
            return {"output": "ran"}

        # SECOND call enters its frame first (its error is already stashed
        # under second_call) and blocks inside next_call...
        t2 = threading.Thread(
            target=lambda: harness.run_call(token=second_tok,
                                            tool_call_id=second_call,
                                            hook=slow_hook),
            name=f"slow-{tag}")
        t2.start()
        assert opened.wait(timeout=_TIMEOUT)

        # ...while the FIRST call completes fully.
        harness.run_call(token=first_tok, tool_call_id=first_call)

        snap = _pending_snapshot()
        if first_tok not in snap.get(first_call, ""):
            failures[f"{first_call}-stashed"] = f"missing own entry: {snap!r}"
        if second_tok not in snap.get(second_call, ""):
            failures[f"{second_call}-intact"] = (
                f"concurrent entry damaged: {snap!r}")

        # post surfacing for the FINISHED call must not touch the open one.
        errs = harness.surface(tool_call_id=first_call)
        if not (len(errs) == 1 and first_tok in errs[0]["error"]):
            failures[f"{first_call}-surface"] = f"wrong surface: {errs!r}"
        snap2 = _pending_snapshot()
        if second_tok not in snap2.get(second_call, ""):
            failures[f"{second_call}-after-post"] = (
                f"post consumed concurrent entry: {snap2!r}")

        release.set()
        t2.join(timeout=_TIMEOUT)
        if t2.is_alive():  # pragma: no cover - failure path
            failures[f"{second_call}-hang"] = "thread stuck"

    try:
        ordered("1", CALL_A + "-o1", TOK_A, CALL_B + "-o1", TOK_B)
        ordered("2", CALL_B + "-o2", TOK_B, CALL_A + "-o2", TOK_A)
    except Exception as exc:  # pragma: no cover - failure path
        failures["exception"] = repr(exc)
    assert not failures, failures

    # The still-open-side calls eventually posted nowhere yet — their
    # entries linger until their own post/cleanup; drain deterministically.
    for call_id in (CALL_B + "-o1", CALL_A + "-o2"):
        errs = harness.surface(tool_call_id=call_id)
        assert len(errs) == 1


# ---------------------------------------------------------------------------
# 3. Cleanup: after both calls ran and posted, NO stale pending-error
#    entries remain for their correlation keys.
# ---------------------------------------------------------------------------

def test_cleanup_after_both_calls_leaves_no_stale_entries(
        harness: _Harness) -> None:
    harness.run_call(token=TOK_A, tool_call_id=CALL_A)
    harness.run_call(token=TOK_B, tool_call_id=CALL_B)

    snap = _pending_snapshot()
    assert CALL_A in snap and CALL_B in snap  # both stashed while pending
    assert TOK_A in snap[CALL_A] and TOK_B in snap[CALL_B]

    errs_a = harness.surface(tool_call_id=CALL_A)
    errs_b = harness.surface(tool_call_id=CALL_B)
    assert len(errs_a) == 1 and len(errs_b) == 1

    snap2 = _pending_snapshot()
    assert CALL_A not in snap2 and CALL_B not in snap2
    assert any(e["error_code"] == "PLACEHOLDER_ERROR"
               for e in errs_a + errs_b)
    assert active_scope_count() == 0  # scope lifecycle also clean


# ---------------------------------------------------------------------------
# 4. Fallback: host provides no tool_call_id -> task_id correlation still
#    stashes AND surfaces the diagnostic end-to-end, sanitized.
# ---------------------------------------------------------------------------

def test_fallback_task_id_still_surfaces_errors(harness: _Harness) -> None:
    harness.run_call(token=TOK_A, tool_call_id=None)  # legacy-style call

    snap = _pending_snapshot()
    assert TASK in snap and TOK_A in snap[TASK]
    assert CALL_A not in snap  # no per-call key was ever derived

    errs = harness.surface(task_id=TASK)  # observer without tool_call_id
    assert len(errs) == 1
    assert TOK_A in errs[0]["error"]
    assert errs[0]["error_code"] == "PLACEHOLDER_ERROR"
    _assert_sanitized(errs)

    snap2 = _pending_snapshot()
    assert TASK not in snap2  # per-correlation cleanup done

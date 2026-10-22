"""VWP-18: Concurrency tests for placeholder generation and consumption.

Validates that the single-use placeholder registry is thread-safe and that
race conditions (e.g. two threads consuming the same placeholder) are
handled correctly.

NOTE on single-use semantics: ``PlaceholderRegistry.consume()`` raises
``errors.PlaceholderError`` (code PLACEHOLDER_ERROR, "already used") for a
replay — it never returns None for a known token. The loser of a consume
race therefore fails GRACEFULLY with PlaceholderError, exactly like the
existing ``test_concurrent_consume_single_winner`` guard in
test_placeholders.py. This file keeps that contract visible under several
additional race shapes (stampede barrier + create/consume mixes).
"""
import threading

import pytest

from vaultwarden import errors
from vaultwarden.placeholders import PlaceholderRegistry


def _run_threads(n, target, args_per_thread=None):
    """Start n identical-ish threads, join all, return nothing."""
    threads = []
    for i in range(n):
        args = (args_per_thread[i] if args_per_thread else ())
        threads.append(threading.Thread(target=target, args=args))
    for t in threads:
        t.start()
    for t in threads:
        t.join()


class TestPlaceholderConcurrency:
    def test_concurrent_placeholder_creation(self):
        """Multiple threads creating placeholders get unique tokens."""
        registry = PlaceholderRegistry(ttl_seconds=300, max_entries=200)
        tokens = []
        failures = []

        def create_placeholder():
            try:
                entry = registry.create("test-item", "password")
                tokens.append(entry.token)
            except Exception as e:  # noqa: BLE001 - surfaced via assertion below
                failures.append(e)

        _run_threads(20, create_placeholder)

        assert not failures, f"Errors during concurrent creation: {failures}"
        assert len(tokens) == 20, "All threads should create a placeholder"
        assert len(set(tokens)) == 20, "All tokens must be unique (no race condition)"

    def test_concurrent_consumption_same_placeholder(self):
        """Only one thread can consume a placeholder; the others fail gracefully."""
        registry = PlaceholderRegistry(ttl_seconds=300)
        entry = registry.create("test-item", "password")
        results = []
        unexpected_errors = []
        replay_errors = []
        barrier = threading.Barrier(5)

        def consume_placeholder():
            try:
                barrier.wait()  # maximize the race window
                consumed = registry.consume(entry.token)
                results.append(consumed is not None)
            except errors.PlaceholderError as exc:
                # expected, graceful single-use rejection for the losers
                replay_errors.append(exc)
            except Exception as e:  # noqa: BLE001 - surfaced via assertion below
                unexpected_errors.append(e)

        _run_threads(5, consume_placeholder)

        assert not unexpected_errors, (
            f"Unexpected errors during consumption: {unexpected_errors}")
        assert sum(results) == 1, "Exactly one thread should consume the placeholder"
        assert len(replay_errors) == 4, (
            "Every losing thread must fail gracefully with PlaceholderError "
            "(single-use policy), never receive None or an unhandled exception")
        # after the race the entry is gone from the registry (used + removed)
        assert registry.peek(entry.token) is None

    def test_concurrent_different_placeholders(self):
        """Different placeholders can be consumed concurrently without conflict."""
        registry = PlaceholderRegistry(ttl_seconds=300)
        entries = [registry.create(f"item-{i}", "password") for i in range(10)]
        results = []
        failures = []

        def consume_placeholder(token):
            try:
                consumed = registry.consume(token)
                results.append(consumed is not None)
            except Exception as e:  # noqa: BLE001 - surfaced via assertion below
                failures.append(e)

        _run_threads(10, consume_placeholder,
                     args_per_thread=[(entry.token,) for entry in entries])

        assert not failures, f"Errors during concurrent consumption: {failures}"
        assert sum(results) == 10, "All placeholders should be consumed"

    def test_concurrent_mixed_create_and_cleanup(self):
        """create/consume/cleanup_used racing must not corrupt the registry."""
        registry = PlaceholderRegistry(ttl_seconds=300, max_entries=500)
        created = []
        lock = threading.Lock()

        def producer():
            for _ in range(20):
                try:
                    entry = registry.create("mixed-item", "password")
                except errors.PlaceholderError:
                    return  # cap reached under contention — acceptable
                with lock:
                    created.append(entry.token)
                try:
                    registry.consume(entry.token)
                except errors.PlaceholderError:
                    pass

        def cleaner():
            for _ in range(40):
                registry.cleanup_used()

        threads = ([threading.Thread(target=producer) for _ in range(4)]
                   + [threading.Thread(target=cleaner) for _ in range(2)])
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # every produced token was unique and none survives as consumable
        assert len(set(created)) == len(created)
        for token in created:
            with pytest.raises(errors.PlaceholderError):
                registry.consume(token)  # consumed and/or cleaned already
        assert registry.active_tokens() == []

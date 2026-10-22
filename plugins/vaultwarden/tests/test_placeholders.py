"""Unit tests: PlaceholderRegistry — format, TTL, single-use, cap, concurrency."""
from __future__ import annotations

import re
import threading

import pytest

from vaultwarden import errors
from vaultwarden.placeholders import TOKEN_PREFIX, PlaceholderRegistry

TOKEN_RE = re.compile(r"^__VW_SECRET_[0-9a-f]{12}__$")


def test_token_format_and_entropy():
    reg = PlaceholderRegistry(ttl_seconds=300)
    entry = reg.create("item-uuid", "password")
    assert TOKEN_RE.match(entry.token)
    body = entry.token[len(TOKEN_PREFIX):-2]
    assert len(body) == 12 and body.islower()
    # v0.1.4 (FAIL-3): the registry caps live entries at max_entries (default 50).
    # The first token above is still live, so creating another 50 would hit the
    # cap; drop it first so the entropy check starts from a clean slate.
    reg.remove(entry.token)
    tokens = {reg.create("i", "password").token for _ in range(50)}
    assert len(tokens) == 50  # collision-free in practice


def test_entry_shape_matches_plan():
    reg = PlaceholderRegistry(ttl_seconds=300)
    e = reg.create("uuid-1", "totp")
    d = e.as_dict()
    assert set(d) == {"item_id", "field", "created_at", "ttl_seconds", "used"}
    assert d["item_id"] == "uuid-1" and d["field"] == "totp"
    assert d["ttl_seconds"] == 300 and d["used"] is False


def test_single_use():
    reg = PlaceholderRegistry()
    e = reg.create("id", "password")
    first = reg.consume(e.token)          # ok
    assert first.used is True
    with pytest.raises(errors.PlaceholderError):
        reg.consume(e.token)              # replay rejected + removed
    assert reg.peek(e.token) is None


def test_ttl_expiry(monkeypatch):
    reg = PlaceholderRegistry(ttl_seconds=1)
    e = reg.create("id", "password")
    monkeypatch.setattr("time.time", lambda: e.created_at + 2)
    assert reg.peek(e.token) is None
    with pytest.raises(errors.PlaceholderError) as ei:
        reg.consume(e.token)
    assert "expired" in ei.value.message.lower()
    assert reg.snapshot() == {}           # purged on access


def test_purge_expired_and_cleanup_used():
    reg = PlaceholderRegistry(ttl_seconds=300)
    a = reg.create("x", "password")
    b = reg.create("y", "username")
    reg.consume(a.token)                  # mark used (stays until cleanup)
    assert reg.cleanup_used() == 1
    assert list(reg.snapshot()) == [b.token]
    b.created_at -= 400                   # force expiry
    assert reg.purge_expired() == 1
    assert reg.snapshot() == {}


def test_max_placeholders_cap():
    reg = PlaceholderRegistry(max_entries=3)
    for i in range(3):
        reg.create(f"id{i}", "password")
    with pytest.raises(errors.PlaceholderError):
        reg.create("one-too-many", "password")


def test_clear_wipes_all():
    reg = PlaceholderRegistry()
    reg.create("a", "password")
    reg.create("b", "notes")
    reg.clear()
    assert reg.snapshot() == {}


def test_concurrent_create_unique_and_bounded():
    reg = PlaceholderRegistry(max_entries=200)
    tokens: list[str] = []
    lock = threading.Lock()

    def worker():
        for _ in range(20):
            try:
                e = reg.create("id", "password")
            except errors.PlaceholderError:
                return
            with lock:
                tokens.append(e.token)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(set(tokens)) == len(tokens) <= 200


def test_concurrent_consume_single_winner():
    reg = PlaceholderRegistry()
    e = reg.create("id", "password")
    winners = []

    def worker():
        try:
            reg.consume(e.token)
            winners.append(1)
        except errors.PlaceholderError:
            pass

    ts = [threading.Thread(target=worker) for _ in range(10)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(winners) == 1   # exactly one resolution despite races

"""Placeholder Registry (plan §6).

Maps single-use tokens ``__VW_SECRET_<12 hex>__`` -> (item_id, field).
The resolved secret value is fetched lazily at resolution time via the
AuthManager and is NEVER stored in the registry or returned to the LLM.

Invariants:
- token generation: secrets.token_hex(6)  (2^48 collision space)
- TTL default 300s (configurable), purged on access + explicit purge()
- single-use: a token is consumed atomically on first resolution
- storage: in-memory dict only; concurrency guarded by threading.Lock
- max_placeholders cap prevents unbounded registry growth
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field

from . import errors
from .security import get_logger

log = get_logger("placeholders")

TOKEN_PREFIX = "__VW_SECRET_"
TOKEN_SUFFIX = "__"


def _token_shape(token: str) -> bool:
    body = token[len(TOKEN_PREFIX):-len(TOKEN_SUFFIX)] if (
        token.startswith(TOKEN_PREFIX) and token.endswith(TOKEN_SUFFIX)) else ""
    return len(body) == 12 and all(c in "0123456789abcdef" for c in body)


@dataclass
class PlaceholderEntry:
    token: str
    item_id: str
    field_name: str          # password|username|totp|notes|uri|custom:<name>
    created_at: float
    ttl_seconds: float
    used: bool = False
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "item_id": self.item_id,
            "field": self.field_name,
            "created_at": self.created_at,
            "ttl_seconds": self.ttl_seconds,
            "used": self.used,
        }


class PlaceholderRegistry:
    def __init__(self, *, ttl_seconds: int = 300, max_entries: int = 50):
        self._ttl = max(1, int(ttl_seconds))
        self._max = max(1, int(max_entries))
        self._entries: dict[str, PlaceholderEntry] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ api
    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    def create(self, item_id: str, field_name: str) -> PlaceholderEntry:
        """Register a new single-use placeholder for (item_id, field_name)."""
        with self._lock:
            self._purge_locked()
            if len(self._entries) >= self._max:
                raise errors.PlaceholderError(
                    f"Placeholder limit reached ({self._max}); "
                    "unused tokens were not created.",
                    suggestion="Use pending placeholders or wait for TTL expiry.")
            for _attempt in range(5):
                token = f"{TOKEN_PREFIX}{secrets.token_hex(6)}{TOKEN_SUFFIX}"
                if token not in self._entries:
                    break
            else:  # pragma: no cover - astronomically unlikely
                raise errors.PlaceholderError("Token collision; try again.")
            entry = PlaceholderEntry(
                token=token, item_id=item_id, field_name=field_name,
                created_at=time.time(), ttl_seconds=self._ttl)
            self._entries[token] = entry
            log.debug("Created placeholder %s for item=%s field=%s",
                      token, item_id, field_name)
            return entry

    def peek(self, token: str) -> PlaceholderEntry | None:
        """Non-consuming lookup (unknown/expired/already-used -> None).

        SEC-02 (v0.5.7): the middleware no longer needs a non-consuming
        lookup on the injection path — :meth:`consume_and_resolve` is the
        single atomic primitive. ``peek`` stays as a safe introspection
        helper; it reports already-used tokens as ``None`` so callers can
        never mistake a consumed placeholder for a live one.
        """
        with self._lock:
            entry = self._entries.get(token)
            if entry is None or entry.used or self._expired_locked(entry):
                return None
            return entry

    def consume_and_resolve(self, token: str) -> PlaceholderEntry | None:
        """SEC-02 (v0.5.7): atomically mark *token* consumed AND return its
        entry in one locked operation.

        The entry is marked used BEFORE it is handed back to the caller, so
        the very same token can never be resolved twice — even when a single
        command string references it multiple times (the middleware resolves
        each unique token exactly once and maps every occurrence onto the
        same injected temp file).

        Returns ``None`` (never raises) when the token is unknown, expired,
        or already consumed; expired/used entries are dropped from the
        registry, mirroring :meth:`consume`. Raising-vs-returning policy is
        left to the caller (the middleware logs a warning and fails safe).
        """
        with self._lock:
            entry = self._entries.get(token)
            if entry is None:
                return None
            if self._expired_locked(entry):
                del self._entries[token]
                return None
            if entry.used:
                del self._entries[token]
                return None
            entry.used = True
            return entry

    def consume(self, token: str) -> PlaceholderEntry:
        """Atomically mark a token used and return it (single-use enforcement).

        Raises PLACEHOLDER_ERROR for unknown/expired/already-used tokens.

        .. deprecated:: 0.5.7
            SEC-02 refactored the middleware onto
            :meth:`consume_and_resolve`, which never raises. This raising
            variant is retained only for existing test/consumer call sites;
            new code should use ``consume_and_resolve``.
        """
        with self._lock:
            entry = self._entries.get(token)
            if entry is None:
                raise errors.PlaceholderError(
                    f"Unknown placeholder '{token}'.",
                    suggestion="Request a fresh one via vaultwarden_get_secret_ref.")
            if self._expired_locked(entry):
                del self._entries[token]
                raise errors.PlaceholderError(
                    f"Placeholder '{token}' expired (TTL {int(entry.ttl_seconds)}s).")
            if entry.used:
                del self._entries[token]
                raise errors.PlaceholderError(
                    f"Placeholder '{token}' was already used (single-use policy).")
            entry.used = True
            return entry

    def remove(self, token: str) -> None:
        with self._lock:
            self._entries.pop(token, None)

    def cleanup_used(self) -> int:
        """post_tool_call hook: drop every token already consumed."""
        with self._lock:
            used = [t for t, e in self._entries.items() if e.used]
            for t in used:
                del self._entries[t]
        if used:
            log.debug("Cleaned up %d used placeholder(s).", len(used))
        return len(used)

    def purge_expired(self) -> int:
        with self._lock:
            return self._purge_locked()

    def clear(self) -> None:
        """on_session_end / shutdown: wipe the whole mapping."""
        with self._lock:
            n = len(self._entries)
            self._entries.clear()
        if n:
            log.debug("Cleared %d placeholder(s) from registry.", n)

    def snapshot(self) -> dict[str, dict]:
        """Safe introspection (ids/fields only — never secret values)."""
        with self._lock:
            return {t: e.as_dict() for t, e in self._entries.items()}

    def active_tokens(self) -> list[str]:
        with self._lock:
            return [t for t, e in self._entries.items()
                    if not e.used and not self._expired_locked(e)]

    # -------------------------------------------------------------- internal
    def _expired_locked(self, entry: PlaceholderEntry) -> bool:
        return (time.time() - entry.created_at) > entry.ttl_seconds

    def _purge_locked(self) -> int:
        expired = [t for t, e in self._entries.items() if self._expired_locked(e)]
        for t in expired:
            del self._entries[t]
        return len(expired)

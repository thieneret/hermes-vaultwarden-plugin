"""Security primitives: log redaction, subprocess-env auditing, escaping.

Design rules (plan §10):
- Secrets flow ONE WAY: secrets.yaml -> plugin memory -> subprocess env.
  NEVER reverse; they never enter os.environ (v0.5.0 BREAKING: the .env
  channel was removed — see secrets.py).
- Only these keys may ever appear in a bw subprocess env carrying secrets:
    BW_SESSION, BW_CLIENTID, BW_CLIENTSECRET, BW_MP
  plus the non-secret plumbing keys PATH, HOME, BITWARDENCLI_APPDATA_DIR.
- Master password / client secret / session key are NEVER logged.
- Shell context values are escaped with shlex.quote(); URL-context values with
  urllib.parse.quote_plus(). Unknown context -> apply both conservatively.
"""
from __future__ import annotations

import json as _json
import logging
import re
import shlex
import threading
import urllib.parse
from typing import Any

# Keys allowed to exist in an isolated bw subprocess environment.
BW_ENV_ALLOWLIST = frozenset({
    "PATH",
    "HOME",
    "BITWARDENCLI_APPDATA_DIR",
    "BW_SESSION",
    "BW_CLIENTID",
    "BW_CLIENTSECRET",
    "BW_MP",
})

# Legacy bootstrap env names: since v0.5.0 these must NEVER appear in
# os.environ at all (secrets come from secrets.yaml, not the environment).
SECRET_ENV_NAMES = ("VW_CLIENT_SECRET", "VW_MASTER_PASSWORD")

_TOKEN_RE = re.compile(r"__VW_SECRET_([0-9a-f]{12})__")

#: Logger for redactor-internal diagnostics (AUD-02). Deliberately a plain
#: logging.Logger WITHOUT the RedactingFilter attached: the filter must never
#: recurse into its own logging, and every message emitted through it is
#: sanitized by construction (counts / lengths only, never secret values).
_module_logger = logging.getLogger(__name__)


def is_placeholder(text: str) -> bool:
    return isinstance(text, str) and "__VW_SECRET_" in text


def placeholder_tokens(text: str) -> list[str]:
    """Return the ordered unique tokens found in *text*."""
    seen: list[str] = []
    for m in _TOKEN_RE.finditer(text or ""):
        tok = m.group(0)
        if tok not in seen:
            seen.append(tok)
    return seen


def shell_escape(value: str) -> str:
    """Escape for direct shell interpolation."""
    return shlex.quote(value if isinstance(value, str) else str(value))


def url_escape(value: str) -> str:
    """Escape for embedding inside a URL userinfo/param component."""
    return urllib.parse.quote_plus(value if isinstance(value, str) else str(value), safe="")


def looks_like_url_context(command: str, token: str) -> bool:
    """True when *token* sits between '://' and '@' (URL userinfo context)."""
    idx = command.find(token)
    if idx < 0:
        return False
    # scan the "word" containing the token up to the next whitespace
    end = command.find(" ", idx)
    if end == -1:
        end = len(command)
    word = command[idx:end]
    prefix = command[max(0, idx - 16):idx]
    suffix = command[end:min(len(command), end + 32)]
    return ("://" in prefix + word.split(token)[0]) and "@" in (word.split(token)[-1] + suffix)


def escape_for_context(value: str, command: str, token: str) -> str:
    """Context-aware escaping of a resolved secret before injection.

    - URL context (between :// and @): percent-encode only (the whole arg is
      already shell-quoted by the caller's command construction).
    - Shell context: shlex.quote.
    - Unknown: apply BOTH conservatively (quote_plus then shlex.quote).
    """
    if looks_like_url_context(command, token):
        return url_escape(value)
    if "://" in command and "@" in command[command.find(token):]:
        # token appears after a scheme and before a later '@' on same line:
        # still ambiguous -> conservative double escaping
        return shell_escape(url_escape(value))
    return shell_escape(value)


class RedactingFilter(logging.Filter):
    """Logging filter that masks known secret values and session keys.

    Session keys are rendered as [SESSION:****]; master password / client
    secret / resolved credentials are replaced entirely with [REDACTED].

    AUD-02 (phase 1): execution-scoped secrets are retained with reference
    counts (:meth:`retain_secret` / :meth:`release_secret`) so a value still
    in use by another active execution is never dropped, while values whose
    last holder released them leave the redaction state instead of lingering
    for the process lifetime. Long-lived bootstrap material is marked
    permanent (:meth:`register_process_scoped_secret`) and can never be
    removed by an execution-scoped release. ``register_secret`` /
    ``forget_secret`` keep working unchanged: they map onto retain/release
    semantics (a plain register on an already-permanent secret does not
    change its permanence).
    """

    def __init__(self) -> None:
        super().__init__()
        # RLock: re-entrant, so public entry points may compose the private
        # _*_locked helpers without risking deadlock or lock-ordering bugs.
        self._lock = threading.RLock()
        self._secrets: set[str] = set()
        self._secret_refcounts: dict[str, int] = {}
        self._permanent_secrets: set[str] = set()

    # ---------------------------------------------------- internal (locked)
    def _retain_locked(self, value: str) -> None:
        """Increment the refcount for *value* (caller must hold ``_lock``)."""
        self._secret_refcounts[value] = self._secret_refcounts.get(value, 0) + 1
        self._secrets.add(value)

    def _release_locked(self, value: str) -> bool:
        """Decrement the refcount for *value*; drop it when it hits zero.

        Permanent secrets are NEVER removed from the redaction state — their
        refcount is clamped at 1 instead. Returns True when *value* had a
        live registration before this call (False => unknown release).
        Caller must hold ``_lock``.
        """
        count = self._secret_refcounts.get(value)
        if count is None:
            return False
        if value in self._permanent_secrets:
            # Never below one: execution-scoped releases must not remove a
            # process-scoped secret.
            self._secret_refcounts[value] = max(count - 1, 1)
            return True
        if count <= 1:
            del self._secret_refcounts[value]
            self._secrets.discard(value)
        else:
            self._secret_refcounts[value] = count - 1
        return True

    def _bootstrap_locked(self, value: str) -> None:
        """Register *value* as process-scoped WITHOUT inflating its refcount.

        AUD-02 phase 2: long-lived material (bootstrap credentials, session
        keys, startup-injection values) is re-registered on every unlock /
        SecretSource refresh. Under plain retain semantics each refresh
        would add a +1 that NEVER has a matching release — unbounded global
        retention. Permanent values are clamped at refcount 1 by
        :meth:`_release_locked`, so ensuring a baseline of exactly one here
        keeps them permanently redacted while remaining releasable through
        the legacy lifecycle path (see :meth:`demote_process_scoped`).
        Caller must hold ``_lock``.
        """
        self._permanent_secrets.add(value)
        self._secrets.add(value)
        if self._secret_refcounts.get(value, 0) < 1:
            self._secret_refcounts[value] = 1

    def demote_process_scoped(self, value: str) -> bool:
        """Return *value* to normal refcounted retention (AUD-02 phase 2).

        Used by the session-key lifecycle: while unlocked the key is
        process-scoped (a mid-session execution-scoped release must never
        drop it); when the vault locks, the owning component releases its
        bootstrap pin first. Demotion clears permanence ONLY while the value
        still sits at the bootstrap baseline (refcount <= 1): any active
        execution-scoped holder keeps the value permanent AND redacted, so a
        lock operation can never prematurely remove a secret another
        in-flight execution still needs. Returns True when permanence was
        actually cleared. Never raises; empty values are ignored.
        """
        if not value:
            return False
        with self._lock:
            if value not in self._permanent_secrets:
                return False
            if self._secret_refcounts.get(value, 0) > 1:
                # Active execution holders: keep it pinned & permanent.
                return False
            self._permanent_secrets.discard(value)
            if value not in self._secret_refcounts:
                # No live registration left at all — drop from redaction.
                self._secrets.discard(value)
            return True

    # ------------------------------------------------------------ lifecycle
    def retain_secret(self, value: str) -> None:
        """
        Increment reference count for an execution-scoped secret.

        The value stays redacted until every holder released it (see
        :meth:`release_secret`). Empty / too-short values are ignored,
        matching :meth:`register_secret`'s historical minimum-length guard.
        """
        if not value or len(value) < 4:
            return
        with self._lock:
            self._retain_locked(value)

    def release_secret(self, value: str) -> None:
        """
        Decrement reference count for an execution-scoped secret.

        Remove from redaction state only when count reaches zero and the
        secret is not permanent. Releasing an unknown value is a no-op that
        logs a sanitized warning (length fingerprint only — the value itself
        is never logged).
        """
        if not value:
            return
        with self._lock:
            known = self._release_locked(value)
        if not known:
            # Sanitized diagnostic: never expose the secret value here.
            _module_logger.warning(
                "Redactor release for unknown secret (len=%d); ignored.",
                len(value))

    def register_process_scoped_secret(self, value: str) -> None:
        """
        Mark/retain a long-lived secret for the process lifetime.

        Execution-scoped releases (:meth:`release_secret` /
        :meth:`forget_secret`) must not remove it. Idempotent: repeated
        calls do not inflate the refcount beyond one — long-lived material
        is re-registered on every unlock/refresh and must never accumulate
        phantom refcounts (AUD-02: no unbounded global retention).
        """
        if not value or len(value) < 4:
            return
        with self._lock:
            self._bootstrap_locked(value)

    def active_secret_count(self) -> int:
        """
        Return number of currently retained secret values.

        Must not expose values.
        """
        with self._lock:
            return len(self._secrets)

    def has_secret(self, value: str) -> bool:
        """
        Test helper. Must not log the value.
        """
        with self._lock:
            return value in self._secrets

    # ------------------------------------------------------- compatibility
    def register_secret(self, value: str) -> None:
        """Register a runtime secret value to scrub from every log record.

        AUD-02 phase 1: behaves like :meth:`retain_secret` — unless the
        value is already process-scoped/permanent, in which case its
        permanence (and refcount) are left untouched.
        """
        if not value or len(value) < 4:
            return
        with self._lock:
            if value in self._permanent_secrets:
                # Permanence preserved; make sure the value is still part of
                # the redaction state, but never inflate its refcount.
                self._secrets.add(value)
                self._secret_refcounts.setdefault(value, 1)
                return
            self._retain_locked(value)

    def forget_secret(self, value: str) -> None:
        """Release a previously registered secret (refcount-aware).

        Behaves like :meth:`release_secret`: the value leaves the redaction
        state only when its last holder releases it and it is not permanent.
        """
        self.release_secret(value)

    def snapshot_secrets(self) -> list[str]:
        """Thread-safe copy of the registered secret values, LONGEST first.

        SEC-01 (v0.5.4): public accessor so consumers (the authoritative
        `transform_tool_result` redactor) can apply exact plaintext
        replacement without touching private state. Longest-first ordering
        matches :meth:`redact`, keeping overlapping values deterministic.
        """
        with self._lock:
            return sorted(self._secrets, key=len, reverse=True)

    def redact(self, text: str) -> str:
        if not isinstance(text, str) or not text:
            return text
        # generic session-key shapes first (bw --raw output / JWT-ish blobs)
        text = re.sub(r"(?i)(session[_ ]?key[\"':= ]{0,3})[A-Za-z0-9+/=_\-]{20,}",
                      r"\1[SESSION:****]", text)
        text = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:"
                      r"[A-Za-z0-9+/=_\-]{20,}\b", "[SESSION:****]", text)
        with self._lock:
            secrets = set(self._secrets)
        for sec in sorted(secrets, key=len, reverse=True):
            if sec in text:
                text = text.replace(sec, "[REDACTED]")
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return True
        redacted = self.redact(msg)
        if redacted != msg:
            record.msg = redacted
            record.args = ()
        return True


#: shared filter instance used by all plugin modules.
#: AUD-02 (phase 2): resolved LAZILY through :func:`get_redacting_filter`
#: only. Module-level singletons must NOT eagerly capture the shared
#: instance, because tests isolate suites by swapping
#: ``vaultwarden.security._shared_filter`` — an eager module global would
#: pin a stale instance and silently break that isolation.
_shared_filter = RedactingFilter()


def get_redacting_filter() -> RedactingFilter:
    return _shared_filter


_SECRET_KEY_PATTERNS = (
    "password", "passphrase", "secret", "token", "key",
    "credential", "api_key", "apikey", "master_password",
    "client_secret", "session_key",
)


class StructuredJsonFormatter(logging.Formatter):
    """JSON formatter that redacts secret-like keys at format time.

    This is a defense-in-depth layer: it ensures that even if a caller
    accidentally passes a secret value in a structured log field, it
    will be replaced with [REDACTED] before the record reaches any
    handler or sink.
    """

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Include structured extra fields if present
        vw_extra = getattr(record, "vw_extra", None)
        if isinstance(vw_extra, dict):
            entry["data"] = self._redact_dict(vw_extra)
        return _json.dumps(entry, ensure_ascii=False)

    def _redact_dict(self, d: dict[str, Any]) -> dict[str, Any]:
        """Recursively redact values whose keys match secret patterns."""
        result: dict[str, Any] = {}
        for k, v in d.items():
            if any(p in k.lower() for p in _SECRET_KEY_PATTERNS):
                result[k] = "[REDACTED]"
            elif isinstance(v, dict):
                result[k] = self._redact_dict(v)
            else:
                result[k] = v
        return result


def log_structured(logger: logging.Logger, level: int, message: str,
                   **fields) -> None:
    """Emit a structured log record with automatic secret redaction."""
    record = logger.makeRecord(
        logger.name, level, "(unknown)", 0, message, (), None
    )
    record.vw_extra = fields
    logger.handle(record)


def get_logger(name: str) -> logging.Logger:
    """Logger wired into the shared redaction filter.

    v0.1.7: ensures at least one handler exists so plugin logs are visible
    even when Hermes does not configure the hermes.plugins.* hierarchy.

    v0.3.6 (VWP-07): the fallback StreamHandler uses StructuredJsonFormatter
    so plugin log output is JSON with secret-like fields redacted at format
    time. The RedactingFilter remains on the logger as an additional
    defense-in-depth layer; both layers coexist.
    """
    logger = logging.getLogger(f"hermes.plugins.vaultwarden.{name}")
    if not any(isinstance(f, RedactingFilter) for f in logger.filters):
        logger.addFilter(_shared_filter)
    # Ensure visibility: if neither this logger nor the root logger has
    # handlers, add a StreamHandler so logs appear in container stdout.
    if not logger.handlers and not logging.getLogger().handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(StructuredJsonFormatter())
        logger.addHandler(handler)
    return logger


def audit_subprocess_env(env: dict) -> list[str]:
    """Return violations: keys present that are not on the allowlist.

    Used by tests and (optionally) at runtime to guarantee we never leak the
    full parent environment into bw.
    """
    return sorted(k for k in env if k not in BW_ENV_ALLOWLIST)

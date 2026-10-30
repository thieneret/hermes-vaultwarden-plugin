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

    AUD-02 (v0.6.5): retention is reference-counted and SCOPED. Every
    retained value carries two independent counts behind one RLock:

    - ``_secret_refcounts`` — execution-scoped references held by active
      tool executions (see ``hooks.ExecutionSecretScope``). A value leaves
      the redaction state only when its execution refcount reaches zero
      AND no process-scoped baseline remains, so overlapping executions
      that share a secret can never cause premature removal;
    - ``_process_scoped`` — long-lived bootstrap/startup secrets that must
      stay redactable for the whole process lifetime and are NEVER released
      by execution-scoped cleanup.

    ``register_secret()`` / ``forget_secret()`` remain available for
    backward compatibility but are now SYMMETRIC one-shot helpers for
    legacy call sites: each ``register_secret()`` takes exactly ONE
    baseline reference that its paired ``forget_secret()`` drops again —
    so a legacy caller can never leak a permanent baseline into the
    shared filter (AUD-02: no unbounded global retention). Values with
    several owners keep one baseline count per distinct value; the last
    paired forget removes it. New code must NOT use these: runtime
    injected secrets go through the scoped ``retain_secret()`` /
    ``release_secret()`` APIs, genuinely long-lived secrets through
    :meth:`register_process_scoped_secret`.
    """

    def __init__(self) -> None:
        super().__init__()
        # RLock: redact()/snapshot_secrets() run inside logging calls made
        # while other public methods hold the lock — re-entrancy is required.
        self._lock = threading.RLock()
        self._secrets: set[str] = set()
        # AUD-02: thread-safe reference-counted scoped retention.
        self._secret_refcounts: dict[str, int] = {}
        self._process_scoped: dict[str, int] = {}
        # AUD-02: number of symmetric one-shot baselines taken via
        # register_secret() per value. forget_secret() drops exactly one
        # such reference when available; values with several legacy
        # registrants keep the baseline until the LAST paired forget.
        self._legacy_baselines: dict[str, int] = {}

    # ------------------------------------------------------------- legacy API
    def register_secret(self, value: str) -> None:
        """Take ONE symmetric baseline reference for *value* (legacy API).

        AUD-02: pairs with :meth:`forget_secret` — every registration is
        releasable, so legacy/unscoped call sites can never grow the
        redaction state indefinitely. Internally backed by the same
        process-baseline layer as :meth:`register_process_scoped_secret`,
        but tracked per value so the paired ``forget_secret()`` releases
        precisely this one reference. Never logs the value.
        """
        if not value or len(value) < 4:
            return
        with self._lock:
            self._secrets.add(value)
            self._process_scoped[value] = self._process_scoped.get(value, 0) + 1
            self._legacy_baselines[value] = self._legacy_baselines.get(value, 0) + 1

    def forget_secret(self, value: str) -> None:
        """Drop ONE retention layer for *value* (paired legacy API).

        AUD-02 symmetric semantics: when the value carries a
        :meth:`register_secret` baseline reference, exactly that one
        reference is dropped (mirroring the paired registration); other
        owners' baselines and execution-scoped references are untouched.
        For values WITHOUT any tracked owner (e.g. an explicit session-key
        invalidation by its lifecycle owner), falls back to dropping ALL
        layers so a rotated/expired key can never stay registered —
        fail-safe direction for that explicit-invalidate use case. Never
        logs the value.
        """
        if not value:
            return
        with self._lock:
            # AUD-02 (v0.6.5): minimum-length policy IDENTICAL to the
            # scoped/process registration APIs. Values shorter than 4 chars
            # can never ENTER the registry (retain_secret /
            # register_process_scoped_secret ignore them), so forget_secret
            # must not be able to strip a legitimate short baseline that a
            # legacy caller registered directly either — keeping the floors
            # symmetric guarantees every registered value stays redactable
            # until its owner releases it (fail-safe direction: prefer
            # over-redaction over under-redaction).
            if len(value) < 4:
                return
            legacy = self._legacy_baselines.get(value, 0)
            if legacy > 0 or value in self._process_scoped:
                # Paired legacy release: drop exactly ONE baseline
                # reference (prefer the tracked legacy count when present).
                if legacy > 0:
                    if legacy <= 1:
                        del self._legacy_baselines[value]
                    else:
                        self._legacy_baselines[value] = legacy - 1
                base = self._process_scoped.get(value, 0)
                if base > 0:
                    if base <= 1:
                        del self._process_scoped[value]
                    else:
                        self._process_scoped[value] = base - 1
                if (value not in self._process_scoped
                        and value not in self._secret_refcounts):
                    self._secrets.discard(value)
            else:
                # Untracked value: explicit invalidate-everything fallback
                # (e.g. a locked/expired session key whose owner already
                # released its own bookkeeping).
                self._secrets.discard(value)
                self._secret_refcounts.pop(value, None)
                self._process_scoped.pop(value, None)

    # ---------------------------------------------------- AUD-02 scoped API
    def retain_secret(self, value: str) -> None:
        """Increment the execution-scoped reference count for a secret value.

        Used by execution scopes for runtime-injected secrets: the value
        stays redactable until every scope that retained it has released it.
        Empty/short values follow the same minimum-length policy as
        :meth:`register_secret`. Never logs the value.
        """
        if not value or len(value) < 4:
            return
        with self._lock:
            self._secrets.add(value)
            self._secret_refcounts[value] = self._secret_refcounts.get(value, 0) + 1

    def release_secret(self, value: str) -> None:
        """Decrement the execution-scoped reference count for a secret value.

        The value is removed from the redaction state ONLY when its count
        reaches zero and no process-scoped baseline retention remains.
        Releasing an unknown value emits a sanitized WARNING (length +
        error class only — NEVER the value itself) and never decrements
        below zero.
        """
        if not value:
            return
        warn_unknown = False
        with self._lock:
            count = self._secret_refcounts.get(value)
            if count is None:
                warn_unknown = True
            elif count <= 1:
                del self._secret_refcounts[value]
                if value not in self._process_scoped:
                    self._secrets.discard(value)
            else:
                self._secret_refcounts[value] = count - 1
        if warn_unknown:
            # Sanitized diagnostic, emitted OUTSIDE the lock: never expose
            # the secret value — length only.
            _logger.warning(
                "RedactingFilter.release_secret called for an unknown "
                "runtime secret (len=%d); ignoring (no negative counts).",
                len(value))

    def register_process_scoped_secret(self, value: str) -> None:
        """Retain a long-lived secret for the process lifetime.

        Bootstrap secrets (client secret / master password), startup-
        injection secrets and live session keys go through here: execution-
        scoped release must NEVER remove their baseline retention.
        Idempotent per call site — repeated registrations add one baseline
        reference each and require a matching :meth:`release_process_scoped_secret`
        (or an explicit :meth:`forget_secret`) to drop.
        """
        if not value or len(value) < 4:
            return
        with self._lock:
            self._secrets.add(value)
            self._process_scoped[value] = self._process_scoped.get(value, 0) + 1

    def release_process_scoped_secret(self, value: str) -> None:
        """Drop ONE process-scoped baseline retention for *value*.

        Only used by shutdown paths that explicitly invalidate a long-lived
        secret (e.g. a locked/expired session key). When both the execution
        refcount and the remaining process baseline reach zero, the value
        leaves the redaction state. Never logs the value.
        """
        if not value:
            return
        warn_missing = False
        with self._lock:
            count = self._process_scoped.get(value)
            if count is None:
                warn_missing = True
            elif count <= 1:
                del self._process_scoped[value]
                if value not in self._secret_refcounts:
                    self._secrets.discard(value)
            else:
                self._process_scoped[value] = count - 1
        if warn_missing:
            _logger.warning(
                "RedactingFilter.release_process_scoped_secret called "
                "for a value without process-scoped retention (len=%d); "
                "ignoring.", len(value))

    # ------------------------------------------------------- observability
    def scoped_secret_count(self) -> int:
        """Observability helper (AUD-02): number of EXECUTION-scoped retained
        values (refcount > 0). Never exposes secret values and never logs
        them."""
        with self._lock:
            return sum(1 for c in self._secret_refcounts.values() if c > 0)

    def active_secret_count(self) -> int:
        """Number of currently retained secret VALUES (observability only).

        Safe for tests and sanitized diagnostics: returns a bare count and
        never exposes or logs any secret value.
        """
        with self._lock:
            return len(self._secrets)

    def has_secret(self, value: str) -> bool:
        """Whether *value* is currently retained. Never logs the value."""
        with self._lock:
            return value in self._secrets

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


#: Sanitized diagnostic logger for the redactor itself (AUD-02). Defined at
#: module scope AFTER ``get_logger``; resolved lazily at call time from the
#: methods above. NEVER receives secret values — only lengths / counts.
_logger = logging.getLogger("hermes.plugins.vaultwarden.security")

#: shared filter instance used by all plugin modules
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

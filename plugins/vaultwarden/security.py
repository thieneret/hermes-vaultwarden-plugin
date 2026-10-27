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
    """

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self._secrets: set[str] = set()

    def register_secret(self, value: str) -> None:
        """Register a runtime secret value to scrub from every log record."""
        if value and len(value) >= 4:
            with self._lock:
                self._secrets.add(value)

    def forget_secret(self, value: str) -> None:
        with self._lock:
            self._secrets.discard(value)

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
        entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Include structured extra fields if present
        if hasattr(record, "vw_extra") and isinstance(record.vw_extra, dict):
            entry["data"] = self._redact_dict(record.vw_extra)
        return _json.dumps(entry, ensure_ascii=False)

    def _redact_dict(self, d: dict) -> dict:
        """Recursively redact values whose keys match secret patterns."""
        result = {}
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

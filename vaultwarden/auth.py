"""Auth Manager + Session Store (plan §4, §5).

State machine:
    UNINITIALIZED -> CONFIGURED -> (bw status) -> LOGGED_OUT | LOGGED_IN | UNLOCKED
    LOGGED_OUT  --bw login --apikey-->  LOGGED_IN
    LOGGED_IN   --bw unlock --passwordenv-->  UNLOCKED
    UNLOCKED    --expiry/invalid-->     re-unlock / full re-auth

Session key rules:
- lives in plugin memory only; handed to subprocesses via BW_SESSION only;
- NEVER written to os.environ, logs or LLM output;
- cleared on shutdown/lock/timeout; mutations guarded by threading.Lock.
"""
from __future__ import annotations

import enum
import os
import stat
import threading
import time
from pathlib import Path

from . import errors
from .bw_cli import BwCli
from .config import PluginConfig
from .security import get_logger, get_redacting_filter

log = get_logger("auth")


class AuthState(str, enum.Enum):
    UNINITIALIZED = "uninitialized"
    CONFIGURED = "configured"
    LOGGED_OUT = "logged_out"
    LOGGED_IN = "logged_in"        # authenticated but vault locked
    UNLOCKED = "unlocked"          # session key available


def ensure_appdata_dir(path: str | Path) -> Path:
    """Create the isolated bw appdata dir with mode 700 (plan §10)."""
    p = Path(path).expanduser()
    try:
        p.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(p, stat.S_IRWXU)  # rwx------ (idempotent, fixes umask effects)
    except OSError as exc:
        raise errors.AppdataError(
            f"Cannot create isolated bw data directory ({type(exc).__name__}).",
            suggestion="Check permissions of the plugin directory or set VW_APPDATA_DIR.") from exc
    return p


class AuthManager:
    """Owns bw lifecycle: server config, apikey login, unlock, session refresh."""

    def __init__(self, bw: BwCli, config: PluginConfig, *,
                 client_secret: str, master_password: str):
        # FAIL-9 ordering fix: register the bootstrap secrets with the shared
        # RedactingFilter FIRST — before any attribute assignment or log call
        # can possibly echo them. Everything below is scrubbed from here on.
        redactor = get_redacting_filter()
        redactor.register_secret(client_secret)
        redactor.register_secret(master_password)
        self._bw = bw
        self._config = config
        self._client_id = config.client_id
        self._client_secret = client_secret
        self._master_password = master_password
        self._session_key: str | None = None
        # Plan §5 state machine: the manager starts UNINITIALIZED and only
        # becomes CONFIGURED once configure_server_if_needed() has run (the
        # register(ctx) bootstrap flow). is_available()/check_fn therefore
        # report False before bootstrap — tools stay gated until then.
        # (v1.4: test_auth::test_full_bootstrap_flow now matches this.)
        self._state = AuthState.UNINITIALIZED
        self._session_created_at: float = 0.0
        self._last_sync: float = 0.0
        self._lock = threading.RLock()

    # ------------------------------------------------------------ properties
    @property
    def state(self) -> AuthState:
        with self._lock:
            return self._state

    @property
    def session_key(self) -> str | None:
        with self._lock:
            return self._session_key

    @property
    def last_sync(self) -> float:
        with self._lock:
            return self._last_sync

    def is_available(self) -> bool:
        """check_fn passed to ctx.register_tool — graceful degradation gate."""
        return self._state is not AuthState.UNINITIALIZED

    def is_unlocked(self) -> bool:
        with self._lock:
            if self._state is not AuthState.UNLOCKED or not self._session_key:
                return False
            age = time.time() - self._session_created_at
            if age > self._config.session_timeout_seconds:
                self._clear_session_locked()
                self._state = AuthState.LOGGED_IN
                return False
            return True

    # ------------------------------------------------------------- bootstrap
    def configure_server_if_needed(self) -> None:
        """`bw config server <url>` unless data.json already points there."""
        # Plan §5 transition: UNINITIALIZED -> CONFIGURED.
        with self._lock:
            if self._state is AuthState.UNINITIALIZED:
                self._state = AuthState.CONFIGURED

        want = self._config.server_url
        try:
            current = self._bw.config_get()
        except errors.VaultwardenError:
            current = None
        if isinstance(current, str):
            current = current.strip().rstrip("/")
        if current == want.rstrip("/"):
            log.debug("Server URL already configured in isolated profile.")
            return
        self._bw.config_server(want)
        log.info("Configured bw server URL in isolated appdata profile.")

    def probe_status(self) -> dict:
        try:
            status = self._bw.status()
        except errors.VaultwardenError as exc:
            return {"state": "error", "error_code": exc.code}
        if isinstance(status, dict):
            return status
        return {"state": str(status)}

    def ensure_authenticated(self) -> None:
        """Startup sequence steps 6-7: status -> login (if needed) -> unlock.

        v1.4 hardening: an invalid client secret is detected here and raised
        as a clear AuthError BEFORE any unlock attempt, so the master password
        never travels in the environment of a doomed subprocess (defense in
        depth for FAIL-9); the secret VALUE is never included anywhere.
        """
        with self._lock:
            if not self._api_key_available():
                try:
                    self._do_login()
                except errors.VaultwardenError as exc:
                    if exc.code in ("AUTH_ERROR", "SESSION_ERROR", "PLUGIN_ERROR"):
                        raise errors.AuthError(
                            "API-key authentication failed.",
                            suggestion="Check client_id and VW_CLIENT_SECRET in .env.") from exc
                    raise
            status = self.probe_status()
            raw_state = str(status.get("state", "unauthenticated"))
            if raw_state == "unlocked":
                # Existing session file in our isolated profile: re-unlock to
                # obtain a fresh BW_SESSION we hold in memory.
                self._state = AuthState.LOGGED_IN
            self._do_unlock()
            if self._config.auto_sync and self._last_sync == 0.0:
                try:
                    self.sync(force=False)
                except errors.VaultwardenError as exc:
                    log.warning("Initial sync failed (%s); continuing.", exc.code)

    def _api_key_available(self) -> bool:
        """True when the isolated profile already holds a valid apikey login."""
        try:
            st = self._bw.status()
        except errors.VaultwardenError:
            return False
        return isinstance(st, dict) and st.get("status") == "OK"

    # ---------------------------------------------------------------- login
    def _do_login(self) -> None:
        try:
            self._bw.login_apikey(self._client_id, self._client_secret)
        except errors.SessionError as exc:
            raise errors.AuthError(
                "API-key login was rejected.",
                suggestion="Verify client_id and VW_CLIENT_SECRET in .env.") from exc
        except errors.AuthError:
            raise
        except errors.VaultwardenError as exc:
            if exc.code in ("NETWORK_ERROR", "PARSE_ERROR"):
                raise
            raise errors.AuthError("Login failed.") from exc
        self._state = AuthState.LOGGED_IN
        log.info("bw apikey login succeeded (client id %s).", self._client_id)

    def _do_unlock(self) -> None:
        if not self._config.auto_unlock:
            return
        try:
            key = self._bw.unlock_passwordenv(self._master_password)
        except errors.VaultwardenError as exc:
            # Invalid master password: clear error, NO retry, value never logged.
            if exc.code in ("AUTH_ERROR", "PLUGIN_ERROR"):
                raise errors.AuthError(
                    "Unlock failed: master password was rejected.",
                    suggestion="Check VW_MASTER_PASSWORD in your .env file.") from exc
            raise
        self._session_key = key
        self._session_created_at = time.time()
        self._state = AuthState.UNLOCKED
        get_redacting_filter().register_secret(key)
        log.info("Vault unlocked; session key held in plugin memory only.")

    # -------------------------------------------------------- session mgmt
    def get_session(self) -> str:
        """Return a usable session key, auto-recovering per plan §5."""
        with self._lock:
            if self.is_unlocked():
                assert self._session_key is not None
                return self._session_key
            if self._state is AuthState.UNLOCKED:  # expired -> locked
                self._clear_session_locked()
                self._state = AuthState.LOGGED_IN
            if self._state in (AuthState.CONFIGURED, AuthState.LOGGED_OUT):
                self._do_login()
            if self._state is AuthState.LOGGED_IN:
                self._do_unlock()
            if self._state is AuthState.UNLOCKED and self._session_key:
                return self._session_key
            raise errors.SessionError("Could not establish a bw session.")

    def run_with_recovery(self, fn):
        """Execute *fn(session_key)*; on SESSION_ERROR re-auth once and retry."""
        session = self.get_session()
        try:
            return fn(session)
        except errors.SessionError:
            log.warning("Session invalidated mid-operation; recovering once.")
            with self._lock:
                self._clear_session_locked()
                self._state = AuthState.LOGGED_IN
                session = self.get_session()
            return fn(session)

    # ------------------------------------------------------------- operations
    def sync(self, force: bool = False) -> dict:
        """`bw sync`; with auto_sync also refreshes when the cache is stale."""
        now = time.time()
        stale = (now - self.last_sync) > self._config.sync_interval_seconds
        if not force and not (self._config.auto_sync and stale):
            return {"synced": False, "timestamp": self._last_sync, "skipped": "cache fresh"}

        # run_with_recovery already wraps fn in SESSION_ERROR retry logic.
        self.run_with_recovery(
            lambda s: self._rate_limited(lambda: self._bw.sync(s)))
        with self._lock:
            self._last_sync = time.time()
        return {"synced": True, "timestamp": self._last_sync}

    @staticmethod
    def _rate_limited(fn):
        """Exponential backoff for RATE_LIMIT errors: 1s, 2s, 4s — max 3 retries."""
        delay = 1.0
        last_exc: Exception | None = None
        for _attempt in range(4):  # initial try + 3 retries
            try:
                return fn()
            except errors.RateLimitError as exc:
                last_exc = exc
                time.sleep(delay)
                delay *= 2
        raise last_exc  # pragma: no cover - only after full backoff exhaustion

    # ------------------------------------------------------------ data ops
    def list_items(self, filters: list[str] | None = None) -> list[dict]:
        return self.run_with_recovery(
            lambda s: self._rate_limited(lambda: self._bw.list_items(s, filters)))

    def get_item(self, query: str) -> dict:
        return self.run_with_recovery(
            lambda s: self._rate_limited(lambda: self._bw.item_get(s, query)))

    def create_item(self, item: dict) -> dict:
        from .bw_cli import encode_item

        def _do(session: str):
            blob = encode_item(session, item, self._bw)
            return self._bw.create_item(session, blob)
        return self.run_with_recovery(_do)

    def edit_item(self, item: dict) -> dict:
        from .bw_cli import encode_item

        def _do(session: str):
            blob = encode_item(session, item, self._bw)
            return self._bw.edit_item(session, blob)
        return self.run_with_recovery(_do)

    def delete_item(self, item_id: str, permanent: bool = False) -> str:
        def _do(session: str):
            return self._bw.delete_item(session, item_id, permanent)
        return self.run_with_recovery(_do)

    def generate_password(self, args: list[str]) -> str:
        return self.run_with_recovery(lambda s: self._bw.generate_password(s, args))

    # --------------------------------------------------------------- shutdown
    def _clear_session_locked(self) -> None:
        if self._session_key:
            get_redacting_filter().forget_secret(self._session_key)
        self._session_key = None
        self._session_created_at = 0.0

    def lock(self) -> None:
        """Best-effort `bw lock` on the isolated profile + clear memory."""
        with self._lock:
            key = self._session_key
            if key:
                self._bw.lock(key)
            self._clear_session_locked()
            self._state = AuthState.LOGGED_IN
            log.info("Vault locked; session cleared from plugin memory.")

    def shutdown(self, *, keep_appdata: bool = True) -> None:
        """Plan §12 lifecycle: clear session + placeholders, lock vault, keep .bw-data."""
        try:
            self.lock()
        finally:
            if not keep_appdata:  # pragma: no cover - destructive, off by default
                log.debug("keep_appdata=False requested; leaving .bw-data untouched for safety.")

    def status_snapshot(self) -> dict:
        bw_status = self.probe_status()
        with self._lock:
            state = self._state.value
            has_session = bool(self._session_key)
            age = (time.time() - self._session_created_at) if has_session else None
        return {
            "plugin": "vaultwarden",
            "enabled": self._config.enabled,
            "auth_state": state,
            "session_active": has_session,
            "session_age_seconds": round(age, 1) if age is not None else None,
            "session_timeout_seconds": self._config.session_timeout_seconds,
            "server_configured": self._config.server_url,
            "server_status": {
                "state": bw_status.get("state"),
                "serverUrl": bw_status.get("serverUrl"),
                "userEmail": bw_status.get("userEmail"),
            },
            "appdata_dir": self._bw.appdata_dir,
            "allow_write": self._config.allow_write,
            "last_sync": self._last_sync,
        }

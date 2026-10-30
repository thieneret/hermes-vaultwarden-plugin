"""Auth Manager + Session Store (plan §4, §5).

v0.2.8: this module imports `os` at top level — the SSH key wrappers
(create_ssh_item) use os.path.basename() for the attachment note. Passphrase
delivery is stdin-pipe-only by design; no passphrase is ever written to disk.

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
import threading
import time
from pathlib import Path

from . import compat, errors
from .bw_cli import BwCli
from .config import PluginConfig
from .secure_fs import FilesystemSecurityError, ensure_hardened_directory
from .security import get_logger, get_redacting_filter

log = get_logger("auth")


class AuthState(str, enum.Enum):
    UNINITIALIZED = "uninitialized"
    CONFIGURED = "configured"
    LOGGED_OUT = "logged_out"
    LOGGED_IN = "logged_in"        # authenticated but vault locked
    UNLOCKED = "unlocked"          # session key available


def ensure_appdata_dir(path: str | Path) -> Path:
    """Validate/create the isolated bw appdata dir (.bw-data), fail-closed.

    AUD-04 (v0.6.2): hardened through the SHARED validator module
    :func:`vaultwarden.secure_fs.ensure_hardened_directory` — absolute,
    real (non-symlink) directory owned by the CURRENT EFFECTIVE UID with
    mode EXACTLY 0700. A missing directory is created hardened (umask-
    forced); an existing but INSECURE directory is NEVER silently repaired
    (the old implicit chmod is gone) — the operator must fix it explicitly.

    Raises:
        FilesystemSecurityError: on ANY validation failure (fail-closed —
        ``bw`` must not be invoked against an insecure appdata dir).
        errors.AppdataError: when creation itself fails at the OS level.
    """
    p = Path(path).expanduser()
    try:
        return ensure_hardened_directory(p, create_if_missing=True)
    except FilesystemSecurityError:
        # Fail closed — never downgrade; register()/callers abort on this.
        raise
    except OSError as exc:
        raise errors.AppdataError(
            f"Cannot create isolated bw data directory ({type(exc).__name__}).",
            suggestion="Check permissions of the plugin directory or set VW_APPDATA_DIR.") from exc


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
        # v0.6.4 (HOTFIX): register with bw_cli's weak in-memory registry so
        # the subprocess-env choke point can always re-inject BW_SESSION for
        # session-requiring commands (defense-in-depth against a dropped key).
        bw.register_auth_manager(self)
        # Plan §5 state machine: the manager starts UNINITIALIZED and only
        # becomes CONFIGURED once configure_server_if_needed() has run (the
        # register(ctx) bootstrap flow). is_available()/check_fn therefore
        # report False before bootstrap — tools stay gated until then.
        # (v0.1.4: test_auth::test_full_bootstrap_flow now matches this.)
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

    def get_session_key(self) -> str | None:
        """Return the current in-memory session key, or None when locked.

        v0.6.4 (HOTFIX): used by ``bw_cli.BwCli._ensure_session_env`` as a
        defense-in-depth fallback so BW_SESSION can never be silently dropped
        from a session-requiring subprocess environment. NEVER logs the value
        and NEVER writes it to disk — memory-only handoff to the child env.
        """
        with self._lock:
            if self._state is AuthState.UNLOCKED and self._session_key:
                return self._session_key
            return None

    @property
    def last_sync(self) -> float:
        with self._lock:
            return self._last_sync

    def is_available(self) -> bool:
        """check_fn passed to ctx.register_tool — graceful degradation gate.

        v0.1.9 lazy auth: register() no longer authenticates eagerly (it used
        to block past Hermes' 10s plugin-load timeout). The first tool call
        (or check_fn evaluation) triggers ``ensure_authenticated()`` here so
        the vault comes up on demand instead. A manager that was never
        bootstrapped (state UNINITIALIZED) stays gated off, exactly like
        before v0.1.9.
        """
        # NOTE: deliberately NOT taking self._lock here — ensure_authenticated
        # acquires it and RLock is only re-entrant on the owning thread; a
        # plain read of the enum reference is atomic under CPython.
        if getattr(self, "_state", AuthState.UNINITIALIZED) is AuthState.UNINITIALIZED:
            return False
        with self._lock:
            if self._state is AuthState.UNLOCKED and self._session_key:
                return True
            try:
                self.ensure_authenticated()
            except Exception as exc:  # noqa: BLE001 - degrade gracefully
                # VWP-17: error-code extraction centralized in compat.py
                code = compat.get_error_code(exc)
                log.warning("Lazy authentication failed (%s); vault unavailable.",
                            code)
                return False
            return self._state is AuthState.UNLOCKED

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
        """UNINITIALIZED -> CONFIGURED transition (kept for the state machine).

        v0.1.9: server configuration itself is now handled inside
        ``ensure_authenticated()`` — this method no longer runs
        `bw config server` unconditionally at startup (that caused the
        "Logout required before server config update" error when a valid
        session already existed on the profile). It only flips the state
        so tools/check_fn can gate on it.
        """
        with self._lock:
            if self._state is AuthState.UNINITIALIZED:
                self._state = AuthState.CONFIGURED

    def probe_status(self) -> dict:
        try:
            status = self._bw.status()
        except errors.VaultwardenError as exc:
            return {"status": "error", "error_code": exc.code}
        if isinstance(status, dict):
            return status
        return {"status": str(status)}

    @staticmethod
    def _session_state(status: dict) -> str:
        """Normalise the bw session state from a `bw status` payload.

        Real bw uses the key "status"; older fixtures used "state". When
        neither is present but the profile reports a userId, infer LOGGED_IN.
        """
        st = str(status.get("status") or status.get("state") or "")
        if st in ("unauthenticated", "locked", "unlocked"):
            return st
        if status.get("userId"):
            return "locked"
        return "unauthenticated"

    def ensure_authenticated(self) -> None:
        """v0.1.9 auth flow: check `bw status` FIRST, then do the minimum.

        Case A: not logged in            -> config server + login + unlock
        Case B: logged in, wrong server
                or wrong account         -> logout + config + login + unlock
        Case C: correct session          -> unlock only if locked;
                                            nothing if already unlocked

        Account verification: config.yaml carries client_id "user.<uuid>";
        bw status reports userId "<uuid>" — they must match.
        """
        log.info("Checking authentication status...")
        with self._lock:
            # Step 1: current session snapshot.
            status = self.probe_status()
            current_status = self._session_state(status)
            current_server = str(status.get("serverUrl") or "").rstrip("/")
            current_user_id = str(status.get("userId") or "")

            # Expected session per plugin config.
            expected_server = self._config.server_url.rstrip("/")
            expected_user_id = self._client_id.removeprefix("user.")

            log.info("Current: status=%s, server=%s, user=%s",
                     current_status, current_server, current_user_id)
            log.info("Expected: server=%s, user=%s", expected_server, expected_user_id)

            # Step 2: does the existing session match server AND account?
            is_correct_server = (current_server == expected_server)
            # v0.2.2 (SECURITY FIX): strict fail-closed account verification.
            # A missing or empty userId is now treated as a MISMATCH, forcing
            # logout + re-auth instead of blindly adopting an unknown session.
            is_correct_account = (
                bool(current_user_id) and current_user_id == expected_user_id)
            needs_reauth = not (is_correct_server and is_correct_account)

            # Case C: already authenticated with the correct session.
            if not needs_reauth:
                if current_status == "unlocked":
                    log.info("Already authenticated and unlocked; nothing to do.")
                    self._state = AuthState.LOGGED_IN
                    if self._session_key:
                        # v0.1.9 fast path: our remembered in-memory session is
                        # still valid (idempotent re-check, e.g. lazy auth via
                        # check_fn followed by another tool call) — no extra
                        # subprocess round-trip needed.
                        self._state = AuthState.UNLOCKED
                    else:
                        self._adopt_existing_unlocked_session()
                    self._maybe_initial_sync()
                    return
                if current_status == "locked":
                    log.info("Already authenticated but locked, unlocking...")
                    self._state = AuthState.LOGGED_IN
                    self._do_unlock()
                    self._maybe_initial_sync()
                    return
                # Correct server/account but bw reports unauthenticated
                # (e.g. inconclusive status payload) — fall through to login.

            # Case B: wrong server or account -> logout before reconfiguring.
            if current_status in ("locked", "unlocked") and needs_reauth:
                log.info("Session mismatch (server/account), logging out first...")
                self._clear_session_locked()
                self._bw.logout()
                current_status = "unauthenticated"

            # Case A: not logged in -> config server + login + unlock.
            if current_status == "unauthenticated":
                log.info("Not authenticated, configuring server and logging in...")
                self._configure_server()
                self._do_login()
                self._do_unlock()
                self._maybe_initial_sync()
                return

            # Unreachable in practice; treat as needing full re-auth.
            self._configure_server()
            self._do_login()
            self._do_unlock()
            self._maybe_initial_sync()

    def _configure_server(self) -> None:
        """`bw config server <url>` — ONLY when the session needs (re)auth."""
        server_url = self._config.server_url
        if not server_url:
            return
        log.info("Configuring bw server: %s", server_url)
        try:
            self._bw.config_server(server_url)
        except errors.VaultwardenError as exc:
            raise errors.PluginError(
                f"bw config server failed: {exc.message}",
                suggestion="Run 'bw logout' in the isolated profile, then retry."
            ) from exc
        log.info("Server configured successfully")

    def _adopt_existing_unlocked_session(self) -> None:
        """Case C/unlocked: bw keeps its own session key; we never stored one
        in memory (e.g. after a plugin restart). Re-unlock locally so tool
        calls keep flowing — deterministic and safe."""
        if self._session_key:
            return  # our remembered key is still valid
        # v0.2.3: always re-unlock — auto_unlock toggle removed.
        log.info("Adopting existing unlocked profile via local re-unlock.")
        self._do_unlock()

    def _maybe_initial_sync(self) -> None:
        """Best-effort first sync after authentication (auto_sync only)."""
        if self._config.auto_sync and self._last_sync == 0.0:
            try:
                self.sync(force=False)
            except errors.VaultwardenError as exc:
                log.warning("Initial sync failed (%s); continuing.", exc.code)

    # ---------------------------------------------------------------- login
    def _do_login(self) -> None:
        try:
            self._bw.login_apikey(self._client_id, self._client_secret)
        except errors.SessionError as exc:
            raise errors.AuthError(
                "API-key login was rejected.",
                suggestion="Verify client_id and the client_secret in "
                           "secrets.yaml (chmod 600).") from exc
        except errors.AuthError:
            raise
        except errors.VaultwardenError as exc:
            if exc.code in ("NETWORK_ERROR", "PARSE_ERROR"):
                raise
            raise errors.AuthError("Login failed.") from exc
        self._state = AuthState.LOGGED_IN
        log.info("bw apikey login succeeded (client id %s).", self._client_id)

    def _do_unlock(self) -> None:
        # v0.2.3 (BREAKING): auto_unlock toggle removed — the vault is ALWAYS
        # auto-unlocked with the master password. No early-return guard.
        try:
            key = self._bw.unlock_passwordenv(self._master_password)
        except errors.VaultwardenError as exc:
            # Invalid master password: clear error, NO retry, value never logged.
            if exc.code in ("AUTH_ERROR", "PLUGIN_ERROR"):
                raise errors.AuthError(
                    "Unlock failed: master password was rejected.",
                    suggestion="Check the master_password in your "
                               "secrets.yaml file (chmod 600).") from exc
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
            blob = encode_item(item)
            return self._bw.create_item(session, blob)
        return self.run_with_recovery(_do)

    def edit_item(self, item: dict) -> dict:
        from .bw_cli import encode_item

        item_id = str(item.get("id") or "")

        def _do(session: str):
            blob = encode_item(item)
            return self._bw.edit_item(session, item_id, blob)
        return self.run_with_recovery(_do)

    def delete_item(self, item_id: str, permanent: bool = False) -> str:
        def _do(session: str):
            return self._bw.delete_item(session, item_id, permanent)
        return self.run_with_recovery(_do)

    def generate_password(self, args: list[str]) -> str:
        return self.run_with_recovery(lambda s: self._bw.generate_password(s, args))

    # ----------------------------------------------------- SSH key ops (v0.2.8)
    def search_items(self, query: str) -> list[dict]:
        """Search vault items by name. Returns list of matching items."""
        def _do(session: str):
            return self._bw.list_items(session, filters=["--search", query])
        return self.run_with_recovery(_do) or []

    def create_ssh_item(self, name: str, username: str, password: str,
                        key_file_path: str) -> dict:
        """Create a login item + SSH key attachment.

        v0.2.8: enforces name uniqueness before creation.
        """
        from .bw_cli import encode_item

        # Name uniqueness check
        existing = self.search_items(name)
        exact = [i for i in existing if i.get("name") == name]
        if exact:
            raise errors.VaultwardenError(
                f"Item name '{name}' already exists ({len(exact)} match(es)). "
                "SSH key names must be unique.",
                code="DUPLICATE_NAME",
                suggestion="Choose a different name or use vaultwarden_update_ssh.")

        item = {
            "type": 1,  # login
            "name": name,
            "login": {
                "username": username,
                "password": password,
            },
        }
        if key_file_path:
            item["notes"] = f"SSH key: {os.path.basename(key_file_path)}"

        def _do(session: str):
            blob = encode_item(item)
            created = self._bw.create_item(session, blob)
            item_id = created.get("id", "")
            if key_file_path and item_id:
                self._bw.create_attachment(session, key_file_path, item_id)
            return created
        return self.run_with_recovery(_do)

    def get_ssh_key(self, item_id: str, output_path: str) -> tuple[str, str]:
        """Download SSH key attachment and return (key_path, passphrase).

        v0.3.3 (BUGFIX): passphrase is retrieved via `bw get password`,
        NOT from `bw get item` output (which returns null for encrypted
        fields). This fixes vaultwarden_use_ssh prompting the user for a
        passphrase instead of using the stored one.
        """
        def _do(session: str):
            # v0.3.3: bw get item does NOT include encrypted fields.
            # Use the dedicated `bw get password` command instead.
            passphrase = self._bw.get_password(session, item_id)

            # Get item metadata to find the attachment
            item = self._bw.item_get(session, item_id)
            attachments = item.get("attachments") or []
            if not attachments:
                raise errors.VaultwardenError(
                    "Item has no SSH key attachment.",
                    code="NOT_FOUND",
                    suggestion="Use vaultwarden_store_ssh to create the key.")
            att = attachments[0]
            att_name = att.get("fileName", "ssh_key")

            self._bw.get_attachment(session, att_name, item_id, output_path)
            return output_path, passphrase
        return self.run_with_recovery(_do)

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
                # v0.2.6 (BUGFIX): use internal session state for the lock indicator.
                # bw status is called WITHOUT BW_SESSION (session key lives in plugin
                # memory only, by design), so it always reports "locked" even when
                # the plugin holds an active session. The internal state is authoritative.
                "state": "unlocked" if has_session else (
                    bw_status.get("status") or bw_status.get("state") or "unknown"),
                "serverUrl": bw_status.get("serverUrl"),
                "userEmail": bw_status.get("userEmail"),
                "userId": bw_status.get("userId"),
            },
            "appdata_dir": self._bw.appdata_dir,
            "allow_write": self._config.allow_write,
            "last_sync": self._last_sync,
        }

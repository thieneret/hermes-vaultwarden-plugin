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
import json
import os
import re
import threading
import time
from pathlib import Path

from . import compat, errors
from .bw_cli import BwCli
from .config import PluginConfig, _sanitize_url_for_logging
from .secure_fs import FilesystemSecurityError, ensure_hardened_directory
from .security import get_logger, get_redacting_filter

log = get_logger("auth")


def _initial_sync_failure_summary(exc: BaseException) -> str:
    """Sanitized single-line failure summary for initial-sync logs (Phase 2).

    Hardening rule: log lines carry ONLY sanitized error codes from
    errors.py — never raw exception text or values. Exception messages in
    this codebase can transitively contain secret material (session key,
    client_secret, master password — see the production redaction audit),
    so raw ``str(exc)`` must NEVER reach a log record. We extract only:

      * the sanitized error code constant, and
      * an optional safe context substring (hostname / numeric ids) taken
        from a strict allowlist of characters. Anything that could be a
        credential, URL userinfo, or free-form server text is dropped.
    """
    code = compat.get_error_code(exc)
    parts = [code]
    msg = str(exc)
    # "server <url>" context: reduce to scheme://hostname via the existing
    # HVA-02 sanitizer (strips userinfo/path/query — never credentials).
    m = re.search(r"server\s+([A-Za-z][A-Za-z0-9+.-]*://[^\s]+)", msg)
    if m:
        try:
            parts.append(f"server {_sanitize_url_for_logging(m.group(1))}")
        except Exception:  # noqa: BLE001 - diagnostics only, never raise
            pass
    else:
        # Safe scalar contexts only: numeric ids / bounded integers.
        m2 = re.search(r"\b(?:status|code)[ =]+(\d{3})\b", msg)
        if m2:
            parts.append(f"status={m2.group(1)}")
    return " ".join(parts)


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
        # AUD-02 (phase 2): bootstrap credentials are PROCESS-SCOPED — they
        # live for the whole process and must never be dropped by an
        # execution-scoped release. register_process_scoped_secret is
        # idempotent (permanent marking never inflates refcounts), so Auth
        # Manager constructions across a test suite / session can no longer
        # accumulate phantom references on these values.
        redactor.register_process_scoped_secret(client_secret)
        redactor.register_process_scoped_secret(master_password)
        self._bw = bw
        self._config = config
        self._client_id = config.client_id
        self._client_secret = client_secret
        self._master_password = master_password
        self._session_key: str | None = None
        # v0.6.4 (HOTFIX): register with bw_cli's weak in-memory registry so
        # the subprocess-env choke point can always re-inject BW_SESSION for
        # session-requiring commands (defense-in-depth against a dropped key).
        from . import bw_cli as _bw_cli
        _bw_cli.register_auth_manager(self)
        # v0.7.2 (first-burst bootstrap fix, CHANGE 1/2): let the choke
        # point run THIS FSM for commands issued through our own wrappers
        # (see _attach_bootstrap_secrets_to_bw).
        self._attach_bootstrap_secrets_to_bw()
        # Plan §5 state machine: the manager starts UNINITIALIZED and only
        # becomes CONFIGURED once configure_server_if_needed() has run (the
        # register(ctx) bootstrap flow). is_available()/check_fn therefore
        # report False before bootstrap — tools stay gated until then.
        # (v0.1.4: test_auth::test_full_bootstrap_flow now matches this.)
        self._state = AuthState.UNINITIALIZED
        self._session_created_at: float = 0.0
        self._last_sync: float = 0.0
        # v0.7.3 (Phase 3): bounded item count from the most recent SUCCESSFUL
        # sync — internal hand-off for BwCli's empty-read defense log line
        # only. A plain int (never vault content, never a secret). None until
        # a sync reports a parseable count. NOT part of status_snapshot().
        self._last_sync_item_count: int | None = None
        self._lock = threading.RLock()
        # v0.7.2 (first-burst bootstrap fix, CHANGE 1): observability pin —
        # counts how many times the FULL bootstrap body of
        # ensure_authenticated() actually RAN (i.e. past the idempotency fast
        # path, spawning status/config/login/unlock subprocesses). Tests use
        # it to prove concurrent first calls bootstrap EXACTLY once. No
        # secret material involved; plain int under the existing lock.
        self._full_bootstrap_count: int = 0
        # v0.7.3 (Phase 2, CHANGE 2): initial-sync state tracking for
        # downstream consumers (Phase 3 empty-read defense, Phase 4 status
        # honesty). _initial_sync_completed flips True exactly once — when
        # the FIRST post-auth sync attempt succeeds. _initial_sync_failed
        # flips True only after the bounded retry loop EXHAUSTS its attempts
        # (or a non-retryable error aborts it) without ever succeeding.
        # Plain bools under the existing RLock; no secret material involved.
        self._initial_sync_completed: bool = False
        self._initial_sync_failed: bool = False
        # v0.7.3 (Phase 2): WARNING-budget flag — _maybe_initial_sync() sets
        # this around its sync() calls so per-attempt failures log at INFO
        # only (spec); direct sync() callers never see it set and keep the
        # Phase 1 "Sync failed (...)" WARNING unchanged.
        self._sync_warn_suppressed: bool = False

    # ------------------------------------------------------------ properties
    @property
    def initial_sync_completed(self) -> bool:
        """True once the first post-auth sync has succeeded (v0.7.3 Phase 2)."""
        with self._lock:
            return self._initial_sync_completed

    @property
    def initial_sync_failed(self) -> bool:
        """True when the bounded initial-sync retry loop gave up (Phase 2)."""
        with self._lock:
            return self._initial_sync_failed

    @property
    def state(self) -> AuthState:
        with self._lock:
            return self._state

    @property
    def session_key(self) -> str | None:
        with self._lock:
            return self._session_key

    def _session_valid_locked(self) -> bool:
        """Shared validity predicate — single source of truth (v0.7.2).

        A session is VALID iff state is UNLOCKED ∧ key present ∧ age within
        ``session_timeout_seconds``. When the raw age exceeds the timeout the
        expired session is lazily cleared and demoted to LOGGED_IN (the exact
        behaviour :meth:`is_unlocked` has always had — extracted here so
        :meth:`get_session_key` closes the stale-key gap without duplicating
        the logic).

        Caller MUST hold ``self._lock`` (RLock — re-entrant on the owner).
        NEVER logs the key value.
        """
        if self._state is not AuthState.UNLOCKED or not self._session_key:
            return False
        age = time.time() - self._session_created_at
        if age > self._config.session_timeout_seconds:
            # Expired -> locked: clear the key, demote state (lazy expiry).
            self._clear_session_locked()
            self._state = AuthState.LOGGED_IN
            return False
        return True

    def get_session_key(self) -> str | None:
        """Return the current in-memory session key, or None when locked.

        v0.6.4 (HOTFIX): used by ``bw_cli.BwCli._ensure_session_env`` as a
        defense-in-depth fallback so BW_SESSION can never be silently dropped
        from a session-requiring subprocess environment. NEVER logs the value
        and NEVER writes it to disk — memory-only handoff to the child env.

        v0.7.2 (CHANGE 1): expiry-age is now ENFORCED here via the shared
        :meth:`_session_valid_locked` predicate — identical semantics to
        :meth:`is_unlocked`. Previously this gated on state + presence only,
        so a STALE (expired-but-remembered) key could still be injected at
        the choke point and run ``bw`` against a locked profile — one leg of
        the first-burst "empty vault + exit 1" regression. An expired key is
        cleared, the state demotes to LOGGED_IN, and None is returned.
        """
        with self._lock:
            if self._session_valid_locked():
                return self._session_key
            return None

    @property
    def last_sync(self) -> float:
        with self._lock:
            return self._last_sync

    @property
    def last_sync_result(self) -> int | None:
        """Bounded item count of the most recent successful sync (Phase 3).

        Internal hand-off consumed by ``BwCli._forced_full_sync_retry()`` so
        its "Forced full sync completed (<N> items)" line can carry the count.
        Plain int or None — never vault content, never a secret. Duck-typed
        test managers without this property are handled via getattr default.
        """
        return getattr(self, "_last_sync_item_count", None)

    def is_available(self) -> bool:
        """check_fn passed to ctx.register_tool — graceful degradation gate.

        v0.1.9 lazy auth: register() no longer authenticates eagerly (it used
        to block past Hermes' 10s plugin-load timeout). The first tool call
        (or check_fn evaluation) triggers ``ensure_authenticated()`` here so
        the vault comes up on demand instead. A manager that was never
        bootstrapped (state UNINITIALIZED) stays gated off, exactly like
        before v0.1.9.

        v0.7.2 (first-burst bootstrap fix, CHANGE 4): bootstrap failures are
        no longer swallowed silently. The return value keeps its graceful-
        degradation contract (False), but WHY the bootstrap failed is now
        recorded at WARNING level — sanitized error code + bootstrap STAGE
        only (never exception text, never a secret value), so operators can
        distinguish "login/server-config stage" from "unlock stage" in the
        logs without any leakage.
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
                # CHANGE 4: record WHY the bootstrap failed — sanitized code +
                # stage attribution (see _stage_from_code); never exc text.
                stage = self._stage_from_code(code)
                log.warning(
                    "Lazy authentication failed (%s; bootstrap stage=%s); "
                    "vault unavailable.", code, stage)
                return False
            return self._state is AuthState.UNLOCKED

    def is_unlocked(self) -> bool:
        # v0.7.2 (CHANGE 1): delegates to the shared _session_valid_locked()
        # predicate — identical semantics AND identical lazy-expiry behaviour
        # (expired -> clear key, demote to LOGGED_IN, return False). Kept as
        # a public method; get_session_key() now agrees with it exactly, so
        # no stale-key gap can exist between the two capability predicates.
        with self._lock:
            return self._session_valid_locked()

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
            # v0.7.2 (first-burst bootstrap fix, CHANGE 1): IDEMPOTENCY fast
            # path — when this process already holds a VALID (unexpired)
            # in-memory session, the FSM is by construction already past
            # config-server + login + unlock, so return WITHOUT spawning any
            # subprocess. This makes repeated ensure_authenticated() calls
            # (check_fn -> tool call -> choke-point lazy unlock) cheap and
            # keeps concurrent first callers from re-running the bootstrap.
            if self._session_valid_locked():
                log.debug("Already authenticated and unlocked; "
                          "ensure_authenticated() no-op.")
                return
            # v0.7.2 (first-burst bootstrap fix, CHANGE 1): we are past the
            # idempotency fast path — this call runs the FULL bootstrap body
            # (status probe + config server + login + unlock). Count it under
            # the lock so tests can pin "concurrent first calls bootstrap
            # EXACTLY once" deterministically.
            self._full_bootstrap_count = getattr(
                self, "_full_bootstrap_count", 0) + 1
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
        log.info("Configuring bw server: %s", _sanitize_url_for_logging(server_url))
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
        """First sync after authentication, with bounded retry (auto_sync only).

        v0.7.3 (Phase 2, CHANGE 1): converted from single-shot to a BOUNDED
        retry loop. Root cause of the production incident (2026-11-02): a
        transient NetworkError during a Docker container's 1-2 minute network
        cold-start window was swallowed by the single attempt, leaving
        ``_last_sync == 0.0`` and an unpopulated cache for the whole process
        lifetime ("first-burst empty vault").

        Retry policy:
        - Max attempts / inter-attempt delay come from PluginConfig
          (defaults: 3 attempts x 10s; hard-capped so total sleep <= 20s —
          well under the 30s plugin-load timeout ceiling).
        - ONLY ``errors.NetworkError`` is retried (cold-start DNS/TLS
          transients). ``AuthError``/``SessionError`` are NOT transient here:
          they abort the loop immediately with the same WARNING wording.
        - On success: ``_initial_sync_completed = True`` (sync() itself sets
          ``_last_sync``); INFO logs identify the winning attempt.
        - On exhaustion/non-retryable failure: ``_initial_sync_failed = True``
          and ONE WARNING (individual retry failures are INFO — expected
          during cold-start; only the final outcome is WARNING).

        Phase 1 logging (attempt/success/failure lines) is preserved verbatim
        for backward compatibility. Log lines never contain secret values or
        raw exception text — sanitized error codes from errors.py only.
        """
        if not self._config.auto_sync or self._last_sync != 0.0:
            return
        # Already completed in this process (idempotency guard; also keeps a
        # re-entry after a successful loop from re-spawning subprocesses).
        with self._lock:
            if self._initial_sync_completed:
                return

        max_attempts = int(getattr(self._config, "initial_sync_max_attempts", 3))
        delay = float(getattr(self._config, "initial_sync_retry_delay_seconds",
                              10.0))

        log.info("Initial sync started")
        if max_attempts > 1:
            log.info("Initial sync retry loop started (max %d attempts, %.1fs "
                     "interval)", max_attempts, delay)
        started = time.monotonic()

        # Defense-in-depth for the WARNING-budget invariant (spec: individual
        # retry-attempt failures are INFO; only the FINAL outcome is WARNING):
        # suppress sync()'s own Phase 1 failure WARNING while this loop owns
        # the outcome reporting, and emit exactly ONE WARNING per terminal
        # path below. We deliberately do NOT mutate _last_sync/_state here —
        # sync()'s fresh-process full-vs-delta verb decision must stay
        # intact (Phase 1 semantics). Direct callers of sync() (tool
        # handlers, auto-sync refresh) never enter this context manager and
        # keep their full Phase 1 WARNING — no observability regression.
        class _SyncWarningBudget:
            def __init__(self, manager: "AuthManager") -> None:
                self._mgr = manager
                self._saved = None

            def __enter__(self) -> "_SyncWarningBudget":
                self._saved = self._mgr._sync_warn_suppressed
                self._mgr._sync_warn_suppressed = True
                return self

            def __exit__(self, *exc_info) -> bool:
                self._mgr._sync_warn_suppressed = self._saved
                return False

        with _SyncWarningBudget(self):
            last_summary = "UNKNOWN_ERROR"
            for attempt in range(1, max_attempts + 1):
                # v0.7.3 Phase 2: track the LAST failure summary (sanitized
                # error code + safe context only — never raw exception text)
                # so the exhaustion WARNING can carry the real reason
                # instead of a bare count.
                try:
                    result = self.sync(force=False)
                except errors.NetworkError as exc:
                    # VWP-17 centralized extraction; exc.code is already a
                    # sanitized constant from errors.py — never message text.
                    code = compat.get_error_code(exc)
                    last_summary = _initial_sync_failure_summary(exc)
                    if attempt < max_attempts:
                        # INFO, not WARNING: transient failures are EXPECTED
                        # during a container network cold-start window.
                        log.info("Initial sync attempt %d/%d failed (%s), "
                                 "retrying in %.1fs", attempt, max_attempts,
                                 code, delay)
                        time.sleep(delay)
                        continue
                    with self._lock:
                        self._initial_sync_failed = True
                    # ONE WARNING on exhaustion (spec wording, extended with
                    # the sanitized last-failure summary).
                    log.warning("Initial sync failed after %d attempts (%s); "
                                "cache unpopulated, will retry on first read",
                                max_attempts, last_summary)
                    return
                except errors.VaultwardenError as exc:
                    # AuthError / SessionError / anything else: NOT transient
                    # — no retry, immediate WARNING (single-shot wording kept).
                    code = compat.get_error_code(exc)
                    with self._lock:
                        self._initial_sync_failed = True
                    log.warning("Initial sync failed (%s); cache unpopulated, "
                                "will retry on first read", code)
                    return

                if result.get("synced"):
                    duration = time.monotonic() - started
                    count = result.get("item_count")
                    with self._lock:
                        self._initial_sync_completed = True
                    # Phase 1 summary line (kept for compatibility): sync()
                    # already logged the item count when parseable; this
                    # mirrors it (count omitted when not parseable).
                    if count is None:
                        log.info("Initial sync completed (%.1fs)", duration)
                    else:
                        log.info("Initial sync completed (%d items, %.1fs)",
                                 int(count), duration)
                    # Phase 2 retry-lifecycle line (only when a retry was
                    # actually needed — happy path stays quiet per spec).
                    if attempt > 1:
                        if count is None:
                            log.info("Initial sync succeeded on attempt %d",
                                     attempt)
                        else:
                            log.info("Initial sync succeeded on attempt %d "
                                     "(%d items)", attempt, int(count))
                    return
                # sync() skipped (cache fresh / not stale): nothing left to do.
                return

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
        # v0.7.2 (lazy-unlock prompt hardening, CHANGE 2): fail CLOSED when
        # the in-memory master password is falsy — raise a sanitized AUTH
        # error BEFORE spawning `bw unlock --passwordenv BW_MP` (base_env()
        # drops falsy extras, so the spawn would point --passwordenv at a
        # nonexistent variable and bw could fall back to its interactive
        # "? Master password:" prompt). AuthError (NOT SessionError) keeps
        # run_with_recovery from looping on a re-unlock that can never
        # succeed without a master password. The value is never logged.
        if not self._master_password or not str(self._master_password).strip():
            raise errors.AuthError(
                "master password unavailable; cannot unlock "
                "non-interactively. Verify master_password in secrets.yaml "
                "and re-bootstrap.")
        try:
            key = self._bw.unlock_passwordenv(self._master_password)
        except errors.VaultwardenError as exc:
            # Invalid master password: clear error, NO retry, value never logged.
            if exc.code in ("AUTH_ERROR", "PLUGIN_ERROR"):
                # v0.7.2 (first-burst fix, CHANGE 3): mark this as a genuine
                # UNLOCK-stage failure so callers/choke point may accurately
                # reference master_password here — and only here.
                _err = errors.AuthError(
                    "Unlock failed: master password was rejected.",
                    suggestion="Check the master_password in your "
                               "secrets.yaml file (chmod 600).")
                _err.bootstrap_stage = "unlock"
                raise _err from exc
            raise
        self._session_key = key
        self._session_created_at = time.time()
        self._state = AuthState.UNLOCKED
        # AUD-02 (phase 2): the session key lives for the whole UNLOCKED
        # period — it is PROCESS-SCOPED redaction material, not an
        # execution-scoped secret. register_process_scoped_secret is
        # idempotent (permanent marking never inflates refcounts), so
        # repeated unlocks of the same key cannot accumulate phantom
        # references, and no execution-scoped release can ever drop it while
        # the vault stays unlocked.
        get_redacting_filter().register_process_scoped_secret(key)
        log.info("Vault unlocked; session key held in plugin memory only.")

    # -------------------------------------------------------- session mgmt
    def _stage_from_code(self, code: str | None) -> str:
        """Map a sanitized error code to the bootstrap STAGE that failed.

        v0.7.2 (first-burst bootstrap fix, CHANGE 3): stage attribution keeps
        choke-point / caller messages accurate — a LOGIN or server-CONFIG
        failure must never be reported as a master-password problem. Only the
        unlock stage legitimately points at ``master_password``. Classification
        uses the sanitized CODE alone (never raw exception text), so no secret
        material can ride this path into a message or log line.
        """
        if code == "NETWORK_ERROR":
            return "network"
        if code in ("AUTH_ERROR", "PLUGIN_ERROR"):
            # AuthError is raised by _do_login (login rejected) AND by
            # _do_unlock (MP rejected / falsy-MP fail-closed); PluginError
            # wraps `bw config server` failures (_configure_server). The
            # profile state disambiguates: still CONFIGURED/LOGGED_OUT means
            # login/config never succeeded; LOGGED_IN means login succeeded
            # and the UNLOCK stage failed.
            with self._lock:
                if self._state in (AuthState.CONFIGURED, AuthState.LOGGED_OUT,
                                   AuthState.UNINITIALIZED):
                    return "login"
            return "unlock"
        return "unknown"

    def get_session(self) -> str:
        """Return a usable session key, auto-recovering per plan §5.

        v0.7.2 (first-burst bootstrap fix, CHANGE 1 — PRIMARY): the
        CONFIGURED/LOGGED_OUT branch no longer calls a bare ``_do_login()``.
        On a FRESH deferred-auth profile ``bw login --apikey`` FAILS unless
        the server URL was configured first (``bw config server``), and the
        ONLY code path performing the full bootstrap sequence
        (``bw status`` -> config server -> login -> unlock -> verification)
        was ``ensure_authenticated()`` — reachable solely via
        ``is_available()``/``check_fn`` or the swallowed-failure fallback in
        ``vaultwarden_status``. Every read/write tool goes through THIS
        method (directly or via ``run_with_recovery``), so the first burst on
        a fresh profile died at login and — thanks to its side effects — the
        second burst worked. Now CONFIGURED routes through the full FSM:

          * logic reused from ``ensure_authenticated()`` — NOT duplicated;
          * idempotent: an already-UNLOCKED manager returns immediately
            (fast path below + inside ensure_authenticated — no extra
            subprocesses once bootstrapped);
          * serialized under ``self._lock`` (RLock): concurrent first calls
            bootstrap EXACTLY once — the loser of the lock race sees a valid
            session on entry and takes the fast path;
          * deferred startup preserved: this runs on the FIRST TOOL CALL,
            never at register() (v0.1.9 Hermes 10s load-timeout constraint).

        A bootstrap that fails at the login/config stage raises a sanitized
        SessionError carrying an explicit ``bootstrap_stage`` marker so the
        choke point can describe it accurately instead of blaming
        master_password (CHANGE 3). Genuine unlock failures keep their
        original AuthError (master-password hint legitimate there).
        """
        with self._lock:
            if self.is_unlocked():
                assert self._session_key is not None
                return self._session_key
            if self._state is AuthState.UNLOCKED:  # expired -> locked
                self._clear_session_locked()
                self._state = AuthState.LOGGED_IN
            if self._state in (AuthState.CONFIGURED, AuthState.LOGGED_OUT):
                # Full FSM bootstrap (status probe + config server + login +
                # unlock + server/account verification). Re-entrant RLock:
                # ensure_authenticated() re-acquires it on this thread.
                try:
                    self.ensure_authenticated()
                except errors.VaultwardenError as exc:
                    if exc.code in ("NETWORK_ERROR", "PARSE_ERROR"):
                        raise
                    # CHANGE 3: propagate any structured stage marker that the
                    # source (e.g. BwCli.unlock_passwordenv) attached to the
                    # ORIGINAL exception, and use it as the primary stage
                    # signal — fixed identifiers only, never exception text.
                    _src_stage = getattr(exc, "bootstrap_stage", None)
                    if _src_stage == "login":
                        stage = "login"
                    elif (_src_stage is None
                          and self._state in (AuthState.CONFIGURED,
                                              AuthState.LOGGED_OUT)):
                        # The FSM never advanced past CONFIGURED: login itself
                        # failed, so even an unlock-LOOKING code (AUTH_ERROR /
                        # PLUGIN_ERROR mapped by _stage_from_code via the
                        # state) belongs to the LOGIN stage. A genuine unlock
                        # failure implies LOGGED_IN state with a source-
                        # attached "unlock" marker — never this branch.
                        stage = "login"
                    else:
                        stage = self._stage_from_code(exc.code)
                    if stage == "login":
                        # CHANGE 3: attach the structured stage marker to
                        # the ORIGINAL exception too, so callers that catch
                        # AuthError/PluginError directly (and the choke
                        # point's getattr probe on re-raised instances) can
                        # attribute the failure accurately without parsing
                        # any text. Fixed identifier only — never secret
                        # material; to_dict() shape is unchanged.
                        exc.bootstrap_stage = "login"
                        raise errors.SessionError(
                            "Vault profile bootstrap failed during login/"
                            "server configuration; verify client_id and "
                            "server_url.",
                            suggestion="The isolated bw profile could not be "
                                       "bootstrapped (server config or apikey "
                                       "login stage). Check server_url/"
                                       "client_id in config.yaml and the "
                                       "client_secret in secrets.yaml "
                                       "(chmod 600).",
                            bootstrap_stage="login",
                        ) from exc
                    raise
                if self._state is AuthState.UNLOCKED and self._session_key:
                    return self._session_key
            elif self._state is AuthState.LOGGED_IN:
                # Lighter recovery for an already-bootstrapped profile:
                # unlock only (no login needed); _do_unlock keeps the
                # master-password-specific messaging.
                self._do_unlock()
            if self._state is AuthState.UNLOCKED and self._session_key:
                return self._session_key
            raise errors.SessionError("Could not establish a bw session.")

    def run_with_recovery(self, fn):
        """Execute *fn(session_key)*; on SESSION_ERROR re-auth once and retry.

        v0.7.2 (CHANGE 3): the single-retry policy is unchanged — it applies
        to EVERY wrapped operation, including NON-idempotent writes
        (create/edit/delete/attachments, VWP-10). The wrapped ``fn`` performs
        exactly ONE subprocess attempt; the recovery path adds at most ONE
        further attempt AFTER a synchronous re-unlock. No additional retries
        are ever introduced for non-idempotent operations: network-level
        retry remains governed by ``BwCli.run(retryable=...)`` inside the
        first pass, and locked-vault SessionErrors raised from the write
        paths now land HERE (instead of escaping as generic PLUGIN_ERRORs),
        so the first burst after idle/expiry recovers synchronously rather
        than failing the caller's initial call outright.
        """
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
    def _attach_bootstrap_secrets_to_bw(self) -> None:
        """Give the BwCli instance a capability to re-bootstrap via THIS FSM.

        v0.7.2 (first-burst bootstrap fix, CHANGE 1/2): the subprocess-env
        choke point (:meth:`BwCli._ensure_session_env`) must be able to run
        the FULL ``ensure_authenticated()`` FSM for every session-requiring
        command — including calls made through the AuthManager's own command
        wrappers, which pass an explicit (possibly expired) BW_SESSION.
        Without that, a stale key injected by e.g. ``run_with_recovery``
        would spawn `bw list` against a locked/un-bootstrapped profile —
        exactly the read blind spot this closes. The closure is set only on
        instances constructed by the real AuthManager; duck-typed test
        doubles and bare BwCli instances never get it, so their explicit
        keys stay trusted as-is (zero extra subprocesses on healthy paths).
        No secret material crosses this boundary — the closure takes and
        returns nothing sensitive beyond what the FSM already holds.
        """
        try:
            self._bw._bootstrap_via_auth_manager = self.ensure_authenticated
        except AttributeError:  # pragma: no cover - exotic non-writable obj
            pass

    def sync(self, force: bool = False) -> dict:
        """`bw sync`; with auto_sync also refreshes when the cache is stale.

        v0.7.3 (Phase 1, CHANGE 1/2):
        - SYNC VERB SELECTION: when ``_last_sync == 0.0`` this process has
          never completed a sync, so the profile's FULL snapshot may not
          exist locally. ``bw sync --last`` is a DELTA pull keyed to the
          CLI's own server-side sync timestamp — on a never-fully-synced
          profile it can report success while pulling NOTHING, leaving an
          empty cache behind a ``{"synced": true}`` response (production
          incident 2026-11-02). Plain ``bw sync`` (full pull) is used for
          the first sync; ``--last`` only for incremental refreshes.
        - OBSERVABILITY: every outcome (verb decision, success, skip,
          failure) is logged at INFO/WARNING. Log lines carry ONLY
          sanitized error codes from errors.py, epoch timestamps, item
          counts and durations — never a secret value or raw exception
          text.
        """
        now = time.time()
        stale = (now - self.last_sync) > self._config.sync_interval_seconds
        if not force and not (self._config.auto_sync and stale):
            log.info("Sync skipped: cache fresh (last_sync=%.1f, age=%.1fs)",
                     self._last_sync, max(0.0, now - self._last_sync))
            return {"synced": False, "timestamp": self._last_sync, "skipped": "cache fresh"}

        with self._lock:
            last_sync_snapshot = self._last_sync
        full_sync = last_sync_snapshot == 0.0
        if full_sync:
            log.info("Running full sync (no prior sync in this process)")
        else:
            log.info("Running delta sync --last (last_sync=%.1f)",
                     last_sync_snapshot)

        # run_with_recovery already wraps fn in SESSION_ERROR retry logic.
        started = time.monotonic()
        try:
            result = self.run_with_recovery(
                lambda s: self._rate_limited(
                    lambda: self._bw.sync(s, full=full_sync)))
        except Exception as exc:  # noqa: BLE001 - observability path, re-raised below
            # VWP-17: sanitized code only (never raw exception text/values).
            code = compat.get_error_code(exc)
            with self._lock:
                populated = self._last_sync > 0.0
            # v0.7.3 Phase 2: when _maybe_initial_sync() drives the call it
            # owns the WARNING budget for this outcome (per-attempt failures
            # are INFO by spec; only its final line is WARNING). The loop
            # sets _sync_warn_suppressed around its sync() calls; direct
            # callers (tool handlers, auto-sync refresh) never do and keep
            # the full Phase 1 WARNING — no observability regression.
            if not getattr(self, "_sync_warn_suppressed", False):
                log.warning("Sync failed (%s); cache state: %s",
                            code, "populated" if populated else "unpopulated")
            raise
        duration = time.monotonic() - started
        with self._lock:
            self._last_sync = time.time()
        count = self._parse_sync_item_count(result)
        if count is None:
            log.info("Sync completed (%.1fs)", duration)
        else:
            log.info("Sync completed (%d items, %.1fs)", count, duration)
        out: dict = {"synced": True, "timestamp": self._last_sync}
        if count is not None:
            # Internal hand-off for _maybe_initial_sync()'s summary line;
            # contains only a bounded integer — never vault content.
            out["item_count"] = count
            # v0.7.3 Phase 3: same hand-off for BwCli's empty-read defense
            # ("Forced full sync completed (<N> items)"). Bounded int only.
            self._last_sync_item_count = count
        return out

    @staticmethod
    def _parse_sync_item_count(result: object) -> int | None:
        """Best-effort item count from ``bw sync`` output (v0.7.3 Phase 1).

        Returns None whenever the output is not parseable — per the logging
        spec the item count is then OMITTED from the success line. Never
        raises, never logs; the raw output may contain encrypted vault
        material, so only a bounded integer is ever extracted from it.
        """
        if isinstance(result, list):
            return len(result)
        if isinstance(result, dict):
            data = result.get("data")
            if isinstance(data, list):
                return len(data)
            return None
        if isinstance(result, str):
            text = result.strip()
            if not text:
                return None
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None
            if isinstance(parsed, list):
                return len(parsed)
            m = re.search(r"\b(\d{1,9})\s+items?\b", text.lower())
            if m:
                return int(m.group(1))
        return None

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
            # AUD-02 (phase 2): the key leaves process scope when the vault
            # locks. demote_process_scoped clears permanence ONLY while no
            # active execution-scope holder still pins the value (refcount
            # <= bootstrap baseline); any in-flight execution keeps it
            # permanent AND redacted until its own scope closes. When
            # demotion succeeds there is no live registration left, so the
            # value simply drops out of the redaction state; forget_secret
            # afterwards is a guaranteed no-op (unknown releases are
            # sanitized warnings only, never exceptions).
            get_redacting_filter().demote_process_scoped(self._session_key)
            get_redacting_filter().forget_secret(self._session_key)
        self._session_key = None
        self._session_created_at = 0.0

    def lock(self) -> None:
        """Best-effort `bw lock` on the isolated profile + clear memory.

        v0.7.2 (first-burst bootstrap fix, CHANGE 5): demote to LOGGED_OUT —
        NOT LOGGED_IN. The in-memory session key is cleared here, so after a
        lock there is NO usable session at all; LOGGED_IN would wrongly claim
        a re-authenticatable (login-succeeded) profile and route
        get_session() down the unlock-only branch, which cannot succeed
        without a key. LOGGED_OUT keeps every recovery path on the full-FSM
        branch (status probe reconciles the real bw login state anyway).
        """
        with self._lock:
            key = self._session_key
            if key:
                self._bw.lock(key)
            self._clear_session_locked()
            self._state = AuthState.LOGGED_OUT
            log.info("Vault locked; session cleared from plugin memory.")

    def shutdown(self, *, keep_appdata: bool = True) -> None:
        """Plan §12 lifecycle: clear session + placeholders, lock vault, keep .bw-data."""
        try:
            self.lock()
        finally:
            if not keep_appdata:  # pragma: no cover - destructive, off by default
                log.debug("keep_appdata=False requested; leaving .bw-data untouched for safety.")

    def _capability_locked(self) -> tuple[AuthState, bool, float | None]:
        """Authoritative capability predicate — single source of truth.

        Phase-2B (Bug #1 fix): mirrors ``is_unlocked()`` / ``get_session_key()``
        with AND-semantics: UNLOCKED ∧ key-present ∧ age <= timeout. Presence
        alone is NOT capability — a stale key lingering while the FSM sits in
        LOGGED_IN (e.g. lock()/expiry race windows) can never be injected by
        the v0.6.4 ``_ensure_session_env`` choke point, because
        ``get_session_key()`` gates on UNLOCKED. Computed without mutating
        anything (unlike ``is_unlocked()``, which lazily clears expired
        sessions); recovery-on-read happens in the status handler instead.

        Caller MUST hold ``self._lock`` (RLock — re-entrant on the owner).
        Returns ``(state, usable, age_or_None)``; ``age`` is the RAW key age
        whenever a key is present, even when ``usable`` is False, so
        ``session_age_seconds`` keeps reporting the numeric value for existing
        consumers.
        """
        has_key = bool(self._session_key)
        age = (time.time() - self._session_created_at) if has_key else None
        usable = (
            self._state is AuthState.UNLOCKED
            and has_key
            and age is not None
            and age <= self._config.session_timeout_seconds
        )
        return self._state, usable, age

    def status_snapshot(self) -> dict:
        # NOTE: deliberately observational — no lazy expiry *enforcement*
        # (i.e. no state mutation) here; operations recover via
        # get_session()/run_with_recovery(), and the vaultwarden_status tool
        # additionally reconciles BEFORE snapshotting (Phase-2B Bug #2 fix,
        # tools.py h_status), so the snapshot an operator sees reflects the
        # post-recovery state.
        bw_status = self.probe_status()
        # Raw `bw status` profile state, unmodified (real bw uses "status";
        # older fixtures used "state"). This is the CLI's PERSISTENT-session
        # view of the isolated profile — by security design the plugin never
        # persists BW_SESSION to disk/os.environ, so this legitimately reads
        # "locked" even while every operation succeeds via per-command
        # BW_SESSION injection (_ensure_session_env, v0.6.4 HOTFIX).
        bw_profile_state = (bw_status.get("status")
                            or bw_status.get("state") or "unknown")
        with self._lock:
            state, usable, age = self._capability_locked()
            state = state.value
        # Phase-2B (Bug #1 fix): the capability fields are driven by ONE
        # authoritative AND-predicate — UNLOCKED ∧ key-present ∧ unexpired —
        # identical to what get_session_key()/is_unlocked() use to decide
        # whether BW_SESSION can actually be injected per-command (v0.6.4
        # _ensure_session_env choke point). Presence-only over-reported
        # capability whenever a stale key lingered in LOGGED_IN state or the
        # session had expired; both cases now correctly read False.
        session_key_available = usable
        # Phase 4 (v0.7.3 status honesty): cache freshness is now part of the
        # operational predicate. A valid session with a never-populated cache
        # (_last_sync == 0.0) previously reported operational=true while every
        # read returned empty — the exact contradiction behind the first-burst
        # bug. session_active / session_key_available semantics are unchanged
        # (session-key-only predicates); the new fields are additive.
        cache_populated = self._last_sync > 0.0
        if session_key_available and not cache_populated:
            log.warning(
                "Status inconsistency: session active but cache never populated"
            )
        return {
            "plugin": "vaultwarden",
            "enabled": self._config.enabled,
            "auth_state": state,
            # Phase-2B: reinterpreted as the authoritative capability flag
            # (was presence-only `bool(self._session_key)`). Type-compatible
            # (bool); every pinned scenario (fresh unlock -> True, no key ->
            # False) keeps its value — only the stale-key/expired edge cases
            # change, which is precisely Bug #1.
            "session_active": usable,
            # Raw age whenever a key is present — NOT nulled out on expiry, so
            # existing numeric consumers keep working.
            "session_age_seconds": round(age, 1) if age is not None else None,
            "session_timeout_seconds": self._config.session_timeout_seconds,
            # HVA-02 (v0.7.1): status/diagnostic output uses the sanitized
            # accessor (scheme://host[:port] only) so user-info / query /
            # fragment material can never appear in snapshots.
            "server_configured": self._config.server_url_sanitized,
            # ---- additive fields (v0.6.x status fix): new consumers should
            # prefer these over reinterpreting session_active/server_status.
            # True iff AuthManager holds an INJECTABLE BW_SESSION value under
            # the authoritative gate — i.e. the plugin CAN perform read/write
            # operations right now.
            "session_key_available": session_key_available,
            # Overall operational capability. Phase 4 (v0.7.3): requires BOTH
            # a usable session AND a populated cache — a valid session against
            # a never-synced profile is NOT fully operational. Type unchanged
            # (bool) for backward compatibility.
            "operational": session_key_available and cache_populated,
            # ---- additive fields (Phase 4, v0.7.3 status honesty).
            # True iff at least one sync has completed in this process.
            "cache_populated": cache_populated,
            # True iff the bounded initial-sync retry loop (Phase 2) has
            # succeeded exactly once. Consumed by diagnostics.
            "initial_sync_completed": self._initial_sync_completed,
            # Verbatim persistent-session state reported by `bw status` for
            # the isolated profile — informational fidelity, NOT capability.
            # Unchanged by design (Phase-2B CHANGE 3): legitimately "locked"
            # while operational=true because BW_SESSION is memory-only.
            "bw_profile_state": bw_profile_state,
            "server_status": {
                # v0.2.6 (BUGFIX): use internal session state for the lock indicator.
                # bw status is called WITHOUT BW_SESSION (session key lives in plugin
                # memory only, by design), so it always reports "locked" even when
                # the plugin holds an active session. The internal state is authoritative.
                # Phase-2B: "unlocked" now requires the USABLE predicate, so a stale/
                # expired key no longer falsely flips this indicator.
                "state": "unlocked" if usable else bw_profile_state,
                "serverUrl": bw_status.get("serverUrl"),
                "userEmail": bw_status.get("userEmail"),
                "userId": bw_status.get("userId"),
            },
            "appdata_dir": self._bw.appdata_dir,
            "allow_write": self._config.allow_write,
            "last_sync": self._last_sync,
        }

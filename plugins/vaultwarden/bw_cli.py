"""Thin, isolated wrapper around the ``bw`` (Bitwarden CLI) binary.

Every subprocess is executed with a MINIMAL, explicitly constructed env:
    PATH, HOME, BITWARDENCLI_APPDATA_DIR  (+ BW_SESSION when unlocked,
    + BW_CLIENTID/BW_CLIENTSECRET during login, + BW_MP during unlock)
The parent environment is NEVER inherited — this both isolates plugin state
from the host user's bw profile and prevents .env secrets from leaking.

`create`/`edit` require the `bw encode` pipeline for all JSON string fields;
this module handles encoding transparently in ``encode_item``.
"""
from __future__ import annotations

import base64
import json
import os
import random
import stat
import subprocess
import time
from pathlib import Path
from typing import Any, Mapping

from . import compat, errors
from .secure_fs import ensure_hardened_directory
from .security import audit_subprocess_env, get_logger

log = get_logger("bw_cli")

# v0.6.4 (HOTFIX): in-memory AuthManager registry used as a DEFENSE-IN-DEPTH
# fallback for BW_SESSION injection at the subprocess-env choke point
# (BwCli._ensure_session_env). The session key lives in plugin memory only —
# it is never written to disk and never logged. auth.AuthManager registers
# itself here on construction; no strong reference cycle is created (the
# manager holds the BwCli, the registry holds the manager weakly).
import weakref  # noqa: E402

_AUTH_MANAGER_HOLDER: list = []  # single-slot holder: [weakref.ref(AuthManager)]
# v0.6.4: keep a strong ref to the *dummy* objects registered by tests only.
# Production AuthManagers are held weakly (no reference cycle); CPython can
# garbage-collect an inline-constructed test double between the registration
# call and its use, so non-AuthManager registrations are pinned strongly.
_AUTH_MANAGER_STRONG_HOLDER: list = []


def register_auth_manager(auth) -> None:
    """Register the live AuthManager (weakly) for session-key fallback.

    Called from ``AuthManager.__init__``. Safe to call more than once: the
    most recently constructed manager wins (tests construct throwaway
    managers frequently).
    """
    _AUTH_MANAGER_HOLDER.clear()
    _AUTH_MANAGER_STRONG_HOLDER.clear()
    if auth is None:
        return
    _AUTH_MANAGER_HOLDER.append(weakref.ref(auth))
    if type(auth).__name__ != "AuthManager":
        # test double (duck-typed stub): pin it so GC cannot collect it
        # before the assertion that exercises the fallback path.
        _AUTH_MANAGER_STRONG_HOLDER.append(auth)


def get_auth_manager():
    """Return the registered AuthManager, or None if absent/garbage-collected."""
    if not _AUTH_MANAGER_HOLDER:
        return None
    return _AUTH_MANAGER_HOLDER[0]()

# VWP-11: minimum supported bw CLI version (hardcoded — NOT configurable).
# The plugin was developed and tested against bw 2026.9.1. Versions below
# this are unsupported: the marker-based error classification cannot be
# guaranteed to work against an unknown bw build. There is no override.
# VWP-17: the constant now lives in compat.MIN_BW_VERSION; this module
# re-exports it as _MIN_BW_VERSION so existing imports keep working.
_MIN_BW_VERSION = compat.MIN_BW_VERSION

# ── VWP-09: Error markers by source category ──────────────────────
# Priority order in _classify_error(): Cat-2 → rate_limit → Cat-1 → Cat-3

# Cat-2: Node.js network error codes (MOST STABLE — official Node.js API)
_NODE_NETWORK_MARKERS = (
    "econnrefused", "etimedout", "enotfound", "eai_again",
    "socket hang up", "fetch failed", "network",
    "unable to connect", "self signed certificate", "certificate",
    "502 bad gateway", "503 service unavailable", "504 gateway timeout",
)

# Rate limit (server response, stable format — NOT retried, raised immediately)
_RATE_LIMIT_MARKERS = ("too many requests", "rate limit", "429")

# Cat-1: bw CLI state messages (MEDIUM stability — version-dependent,
# anchored by the step-1 version check)
# v0.7.2 (lazy-unlock prompt hardening, CHANGE 3): signature of the bw CLI's
# INTERACTIVE master-password fallback ("? Master password: [input is hidden]").
# When this text appears on stderr the child actually tried to prompt a human;
# the operator-facing message must point at secrets.yaml instead of echoing
# the raw prompt text back through logs / tool responses.
_PASSWORD_PROMPT_MARKERS = (
    "master password:", "[input is hidden]", "password: [hidden]",
)

_SESSION_INVALID_MARKERS = (
    "not logged in",
    "you are not currently logged in",
    "session has timed out",
    "session timed out",
    "vault is locked",
    "mac key dec validation failed",
    "you must log in",
    "please log in first",
    "invalid master password",
    "authentication failed",
    "session expired",
)

# Cat-3: Server API errors (LEAST STABLE — server-version-dependent)
_NOT_FOUND_MARKERS = (
    "cannot find", "does not exist", "not found the given",
    "not found",
)


def validate_bw_path(path: str) -> str:
    """VWP-01: strictly validate the pinned bw binary path.

    The ``bw`` binary is executed ONLY from the absolute path configured in
    ``plugins.entries.vaultwarden.settings.bw_cli_path`` (config.yaml).
    There is NO PATH lookup and NO environment-variable override — a
    compromised PATH or same-named binary must never run with the plugin's
    privileges.

    Validation rules (any failure raises):
      * path must be non-empty                       -> ConfigError
      * path must be absolute                        -> BinaryError
      * no symlink anywhere in the chain             -> BinaryError
        (os.path.abspath(p) must equal os.path.realpath(p))
      * target must be a regular file                -> BinaryError
      * target must be executable (X_OK)             -> BinaryError
      * target must NOT be group/world-writable      -> BinaryError
      * owner must be root (uid 0) or the euid       -> BinaryError

    Returns the validated path string on success.
    """
    raw = str(path or "").strip()
    if not raw:
        raise errors.ConfigError(
            "bw_cli_path is required.",
            suggestion="Set plugins.entries.vaultwarden.settings.bw_cli_path "
                       "to the FULL absolute path of the bw binary "
                       "(e.g. /usr/local/bin/bw) in config.yaml.")

    if not os.path.isabs(raw):
        raise errors.BinaryError(
            f"bw_cli_path {raw!r} must be an absolute path.")

    # Symlink check FIRST: reject if the configured path is (or traverses)
    # any symlink — abspath (lexical) must equal realpath (resolved).
    abs_path = os.path.abspath(raw)
    real_path = os.path.realpath(abs_path)
    if abs_path != real_path:
        raise errors.BinaryError(
            f"bw_cli_path {raw!r} resolves through a symlink "
            f"(realpath: {real_path}); symlinks are not allowed.")

    try:
        st = os.stat(abs_path)
    except OSError as exc:
        raise errors.BinaryError(
            f"bw binary at {raw!r} not found or not accessible: "
            f"{type(exc).__name__}") from exc

    if not stat.S_ISREG(st.st_mode):
        raise errors.BinaryError(
            f"bw_cli_path {raw!r} is not a regular file.")

    if not os.access(abs_path, os.X_OK):
        raise errors.BinaryError(
            f"bw binary at {raw!r} is not executable.")

    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise errors.BinaryError(
            f"bw binary at {raw!r} is group/world-writable; refusing to "
            "execute a binary other users can modify.")

    if st.st_uid not in (0, os.geteuid()):
        raise errors.BinaryError(
            f"bw binary at {raw!r} has unexpected owner uid {st.st_uid}; "
            "it must be owned by root or the current effective user.")

    return abs_path


def find_bw_binary(explicit: str = "") -> str | None:
    """Return the validated pinned bw path, or None on any validation failure.

    VWP-01 (v0.4.7 BREAKING): validates ONLY the explicitly configured
    ``bw_cli_path``. The former environment-variable override and the
    PATH-lookup fallback are REMOVED — config.yaml is the single source of
    truth for the binary location. On failure the reason is logged and None
    is returned (the caller fails closed).
    """
    try:
        return validate_bw_path(explicit)
    except errors.VaultwardenError as exc:
        log.warning("bw_cli_path validation failed (%s): %s", exc.code, exc.message)
        return None


_SESSION_LOCKED_MARKERS = ("vault is locked", "locked")

# v0.6.4 (CHANGE 3): markers that specifically indicate the session key is
# no longer usable (expired / timed out / absent) rather than merely locked.
_SESSION_EXPIRED_MARKERS = (
    "session has timed out", "session timed out", "session expired",
    "not logged in", "you are not currently logged in", "you must log in",
    "please log in first",
)


def _sanitize_bw_stderr(err: str, *secret_values: str | None) -> str:
    """Redact secrets and truncate bw stderr for safe logging/diagnostics.

    v0.6.4 (CHANGE 3): stderr fragments may contain payload material or even
    the session key itself — every known secret value is replaced with a
    ``[REDACTED]`` marker before the (short) excerpt is ever surfaced in a
    log line or an error response.
    """
    text = " ".join((err or "").split())
    for secret in secret_values:
        if secret:
            text = text.replace(str(secret), "[REDACTED]")
    return text[:200]


def _looks_like_password_prompt(err: str) -> bool:
    """True when bw stderr carries the interactive master-password prompt.

    v0.7.2 (lazy-unlock prompt hardening, CHANGE 3): used at the session
    choke point to convert a raw "? Master password: [input is hidden]"
    fallback into an actionable operator message. Detection only — the raw
    prompt text is never surfaced.
    """
    lowered = (err or "").lower()
    return any(m in lowered for m in _PASSWORD_PROMPT_MARKERS)


# v0.7.2 (first-burst bootstrap fix, CHANGE 3): markers showing the failure
# happened BEFORE any unlock attempt — the profile was never bootstrapped
# (server not configured / apikey login rejected). Such failures must NEVER
# be reported as a master-password problem.
_LOGIN_STAGE_MARKERS = (
    "not logged in",
    "you are not currently logged in",
    "you must log in",
    "please log in first",
    "logout required",
    # v0.7.2 (first-burst bootstrap fix, CHANGE 3): the apikey-login stage
    # of a FRESH profile fails with this exact bw wording when the server
    # URL was never configured (or the credentials were rejected) — it is
    # NOT an unlock failure and must never be blamed on master_password.
    # Genuine UNLOCK rejections use the distinct "cannot unlock vault" /
    # "invalid master password" wording (see _unlock_passwordenv path).
    "username or password is incorrect",
)


def _looks_like_login_stage_failure(err: str) -> bool:
    """True when sanitized text shows a LOGIN / server-CONFIG stage failure.

    v0.7.2 (first-burst bootstrap fix, CHANGE 3): distinguishes an
    un-bootstrapped profile (config-server / apikey-login stage) from a
    genuine UNLOCK failure. Only fixed marker substrings are matched — the
    input is always sanitized/derived text, and nothing matched here is ever
    propagated into a message or log line.
    """
    lowered = (err or "").lower()
    return any(m in lowered for m in _LOGIN_STAGE_MARKERS)


class BwCli:
    """Stateless command runner; session/auth state lives in AuthManager."""

    def __init__(self, bw_path: str, appdata_dir: str | Path, *,
             timeout: int = 30,
             max_retries: int = 3,
             backoff_base: float = 1.0,
             max_delay: float = 10.0,
             check_version: bool = True):
        if not bw_path or not find_bw_binary(bw_path):
            # VWP-01 (v0.4.7): the path is validated strictly here — no PATH
            # lookup and no env override; config.yaml is the only source of
            # truth for the binary location.
            raise errors.BinaryError(
                "Configured bw_cli_path is missing or failed validation "
                "(see plugin log).")
        self.bw_path = str(bw_path)
        self.appdata_dir = str(Path(appdata_dir).expanduser())
        self.timeout = timeout

        # VWP-10: retry / backoff parameters
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._max_delay = max_delay

        # v0.7.2 (first-burst bootstrap fix, CHANGE 1): register() must
        # perform ZERO bw subprocesses — even the fail-fast version probe
        # is deferred to the first authenticated operation (the auth FSM /
        # choke point), so a fresh profile sees its FIRST `bw` spawn as the
        # status probe of the bootstrap sequence, not --version at load
        # time. ``check_version=False`` marks a construction that will be
        # probed lazily; direct constructions keep the eager VWP-11 default.
        self._version_checked = False
        if check_version:
            self._bw_version = self._check_version()
        else:
            self._bw_version = ""

    @property
    def bw_version(self) -> str:
        """The validated bw CLI version string (VWP-11)."""
        return self._bw_version

    def _ensure_version_checked(self) -> None:
        """Lazily run the VWP-11 fail-fast version probe (v0.7.2).

        Idempotent: runs `bw --version` exactly once per instance, on the
        first session-requiring / bootstrap command — never at register()
        time (deferred startup pin). A too-old or unparsable bw still fails
        closed with UnsupportedBwVersionError at the first real use.
        """
        if self._version_checked:
            return
        self._bw_version = self._check_version()
        self._version_checked = True

    # ------------------------------------------------------------------ env
    def base_env(self, extra: Mapping[str, str] | None = None) -> dict:
        """Build the minimal isolated subprocess environment.

        AUD-04 (v0.6.2, FAIL-CLOSED): the appdata directory is re-validated
        through :func:`secure_fs.ensure_hardened_directory` BEFORE
        ``BITWARDENCLI_APPDATA_DIR`` is set — every ``bw`` subprocess runs
        through this single choke point, so ``bw`` can NEVER be invoked
        against an insecure appdata dir (symlink / wrong owner / mode not
        exactly 0700). A missing dir is created hardened; an insecure one
        raises ``FilesystemSecurityError``, which propagates to the caller
        and blocks execution (never caught and ignored here).
        """
        ensure_hardened_directory(Path(self.appdata_dir),
                                  create_if_missing=True)
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", str(Path.home())),
            "BITWARDENCLI_APPDATA_DIR": self.appdata_dir,
        }
        if extra:
            env.update({k: v for k, v in extra.items() if v})
        violations = audit_subprocess_env(env)
        if violations:  # pragma: no cover - defensive invariant
            log.error("Subprocess env allowlist violation: %s", violations)
        return env

    # ------------------------------------------------------------ version check
    def _check_version(self) -> str:
        """Validate bw CLI version at startup (VWP-11, fail-closed, no override).

        Runs `bw --version` with the isolated base_env and a 5s timeout.
        Parses the calendar version string (YYYY.M.P) into a tuple of ints.
        Raises UnsupportedBwVersionError if the version is below
        _MIN_BW_VERSION or cannot be parsed. There is NO override: if the
        check fails, the plugin does not start.

        Returns the raw version string on success.
        """
        try:
            # v0.7.2 (lazy-unlock prompt hardening, CHANGE 1): DEVNULL here
            # too — every bw invocation without an input payload must run
            # with stdin closed so an interactive prompt can never render.
            proc = subprocess.run(
                [self.bw_path, "--version"],
                env=self.base_env(),
                capture_output=True, text=True, timeout=5,
                stdin=subprocess.DEVNULL,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise errors.BinaryError(
                f"Cannot execute bw --version: {type(exc).__name__}"
            ) from exc

        if proc.returncode != 0:
            raise errors.BinaryError(
                f"bw --version failed (exit {proc.returncode})"
            )

        version_str = (proc.stdout or "").strip()
        min_str = ".".join(str(x) for x in compat.MIN_BW_VERSION)

        # VWP-17: parsing + minimum enforcement centralized in compat.py
        try:
            nums = compat.parse_bw_version(version_str)
        except ValueError as exc:
            log.error(
                "bw version %r cannot be parsed; plugin requires >= %s. "
                "Upgrade the Bitwarden CLI.", version_str, min_str,
            )
            raise errors.UnsupportedBwVersionError(
                f"Cannot parse bw version: {version_str!r}"
            ) from exc

        if nums < compat.MIN_BW_VERSION:
            log.error(
                "bw version %s is below the minimum supported version %s. "
                "Upgrade the Bitwarden CLI. Plugin will not start.",
                version_str, min_str,
            )

        compat.require_min_bw_version(version_str)

        log.info("bw CLI version %s validated (minimum: %s)", version_str, min_str)
        return version_str

    # ------------------------------------------------------- classification (VWP-09)
    def _classify_error(self, combined: str) -> str:
        """Classify a bw error by source category (VWP-09).

        Priority (most stable first): Cat-2 network → rate_limit →
        Cat-1 session → Cat-3 not_found → unknown.

        Returns one of: "network", "rate_limit", "session", "not_found",
        "unknown".
        """
        if any(m in combined for m in _NODE_NETWORK_MARKERS):
            return "network"
        if any(m in combined for m in _RATE_LIMIT_MARKERS):
            return "rate_limit"
        if any(m in combined for m in _SESSION_INVALID_MARKERS):
            return "session"
        if any(m in combined for m in _NOT_FOUND_MARKERS):
            return "not_found"
        return "unknown"

    def _parse_output(self, out: str, args: list[str]) -> Any:
        """Parse bw stdout as JSON, falling back to raw string (VWP-09).

        If output looks like JSON but fails to parse, log a debug message
        and return the raw string instead of raising ParseError, so a
        single malformed bw response does not crash the operation.
        """
        if not out:
            return None
        if out.startswith("{") or out.startswith("["):
            try:
                return json.loads(out)
            except json.JSONDecodeError:
                log.debug(
                    "bw %s returned non-JSON output despite JSON prefix; "
                    "treating as raw. first 100 chars: %.100s", args[0], out,
                )
                return out
        return out

    # ------------------------------------------------------------- backoff (VWP-10)
    def _compute_backoff(self, attempt: int) -> float:
        """Bounded exponential backoff with additive jitter (VWP-10).

        Formula: base * 2^attempt + uniform(0, 1), capped at max_delay.
        attempt=0 → ~1s, attempt=1 → ~2s, attempt=2 → ~4s
        (with base=1.0, max_delay=10.0).
        """
        delay = self._backoff_base * (2 ** attempt) + random.uniform(0, 1)
        return min(delay, self._max_delay)

    # ------------------------------------------- session injection (v0.6.4)
    #: bw commands that operate on vault data and therefore REQUIRE a live
    #: session key (BW_SESSION) in the subprocess environment.
    _SESSION_REQUIRED_COMMANDS = frozenset({
        "list", "get", "create", "edit", "delete", "sync", "generate",
        "encode", "lock",
    })

    def _ensure_session_env(self, args: list[str],
                            env: Mapping[str, str] | None) -> dict:
        """Build the isolated subprocess env, guaranteeing BW_SESSION (v0.6.4).

        HOTFIX (v0.6.4): vault read/write operations (``list``, ``get``,
        ``create``, ``edit``, ``delete``, ...) require the session key in the
        ``bw`` subprocess environment. A missing ``BW_SESSION`` makes ``bw``
        run against a LOCKED vault — empty lists from ``list`` and exit-1
        failures from ``create`` — exactly the v0.6.3 regression this restores.

        Injection is defense-in-depth at the single env choke point:
          * explicit callers (the AuthManager-wrapped command methods below)
            already pass ``env={"BW_SESSION": session_key}`` — preserved;
          * if no session is supplied for a session-requiring command, the
            current in-memory session key is injected here so the isolation
            choke point can never silently drop it.

        v0.7.2 (CHANGE 2): PRE-FLIGHT LOCK CHECK — the choke point can now
        NEVER spawn a session-requiring command without a valid BW_SESSION:
          * the fallback key comes from ``AuthManager.get_session_key()``,
            which enforces expiry since v0.7.2 (no stale-key injection);
          * when NO valid key is available, a synchronous lazy-unlock runs
            via ``AuthManager.get_session()`` for EVERY registered manager —
            get_session() is itself gated: it only spawns login/unlock when
            the FSM already sits in CONFIGURED/LOGGED_IN/UNLOCKED (a
            re-authenticatable profile), and raises a sanitized SessionError
            for UNINITIALIZED/LOGGED_OUT profiles, so an un-bootstrapped
            profile can never be force-logged-in from inside a data command;
          * if no recoverable key exists, a sanitized :class:`errors.SessionError`
            is raised BEFORE the subprocess is spawned — instead of silently
            proceeding against a locked profile (the read blind spot: locked
            ``bw list`` returns an EMPTY list with exit 0 and would never
            reach error classification).
        Explicit caller-provided env values still take precedence, and
        non-session commands are completely unaffected.

        The session key lives in plugin memory ONLY: it is never written to
        disk and never logged (base_env() still builds the env from scratch —
        the parent environment is NOT inherited). No session-key value ever
        appears in the raised error message or any log line.
        """
        merged: dict[str, str] = dict(env or {})
        verb = args[0] if args else ""
        # v0.7.2 (first-burst bootstrap fix, CHANGE 1/2): LAZY BOOTSTRAP for
        # session-requiring commands — whenever NO valid BW_SESSION is
        # available (explicitly falsy caller key OR no key at all), the full
        # ensure_authenticated() FSM runs BEFORE the subprocess is spawned,
        # so a fresh CONFIGURED profile bootstraps correctly on the FIRST
        # burst instead of spawning `bw list` against an un-bootstrapped
        # profile (which exits 0 with an EMPTY payload — the read blind spot)
        # or letting `bw create` die with exit 1. Gated INTERNALLY by
        # AuthManager.get_session(): UNINITIALIZED profiles raise a
        # sanitized SessionError before any spawn (deferred-startup +
        # never-force-login pins preserved); non-session commands and
        # callers that already hold a VALID explicit key are completely
        # unaffected (no extra subprocess on the healthy path).
        auth_manager = get_auth_manager()
        # v0.7.2 (first-burst bootstrap fix, CHANGE 1/2): the FSM re-bootstrap
        # capability attached by the REAL AuthManager constructor
        # (``_bootstrap_via_auth_manager``) is the authoritative signal that
        # a lazy full-FSM bootstrap is possible for THIS BwCli instance —
        # including when the call arrives through the manager's own command
        # wrappers with an explicit (possibly expired) BW_SESSION. Duck-typed
        # test doubles and bare BwCli instances never get the capability, so
        # their explicit keys stay trusted as-is (zero extra subprocesses on
        # healthy paths, minimal doubles keep working).
        _fsm_bootstrap = getattr(self, "_bootstrap_via_auth_manager", None)
        _is_real_manager = callable(_fsm_bootstrap) or callable(
            getattr(auth_manager, "ensure_authenticated", None))
        _can_vouch = callable(getattr(auth_manager, "get_session_key", None))
        if verb in self._SESSION_REQUIRED_COMMANDS:
            _explicit_key = merged.get("BW_SESSION")
            _valid_key_available = bool(
                _explicit_key
                and (_is_real_manager
                     and _can_vouch
                     and auth_manager is not None
                     and auth_manager.get_session_key() == _explicit_key
                     or not _is_real_manager))
            if not _valid_key_available and auth_manager is not None:
                _gs = getattr(auth_manager, "get_session", None)
                if callable(_gs):
                    try:
                        _boot_key = _gs()
                    except Exception as _exc:  # noqa: BLE001 - fail-closed below
                        # Sanitized code extraction only — never exception
                        # text; the canonical SessionError further down keeps
                        # the surfaced message free of secret-bearing detail.
                        log.warning(
                            "Choke-point lazy bootstrap failed (%s) before "
                            "spawning '%s'.",
                            compat.get_error_code(_exc), verb)
                    else:
                        if _boot_key and not _explicit_key:
                            merged["BW_SESSION"] = _boot_key
        # v0.7.2 (lazy-unlock prompt hardening): initialized OUTSIDE the
        # lazy-unlock branch so the fail-closed check below is always bound —
        # including when no auth manager is registered at all (both default
        # to "no prompt signature detected", which keeps the canonical
        # sanitized SessionError wording for that path).
        unlock_error_code: str | None = None
        unlock_prompt_seen = False
        # v0.7.2 (first-burst bootstrap fix, CHANGE 3): structured stage
        # marker set by get_session() ("login" when the config-server /
        # apikey-login stage failed on an un-bootstrapped profile). Only a
        # fixed identifier string — never secret material.
        unlock_bootstrap_stage: str | None = None
        if verb in self._SESSION_REQUIRED_COMMANDS:
            if not merged.get("BW_SESSION"):
                auth = auth_manager
                key = auth.get_session_key() if _can_vouch else None
                if not key and auth is not None and _can_vouch:
                    # Pre-flight synchronous lazy-unlock via get_session().
                    # Gated INTERNALLY by AuthManager.get_session(): it only
                    # spawns login/unlock when the FSM already sits in
                    # CONFIGURED/LOGGED_OUT/LOGGED_IN/UNLOCKED (a
                    # re-authenticatable profile) and raises a sanitized
                    # SessionError otherwise, so an un-bootstrapped/locked-out
                    # profile can never be force-logged-in from inside a data
                    # command. Duck-typed managers without get_session()
                    # simply fail the callable() check below and fall through
                    # to the canonical SessionError.
                    get_session = getattr(auth, "get_session", None)
                    if callable(get_session):
                        # Any failure is swallowed here — the canonical,
                        # sanitized SessionError below keeps the message free
                        # of exception text that could carry secret fragments.
                        # v0.7.2 (lazy-unlock prompt hardening, CHANGE 3):
                        # the exception TYPE (sanitized code) and its
                        # sanitized message/suggestion text are captured so a
                        # failed unlock that fell back to bw's INTERACTIVE
                        # master-password prompt can be converted into an
                        # actionable operator message ("verify master_password
                        # in secrets.yaml") instead of echoing the raw prompt
                        # text. The matched excerpt is NEVER propagated — only
                        # the boolean matters; no master password or session
                        # key value appears in any log line or raised message.
                        unlock_error_code = None
                        unlock_prompt_seen = False
                        unlock_bootstrap_stage = None
                        try:
                            key = get_session()
                        except Exception as exc:  # noqa: BLE001 - fail-closed below
                            # VWP-17: code extraction only — never the message.
                            unlock_error_code = compat.get_error_code(exc)
                            # CHANGE 3: read ONLY the structured stage marker
                            # (a fixed identifier like "login"), never any
                            # exception text — a login/config-stage failure
                            # must not be blamed on master_password below.
                            _stage = getattr(exc, "bootstrap_stage", None)
                            if isinstance(_stage, str) and _stage == "login":
                                unlock_bootstrap_stage = "login"
                            # Detection inputs are ONLY sanitized/derived
                            # text (the already-scrubbed exception message/
                            # suggestion and the test-only stderr-injection
                            # hook). The raw child stderr is never read here;
                            # nothing matched is ever propagated into a log
                            # line or raised message — only the boolean.
                            probe = (
                                str(getattr(exc, "message", "") or "") + " " +
                                str(getattr(exc, "suggestion", "") or "")
                            )
                            if _looks_like_password_prompt(probe):
                                unlock_prompt_seen = True
                            elif _looks_like_login_stage_failure(probe):
                                # CHANGE 3: structured-marker fallback for
                                # managers that do not attach
                                # ``bootstrap_stage`` — detection only; the
                                # matched excerpt is never propagated.
                                unlock_bootstrap_stage = "login"
                            else:
                                # Belt-and-braces: run()'s classification path
                                # may not have scrubbed every prompt variant
                                # from the suggestion text. BW_TEST_FORCE_STDERR
                                # is the only stderr source observable at this
                                # layer (test hook, never set in production).
                                injected = os.environ.get(
                                    "BW_TEST_FORCE_STDERR")
                                if injected and _looks_like_password_prompt(
                                        injected):
                                    unlock_prompt_seen = True
                            log.warning(
                                "Choke-point lazy unlock failed (%s; "
                                "bootstrap stage=%s); raising SessionError "
                                "before spawning '%s'.",
                                unlock_error_code,
                                unlock_bootstrap_stage or "unlock/unknown",
                                verb)
                            key = None
                if key:
                    merged["BW_SESSION"] = key
                else:
                    # v0.7.2 (CHANGE 3): when the lazy-unlock failed with the
                    # interactive-prompt signature (or an AUTH_ERROR — e.g.
                    # the falsy-master-password fail-closed path), surface an
                    # actionable bootstrap hint. The raw "? Master password:"
                    # prompt text NEVER reaches this message, any log line,
                    # or the tool response.
                    #
                    # v0.7.2 (first-burst bootstrap fix, CHANGE 3 — error
                    # mapping accuracy): a LOGIN / server-config stage
                    # failure is checked FIRST and must NOT blame
                    # master_password — the credential was never even used
                    # at that stage. "verify master_password in
                    # secrets.yaml" stays reserved for genuine UNLOCK-stage
                    # failures (login succeeded, unlock rejected).
                    if unlock_bootstrap_stage == "login":
                        raise errors.SessionError(
                            f"Vault profile not yet bootstrapped — server "
                            f"not configured or not logged in ('{verb}'); "
                            f"bootstrap was attempted.",
                            suggestion="The isolated bw profile could not be "
                                       "bootstrapped (server configuration or "
                                       "apikey login stage — the master "
                                       "password was NOT the problem). Verify "
                                       "server_url and client_id in "
                                       "config.yaml and the client_secret in "
                                       "$HERMES_HOME/plugins/vaultwarden/"
                                       "secrets.yaml (chmod 600), then retry.")
                    if unlock_prompt_seen or unlock_error_code == "AUTH_ERROR":
                        raise errors.SessionError(
                            f"Non-interactive unlock failed — verify "
                            f"master_password in secrets.yaml ('{verb}').",
                            suggestion="The plugin refused to fall back to "
                                       "bw's interactive master-password "
                                       "prompt. Check the master_password "
                                       "entry in "
                                       "$HERMES_HOME/plugins/vaultwarden/"
                                       "secrets.yaml (chmod 600) and "
                                       "re-bootstrap.")
                    raise errors.SessionError(
                        f"Vault session is locked and could not be "
                        f"re-established; re-unlock required ('{verb}').",
                        suggestion="The plugin will attempt automatic "
                                   "re-unlock on the next call after you "
                                   "unlock the vault (vaultwarden_status / "
                                   "re-auth).")
        return self.base_env(merged)

    def _session_error(self, verb: str, err: str,
                       session_key: str | None = None) -> errors.VaultwardenError:
        """Build a precise error for locked/expired bw sessions (v0.6.4).

        CHANGE 3: ``SESSION_EXPIRED`` when stderr carries an explicit
        expired/timed-out/not-logged-in marker; otherwise the classic
        ``SESSION_ERROR`` (the plugin's run_with_recovery auto re-unlock path
        keys off SESSION_ERROR and must keep working). The sanitized stderr
        excerpt is logged at debug level — never the raw session key or any
        vault payload.
        """
        err_lower = (err or "").lower()
        safe_err = _sanitize_bw_stderr(err, session_key)
        log.debug("bw %s session failure rc context: stderr=%.200s",
                  verb, safe_err)
        if any(m in err_lower for m in _SESSION_EXPIRED_MARKERS):
            return errors.SessionError(
                f"bw session expired or invalid ({verb}).",
                code="SESSION_EXPIRED",
                suggestion="Vault session may have expired. Try unlocking "
                           "again (vaultwarden_status / re-auth). "
                           f"bw stderr: {safe_err}")
        return errors.SessionError(
            f"bw session invalid or vault locked ({verb}).",
            suggestion=f"Vault appears locked for '{verb}'. Unlock the vault "
                       f"and retry. bw stderr: {safe_err}")

    # ------------------------------------------------------------- run core
    def _write_failure(self, verb: str, rc: int, out: str, err: str,
                       session_key: str | None) -> errors.VaultwardenError:
        """Classify a direct-subprocess write failure (v0.7.2, CHANGE 3).

        ``create_item`` / ``edit_item`` bypass :meth:`run` (they pipe the
        encoded payload via stdin), so their non-zero exit codes never reach
        the generic ``_classify_error()`` taxonomy — a locked-vault failure
        used to surface as a generic ``VaultwardenError`` (PLUGIN_ERROR),
        which ``AuthManager.run_with_recovery`` does NOT catch (it only
        handles ``SessionError``). That was the "write recovery bypass" leg
        of the first-burst regression: ``bw create item failed (exit 1)``
        propagated with zero re-unlock.

        Now the stderr is routed through the SAME marker classification as
        :meth:`run`:
          * session markers ("vault is locked", "not logged in", "invalid
            master password", ...) => :func:`_session_error` — a
            ``SessionError`` (SESSION_EXPIRED vs SESSION_ERROR mapping
            preserved from v0.6.4) that ``run_with_recovery`` catches and
            recovers synchronously;
          * rate-limit / network markers => the matching error classes;
          * anything else => the sanitized generic ``VaultwardenError``
            (unchanged message shape: "bw <verb> failed (exit N).").

    Security: bw stderr on write paths may contain payload fragments — it is
        NEVER logged or attached raw. Only :func:`_sanitize_bw_stderr` output
        (known secrets replaced with [REDACTED], length-capped) is ever
        surfaced, exactly like the v0.6.4 read path.
        """
        combined = ((out or "") + "\n" + (err or "")).lower()
        category = self._classify_error(combined)
        if category == "session":
            return self._session_error(verb, err, session_key)
        if category == "rate_limit":
            return errors.RateLimitError(
                "Vaultwarden rate limit hit (HTTP 429).")
        if category == "network":
            return errors.NetworkError(
                "Vaultwarden server appears unreachable.")
        safe_err = _sanitize_bw_stderr(err, session_key, out)
        # v0.7.2 (lazy-unlock prompt hardening, CHANGE 3): never echo the
        # interactive master-password prompt into logs / tool responses —
        # replace it with an actionable operator message (secrets.yaml hint).
        if _looks_like_password_prompt(safe_err):
            safe_err = ("non-interactive unlock failed — verify "
                        "master_password in secrets.yaml")
        log.error(
            "bw %s failed rc=%d category=%s; sanitized stderr: %s",
            verb, rc, category, safe_err or "<empty>",
        )
        suggestion = "Run 'vaultwarden_status' for details."
        if safe_err:
            suggestion += f" bw stderr: {safe_err}"
        return errors.VaultwardenError(
            f"bw {verb} failed (exit {rc}).", suggestion=suggestion)

    def run(self, args: list[str], *, env: Mapping[str, str] | None = None,
            raw: bool = False, timeout: int | None = None,
            _retry_count: int = 0, retryable: bool = True) -> Any:
        """Execute bw, returning parsed JSON (default) or stripped stdout (raw).

        VWP-09: errors classified by source category via _classify_error().
        VWP-10: network errors on idempotent ops retried with bounded
        exponential backoff + jitter. Non-idempotent callers pass
        retryable=False. Never includes argv/env contents in raised messages.

        v0.6.4: BW_SESSION is guaranteed for session-requiring commands via
        :meth:`_ensure_session_env` (see the hotfix docstring there).
        """
        # v0.7.2 (first-burst bootstrap fix, CHANGE 1): the choke point is
        # the single spawn gate for every bw invocation — run the deferred
        # VWP-11 version probe here exactly once (register() performs zero
        # subprocesses), BEFORE any session-requiring command may execute.
        # Non-session commands (e.g. the FSM's own `bw status` probe) also
        # trigger it, so a too-old bw fails closed before the first burst.
        self._ensure_version_checked()
        full_env = self._ensure_session_env(args, env)
        cmd = [self.bw_path, *args]
        # v0.7.2 (lazy-unlock prompt hardening, CHANGE 1): every bw call that
        # does NOT carry an input payload runs with stdin=subprocess.DEVNULL.
        # Without this the child INHERITS the gateway's stdin, so any bw
        # command that falls back to an interactive prompt (e.g.
        # "? Master password: [input is hidden]" when --passwordenv points at
        # a missing BW_MP variable) can actually render and block — exactly
        # the first-burst regression this closes. DEVNULL makes an interactive
        # prompt structurally impossible for argv-only invocations, matching
        # the pattern already used by the SSH helpers in tools.py. Callers
        # that DO pass input= (create_item / edit_item / encode) keep their
        # own stdin=PIPE path — those bypass run() entirely, and subprocess
        # forbids combining input= with stdin= in one call, so the two are
        # never mixed here.
        try:
            # v0.1.4 (FAIL-5): look up subprocess.run via the module attribute so
            # tests can monkeypatch subprocess.run deterministically.
            proc = subprocess.run(
                cmd, env=full_env, capture_output=True, text=True,
                timeout=timeout or self.timeout,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired as exc:
            raise errors.NetworkError(
                f"bw {' '.join(args[:1])} timed out after "
                f"{timeout or self.timeout}s."
            ) from exc
        except OSError as exc:
            raise errors.BinaryError(
                f"Failed to execute bw: {type(exc).__name__}"
            ) from exc

        # v0.1.4 (FAIL-4): test-only hook — lets tests inject synthetic stderr
        # (e.g. a stale-session marker) WITHOUT smuggling non-allowlisted keys
        # into the isolated subprocess env. Never set in production. Injected
        # AFTER subprocess.run, BEFORE classification (preserved from v0.1.4).
        injected = os.environ.get("BW_TEST_FORCE_STDERR")
        if injected:
            proc = subprocess.CompletedProcess(
                cmd, returncode=1, stdout=proc.stdout, stderr=injected)

        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        combined = (out + "\n" + err).lower()

        if proc.returncode != 0:
            category = self._classify_error(combined)

            # VWP-10: retry only network errors on idempotent operations
            if (category == "network" and retryable
                    and _retry_count < self._max_retries):
                delay = self._compute_backoff(_retry_count)
                log.warning(
                    "bw %s network error (rc=%d), retry %d/%d in %.1fs",
                    args[0], proc.returncode,
                    _retry_count + 1, self._max_retries, delay,
                )
                time.sleep(delay)
                return self.run(args, env=env, raw=raw, timeout=timeout,
                                _retry_count=_retry_count + 1,
                                retryable=retryable)

            if category == "rate_limit":
                raise errors.RateLimitError(
                    "Vaultwarden rate limit hit (HTTP 429).")
            if category == "network":
                if _retry_count > 0:
                    log.error(
                        "bw %s failed after %d retries (rc=%d)",
                        args[0], _retry_count, proc.returncode,
                    )
                raise errors.NetworkError(
                    "Vaultwarden server appears unreachable.")
            if category == "session":
                # v0.6.4 (CHANGE 3): precise SESSION_EXPIRED vs SESSION_ERROR
                # classification + sanitized stderr excerpt in the suggestion.
                raise self._session_error(args[0], err,
                                          (env or {}).get("BW_SESSION"))
            if category == "not_found":
                raise errors.NotFoundError(
                    f"No matching item for query '{args[-1]}'.")

            safe_err = _sanitize_bw_stderr(
                err, (env or {}).get("BW_SESSION"), out)
            # v0.7.2 (lazy-unlock prompt hardening, CHANGE 3): if bw fell
            # back to its interactive master-password prompt, NEVER echo the
            # raw prompt text into logs or the tool response — replace it
            # with an actionable operator message pointing at secrets.yaml.
            if _looks_like_password_prompt(safe_err):
                safe_err = ("non-interactive unlock failed — verify "
                            "master_password in secrets.yaml")
            log.error(
                "bw %s failed rc=%d category=unknown; sanitized stderr: %s",
                args[0], proc.returncode, safe_err or "<empty>",
            )
            suggestion = "Run 'vaultwarden_status' for details."
            if safe_err:
                suggestion += f" bw stderr: {safe_err}"
            raise errors.VaultwardenError(
                f"bw {args[0]} failed (exit {proc.returncode}).",
                suggestion=suggestion)

        if raw:
            return out
        return self._parse_output(out, args)

    # ------------------------------------------------------------ commands
    def status(self) -> dict:
        """`bw status` -> parsed JSON dict.

        v0.1.9: an unauthenticated profile answers with rc!=0 + empty stdout;
        that plain failure degrades to {} ("not logged in") so the auth
        flow can branch on it without raising. Transport-level errors
        (network / timeout / binary) still propagate through the normal
        retry + error taxonomy — otherwise a downed server would masquerade
        as "unauthenticated" and trigger a pointless login attempt.
        """
        try:
            data = self.run(["status"])
        except errors.SessionError:
            return {}  # stale/absent session on the profile -> not logged in
        if isinstance(data, dict):
            return data
        if data is None:
            return {}
        return {"status": "unauthenticated", "message": str(data)}

    def verify_session(self, session_key: str) -> str:
        """Verify a session key is still valid by calling ``bw status`` with it.

        v0.7.6 (Phase 1, CHANGE 1): session-invalidation defense. bw supports
        exactly ONE session key per profile — when a second AuthManager (e.g.
        the gateway process alongside the dashboard process) unlocks the same
        profile, the first manager's BW_SESSION is invalidated EXTERNALLY while
        its local state still reports UNLOCKED. This probe asks the binary
        directly whether the key still authenticates.

        Returns the status string ("unlocked", "locked", "unauthenticated").
        Returns "locked" on any error (conservative — triggers re-unlock).
        Never logs the session key value.

        The verification call MUST carry the key under test via BW_SESSION —
        the persistent profile state always reports "locked" by design, so a
        session-less ``status()`` could never detect external invalidation.
        ``run()`` gives explicit caller env precedence over the choke point's
        fallback injection, so exactly this key is verified.
        """
        try:
            result = self.run(["status"], env={"BW_SESSION": session_key})
            if isinstance(result, dict):
                return str(result.get("status") or result.get("state")
                           or "unknown")
            return "unknown"
        except errors.SessionError:
            return "locked"  # session key is invalid
        except errors.VaultwardenError:
            return "unknown"  # network/parse error — conservative

    def logout(self) -> bool:
        """`bw logout`. Returns True on success or when already logged out."""
        try:
            self.run(["logout"])
            return True
        except (errors.SessionError, errors.NotFoundError):
            return True  # nothing to log out from

    def config_server(self, url: str) -> None:
        self.run(["config", "server", url])

    def config_get(self) -> Any:
        return self.run(["config", "get", "server"])

    # VWP-10: login/unlock generate a session key (a retry would create a
    # duplicate session); create_attachment duplicates the attachment on
    # retry; delete returns NotFoundError on a successful-but-retried
    # delete (false negative). These five callers pass retryable=False.
    def login_apikey(self, client_id: str, client_secret: str) -> str:
        env = {"BW_CLIENTID": client_id, "BW_CLIENTSECRET": client_secret}
        return self.run(["login", "--apikey", "--nointeraction"], env=env,
                      raw=True, retryable=False)

    def unlock_passwordenv(self, master_password: str) -> str:
        """Returns the raw session key (kept in plugin memory only).

        v0.7.2 (lazy-unlock prompt hardening, CHANGE 2): FAIL-CLOSED guard —
        a falsy master password raises ``errors.AuthError`` (AUTH_ERROR
        category, NOT SessionError) BEFORE any subprocess is spawned. The
        master password is delivered exclusively via the BW_MP environment
        variable, and ``base_env()`` silently drops falsy extras — so
        spawning ``bw unlock --passwordenv BW_MP`` with an empty/missing MP
        would point --passwordenv at a nonexistent variable and bw would fall
        back to its interactive "? Master password:" prompt. Using AuthError
        (recoverable=False) also keeps ``run_with_recovery`` from entering a
        re-unlock loop that can never succeed without a master password. The
        password VALUE never appears in the message or any log line.
        """
        if not master_password or not str(master_password).strip():
            raise errors.AuthError(
                "master password unavailable; cannot unlock "
                "non-interactively. Verify master_password in secrets.yaml "
                "and re-bootstrap.")
        env = {"BW_MP": master_password}
        try:
            key = self.run(["unlock", "--passwordenv", "BW_MP", "--raw",
                            "--nointeraction"],
                           env=env, raw=True, retryable=False)
        except errors.VaultwardenError as exc:
            # v0.7.2 (first-burst bootstrap fix, CHANGE 3): structured stage
            # attribution at the source. When `bw unlock` fails because the
            # profile is NOT LOGGED IN (login-stage prerequisite unmet — e.g.
            # an un-bootstrapped fresh profile), attach the fixed "login"
            # stage marker so upstream messages never blame master_password.
            # A genuine unlock rejection keeps its legitimate
            # master-password messaging untouched. Detection uses fixed
            # markers on ALREADY-SANITIZED derived text only; nothing
            # matched is propagated and no secret value rides this path.
            probe = (str(exc.message or "") + " " +
                     str(exc.suggestion or ""))
            if (_looks_like_login_stage_failure(probe)
                    and not _looks_like_password_prompt(probe)):
                exc.bootstrap_stage = "login"
            raise
        if not key:
            raise errors.AuthError("bw unlock returned an empty session key.")
        return key

    def lock(self, session_key: str) -> None:
        try:
            self.run(["lock"], env={"BW_SESSION": session_key})
        except errors.VaultwardenError as exc:
            log.warning("bw lock failed (%s); clearing local session anyway.", exc.code)

    def sync(self, session_key: str, force: bool = False, *,
             full: bool | None = None) -> Any:
        """Run ``bw sync``; full (--force) vs incremental pull is explicit.

        v0.7.4 (sync verb correction, CHANGE 1): ``full`` selects the sync
        VERB explicitly.
        ``full=True``  -> ``bw sync --force`` (FULL snapshot pull — forces a
        complete re-download into the local SQLite cache);
        ``full=False`` -> ``bw sync`` (incremental pull of the latest vault
        data from the server).
        The v0.7.3 ``--last`` delta verb is REMOVED entirely: per
        ``bw sync --help``, ``--last`` ONLY prints the last sync date and
        performs NO synchronization at all — every code path that routed to
        it silently skipped syncing. When ``full`` is None the legacy
        ``force`` parameter maps directly onto the verb (force=True ->
        ``bw sync --force``); the v0.7.3 inverted mapping (force -> delta
        ``--last``) was part of the bug. Both verbs parse output as JSON
        (raw mode removed): neither ``bw sync`` nor ``bw sync --force``
        produces meaningful raw stdout that callers depend on.
        """
        if full is None:
            full = force  # force=True -> full=True -> bw sync --force
        args = ["sync", "--force"] if full else ["sync"]
        return self.run(args, env={"BW_SESSION": session_key}, raw=False)

    def list_items(self, session_key: str, filters: list[str] | None = None) -> list[dict]:
        args = ["list", "items", "--pretty"]
        if filters:
            args += filters
        data = self.run(args, env={"BW_SESSION": session_key})
        items = self._extract_items(data)
        # v0.7.2 (first-burst bootstrap fix, CHANGE 5): read blind-spot
        # defense — see _reconcile_empty_read().
        if not items:
            retry = self._reconcile_empty_read(args, session_key)
            if retry is not None:
                items = retry
        return items

    @staticmethod
    def _extract_items(data: Any) -> list[dict]:
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "data" in data:
            return data["data"]
        return []

    def _reconcile_empty_read(self, args: list[str],
                              session_key: str) -> list[dict] | None:
        """Empty-read reconciliation for the read blind spot (v0.7.2, CHANGE 5).

        A locked/un-bootstrapped profile answers ``bw list`` with exit 0 + an
        EMPTY payload — error classification never runs and recovery is
        unreachable for reads. When a read returns empty AND the AuthManager
        state is NOT UNLOCKED, the result is SUSPECT, not a genuine empty
        vault: reconcile by running the full ``ensure_authenticated()`` FSM,
        then retry the read EXACTLY ONCE with the confirmed session key. If
        the retry still comes back empty while the state IS UNLOCKED, accept
        it as a genuinely empty vault (return None → caller keeps []).

        Guards:
          * NO extra subprocess when the state is already UNLOCKED (the
            common healthy path pays nothing);
          * only triggered when the caller's key differs from the freshly
            reconciled key (a stale/adopted key) — an in-sync UNLOCKED
            manager never re-spawns;
          * duck-typed managers without ``get_session_key`` /
            ``ensure_authenticated`` skip the defense entirely;
          * reconciliation failures degrade to the original empty result
            (no behavior change on the error path);
          * NEVER logs or surfaces any secret value.
        """
        auth = get_auth_manager()
        if auth is None:
            return None
        try:
            key_valid = auth.get_session_key() is not None
        except Exception:  # noqa: BLE001 - defense-in-depth, degrade silently
            return None
        if key_valid:
            # v0.7.3 (Phase 3, CHANGE 1): SECOND suspect condition. An
            # UNLOCKED session with a valid key is NOT proof of a populated
            # cache: when this process never completed a sync
            # (``last_sync == 0.0``) even ``bw list`` against a healthy
            # session legitimately answers exit 0 + [] because the local
            # snapshot does not exist yet (production first-burst bug,
            # second leg). Force ONE FULL sync (v0.7.4: ``bw sync --force``;
            # the old ``--last`` "delta" verb never synced at all — Phase 1
            # verb selection guarantees the full pull while
            # ``_last_sync == 0.0``) and retry the read exactly once.
            last_sync = getattr(auth, "last_sync", None)
            if last_sync is None:
                return None  # duck-typed manager without sync state
            try:
                suspect = float(last_sync) == 0.0
            except (TypeError, ValueError):
                return None
            if suspect:
                # Re-entrancy guard (see _forced_full_sync_retry): the retry
                # read must NEVER re-trigger the defense — one forced sync
                # + one retry max per original read.
                if getattr(self, "_empty_read_reconciling", False):
                    self._empty_read_reconciling = False
                    return None
                return self._forced_full_sync_retry(args, session_key, auth)

            # v0.7.6 (Phase 1, CHANGE 2): THIRD suspect condition. The cache
            # WAS populated (last_sync > 0.0) and this manager still reports
            # a valid UNLOCKED key — but bw supports exactly ONE session key
            # per profile, so ANOTHER AuthManager (dashboard process + gateway
            # process loading the plugin twice) that unlocked later silently
            # INVALIDATED our key externally. Neither condition 1 (key_valid)
            # nor condition 2 (last_sync > 0.0) can see this, and the empty
            # payload was previously accepted as a "genuinely empty vault"
            # while the real cause was a locked vault answering exit 0 + [].
            # Verify the key itself with ONE extra `bw status` call carrying
            # BW_SESSION — the persistent profile state always reports
            # "locked" by design, only the key answers honestly.
            if getattr(self, "_empty_read_reconciling", False):
                # Re-entrancy guard (same flag as condition 2): a retry read
                # from ANY defense leg must never re-trigger the defense —
                # at most ONE verification + ONE re-unlock + ONE retry per
                # original read. Consume the flag and accept the result.
                self._empty_read_reconciling = False
                return None
            try:
                status = self.verify_session(session_key)
            except Exception:  # noqa: BLE001 - degrade silently
                return None

            if status == "unlocked":
                # Key is valid and the vault reports unlocked, yet the list
                # is empty: genuinely an empty vault (or a server-side issue
                # beyond our control). Accept the empty result.
                return None

            # Session key was externally invalidated (status == "locked" or
            # "unauthenticated" despite our key_valid == True). Demote the
            # local state FIRST: get_session()'s UNLOCKED fast path would
            # otherwise hand back the very same dead key and the recovery
            # could never re-unlock.
            log.warning(
                "Empty read with externally invalidated session key "
                "(bw status=%s); forcing re-unlock", status)
            demote = getattr(auth, "invalidate_session", None)
            if callable(demote):
                try:
                    demote()
                except Exception as exc:  # noqa: BLE001 - best effort
                    log.warning(
                        "Local session invalidation failed (%s); "
                        "attempting re-unlock anyway",
                        compat.get_error_code(exc))

            # Re-unlock via AuthManager to get a fresh session key
            # (routes through the FSM/_do_unlock once the stale key is gone).
            try:
                fresh_key = auth.get_session()
            except Exception as exc:  # noqa: BLE001 - degrade to empty result
                log.warning(
                    "Re-unlock after external invalidation failed (%s); "
                    "returning empty list", compat.get_error_code(exc))
                return None

            if not fresh_key or fresh_key == session_key:
                # Re-unlock didn't produce a new key — nothing left to retry
                return None

            log.info("Session re-established after external invalidation; "
                     "retrying read once")

            # Retry the read with the fresh key. If it comes back empty
            # again, arm the re-entrancy guard so the nested defense pass
            # consumes it and accepts the result — no loop.
            data = self.run(args, env={"BW_SESSION": fresh_key})
            items = self._extract_items(data)
            if not items:
                self._empty_read_reconciling = True
            return items
        # Non-UNLOCKED (or expired) with an empty read => suspect. Reconcile
        # through the full FSM (idempotent fast path when already valid).
        try:
            auth.ensure_authenticated()
            fresh_key = auth.get_session_key()
        except Exception as exc:  # noqa: BLE001 - keep original empty result
            log.warning(
                "Empty read reconciliation failed (%s); accepting empty "
                "result.", compat.get_error_code(exc))
            return None
        if not fresh_key or fresh_key == session_key:
            # Still no usable session after reconciliation, or the caller
            # already used the confirmed key — nothing left to retry.
            return None
        log.info("Suspect empty read in non-UNLOCKED state; retrying once "
                 "after authentication reconciliation.")
        data = self.run(args, env={"BW_SESSION": fresh_key})
        return self._extract_items(data)

    def _forced_full_sync_retry(self, args: list[str], session_key: str,
                                auth) -> list[dict] | None:
        """Forced FULL sync + single read retry for an unpopulated cache.

        v0.7.3 (Phase 3, CHANGE 1/2): second leg of the first-burst empty
        vault defense. The empty read came from a VALID UNLOCKED session but
        ``auth.last_sync == 0.0`` — this process never completed a sync, so
        the local snapshot may not exist and exit 0 + [] is NOT proof of a
        genuinely empty vault.

        Guarantees:
          * ONE full sync only: routed through ``AuthManager.sync(force=True)``
            which, after the v0.7.4 verb correction, issues
            ``bw sync --force`` while ``_last_sync == 0.0`` (never the
            no-op ``--last`` date query). Duck-typed managers without
            ``sync()`` fall back to ``BwCli.sync(full=True)``, which also
            produces ``bw sync --force``.
          * ONE read retry max — if the retry still returns [], the result is
            accepted as genuinely empty (no loop; a successful sync moves
            ``last_sync`` > 0.0 so later reads short-circuit).
          * Log lines carry ONLY sanitized error codes / item counts — never
            secret values or raw exception text.
        """
        log.warning("Empty read detected with unpopulated cache "
                    "(last_sync=0.0)")
        log.info("Triggering forced full sync (prior sync never completed)")
        try:
            mgr_sync = getattr(auth, "sync", None)
            if callable(mgr_sync):
                # AuthManager.sync(force=True) skips the freshness gate and
                # picks the FULL verb because last_sync is still 0.0 (Phase 1).
                result = mgr_sync(force=True)
            else:
                result = self.sync(session_key, full=True)
        except Exception as exc:  # noqa: BLE001 - degrade to the empty result
            code = compat.get_error_code(exc)
            log.warning("Forced full sync failed (%s); returning empty list",
                        code)
            return None
        # Item-count source: AuthManager.sync() returns the bounded count in
        # its dict result ("item_count", Phase 3 hand-off); prefer that, fall
        # back to the last_sync_result property, then parse the raw payload.
        # Duck-typed managers expose neither — the count is simply omitted.
        count = None
        if isinstance(result, dict):
            c = result.get("item_count")
            if isinstance(c, int) and not isinstance(c, bool):
                count = c
        if count is None:
            count = self._extract_item_count(getattr(auth, "last_sync_result",
                                                     None))
        if count is None:
            count = self._extract_item_count(result)
        if count is None:
            log.info("Forced full sync completed")
        else:
            log.info("Forced full sync completed (%d items)", count)
        data = self.run(args, env={"BW_SESSION": session_key})
        items = self._extract_items(data)
        # v0.7.3 Phase 3 RE-ENTRANCY GUARD: the retry read runs with a real
        # UNLOCKED session key; if it comes back empty while the manager's
        # last_sync is still 0.0 (e.g. a duck-typed manager that does not
        # advance sync state, or a sync that pulled nothing), re-entering the
        # second suspect leg would force ANOTHER sync + retry — an infinite
        # loop. The defense is limited to ONE forced sync + ONE retry per
        # original read; a still-empty retry is accepted as genuinely empty.
        if not items:
            self._empty_read_reconciling = True
        log.info("Read retry after forced sync returned %d items",
                 len(items))
        return items

    @staticmethod
    def _extract_item_count(result: object) -> int | None:
        """Best-effort item count from a sync payload (v0.7.3 Phase 3).

        Mirrors ``AuthManager._parse_sync_item_count`` semantics at the CLI
        layer: returns None whenever the value is not parseable so the item
        count is simply OMITTED from the log line. Never raises, never logs;
        only a bounded integer is ever extracted — vault content itself is
        never surfaced.
        """
        if isinstance(result, list):
            return len(result)
        if isinstance(result, dict):
            data = result.get("data")
            if isinstance(data, list):
                return len(data)
        return None

    def item_get(self, session_key: str, query: str) -> dict:
        data = self.run(["get", "item", query], env={"BW_SESSION": session_key})
        if not isinstance(data, dict):
            raise errors.NotFoundError(f"No item matching '{query}'.")
        return data

    def get_password(self, session_key: str, item_id: str) -> str:
        """`bw get password <item_id>` -> decrypted password string.

        v0.3.3: bw get item does NOT return encrypted fields (password
        is null in the output). This dedicated command retrieves the
        decrypted password value.
        """
        data = self.run(["get", "password", item_id],
                        env={"BW_SESSION": session_key}, raw=True)
        if isinstance(data, str):
            return data.strip()
        return str(data).strip()

    def create_item(self, session_key: str, encoded_json: str) -> dict:
        """`bw create item` via stdin -> created item JSON.

        v0.2.7 (BUGFIX): the encoded JSON used to be passed as a CLI
        positional argument; large items could exceed the OS ARG_MAX limit.
        The CLI reads the encoded JSON from stdin when no positional arg
        is given, so we pipe it. Mirrors the stdin-based `encode()` fix
        from v0.2.3. Bypasses the generic run() helper (run() is argv-only).
        """
        full_env = self.base_env({"BW_SESSION": session_key})
        cmd = [self.bw_path, "create", "item"]
        try:
            proc = subprocess.run(
                cmd, env=full_env, input=encoded_json, capture_output=True,
                text=True, timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise errors.NetworkError("bw create item timed out.") from exc
        except OSError as exc:
            raise errors.BinaryError(
                f"Failed to execute bw create: {type(exc).__name__}") from exc

        out = (proc.stdout or "").strip()
        if proc.returncode != 0:
            # v0.7.2 (CHANGE 3): classify through the SAME marker taxonomy as
            # run() — locked-vault stderr now raises SessionError so
            # AuthManager.run_with_recovery can re-unlock synchronously
            # instead of the failure escaping as a generic PLUGIN_ERROR.
            # NB: stderr may contain payload fragments — never logged raw;
            # _write_failure sanitizes it (v0.6.4 behavior preserved).
            raise self._write_failure("create item", proc.returncode,
                                      out, (proc.stderr or "").strip(),
                                      session_key)
        if not out:
            raise errors.ParseError("bw create item returned empty output.")
        try:
            data = json.loads(out)
        except json.JSONDecodeError as exc:
            raise errors.ParseError(
                "Could not parse bw create item output as JSON.") from exc
        if not isinstance(data, dict):
            raise errors.ParseError("bw create item returned unexpected payload.")
        return data

    def edit_item(self, session_key: str, item_id: str, encoded_json: str) -> dict:
        """`bw edit item <id>` via stdin -> updated item JSON.

        v0.2.7 (BUGFIX): same ARG_MAX fix as create_item — pipe the encoded
        JSON via stdin. Also passes the required item id positional argument.
        """
        full_env = self.base_env({"BW_SESSION": session_key})
        cmd = [self.bw_path, "edit", "item", item_id]
        try:
            proc = subprocess.run(
                cmd, env=full_env, input=encoded_json, capture_output=True,
                text=True, timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise errors.NetworkError("bw edit item timed out.") from exc
        except OSError as exc:
            raise errors.BinaryError(
                f"Failed to execute bw edit: {type(exc).__name__}") from exc

        out = (proc.stdout or "").strip()
        if proc.returncode != 0:
            # v0.7.2 (CHANGE 3): same classification as create_item — locked-
            # vault stderr => SessionError for synchronous run_with_recovery;
            # stderr is only ever surfaced sanitized, never raw.
            raise self._write_failure("edit item", proc.returncode,
                                      out, (proc.stderr or "").strip(),
                                      session_key)
        if not out:
            raise errors.ParseError("bw edit item returned empty output.")
        try:
            data = json.loads(out)
        except json.JSONDecodeError as exc:
            raise errors.ParseError(
                "Could not parse bw edit item output as JSON.") from exc
        if not isinstance(data, dict):
            raise errors.ParseError("bw edit item returned unexpected payload.")
        return data

    def delete_item(self, session_key: str, item_id: str, permanent: bool = False) -> str:
        args = ["delete", "item", item_id]
        if permanent:
            args.append("--permanent")
        # v0.4.8 (BUGFIX, Defect 3): a permanent delete can hit not_found
        # when the item is already in the trash and invisible in a stale
        # local cache. On NotFoundError with permanent=True, run a REAL
        # FULL sync and retry the delete exactly once. v0.7.4 (CHANGE 3):
        # the recovery sync EXPLICITLY requests the full verb
        # (``bw sync --force``) — relying on the legacy default mapping is
        # fragile, and the old "plain bw sync" wording predates the fact
        # that only --force guarantees a complete re-download of the vault
        # into the local SQLite cache. The final error message names
        # the item_id — never args[-1] ("--permanent"), which produced the
        # misleading "No matching item for query '--permanent'".
        try:
            return self.run(args, env={"BW_SESSION": session_key}, raw=True,
                          retryable=False)
        except errors.NotFoundError:
            if not permanent:
                raise errors.NotFoundError(
                    f"No item matching id '{item_id}'.")
            log.info("Permanent delete of %s returned not_found; "
                     "syncing vault and retrying once.", item_id)
            self.sync(session_key, full=True)
            try:
                return self.run(args, env={"BW_SESSION": session_key},
                                raw=True, retryable=False)
            except errors.NotFoundError:
                raise errors.NotFoundError(
                    f"No item matching id '{item_id}'.")

    # ---------------------------------------------------------- attachments
    def create_attachment(self, session_key: str, file_path: str,
                          item_id: str) -> dict:
        """`bw create attachment --file <path> --itemid <id>` -> attachment JSON.

        v0.2.8: uploads a file as an attachment to a vault item.
        The file content is read by bw directly from file_path.
        """
        data = self.run(
            ["create", "attachment", "--file", file_path, "--itemid", item_id],
            env={"BW_SESSION": session_key}, retryable=False)
        if not isinstance(data, dict):
            raise errors.ParseError(
                "bw create attachment returned unexpected payload.")
        return data

    def get_attachment(self, session_key: str, filename: str, item_id: str,
                       output_path: str) -> str:
        """`bw get attachment <filename> --itemid <id> --output <path>`.

        v0.2.8: downloads an attachment to output_path. Returns the path.
        Caller is responsible for setting 0600 permissions on output_path.
        """
        self.run(
            ["get", "attachment", filename, "--itemid", item_id,
             "--output", output_path],
            env={"BW_SESSION": session_key}, raw=True)
        return output_path

    def delete_attachment(self, session_key: str, attachment_id: str,
                          item_id: str) -> None:
        """`bw delete attachment <id> --itemid <item_id>`."""
        self.run(
            ["delete", "attachment", attachment_id, "--itemid", item_id],
            env={"BW_SESSION": session_key}, raw=True, retryable=False)

    def generate_password(self, session_key: str, args: list[str]) -> str:
        pw = self.run(["generate", *args], env={"BW_SESSION": session_key}, raw=True)
        if not pw:
            raise errors.ParseError("bw generate returned no password.")
        return pw

    def encode(self, session_key: str, value: str) -> str:
        """`bw encode` via stdin -> base64. Avoids ARG_MAX for large values.

        v0.2.3 (BUGFIX): the value used to be passed as a CLI positional
        argument; SSH keys / certificates / long notes could exceed the OS
        ARG_MAX limit and crash with OSError. The Bitwarden CLI reads from
        stdin when `encode` gets no positional argument, so we pipe it.
        This method intentionally bypasses the generic run() helper because
        run() only supports argv-based invocation; `encode` is the ONLY
        command that needs stdin input.
        """
        full_env = self.base_env({"BW_SESSION": session_key})
        cmd = [self.bw_path, "encode"]
        try:
            proc = subprocess.run(
                cmd, env=full_env, input=value, capture_output=True, text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise errors.NetworkError("bw encode timed out.") from exc
        except OSError as exc:
            raise errors.BinaryError(f"Failed to execute bw encode: {type(exc).__name__}") from exc

        out = (proc.stdout or "").strip()
        if proc.returncode != 0:
            # NB: stderr may contain fragments of the encoded payload — never log it.
            raise errors.ParseError(f"bw encode failed (exit {proc.returncode}).")
        if not out:
            raise errors.ParseError("bw encode returned empty output.")
        return out


def encode_item(item: dict) -> str:
    """Return base64 of the item JSON, ready for `bw create/edit item`.

    v0.2.7 (BUGFIX): the Bitwarden CLI expects the ENTIRE JSON object to be
    base64-encoded (per official docs: "The encode command Base 64 encodes
    stdin" — standard RFC 4648). Previous implementation double-encoded
    individual fields, producing a non-base64 string that `bw create`
    rejected with exit 1. Now we JSON-dump the raw item and base64-encode
    the whole string with Python's stdlib — no subprocess, no bw binary
    dependency for this step, explicit UTF-8 handling.
    """
    cleaned = {k: v for k, v in item.items() if v not in (None, "", [], {})}
    json_bytes = json.dumps(cleaned, ensure_ascii=False).encode("utf-8")
    return base64.b64encode(json_bytes).decode("ascii")

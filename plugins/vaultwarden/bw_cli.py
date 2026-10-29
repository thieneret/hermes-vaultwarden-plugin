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


class BwCli:
    """Stateless command runner; session/auth state lives in AuthManager."""

    def __init__(self, bw_path: str, appdata_dir: str | Path, *,
             timeout: int = 30,
             max_retries: int = 3,
             backoff_base: float = 1.0,
             max_delay: float = 10.0):
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

        # VWP-11 (step 1): fail-fast version check — keep LAST
        self._bw_version = self._check_version()

    @property
    def bw_version(self) -> str:
        """The validated bw CLI version string (VWP-11)."""
        return self._bw_version

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
            proc = subprocess.run(
                [self.bw_path, "--version"],
                env=self.base_env(),
                capture_output=True, text=True, timeout=5,
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

    # ------------------------------------------------------------- run core
    def run(self, args: list[str], *, env: Mapping[str, str] | None = None,
            raw: bool = False, timeout: int | None = None,
            _retry_count: int = 0, retryable: bool = True) -> Any:
        """Execute bw, returning parsed JSON (default) or stripped stdout (raw).

        VWP-09: errors classified by source category via _classify_error().
        VWP-10: network errors on idempotent ops retried with bounded
        exponential backoff + jitter. Non-idempotent callers pass
        retryable=False. Never includes argv/env contents in raised messages.
        """
        full_env = self.base_env(env)
        cmd = [self.bw_path, *args]
        try:
            # v0.1.4 (FAIL-5): look up subprocess.run via the module attribute so
            # tests can monkeypatch subprocess.run deterministically.
            proc = subprocess.run(
                cmd, env=full_env, capture_output=True, text=True,
                timeout=timeout or self.timeout,
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
                raise errors.SessionError(
                    f"bw session invalid or vault locked ({args[0]}).")
            if category == "not_found":
                raise errors.NotFoundError(
                    f"No matching item for query '{args[-1]}'.")

            log.debug(
                "bw %s failed rc=%d category=unknown stderr(redacted)=%.200s",
                args[0], proc.returncode, err,
            )
            raise errors.VaultwardenError(
                f"bw {args[0]} failed (exit {proc.returncode}).",
                suggestion="Run 'vaultwarden_status' for details.")

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
        """Returns the raw session key (kept in plugin memory only)."""
        env = {"BW_MP": master_password}
        key = self.run(["unlock", "--passwordenv", "BW_MP", "--raw", "--nointeraction"],
                       env=env, raw=True, retryable=False)
        if not key:
            raise errors.AuthError("bw unlock returned an empty session key.")
        return key

    def lock(self, session_key: str) -> None:
        try:
            self.run(["lock"], env={"BW_SESSION": session_key})
        except errors.VaultwardenError as exc:
            log.warning("bw lock failed (%s); clearing local session anyway.", exc.code)

    def sync(self, session_key: str, force: bool = False) -> Any:
        args = ["sync"] + (["--last"] if force else [])
        return self.run(args, env={"BW_SESSION": session_key}, raw=force)

    def list_items(self, session_key: str, filters: list[str] | None = None) -> list[dict]:
        args = ["list", "items", "--pretty"]
        if filters:
            args += filters
        data = self.run(args, env={"BW_SESSION": session_key})
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "data" in data:
            return data["data"]
        return []

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
            # NB: stderr may contain payload fragments — never log it.
            raise errors.VaultwardenError(
                f"bw create item failed (exit {proc.returncode}).",
                suggestion="Run 'vaultwarden_status' for details.")
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
            raise errors.VaultwardenError(
                f"bw edit item failed (exit {proc.returncode}).",
                suggestion="Run 'vaultwarden_status' for details.")
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
        # `bw sync` (NOT sync(force=True), which maps to `bw sync --last`)
        # and retry the delete exactly once. The final error message names
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
            self.sync(session_key)
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

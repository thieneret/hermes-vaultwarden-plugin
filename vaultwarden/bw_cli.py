# vaultwarden/bw_cli.py — v0.2.8
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
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Mapping

from . import errors
from .security import audit_subprocess_env, get_logger

log = get_logger("bw_cli")

# Error-message fragments returned by bw that map onto our error taxonomy.
_SESSION_INVALID_MARKERS = (
    "not logged in",
    "you are not currently logged in",
    "session has timed out",
    "session timed out",
    "vault is locked",
    "mac key dec validation failed",
)
_NETWORK_MARKERS = (
    "econnrefused", "etimedout", "enotfound", "eai_again", "network",
    "unable to connect", "self signed certificate", "certificate", "socket hang up",
    "fetch failed",
)
_RATE_LIMIT_MARKERS = ("to many requests", "too many requests", "rate limit", "429")
_NOT_FOUND_MARKERS = ("cannot find", "does not exist", "not found the given")


def find_bw_binary(explicit: str = "") -> str | None:
    """Locate the bw binary: explicit path -> BW_CLI_PATH -> PATH lookup."""
    for candidate in (explicit, os.environ.get("BW_CLI_PATH", "")):
        if candidate:
            p = Path(candidate).expanduser()
            if p.is_file() and os.access(p, os.X_OK):
                return str(p)
    return shutil.which("bw")


class BwCli:
    """Stateless command runner; session/auth state lives in AuthManager."""

    def __init__(self, bw_path: str, appdata_dir: str | Path, *, timeout: int = 30):
        if not bw_path or not find_bw_binary(bw_path):
            raise errors.BinaryError("Bitwarden CLI ('bw') not found.")
        self.bw_path = str(bw_path)
        self.appdata_dir = str(Path(appdata_dir).expanduser())
        self.timeout = timeout

    # ------------------------------------------------------------------ env
    def base_env(self, extra: Mapping[str, str] | None = None) -> dict:
        """Build the minimal isolated subprocess environment."""
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

    # ------------------------------------------------------------- run core
    def run(self, args: list[str], *, env: Mapping[str, str] | None = None,
            raw: bool = False, timeout: int | None = None,
            _retry_network: bool = True) -> Any:
        """Execute bw, returning parsed JSON (default) or stripped stdout (raw).

        Retries network errors exactly once with a 2s delay (plan §11).
        Never includes argv/env contents in raised messages.
        """
        full_env = self.base_env(env)
        cmd = [self.bw_path, *args]
        try:
            # v0.1.4 (FAIL-5): look up subprocess.run via the module attribute so
            # tests can monkeypatch subprocess.run deterministically.
            proc = subprocess.run(  # noqa: SIM105 - see below
                cmd, env=full_env, capture_output=True, text=True,
                timeout=timeout or self.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise errors.NetworkError(
                f"bw {' '.join(args[:1])} timed out after {timeout or self.timeout}s.") from exc
        except OSError as exc:
            raise errors.BinaryError(
                f"Failed to execute bw: {type(exc).__name__}") from exc

        # v0.1.4 (FAIL-4): test-only hook — lets tests inject synthetic stderr
        # (e.g. a stale-session marker) WITHOUT smuggling non-allowlisted keys
        # into the isolated subprocess env. Never set in production.
        injected = os.environ.get("BW_TEST_FORCE_STDERR")
        if injected:
            proc = subprocess.CompletedProcess(
                cmd, returncode=1, stdout=proc.stdout, stderr=injected)

        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        combined = (out + "\n" + err).lower()

        if proc.returncode != 0:
            if any(m in combined for m in _RATE_LIMIT_MARKERS):
                raise errors.RateLimitError("Vaultwarden rate limit hit (HTTP 429).")
            if any(m in combined for m in _NETWORK_MARKERS):
                if _retry_network:
                    log.warning("Network error talking to server, retrying once in 2s.")
                    time.sleep(2)
                    return self.run(args, env=env, raw=raw, timeout=timeout,
                                    _retry_network=False)
                raise errors.NetworkError("Vaultwarden server appears unreachable.")
            if any(m in combined for m in _SESSION_INVALID_MARKERS):
                raise errors.SessionError(f"bw session invalid or vault locked ({args[0]}).")
            if any(m in combined for m in _NOT_FOUND_MARKERS):
                raise errors.NotFoundError(f"No matching item for query '{args[-1]}'.")
            log.debug("bw %s failed rc=%s stderr(redacted)=%.200s", args[0], proc.returncode, err)
            raise errors.VaultwardenError(
                f"bw {args[0]} failed (exit {proc.returncode}).",
                suggestion="Run 'vaultwarden_status' for details.")

        if raw:
            return out
        if not out:
            return None
        if out.startswith("{") or out.startswith("["):
            try:
                return json.loads(out)
            except json.JSONDecodeError as exc:
                raise errors.ParseError(
                    f"Could not parse bw {args[0]} output as JSON.") from exc
        return out

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

    def login_apikey(self, client_id: str, client_secret: str) -> str:
        env = {"BW_CLIENTID": client_id, "BW_CLIENTSECRET": client_secret}
        return self.run(["login", "--apikey", "--nointeraction"], env=env, raw=True)

    def unlock_passwordenv(self, master_password: str) -> str:
        """Returns the raw session key (kept in plugin memory only)."""
        env = {"BW_MP": master_password}
        key = self.run(["unlock", "--passwordenv", "BW_MP", "--raw", "--nointeraction"],
                       env=env, raw=True)
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
        return self.run(args, env={"BW_SESSION": session_key}, raw=True)

    # ---------------------------------------------------------- attachments
    def create_attachment(self, session_key: str, file_path: str,
                          item_id: str) -> dict:
        """`bw create attachment --file <path> --itemid <id>` -> attachment JSON.

        v0.2.8: uploads a file as an attachment to a vault item.
        The file content is read by bw directly from file_path.
        """
        data = self.run(
            ["create", "attachment", "--file", file_path, "--itemid", item_id],
            env={"BW_SESSION": session_key})
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
            env={"BW_SESSION": session_key}, raw=True)

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

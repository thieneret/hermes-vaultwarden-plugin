"""Shared filesystem-hardening validators (v0.6.2, AUD-03 / AUD-04 / AUD-08).

Three security-sensitive paths must be validated FAIL-CLOSED before the
plugin trusts them:

1. the secret-injection directory holding runtime placeholder temp files
   (``$XDG_RUNTIME_DIR/vw-secrets`` — AUD-03),
2. the Bitwarden appdata directory (``.bw-data``, exported to bw as
   ``BITWARDENCLI_APPDATA_DIR`` — AUD-04),
3. the bootstrap secret file (``secrets.yaml`` — AUD-08).

This module provides ONE hardened implementation shared by all three call
sites so the rules cannot drift apart:

* :func:`ensure_hardened_directory` — directories: absolute, real
  (non-symlink) directory, owned by the current effective UID, mode EXACTLY
  ``0700``.
* :func:`ensure_hardened_secret_file` — secret files: absolute, regular
  (non-symlink) file, owned by the current effective UID, NO group/other
  access (``mode & 0o077 == 0``, i.e. typically ``0600``).
* :func:`read_hardened_secret_file` — HVA-03: tool-provided secret input
  files (``password_file`` / ``pass_file``): open + validate + read in ONE
  fd-scoped operation (``O_NOFOLLOW`` open, ``fstat`` on the descriptor,
  exact ``0600``), closing the TOCTOU / symlink-substitution window that a
  path-check-then-open sequence leaves open.

Design rules (fail-closed, defense in depth):

* every check uses ``os.lstat()`` — never ``os.stat()`` — so a symlink is
  inspected AS a symlink and never silently followed;
* insecure permissions are NEVER silently repaired — the operator must fix
  them explicitly (a silent chmod would mask an attack or misconfiguration);
* any violation raises :class:`FilesystemSecurityError`. Callers MUST NOT
  catch and ignore it: plugin activation aborts / ``bw`` is not invoked /
  secrets are not parsed.
* error messages may include PATHS but NEVER secret values, file contents,
  or environment variables.
"""
from __future__ import annotations

import errno
import os
import stat
from pathlib import Path


class FilesystemSecurityError(Exception):
    """Raised when a security-sensitive path fails hardening validation.

    Fail-closed contract: consumers must treat this as fatal for the current
    operation — the plugin does not load, ``bw`` is not executed, or
    bootstrap secrets are not parsed. It must NEVER be downgraded to a
    warning or swallowed.
    """


#: Owner-only directory mode enforced by ensure_hardened_directory().
DIRECTORY_MODE = 0o700


def _require_absolute(path: Path, kind: str) -> None:
    if not str(path) or not os.path.isabs(str(path)):
        raise FilesystemSecurityError(
            f"{kind} path must be absolute: {str(path)!r}")


def _check_ownership(st: os.stat_result, path: Path, kind: str) -> None:
    """Ownership gate — fail closed unless the CURRENT EFFECTIVE UID owns it.

    Root-owned paths are NOT trusted either: a root-owned 0700 directory is
    unwritable by the plugin and an attacker that swapped an operator path
    for a root-owned decoy must not pass validation silently. Operators fix
    ownership explicitly via ``chown`` (see README remediation commands).
    """
    euid = os.geteuid()
    if st.st_uid != euid:
        raise FilesystemSecurityError(
            f"{kind} {path} is owned by uid {st.st_uid}, not the current "
            f"effective uid {euid}; refusing to use it. Fix it explicitly "
            f'with: chown "$USER":"$USER" {path}')


# ── directories (AUD-03 secrets dir, AUD-04 .bw-data) ───────────────────────

def ensure_hardened_directory(
    path: Path,
    *,
    create_if_missing: bool = True,
) -> Path:
    """Validate (and optionally create) a hardened 0700 private directory.

    Rules (all fail-closed with :class:`FilesystemSecurityError`):

    * the path must be ABSOLUTE;
    * it must be a real DIRECTORY — not a file and not a symlink
      (checked via ``os.lstat()``, which never follows symlinks);
    * it must be owned by the CURRENT EFFECTIVE UID;
    * its mode must be EXACTLY ``0700`` (no group or other access).

    Missing-directory behaviour:

    * ``create_if_missing=True``: the directory is created with mode 0700
      (the process umask is temporarily forced to ``0o077`` so the mode is
      exact even under a restrictive umask) and then re-validated through
      the SAME checks — creation is only trusted after validation.
    * ``create_if_missing=False``: raises :class:`FilesystemSecurityError`.

    Insecure existing paths are NEVER silently repaired (no implicit chmod) —
    the operator must fix ownership/permissions explicitly.

    Returns the validated path on success.
    """
    p = Path(path)
    _require_absolute(p, "Directory")

    try:
        st = os.lstat(str(p))
    except FileNotFoundError:
        if not create_if_missing:
            raise FilesystemSecurityError(
                f"Directory does not exist and creation is disabled: {p}") \
                from None
        prev_umask = os.umask(0o077)
        try:
            try:
                os.mkdir(str(p), mode=0o700)
            except FileExistsError:
                # Lost a creation race — fall through and validate whatever
                # exists (symlink / wrong owner / wrong mode all fail closed).
                pass
            except FileNotFoundError:
                # A PARENT directory is missing — mkdir cannot create the
                # whole chain. Create ancestors owner-only, then retry the
                # leaf once; every created level is still re-validated by
                # the checks below (fail-closed, no silent repair).
                try:
                    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                except OSError as exc:
                    raise FilesystemSecurityError(
                        f"Cannot create hardened directory {p}: "
                        f"{type(exc).__name__}") from exc
                try:
                    os.mkdir(str(p), mode=0o700)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise FilesystemSecurityError(
                        f"Cannot create hardened directory {p}: "
                        f"{type(exc).__name__}") from exc
            except OSError as exc:
                raise FilesystemSecurityError(
                    f"Cannot create hardened directory {p}: "
                    f"{type(exc).__name__}") from exc
        finally:
            os.umask(prev_umask)
        st = os.lstat(str(p))

    if stat.S_ISLNK(st.st_mode):
        raise FilesystemSecurityError(
            f"Directory {p} is a symlink; symlinks are rejected (it could "
            "redirect secret material to an attacker-controlled location)")
    if not stat.S_ISDIR(st.st_mode):
        raise FilesystemSecurityError(
            f"{p} is not a directory")

    _check_ownership(st, p, "Directory")

    mode = stat.S_IMODE(st.st_mode)
    if mode != 0o700:
        raise FilesystemSecurityError(
            f"Insecure permissions on directory {p}: {oct(mode)} "
            "(expected exactly 0700). Fix it explicitly — the plugin never "
            f"repairs permissions silently. Run: chmod 700 {p}")

    return p


# ── secret files (AUD-08 secrets.yaml) ──────────────────────────────────────

def ensure_hardened_secret_file(
    path: Path,
    *,
    allow_missing: bool = False,
) -> Path:
    """Validate a hardened owner-only secret file BEFORE it is ever read.

    Rules (all fail-closed with :class:`FilesystemSecurityError`):

    * the path must be ABSOLUTE;
    * it must be a REGULAR file — not a directory and not a symlink
      (checked via ``os.lstat()``, which never follows symlinks);
    * it must be owned by the CURRENT EFFECTIVE UID;
    * it must have NO group or other access bits (``mode & 0o077 == 0``;
      the canonical mode is ``0600``).

    Missing-file behaviour:

    * ``allow_missing=True``: returns the path without raising (the caller
      decides what a missing file means — e.g. first-run bootstrap).
    * ``allow_missing=False``: raises :class:`FilesystemSecurityError`.

    This validator performs NO read of the file — an existing but insecure
    file is rejected BEFORE any parsing can happen. Error messages contain
    paths and modes only, NEVER file contents or secret values.

    Returns the validated path on success.
    """
    p = Path(path)
    _require_absolute(p, "Secret file")

    try:
        st = os.lstat(str(p))
    except FileNotFoundError:
        if allow_missing:
            return p
        raise FilesystemSecurityError(
            f"Secret file does not exist: {p}") from None
    except OSError as exc:
        raise FilesystemSecurityError(
            f"Cannot lstat secret file {p}: {type(exc).__name__}") from exc

    if stat.S_ISLNK(st.st_mode):
        raise FilesystemSecurityError(
            f"Secret file {p} is a symlink; symlinks are rejected (the "
            "target could be read/tampered with by other users)")
    if not stat.S_ISREG(st.st_mode):
        raise FilesystemSecurityError(
            f"Secret file {p} is not a regular file")

    _check_ownership(st, p, "Secret file")

    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise FilesystemSecurityError(
            f"Insecure permissions on secret file {p}: {oct(mode)} grants "
            "group/other access (expected 0600). Fix it explicitly — the "
            f"plugin never repairs permissions silently. Run: chmod 600 {p}")

    return p


# ── fd-scoped secret INPUT reads (HVA-03, v0.7.8 hardening) ─────────────────

def read_hardened_secret_file(path: Path | str) -> bytes:
    """Open, validate and read a tool-provided secret input file in ONE
    fd-scoped operation — eliminating the TOCTOU / symlink window.

    HVA-03 (v0.6.9 audit, Low): ``password_file`` / ``pass_file`` used to
    be validated on the PATH (``lstat``/``stat``) and only then opened —
    between the two steps an attacker able to manipulate the filesystem
    could swap the path or substitute a symlink. This helper collapses
    open+validate+read onto the OPENED FILE DESCRIPTOR:

    * ``os.open(O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)`` — a
      symlinked path fails at open (``ELOOP``) and is NEVER followed;
      ``O_NONBLOCK`` prevents a hang on FIFOs (which are then rejected by
      the regular-file check);
    * validated via ``os.fstat(fd)`` — NOT the path: must be a REGULAR
      file, owned by the CURRENT EFFECTIVE UID, mode EXACTLY ``0600``
      (owner read+write only, no group/other, no extra owner bits);
    * the secret bytes are read from the SAME descriptor; the fd is closed
      in a ``finally`` block on every path;
    * every violation raises :class:`FilesystemSecurityError` (fail-closed
      — no fallback, no silent repair); error text contains PATH, MODE and
      error code only, NEVER file contents.

    Returns the raw bytes on success. Decoding/stripping/emptiness are the
    caller's concern (they are not security-relevant for this gate).
    """
    p = Path(path)
    _require_absolute(p, "Secret input file")

    def _validate_fd_st(st: os.stat_result) -> None:
        """Apply the fd-scoped gate to an fstat() result (fail-closed)."""
        if not stat.S_ISREG(st.st_mode):
            # O_NOFOLLOW only guards the LAST path component; parent-dir
            # trickery or a race swap after open can still land on a
            # non-regular object — reject it based on the fd, not the path.
            raise FilesystemSecurityError(
                f"Secret input file {p} is not a regular file")
        _check_ownership(st, p, "Secret input file")
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o077:
            raise FilesystemSecurityError(
                f"Secret input file {p} must be readable only by the owner "
                f"(chmod 600); current mode is {oct(mode)} — the plugin "
                "never repairs permissions silently. Run: "
                f"chmod 600 {p}")
        if not (mode & 0o400):
            raise FilesystemSecurityError(
                f"Secret input file {p} is not readable by the owner "
                f"(mode {oct(mode)}). Run: chmod 600 {p}")
        if mode != 0o600:
            # Fail-closed on anything that is not EXACTLY 0600 (e.g.
            # 0500, 0700): stricter than the legacy mode-only check.
            raise FilesystemSecurityError(
                f"Unexpected mode on secret input file {p}: {oct(mode)} "
                "(expected exactly 0600). Fix it explicitly — the plugin "
                f"never repairs permissions silently. Run: chmod 600 {p}")

    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = os.open(str(p), flags)
    except FileNotFoundError:
        raise FilesystemSecurityError(
            f"Secret input file does not exist: {p}") from None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise FilesystemSecurityError(
                f"Secret input file {p} is a symlink; symlinks are "
                "rejected (the target could be read/tampered with by "
                "other users)") from exc
        if exc.errno == errno.EACCES:
            # DIAGNOSTIC ONLY (never part of the security gate): the file
            # could NOT be opened, so no secret material was ever read.
            # An lstat() lets us report the precise reason (wrong owner /
            # unreadable mode) instead of a bare PermissionError. The
            # result cannot cause a false accept — acceptance requires a
            # successful os.open() plus fstat() on the real descriptor.
            try:
                _validate_fd_st(os.lstat(str(p)))
            except FilesystemSecurityError:
                raise
            except OSError:
                pass
        raise FilesystemSecurityError(
            f"Cannot open secret input file {p}: "
            f"{type(exc).__name__}") from exc

    try:
        _validate_fd_st(os.fstat(fd))
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)

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

"""Tool handlers for the 12 vaultwarden_* tools (plan §8).

``get_tools(auth, config, registry)`` yields (schema, handler) pairs.
v0.2.4: Handlers return JSON strings (Hermes tool_call requires str);
on failure they return the standard error envelope serialized to JSON:
{"error", "error_code", "recoverable", "suggestion"}.

Hard rule (VWP-12 / VWP-14, v0.3.7): no handler EVER returns a raw
secret value. Generated passwords (via ``generate=true`` on store /
update) go directly into the vault item; only a placeholder is
returned. ``vaultwarden_get_secret_ref`` always returns only a
placeholder — the direct-retrieval escape hatch was removed.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable

from . import errors, schemas
from .auth import AuthManager
from .config import PluginConfig
from .placeholders import PlaceholderRegistry
from .security import get_logger, get_redacting_filter

log = get_logger("tools")

Handler = Callable[..., str]


#: AUD-02 (v0.6.5): handler-invocation depth counter (thread-local).
#: While a tool handler runs inside :func:`_guard` its OWN execution scope
#: is authoritative; a non-zero depth means "a scope found in the ContextVar
#: belongs to some OTHER (older) execution" and must never capture this
#: handler's runtime secrets (that would strand them until the other
#: execution's deferred release -- or forever, if that release never runs).
_HANDLER_DEPTH = threading.local()


def _current_execution_scope():
    """Active execution scope via lazy import (AUD-02).

    ``hooks`` imports ``tools`` at module level, so a top-level
    ``from .hooks import ...`` here would be a circular import. The scope
    lookup is only needed while handlers run, i.e. after both modules are
    fully initialized. Returns None when no scope is active.

    Robustness rules:
      - an already-CLOSED scope must never capture new secrets -- a stale
        ContextVar reference (e.g. a handler invoked later on the same
        thread) would otherwise hand values to a scope whose release already
        ran, leaking them in the redactor forever;
      - while a handler is executing (depth > 0), only a scope opened by the
        placeholder middleware for THIS handler invocation counts. The
        middleware opens its scope around ``next_call`` (which dispatches
        the tool handler), so it is exactly what we want to find; any other
        leftover ContextVar value belongs to an unrelated older execution
        and is ignored, keeping the scope lifetime strictly bounded by the
        execution that created it.
    """
    from .hooks import current_execution_scope
    scope = current_execution_scope()
    if scope is None or getattr(scope, "closed", False):
        return None
    if getattr(_HANDLER_DEPTH, "value", 0) <= 0:
        # Direct/legacy call outside any handler frame: the middleware
        # scope still legitimately owns this execution's plaintexts.
        return scope
    # Inside a handler: accept ONLY a live placeholder-middleware scope.
    # (The middleware sets the ContextVar right before next_call -> the
    # host dispatches the handler synchronously on this thread.)
    return scope


# ---------------------------------------------------------------------------
# AUD-02 (v0.6.5): scoped retention helpers for RUNTIME tool-handler secrets
# ---------------------------------------------------------------------------
# Generated passwords, resolved password channels and SSH passphrases are
# runtime secrets: they must be redactable while the handler executes but
# must NEVER accumulate unboundedly in the global RedactingFilter afterwards.
#
# - retain_runtime_secret(): if an execution scope is active (placeholder
#   middleware path), the plaintext is retained THROUGH the scope so the
#   deferred release at the safe final lifecycle point drops exactly one
#   execution reference per value; otherwise it falls back to a scoped
#   retain paired with the explicit release performed by the handler's
#   finally block (legacy / direct-call paths). The old
#   ``register_secret`` + ``forget_secret`` pair is not used here anymore:
#   forget() would drop ALL retention layers, which could strip a baseline
#   another owner (e.g. startup injection or bootstrap auth) still needs,
#   while plain register() would leak the value globally when the paired
#   forget is skipped on an abnormal path.
# - release_runtime_secret(): symmetric release; goes through the scope when
#   this handler runs inside one (closing the scope releases it later --
#   double release is impossible because close() is release-once), else the
#   handler's own finally performs the decrement.
#: AUD-02 (v0.6.5): per-handler bookkeeping of values that were retained in
#: FALLBACK mode (no active execution scope -- legacy/direct-call paths and
#: tests invoking handlers without the middleware). The handler's finally
#: block releases exactly these references, so nothing accumulates globally.
#: Keyed by execution id (ContextVar task identity); thread-safe.
_FALLBACK_RETAINED: dict[str, list[str]] = {}
_FALLBACK_LOCK = threading.Lock()


def _fallback_key() -> str:
    """Stable per-execution key for fallback retention bookkeeping.

    Handlers run synchronously on one thread from retain to the paired
    release / _guard finally, so the worker-thread identity is a safe
    per-execution bucket; concurrent executions live on different threads.
    """
    return f"t{threading.get_ident()}"


def retain_runtime_secret(value: str) -> None:
    """Retain a runtime tool-secret for redaction (scoped, ref-counted)."""
    if not value:
        return
    scope = _current_execution_scope()
    if scope is not None:
        scope.retain(value)
    else:
        redactor = get_redacting_filter()
        redactor.retain_secret(value)
        # Fallback path: remember it so THIS handler's finally releases the
        # reference even when no execution scope owns the lifecycle.
        with _FALLBACK_LOCK:
            _FALLBACK_RETAINED.setdefault(_fallback_key(), []).append(value)


def release_runtime_secret(value: str) -> None:
    """Release a runtime tool-secret retained via :func:`retain_runtime_secret`.

    When the handler ran inside an execution scope, releasing is left to the
    scope's single, release-once ``close()`` -- releasing here too would
    double-decrement the shared refcount. Otherwise this is the handler's
    own finally-block decrement of a FALLBACK retention recorded at retain
    time (unknown values are ignored by the redactor with a sanitized
    warning, so a mismatched release can never corrupt another owner's
    count or go negative). Never logs the value.
    """
    if not value:
        return
    scope = _current_execution_scope()
    if scope is not None:
        return  # the scope owns the release; close() is release-once
    with _FALLBACK_LOCK:
        pending = _FALLBACK_RETAINED.get(_fallback_key()) or []
        if value in pending:
            pending.remove(value)
    get_redacting_filter().release_secret(value)


def release_all_fallback_retained() -> None:
    """Fail-safe sweep: release every fallback retention for this execution.

    Handlers call this in their outermost finally so secrets retained on
    early-exit paths (validation errors raised BEFORE an inner try/finally
    was established) are still released. Values retained through an active
    execution scope are NOT touched here -- the scope's release-once
    ``close()`` owns those references.
    """
    key = _fallback_key()
    with _FALLBACK_LOCK:
        pending = _FALLBACK_RETAINED.pop(key, [])
    redactor = get_redacting_filter()
    for v in pending:
        redactor.release_secret(v)


# --------------------------------------------------------------- helpers
def _remove_quietly(path: str, label: str) -> None:
    """Delete *path*, never raising; log a sanitized WARNING on failure.

    v0.5.8 cleanup observability: leftover secret material must be visible
    to operators instead of failing silently. The path itself is safe to
    log (generated temp name); file CONTENTS are NEVER read or logged.
    ENOENT means the file is already gone — nothing leaked, so it stays
    quiet.
    """
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        log.warning("Failed to remove %s %s: %s", label, path, exc)


def _rmtree_quietly(dir_path: str) -> None:
    """Remove keypair temp dir *dir_path*; warn (sanitized) on failure.

    v0.5.8: replaces the silent ``shutil.rmtree(..., ignore_errors=True)``
    pattern — a failed removal leaves the generated PRIVATE KEY on disk,
    which operators must see in the logs (path + error only).
    """
    try:
        shutil.rmtree(dir_path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        log.warning("Failed to remove temp key directory %s: %s",
                    dir_path, exc)


def _ssh_base_env(extra: dict | None = None) -> dict:
    """Minimal, isolated environment for SSH subprocess calls.

    Mirrors BwCli.base_env(): only explicitly allowlisted keys are
    passed through. The parent environment is NEVER inherited.

    VWP-08 (v0.3.7): prevents leakage of sensitive host variables and
    PATH manipulation via the inherited environment.
    """
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", str(Path.home())),
        "LC_ALL": "C",
    }
    if extra:
        env.update({k: v for k, v in extra.items() if v})
    return env


_ASKPASS_SCRIPT_BODY = '#!/bin/sh\necho "$VW_SSH_PASS"\n'
_ASKPASS_ENV_VAR = "VW_SSH_PASS"


def _make_askpass_script() -> str:
    """Create the SSH_ASKPASS helper script and return its path.

    The script body contains NO secret material — it only echoes the
    VW_SSH_PASS environment variable, which the caller sets on the
    subprocess. Created via mkstemp (atomic, owner-only) and chmod 0700
    so ssh-keygen/ssh-add will execute it.

    Caller is responsible for os.unlink() in a finally block.
    """
    fd, path = tempfile.mkstemp(suffix=".sh", prefix="vw_askpass_")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(_ASKPASS_SCRIPT_BODY)
        os.chmod(path, 0o700)
    except BaseException:
        # never leave a half-written helper behind
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path


def _askpass_env(passphrase: str, extra: dict | None = None) -> dict:
    """Build the isolated subprocess env for askpass-based passphrase delivery.

    Forces the SSH_ASKPASS channel (supported: OpenSSH >= 8.4; verified
    10.0p2) so neither ssh-add nor ssh-keygen can fall back to /dev/tty.
    The passphrase travels as an environment variable ONLY.

    Returns the env dict; the caller must read ``env["SSH_ASKPASS"]`` and
    unlink the helper script in a ``finally`` block.
    """
    env = {
        "SSH_ASKPASS_REQUIRE": "force",
        "SSH_ASKPASS": _make_askpass_script(),
        _ASKPASS_ENV_VAR: passphrase,
    }
    if extra:
        env.update({k: v for k, v in extra.items() if v})
    return _ssh_base_env(env)


def _generate_password(auth: AuthManager, options: dict) -> str:
    """Generate a password/passphrase via `bw generate`.

    Returns the raw generated string. Caller is responsible for
    registering it with RedactingFilter and never returning it
    to the LLM.

    bw generate takes NO positional arguments: --length and --words are
    flags, and there is no -w short alias (verified against the real CLI:
    `bw generate 20 …` fails with "too many arguments"). Build the arg
    list accordingly.
    """
    mode = options.get("mode") or "password"
    if mode == "passphrase":
        words = int(options.get("words") or 4)
        sep = str(options.get("separator") or "-")
        bw_args = ["--passphrase", "--words", str(words), "--separator", sep]
    else:
        length = int(options.get("length") or 20)
        bw_args = ["--length", str(length)]
        if options.get("uppercase", True):
            bw_args.append("--uppercase")
        if options.get("lowercase", True):
            bw_args.append("--lowercase")
        if options.get("numbers", True):
            bw_args.append("--number")
        if options.get("special", True):
            bw_args.append("--special")
    return auth.generate_password(bw_args)


# ----------------------------------------------------- secret input channels
#: v0.4.0 (Feature 1): advisory returned in the tool response when a raw
#: secret was passed directly in the tool call. NEVER interpolates the
#: secret value itself — only parameter names.
_DIRECT_SECRET_WARNING = (
    "AGENT INSTRUCTION: A raw secret was supplied directly via {key!r} in "
    "{tool}. This value has entered your context window and the chat history, "
    "which is NOT secure. You MUST warn the user about this now: tell them "
    "direct secret input is insecure, and recommend providing it via "
    "{file_key!r} (an owner-only file, chmod 600) instead. Do NOT repeat "
    "the secret value in your reply."
)


def _reject_removed_env_channel(args: dict, env_key: str, file_key: str,
                                tool_name: str) -> None:
    """Explicitly reject the removed *_env secret-input channel (v0.4.9).

    BREAKING CHANGE (v0.4.9): the password_env / pass_env channels were
    removed — in multiplex gateway mode Hermes loads .env only at startup,
    so a secret added to .env requires a full Hermes restart before the
    plugin can resolve it. Callers that still supply the parameter get a
    clear ConfigError (never silently ignored). Called at the start of each
    handler body, BEFORE the generate branch, so the rejection fires in
    both generate and non-generate modes.
    """
    if args.get(env_key):
        raise errors.ConfigError(
            f"{tool_name}: {env_key!r} was removed in v0.4.9 — "
            "environment secrets require a Hermes restart to load.",
            suggestion=f"Use {file_key!r} (owner-only file, chmod 600) "
                       "or generate=true instead.")


def _resolve_secret_input(
    args: dict, *, direct_key: str, file_key: str, tool_name: str,
) -> tuple[str | None, str | None]:
    """Resolve a secret from exactly one of: direct value or file.

    v0.4.0 (Feature 1): returns (value, warning). `warning` is a non-secret
    advisory string when a raw secret was passed directly (also emitted to
    the log), else None. Raises ConfigError on conflict (multiple sources)
    or an unusable file source. Raises NotFoundError when a *_file path
    does not exist. The file channel is strict: regular file, owner-readable
    (mode & 0o400), no group/other access (mode & 0o077 == 0) — otherwise
    the file is NOT read and ConfigError is raised.

    v0.4.9 (BREAKING CHANGE): the *_env channel (and with it the `env_key`
    and `config` parameters) was REMOVED from this resolver; handlers
    reject the removed parameters up front via _reject_removed_env_channel.
    """
    provided = [k for k in (direct_key, file_key) if args.get(k)]
    if len(provided) > 1:
        raise errors.ConfigError(
            f"{tool_name}: provide only ONE of {direct_key!r}, "
            f"{file_key!r}; got {provided}",
            suggestion="Choose a single secret source.",
        )
    if args.get(direct_key):
        warning = _DIRECT_SECRET_WARNING.format(
            key=direct_key, tool=tool_name, file_key=file_key,
        )
        log.warning(
            "%s: raw secret passed directly via %r; prefer %r",
            tool_name, direct_key, file_key,
        )
        return str(args[direct_key]), warning
    if args.get(file_key):
        path = str(args[file_key])
        if not os.path.isfile(path):
            raise errors.NotFoundError(
                f"{tool_name}: {file_key} not found: {path}",
                suggestion="Provide an absolute path to an existing file.",
            )
        try:
            st = os.stat(path)
        except OSError as exc:
            raise errors.ConfigError(
                f"{tool_name}: cannot stat {file_key} path: {type(exc).__name__}"
            ) from exc
        mode = st.st_mode & 0o777
        if mode & 0o077:
            raise errors.ConfigError(
                f"{tool_name}: {file_key} must be readable only by the owner "
                f"(chmod 600); current mode is {oct(mode)}",
                suggestion="Run: chmod 600 <file>",
            )
        if not (mode & 0o400):
            raise errors.ConfigError(
                f"{tool_name}: {file_key} is not readable by the owner "
                f"(mode {oct(mode)})",
                suggestion="Run: chmod 600 <file>",
            )
        try:
            with open(path, "r", encoding="utf-8") as f:
                val = f.read().strip()
        except OSError as exc:
            raise errors.ConfigError(
                f"{tool_name}: cannot read {file_key}: {type(exc).__name__}"
            ) from exc
        if not val:
            raise errors.ConfigError(f"{tool_name}: {file_key} is empty")
        return val, None
    return None, None


def _generate_ssh_keypair(
    key_type: str, rsa_bits: int, comment: str, passphrase: str,
) -> tuple[str, str, str, str]:
    """Generate an SSH keypair in a temp dir; passphrase via SSH_ASKPASS.

    ssh-keygen reads passphrases through read_passphrase(), which NEVER reads
    stdin — with a tty present it prompts the user on /dev/tty. Delivery is
    therefore via the SSH_ASKPASS helper (script echoes an env var; the secret
    is never in a file or argv) with SSH_ASKPASS_REQUIRE=force, and stdin is
    DEVNULL so a tty fallback or hang is impossible.

    v0.4.2: every subprocess here runs with start_new_session=True, detaching
    the child from any controlling terminal. Without a controlling tty the
    child cannot open /dev/tty, so ssh-keygen can NEVER fall back to an
    interactive passphrase prompt (which hung interactive/dashboard sessions
    until the timeout). This is defense-in-depth on top of askpass delivery.

    Returns (tmpdir, private_key_path, public_key_str, fingerprint).
    Caller owns tmpdir cleanup and RedactingFilter register/forget for
    `passphrase`.

    Safety: after generation, `ssh-keygen -yf` with stdin=DEVNULL must FAIL.
    Success means the key is UNENCRYPTED (the askpass channel yielded an empty
    passphrase) -> abort; never store an unprotected key.
    """
    tmpdir = tempfile.mkdtemp(prefix="vw_sshgen_")
    os.chmod(tmpdir, 0o700)
    key_path = os.path.join(tmpdir, "key")
    env = _askpass_env(passphrase)
    askpass_path = env["SSH_ASKPASS"]
    try:
        cmd = ["ssh-keygen", "-t", key_type, "-f", key_path, "-C", comment]
        if key_type == "rsa":
            cmd += ["-b", str(rsa_bits)]
        proc = subprocess.run(
            cmd, env=env, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=30,
            start_new_session=True,   # detach from controlling tty
        )
        if proc.returncode != 0:
            raise errors.VaultwardenError(
                f"ssh-keygen failed (exit {proc.returncode})",
                suggestion="Check ssh-keygen availability and key_type.",
            )
        # SAFETY VERIFY — see docstring.
        # v0.4.2: start_new_session=True is the critical fix here — without a
        # controlling tty, -yf on an encrypted key fails fast instead of
        # hanging on a /dev/tty passphrase prompt (interactive sessions).
        verify = subprocess.run(
            ["ssh-keygen", "-yf", key_path], env=_ssh_base_env(),
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=10,
            start_new_session=True,   # detach from controlling tty: no
                                      # /dev/tty prompt
        )
        if verify.returncode == 0:
            raise errors.VaultwardenError(
                "ssh-keygen produced an UNENCRYPTED private key (askpass "
                "delivery failed); aborting to avoid storing an unprotected "
                "key.",
                suggestion="Report this; verify SSH_ASKPASS handling.",
            )
        pub_path = key_path + ".pub"
        with open(pub_path, "r", encoding="utf-8") as f:
            public_key = f.read().strip()
        fp_proc = subprocess.run(
            ["ssh-keygen", "-lf", pub_path], env=_ssh_base_env(),
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            timeout=10,
            start_new_session=True,   # detach from controlling tty
        )
        fingerprint = "unknown"
        if fp_proc.returncode == 0 and fp_proc.stdout:
            parts = fp_proc.stdout.strip().split()
            if len(parts) >= 2:
                fingerprint = parts[1]
        return tmpdir, key_path, public_key, fingerprint
    finally:
        # v0.5.8 cleanup observability: sanitized WARNING on failure.
        _remove_quietly(askpass_path, "askpass helper")


def _item_type_name(item: dict) -> str:
    mapping = {1: "login", 2: "note", 3: "card", 4: "identity"}
    t = item.get("type")
    if isinstance(t, int):
        return mapping.get(t, str(t))
    return str(t or "login")


def _metadata(item: dict, mask: bool = False) -> dict:
    """Safe metadata projection — NEVER includes password/totp/notes values.

    VWP-13 (v0.4.3): when mask=True, `username` and `uris` are replaced with
    '***'. `name`, `id`, `type`, `folder_id` are never masked (needed for
    item identification). Masking is applied ONLY in h_list()/h_search().
    """
    login = item.get("login") or {}
    uris = [u.get("uri") for u in (login.get("uris") or []) if u.get("uri")]
    out = {
        "id": item.get("id"),
        "name": item.get("name"),
        "type": _item_type_name(item),
        "username": "***" if mask and login.get("username") else login.get("username"),
        "uris": ["***"] if mask and uris else uris,
        "folder_id": item.get("folderId"),
    }
    return {k: v for k, v in out.items() if v not in (None, [], "")}


def _field_value(item: dict, field_name: str, custom_field_name: str | None) -> str:
    """Extract a raw secret field from an item object (memory only!)."""
    if custom_field_name:
        for cf in item.get("fields") or []:
            if cf.get("name") == custom_field_name:
                return str(cf.get("value") or "")
        raise errors.NotFoundError(f"Custom field '{custom_field_name}' not found on item.")
    login = item.get("login") or {}
    if field_name == "password":
        return str(login.get("password") or "")
    if field_name == "username":
        return str(login.get("username") or "")
    if field_name == "totp":
        return str(login.get("totp") or "")
    if field_name == "uri":
        uris = login.get("uris") or []
        return str(uris[0].get("uri") or "") if uris else ""
    if field_name == "notes":
        return str(item.get("notes") or "")
    raise errors.ConfigError(f"Unsupported field '{field_name}'.")


def _require_write(config: PluginConfig) -> None:
    if not config.allow_write:
        raise errors.PermissionError_(
            "Write operations are disabled for the Vaultwarden plugin.")


# ---------------------------------------------------------------- version
#: SEC-02 companion (v0.5.7): single sanctioned sources of truth for the
#: plugin version are plugin.yaml + pyproject.toml (handoff rule 6 — see
#: tests/test_no_version_coupling.py). There is deliberately NO __version__
#: constant; vaultwarden_status reads the version from plugin.yaml instead.
_PLUGIN_VERSION_RE = re.compile(r"^version:\s*([^\s]+)", re.M)
_PLUGIN_VERSION: str | None = None


def get_plugin_version() -> str:
    """Return the plugin version, read (once, cached) from plugin.yaml.

    The lookup is a plain pathlib read relative to the package directory —
    no third-party YAML dependency. On any failure (file missing, unreadable)
    ``"unknown"`` is returned and cached, so the status tool never raises
    over version introspection.
    """
    global _PLUGIN_VERSION
    if _PLUGIN_VERSION is None:
        try:
            yaml_path = Path(__file__).resolve().parent / "plugin.yaml"
            text = yaml_path.read_text(encoding="utf-8")
            m = _PLUGIN_VERSION_RE.search(text)
            _PLUGIN_VERSION = m.group(1) if m else "unknown"
        except OSError:
            _PLUGIN_VERSION = "unknown"
    return _PLUGIN_VERSION


def _collect_secret_strings(obj: Any) -> list[str]:
    """Recursively extract all non-empty string values from a nested structure.

    v0.2.3 (SECURITY FIX): h_store previously only registered `password` with
    the RedactingFilter and h_update registered nothing at all — secrets in
    username/uri/notes/custom_fields leaked into logs. This helper collects
    EVERY string value so write handlers can redact them all during the
    operation.
    """
    results: list[str] = []
    if isinstance(obj, str) and obj.strip():
        results.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            results.extend(_collect_secret_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            results.extend(_collect_secret_strings(v))
    return results


def _guard(fn: Callable[[], dict]) -> str:
    """Execute handler and return JSON string.

    v0.2.4 (BUGFIX): Hermes Agent tool_call requires handlers to return str.
    Returning dict causes 'unsupported result type: dict' for every tool.
    JSON serialization with default=str handles datetime/Path/enum values safely.

    v0.2.8: ``code=`` passes an explicit error code through the base-class
    constructor (used by the SSH tools: DUPLICATE_NAME / AMBIGUOUS_ERROR /
    AGENT_ERROR / VALIDATION_ERROR) without changing the error taxonomy.
    """
    # AUD-02 (v0.6.5): mark "inside a handler" for the duration of this
    # invocation so scope lookups can distinguish THIS execution's live
    # placeholder-middleware scope from leftovers of unrelated executions.
    _HANDLER_DEPTH.value = getattr(_HANDLER_DEPTH, "value", 0) + 1
    try:
        result = fn()
        return json.dumps(result, ensure_ascii=False, default=str)
    except errors.VaultwardenError as exc:
        log.debug("tool error: %s (%s)", exc.message, exc.code)
        return json.dumps(exc.to_dict(), ensure_ascii=False, default=str)
    except Exception as exc:  # pragma: no cover - defensive
        log.exception("unexpected tool failure")
        return json.dumps(errors.error_response(exc), ensure_ascii=False, default=str)
    finally:
        # AUD-02 (v0.6.5) fail-safe: release every FALLBACK retention this
        # handler recorded (no active execution scope). Covers early-exit
        # paths where an inner finally never got established. Scope-owned
        # references are untouched -- their release-once close() owns them.
        _HANDLER_DEPTH.value = max(getattr(_HANDLER_DEPTH, "value", 0) - 1, 0)
        release_all_fallback_retained()


def _vault_error(message: str, *, code: str,
                 suggestion: str | None = None) -> errors.VaultwardenError:
    """Build a VaultwardenError carrying an explicit taxonomy code (v0.2.8)."""
    exc = errors.VaultwardenError(message or code, suggestion=suggestion)
    exc.code = code
    if suggestion is not None:
        exc.suggestion = suggestion
    return exc


# --------------------------------------------------------------- handlers
def get_tools(auth: AuthManager, config: PluginConfig,
              registry: PlaceholderRegistry) -> list[tuple[dict, Handler]]:
    """Return (schema, handler) pairs for all vaultwarden tools.

    v0.2.8: returns a concrete list of (schema, handler) pairs — the
    SSH key management tools (store/update/delete/use_ssh) are appended at
    the end of the list.
    v0.3.7 (VWP-12): 12 tools — vaultwarden_generate_password was removed;
    password generation is integrated into store/update via generate=true.
    """
    _tools: list[tuple[dict, Handler]] = []

    # ------------------------------------------------------------ status
    def h_status(args: dict, **kw: Any) -> str:
        # v0.5.7 (SEC-02 companion): expose the running plugin version so
        # operators and the LLM can verify the exact build for debugging and
        # audit compliance. Read dynamically from plugin.yaml (single source
        # of truth — see get_plugin_version).
        return _guard(lambda: {"status": auth.status_snapshot(),
                               "plugin_version": get_plugin_version(),
                               "placeholders_active": len(registry.active_tokens())})

    _tools.append((schemas.VAULTWARDEN_STATUS, h_status))

    # ---------------------------------------------------------------- sync
    def h_sync(args: dict, **kw: Any) -> str:
        return _guard(lambda: auth.sync(force=bool(args.get("force"))))

    _tools.append((schemas.VAULTWARDEN_SYNC, h_sync))

    # ---------------------------------------------------------------- list
    def h_list(args: dict, **kw: Any) -> str:
        def run():
            # BUG-3 fix: bw list items supports only --folderid/--collectionid/
            # --search; there is NO --filter-type flag. Type filtering is done
            # client-side on the returned items via _item_type_name().
            filters: list[str] = []
            if args.get("folder_id"):
                filters += ["--folderid", str(args["folder_id"])]
            if args.get("collection_id"):
                filters += ["--collectionid", str(args["collection_id"])]
            items = auth.list_items(filters or None)
            want_type = args.get("type")
            if want_type:
                items = [i for i in items if _item_type_name(i) == want_type]
            limit = int(args.get("limit") or 100)
            # VWP-13: config-driven metadata masking (username/uris -> '***')
            projected = [_metadata(i, mask=config.metadata_masking) for i in items[:limit]]
            return {"items": projected, "total": len(items),
                    "returned": len(projected)}
        return _guard(run)

    _tools.append((schemas.VAULTWARDEN_LIST, h_list))

    # -------------------------------------------------------------- search
    def h_search(args: dict, **kw: Any) -> str:
        def run():
            query = str(args["query"])
            field = args.get("field")
            want_type = args.get("type")
            # BUG-5 fix: bw supports server/cache-side name search via
            # `bw list items --search <query>` — use it when the query targets
            # name/username (the fields bw searches natively). Fall back to a
            # full client-side pass only for uri / explicit type filtering,
            # which bw's --search does not cover.
            native_ok = field in (None, "name", "username") and not want_type
            if native_ok:
                items = auth.list_items(["--search", query])
            else:
                items = auth.list_items(None)
            q = query.lower()
            matches = []
            # VWP-13: config-driven metadata masking (username/uris -> '***').
            mask = config.metadata_masking
            for it in items:
                if want_type and _item_type_name(it) != want_type:
                    continue
                meta = _metadata(it, mask=mask)
                haystacks = []
                if field in (None, "name"):
                    haystacks.append(str(meta.get("name") or "").lower())
                if field in (None, "username"):
                    haystacks.append(str(meta.get("username") or "").lower())
                if field in (None, "uri"):
                    haystacks.extend(u.lower() for u in meta.get("uris", []))
                if any(q in h or fnmatch.fnmatch(h, f"*{q}*") for h in haystacks):
                    matches.append(meta)
            return {"query": query, "matches": matches, "count": len(matches)}
        return _guard(run)

    _tools.append((schemas.VAULTWARDEN_SEARCH, h_search))

    # ------------------------------------------------------- get_secret_ref
    def h_get_secret_ref(args: dict, **kw: Any) -> str:
        def run():
            item_id = str(args["item_id"])
            field_name = str(args["field"])
            custom = args.get("custom_field_name")
            # Validate the reference target NOW (fail fast on bad ids/fields),
            # but the extracted value stays in local memory only.
            item = auth.get_item(item_id)
            value = _field_value(item, field_name, custom)
            if not value:
                raise errors.NotFoundError(
                    f"Field '{custom or field_name}' is empty on item '{item.get('name')}'.")
            entry = registry.create(item.get("id") or item_id,
                                    f"custom:{custom}" if custom else field_name)
            result: dict[str, Any] = {
                "placeholder": f"${entry.token}",
                "ttl_seconds": registry.ttl_seconds,
                "usage": ("Insert this exact reference into a terminal command "
                          "INSIDE DOUBLE QUOTES (or unquoted — never inside "
                          "single quotes). At execution time the middleware "
                          "writes the real secret to a temp file and rewrites "
                          "the reference to $(< path) so the shell reads it; "
                          "the secret itself never appears in the command, "
                          "argv, history or logs. Single use, expires after "
                          f"{registry.ttl_seconds}s."),
            }
            # VWP-14 (v0.3.7): the allow_direct_secret_retrieval escape hatch
            # was removed — `value` stays in local memory only and NEVER
            # appears in the returned dict. Placeholder is the ONLY path.
            return result
        return _guard(run)

    _tools.append((schemas.VAULTWARDEN_GET_SECRET_REF, h_get_secret_ref))

    # --------------------------------------------------------------- store
    def h_store(args: dict, **kw: Any) -> str:
        def run():
            _require_write(config)
            # v0.4.9 (BREAKING CHANGE): explicit rejection of the removed
            # password_env channel — fires in generate AND non-generate mode.
            _reject_removed_env_channel(args, "password_env", "password_file",
                                        "vaultwarden_store")
            # AUD-02 (v0.6.5): runtime tool secrets now go through the
            # scoped retain/release helpers below; the raw redactor handle
            # is no longer needed in this handler.

            generated_pw = None
            generate = bool(args.get("generate", False))

            # v0.4.0 (Feature 1): resolve the password via the secret-input
            # channels (raw / *_file). In generate mode no password
            # input is allowed — generation takes precedence (v0.3.9 path).
            if generate:
                for k in ("password", "password_file"):
                    if args.get(k):
                        raise errors.ConfigError(
                            "vaultwarden_store: generate=true conflicts with "
                            f"{k!r}; the generated password replaces it.",
                            suggestion="Drop generate=true or remove the "
                                       "password input channel.",
                        )
            else:
                resolved_password, pw_warning = _resolve_secret_input(
                    args, direct_key="password",
                    file_key="password_file", tool_name="vaultwarden_store")

            if generate:
                gen_opts = args.get("generate_options") or {}
                generated_pw = _generate_password(auth, gen_opts)
                pw_warning = None

            tracked = _collect_secret_strings(args)
            # AUD-02: EVERY runtime plaintext (generated password included)
            # is retained exactly once through ``tracked`` and released in
            # the matching finally -- one symmetric retain/release pairing
            # per value, no unpaired double decrements.
            if generated_pw is not None:
                tracked.append(generated_pw)
            # AUD-02: resolved_password is retained exactly ONCE below as
            # part of ``tracked`` -- retaining it separately would require a
            # symmetric double release and any mismatch leaks a refcount.
            if not generate and resolved_password:
                tracked.append(resolved_password)
            for t in tracked:
                retain_runtime_secret(t)

            try:
                item = _build_item(args)

                # v0.4.0: fold the file-resolved password into the item
                # (the raw channel is already inside args -> _build_item).
                if not generate and resolved_password:
                    login = item.get("login") or {}
                    login["password"] = resolved_password
                    item["login"] = login

                # VWP-12: If generate=true, override the password field.
                # The generated value goes straight into the vault item and
                # is NEVER returned to the LLM — only a placeholder is.
                if generated_pw is not None:
                    login = item.get("login") or {}
                    login["password"] = generated_pw
                    item["login"] = login

                created = auth.create_item(item)
                log.info("Created vault item '%s' (%s).",
                         created.get("name"), created.get("id"))

                result = {"created": True, "id": created.get("id"),
                          "item": _metadata(created)}

                if generated_pw is not None:
                    item_id = created.get("id") or ""
                    entry = registry.create(item_id, "password")
                    result["password_generated"] = True
                    result["password_placeholder"] = entry.token
                    result["placeholder_ttl_seconds"] = registry.ttl_seconds

                if pw_warning:
                    result["warning"] = pw_warning

                return result
            finally:
                for t in tracked:
                    release_runtime_secret(t)
                # AUD-02: generated password and resolved password were both
                # retained through ``tracked`` above; the loop releases every
                # pairing exactly once -- no separate release calls.
        return _guard(run)

    _tools.append((schemas.VAULTWARDEN_STORE, h_store))

    # -------------------------------------------------------------- update
    def h_update(args: dict, **kw: Any) -> str:
        def run():
            _require_write(config)
            # v0.4.9 (BREAKING CHANGE): explicit rejection of the removed
            # password_env channel — fires in generate AND non-generate mode.
            _reject_removed_env_channel(args, "password_env", "password_file",
                                        "vaultwarden_update")
            # AUD-02 (v0.6.5): runtime tool secrets now go through the
            # scoped retain/release helpers below; the raw redactor handle
            # is no longer needed in this handler.

            generated_pw = None
            generate = bool(args.get("generate", False))

            # v0.4.0 (Feature 1): resolve the password via the secret-input
            # channels (raw / *_file). In generate mode no password
            # input is allowed — generation takes precedence (v0.3.9 path).
            if generate:
                for k in ("password", "password_file"):
                    if args.get(k):
                        raise errors.ConfigError(
                            "vaultwarden_update: generate=true conflicts with "
                            f"{k!r}; the generated password replaces it.",
                            suggestion="Drop generate=true or remove the "
                                       "password input channel.",
                        )
            else:
                resolved_password, pw_warning = _resolve_secret_input(
                    args, direct_key="password",
                    file_key="password_file", tool_name="vaultwarden_update")

            if generate:
                gen_opts = args.get("generate_options") or {}
                generated_pw = _generate_password(auth, gen_opts)
                pw_warning = None

            tracked = _collect_secret_strings(args)
            # AUD-02: EVERY runtime plaintext (generated password included)
            # is retained exactly once through ``tracked`` and released in
            # the matching finally -- one symmetric retain/release pairing
            # per value, no unpaired double decrements.
            if generated_pw is not None:
                tracked.append(generated_pw)
            # AUD-02: resolved_password is retained exactly ONCE below as
            # part of ``tracked`` -- retaining it separately would require a
            # symmetric double release and any mismatch leaks a refcount.
            if not generate and resolved_password:
                tracked.append(resolved_password)
            for t in tracked:
                retain_runtime_secret(t)

            try:
                item_id = str(args["item_id"])
                current = auth.get_item(item_id)
                merged = _apply_updates(current, args)

                # v0.4.0: fold the file-resolved password into the item
                # (the raw channel is already inside args -> _apply_updates).
                if not generate and resolved_password:
                    login = merged.get("login") or {}
                    login["password"] = resolved_password
                    merged["login"] = login

                # VWP-12: If generate=true, override the password field.
                # The generated value goes straight into the vault item and
                # is NEVER returned to the LLM — only a placeholder is.
                if generated_pw is not None:
                    login = merged.get("login") or {}
                    login["password"] = generated_pw
                    merged["login"] = login

                updated = auth.edit_item(merged)
                log.info("Updated vault item %s.", item_id)

                result = {"updated": True, "id": updated.get("id") or item_id,
                          "item": _metadata(updated)}

                if generated_pw is not None:
                    entry = registry.create(item_id, "password")
                    result["password_generated"] = True
                    result["password_placeholder"] = entry.token
                    result["placeholder_ttl_seconds"] = registry.ttl_seconds

                if pw_warning:
                    result["warning"] = pw_warning

                return result
            finally:
                for t in tracked:
                    release_runtime_secret(t)
                # AUD-02: generated password and resolved password were both
                # retained through ``tracked`` above; the loop releases every
                # pairing exactly once -- no separate release calls.
        return _guard(run)

    _tools.append((schemas.VAULTWARDEN_UPDATE, h_update))

    # -------------------------------------------------------------- delete
    def h_delete(args: dict, **kw: Any) -> str:
        def run():
            _require_write(config)
            if not args.get("confirm"):
                raise errors.PermissionError_(
                    "Delete requires confirm:true (explicit user confirmation).",
                    suggestion="Re-issue with confirm=true after user approval.")
            permanent = bool(args.get("permanent"))
            # BUG-4 fix: dead code removed — the confirm check above already
            # guarantees confirm is truthy here, so a second check was
            # unreachable. Soft vs permanent is decided by `permanent` alone.
            item_id = str(args["item_id"])
            auth.delete_item(item_id, permanent=permanent)
            log.warning("Deleted vault item %s (permanent=%s).", item_id, permanent)
            return {"deleted": True, "id": item_id, "permanent": permanent}
        return _guard(run)

    _tools.append((schemas.VAULTWARDEN_DELETE, h_delete))

    # ================================================== SSH key management
    # v0.3.5: the single implementations of the SSH tool handlers live at
    # module level below (h_store_ssh / h_update_ssh / h_delete_ssh /
    # h_use_ssh). The registrations here are thin wrappers that bind the
    # per-session auth/config objects — no duplicated implementation code.
    # Helpers (_validate_ssh_key_file / _resolve_socket_path) are also
    # module-level only.

    def _h_store_ssh_bound(args: dict, **kw: Any) -> str:
        return h_store_ssh(args, auth=auth, config=config, **kw)

    _tools.append((schemas.VAULTWARDEN_STORE_SSH, _h_store_ssh_bound))

    def _h_update_ssh_bound(args: dict, **kw: Any) -> str:
        return h_update_ssh(args, auth=auth, config=config, **kw)

    _tools.append((schemas.VAULTWARDEN_UPDATE_SSH, _h_update_ssh_bound))

    def _h_delete_ssh_bound(args: dict, **kw: Any) -> str:
        return h_delete_ssh(args, auth=auth, config=config, **kw)

    _tools.append((schemas.VAULTWARDEN_DELETE_SSH, _h_delete_ssh_bound))

    def _h_use_ssh_bound(args: dict, **kw: Any) -> str:
        return h_use_ssh(args, auth=auth, config=config, **kw)

    _tools.append((schemas.VAULTWARDEN_USE_SSH, _h_use_ssh_bound))

    return _tools


_SSH_KEY_PREFIXES = ("-----BEGIN", "ssh-", "ecdsa-", "ssh-ed25519")


def _validate_ssh_key_file(path: str) -> None:
    """Validate that path exists, is readable, and looks like an SSH key."""
    if not os.path.isfile(path):
        # errors.NotFoundError carries code "NOT_FOUND".
        raise errors.NotFoundError(
            f"File not found: {path}",
            suggestion="Provide an absolute path to an existing SSH key file.")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            head = f.read(256)
    except OSError as exc:
        raise _vault_error(
            f"Cannot read file: {path}", code="VALIDATION_ERROR",
            suggestion="Check file permissions.") from exc
    if not any(head.strip().startswith(p) for p in _SSH_KEY_PREFIXES):
        raise _vault_error(
            f"File does not appear to be an SSH key: {path}",
            code="VALIDATION_ERROR",
            suggestion="Expected a file starting with '-----BEGIN' or 'ssh-'.")


def _resolve_socket_path() -> tuple[str, bool]:
    """Resolve the ssh-agent socket path (developer-controlled).

    VWP-02 (v0.4.6, BREAKING): the LLM-controlled ``ssh_auth_sock`` tool
    parameter was removed — it enabled local process/socket takeover
    attacks. The socket path is now resolved exclusively from
    developer-controlled environment variables.

    Resolution order:
    1. $VW_SSH_SOCKET_PATH env var (if set): use that path. Reuse if agent running.
    2. $XDG_RUNTIME_DIR/auth.sock (fallback): reuse if agent running.

    This is a developer-controlled setting, NOT user/LLM-configurable.
    The $VW_SSH_SOCKET_PATH env var allows sharing the socket with external
    tools (e.g. ssh-mcp server).

    Returns (socket_path, agent_started_by_plugin).
    """
    def _agent_running(sock: str) -> bool:
        try:
            r = subprocess.run(["ssh-add", "-l"],
                               env=_ssh_base_env({"SSH_AUTH_SOCK": sock}),
                               capture_output=True, text=True, timeout=5)
            return r.returncode in (0, 1)
        except Exception:
            return False

    def _start_agent_at(sock: str) -> None:
        # Ensure parent directory exists with safe permissions
        parent = os.path.dirname(sock)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, mode=0o700, exist_ok=True)
        # Security (VWP-02): reject symlinks — path redirection would let a
        # local attacker swap the socket after resolution. errors has no
        # dedicated SecurityError class (errors.py is frozen), so the
        # SECURITY_ERROR taxonomy code is used via _vault_error().
        if os.path.islink(sock) or (parent and os.path.islink(parent)):
            raise _vault_error(
                "Socket path or parent directory is a symlink.",
                code="SECURITY_ERROR",
                suggestion="Use a direct path, not a symlink.")
        subprocess.run(["ssh-agent", "-a", sock],
                       env=_ssh_base_env(),
                       capture_output=True, text=True, timeout=10)

    # Step 1: Check $VW_SSH_SOCKET_PATH
    vw_sock = os.environ.get("VW_SSH_SOCKET_PATH", "").strip()
    if vw_sock:
        sock = os.path.abspath(vw_sock)
        if _agent_running(sock):
            return sock, False
        else:
            _start_agent_at(sock)
            return sock, True

    # Step 2: Fallback to $XDG_RUNTIME_DIR/auth.sock
    xdg = os.environ.get("XDG_RUNTIME_DIR", "")
    if xdg:
        sock = os.path.join(xdg, "auth.sock")
    else:
        sock = os.path.join(tempfile.gettempdir(), f"vw-auth-{os.getuid()}.sock")

    if _agent_running(sock):
        return sock, False
    else:
        _start_agent_at(sock)
        return sock, True


def h_store_ssh(args: dict, auth: AuthManager, config: PluginConfig,
                **kw: Any) -> str:
    """Store an SSH key as a login item + file attachment (v0.2.8).

    v0.3.5: single module-level source of truth — get_tools() registers a
    thin wrapper that binds auth/config. username=SSH user, password=
    passphrase, key=file attachment; name uniqueness enforced by auth.

    v0.4.0: two modes —
     - generate=true: the plugin generates a 32-char passphrase via the SAME
       _generate_password (`bw generate`) path used by store/update, then an
       SSH keypair via ssh-keygen (passphrase delivered on STDIN, never
       argv), stores private key as attachment + passphrase as the item
       password, and returns ONLY the public key + fingerprint (non-secret).
       pass/pass_file/file are FORBIDDEN in this mode.
     - upload (default): passphrase resolved via _resolve_secret_input
       (pass / pass_file); raw pass emits a dual-channel warning
       (log + response "warning" field).

    v0.4.9 (BREAKING CHANGE): the pass_env channel was removed; supplying
    it raises an explicit ConfigError (see _reject_removed_env_channel).
    """

    def run():
        _require_write(config)
        # v0.4.9 (BREAKING CHANGE): explicit rejection of the removed
        # pass_env channel — fires in generate AND non-generate mode.
        _reject_removed_env_channel(args, "pass_env", "pass_file",
                                    "vaultwarden_store_ssh")
        name = str(args["name"])
        generate = bool(args.get("generate", False))
        # AUD-02 (v0.6.5): runtime tool secrets now go through the
        # scoped retain/release helpers below; the raw redactor handle
        # is no longer needed in this handler.

        if generate:
            # Generate mode: the plugin supplies pass + file itself.
            for k in ("pass", "pass_file", "file"):
                if args.get(k):
                    raise errors.ConfigError(
                        f"vaultwarden_store_ssh: generate=true conflicts with "
                        f"{k!r}; the plugin generates the key and passphrase.",
                        suggestion="Remove the supplied parameter or drop "
                                   "generate=true.",
                    )
            key_type = str(args.get("key_type") or "ed25519")
            if key_type not in ("ed25519", "rsa"):
                raise errors.ConfigError(
                    f"vaultwarden_store_ssh: unsupported key_type {key_type!r}",
                    suggestion="Use 'ed25519' or 'rsa'.",
                )
            rsa_bits = int(args.get("rsa_bits") or 4096)
            user = str(args.get("user") or "")

            # Single secret-generation path (decision 1): bw generate, NOT a
            # stdlib generator. Register immediately with the RedactingFilter.
            passphrase = _generate_password(auth, {"mode": "password", "length": 32})
            retain_runtime_secret(passphrase)
            tmpdir = None
            try:
                tmpdir, key_path, public_key, fingerprint = \
                    _generate_ssh_keypair(key_type, rsa_bits,
                                          comment=name, passphrase=passphrase)
                try:
                    with open(key_path, "r", encoding="utf-8",
                              errors="replace") as f:
                        retain_runtime_secret(f.read())
                except OSError:
                    pass
                result = auth.create_ssh_item(name, user, passphrase, key_path)
                log.info("Generated %s SSH key item '%s' (%s).",
                         key_type, name, result.get("id"))
                return {
                    "created": True,
                    "id": result.get("id", ""),
                    "name": name,
                    "ssh_user": user,
                    "key_type": key_type,
                    "public_key": public_key,
                    "fingerprint": fingerprint,
                    "passphrase_generated": True,
                }
            finally:
                # v0.5.8 cleanup observability: sanitized WARNING on failure.
                if tmpdir is not None:
                    _rmtree_quietly(tmpdir)
                release_runtime_secret(passphrase)

        # Upload mode: resolve the passphrase from exactly one channel.
        passphrase, pw_warning = _resolve_secret_input(
            args, direct_key="pass",
            file_key="pass_file", tool_name="vaultwarden_store_ssh")
        if passphrase is None:
            raise errors.ConfigError(
                "vaultwarden_store_ssh: requires pass, pass_file, "
                "or generate=true.",
                suggestion="Provide the passphrase via one channel, or set "
                           "generate=true to create a new keypair.",
            )
        # v0.4.8 (BUGFIX, Defects 1-2): validate presence BEFORE the raw
        # dict lookups — a missing 'file'/'user' must raise a clear
        # ConfigError, never leak a KeyError ("Internal plugin error").
        if not args.get("user"):
            raise errors.ConfigError(
                "vaultwarden_store_ssh: 'user' is required in upload mode.",
                suggestion="Provide the SSH username, or use generate=true.")
        if not args.get("file"):
            raise errors.ConfigError(
                "vaultwarden_store_ssh: 'file' (absolute SSH private key path) "
                "is required in upload mode.",
                suggestion="Provide the key file path, or use generate=true.")
        user = str(args["user"])
        file_path = str(args["file"])

        _validate_ssh_key_file(file_path)

        retain_runtime_secret(passphrase)
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                retain_runtime_secret(f.read())
        except OSError:
            pass

        result = auth.create_ssh_item(name, user, passphrase, file_path)
        log.info("Stored SSH key item '%s' (%s).", name, result.get("id"))
        response = {
            "created": True,
            "id": result.get("id", ""),
            "name": name,
            "ssh_user": user,
            "attachment": os.path.basename(file_path),
        }
        if pw_warning:
            response["warning"] = pw_warning
        return response
    return _guard(run)


def h_update_ssh(args: dict, auth: AuthManager, config: PluginConfig,
                 **kw: Any) -> str:
    """Update an existing SSH key item — user/pass/notes/key attachment.

    v0.4.0: supports generate=true — a destructive KEY ROTATION (replaces
    the existing keypair + passphrase) that REQUIRES confirm=true, mirroring
    vaultwarden_delete_ssh. The new passphrase comes from the same
    _generate_password (`bw generate`) path; the keypair from
    _generate_ssh_keypair (SSH_ASKPASS passphrase delivery). Only the public
    key + fingerprint are returned. In generate mode pass/pass_file/
    file are forbidden. Without generate, the passphrase is resolved via
    _resolve_secret_input (pass / pass_file) with a dual-channel
    warning on raw input.

    v0.4.9 (BREAKING CHANGE): the pass_env channel was removed; supplying
    it raises an explicit ConfigError (see _reject_removed_env_channel).
    """

    def run():
        _require_write(config)
        # v0.4.9 (BREAKING CHANGE): explicit rejection of the removed
        # pass_env channel — fires in generate AND non-generate mode.
        _reject_removed_env_channel(args, "pass_env", "pass_file",
                                    "vaultwarden_update_ssh")
        name = str(args["name"])
        generate = bool(args.get("generate", False))
        # AUD-02 (v0.6.5): runtime tool secrets now go through the
        # scoped retain/release helpers below; the raw redactor handle
        # is no longer needed in this handler.

        matches = auth.search_items(name)
        exact = [m for m in matches if m.get("name") == name]
        if not exact:
            raise errors.NotFoundError(
                f"No SSH key item named '{name}'.",
                suggestion="Use vaultwarden_list to see available items.")
        if len(exact) > 1:
            raise _vault_error(
                f"Multiple items match name '{name}' ({len(exact)} found).",
                code="AMBIGUOUS_ERROR",
                suggestion="Use vaultwarden_search to find the correct item_id.")
        item = exact[0]
        item_id = item.get("id", "")

        if generate:
            # Key rotation is destructive — explicit confirmation required.
            if not args.get("confirm"):
                raise errors.PermissionError_(
                    "vaultwarden_update_ssh: generate=true rotates (replaces) "
                    "the existing keypair and passphrase; explicit "
                    "confirmation required.",
                    suggestion="Re-issue with confirm=true to rotate the key.")
            for k in ("pass", "pass_file", "file"):
                if args.get(k):
                    raise errors.ConfigError(
                        f"vaultwarden_update_ssh: generate=true conflicts with "
                        f"{k!r}; the plugin generates the key and passphrase.",
                        suggestion="Remove the supplied parameter or drop "
                                   "generate=true.",
                        )
            key_type = str(args.get("key_type") or "ed25519")
            if key_type not in ("ed25519", "rsa"):
                raise errors.ConfigError(
                    f"vaultwarden_update_ssh: unsupported key_type {key_type!r}",
                    suggestion="Use 'ed25519' or 'rsa'.",
                )
            rsa_bits = int(args.get("rsa_bits") or 4096)

            passphrase = _generate_password(auth, {"mode": "password", "length": 32})
            retain_runtime_secret(passphrase)
            tmpdir = None
            try:
                tmpdir, key_path, public_key, fingerprint = \
                    _generate_ssh_keypair(key_type, rsa_bits,
                                          comment=name, passphrase=passphrase)
                try:
                    with open(key_path, "r", encoding="utf-8",
                              errors="replace") as f:
                        retain_runtime_secret(f.read())
                except OSError:
                    pass

                current = auth.get_item(item_id)
                login = dict(current.get("login") or {})
                if args.get("user"):
                    login["username"] = str(args["user"])
                login["password"] = passphrase
                current["login"] = login
                auth.edit_item(current)

                session = auth.get_session()
                for att in (item.get("attachments") or []):
                    auth._bw.delete_attachment(session, att.get("id", ""),
                                               item_id)
                auth._bw.create_attachment(session, key_path, item_id)

                log.warning("Rotated SSH key pair for item '%s' (%s).",
                            name, item_id)
                return {
                    "updated": True,
                    "id": item_id,
                    "name": name,
                    "key_type": key_type,
                    "public_key": public_key,
                    "fingerprint": fingerprint,
                    "passphrase_rotated": True,
                }
            finally:
                # v0.5.8 cleanup observability: sanitized WARNING on failure.
                if tmpdir is not None:
                    _rmtree_quietly(tmpdir)
                release_runtime_secret(passphrase)

        # Non-generate update path (upload semantics).
        resolved_pass, pw_warning = _resolve_secret_input(
            args, direct_key="pass",
            file_key="pass_file", tool_name="vaultwarden_update_ssh")

        updates = {}
        if args.get("user"):
            updates["username"] = str(args["user"])
        if resolved_pass is not None:
            updates["password"] = resolved_pass
            retain_runtime_secret(resolved_pass)
        if args.get("notes") is not None:
            updates["notes"] = str(args["notes"])

        if updates:
            current = auth.get_item(item_id)
            login = dict(current.get("login") or {})
            login.update(updates)
            current["login"] = login
            auth.edit_item(current)

        if args.get("file"):
            file_path = str(args["file"])
            _validate_ssh_key_file(file_path)
            session = auth.get_session()
            atts = item.get("attachments") or []
            for att in atts:
                auth._bw.delete_attachment(session, att.get("id", ""), item_id)
            auth._bw.create_attachment(session, file_path, item_id)

        log.info("Updated SSH key item '%s' (%s).", name, item_id)
        response = {"updated": True, "id": item_id, "name": name}
        if pw_warning:
            response["warning"] = pw_warning
        return response
    return _guard(run)


def h_delete_ssh(args: dict, auth: AuthManager, config: PluginConfig,
                 **kw: Any) -> str:
    """Delete an SSH key item (including its attachment). confirm=true required."""

    def run():
        _require_write(config)
        if not args.get("confirm"):
            raise errors.PermissionError_(
                "Deletion requires explicit confirm=true.",
                suggestion="Re-run with confirm=true to proceed.")

        name = str(args["name"])
        matches = auth.search_items(name)
        exact = [m for m in matches if m.get("name") == name]
        if not exact:
            raise errors.NotFoundError(f"No SSH key item named '{name}'.")
        if len(exact) > 1:
            raise _vault_error(
                f"Multiple items match name '{name}'.",
                code="AMBIGUOUS_ERROR")
        item_id = exact[0].get("id", "")
        permanent = bool(args.get("permanent"))

        def _do(session: str):
            auth._bw.delete_item(session, item_id, permanent)
        auth.run_with_recovery(_do)
        log.warning("Deleted SSH key item '%s' (%s, permanent=%s).",
                    name, item_id, permanent)
        return {"deleted": True, "id": item_id, "permanent": permanent}
    return _guard(run)


def h_use_ssh(args: dict, auth: AuthManager, **kw: Any) -> str:
    """Load an SSH private key from the vault into ssh-agent (v0.2.8).

    Security guarantees:
    - Passphrase delivered via the SSH_ASKPASS mechanism: a dynamically
      generated shell script containing ONLY `echo "$VW_SSH_PASS"` runs
      as the askpass helper; the passphrase itself is passed to the
      subprocess via environment variable only — NEVER written to any
      file and NEVER entering the agent's context window.
    - Key material: temp file unavoidable (ssh-add reads key from file).
      Created with tempfile.mkstemp() (atomic), chmod 0600, deleted in
      `finally` along with the askpass script.
    - Both passphrase and key content registered with RedactingFilter.
    """

    def run():
        name = str(args["name"])
        # VWP-02 (v0.4.6): the LLM-controlled `ssh_auth_sock` argument was
        # removed from the schema; the socket path is resolved exclusively
        # from developer-controlled environment variables.

        matches = auth.search_items(name)
        exact = [m for m in matches if m.get("name") == name]
        if not exact:
            raise errors.NotFoundError(
                f"No SSH key item named '{name}'.",
                suggestion="Use vaultwarden_list to see available items.")
        if len(exact) > 1:
            raise _vault_error(
                f"Multiple items match name '{name}'.",
                code="AMBIGUOUS_ERROR")
        item = exact[0]
        item_id = item.get("id", "")

        sock, agent_started = _resolve_socket_path()

        key_path = None
        askpass_path = None
        try:
            fd, key_path = tempfile.mkstemp(suffix=".sshkey", prefix="vw_")
            os.close(fd)
            os.chmod(key_path, 0o600)

            key_path, passphrase = auth.get_ssh_key(item_id, key_path)
            os.chmod(key_path, 0o600)

            # AUD-02 (v0.6.5): runtime tool secrets now go through the
            # scoped retain/release helpers below; the raw redactor handle
            # is no longer needed in this handler.
            retain_runtime_secret(passphrase)
            try:
                with open(key_path, "r", encoding="utf-8",
                          errors="replace") as f:
                    retain_runtime_secret(f.read())
            except OSError:
                pass

            # Passphrase delivery via the SSH_ASKPASS mechanism (shared
            # single implementation: _askpass_env / _make_askpass_script).
            # The askpass script contains ONLY `echo "$VW_SSH_PASS"` —
            # no secret content in the file. The passphrase is passed
            # via environment variable to the subprocess only.
            # VWP-08: env built on _ssh_base_env() — minimal allowlist,
            # parent environment NEVER inherited.
            env = _askpass_env(passphrase, extra={"SSH_AUTH_SOCK": sock})
            askpass_path = env["SSH_ASKPASS"]
            proc = subprocess.run(
                ["ssh-add", key_path],
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True, text=True, timeout=30,
                start_new_session=True,   # detach from controlling tty:
                                          # no /dev/tty passphrase prompt
            )
            if proc.returncode != 0:
                stderr = (proc.stderr or "").strip()
                raise errors.AuthError(
                    f"ssh-add failed (exit {proc.returncode}): {stderr}",
                    suggestion="Check if the passphrase is correct.")

            fp_proc = subprocess.run(
                ["ssh-keygen", "-lf", key_path],
                env=_ssh_base_env(),
                capture_output=True, text=True, timeout=10)
            fingerprint = (fp_proc.stdout or "").strip().split()[1] \
                if fp_proc.returncode == 0 else "unknown"

            return {
                "loaded": True,
                "item": name,
                "ssh_user": (item.get("login") or {}).get("username", ""),
                "key_fingerprint": fingerprint,
                "ssh_auth_sock": sock,
                "agent_started_by_plugin": agent_started,
                "message": (
                    f"Key loaded. Use SSH_AUTH_SOCK={sock} for subsequent "
                    "SSH commands."),
            }
        finally:
            # Clean up temp key file
            # v0.5.8 cleanup observability: sanitized WARNING on failure —
            # leftover private-key material on disk must never be silent.
            if key_path and os.path.exists(key_path):
                _remove_quietly(key_path, "temp SSH key file")
            # Clean up askpass script
            if askpass_path and os.path.exists(askpass_path):
                _remove_quietly(askpass_path, "askpass helper")
    return _guard(run)


# ---------------------------------------------------------- item builders
_TYPE_NUMBERS = {"login": 1, "note": 2, "card": 3, "identity": 4}


def _build_item(args: dict) -> dict:
    item: dict[str, Any] = {
        "type": _TYPE_NUMBERS.get(args.get("type", "login"), 1),
        "name": args["name"],
    }
    if args.get("notes"):
        item["notes"] = args["notes"]
    if args.get("folder_id"):
        item["folderId"] = args["folder_id"]
    login: dict[str, Any] = {}
    if args.get("username"):
        login["username"] = args["username"]
    if args.get("password"):
        login["password"] = args["password"]
    if args.get("uri"):
        login["uris"] = [{"uri": args["uri"]}]
    if login:
        item["login"] = login
    fields = []
    for cf in args.get("custom_fields") or []:
        fields.append({"name": cf["name"], "value": cf["value"],
                       "type": int(cf.get("field_type", 0))})
    if fields:
        item["fields"] = fields
    return item


def _apply_updates(current: dict, args: dict) -> dict:
    """Fetch-modify-save merge for vaultwarden_update."""
    merged = dict(current)
    if args.get("name"):
        merged["name"] = args["name"]
    if args.get("notes") is not None and args.get("notes") != "":
        merged["notes"] = args["notes"]
    login = dict(merged.get("login") or {})
    if args.get("username"):
        login["username"] = args["username"]
    if args.get("password"):
        login["password"] = args["password"]
    if args.get("uri"):
        login["uris"] = [{"uri": args["uri"]}]
    if login:
        merged["login"] = login
    if args.get("custom_fields") is not None:
        existing = [f for f in (merged.get("fields") or [])
                    if f.get("name") not in {cf["name"] for cf in args["custom_fields"]}]
        new = [{"name": cf["name"], "value": cf["value"],
                "type": int(cf.get("field_type", 0))} for cf in args["custom_fields"]]
        merged["fields"] = existing + new
    return merged

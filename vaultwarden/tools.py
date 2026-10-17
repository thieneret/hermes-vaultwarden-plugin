# vaultwarden/tools.py — v0.2.8
"""Tool handlers for the 13 vaultwarden_* tools (plan §8).

``get_tools(auth, config, registry)`` yields (schema, handler) pairs.
v0.2.4: Handlers return JSON strings (Hermes tool_call requires str);
on failure they return the standard error envelope serialized to JSON:
{"error", "error_code", "recoverable", "suggestion"}.

Hard rule: no handler ever returns a stored secret value. The single
exception is vaultwarden_generate_password (explicitly by design) and
vaultwarden_get_secret_ref when allow_direct_secret_retrieval=true
(default false — placeholders are used instead).
"""
from __future__ import annotations

import fnmatch
import json
import os
import subprocess
import tempfile
from typing import Any, Callable

from . import errors, schemas
from .auth import AuthManager
from .config import PluginConfig
from .placeholders import PlaceholderRegistry
from .security import get_logger, get_redacting_filter

log = get_logger("tools")

Handler = Callable[..., str]


# --------------------------------------------------------------- helpers
def _item_type_name(item: dict) -> str:
    mapping = {1: "login", 2: "note", 3: "card", 4: "identity"}
    t = item.get("type")
    if isinstance(t, int):
        return mapping.get(t, str(t))
    return str(t or "login")


def _metadata(item: dict) -> dict:
    """Safe metadata projection — NEVER includes password/totp/notes values."""
    login = item.get("login") or {}
    uris = [u.get("uri") for u in (login.get("uris") or []) if u.get("uri")]
    out = {
        "id": item.get("id"),
        "name": item.get("name"),
        "type": _item_type_name(item),
        "username": login.get("username"),
        "uris": uris,
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
    try:
        result = fn()
        return json.dumps(result, ensure_ascii=False, default=str)
    except errors.VaultwardenError as exc:
        log.debug("tool error: %s (%s)", exc.message, exc.code)
        return json.dumps(exc.to_dict(), ensure_ascii=False, default=str)
    except Exception as exc:  # pragma: no cover - defensive
        log.exception("unexpected tool failure")
        return json.dumps(errors.error_response(exc), ensure_ascii=False, default=str)


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

    v0.2.8: returns a concrete list of 13 (schema, handler) pairs — the
    SSH key management tools (store/update/delete/use_ssh) are appended at
    the end of the list.
    """
    _tools: list[tuple[dict, Handler]] = []

    # ------------------------------------------------------------ status
    def h_status(args: dict, **kw: Any) -> str:
        return _guard(lambda: {"status": auth.status_snapshot(),
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
            projected = [_metadata(i) for i in items[:limit]]
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
            for it in items:
                if want_type and _item_type_name(it) != want_type:
                    continue
                meta = _metadata(it)
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
                "placeholder": entry.token,
                "ttl_seconds": registry.ttl_seconds,
                "usage": ("Insert this exact token into a terminal command; it is "
                          "replaced with the real value at execution time (single use)."),
            }
            if config.allow_direct_secret_retrieval:  # DEFAULT OFF — escape hatch
                result["direct_value"] = value
            return result
        return _guard(run)

    _tools.append((schemas.VAULTWARDEN_GET_SECRET_REF, h_get_secret_ref))

    # --------------------------------------------------------------- store
    def h_store(args: dict, **kw: Any) -> str:
        def run():
            _require_write(config)
            redactor = get_redacting_filter()
            tracked = _collect_secret_strings(args)
            for t in tracked:
                redactor.register_secret(t)
            try:
                item = _build_item(args)
                created = auth.create_item(item)
                log.info("Created vault item '%s' (%s).", created.get("name"), created.get("id"))
                return {"created": True, "id": created.get("id"),
                        "item": _metadata(created)}
            finally:
                for t in tracked:
                    redactor.forget_secret(t)
        return _guard(run)

    _tools.append((schemas.VAULTWARDEN_STORE, h_store))

    # -------------------------------------------------------------- update
    def h_update(args: dict, **kw: Any) -> str:
        def run():
            _require_write(config)
            redactor = get_redacting_filter()
            tracked = _collect_secret_strings(args)
            for t in tracked:
                redactor.register_secret(t)
            try:
                item_id = str(args["item_id"])
                current = auth.get_item(item_id)
                merged = _apply_updates(current, args)
                updated = auth.edit_item(merged)
                log.info("Updated vault item %s.", item_id)
                return {"updated": True, "id": updated.get("id") or item_id,
                        "item": _metadata(updated)}
            finally:
                for t in tracked:
                    redactor.forget_secret(t)
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

    # ----------------------------------------------------- generate_password
    def h_generate(args: dict, **kw: Any) -> str:
        def run():
            # BUG-2 fix: no _require_write() here — generation does not touch
            # the vault (plan §8), so it works with allow_write=false.
            mode = args.get("mode") or "password"
            if mode == "passphrase":
                words = int(args.get("words") or 4)
                sep = str(args.get("separator") or "-")
                # BUG-1 fix: real bw generate passphrase syntax uses flags,
                # not positional 1/0 values: bw generate --passphrase -w N --separator S
                bw_args = ["--passphrase", "-w", str(words), "--separator", sep]
            else:
                length = int(args.get("length") or 20)
                upper = args.get("uppercase", True)
                lower = args.get("lowercase", True)
                nums = args.get("numbers", True)
                special = args.get("special", True)
                # BUG-1 fix: real bw generate password syntax uses flags, not
                # positional 1/0 values: bw generate <length> --uppercase
                # --lowercase --number --special (verified against the Bitwarden
                # CLI source; note the singular "--number"). Only include a flag
                # when the corresponding boolean is True.
                bw_args = [str(length)]
                if upper:
                    bw_args.append("--uppercase")
                if lower:
                    bw_args.append("--lowercase")
                if nums:
                    bw_args.append("--number")
                if special:
                    bw_args.append("--special")
            pw = auth.generate_password(bw_args)
            log.info("Generated a new %s (value not logged).", mode)
            return {"mode": mode, "generated": pw, "length": len(pw)}
        return _guard(run)

    _tools.append((schemas.VAULTWARDEN_GENERATE_PASSWORD, h_generate))

    # ================================================== SSH key management
    # v0.2.8: store/update/delete/use SSH keys (login item + file attachment).
    # Validation/socket helpers are the module-level functions defined below
    # (_validate_ssh_key_file / _resolve_socket_path); handlers registered here
    # close over auth/config only.

    def h_store_ssh(args: dict, **kw: Any) -> str:
        def run():
            _require_write(config)
            name = str(args["name"])
            user = str(args["user"])
            passphrase = str(args["pass"])
            file_path = str(args["file"])

            _validate_ssh_key_file(file_path)

            redactor = get_redacting_filter()
            redactor.register_secret(passphrase)
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    redactor.register_secret(f.read())
            except OSError:
                pass

            result = auth.create_ssh_item(name, user, passphrase, file_path)
            log.info("Stored SSH key item '%s' (%s).", name, result.get("id"))
            return {
                "created": True,
                "id": result.get("id", ""),
                "name": name,
                "ssh_user": user,
                "attachment": os.path.basename(file_path),
            }
        return _guard(run)

    _tools.append((schemas.VAULTWARDEN_STORE_SSH, h_store_ssh))

    def h_update_ssh(args: dict, **kw: Any) -> str:
        def run():
            _require_write(config)
            name = str(args["name"])

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

            updates = {}
            if args.get("user"):
                updates["username"] = str(args["user"])
            if args.get("pass"):
                updates["password"] = str(args["pass"])
                get_redacting_filter().register_secret(str(args["pass"]))
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
            return {"updated": True, "id": item_id, "name": name}
        return _guard(run)

    _tools.append((schemas.VAULTWARDEN_UPDATE_SSH, h_update_ssh))

    def h_delete_ssh(args: dict, **kw: Any) -> str:
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

    _tools.append((schemas.VAULTWARDEN_DELETE_SSH, h_delete_ssh))

    def h_use_ssh(args: dict, **kw: Any) -> str:
        def run():
            name = str(args["name"])
            ssh_auth_sock_param = args.get("ssh_auth_sock")

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

            sock, agent_started = _resolve_socket_path(ssh_auth_sock_param)

            key_path = None
            try:
                # v0.2.8: SSH key delivery — temp file unavoidable (ssh-add
                # reads the key from a file; stdin is reserved for the
                # passphrase). mkstemp is atomic; 0600; deleted in `finally`.
                fd, key_path = tempfile.mkstemp(suffix=".sshkey", prefix="vw_")
                os.close(fd)
                os.chmod(key_path, 0o600)

                key_path, passphrase = auth.get_ssh_key(item_id, key_path)
                os.chmod(key_path, 0o600)

                redactor = get_redacting_filter()
                redactor.register_secret(passphrase)
                try:
                    with open(key_path, "r", encoding="utf-8",
                              errors="replace") as f:
                        redactor.register_secret(f.read())
                except OSError:
                    pass

                # Passphrase delivery: stdin pipe ONLY — NEVER a temp file.
                env = {"SSH_AUTH_SOCK": sock,
                       "HOME": os.environ.get("HOME", "/")}
                proc = subprocess.run(
                    ["ssh-add", key_path],
                    env=env, input=passphrase,
                    capture_output=True, text=True, timeout=30,
                )
                if proc.returncode != 0:
                    stderr = (proc.stderr or "").strip()
                    raise errors.AuthError(
                        f"ssh-add failed (exit {proc.returncode}): {stderr}",
                        suggestion="Check if the passphrase is correct.")

                fp_proc = subprocess.run(
                    ["ssh-keygen", "-lf", key_path],
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
                        f"Key loaded. Export SSH_AUTH_SOCK={sock} for "
                        "subsequent SSH commands."),
                }
            finally:
                if key_path and os.path.exists(key_path):
                    try:
                        os.unlink(key_path)
                    except OSError:
                        pass
        return _guard(run)

    _tools.append((schemas.VAULTWARDEN_USE_SSH, h_use_ssh))

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


def _resolve_socket_path(ssh_auth_sock: str | None) -> tuple[str, bool]:
    """Resolve the ssh-agent socket path (module-level mirror, v0.2.8).

    Returns (socket_path, agent_started_by_plugin). Resolution rules are
    documented on the closure version inside get_tools().
    """
    def _agent_running(sock: str) -> bool:
        try:
            r = subprocess.run(["ssh-add", "-l"],
                               env={**os.environ, "SSH_AUTH_SOCK": sock},
                               capture_output=True, text=True, timeout=5)
            return r.returncode in (0, 1)
        except Exception:
            return False

    def _start_agent_at(sock: str) -> None:
        subprocess.run(["ssh-agent", "-a", sock],
                       capture_output=True, text=True, timeout=10)

    def _start_agent_default() -> str:
        r = subprocess.run(["ssh-agent"], capture_output=True, text=True,
                           timeout=10)
        for line in (r.stdout or "").splitlines():
            if line.startswith("SSH_AUTH_SOCK="):
                # v0.2.8: ssh-agent prints "SSH_AUTH_SOCK=/path; export ..."
                return line.split("=", 1)[1].split(";", 1)[0].strip()
        raise _vault_error(
            "Failed to start ssh-agent: could not parse socket path.",
            code="AGENT_ERROR")

    if ssh_auth_sock:
        if "/" in ssh_auth_sock or os.path.exists(ssh_auth_sock):
            sock = ssh_auth_sock
        else:
            env_val = os.environ.get(ssh_auth_sock, "")
            if not env_val:
                raise _vault_error(
                    f"Environment variable '{ssh_auth_sock}' is not set or empty.",
                    code="VALIDATION_ERROR",
                    suggestion=(
                        "Provide a direct socket path (e.g. /tmp/ssh-xxx/agent.123) "
                        "or set the environment variable first."))
            sock = env_val

        if _agent_running(sock):
            return sock, False
        else:
            _start_agent_at(sock)
            return sock, True
    else:
        env_sock = os.environ.get("SSH_AUTH_SOCK", "")
        if env_sock:
            if _agent_running(env_sock):
                return env_sock, False
            else:
                _start_agent_at(env_sock)
                return env_sock, True
        else:
            sock = _start_agent_default()
            return sock, True


def h_store_ssh(args: dict, **kw: Any) -> str:
    """Store an SSH key as a login item + file attachment (v0.2.8).

    Module-level implementation mirroring the get_tools() closure so it is
    directly importable and unit-testable. username=SSH user, password=
    passphrase, key=file attachment; name uniqueness enforced by auth.
    """

    def run():
        _require_write(kw["config"])
        name = str(args["name"])
        user = str(args["user"])
        passphrase = str(args["pass"])
        file_path = str(args["file"])

        _validate_ssh_key_file(file_path)

        redactor = get_redacting_filter()
        redactor.register_secret(passphrase)
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                redactor.register_secret(f.read())
        except OSError:
            pass

        result = kw["auth"].create_ssh_item(name, user, passphrase, file_path)
        return {
            "created": True,
            "id": result.get("id", ""),
            "name": name,
            "ssh_user": user,
            "attachment": os.path.basename(file_path),
        }
    return _guard(run)


def h_update_ssh(args: dict, **kw: Any) -> str:
    """Update an existing SSH key item — user/pass/notes/key attachment."""

    def run():
        _require_write(kw["config"])
        name = str(args["name"])
        auth = kw["auth"]

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

        updates = {}
        if args.get("user"):
            updates["username"] = str(args["user"])
        if args.get("pass"):
            updates["password"] = str(args["pass"])
            get_redacting_filter().register_secret(str(args["pass"]))
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

        return {"updated": True, "id": item_id, "name": name}
    return _guard(run)


def h_delete_ssh(args: dict, **kw: Any) -> str:
    """Delete an SSH key item (including its attachment). confirm=true required."""

    def run():
        _require_write(kw["config"])
        if not args.get("confirm"):
            raise errors.PermissionError_(
                "Deletion requires explicit confirm=true.",
                suggestion="Re-run with confirm=true to proceed.")

        name = str(args["name"])
        auth = kw["auth"]
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
        return {"deleted": True, "id": item_id, "permanent": permanent}
    return _guard(run)


def h_use_ssh(args: dict, **kw: Any) -> str:
    """Load an SSH private key from the vault into ssh-agent (v0.2.8).

    Security guarantees:
    - Passphrase delivered via stdin pipe ONLY (subprocess input=...);
      NEVER written to a temp file.
    - Key material: temp file unavoidable (ssh-add reads key from file,
      stdin reserved for passphrase). Created with tempfile.mkstemp()
      (atomic), chmod 0600, deleted in `finally`.
    - Both passphrase and key content registered with RedactingFilter.
    """

    def run():
        name = str(args["name"])
        ssh_auth_sock_param = args.get("ssh_auth_sock")
        auth = kw["auth"]

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

        sock, agent_started = _resolve_socket_path(ssh_auth_sock_param)

        key_path = None
        try:
            fd, key_path = tempfile.mkstemp(suffix=".sshkey", prefix="vw_")
            os.close(fd)
            os.chmod(key_path, 0o600)

            key_path, passphrase = auth.get_ssh_key(item_id, key_path)
            os.chmod(key_path, 0o600)

            redactor = get_redacting_filter()
            redactor.register_secret(passphrase)
            try:
                with open(key_path, "r", encoding="utf-8",
                          errors="replace") as f:
                    redactor.register_secret(f.read())
            except OSError:
                pass

            env = {"SSH_AUTH_SOCK": sock,
                   "HOME": os.environ.get("HOME", "/")}
            proc = subprocess.run(
                ["ssh-add", key_path],
                env=env, input=passphrase,
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode != 0:
                stderr = (proc.stderr or "").strip()
                raise errors.AuthError(
                    f"ssh-add failed (exit {proc.returncode}): {stderr}",
                    suggestion="Check if the passphrase is correct.")

            fp_proc = subprocess.run(
                ["ssh-keygen", "-lf", key_path],
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
                    f"Key loaded. Export SSH_AUTH_SOCK={sock} for "
                    "subsequent SSH commands."),
            }
        finally:
            if key_path and os.path.exists(key_path):
                try:
                    os.unlink(key_path)
                except OSError:
                    pass
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

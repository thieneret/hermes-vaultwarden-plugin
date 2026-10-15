# vaultwarden/tools.py — v0.2.4
"""Tool handlers for the 9 vaultwarden_* tools (plan §8).

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


# --------------------------------------------------------------- handlers
def get_tools(auth: AuthManager, config: PluginConfig,
              registry: PlaceholderRegistry):
    """Yield (schema, handler) for every enabled tool."""

    # ------------------------------------------------------------ status
    def h_status(args: dict, **kw: Any) -> str:
        return _guard(lambda: {"status": auth.status_snapshot(),
                               "placeholders_active": len(registry.active_tokens())})

    yield schemas.VAULTWARDEN_STATUS, h_status

    # ---------------------------------------------------------------- sync
    def h_sync(args: dict, **kw: Any) -> str:
        return _guard(lambda: auth.sync(force=bool(args.get("force"))))

    yield schemas.VAULTWARDEN_SYNC, h_sync

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

    yield schemas.VAULTWARDEN_LIST, h_list

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

    yield schemas.VAULTWARDEN_SEARCH, h_search

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

    yield schemas.VAULTWARDEN_GET_SECRET_REF, h_get_secret_ref

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

    yield schemas.VAULTWARDEN_STORE, h_store

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

    yield schemas.VAULTWARDEN_UPDATE, h_update

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

    yield schemas.VAULTWARDEN_DELETE, h_delete

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

    yield schemas.VAULTWARDEN_GENERATE_PASSWORD, h_generate


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
        login["passwordRevisionDate"] = None
    if args.get("uri"):
        login["uris"] = [{"uri": args["uri"], "match": None}]
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
        login["passwordRevisionDate"] = None
    if args.get("uri"):
        login["uris"] = [{"uri": args["uri"], "match": None}]
    if login:
        merged["login"] = login
    if args.get("custom_fields") is not None:
        existing = [f for f in (merged.get("fields") or [])
                    if f.get("name") not in {cf["name"] for cf in args["custom_fields"]}]
        new = [{"name": cf["name"], "value": cf["value"],
                "type": int(cf.get("field_type", 0))} for cf in args["custom_fields"]]
        merged["fields"] = existing + new
    return merged

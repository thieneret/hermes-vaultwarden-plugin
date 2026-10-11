"""JSON schemas for the 9 vaultwarden_* tools (plan §8).

Handlers receive these as validated ``args`` dicts. None of the schemas
accept or return raw secret values except vaultwarden_generate_password,
which returns a freshly generated password explicitly by design.

Schema key convention (BUG-8 verification note):
The per-tool JSON Schema lives under the "input_schema" key (Anthropic
tool-definition style). The Hermes Agent register_tool() source
(tools/registry.py) is NOT vendored into this repository and could not be
inspected offline, so compatibility was verified structurally instead:

  * every consumer inside this plugin reads only schema["name"] (and the
    whole dict is passed through verbatim as ``schema=``);
  * no code path here depends on the inner key being named
    "input_schema" vs "parameters".

If a deployed Hermes registry expects OpenAI-style "parameters", rename the
key in ONE place below or normalise it at registration time in __init__.py
(e.g. ``schema = {**schema, "parameters": schema["input_schema"]}``).
"""
from __future__ import annotations

ITEM_TYPES = ["login", "note", "card", "identity"]
SECRET_FIELDS = ["password", "username", "totp", "notes", "uri"]

#: Canonical key holding each tool's JSON Schema. See module docstring
#: (BUG-8): switch this single constant if the host Hermes build expects
#: "parameters" instead of the Anthropic-style "input_schema".
SCHEMA_KEY = "input_schema"

VAULTWARDEN_STATUS = {
    "name": "vaultwarden_status",
    "description": (
        "Report Vaultwarden plugin health: auth state machine status, session "
        "activity/age, configured server, isolated appdata dir and write-mode. "
        "Contains no secrets."),
    "input_schema": {"type": "object", "properties": {}, "required": []},
}

VAULTWARDEN_SYNC = {
    "name": "vaultwarden_sync",
    "description": "Force a vault sync against the Vaultwarden server.",
    "input_schema": {
        "type": "object",
        "properties": {
            "force": {"type": "boolean",
                      "description": "Sync even if the auto-sync interval has not elapsed."},
        },
        "required": [],
    },
}

VAULTWARDEN_LIST = {
    "name": "vaultwarden_list",
    "description": (
        "List vault items with METADATA ONLY (id, name, type, username hint, "
        "URIs). Passwords and secret fields are never included."),
    "input_schema": {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ITEM_TYPES,
                     "description": "Filter by item type."},
            "folder_id": {"type": "string", "description": "Filter by folder id."},
            "collection_id": {"type": "string", "description": "Filter by collection id."},
            "limit": {"type": "integer", "minimum": 1, "maximum": 500,
                      "default": 100,
                      # BUG-6 fix: explicit default matching the handler's
                      # `args.get("limit") or 100` behaviour.
                      "description": "Max items to return (default 100)."},
        },
        "required": [],
    },
}

VAULTWARDEN_SEARCH = {
    "name": "vaultwarden_search",
    "description": "Search vault items by name/username/uri; returns metadata only.",
    "input_schema": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search text."},
            "field": {"type": "string", "enum": ["name", "username", "uri"],
                      "description": "Restrict matching to one metadata field."},
            "type": {"type": "string", "enum": ITEM_TYPES},
        },
        "required": ["query"],
    },
}

VAULTWARDEN_GET_SECRET_REF = {
    "name": "vaultwarden_get_secret_ref",
    "description": (
        "Create a single-use placeholder token (__VW_SECRET_xxxxxxxxxxxxxx__) "
        "referencing a secret field of a vault item. Put the placeholder in a "
        "terminal command instead of the real secret; the tool_request "
        "middleware substitutes it at execution time. The secret value is "
        "NEVER returned here."),
    "input_schema": {
        "type": "object",
        "properties": {
            "item_id": {"type": "string",
                        "description": "Item id (uuid) or exact item name."},
            "field": {"type": "string", "enum": SECRET_FIELDS,
                      "description": "Which field the placeholder resolves to."},
            "custom_field_name": {
                "type": "string",
                "description": "If set, resolve this custom field instead of 'field'."},
        },
        "required": ["item_id", "field"],
    },
}

VAULTWARDEN_STORE = {
    "name": "vaultwarden_store",
    "description": ("Create a new vault item. Requires allow_write=true. "
                    "Secret values passed here go straight into bw via the "
                    "encode pipeline and are redacted from all logs."),
    "input_schema": {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ITEM_TYPES},
            "name": {"type": "string"},
            "username": {"type": "string"},
            "password": {"type": "string"},
            "uri": {"type": "string", "description": "Login URI."},
            "notes": {"type": "string"},
            "folder_id": {"type": "string"},
            "custom_fields": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "value": {"type": "string"},
                        "field_type": {"type": "integer", "enum": [0, 1],
                                       "description": "0=text, 1=hidden."},
                    },
                    "required": ["name", "value"],
                },
            },
        },
        "required": ["type", "name"],
    },
}

VAULTWARDEN_UPDATE = {
    "name": "vaultwarden_update",
    "description": ("Update an existing item via fetch-modify-save. Requires "
                    "allow_write=true. Omitted fields stay unchanged."),
    "input_schema": {
        "type": "object",
        "properties": {
            "item_id": {"type": "string"},
            "name": {"type": "string"},
            "username": {"type": "string"},
            "password": {"type": "string"},
            "uri": {"type": "string"},
            "notes": {"type": "string"},
            "custom_fields": VAULTWARDEN_STORE["input_schema"]["properties"]["custom_fields"],
        },
        "required": ["item_id"],
    },
}

VAULTWARDEN_DELETE = {
    "name": "vaultwarden_delete",
    "description": ("Delete a vault item. Soft delete by default; permanent "
                    "deletion requires BOTH permanent=true and confirm=true. "
                    "Requires allow_write=true."),
    "input_schema": {
        "type": "object",
        "properties": {
            "item_id": {"type": "string"},
            "permanent": {"type": "boolean", "default": False},
            "confirm": {"type": "boolean",
                        "description": "Must be true — explicit user confirmation."},
        },
        "required": ["item_id", "confirm"],
    },
}

VAULTWARDEN_GENERATE_PASSWORD = {
    "name": "vaultwarden_generate_password",
    "description": ("Generate a strong password or passphrase with bw. The "
                    "ONLY tool that intentionally returns a secret value "
                    "(freshly generated, not read from the vault)."),
    "input_schema": {
        "type": "object",
        "properties": {
            "mode": {"type": "string", "enum": ["password", "passphrase"],
                     "default": "password"},
            "length": {"type": "integer", "minimum": 8, "maximum": 128,
                       "description": "Password length (mode=password)."},
            "uppercase": {"type": "boolean", "default": True},
            "lowercase": {"type": "boolean", "default": True},
            "numbers": {"type": "boolean", "default": True},
            "special": {"type": "boolean", "default": True},
            "words": {"type": "integer", "minimum": 3, "maximum": 20,
                      "description": "Word count (mode=passphrase)."},
            "separator": {"type": "string", "description": "Passphrase separator."},
        },
        "required": [],
    },
}

TOOL_SCHEMAS = [
    VAULTWARDEN_STATUS,
    VAULTWARDEN_SYNC,
    VAULTWARDEN_LIST,
    VAULTWARDEN_SEARCH,
    VAULTWARDEN_GET_SECRET_REF,
    VAULTWARDEN_STORE,
    VAULTWARDEN_UPDATE,
    VAULTWARDEN_DELETE,
    VAULTWARDEN_GENERATE_PASSWORD,
]

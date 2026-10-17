# vaultwarden/schemas.py — v0.2.8
"""JSON schemas for the vaultwarden_* tools (plan §8).

Handlers receive these as validated `args` dicts. None of the schemas
accept or return raw secret values except vaultwarden_generate_password,
which returns a freshly generated password explicitly by design.

Schema key convention (BUG-8 — RESOLVED in v0.2.6):
The per-tool JSON Schema lives under the "parameters" key (OpenAI
tool-definition style). The deployed Hermes Agent registry was confirmed
to expect this key via live `tool_describe` output: when the schemas
used the Anthropic-style "input_schema" key, every tool showed empty
properties and required lists. Switched to "parameters" in v0.2.6.
"""
from __future__ import annotations

ITEM_TYPES = ["login", "securenote", "card", "identity", "sshkey"]
SECRET_FIELDS = ["password", "username", "totp", "notes", "uri", "privateKey"]

#: Canonical key holding each tool's JSON Schema. The deployed Hermes Agent
#: registry expects the OpenAI-style "parameters" key (confirmed via live
#: tool_describe output — v0.2.6).
SCHEMA_KEY = "parameters"

VAULTWARDEN_STATUS = {
    "name": "vaultwarden_status",
    "description": (
        "Report Vaultwarden plugin health: auth state machine status, session "
        "activity/age, configured server, isolated appdata dir and write-mode. "
        "Contains no secrets."),
    "parameters": {"type": "object", "properties": {}, "required": []},
}

VAULTWARDEN_SYNC = {
    "name": "vaultwarden_sync",
    "description": "Force a vault sync against the Vaultwarden server.",
    "parameters": {
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
    "parameters": {
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
    "parameters": {
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
    "parameters": {
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
    "parameters": {
        "type": "object",
        "properties": {
            # v0.2.6: "type" is optional — the handler defaults to "login"
            # via args.get("type", "login").
            "type": {"type": "string", "enum": ITEM_TYPES, "default": "login"},
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
        "required": ["name"],
    },
}

VAULTWARDEN_STORE_SSH = {
    "name": "vaultwarden_store_ssh",
    "description": (
        "Create a new SSH key vault item (type 5). Requires allow_write=true. "
        "WARNING: Bitwarden/Vaultwarden stores the private key WITHOUT passphrase "
        "encryption — if the vault is compromised, the SSH key can be used immediately. "
        "The private key is redacted from all logs. "
        "Secret values passed here go straight into bw via the encode pipeline."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "name": {"type": "string", "description": "Item name (required)."},
            "private_key": {
                "type": "string",
                "description": (
                    "SSH private key content (e.g., '-----BEGIN OPENSSH PRIVATE KEY-----\\n...'). "
                    "Can be a placeholder token from vaultwarden_get_secret_ref."
                ),
            },
            "public_key": {
                "type": "string",
                "description": "SSH public key (e.g., 'ssh-ed25519 AAAA... user@host').",
            },
            "key_fingerprint": {
                "type": "string",
                "description": "Key fingerprint (e.g., 'SHA256:xxx'). Auto-generated if omitted.",
            },
            "notes": {"type": "string", "description": "Optional notes."},
            "folder_id": {"type": "string", "description": "Folder UUID."},
        },
        "required": ["name", "private_key"],
    },
}

VAULTWARDEN_UPDATE = {
    "name": "vaultwarden_update",
    "description": ("Update an existing item via fetch-modify-save. Requires "
                    "allow_write=true. Omitted fields stay unchanged."),
    "parameters": {
        "type": "object",
        "properties": {
            "item_id": {"type": "string"},
            "name": {"type": "string"},
            "username": {"type": "string"},
            "password": {"type": "string"},
            "uri": {"type": "string"},
            "notes": {"type": "string"},
            "custom_fields": VAULTWARDEN_STORE["parameters"]["properties"]["custom_fields"],
        },
        "required": ["item_id"],
    },
}

VAULTWARDEN_DELETE = {
    "name": "vaultwarden_delete",
    "description": ("Delete a vault item. Soft delete by default; permanent "
                    "deletion requires BOTH permanent=true and confirm=true. "
                    "Requires allow_write=true."),
    "parameters": {
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
    "parameters": {
        "type": "object",
        "properties": {
            "mode": {"type": "string", "enum": ["password", "passphrase"],
                     "default": "password"},
            "length": {"type": "integer", "minimum": 8, "maximum": 128,
                       "default": 20,
                       "description": "Password length (mode=password)."},
            "uppercase": {"type": "boolean", "default": True},
            "lowercase": {"type": "boolean", "default": True},
            "numbers": {"type": "boolean", "default": True},
            "special": {"type": "boolean", "default": True},
            "words": {"type": "integer", "minimum": 3, "maximum": 20,
                      "default": 4,
                      "description": "Word count (mode=passphrase)."},
            "separator": {"type": "string", "default": "-",
                          "description": "Passphrase separator."},
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
    VAULTWARDEN_STORE_SSH,  # NEW in v0.2.8
    VAULTWARDEN_UPDATE,
    VAULTWARDEN_DELETE,
    VAULTWARDEN_GENERATE_PASSWORD,
]

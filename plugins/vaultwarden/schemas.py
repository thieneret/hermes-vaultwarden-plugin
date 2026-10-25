"""JSON schemas for the 12 vaultwarden_* tools (plan §8).

Handlers receive these as validated `args` dicts. No schema accepts or
returns raw secret values in its RESPONSE (v0.3.7, VWP-12): password
generation is integrated into vaultwarden_store / vaultwarden_update via
the `generate=true` parameter — the generated value goes directly into
the vault item and only a placeholder is returned.

Schema key convention (BUG-8 — RESOLVED in v0.2.6):
The per-tool JSON Schema lives under the "parameters" key (OpenAI
tool-definition style). The deployed Hermes Agent registry was confirmed
to expect this key via live `tool_describe` output: when the schemas
used the Anthropic-style "input_schema" key, every tool showed empty
properties and required lists. Switched to "parameters" in v0.2.6.
"""
from __future__ import annotations

ITEM_TYPES = ["login", "note", "card", "identity"]
SECRET_FIELDS = ["password", "username", "totp", "notes", "uri"]

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
        "Create a single-use placeholder reference ($__VW_SECRET_xxxxxxxxxxxxxx__) "
        "pointing at a secret field of a vault item. Put the reference in a "
        "terminal command INSIDE DOUBLE QUOTES (never single quotes); the "
        "tool_execution middleware injects the real secret via a temp file "
        "($(< path)) at execution time. The secret value is "
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

_GENERATE_PROPERTIES = {
    "generate": {
        "type": "boolean",
        "default": False,
        "description": (
            "Generate a password instead of using the password field. "
            "The generated password is stored directly in the vault and "
            "never returned to the caller. Mutually exclusive with "
            "password/password_file."),
    },
    "generate_options": {
        "type": "object",
        "description": "Password generation options. Used only when generate=true.",
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["password", "passphrase"],
                "default": "password"
            },
            "length": {"type": "integer", "default": 20},
            "words": {"type": "integer", "default": 4},
            "separator": {"type": "string", "default": "-"},
            "uppercase": {"type": "boolean", "default": True},
            "lowercase": {"type": "boolean", "default": True},
            "numbers": {"type": "boolean", "default": True},
            "special": {"type": "boolean", "default": True}
        }
    }
}

#: v0.4.0 (Feature 1): secret-input channel descriptions shared by the
#: store/update password pair and the SSH passphrase pair.
#: v0.4.9 (BREAKING CHANGE): the *_env channels were removed — only the
#: raw and *_file channels remain.
_PASSWORD_DIRECT_DESC = (
    "Password. Passing it RAW here is NOT secure: the value enters the LLM "
    "context and chat history, the plugin logs a warning AND returns a "
    "'warning' field in the tool response (relay it to the user). Prefer "
    "password_file. Mutually exclusive with password_file."
)
_PASSWORD_FILE_DESC = (
    "Path to a file holding the password; must be owner-readable only "
    "(chmod 600); mutually exclusive with password."
)
_PASS_DIRECT_DESC = (
    "SSH key passphrase. Passing it RAW here is NOT secure: the value "
    "enters the LLM context and chat history, the plugin logs a warning AND "
    "returns a 'warning' field in the tool response (relay it to the user). "
    "Prefer pass_file. Mutually exclusive with "
    "pass_file. Forbidden when generate=true."
)
_PASS_FILE_DESC = (
    "Path to a file holding the passphrase; must be owner-readable only "
    "(chmod 600); mutually exclusive with pass. Forbidden when "
    "generate=true."
)
_SSH_GENERATE_PROPERTIES = {
    "generate": {
        "type": "boolean",
        "default": False,
        "description": (
            "Generate a new SSH keypair inside the plugin: a 32-char "
            "passphrase is produced via the same `bw generate` path used by "
            "store/update generate=true, the keypair via ssh-keygen "
            "(passphrase delivered on stdin, never argv). The private key "
            "is stored as an attachment and the passphrase as the item "
            "password; ONLY the public key + fingerprint (non-secret) are "
            "returned. In generate mode pass/pass_file/file are "
            "forbidden."),
    },
    "key_type": {
        "type": "string",
        "enum": ["ed25519", "rsa"],
        "default": "ed25519",
        "description": "SSH key type for generate=true. Default ed25519.",
    },
    "rsa_bits": {
        "type": "integer",
        "default": 4096,
        "description": ("RSA key size in bits, used only when "
                        "key_type='rsa'. Default 4096."),
    },
}


VAULTWARDEN_STORE = {
    "name": "vaultwarden_store",
    "description": ("Create a new vault item. Requires allow_write=true. "
                    "Secret values passed here go straight into bw via the "
                    "encode pipeline and are redacted from all logs. "
                    "Supports generate=true to auto-generate a password "
                    "stored directly in the vault (never returned). "
                    "Passwords can be supplied via password_file (owner-only "
                    "file, chmod 600) to keep them out of the LLM context; "
                    "raw password input is allowed but returns a 'warning' "
                    "field."),
    "parameters": {
        "type": "object",
        "properties": {
            # v0.2.6: "type" is optional — the handler defaults to "login"
            # via args.get("type", "login").
            "type": {"type": "string", "enum": ITEM_TYPES, "default": "login"},
            "name": {"type": "string"},
            "username": {"type": "string"},
            "password": {"type": "string",
                         "description": _PASSWORD_DIRECT_DESC},
            "password_file": {"type": "string",
                              "description": _PASSWORD_FILE_DESC},
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
            **_GENERATE_PROPERTIES,
        },
        "required": ["name"],
    },
}

VAULTWARDEN_UPDATE = {
    "name": "vaultwarden_update",
    "description": ("Update an existing item via fetch-modify-save. Requires "
                    "allow_write=true. Omitted fields stay unchanged. "
                    "Supports generate=true to regenerate the password, "
                    "stored directly in the vault (never returned). "
                    "Passwords can be supplied via password_file (owner-only "
                    "file, chmod 600) to keep them out of the LLM context; "
                    "raw password input is allowed but returns a 'warning' "
                    "field."),
    "parameters": {
        "type": "object",
        "properties": {
            "item_id": {"type": "string"},
            "name": {"type": "string"},
            "username": {"type": "string"},
            "password": {"type": "string",
                         "description": _PASSWORD_DIRECT_DESC},
            "password_file": {"type": "string",
                              "description": _PASSWORD_FILE_DESC},
            "uri": {"type": "string"},
            "notes": {"type": "string"},
            "custom_fields": VAULTWARDEN_STORE["parameters"]["properties"]["custom_fields"],
            **_GENERATE_PROPERTIES,
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

VAULTWARDEN_STORE_SSH = {
    "name": "vaultwarden_store_ssh",
    "description": (
        "Store an SSH private key in the vault as a login item with file "
        "attachment. The username holds the SSH user, the password holds "
        "the key passphrase, and the key file is stored as an attachment. "
        "Requires allow_write=true. Name must be unique. "
        "v0.4.0: supports generate=true — the plugin generates a 32-char "
        "passphrase (same `bw generate` path as store/update) and an SSH "
        "keypair via ssh-keygen (passphrase delivered on stdin), stores "
        "both in the vault, and returns ONLY the public key + fingerprint. "
        "In generate mode pass/pass_file/file are forbidden. "
        "Without generate, the passphrase can come from pass (raw — warns "
        "in log AND response) or pass_file (chmod 600)."),
    "parameters": {
        "type": "object",
        "properties": {
            "name": {"type": "string",
                     "description": "Unique item name (e.g. 'SSH - Production')."},
            "user": {"type": "string",
                     "description": ("SSH username (e.g. 'deploy', 'root'). "
                                     "Optional when generate=true.")},
            "pass": {"type": "string",
                     "description": _PASS_DIRECT_DESC},
            "pass_file": {"type": "string",
                          "description": _PASS_FILE_DESC},
            "file": {"type": "string",
                     "description": ("Absolute path to the SSH private key "
                                     "file. Forbidden when generate=true.")},
            "folder_id": {"type": "string",
                          "description": "Optional folder UUID."},
            "notes": {"type": "string",
                      "description": "Optional description."},
            **_SSH_GENERATE_PROPERTIES,
        },
        # v0.4.0: "user"/"pass"/"file" are no longer unconditionally
        # required — generate=true supplies them internally, and the
        # passphrase may arrive via pass_file instead of raw pass.
        # The handlers enforce the per-mode requirements at runtime.
        "required": ["name"],
    },
}

VAULTWARDEN_UPDATE_SSH = {
    "name": "vaultwarden_update_ssh",
    "description": (
        "Update an existing SSH key item. Can update user, passphrase, "
        "and/or the key file attachment. Requires allow_write=true. "
        "v0.4.0: generate=true performs a destructive KEY ROTATION (new "
        "keypair + new 32-char passphrase generated by the plugin, same "
        "`bw generate` path as store/update) and REQUIRES confirm=true; it "
        "returns only the new public key + fingerprint. In generate mode "
        "pass/pass_file/file are forbidden. Without generate, the "
        "passphrase can come from pass (raw — warns in log AND response) "
        "or pass_file (chmod 600)."),
    "parameters": {
        "type": "object",
        "properties": {
            "name": {"type": "string",
                     "description": "Item name to update."},
            "user": {"type": "string",
                     "description": "New SSH username (optional)."},
            "pass": {"type": "string",
                     "description": _PASS_DIRECT_DESC},
            "pass_file": {"type": "string",
                          "description": _PASS_FILE_DESC},
            "file": {"type": "string",
                     "description": ("New SSH key file path (optional). "
                                     "Forbidden when generate=true.")},
            "notes": {"type": "string",
                      "description": "New description (optional)."},
            **_SSH_GENERATE_PROPERTIES,
            "confirm": {"type": "boolean",
                        "description": ("Must be true when generate=true — "
                                        "key rotation is destructive and "
                                        "requires explicit confirmation.")},
        },
        "required": ["name"],
    },
}

VAULTWARDEN_DELETE_SSH = {
    "name": "vaultwarden_delete_ssh",
    "description": (
        "Delete an SSH key item (including its attachment). Requires "
        "allow_write=true and confirm=true."),
    "parameters": {
        "type": "object",
        "properties": {
            "name": {"type": "string",
                     "description": "Item name to delete."},
            "confirm": {"type": "boolean",
                        "description": "Must be true — explicit confirmation."},
            "permanent": {"type": "boolean", "default": False,
                          "description": "Permanently delete (skip trash)."},
        },
        "required": ["name", "confirm"],
    },
}

VAULTWARDEN_USE_SSH = {
    "name": "vaultwarden_use_ssh",
    # VWP-02 (v0.4.6): the LLM-controlled `ssh_auth_sock` parameter was
    # REMOVED — it enabled local process/socket takeover attacks. The socket
    # path is now resolved from developer-controlled environment variables
    # only (see tools._resolve_socket_path). Tool description intentionally
    # carries no socket-behavior details.
    "description": (
        "Load an SSH private key from the vault into ssh-agent."),
    "parameters": {
        "type": "object",
        "properties": {
            "name": {"type": "string",
                     "description": "SSH key item name to load."},
        },
        "required": ["name"],
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
    # v0.3.7 (VWP-12): VAULTWARDEN_GENERATE_PASSWORD removed — generation
    # is integrated into STORE/UPDATE via generate=true.
    # v0.2.8: SSH key management
    VAULTWARDEN_STORE_SSH,
    VAULTWARDEN_UPDATE_SSH,
    VAULTWARDEN_DELETE_SSH,
    VAULTWARDEN_USE_SSH,
]

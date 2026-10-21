---
name: vaultwarden-usage
description: "vaultwarden: secrets via env-injected placeholder tokens, ssh-add, git, password/key generation via store/update"
version: 2.0.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [vaultwarden, secrets, security, terminal, ssh, git]
    category: security
---

# Vaultwarden Secret Management

> Minimum vaultwarden plugin version: **v0.4.4** (12 tools). This skill targets
> the env-injection architecture (`$__VW_SECRET_x__` placeholders).

## When to Use

Use when a terminal command needs a password, API key, token, or SSH passphrase
(e.g. `git clone`, `curl`, `ssh-add`, API requests), when SSH keys must be
stored/retrieved/generated/loaded into ssh-agent, or when a new credential must
be created (use `generate=true` so the secret never enters your context).

Trigger keywords: password, secret, token, API key, passphrase, vaultwarden,
credential, ssh-add, git clone, ssh key, ssh agent, generate password,
generate ssh key, key rotation.

## When NOT to Use

- Reading/writing local files that don't need credentials (`read_file` / `write_file`)
- Generating random strings for non-credential purposes (`terminal` + `openssl rand`)
- Listing environment variables already loaded by the Hermes process (`terminal` + `env`)

## Core Security Rule

**NEVER attempt to read, extract, or output raw secret values.**

The plugin uses **env-injected placeholder tokens**: you only ever see opaque
`$__VW_SECRET_xxxx__` tokens. At execution time the middleware injects the real
secret into the terminal call's `env` as a `VW_TOKEN_xxxx` variable and rewrites
the command to reference it — the raw secret never enters your context window,
the command string, shell history, or `ps` output.

**There is NO escape hatch.** No tool returns a raw stored secret under any
configuration. For SSH keys, `vaultwarden_use_ssh` handles everything internally
— the key and passphrase never enter your context.

## Pre-Flight Checklist (MANDATORY)

- [ ] `vaultwarden_status` → expect `auth_state: unlocked`, `session_active: true`; if it fails, do NOT proceed
- [ ] If the `vaultwarden_*` tools are **missing entirely**, the plugin failed to start (`bw` CLI below the enforced minimum **2026.9.1** or unparseable). Tell the user to upgrade the Bitwarden CLI; no workaround (fail-closed by design)
- [ ] Identify the item via `vaultwarden_search` BEFORE requesting a placeholder
- [ ] For write operations (`store`, `update`, `delete`, `*_ssh`, any `generate=true`): verify `allow_write: true` in status output

## Available Tools (12)

| Tool | Purpose |
| --- | --- |
| `vaultwarden_status` | Plugin health, auth state, session info |
| `vaultwarden_sync` | Force vault sync |
| `vaultwarden_list` | List items (metadata only) |
| `vaultwarden_search` | Search by name/username/uri |
| `vaultwarden_get_secret_ref` | Single-use placeholder token (returned with `$` prefix) |
| `vaultwarden_store` | Create item. `generate=true` (password) or `password_env`/`password_file` input |
| `vaultwarden_update` | Update item. `generate=true` or `password_env`/`password_file` input |
| `vaultwarden_delete` | Delete item (requires `confirm: true`) |
| `vaultwarden_store_ssh` | Store SSH key. `generate=true` (keypair) or `pass_env`/`pass_file` input |
| `vaultwarden_update_ssh` | Update SSH key. `generate=true` (rotation, needs `confirm`) or `pass_env`/`pass_file` |
| `vaultwarden_delete_ssh` | Delete SSH key (requires `confirm: true`) |
| `vaultwarden_use_ssh` | Load SSH key from vault into ssh-agent |

## Password generation (`generate=true` on store/update)

Generates a strong password via `bw generate`, stores it directly in the vault,
returns **only a placeholder** (`password_placeholder`, `$`-prefixed). Optional
`generate_options`: `mode` (`password`|`passphrase`), `length` (20), `words` (4),
`separator` ("-"), `uppercase`/`lowercase`/`numbers`/`special` (true). Requires
`allow_write: true`.

## SSH key generation (`generate=true` on store_ssh/update_ssh)

The plugin generates a 32-char passphrase and a keypair internally; the private
key + passphrase go to the vault, **only the public key + fingerprint are
returned** (paste the public key into `authorized_keys`). Parameters:
`key_type` (`ed25519` default | `rsa`), `rsa_bits` (default **4096**, rsa only).
In generate mode `pass`/`pass_env`/`pass_file`/`file` are **forbidden**.
`update_ssh` + `generate=true` is a **key rotation** and requires `confirm=true`.

## Secret input channels (store/update + ssh_store/ssh_update)

Three mutually-exclusive sources per secret; supplying more than one is a
`ConfigError`:

| Source | Param (store/update) | Param (ssh) | Notes |
| --- | --- | --- | --- |
| Env var | `password_env` | `pass_env` | Name of a var in the Hermes process env (e.g. `~/.hermes/.env`) |
| Owner-only file | `password_file` | `pass_file` | Must be chmod 600 (owner-read only); rejected otherwise |
| Raw value | `password` | `pass` | **Discouraged** — response carries a `"warning"` field to relay to the user |

## Standard Workflow (3 Steps)

1. `vaultwarden_search(query="github")` → metadata (id, name, username), NOT the password
2. `vaultwarden_get_secret_ref(item_id="<uuid>", field="password")` → `{"placeholder": "$__VW_SECRET_a1b2c3d4e5f6__", "ttl_seconds": 300}`
3. Place the placeholder inside a **double-quoted** terminal command:
   `terminal(command="git clone https://myuser:$__VW_SECRET_a1b2c3d4e5f6__@github.com/org/repo.git")`
   The middleware injects the real secret as an env var and rewrites the reference.

**Critical:** the placeholder reference is expanded by the shell, so it MUST be
inside double quotes (or unquoted). Single quotes prevent expansion and break the
injection. See `references/architecture.md`.

## Important Constraints

| Constraint | Details |
| --- | --- |
| Single-Use | Placeholders are consumed after one execution; retry needs a NEW one |
| TTL | Placeholders expire after 5 minutes (300s) |
| No Direct Retrieval | No tool ever returns a raw stored secret |
| Double quotes | Placeholder references MUST be double-quoted (or unquoted); never single-quoted |
| One per command | Never store placeholders in variables; never reuse across commands |
| Multiple fields | Username AND password → two separate placeholders |
| SSH name uniqueness | `store_ssh` rejects duplicate names |
| Generated secrets | `generate=true` stores the secret in the vault; only a placeholder/public key is returned |
| Conflict = error | Two secret sources at once → `ConfigError`, not silent precedence |

## DO NOT

- ❌ NEVER read, extract, or output raw secret values
- ❌ NEVER reuse a placeholder across commands, or store it in a variable
- ❌ NEVER place a placeholder inside single quotes (shell won't expand it)
- ❌ NEVER echo/cat/grep a placeholder to "verify" it (logging risk)
- ❌ NEVER request a placeholder "just in case" — only when a concrete command is ready
- ❌ NEVER retry a failed command with the same placeholder (it's consumed)
- ❌ NEVER read the SSH key file after `use_ssh` loads it
- ❌ NEVER pass a raw `password`/`pass` when `*_env`/`*_file` is available — if you must, relay the response `"warning"` to the user
- ❌ NEVER pass `pass`/`file` alongside `generate=true` on an SSH tool (ConfigError)
- ❌ NEVER rotate an SSH key (`update_ssh` + `generate=true`) without `confirm=true`

## References (load on demand)

- **Examples** (concrete tool calls for every flow): `references/examples.md`
- **Troubleshooting** (error recovery, best practices, verification): `references/troubleshooting.md`
- **Architecture** (env-injection internals and the double-quote rule): `references/architecture.md`

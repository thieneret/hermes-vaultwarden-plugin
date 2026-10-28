# Vaultwarden Plugin for Hermes Agent

**Current version: v0.5.3**

> ⚠️ **WARNING: This entire plugin was developed through AI-assisted coding sessions without
> traditional manual code review of every line. Use at your own
> risk. Audit before production deployment.**
>>
> ⚠️ This is my first "vibe-coded" program, intended primarily for my own use. Use it entirely at your own risk!
>
> ⚠️ AI audit results: [Qwen](https://github.com/thieneret/hermes-vaultwarden-plugin/blob/9cf9f22d0abbb694affe22f98dd8c5dfa31688c6/audit/v0.3.2%20audit%20by%20Qwen3.8-max.md) [ChatGPT](https://github.com/thieneret/hermes-vaultwarden-plugin/blob/9cf9f22d0abbb694affe22f98dd8c5dfa31688c6/audit/v0.3.2%20audit%20by%20ChatGPT.md)
>
> ⚠️ **Security:** See [SECURITY.md](SECURITY.md) for the full threat model
> and security guarantees.

Secure secrets management for Hermes Agent via Vaultwarden. Provides safe
access to vault items through a placeholder injection architecture, plus SSH
key storage and ssh-agent integration.

## Features

- **12 registered tools** covering vault read/write, secret references, and SSH key management
- **Placeholder injection** — raw secrets never enter the agent's context window
- **SSH key management** — store private keys as vault attachments, load them into ssh-agent on demand
- **Bitwarden CLI integration** — all vault operations go through the audited `bw` binary
- **Session isolation** — the Bitwarden session key lives only in plugin memory, never on disk
- **Write protection** — mutating operations are gated behind an explicit `allow_write` flag
- **Log redaction** — every secret that passes through the plugin is registered with a redacting filter

## Requirements

| Dependency | Purpose |
| --- | --- |
| Hermes Agent | Host platform (plugin API) |
| Bitwarden CLI (`bw`) | Vault operations (login, sync, CRUD). **Minimum version: 2026.9.1** (enforced at startup; plugin refuses to load below this) |
| Vaultwarden server | Backend (any Bitwarden-compatible instance) |
| OpenSSH ≥ 8.4 | SSH features (`ssh-add`, `ssh-keygen`) — `SSH_ASKPASS_REQUIRE=force` passphrase delivery |

## Installation

### Prerequisites

- **Hermes Agent** — host platform
- **Bitwarden CLI** (`bw`) — installed and accessible
- **OpenSSH ≥ 8.4** — required for SSH key management tools
- **Python 3.10+** — required for development and testing

### Production (Hermes Agent)

Copy the plugin directory into your Hermes plugins folder:

```
cp -r plugins/vaultwarden ~/.hermes/plugins/vaultwarden
```

Then configure `~/.hermes/config.yaml` (see Configuration section)
and restart Hermes.

### Development & Testing

To run the test suite or contribute, install the repository as an
editable package with development dependencies.

**Using `pip`:**

```
git clone <repository-url>
cd hermes-vaultwarden-plugin
pip install -e ".[dev]"
```

**Using `uv` (recommended):**

```
git clone <repository-url>
cd hermes-vaultwarden-plugin
uv pip install -e ".[dev]"
```

This installs `pytest`, `ruff`, and `mypy` without affecting the
production Hermes runtime.

## Configuration

### `config.yaml`

Plugin settings live under `plugins.entries.vaultwarden.settings`:

```yaml
plugins:
  enabled:
    - vaultwarden
  entries:
    vaultwarden:
      settings:
        enabled: true
        server_url: "https://vault.example.com"
        client_id: "user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        allow_write: false
        allow_startup_secret_injection: false
        auto_sync: true
        sync_interval_seconds: 300
        session_timeout_seconds: 14400
        placeholder_ttl_seconds: 300
        max_placeholders: 50
        bw_cli_path: "/usr/local/bin/bw"   # REQUIRED, absolute path
        metadata_masking: false
        bw_max_retries: 3
        bw_backoff_base: 1.0
        bw_max_delay: 10.0
```

### `secrets.yaml` (bootstrap secrets)

Bootstrap secrets are loaded from a plugin-private YAML file that the plugin
reads directly — **never** from `.env` or OS environment variables:

```
$HERMES_HOME/plugins/vaultwarden/secrets.yaml   # chmod 600 (enforced)
```

Setup: copy the shipped template, fill in the values, and lock down
permissions:

```bash
mkdir -p ~/.hermes/plugins/vaultwarden
cp plugins/vaultwarden/secret.yaml.template ~/.hermes/plugins/vaultwarden/secrets.yaml
chmod 600 ~/.hermes/plugins/vaultwarden/secrets.yaml
# then edit secrets.yaml:
#   client_secret: "your-client-secret"
#   master_password: "your-master-password"
```

The plugin validates the file at startup: it must exist, be exactly mode
`0600`, and contain non-empty `client_secret` and `master_password` values;
otherwise it fails closed with a `ConfigError`.

The secrets never enter the OS environment or the Hermes secret_scope, which
closes the `printenv` and `cat .env` attack surfaces.

> **Residual risk:** if the terminal backend is `local`, the LLM runs as the
> same OS user and could still `cat secrets.yaml`. The plugin logs a WARNING
> in that case — for production, use a sandboxed backend (`docker` / `ssh` /
> `modal`) for privilege separation.

### Startup secret injection (optional, disabled by default)

The plugin can optionally expose a fixed, pre-configured set of vault items
as environment-style secrets to Hermes at **startup** via the `SecretSource`
adapter. This is intended for consumers that read secrets from environment
variables at process start (e.g. legacy apps), and is **not** a replacement
for the runtime placeholder injection used by tools.

The feature is controlled by two settings under
`plugins.entries.vaultwarden.settings`:

```yaml
allow_startup_secret_injection: true
startup_injections:
  - item_id: "abc-123-def"   # vault item UUID
    field: "password"        # password | username | totp | notes | uri
    env: "DB_PASSWORD"       # env-style key exposed at startup (optional)
  - item_id: "xyz-456-ghi"
    field: "username"
    env: "DB_USER"
```

| Setting | Default | Effect |
| --- | --- | --- |
| `allow_startup_secret_injection` | `false` | Master switch for the SecretSource adapter. When `false`, no startup secrets are exposed. |
| `startup_injections` | `[]` | List of `{item_id, field, env}` mappings. Only explicitly listed item/field pairs are reachable. If `env` is omitted, a key of the form `VW_<item_id prefix>` is used. |

Behavior and guarantees:

- **Read-only:** the adapter only reads vault items; it never writes.
- **Explicit allowlist:** only configured `item_id`/`field` pairs are exposed — there is no way to enumerate or fetch arbitrary items through this adapter.
- **Fail-safe:** any retrieval error results in that secret being skipped and a warning logged; agent startup is never crashed.
- **Redacted:** injected secret values are registered with the redacting filter so they do not leak into logs.
- **Does not replace placeholder injection:** tool calls still use the single-use `$__VW_SECRET_x__` placeholder flow at runtime.

> **Security note:** secrets injected at startup enter the process
> environment of the host application. Prefer the runtime placeholder model
> (`vaultwarden_get_secret_ref`) whenever possible, and enable this adapter
> only when a consumer strictly requires startup-time environment variables.

### Key settings

| Setting | Effect |
| --- | --- |
| `enabled` | Master switch. Default: `false` |
| `server_url` | Vaultwarden server URL (required) |
| `client_id` | API-key client id, format `user.<uuid>` (required) |
| `allow_write` | Enables `store`/`update`/`delete` operations. Default: `false` |
| `auto_sync` | Sync vault before read operations. Default: `true` |
| `sync_interval_seconds` | Auto-sync interval. Default: `300` |
| `session_timeout_seconds` | Vault session lifetime. Default: `14400` (4h) |
| `placeholder_ttl_seconds` | Placeholder token lifetime. Default: `300` (5min) |
| `max_placeholders` | Maximum active placeholders. Default: `50` |
| `bw_cli_path` | **REQUIRED** FULL absolute path to the `bw` binary (e.g. `/usr/local/bin/bw`). There is NO PATH lookup and NO environment-variable override — config.yaml is the single source of truth. The path is validated before use: absolute, regular file, no symlink anywhere in the chain, executable, not group/world-writable, owned by root or the current user. If missing or invalid the plugin fails closed (does not load; the agent continues without it). |
| `metadata_masking` | When `true`, `vaultwarden_list` and `vaultwarden_search` mask `username` and `uris` with `***`. `name` is never masked. Default: `false` |
| `allow_startup_secret_injection` | Register the optional SecretSource adapter for startup-time secret injection. Default: `false` (disabled). See the Startup secret injection section. |
| `bw_max_retries` | Max retry attempts for idempotent `bw` calls on network errors. Default: `3` |
| `bw_backoff_base` | Base delay (seconds) for exponential backoff. Default: `1.0` |
| `bw_max_delay` | Maximum delay cap (seconds). Default: `10.0` |

## Tools

### Core tools

| Tool | Purpose | Requires `allow_write` |
| --- | --- | :-: |
| `vaultwarden_status` | Plugin health: auth state, session, server config | ❌ |
| `vaultwarden_sync` | Sync vault (`force=true` bypasses auto-sync interval) | ❌ |
| `vaultwarden_list` | List items — metadata only | ❌ |
| `vaultwarden_search` | Search items by name/username/uri — metadata only | ❌ |
| `vaultwarden_get_secret_ref` | Generate a single-use placeholder token | ❌ |
| `vaultwarden_store` | Create a new vault item. Supports `generate=true` to auto-generate a password stored directly in the vault; password can be supplied via `password_file` to keep it out of the LLM context. | ✅ |
| `vaultwarden_update` | Update an existing item. Supports `generate=true` to regenerate the password, stored directly in the vault; password can be supplied via `password_file` to keep it out of the LLM context. | ✅ |
| `vaultwarden_delete` | Delete an item (`confirm=true` required) | ✅ |

### SSH key management tools

| Tool | Purpose | Requires `allow_write` |
| --- | --- | :-: |
| `vaultwarden_store_ssh` | Store SSH key as login item + attachment (name must be unique). Supports `generate=true` to generate a keypair internally and return the public key; passphrase via `pass_file`. | ✅ |
| `vaultwarden_update_ssh` | Update user/passphrase/key attachment. Supports `generate=true` for key rotation (`confirm=true` required); returns the new public key; passphrase via `pass_file`. | ✅ |
| `vaultwarden_delete_ssh` | Delete SSH key item (attachment included) | ✅ |
| `vaultwarden_use_ssh` | Load SSH key into ssh-agent (socket path resolved from developer-controlled env vars, see SSH Agent Socket) | ❌ |

## Placeholder Injection (security model)

Raw secrets are never exposed to the agent. Instead:

```
1. vaultwarden_search(query="github")              → metadata only
2. vaultwarden_get_secret_ref(item_id, field)      → $__VW_SECRET_xxxx__
3. terminal(command="curl -H \"Bearer $__VW_SECRET_xxxx__\" ...")
   ↑ tool_execution middleware writes the real secret to a temp file in
     $XDG_RUNTIME_DIR/vw-secrets/ (chmod 600, mkstemp) and rewrites the
     command to read from it via $(< path); the shell expands it at
     execution time and the file is deleted in a finally block
```

The placeholder reference MUST be double-quoted (or unquoted) — never single
quotes — so the shell expands the `$(< path)` substitution.

- Placeholders are **single-use** and expire after `placeholder_ttl_seconds`
- The real secret is injected only at the moment of command execution
- The raw secret never appears in the command string, argv, shell history, or logs
- Every secret is registered with a redacting filter so it cannot leak into logs

## SSH Key Management

SSH private keys are stored as login items with a file attachment:

| Vault field | Meaning |
| --- | --- |
| `name` | Item name (must be unique) |
| `username` | SSH user (e.g. `deploy`, `root`) |
| `password` | SSH key passphrase |
| attachment | SSH private key file (original filename) |

### Store a key

```
vaultwarden_store_ssh(name="SSH - Production", user="deploy",
                      pass_file="/run/secrets/ssh_pass",
                      file="/path/to/id_ed25519")
```

### Load a key into ssh-agent

```
vaultwarden_use_ssh(name="SSH - Production")
```

The passphrase is delivered via the `SSH_ASKPASS` mechanism (see Security
Architecture below) — never via stdin, argv, or a file; the key uses an atomic
temp file (`mkstemp`, `0600`) deleted in a `finally` block.

### SSH Agent Socket

The `vaultwarden_use_ssh` tool resolves the ssh-agent socket via a
developer-controlled mechanism (NOT configurable by the LLM):

1. **`$VW_SSH_SOCKET_PATH`** env var (if set): the socket is created/reused
   at this path. This allows sharing the socket with external tools (e.g.
   an ssh-mcp server).
2. **`$XDG_RUNTIME_DIR/auth.sock`** (fallback): if `$VW_SSH_SOCKET_PATH`
   is unset, the socket is created/reused here.

If an agent is already running at the resolved socket, it is reused.
Otherwise, a new agent is started. Stale sockets (file exists but no agent
running) are cleaned up at plugin startup.

**Sharing with ssh-mcp:** Set `$VW_SSH_SOCKET_PATH` to a path accessible by
both the plugin and the ssh-mcp server, e.g.:

```bash
export VW_SSH_SOCKET_PATH=$XDG_RUNTIME_DIR/shared-ssh.sock
```

### SSH key generation (`generate=true`)

`vaultwarden_store_ssh` and `vaultwarden_update_ssh` accept `generate=true`,
which makes the plugin generate the keypair internally — the user never types
a passphrase or a key file path:

1. A **32-character passphrase** is generated via the same `bw generate` path
   used by `vaultwarden_store` / `vaultwarden_update` `generate=true` (one
   consistent secret-generation mechanism across the plugin).
2. An SSH keypair is generated with `ssh-keygen` — default `ed25519`, optional
   `rsa` via `key_type` / `rsa_bits` (default **4096** bits). The passphrase is
   delivered via the **`SSH_ASKPASS` mechanism** (env var only — never stdin,
   which `ssh-keygen` does not read for passphrases, and never `-N` argv,
   which would leak it to `ps`).
3. Post-generation safety verify: `ssh-keygen -yf <key>` with `stdin=DEVNULL`
   must FAIL — if it succeeds, the key is unencrypted and the operation aborts
   rather than storing an unprotected key. The generation, `-yf` verify,
   fingerprint, and `ssh-add` subprocesses all run with `start_new_session=True`,
   detaching them from any controlling terminal so they can never fall back to
   a `/dev/tty` passphrase prompt on interactive (dashboard) sessions.
4. The private key is stored as a vault attachment and the passphrase as the
   item `password` field. Neither is ever returned.
5. The response contains the **public key** and **fingerprint** (non-secret —
   paste the public key into `authorized_keys`).

In generate mode, `pass` / `pass_file` / `file` are forbidden (the plugin
supplies them). `vaultwarden_update_ssh` + `generate=true` is a **key rotation**
(destructive: replaces the existing keypair + passphrase) and therefore
requires `confirm=true`, mirroring `vaultwarden_delete_ssh`.

```
# Generate a new ed25519 keypair
vaultwarden_store_ssh(name="SSH - New", user="deploy", generate=true)
-> {"created": true, "id": "...", "name": "SSH - New", "ssh_user": "deploy",
    "key_type": "ed25519", "public_key": "ssh-ed25519 AAAA... SSH - New",
    "fingerprint": "SHA256:...", "passphrase_generated": true}

# Generate an RSA keypair (4096-bit default)
vaultwarden_store_ssh(name="SSH - RSA", generate=true, key_type="rsa")

# Rotate an existing key (destructive - confirm required)
vaultwarden_update_ssh(name="SSH - New", generate=true, confirm=true)
-> {"updated": true, ..., "public_key": "ssh-ed25519 AAAA...",
    "fingerprint": "SHA256:...", "passphrase_rotated": true}
```

## Secret input channels

Write tools that accept a secret (`vaultwarden_store` / `vaultwarden_update`
via `password*`, `vaultwarden_store_ssh` / `vaultwarden_update_ssh` via
`pass*`) support two **mutually exclusive** input sources (plus `generate=true`):

| Source | Parameter (store/update) | Parameter (ssh) | Notes |
| --- | --- | --- | --- |
| Raw value | `password` | `pass` | Enters the LLM context and chat history — **not secure**. Emits a warning in BOTH the log and the tool response. |
| Owner-only file | `password_file` | `pass_file` | Path to a file holding the secret. Must be a regular file readable **only by the owner** (chmod 600) — permission violations are rejected before the file is read. |

Rules:

- **Conflicting sources are an error.** Providing more than one of the pair
  raises `ConfigError` (no silent precedence). In generate mode, supplying any
  secret/file parameter is also a `ConfigError`.
- **Raw input triggers a dual-channel warning:** a value-free `log.warning`
  AND a `"warning"` field in the tool response. The response warning is an
  **imperative instruction directing the agent to warn the user** that direct
  secret input is insecure and to recommend the safer `*_file` channel; it
  never contains the secret value itself. Raw input is still accepted
  (accept-and-warn).
- File-resolved secrets never appear in the tool call arguments, keeping them
  out of the LLM context entirely.

```
# Passphrase from an owner-only file (chmod 600)
vaultwarden_store_ssh(name="SSH - Prod", user="deploy",
                      pass_file="/run/secrets/ssh_pass",
                      file="/home/u/.ssh/id_ed25519")

# Password from an owner-only file (chmod 600)
vaultwarden_store(name="GitHub account", username="octocat",
                  password_file="/run/secrets/gh_token")

# Raw password still works, but the response carries a warning
vaultwarden_store(name="raw-test", username="u", password="hunter2")
-> {"created": true, ..., "warning": "AGENT INSTRUCTION: A raw secret was
    supplied directly via 'password' in vaultwarden_store. ... You MUST warn
    the user about this now: tell them direct secret input is insecure, and
    recommend providing it via 'password_file' (an owner-only file, chmod 600)
    instead. Do NOT repeat the secret value in your reply."}
```

## Security Architecture

| Mechanism | Description |
| --- | --- |
| Placeholder injection | Secrets never enter the context window |
| Subprocess env isolation | All `bw` calls run with a minimal, controlled environment |
| Session key in memory only | Bitwarden session key is never written to disk |
| RedactingFilter | All secrets registered; redacted from logs and errors |
| SSH passphrase delivery | Via the `SSH_ASKPASS` mechanism: a temporarily generated helper script whose body is only `echo "$VW_SSH_PASS"` (no secret material) runs as the askpass program with `SSH_ASKPASS_REQUIRE=force`; the passphrase itself is passed to the subprocess **environment only** (never a file, never argv), and `stdin` is `/dev/null` so `ssh-keygen` / `ssh-add` can never prompt on a tty. All passphrase-handling subprocesses additionally run with `start_new_session=True`, detaching them from any controlling terminal. The helper script is removed in a `finally` block. |
| SSH key temp file | `tempfile.mkstemp()` (atomic), `0600` perms, deleted in `finally` |
| Fail-closed auth | Authentication failures never fall back silently |
| bw version enforcement | `bw --version` checked at startup against a hardcoded minimum (2026.9.1); plugin refuses to load if below or unparseable — no override |
| Structured error classification | Errors classified by source stability (Node.js codes → rate limit → bw state → server API); retry only on idempotent network errors with exponential backoff + jitter |
| Metadata masking (opt-in) | `metadata_masking=true` masks `username`/`uris` in list/search responses; `name` never masked. Default OFF preserves search usability |
| Binary path pinning | `bw` is executed ONLY from the REQUIRED absolute `bw_cli_path` (config.yaml). No PATH lookup, no env override. Validated before use: regular file, no symlink in chain, executable, not group/world-writable, owned by root/current user; otherwise the plugin fails closed and does not load |
| Bootstrap secrets via secrets.yaml | `client_secret` / `master_password` are read directly from `$HERMES_HOME/plugins/vaultwarden/secrets.yaml` (mode 0600 enforced, fail-closed `ConfigError`). They never enter `.env`, an OS environment variable, or the Hermes secret_scope — closing the `printenv` and `cat .env` attack surfaces. WARNING logged when the terminal backend is `local` (privilege separation via `docker`/`ssh` recommended for production) |
| Middleware fail-closed | If placeholder-injection middleware cannot be registered, the plugin refuses to load. No silent fallback without secret protection |
| File-injected placeholder injection | Secrets are written to a chmod 600 temp file (mkstemp, atomic) in a dedicated chmod 700 directory under `$XDG_RUNTIME_DIR` (`vw-secrets/`, typically tmpfs). The rewritten command only ever references `$(< path)` — the raw secret never enters the command string, argv, shell history, or logs. Temp files are deleted in a `finally` block even if the command fails |

See SECURITY.md for the full threat model and all security controls.

## Development

```
plugins/vaultwarden/
├── __init__.py           # Plugin registration (register(ctx))
├── plugin.yaml           # Plugin manifest (name, version, tools)
├── config.py             # Settings load via native Hermes API
├── auth.py               # AuthManager: state machine, session, recovery
├── bw_cli.py             # BwCli: subprocess wrapper, base64 encoding, attachments
├── tools.py              # 12 tool handlers
├── schemas.py            # OpenAI-style JSON schemas
├── placeholders.py       # Single-use placeholder registry
├── secrets.py            # Bootstrap secrets from secrets.yaml + terminal-backend check
├── security.py           # RedactingFilter, escaping
├── hooks.py              # Placeholder resolution middleware, cleanup hooks
├── errors.py             # Error taxonomy
├── compat.py             # Centralized compatibility layer (Hermes API, bw version)
├── secret_source.py      # Optional SecretSource adapter (startup injection, disabled by default)
├── secret.yaml.template  # Template users copy to $HERMES_HOME/plugins/vaultwarden/secrets.yaml
└── tests/                # pytest suite
```

The companion coding-agent skill `vaultwarden-usage` lives at
`skills/devops/vaultwarden-usage/` in this repository.

### Running tests

```
pytest plugins/vaultwarden/tests/ -q
```

## License

MIT — see LICENSE file.

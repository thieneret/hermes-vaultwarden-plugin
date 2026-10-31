# Vaultwarden Plugin for Hermes Agent

**Current version: v0.6.5**

> ⚠️ **WARNING: This entire plugin was developed through AI-assisted coding sessions without**
> **traditional manual code review of every line. Use at your own**
> **risk. Audit before production deployment.**
>
> ⚠️ This is my first "vibe-coded" program, intended primarily for my own use. Use it entirely at your own risk!
>
> ⚠️ AI audit results: v0.3.2-Qwen v0.3.2-ChatGPT v0.5.2-Qwen v0.5.2-ChatGPT
>
> ⚠️ **Security:** See SECURITY.md for the full threat model
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

```bash
cp -r plugins/vaultwarden ~/.hermes/plugins/vaultwarden
```

Then configure `~/.hermes/config.yaml` (see Configuration section)
and restart Hermes.

### Development & Testing

To run the test suite or contribute, install the repository as an
editable package with development dependencies.

**Using `pip`:**

```bash
git clone <repository-url>
cd hermes-vaultwarden-plugin
pip install -e ".[dev]"
```

**Using `uv` (recommended):**

```bash
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
        allow_insecure_http: false    # HTTPS enforcement override
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

```text
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

The secrets never enter the OS environment or the Hermes secret\_scope, which
closes the `printenv` and `cat .env` attack surfaces.

> **Residual risk (fail-closed policy):** if the terminal
> backend is `local` (or unset), the LLM runs as the same OS user that owns
> `secrets.yaml` and could simply `cat` it — file permissions do not isolate
> processes of the same user. The plugin therefore **refuses to load** in that
> configuration by default (CRITICAL log, `register()` returns `False`). To
> accept this risk explicitly on a trusted single-user machine, set
> `allow_insecure_local_backend: true` under
> `plugins.entries.vaultwarden.settings` (a WARNING is then logged and the
> plugin loads). Recommended production posture: use a sandboxed backend
> (`docker` / `ssh` / `modal`) for privilege separation.

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
| `server_url` | Vaultwarden server URL (required, HTTPS enforced) |
| `allow_insecure_http` | Disables strict HTTPS enforcement for `server_url`. Default: `false`. If `true`, the plugin will connect to an `http://` server (useful for local testing or isolated networks). In production, this should remain `false`. |
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
| `allow_insecure_local_backend` | Explicit opt-in to run with a `local` (or unset) Hermes terminal backend, where the LLM executes as the SAME OS user that owns `secrets.yaml` and can read `client_secret` / `master_password` via `cat`. Default: `false` — the plugin REFUSES to load on a local/unset backend (fail-closed, CRITICAL log). Set to `true` only on trusted single-user machines; loading then logs a WARNING that the operator accepts the risk. Sandboxed backends (`docker` / `ssh` / `modal`) load regardless of this flag and remain the recommended posture. Read ONLY via the native Hermes config (`plugins.entries.vaultwarden.settings`) — no `.env` / environment-variable channel. |
| `bw_max_retries` | Max retry attempts for idempotent `bw` calls on network errors. Default: `3` |
| `bw_backoff_base` | Base delay (seconds) for exponential backoff. Default: `1.0` |
| `bw_max_delay` | Maximum delay cap (seconds). Default: `10.0` |

## Tools

The plugin exposes 12 tools to the Hermes agent. The LLM constructs the exact tool calls based on the registered JSON schemas and the `vaultwarden-usage` skill.

### Core tools

| Tool | Purpose | Requires `allow_write` |
| --- | --- | :-: |
| `vaultwarden_status` | Plugin health: auth state, session, server config, plugin version | ❌ |
| `vaultwarden_sync` | Sync vault (`force=true` bypasses auto-sync interval) | ❌ |
| `vaultwarden_list` | List items — metadata only | ❌ |
| `vaultwarden_search` | Search items by name/username/uri — metadata only | ❌ |
| `vaultwarden_get_secret_ref` | Generate a single-use placeholder token | ❌ |
| `vaultwarden_store` | Create a new vault item. Supports password generation or secure file input. | ✅ |
| `vaultwarden_update` | Update an existing item. Supports password generation or secure file input. | ✅ |
| `vaultwarden_delete` | Delete an item (`confirm=true` required) | ✅ |

### SSH key management tools

| Tool | Purpose | Requires `allow_write` |
| --- | --- | :-: |
| `vaultwarden_store_ssh` | Store SSH key as login item + attachment. Supports internal keypair generation or secure file input. | ✅ |
| `vaultwarden_update_ssh` | Update user/passphrase/key attachment. Supports internal key rotation (`confirm=true` required). | ✅ |
| `vaultwarden_delete_ssh` | Delete SSH key item (attachment included) | ✅ |
| `vaultwarden_use_ssh` | Load SSH key into ssh-agent (socket path resolved from developer-controlled env vars) | ❌ |

## Placeholder Injection (security model)

Raw secrets are never exposed to the agent's context window or terminal history. Instead, the plugin uses a file-based injection architecture:

1. The LLM requests a single-use placeholder token (e.g., `$__VW_SECRET_xxxx__`) via `vaultwarden_get_secret_ref`.
2. The LLM embeds this token inside a terminal command (e.g., `curl -H "Bearer $__VW_SECRET_xxxx__"`).
3. The Hermes `tool_execution` middleware intercepts the command, writes the real secret to a secure temporary file (`chmod 600`), and rewrites the command to read from it using shell expansion (e.g., `$(< /tmp/vw-secrets/...)`).
4. The shell expands the file content at execution time. The raw secret never appears in the command string, argv, shell history, or logs.

**Key guarantees:**
- Placeholders are **single-use** and expire after `placeholder_ttl_seconds`.
- The placeholder reference MUST be double-quoted (or unquoted) — never single quotes — so the shell expands the `$(< path)` substitution.
- If a command references the same placeholder multiple times, the middleware resolves it exactly once and creates a single temp file.

## SSH Key Management

SSH private keys are managed securely without exposing passphrases to the LLM:

- **Storage:** Keys are stored as Vaultwarden login items, with the private key attached as a secure file attachment.
- **Generation:** The plugin can generate keypairs internally using `ssh-keygen` and `bw generate`. The passphrase is delivered securely via the `SSH_ASKPASS` environment mechanism, never via stdin or command-line arguments.
- **Loading:** The `vaultwarden_use_ssh` tool loads the key into a local `ssh-agent`. The socket path is strictly resolved from developer-controlled environment variables (`$VW_SSH_SOCKET_PATH` or `$XDG_RUNTIME_DIR/auth.sock`), preventing the LLM from hijacking the agent socket.

## Secret input channels

When creating or updating secrets (passwords or SSH passphrases), the LLM can supply the value through two mutually exclusive channels:

1. **Owner-only file (Secure):** A path to a file holding the secret (`password_file` / `pass_file`). The file must be readable only by the owner (`chmod 600`). The secret is read directly from disk and never enters the LLM context or chat history.
2. **Raw value (Insecure):** The secret is passed directly as a string. The plugin accepts it but emits a strict security warning in both the logs and the tool response, instructing the agent to warn the user.

## Filesystem Security Requirements

The plugin enforces a shared filesystem-hardening layer (`plugins/vaultwarden/secure_fs.py`) that validates every security-sensitive path **fail-closed** before it is trusted:

- the **secret-injection directory** (runtime placeholder temp files, `$XDG_RUNTIME_DIR/vw-secrets`) is validated at plugin load;
- the **Bitwarden appdata directory** (`.bw-data`, exported to `bw` as `BITWARDENCLI_APPDATA_DIR`) is validated before _any_ `bw` subprocess invocation;
- the **bootstrap secret file** (`secrets.yaml`) is validated _before_ YAML parsing.

All validators use `os.lstat()` (symlinks are never followed), reject symlinks, require ownership by the current effective UID, and enforce strict permissions. Insecure paths are **never silently repaired** — the operator must fix them explicitly.

### Required permissions

| Path | Required mode | Ownership | Notes |
| --- | --- | --- | --- |
| Secrets directory (`$XDG_RUNTIME_DIR/vw-secrets`) | `0700` exactly | current user (effective UID) | created hardened if missing; must NOT be a symlink |
| `.bw-data` (Bitwarden appdata dir) | `0700` exactly | current user (effective UID) | created hardened if missing; must NOT be a symlink |
| `secrets.yaml` (bootstrap secrets) | `0600` (no group/other bits) | current user (effective UID) | regular file only; must NOT be a symlink |

### Operator remediation commands

Fix ownership and permissions explicitly (the plugin will not do this for you):

```bash
chown "$USER":"$USER" /path/to/secrets-dir
chmod 700 /path/to/secrets-dir

chown "$USER":"$USER" /path/to/.bw-data
chmod 700 /path/to/.bw-data

chown "$USER":"$USER" /path/to/secrets.yaml
chmod 600 /path/to/secrets.yaml
```

If a security-sensitive path is a **symlink**, remove it and recreate a real directory:

```bash
rm /path/to/symlink
mkdir -m 700 /path/to/real-dir
```

> ⚠️ **Validation is fail-closed.** Existing installations with unsafe permissions will **stop working after updating** until the operator applies the remediation commands above.

## Security Architecture

| Mechanism | Description |
| --- | --- |
| Placeholder injection | Secrets never enter the context window |
| Subprocess env isolation | All `bw` calls run with a minimal, controlled environment |
| Session key in memory only | Bitwarden session key is never written to disk. Since v0.6.4 the `BW_SESSION` environment variable is guaranteed at the single subprocess-env choke point for all session-requiring `bw` commands (list/get/create/edit/delete), so vault operations can no longer silently run against a locked vault (v0.6.3 regression: empty `vaultwarden_list`, exit 1 on `vaultwarden_store`). Locked/expired sessions now surface as `SESSION_ERROR` / `SESSION_EXPIRED` with sanitized stderr and a re-unlock suggestion — never the raw session key. |
| RedactingFilter | All secrets registered; redacted from logs and errors |
| SSH passphrase delivery | Via the `SSH_ASKPASS` mechanism (env var only, never stdin/argv). Helper script removed in `finally` block. |
| SSH key temp file | `tempfile.mkstemp()` (atomic), `0600` perms, deleted in `finally` |
| Fail-closed auth | Authentication failures never fall back silently |
| bw version enforcement | `bw --version` checked at startup (minimum 2026.9.1); plugin refuses to load if below |
| Binary path pinning | `bw` is executed ONLY from the REQUIRED absolute `bw_cli_path`. No PATH lookup, no env override. |
| Bootstrap secrets via secrets.yaml | Read directly from `secrets.yaml` (mode 0600 enforced). Never enter `.env` or OS environment. |
| Local-backend fail-closed policy | Plugin refuses to load on `local` backend unless `allow_insecure_local_backend: true` is set. |
| HTTPS enforcement | `server_url` MUST use `https://` scheme; HTTP is rejected fail-closed unless `allow_insecure_http: true` is explicitly set. |
| Filesystem hardening | Secrets dir, `.bw-data`, and `secrets.yaml` validated via `secure_fs.py` before use. Symlinks, wrong owners, and loose permissions abort execution. |
| Lifecycle hook fail-closed registration | Critical lifecycle hooks are validated before tools are exposed; plugin refuses to load if required hook registration fails. |
| Scoped log-redaction lifecycle | Runtime secrets are retained only for active execution scopes and released afterward using reference-counted redaction. Process-scoped secrets remain protected for the process lifetime. |

See SECURITY.md for the full threat model and all security controls.

## Development

```text
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
├── secure_fs.py          # Shared filesystem-hardening helpers (symlink/owner/mode fail-closed)
├── secret.yaml.template  # Template users copy to $HERMES_HOME/plugins/vaultwarden/secrets.yaml
└── tests/                # pytest suite
```

The companion coding-agent skill `vaultwarden-usage` lives at
`skills/devops/vaultwarden-usage/` in this repository.

### Running tests

```bash
pytest plugins/vaultwarden/tests/ -q
```

Current suite: **440 tests** — including positive-control suites for:

- Placeholder lifecycle (single-use, expiry, replay rejection)
- Fail-closed behaviour (missing hooks, broken config, refused loads)
- Auth and secret-source isolation (bootstrap secrets never enter the env)
- E2E pipeline redaction (the "Leaky Cat" scenario verifying `transform_tool_result` prevents secret exfiltration to the LLM context)

## License

MIT — see LICENSE file.

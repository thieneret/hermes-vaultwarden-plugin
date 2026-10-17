# Vaultwarden Plugin for Hermes Agent

> ⚠️ **WARNING: This entire plugin was vibe-coded.**
> It was developed through AI-assisted coding sessions without
> traditional manual code review of every line. Use at your own
> risk. Audit before production deployment.

Secure secrets management for Hermes Agent via Vaultwarden. Provides safe access to vault items through a placeholder injection architecture, plus SSH key storage and ssh-agent integration.

## Features

- **13 registered tools** covering vault read/write, secret references, and SSH key management
- **Placeholder injection** — raw secrets never enter the agent's context window
- **SSH key management** — store private keys as vault attachments, load them into ssh-agent on demand
- **Bitwarden CLI integration** — all vault operations go through the audited `bw` binary
- **Session isolation** — the Bitwarden session key lives only in plugin memory, never on disk
- **Write protection** — mutating operations are gated behind an explicit `allow_write` flag
- **Log redaction** — every secret that passes through the plugin is registered with a redacting filter

## Requirements

| Dependency | Purpose |
|------------|---------|
| Hermes Agent | Host platform (plugin API) |
| Bitwarden CLI (`bw`) | Vault operations (login, sync, CRUD) |
| Vaultwarden server | Backend (any Bitwarden-compatible instance) |
| OpenSSH ≥ 7.2 | SSH features (`ssh-add`, `ssh-agent`) — stdin passphrase fallback |

## Installation

Copy the plugin directory into your Hermes plugins folder:

```bash
cp -r vaultwarden ~/.hermes/plugins/
```

Then enable it in the Hermes configuration (see below) and restart Hermes.

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
        client_secret_env: VW_CLIENT_SECRET
        master_password_env: VW_MASTER_PASSWORD
        allow_write: false
        allow_startup_secret_injection: false
        allow_direct_secret_retrieval: false
        auto_sync: true
        sync_interval_seconds: 300
        session_timeout_seconds: 14400
        placeholder_ttl_seconds: 300
        max_placeholders: 50
        bw_cli_path: "/path/to/bw"
```

### `.env` (secrets)

Secret values are resolved from environment variables and stored in `~/.hermes/.env` (chmod 600):

```bash
VW_CLIENT_SECRET="your-client-secret"
VW_MASTER_PASSWORD="your-master-password"
```

### Key settings

| Setting | Effect |
|---------|--------|
| `allow_write` | Enables `store`/`update`/`delete` operations. Default: `false` |
| `allow_direct_secret_retrieval` | Permits returning raw secrets. **Strongly discouraged.** Default: `false` |
| `session_timeout_seconds` | Vault session lifetime. Default: `14400` (4h) |
| `placeholder_ttl_seconds` | Placeholder token lifetime. Default: `300` (5min) |
| `auto_sync` | Sync vault before read operations |

## Tools

### Core tools

| Tool | Purpose | Requires `allow_write` |
|------|---------|:---:|
| `vaultwarden_status` | Plugin health: auth state, session, server config | ❌ |
| `vaultwarden_sync` | Sync vault (`force=true` bypasses auto-sync interval) | ❌ |
| `vaultwarden_list` | List items — metadata only | ❌ |
| `vaultwarden_search` | Search items by name/username/uri — metadata only | ❌ |
| `vaultwarden_get_secret_ref` | Generate a single-use placeholder token | ❌ |
| `vaultwarden_generate_password` | Generate a strong password/passphrase (the only tool that returns a secret) | ❌ |
| `vaultwarden_store` | Create a new vault item | ✅ |
| `vaultwarden_update` | Update an existing item | ✅ |
| `vaultwarden_delete` | Delete an item (`confirm=true` required) | ✅ |

### SSH key management tools

| Tool | Purpose | Requires `allow_write` |
|------|---------|:---:|
| `vaultwarden_store_ssh` | Store SSH key as login item + attachment (name must be unique) | ✅ |
| `vaultwarden_update_ssh` | Update user/passphrase/key attachment | ✅ |
| `vaultwarden_delete_ssh` | Delete SSH key item (attachment included) | ✅ |
| `vaultwarden_use_ssh` | Load SSH key into ssh-agent | ❌ |

## Placeholder Injection (security model)

Raw secrets are never exposed to the agent. Instead:

```
1. vaultwarden_search(query="github")              → metadata only
2. vaultwarden_get_secret_ref(item_id, field)      → __VW_SECRET_xxxx__
3. terminal(command="curl -H 'Bearer __VW_SECRET_xxxx__' ...")
   ↑ middleware substitutes the real secret at execution time
```

- Placeholders are **single-use** and expire after `placeholder_ttl_seconds`
- The real secret is injected only at the moment of command execution
- Every secret is registered with a redacting filter so it cannot leak into logs

## SSH Key Management

SSH private keys are stored as login items with a file attachment:

| Vault field | Meaning |
|-------------|---------|
| `name` | Item name (must be unique) |
| `username` | SSH user (e.g. `deploy`, `root`) |
| `password` | SSH key passphrase |
| attachment | SSH private key file (original filename) |

### Store a key

```
vaultwarden_store_ssh(name="SSH - Production", user="deploy",
                      pass="key-passphrase", file="/path/to/id_ed25519")
```

### Load a key into ssh-agent

```
vaultwarden_use_ssh(name="SSH - Production")
```

Socket resolution order for `ssh_auth_sock`:
1. Direct socket path, or environment variable name
2. `$SSH_AUTH_SOCK` (if set)
3. Fresh `ssh-agent` (if neither)

If no agent is running on the resolved socket, one is started with `ssh-agent -a <socket>`. The passphrase is piped via stdin (never written to a temp file); the key uses an atomic temp file (`mkstemp`, `0600`) deleted in a `finally` block.

## Security Architecture

| Mechanism | Description |
|-----------|-------------|
| Placeholder injection | Secrets never enter the context window |
| Subprocess env isolation | All `bw` calls run with a minimal, controlled environment |
| Session key in memory only | Bitwarden session key is never written to disk |
| RedactingFilter | All secrets registered; redacted from logs and errors |
| SSH passphrase via stdin | Delivered through `subprocess.run(input=...)`, never a temp file |
| SSH key temp file | `tempfile.mkstemp()` (atomic), `0600` perms, deleted in `finally` |
| Fail-closed auth | Authentication failures never fall back silently |

## Development

```
vaultwarden/
├── __init__.py      # Plugin registration (register(ctx))
├── config.py        # Settings load, env resolution, config fallback
├── auth.py          # AuthManager: state machine, session, recovery
├── bw_cli.py        # BwCli: subprocess wrapper, base64 encoding, attachments
├── tools.py         # 13 tool handlers
├── schemas.py       # OpenAI-style JSON schemas
├── placeholders.py  # Single-use placeholder registry
├── security.py      # RedactingFilter, escaping
├── hooks.py         # Placeholder resolution middleware, cleanup hooks
├── errors.py        # Error taxonomy
├── secret_source.py # Optional SecretSource adapter
└── tests/           # pytest suite
```

### Running tests

```bash
python -m pytest vaultwarden/tests/ -q -p no:libtmux
```

Current suite: **178 tests**.

## License

MIT — see [LICENSE](LICENSE) file.

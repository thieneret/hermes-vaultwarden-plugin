# Security Model — hermes-vaultwarden-plugin

## Threat Model

This plugin handles highly sensitive credentials (master password, client
secret, SSH private keys, vault item secrets). The primary threat vectors are:

1. **Secret leakage into the agent's context window** (LLM prompt injection)
2. **Secret leakage into logs** (disk persistence, log aggregation)
3. **Secret leakage via subprocess environment** (process inspection)
4. **Compromised dependencies** (supply chain)
5. **Unvalidated `bw` CLI version** (marker-based error detection unreliable
   against an unknown bw build)

## Primary Security Controls

These controls MUST NOT fail. They are the foundation of the plugin's security:

| Control | Mechanism |
|---------|-----------|
| Placeholder injection | Secrets never enter the agent's context window. `vaultwarden_get_secret_ref` returns a `__VW_SECRET_xxxx__` token; the real value is injected only at command execution time via middleware. No escape hatch (direct secret retrieval removed in v0.3.7). |
| Subprocess env isolation | All `bw` calls run with a minimal, explicitly constructed environment. The parent environment is NEVER inherited. |
| SSH environment isolation | All SSH subprocess calls (`ssh-add`, `ssh-agent`, `ssh-keygen`) run via `_ssh_base_env()` — a minimal, explicitly allowlisted environment. The parent environment is NEVER inherited. |
| Password generation | `vaultwarden_store` / `vaultwarden_update` with `generate=true` generate a password and store it directly in the vault. The generated value is never returned to the LLM — only a placeholder is. |
| Session key in memory only | The Bitwarden session key is never written to disk. |
| SSH passphrase via env | The SSH passphrase is delivered via `SSH_ASKPASS` + environment variable, never written to a file. |
| Temp file cleanup | SSH key temp files are created with `mkstemp()` (0600 perms) and deleted in a `finally` block. |
| bw version enforcement | At startup, `BwCli._check_version()` runs `bw --version` with an isolated environment and validates against a hardcoded minimum (2026.9.1). Fail-closed with NO override: an unsupported or unparseable version raises `UnsupportedBwVersionError`, logs the error, and prevents the plugin from loading. The minimum version is not configurable — compatibility is the plugin author's responsibility, not the user's. |

### Error Classification by Source (VWP-09)

`bw` errors are detected via string-marker matching (the CLI exposes only two
exit codes: 0 and 1, so structured codes are unavailable). Markers are
organized by source stability and checked in priority order:

1. **Node.js network codes** (`ECONNREFUSED`, `ETIMEDOUT`, `fetch failed`, …)
   — most stable, official Node.js API.
2. **Rate-limit markers** (`too many requests`, `429`) — raised immediately,
   never retried.
3. **bw CLI state messages** (`not logged in`, `vault is locked`, …) —
   version-dependent; reliability is anchored by the startup version check.
4. **Server API errors** (`cannot find`, `does not exist`) — least stable,
   server-version-dependent; used only as fallback.

### Retry Safety (VWP-10)

Network-error retries use bounded exponential backoff with additive jitter
(`base * 2^attempt + uniform(0,1)`, capped at `max_delay`) and are restricted
to idempotent operations only. Non-idempotent `bw` calls (`login --apikey`,
`unlock`, `create attachment`, `delete item/attachment`) are explicitly marked
`retryable=False` and never retried, preventing duplicate session keys,
duplicate attachments, or false-negative delete results.

## Defense-in-Depth: Log Redaction

As of v0.3.7, the `allow_direct_secret_retrieval` escape hatch has been
completely removed. There is no code path that returns a raw secret to
the LLM. The placeholder model is the only supported path for secret
access.

The `RedactingFilter` (in `security.py`) is a **defense-in-depth** mechanism.
It provides an additional layer of protection but has known limitations:

- **Memory storage:** Registered secrets are stored in plugin memory
  (`_secrets: set[str]`) for the duration of the operation.
- **String replacement:** Uses `str.replace()` which is not cryptographic.
- **Known gaps:** Base64-encoded or otherwise transformed secrets may
  bypass detection.

**This mechanism does NOT replace the primary controls above.** If a secret
reaches the logging layer, it has already failed at a higher level.

## Structured Logging

All plugin log output is emitted as JSON via `StructuredJsonFormatter`.
Fields whose keys match secret-like patterns (`password`, `passphrase`,
`secret`, `token`, `key`, `credential`) are automatically replaced with
`[REDACTED]` at format time — before the log record reaches any handler.

## Development Rules

- Never log raw `bw` output (use structured status codes only).
- Always call `register_secret()` before any operation that handles secrets.
- Always call `forget_secret()` in a `finally` block.
- Never pass secret values as log message arguments.
- Generated passwords (via `generate=true`) must never be returned to the
  caller — only a placeholder.
- Never retry a non-idempotent `bw` operation. When adding a new `bw` command
  wrapper, explicitly set `retryable=False` unless the command is proven
  idempotent (read-only or safe-to-repeat write).
- The `_classify_error()` priority order (Cat-2 → rate_limit → Cat-1 → Cat-3)
  must not be changed without updating the source-category table above.

## Supply Chain

- Dev dependencies are pinned via `uv.lock` (committed to the repository).
- CI installs exclusively from the lockfile (`uv sync --frozen`).
- All CI checks (pytest, ruff) are **blocking** — a failing check prevents merge.

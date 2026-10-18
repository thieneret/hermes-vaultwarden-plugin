# Security Model — hermes-vaultwarden-plugin

## Threat Model

This plugin handles highly sensitive credentials (master password, client
secret, SSH private keys, vault item secrets). The primary threat vectors are:

1. **Secret leakage into the agent's context window** (LLM prompt injection)
2. **Secret leakage into logs** (disk persistence, log aggregation)
3. **Secret leakage via subprocess environment** (process inspection)
4. **Compromised dependencies** (supply chain)

## Primary Security Controls

These controls MUST NOT fail. They are the foundation of the plugin's security:

| Control | Mechanism |
|---------|-----------|
| Placeholder injection | Secrets never enter the agent's context window. `vaultwarden_get_secret_ref` returns a `__VW_SECRET_xxxx__` token; the real value is injected only at command execution time via middleware. |
| Subprocess env isolation | All `bw` calls run with a minimal, explicitly constructed environment. The parent environment is NEVER inherited. |
| Session key in memory only | The Bitwarden session key is never written to disk. |
| SSH passphrase via env | The SSH passphrase is delivered via `SSH_ASKPASS` + environment variable, never written to a file. |
| Temp file cleanup | SSH key temp files are created with `mkstemp()` (0600 perms) and deleted in a `finally` block. |

## Defense-in-Depth: Log Redaction

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

## Supply Chain

- Dev dependencies are pinned via `uv.lock` (committed to the repository).
- CI installs exclusively from the lockfile (`uv sync --frozen`).
- All CI checks (pytest, ruff) are **blocking** — a failing check prevents merge.

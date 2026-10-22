# Vaultwarden — Troubleshooting, Best Practices, Verification

Load when an operation fails or you need operational guidance.

## Error Recovery

| Error | Meaning | Action |
| --- | --- | --- |
| `PLACEHOLDER_ERROR` (expired) | TTL exceeded | Request a NEW placeholder, retry |
| `PLACEHOLDER_ERROR` (already used) | Already consumed | Request a NEW placeholder, retry |
| `NOT_FOUND` | Item/field missing, or `*_file` path absent | Use `vaultwarden_search`; verify the file path |
| `SESSION_ERROR` | Vault session expired | Run `vaultwarden_status`; auto-recovers on next call |
| `NETWORK_ERROR` | Server unreachable | Plugin retries idempotent calls with exponential backoff; if persistent, inform the user |
| `PERMISSION_ERROR` | Write disabled, or rotation without `confirm=true` | Inform user `allow_write` is disabled; for rotation re-issue with `confirm=true` |
| `CONFIG_ERROR` | Conflicting secret sources, empty/unset env var, or file not chmod 600 | Use exactly ONE source; set the env var; `chmod 600 <file>` |
| `DUPLICATE_NAME` | SSH item name exists | Choose a different name or use `vaultwarden_update_ssh` |
| `AMBIGUOUS_ERROR` | Multiple items match name | Use `vaultwarden_search` to find the correct `item_id` |
| `AGENT_ERROR` | ssh-agent failed to start | Check socket path permissions; retry with explicit path |
| `VALIDATION_ERROR` | File not a valid SSH key | Verify it starts with `-----BEGIN` or `ssh-` |
| `UNSUPPORTED_BW_VERSION` | Plugin failed to start: `bw` below 2026.9.1 or unparseable | **The `vaultwarden_*` tools are unavailable.** Tell the user to upgrade `bw` to ≥ 2026.9.1. Fail-closed — no workaround |
| Placeholder not substituted | Reference single-quoted, or `$` prefix missing | Use `$__VW_SECRET_x__` inside double quotes (see architecture.md) |

**Critical rule:** After ANY placeholder-related error, NEVER reuse the same
placeholder — always request a fresh one.

## Best Practices

| Practice | Why |
| --- | --- |
| Check `vaultwarden_status` before critical operations | Avoids mid-workflow session errors |
| Always double-quote placeholder references | Single quotes prevent shell expansion and break injection |
| Sync before searching recently created items | `vaultwarden_sync(force=true)` ensures fresh data |
| Use `generate=true` for new credentials/keys | The generated secret is stored in the vault and never enters your context |
| Use `*_env`/`*_file` for input secrets | Keeps the value out of the LLM context and chat history |
| Relay the response `"warning"` to the user | The user learns direct input is insecure and can switch channels |
| Use metadata-only tools (`list`, `search`) for exploration | Safe, no secrets exposed |
| Request placeholder ONLY when command is ready | Minimizes TTL expiry risk |
| Use `vaultwarden_use_ssh` for SSH keys | Handles key download + passphrase + ssh-agent in one call |
| Use descriptive SSH key names | `SSH - Production`, `SSH - Staging` — not `key1`, `key2` |
| Verify `allow_write` before any write/generate operation | Fail fast with a clear error |

## Verification

After a successful operation using a placeholder:

1. Confirm the command returned expected output (exit code 0, expected response)
2. If authentication failed, check: was the placeholder consumed? → request a new one
3. If using `vaultwarden_use_ssh`: verify with `ssh-add -l` (with the returned `SSH_AUTH_SOCK`) that the key is loaded
4. If you generated an SSH keypair: confirm the response has `public_key` + `fingerprint` and NO private key or passphrase

**NEVER** re-request the same placeholder to "check if it worked".

## Integration with Other Skills

| Skill | Integration |
| --- | --- |
| ssh-mcp | Use `vaultwarden_use_ssh` to load key → ssh-mcp handles connection. No manual placeholder/ssh-add needed |
| Git operations | Get token/password → use in git clone/push URL via placeholder |
| Docker/API tasks | Get API key → inject into Authorization headers via placeholder |
| Provisioning | `store_ssh(generate=true)` → public key to the host's `authorized_keys`, private key stays in vault |

# Vaultwarden — Practical Examples

Load when you need a concrete tool-call shape for a specific flow.

**Note:** All placeholder references use the `$` prefix and MUST sit inside
double quotes (or be unquoted) so the shell expands them. Never single-quote a
placeholder reference.

## Example 1: API Request (placeholder)

```
1. vaultwarden_search(query="openai")
2. vaultwarden_get_secret_ref(item_id="def-456", field="password")
   -> $__VW_SECRET_9z8y7x6w5v4u__
3. terminal(command="curl -H \"Authorization: Bearer $__VW_SECRET_9z8y7x6w5v4u__\" https://api.openai.com/v1/models")
```

## Example 2: Git Clone with Token (placeholder)

```
1. vaultwarden_search(query="forgejo-token")
2. vaultwarden_get_secret_ref(item_id="abc-123", field="password")
   -> $__VW_SECRET_7k8m9n0p1q2r__
3. terminal(command="git clone https://oauth2:$__VW_SECRET_7k8m9n0p1q2r__@forgejo.example.com/user/repo.git")
```

## Example 3: SSH Key Loading (use_ssh)

```
1. vaultwarden_use_ssh(name="SSH - Production")
   -> {"loaded": true, "ssh_auth_sock": "<path>", "key_fingerprint": "SHA256:..."}
2. terminal(command="SSH_AUTH_SOCK=<path> ssh user@host 'uname -a'")
```

The tool loads the key and returns a socket path. Use the returned
`ssh_auth_sock` value as `SSH_AUTH_SOCK` for subsequent SSH commands.

## Example 4: New Credential with Generated Password (preferred)

```
vaultwarden_store(
    type="login", name="My New Service", username="admin",
    uri="https://service.example.com",
    generate=true, generate_options={"mode": "password", "length": 24}
)
-> {"created": true, "id": "...", "item": {...},
    "password_generated": true,
    "password_placeholder": "$__VW_SECRET_xxxx__",
    "placeholder_ttl_seconds": 300}
```

The password is generated and stored in the vault; you only receive a placeholder.
Requires `allow_write: true`.

## Example 5: Store a Secret via Owner-Only File (safe input)

```
vaultwarden_store(type="login", name="DB Prod", username="app", password_file="/run/secrets/db_password")
```

The file must be owner-read-only (chmod 600); otherwise the call fails.
The secret never enters your context. No `warning` field in the response.

> **v0.4.9 BREAKING CHANGE:** the former env-var channel (`password_env`) was
> removed — Hermes only loads `.env` at startup in multiplex gateway mode, so
> env secrets required a restart to resolve. Supplying `password_env` now
> raises an explicit `ConfigError` ("removed in v0.4.9"). Use `password_file`
> (this example) or `generate=true` instead.

## Example 7: Raw Password (discouraged — expect a warning)

```
vaultwarden_store(type="login", name="Legacy App", username="admin", password="SecurePassword123!")
-> {"created": true, ..., "warning": "Direct secret input detected for 'password' ..."}
```

Relay the `warning` to the user and switch to `password_env`/`password_file`.
Prefer Example 4 (`generate=true`) for new credentials.

## Example 8: Generate an SSH Keypair (ed25519)

```
vaultwarden_store_ssh(name="SSH - New Server", user="deploy", generate=true)
-> {"created": true, "id": "...", "name": "SSH - New Server", "ssh_user": "deploy",
    "key_type": "ed25519", "public_key": "ssh-ed25519 AAAAC3Nza... SSH - New Server",
    "fingerprint": "SHA256:...", "passphrase_generated": true}
```

Paste `public_key` into the server's `authorized_keys`. The private key +
passphrase stay in the vault; load them later with
`vaultwarden_use_ssh(name="SSH - New Server")`. Do NOT pass `pass`/`file` in
generate mode.

## Example 9: Generate an RSA Keypair

```
vaultwarden_store_ssh(name="SSH - Legacy Host", user="ubuntu",
                      generate=true, key_type="rsa", rsa_bits=4096)
-> public_key begins "ssh-rsa ...", 4096-bit fingerprint
```

## Example 10: Rotate an SSH Key (destructive — confirm required)

```
vaultwarden_update_ssh(name="SSH - New Server", generate=true)
-> PERMISSION_ERROR: "Re-issue with confirm=true to rotate the key."

vaultwarden_update_ssh(name="SSH - New Server", generate=true, confirm=true)
-> {"updated": true, "id": "...", "key_type": "ed25519",
    "public_key": "ssh-ed25519 AAAA... (NEW)", "fingerprint": "SHA256:...",
    "passphrase_rotated": true}
```

Update `authorized_keys` with the new `public_key` and revoke the old one.

## Example 11: Upload an Existing SSH Key (passphrase via env)

```
vaultwarden_store_ssh(name="SSH - Existing", user="deploy",
                      pass_env="SSH_KEY_PASS",
                      file="/home/user/.ssh/id_ed25519_prod")
```

`pass_env`/`pass_file` keep the passphrase out of context; raw `pass` triggers a
`warning` (see Example 7).

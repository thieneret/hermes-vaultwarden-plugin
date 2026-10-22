# Vaultwarden — Placeholder Injection Architecture

Load to understand how secrets are injected.

## Overview

The plugin uses a placeholder-injection middleware. The agent never sees raw
secrets — it only handles opaque `__VW_SECRET_xxxx__` tokens. The middleware
substitutes the real secret into the command at the moment of execution.

## Flow

```
1. vaultwarden_get_secret_ref(item_id, field)
   -> returns __VW_SECRET_<suffix>__

2. Agent calls terminal with the placeholder in the command:
   command='curl -H "Bearer __VW_SECRET_<suffix>__" ...'

3. Middleware intercepts the terminal call, resolves the placeholder via the
   single-use registry, and substitutes the real secret into the command.

4. Hermes executes the terminal call with the substituted secret.
```

## Security Guarantees

- Real secret never enters the agent's context window
- Every secret registered with RedactingFilter (cannot leak into logs)
- Placeholders are single-use with a TTL (default 300s); consumption is atomic
- Middleware registration is fail-closed: if it cannot register, the plugin
  refuses to load (v0.4.3), because running without injection would expose secrets
- `bw` version enforcement (minimum 2026.9.1) is fail-closed at startup

## Related Security Controls

- SSH passphrase delivery uses the `SSH_ASKPASS` mechanism (env-var only,
  never a file/argv), with `SSH_ASKPASS_REQUIRE=force` and `stdin=/dev/null`.
- SSH key temp files use `mkstemp` (atomic, `0600`), deleted in `finally`.
- All `bw` calls run in an isolated subprocess environment.

# Vaultwarden — File-Injection Architecture

Load to understand how secrets are injected and why the double-quote rule exists.

## Overview

The plugin injects secrets via a dedicated temp file in `$XDG_RUNTIME_DIR/vw-secrets/`
(chmod 700 directory, chmod 600 file). The middleware uses Hermes's `tool_execution`
middleware to intercept the terminal call, write the secret to a temp file, and
rewrite the command to read from it via `$(< path)`.

| Threat | String rewrite (old) | File injection (v0.4.4) |
| --- | --- | --- |
| Shell-escape / quote-break | Vulnerable | Secret never in the command |
| `ps` / command-line logging | Secret visible in argv | Only `$(< path)` visible |
| Shell history (`~/.bash_history`) | Secret recorded | Only `$(< path)` recorded |
| Agent context window | At risk | Never present |
| Disk persistence | N/A (memory) | Minimal — `XDG_RUNTIME_DIR` is typically tmpfs (RAM-backed) |

## Flow

```
1. vaultwarden_get_secret_ref(item_id, field)
   -> returns $__VW_SECRET_<suffix>__   ($ prefix = "use as a shell substitution")

2. Agent calls terminal with the reference DOUBLE-QUOTED:
   command='curl -H "Bearer $__VW_SECRET_<suffix>__" ...'

3. tool_execution middleware (wraps the actual tool call):
   - resolves $__VW_SECRET_<suffix>__ via the single-use registry
   - writes the secret to $XDG_RUNTIME_DIR/vw-secrets/vw_<suffix>_XXXXXX (chmod 600)
   - rewrites command: $__VW_SECRET_<suffix>__  ->  $(< /run/user/<uid>/vw-secrets/vw_<suffix>_XXXXXX)
   - registers the secret with RedactingFilter

4. Hermes executes the terminal call; the shell expands $(< path) to the secret.

5. The middleware's finally block deletes the temp file (even if the command fails).
```

The raw secret exists only in the temp file for the duration of the command
execution. It is never placed in the command string, argv, a log line, or a tool
response.

## The Double-Quote Rule

The placeholder reference must be **expanded by the shell** so the `$(< path)`
substitution is evaluated. Shell expansion happens inside double quotes and
unquoted, but NOT inside single quotes:

| Command form | Works? | Why |
| --- | --- | --- |
| `curl -H "Bearer $__VW_SECRET_x__"` | ✅ | Double quotes → shell expands |
| `curl -H Bearer\ $__VW_SECRET_x__` | ✅ | Unquoted/escaped → shell expands |
| `curl -H 'Bearer $__VW_SECRET_x__'` | ❌ | Single quotes → no expansion; injection fails |

Therefore every placeholder reference MUST be double-quoted (or unquoted).

## Why the `$` prefix

The `$` makes the placeholder a valid shell variable reference. If the
middleware does not run (e.g. expired placeholder), the shell expands
`$__VW_SECRET_x__` to an empty string — the secret does NOT leak; the command
just fails with an empty value (fail-safe).

## Security Guarantees

- Real secret never in the command string, argv, log, or tool response
- Dedicated directory chmod 700 — no other user can list the files
- `mkstemp` guarantees chmod 600 and atomic creation (symlink-protected)
- `XDG_RUNTIME_DIR` is typically tmpfs (RAM-backed) — secret does not hit physical disk
- Every real secret registered with RedactingFilter before injection
- Placeholders are single-use with a TTL (default 300s); consumption is atomic
- Middleware registration is fail-closed: if it cannot register, the plugin
  refuses to load (v0.4.3)
- Temp files are deleted in a `finally` block — cleanup runs even if the command fails

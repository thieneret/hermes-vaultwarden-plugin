# Vaultwarden — Env-Injection Architecture

Load to understand how secrets are injected and why the double-quote rule exists.

## Overview

The plugin injects secrets into the `terminal` tool's `env` parameter via a
Hermes `tool_request` middleware. This is strictly more secure than rewriting the
command string with the secret:

| Threat | String rewrite (old) | Env injection (v0.4.4) |
| --- | --- | --- |
| Shell-escape / quote-break | Vulnerable | Secret never in the command |
| `ps` / command-line logging | Secret visible in argv | Only `VW_TOKEN_x` visible |
| Shell history (`~/.bash_history`) | Secret recorded | Only `VW_TOKEN_x` recorded |
| Agent context window | At risk | Never present |

## Flow

```
1. vaultwarden_get_secret_ref(item_id, field)
   -> returns $__VW_SECRET_<suffix>__   ($ prefix = "use as a shell variable")

2. Agent calls terminal with the reference DOUBLE-QUOTED:
   command='curl -H "Bearer $__VW_SECRET_<suffix>__" ...'

3. tool_request middleware (before hooks/guardrails/execution):
   - resolves $__VW_SECRET_<suffix>__ via the single-use registry
   - injects env["VW_TOKEN_<suffix>"] = <real_secret>
   - rewrites command: $__VW_SECRET_<suffix>__  ->  $VW_TOKEN_<suffix>
   - registers <real_secret> with RedactingFilter

4. Hermes executes the terminal call with the injected env.

5. The shell expands $VW_TOKEN_<suffix> to <real_secret> at execution time.
```

The raw secret exists only in the subprocess `env` for the lifetime of the call.
It is never placed in the command string, argv, a file, a log line, or a tool
response.

## The Double-Quote Rule

The placeholder reference must be **expanded by the shell** so the env var is
substituted. Shell expansion happens inside double quotes and unquoted, but NOT
inside single quotes:

| Command form | Works? | Why |
| --- | --- | --- |
| `curl -H "Bearer $__VW_SECRET_x__"` | ✅ | Double quotes → shell expands |
| `curl -H Bearer\ $__VW_SECRET_x__` | ✅ | Unquoted/escaped → shell expands |
| `curl -H 'Bearer $__VW_SECRET_x__'` | ❌ | Single quotes → no expansion; injection fails |

Therefore every placeholder reference MUST be double-quoted (or unquoted). If a
command needs literal single quotes around the value, place the placeholder in a
separate variable or restructure the command rather than single-quoting it.

## Security Guarantees

- Real secret never in the command string, argv, file, log, or tool response
- Real secret only in the subprocess `env` for the call's lifetime
- Every real secret registered with RedactingFilter before injection
- Placeholders are single-use with a TTL (default 300s); consumption is atomic
- Middleware registration is fail-closed: if it cannot register, the plugin
  refuses to load (v0.4.3), because running without injection would expose secrets

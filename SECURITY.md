# Security Model — hermes-vaultwarden-plugin

**Applies to:** v0.7.1

## Threat Model

This plugin handles highly sensitive credentials (master password, client
secret, SSH private keys, vault item secrets). The primary threat vectors are:

01. **Secret leakage into the agent's context window** (LLM prompt injection)
02. **Secret leakage into logs** (disk persistence, log aggregation)
03. **Secret leakage via subprocess environment** (process inspection)
04. **Compromised dependencies** (supply chain)
05. **Unvalidated `bw` CLI version** (marker-based error detection unreliable
    against an unknown bw build)
06. **Secret exposure via tool-call arguments** (WRITE path only) — when the
    LLM supplies a raw password/passphrase directly to `vaultwarden_store` /
    `vaultwarden_update` (or SSH variants) via the `password` / `pass`
    parameters, the secret enters the LLM context and chat history. This is an
    **acknowledged exception** to the "secrets never enter the LLM context"
    guarantee, which applies only to the READ path. Mitigated by the `*_file`
    input channel (chmod 600, owner-only) and internal generation
    (`generate=true`); raw input emits a dual-channel warning. The `*_env`
    channel was REMOVED in v0.4.9 — see threat vector 12.
07. **Middleware registration failure** (plugin operating without placeholder
    injection would expose secrets in terminal commands)
08. **Metadata leakage via list/search** (usernames, URIs revealing internal
    infrastructure or private emails in chat history)
09. **LLM-controlled ssh-agent socket path** (a socket path supplied through a
    tool call would let a local attacker take over the agent socket; mitigated
    by VWP-02 — the socket path is resolved from developer-controlled
    environment variables only)
10. **PATH-based binary discovery of `bw`** (a compromised `PATH` or a
    same-named malicious binary could run with the plugin's privileges;
    mitigated by VWP-01 — `bw` is executed ONLY from the absolute path pinned
    in `bw_cli_path`, with strict validation and fail-closed loading)
11. **Bootstrap secret exposure via OS environment / `.env`** (in multiplex
    gateway mode the LLM shares the plugin's OS user, so secrets loaded from
    the Hermes `.env` file were readable via `cat /opt/data/.env`, and they
    sat in the process environment before deletion, dumpable via `printenv`;
    closed since v0.5.0 — bootstrap secrets are now read directly from a
    plugin-private `$HERMES_HOME/plugins/vaultwarden/secrets.yaml` file
    (chmod 600 enforced at load time) and NEVER enter the OS environment or
    the Hermes secret_scope. Residual risk: with a `local` terminal backend
    the LLM could still `cat secrets.yaml` (same OS user); since v0.5.5
    (SEC-03) this residual risk is closed FAIL-CLOSED by default — the plugin
    refuses to load on a local/unset backend unless the operator explicitly
    opts in via `allow_insecure_local_backend: true`. `docker` / `ssh` /
    `modal` backends provide privilege separation and are recommended for
    production (see threat vector 15.)
12. **Environment-variable secret channel impracticality** (in multiplex
    gateway mode Hermes loads `.env` only at startup, so a secret added to
    `.env` required a full Hermes restart before the plugin could resolve it;
    closed since v0.4.9 — the `password_env` / `pass_env` tool parameters
    were REMOVED. Supplying them now raises an explicit `ConfigError`. The
    `*_file` channel (chmod 600, owner-only) is the supported alternative.)
13. **Config file bypass via fallback loaders** (the plugin previously read
    `config.yaml` directly via `read_user_config_raw()` or raw YAML parsing,
    bypassing Hermes's isolation and permission model; closed since v0.5.2
    by VWP-05 — configuration is loaded exclusively through the native
    `PluginContext.get_config()` API with no fallback layers.)
14. **Exception-based API detection (fail-open)** (the plugin previously used
    `try/except TypeError` / `try/except AttributeError` to detect Hermes API
    capabilities, which could silently degrade to an insecure mode if an
    unexpected exception occurred; closed since v0.5.2 by VWP-06 — explicit
    capability detection via `inspect.signature()` and `hasattr()` with
    fail-closed semantics.)
15. **Same-user secret exposure via a `local` terminal backend (SEC-03)**
    (when the Hermes terminal backend is `local` — or unset, which defaults to
    local — the LLM-driven terminal executes commands as the SAME OS user that
    owns `$HERMES_HOME/plugins/vaultwarden/secrets.yaml`. Because POSIX file
    permissions only isolate across USERS, not across processes of the same
    user, the agent can trivially bypass every protection the plugin
    implements by running `cat ~/.hermes/plugins/vaultwarden/secrets.yaml` and
    reading `client_secret` / `master_password` in plaintext. Closed since
    v0.5.5 by a FAIL-CLOSED default policy: `register()` determines the
    terminal backend before any tool/middleware registration and REFUSES to
    load (CRITICAL log, returns False) on a `local`/unset backend unless the
    operator explicitly accepts the risk via the native config flag
    `allow_insecure_local_backend: true`. With the flag set to true the plugin
    loads but logs a WARNING that the operator has assumed the same-user
    secret-exposure risk. The `docker` / `ssh` / `modal` backends run the
    agent's terminal in a different privilege domain, keep secrets.yaml
    unreadable to the LLM, and load normally regardless of the flag — they
    remain the recommended production posture.)
16. **Insecure transport to the Vaultwarden server** (an `http://` server URL
    could expose authentication material and vault data in transit. Mitigated
    by HTTPS enforcement: `server_url` must use `https://` unless the operator
    explicitly enables `allow_insecure_http: true` for local/testing
    environments. Production deployments should keep this override disabled.)
17. **Filesystem redirection and unsafe local secret storage** (symlinked
    secret directories, symlinked `.bw-data`, symlinked `secrets.yaml`,
    wrong owner, or group/world-accessible permissions could redirect or leak
    secret material. Mitigated by shared fail-closed filesystem validation:
    security-sensitive paths are validated before use and rejected if they are
    symlinks, have unsafe ownership, or have unsafe permissions.)

## Primary Security Controls

These controls MUST NOT fail. They are the foundation of the plugin's security:

| Control | Mechanism |
| --- | --- |
| Placeholder injection|On the READ path (vault → agent), secrets never enter the agent's context window. `vaultwarden_get_secret_ref` returns a `$__VW_SECRET_xxxx__` reference (v0.4.4, VWP-04); the real value is injected at command execution time by the Hermes `tool_execution` middleware via a **temp file**: the secret is written to a chmod 600 file (mkstemp, atomic) in a dedicated chmod 700 directory under `$XDG_RUNTIME_DIR` (`vw-secrets/`, typically tmpfs), and the command is rewritten so the reference becomes `$(< path)`. The command string, argv, shell history, and logs only ever contain the `$(< path)` reference — no shell-escape or exposure of the secret itself. The temp file is deleted in a `finally` block even if the command fails. No escape hatch (direct secret retrieval removed in v0.3.7). **EXCEPTION — WRITE path (agent → vault):** if the LLM supplies a raw secret directly to `vaultwarden_store` / `vaultwarden_update` (or SSH variants) via the `password` / `pass` parameters, that secret DOES enter the LLM context and chat history. The secure alternatives are `password_file` / `pass_file` (owner-only file, chmod 600, permission-validated) or `generate=true` (internal generation). Raw input is accepted but emits a dual-channel warning (log + tool response) directing the agent to warn the user.|
| Subprocess env isolation | All `bw` calls run with a minimal, explicitly constructed environment. The parent environment is NEVER inherited. |
| SSH environment isolation | All SSH subprocess calls (`ssh-add`, `ssh-agent`, `ssh-keygen`) run via `_ssh_base_env()` — a minimal, explicitly allowlisted environment. The parent environment is NEVER inherited. (VWP-08) |
| Password generation | `vaultwarden_store` / `vaultwarden_update` with `generate=true` generate a password and store it directly in the vault. The generated value is never returned to the LLM — only a placeholder is. (VWP-12) |
| Session key in memory only | The Bitwarden session key is never written to disk. It lives exclusively in `AuthManager` (plugin memory) and an in-process weak-reference registry, and reaches the `bw` CLI ONLY as the `BW_SESSION` variable of the isolated subprocess environment — never via argv (which would leak to `ps`), never via file. Since v0.6.4 the injection is guaranteed at the single subprocess-env choke point (`BwCli._ensure_session_env()`): every session-requiring command (`list`, `get`, `create`, `edit`, `delete`, `sync`, …) receives `BW_SESSION` from the AuthManager when the vault is unlocked, so a caller that forgets to pass it can no longer silently run `bw` in a locked state (the v0.6.3 regression: empty lists / exit 1). The parent environment remains non-inherited; explicit caller-provided env values take precedence; non-session commands are unaffected. Regression tests pin all four properties (injection, fallback, no inheritance, no key in errors/logs). |
| SSH passphrase via env | The SSH passphrase is delivered via `SSH_ASKPASS` + environment variable, never written to a file. Since v0.7.0 (HVA-01), SSH passphrases are released from the redaction registry after their execution scope concludes — no plaintext SSH secret lingers in the registry. |
| Temp file cleanup | SSH key temp files are created with `mkstemp()` (0600 perms) and deleted in a `finally` block. |
| Secret input channels|Write tools (`vaultwarden_store`, `vaultwarden_update`, `vaultwarden_store_ssh`, `vaultwarden_update_ssh`) accept secrets through two mutually exclusive channels: (1) owner-only file (`password_file` / `pass_file`, chmod 600, permission-validated before reading) — keeps the secret OUT of the LLM context; (2) raw direct input (`password` / `pass`) — the secret ENTERS the LLM context and chat history, and emits a dual-channel warning (log + tool response). `generate=true` avoids both by generating internally. Conflicting sources are rejected with `ConfigError`. The `*_env` channel was REMOVED in v0.4.9 (see threat vector 12).|
| SSH key generation | `vaultwarden_store_ssh` / `vaultwarden_update_ssh` with `generate=true` produce a keypair internally: a 32-char passphrase generated by the SAME `bw generate` path used by `store`/`update` `generate=true` (one consistent secret-generation mechanism), and the key via `ssh-keygen` with the passphrase delivered via the **`SSH_ASKPASS` mechanism** (`_askpass_env()`: helper script whose body is only `echo "$VW_SSH_PASS"`, `SSH_ASKPASS_REQUIRE=force`, passphrase in the subprocess environment only — never stdin, which OpenSSH's `read_passphrase()` does not consume, and never `-N` argv, which would leak to `ps`; `stdin=DEVNULL` makes a tty prompt impossible), followed by a **post-generation encryption verify** (`ssh-keygen -yf` with stdin=DEVNULL must FAIL, proving the key is protected; the operation aborts otherwise). All passphrase-handling SSH subprocesses run with `start_new_session=True` to detach the child from any controlling terminal. The private key and passphrase go to the vault; only the **public key** (non-secret) and fingerprint are returned. Temp artifacts are 0700/0600 and removed in a `finally` block. Key rotation (`ssh_update` + `generate=true`) requires `confirm=true`. |
| Binary path pinning (VWP-01) | Since v0.4.7, `bw` is executed ONLY from the absolute path configured in `plugins.entries.vaultwarden.settings.bw_cli_path`. There is NO PATH lookup (`shutil.which` removed) and NO environment-variable override — config.yaml is the single source of truth. `validate_bw_path()` rejects: empty/relative paths, any symlink in the path chain, non-regular files, non-executable files, group-/world-writable files, and files owned by anyone other than root or the current effective uid. On any failure the plugin fails closed: `register()` returns False and the agent continues without it. NOTE: cryptographic authenticity/hash verification of the `bw` binary, and pinning of SSH helper binaries, are explicitly OUT OF SCOPE — they are the operator's responsibility. |
| bw version enforcement | At startup, `BwCli._check_version()` runs `bw --version` with an isolated environment and validates against a hardcoded minimum (2026.9.1). Fail-closed with NO override: an unsupported or unparseable version raises `UnsupportedBwVersionError`, logs the error, and prevents the plugin from loading. The minimum version is not configurable — compatibility is the plugin author's responsibility, not the user's. (VWP-11) |
| Middleware fail-closed | If the Hermes placeholder-injection middleware (the v0.4.4 `tool_execution` file-injection middleware) fails to register, `register()` propagates the exception and the plugin does NOT load. This prevents operating without secret injection, which would expose raw secrets in terminal commands. Consistent with the fail-closed bw version check and fail-closed auth. (VWP-03) |
| Metadata masking (opt-in) | When `metadata_masking=true`, `username` and `uris` are replaced with `***` in `list`/`search` responses. `name`, `id`, `type` are never masked. Default OFF preserves search/list usability while offering a privacy mode for environments where metadata is sensitive. (VWP-13) |
| Bootstrap secrets from secrets.yaml | Since v0.5.0, `client_secret` and `master_password` are read directly from `$HERMES_HOME/plugins/vaultwarden/secrets.yaml`. Before YAML parsing, the file is validated: absolute path, regular non-symlink file, owned by the current effective UID, no group/other access bits. An existing but insecure `secrets.yaml` is NEVER parsed and no bootstrap secret is loaded from it. Bootstrap secrets NEVER enter the OS environment or the Hermes secret_scope, closing the `printenv` and `cat .env` attack surfaces. SEC-03 (v0.5.5): on a `local`/unset terminal backend — where the LLM shares this OS user and could still `cat` the file — the plugin now REFUSES to load unless `allow_insecure_local_backend: true` is set explicitly; `docker` / `ssh` / `modal` backends are recommended for production. |
| Local-backend fail-closed policy (SEC-03) | Since v0.5.5, `register()` classifies the Hermes terminal backend (`secrets.check_terminal_backend()` returns it; resolution: `TERMINAL_ENV` override, then `terminal.backend` in `$HERMES_HOME/config.yaml`) BEFORE any tool/middleware registration. Sandboxed backends (`docker` / `ssh` / `modal`) → INFO, load proceeds. `local` or unset/unknown backend → treated as NOT privilege-separated: with `allow_insecure_local_backend` false (the default; missing key or ambiguous value also resolve to false) the plugin logs a CRITICAL naming the same-user `cat secrets.yaml` risk and returns False — no partial state is left behind. With the flag explicitly true the plugin logs a WARNING (operator assumes the risk) and continues. The flag is read ONLY through the native Hermes config API (`plugins.entries.vaultwarden.settings`, VWP-05) — there is NO `.env` / OS-environment / ad-hoc YAML channel for it, and the check performs no network calls and spawns no subprocesses. |
| Native config API only (VWP-05) | Since v0.5.2, plugin configuration is loaded exclusively through the native Hermes `PluginContext.get_config()` API. The former fallback layers (`read_user_config_raw()`, direct YAML file read) have been REMOVED — they bypassed Hermes's isolation and permission model. If the native API yields no configuration, the plugin logs a warning and does not load (fail-closed). |
| Explicit capability detection (VWP-06) | Since v0.5.2, Hermes API compatibility is determined via explicit capability detection (`inspect.signature()` for `register_tool`, `hasattr()` for `register_hook`) instead of exception-based probing. If a required API is unavailable, the plugin fails closed with a `RuntimeError` — it never silently degrades to an insecure mode. |
| Result redaction via transform_tool_result (SEC-01) | Since v0.5.4, the authoritative confidentiality boundary for injected secrets is the Hermes `transform_tool_result` transformation hook (`make_result_redactor` in `hooks.py`), whose RETURN VALUE replaces the tool result before it reaches the model. The per-execution injected-secret set is handed off from the `tool_execution` middleware via a `contextvars.ContextVar` (cleared in a `finally` block — no plaintext persists across turns); the transformer performs exact recursive `[REDACTED]` replacement over str/dict/list results and writable `.output` objects, then applies the global `RedactingFilter` pass. `post_tool_call` is observer-only (placeholder cleanup, metrics, secret-free error surfacing) and no longer mutates results. FAIL-CLOSED: hosts without `transform_tool_result` are refused at load (`register()` returns False). |
| Atomic placeholder resolution (SEC-02) | If a command contains the same placeholder multiple times, it is resolved exactly once via `consume_and_resolve()`, creating a single temp file per unique token. All occurrences are rewritten to the same secure file reference. This prevents sequential consumption hazards and guarantees single-use semantics even on repeated references. |
| HTTPS enforcement | `server_url` must use the `https://` scheme. `http://` is rejected fail-closed at plugin load unless the operator explicitly sets `allow_insecure_http: true` (local/testing override; logs a sanitized WARNING naming only scheme + hostname). Invalid schemes (`ftp://`, `file://`, `ws://`, missing) are always rejected regardless of the override. |
| Filesystem fail-closed hardening | Security-sensitive filesystem paths are validated before use via shared filesystem validators (`secure_fs.py`). The validators reject symlinks, require ownership by the current effective UID, and enforce strict permissions. Insecure paths are never silently repaired. Validation failures raise `FilesystemSecurityError`, which is never caught-and-ignored. |
| Secrets directory load-time validation | The secret-injection directory (`$XDG_RUNTIME_DIR/vw-secrets`) is validated during plugin registration before any tool or hook is registered. A symlinked, wrong-owner, or insecure-mode directory aborts plugin activation. The plugin never becomes partially active with an insecure secrets directory. |
| Bitwarden appdata hardening | The Bitwarden appdata directory (`.bw-data`) is validated before `BITWARDENCLI_APPDATA_DIR` is exported and before every `bw` subprocess call. A symlinked, wrong-owner, or group/world-accessible `.bw-data` directory blocks Bitwarden CLI execution. |
| `secrets.yaml` pre-parse validation | Before bootstrap secret parsing, `secrets.yaml` is validated as an absolute path, regular file, non-symlink, owned by the current effective UID, with no group/other access bits. An existing but insecure `secrets.yaml` is never parsed. |
| Lifecycle hook fail-closed registration | Critical lifecycle hooks required for cleanup and session termination are validated and registered before tools are exposed. If a required lifecycle hook cannot be registered, plugin initialization aborts. Existing `transform_tool_result` and `tool_execution` fail-closed behavior remains unchanged. |
| Scoped redaction lifecycle | Runtime secrets registered with the RedactingFilter are retained only for active execution scopes using thread-safe reference counting. Overlapping executions sharing a secret do not cause premature removal. Process-scoped secrets remain retained for the process lifetime. |
| Shell-safe secret file injection | Injected temporary secret-file paths are shell-quoted (shlex.quote) before command substitution to prevent command injection from unsafe runtime directory paths. Control-character paths fail closed. SEC-02 single-temp-file and $-prefix fail-safe semantics preserved. |

### File-injected Placeholder Injection (VWP-04) — Crash Recovery (VWP-20)

**Platform-dependent risk:** On native Linux with systemd, `$XDG_RUNTIME_DIR` is typically a tmpfs (RAM-backed), so temp files do not hit physical disk and are cleared on logout/reboot. In Docker containers or on Windows, `$XDG_RUNTIME_DIR` may be backed by persistent storage (overlay filesystem or NTFS), so temp files may persist on disk after a crash (SIGKILL/SIGTERM). The plugin mitigates this with startup cleanup: on each launch, it removes any temp files older than the placeholder TTL (5 minutes), ensuring that files left behind by a previous crash are deleted.

**SSH socket path restriction (VWP-02):** The `vaultwarden_use_ssh` tool no
longer accepts a user/LLM-specified socket path. The socket is resolved from
developer-controlled environment variables (`$VW_SSH_SOCKET_PATH` or
`$XDG_RUNTIME_DIR/auth.sock`), eliminating the socket takeover attack vector.
Symlink checks prevent path redirection. Stale sockets are cleaned at startup.

**Binary path pinning (VWP-01):** The `bw` CLI is no longer discovered via
`PATH` and the old environment override was removed. Operators MUST set
`bw_cli_path` to the FULL absolute path of the binary (e.g.
`/usr/local/bin/bw`). Before any subprocess is spawned, the path is validated
(absolute, regular file, no symlink anywhere in the chain, executable, not
group/world-writable, owned by root or the effective uid). An unconfigured or
invalid path makes `register()` return False — the plugin does not load and
no binary is ever executed from an attacker-influenced location. Binary
authenticity (checksums/signatures) remains the operator's responsibility.

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

Since v0.6.4, session-state failures are reported precisely instead of as a
generic `bw <cmd> failed (exit 1)`: stderr is sanitized (session-key-looking
tokens scrubbed, length-capped) before classification. Explicit expiry markers
(`not logged in`, `invalid session key`, …) surface `SESSION_EXPIRED` with an
operator suggestion to re-unlock; generic lock markers surface `SESSION_ERROR`
(the code the plugin's run_with_recovery auto re-unlock path keys off, kept
backwards-compatible). The raw session key never appears in the tool response,
stderr excerpt, or logs.

### Retry Safety (VWP-10)

Network-error retries use bounded exponential backoff with additive jitter
(`base * 2^attempt + uniform(0,1)`, capped at `max_delay`) and are restricted
to idempotent operations only. Non-idempotent `bw` calls (`login --apikey`,
`unlock`, `create attachment`, `delete item/attachment`) are explicitly marked
`retryable=False` and never retried, preventing duplicate session keys,
duplicate attachments, or false-negative delete results.

### Compatibility Layer (VWP-17)

All Hermes API version compatibility, config loading fallback logic, bw version
parsing, and exception-code extraction are centralized in `compat.py`. This
single module is the only place where version-specific or API-version-specific
code lives, improving maintainability and security auditability. No other
module contains `try/except` blocks for API detection or version-specific
branching.

## Defense-in-Depth: Log Redaction

As of v0.3.7 (VWP-14), the `allow_direct_secret_retrieval` escape hatch has been
completely removed. There is no code path that returns a raw secret to
the LLM. The placeholder model is the only supported path for secret
access.

The `RedactingFilter` (in `security.py`) is a **defense-in-depth** mechanism.
It provides an additional layer of protection but has known limitations:

- **Memory storage:** Runtime secrets are retained using execution-scoped reference counting. A secret value is removed from the redaction state when all active execution scopes that retained it have completed. Process-scoped secrets, such as startup-injection secrets, remain retained for the process lifetime.
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

## Testing & Verification

The plugin's security controls are validated by dedicated test suites:

| Suite | Coverage | Related controls |
| --- | --- | --- |
| Concurrency tests | Placeholder registry thread-safety, atomic consumption, race conditions | VWP-18 |
| Env isolation tests | Subprocess environment allowlist enforcement, parent env never inherited | VWP-19 |
| Crash recovery tests | Startup cleanup of stale temp files after SIGKILL/SIGTERM | VWP-20 |
| Filesystem hardening tests | Symlink rejection, ownership enforcement, permission enforcement, plugin load failure, `.bw-data` blocking, insecure `secrets.yaml` rejection | AUD-03 / AUD-04 / AUD-08 |
| Lifecycle hook registration tests | Missing or failing required lifecycle hook registration refuses plugin load; successful registration loads the plugin | AUD-06 |
| Scoped redaction tests | Execution-scoped retain/release lifecycle, overlapping same-secret executions, process-scoped secret retention, and redactor baseline restoration | AUD-02 |
| Shell-escape injection tests | Malicious runtime-directory names (spaces, ;, $, backticks, quotes, newlines) produce safe quoted substitutions; control-character paths fail closed; SEC-02 and fail-safe preserved | AUD-05 |
| Session key injection regression tests | `BW_SESSION` reaches the isolated subprocess env (explicit + AuthManager fallback at the choke point), parent env still never inherited, session key never appears in error messages (locked → `SESSION_ERROR`, expired → `SESSION_EXPIRED`) | HOTFIX-01 (v0.6.4) |

All CI checks (pytest, ruff) are **blocking** — a failing check prevents merge.

## Development Rules

- Never log raw `bw` output (use structured status codes only).
- Runtime secrets must be retained through execution-scoped retain/release APIs; do not reintroduce unbounded global registration for runtime secrets.
- Process-scoped secrets must be registered through the process-scoped retention API and must not be released by execution cleanup.
- Secret release must be reference-counted and thread-safe.
- Never log secret values when diagnosing redactor or scope lifecycle issues.
- Always call `register_secret()` before any operation that handles secrets.
- Always call `forget_secret()` in a `finally` block.
- Every SSH secret registration must be paired with a release in a
  `finally` block, or use `retain_in_execution_scope()` when an active
  execution scope exists (HVA-01). When the scope owns the release, do NOT
  also call `forget_secret()` manually — exactly one release per retention.
- Never pass secret values as log message arguments.
- Generated passwords (via `generate=true`) must never be returned to the
caller — only a placeholder.
- Placeholders are user-facing as `$__VW_SECRET_x__` (registry tokens stay
bare `__VW_SECRET_x__` internally) and must always be documented as
double-quote-only (or unquoted) references. The middleware must inject
secrets via a temp file ONLY (`$(< path)` rewrite); it must NEVER rewrite
the command string with the raw secret value.
- Injected secret-file paths must always be shell-quoted via the shared
quoting helper (`quote_injected_path`) before command substitution; never
interpolate a raw path into a shell command.
- Never pass a raw secret in a tool call when `*_file` is available;
the plugin warns (log + response `warning` field) on raw input. The response
`warning` is an imperative instruction directing the agent to warn the user;
both the log line and the response warning stay value-free.
- All secret generation MUST route through `_generate_password` (`bw generate`); do not introduce parallel generators (e.g. stdlib `secrets`).
- Neither `ssh-add` nor `ssh-keygen` may receive a passphrase via stdin
(`input=`) or `-N` argv. OpenSSH reads passphrases through
`read_passphrase()`, which never consumes stdin and prompts `/dev/tty`
when a tty is present. Always use `_askpass_env()` (single implementation)
and pass `stdin=subprocess.DEVNULL`.
- Any future `ssh-*` subprocess call must use `_askpass_env()` /
`_ssh_base_env()` — never hand-roll the askpass script.
- Any future passphrase-handling subprocess must set `start_new_session=True`
(detach from any controlling terminal so a `/dev/tty` passphrase prompt or
hang is impossible on interactive sessions) and `stdin=subprocess.DEVNULL`.
- Always verify a generated key is encrypted before storing it
(`ssh-keygen -yf` with stdin=DEVNULL must fail).
- `ssh_update` + `generate=true` is destructive (key rotation) and must
require `confirm=true`.
- Never retry a non-idempotent `bw` operation. When adding a new `bw` command
wrapper, explicitly set `retryable=False` unless the command is proven
idempotent (read-only or safe-to-repeat write).
- The `_classify_error()` priority order (Cat-2 → rate_limit → Cat-1 → Cat-3)
must not be changed without updating the source-category table above.
- The middleware registration in `register()` must NEVER be wrapped in a
try/except that swallows failures. Fail-closed is mandatory.
- `_metadata()` must never mask `name` — it is the primary identifier.
- When adding new metadata-exposing tools, apply the same `mask` parameter.
- Configuration loading MUST go through `compat.extract_plugin_section()`
(native Hermes API only). Never read `config.yaml` directly. (VWP-05)
- API capability detection MUST use `compat.register_tool_compat()` /
`compat.register_hook_if_available()`. Never use exception-based probing. (VWP-06)
- Never bypass `secure_fs` validation for security-sensitive paths.
- Never catch and ignore `FilesystemSecurityError`.
- Never silently repair insecure permissions, ownership, or symlinks.
- Use `os.lstat()` for filesystem validation where symlink traversal must be prevented.
- Filesystem validation errors may include paths, but must never include secret values, file contents, or environment variables.
- Critical lifecycle hooks must be registered fail-closed.
- Never wrap mandatory lifecycle-hook registration in a try/except block that swallows failures.
- Do not treat a successful `None` return value from hook registration as failure unless the host API explicitly defines it as failure.
- Lifecycle-hook registration failures must abort plugin initialization before tools are exposed.

## Supply Chain

- Dev dependencies are pinned via `uv.lock` (committed to the repository).
(VWP-16)
- CI installs exclusively from the lockfile (`uv sync --frozen`).
- All CI checks (pytest, ruff) are **blocking** — a failing check prevents
merge. (VWP-15)

## Audit Status (20/20 VWP + SEC-01 + SEC-02 + SEC-03 + AUD-01 + AUD-02 + AUD-03 + AUD-04 + AUD-05 + AUD-06 + AUD-07 + AUD-08 + HOTFIX-01 implemented/rejected)

| ID | Description | Implemented |
| --- | --- | --- |
| SEC-01 | Result redaction via authoritative `transform_tool_result` hook (ContextVar handoff; `post_tool_call` reduced to observer-only; fail-closed load without the hook) | v0.5.4 |
| SEC-02 | Atomic placeholder resolution for multi-occurrence commands — repeated placeholder references are resolved exactly once, creating one temp file and rewriting all occurrences to the same secure file reference | v0.5.7 |
| SEC-03 | Fail-closed policy for local terminal backend (`allow_insecure_local_backend` opt-in; plugin refuses to load on `local`/unset backend by default) | v0.5.5 |
| AUD-01 | HTTPS enforcement for `server_url` — `server_url` MUST use `https://` scheme; `http://` rejected fail-closed unless `allow_insecure_http` override is set; invalid schemes always rejected. Originally implemented in v0.6.0 but reverted before shipping; this is the first production implementation. | v0.6.9 |
| AUD-02 | Scoped redaction lifecycle — runtime secrets registered with the RedactingFilter are retained only for active execution scopes using thread-safe reference counting; overlapping executions sharing a secret are protected from premature removal; process-scoped secrets remain retained for the process lifetime | v0.6.5 |
| AUD-03 | Secrets directory fail-closed validation at plugin load — `register()` runs `secure_fs.ensure_hardened_directory()` before any tool/hook registration; symlink / wrong owner / mode ≠ 0700 aborts activation (no partial state, no silent chmod repair) | v0.6.2 |
| AUD-04 | `.bw-data` fail-closed validation before any `bw` invocation — shared hardened-directory validator gates `BITWARDENCLI_APPDATA_DIR` export and every `bw` subprocess call; insecure appdata dir blocks `bw` execution | v0.6.2 |
| AUD-05 | Shell-escape injected file paths — injected secret temp-file paths are shell-quoted before command substitution; control-character runtime paths fail closed; SEC-02 and $-prefix fail-safe behavior preserved | v0.6.6 |
| AUD-06 | Fail-closed lifecycle hook registration — required `post_tool_call` and session-end lifecycle hooks are validated and registered before tools are exposed; plugin refuses to load if a required lifecycle hook cannot be registered | v0.6.3 |
| AUD-07 | Runtime version disclosure — investigated and **rejected as false positive**. The `bw` CLI version log (`bw_cli.py`) is intentional for operational diagnostics and audit traceability. Erroneous coding-agent rules prohibiting version/audit codes in runtime logs were removed from `hooks.py` docstring. | v0.6.7 (rejected) |
| HOTFIX-01 | `BW_SESSION` injection regression fix — session key guaranteed at the subprocess-env choke point (`BwCli._ensure_session_env()`) for all session-requiring `bw` commands (v0.6.3 regression: empty `list`, exit 1 on `create`); sanitized stderr classification adds `SESSION_EXPIRED` vs `SESSION_ERROR`; env isolation and memory-only key handling unchanged; pinned by regression tests | v0.6.4 |
| AUD-08 | `secrets.yaml` fail-closed filesystem validation before YAML parsing — `secure_fs.ensure_hardened_secret_file()` requires absolute path, regular non-symlink file, euid ownership, no group/other access; insecure file is NEVER parsed | v0.6.2 |
| VWP-01 | Binary path pinning (hash verification = operator responsibility) | v0.4.7 |
| VWP-02 | SSH socket path restriction (dev-controlled env vars) | v0.4.6 |
| VWP-03 | Middleware fail-closed registration | v0.4.3 |
| VWP-04 | File-based secret injection (XDG_RUNTIME_DIR) | v0.4.4 |
| VWP-05 | Native Hermes config API (fallback removal) | v0.5.2 |
| VWP-06 | Explicit capability detection (fail-closed) | v0.5.2 |
| VWP-07 | Log redaction (RedactingFilter + structured JSON) | v0.3.6 |
| VWP-08 | SSH subprocess env isolation | v0.3.7 |
| VWP-09 | Error taxonomy (4-category marker classification) | v0.3.8 |
| VWP-10 | Bounded exponential backoff + jitter | v0.3.8 |
| VWP-11 | bw version enforcement (fail-closed, no override) | v0.3.8 |
| VWP-12 | generate=true integration (no direct retrieval) | v0.3.7 |
| VWP-13 | Metadata masking (opt-in) | v0.4.3 |
| VWP-14 | Direct secret retrieval removal | v0.3.7 |
| VWP-15 | CI blocking checks | v0.3.6 |
| VWP-16 | Dependency lock (uv.lock) | v0.3.6 |
| VWP-17 | Compatibility code centralization (compat.py) | v0.5.1 |
| VWP-18 | Concurrency tests | v0.4.5 |
| VWP-19 | Env isolation tests | v0.4.5 |
| VWP-20 | Crash recovery (startup stale cleanup) | v0.4.5 |

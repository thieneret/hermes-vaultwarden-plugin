# Security Model — hermes-vaultwarden-plugin

## Threat Model

This plugin handles highly sensitive credentials (master password, client
secret, SSH private keys, vault item secrets). The primary threat vectors are:

1.  **Secret leakage into the agent's context window** (LLM prompt injection)
2.  **Secret leakage into logs** (disk persistence, log aggregation)
3.  **Secret leakage via subprocess environment** (process inspection)
4.  **Compromised dependencies** (supply chain)
5.  **Unvalidated `bw` CLI version** (marker-based error detection unreliable
    against an unknown bw build)
6.  **Secret exposure via tool-call arguments** (a raw password/passphrase typed
    into a tool call enters the LLM context and chat history; mitigated since
    v0.4.0 by the `*_file` secret input channel and internal SSH key generation
    so no passphrase is ever user-supplied in generate mode. The `*_env` channel
    was REMOVED in v0.4.9 — see threat vector 12.)
7.  **Middleware registration failure** (plugin operating without placeholder
    injection would expose secrets in terminal commands)
8.  **Metadata leakage via list/search** (usernames, URIs revealing internal
    infrastructure or private emails in chat history)
9.  **LLM-controlled ssh-agent socket path** (a socket path supplied through a
    tool call would let a local attacker take over the agent socket; mitigated
    since v0.4.6 by VWP-02 — the socket path is resolved from
    developer-controlled environment variables only)
10. **PATH-based binary discovery of `bw`** (a compromised `PATH` or a
    same-named malicious binary could run with the plugin's privileges;
    mitigated since v0.4.7 by VWP-01 — `bw` is executed ONLY from the
    absolute path pinned in `bw_cli_path`, with strict validation and
    fail-closed loading)
11. **Bootstrap secret exposure via OS environment / `.env`** (in multiplex
    gateway mode the LLM shares the plugin's OS user, so secrets loaded from
    the Hermes `.env` file were readable via `cat /opt/data/.env`, and they
    sat in the process environment before deletion, dumpable via `printenv`;
    closed since v0.5.0 — bootstrap secrets are now read directly from a
    plugin-private `$HERMES_HOME/plugins/vaultwarden/secrets.yaml` file
    (chmod 600 enforced at load time) and NEVER enter the OS environment or
    the Hermes secret_scope. Residual risk: with a `local` terminal backend
    the LLM could still `cat` `secrets.yaml` (same OS user); since v0.5.5
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
    reading `client_secret` / `master_password` in plaintext. Until v0.5.4 the
    plugin merely logged a WARNING recommending a sandboxed backend — an
    advisory, not a control: the confidentiality boundary silently degraded to
    "trust the model not to `cat` the file". Closed since v0.5.5 by a
    FAIL-CLOSED default policy: `register()` determines the terminal backend
    before any tool/middleware registration and REFUSES to load (CRITICAL log,
    returns False) on a `local`/unset backend unless the operator explicitly
    accepts the risk in writing via the native config flag
    `allow_insecure_local_backend: true` (boolean, default false; any
    ambiguity resolves to false — never fail open). With the flag set to true
    the plugin loads but logs a WARNING that the operator has assumed the
    same-user secret-exposure risk. The `docker` / `ssh` / `modal` backends
    run the agent's terminal in a different privilege domain, keep
    secrets.yaml unreadable to the LLM, and load normally regardless of the
    flag — they remain the recommended production posture.)

## Primary Security Controls

These controls MUST NOT fail. They are the foundation of the plugin's security:

| Control | Mechanism |
|---------|-----------|
| Placeholder injection | Secrets never enter the agent's context window. `vaultwarden_get_secret_ref` returns a `$__VW_SECRET_xxxx__` reference (v0.4.4, VWP-04); the real value is injected at command execution time by the Hermes `tool_execution` middleware via a **temp file**: the secret is written to a chmod 600 file (mkstemp, atomic) in a dedicated chmod 700 directory under `$XDG_RUNTIME_DIR` (`vw-secrets/`, typically tmpfs), and the command is rewritten so the reference becomes `$(< path)`. The command string, argv, shell history, and logs only ever contain the `$(< path)` reference — no shell-escape or exposure of the secret itself. The temp file is deleted in a `finally` block even if the command fails. No escape hatch (direct secret retrieval removed in v0.3.7). |
| Subprocess env isolation | All `bw` calls run with a minimal, explicitly constructed environment. The parent environment is NEVER inherited. |
| SSH environment isolation | All SSH subprocess calls (`ssh-add`, `ssh-agent`, `ssh-keygen`) run via `_ssh_base_env()` — a minimal, explicitly allowlisted environment. The parent environment is NEVER inherited. (VWP-08) |
| Password generation | `vaultwarden_store` / `vaultwarden_update` with `generate=true` generate a password and store it directly in the vault. The generated value is never returned to the LLM — only a placeholder is. (VWP-12) |
| Session key in memory only | The Bitwarden session key is never written to disk. |
| SSH passphrase via env | The SSH passphrase is delivered via `SSH_ASKPASS` + environment variable, never written to a file. |
| Temp file cleanup | SSH key temp files are created with `mkstemp()` (0600 perms) and deleted in a `finally` block. |
| Secret input channels | Passwords/passphrases for write tools can be supplied via an owner-only file (chmod 600, permission-validated before reading), keeping them out of the LLM context. Conflicting sources are rejected (`ConfigError`). Raw direct input is permitted but emits a warning in BOTH the log and the tool response. The `*_env` channel was REMOVED in v0.4.9 (see threat vector 12). |
| SSH key generation | `vaultwarden_store_ssh` / `vaultwarden_update_ssh` with `generate=true` produce a keypair internally: a 32-char passphrase generated by the SAME `bw generate` path used by `store`/`update` `generate=true` (one consistent secret-generation mechanism), and the key via `ssh-keygen` with the passphrase delivered via the **`SSH_ASKPASS` mechanism** (`_askpass_env()`: helper script whose body is only `echo "$VW_SSH_PASS"`, `SSH_ASKPASS_REQUIRE=force`, passphrase in the subprocess environment only — never stdin, which OpenSSH's `read_passphrase()` does not consume, and never `-N` argv, which would leak to `ps`; `stdin=DEVNULL` makes a tty prompt impossible), followed by a **post-generation encryption verify** (`ssh-keygen -yf` with stdin=DEVNULL must FAIL, proving the key is protected; the operation aborts otherwise). All passphrase-handling SSH subprocesses run with `start_new_session=True` to detach the child from any controlling terminal. The private key and passphrase go to the vault; only the **public key** (non-secret) and fingerprint are returned. Temp artifacts are 0700/0600 and removed in a `finally` block. Key rotation (`ssh_update` + `generate=true`) requires `confirm=true`. |
| Binary path pinning (VWP-01) | Since v0.4.7, `bw` is executed ONLY from the absolute path configured in `plugins.entries.vaultwarden.settings.bw_cli_path`. There is NO PATH lookup (`shutil.which` removed) and NO environment-variable override — config.yaml is the single source of truth. `validate_bw_path()` rejects: empty/relative paths, any symlink in the path chain, non-regular files, non-executable files, group-/world-writable files, and files owned by anyone other than root or the current effective uid. On any failure the plugin fails closed: `register()` returns False and the agent continues without it. NOTE: cryptographic authenticity/hash verification of the `bw` binary, and pinning of SSH helper binaries, are explicitly OUT OF SCOPE — they are the operator's responsibility. |
| bw version enforcement | At startup, `BwCli._check_version()` runs `bw --version` with an isolated environment and validates against a hardcoded minimum (2026.9.1). Fail-closed with NO override: an unsupported or unparseable version raises `UnsupportedBwVersionError`, logs the error, and prevents the plugin from loading. The minimum version is not configurable — compatibility is the plugin author's responsibility, not the user's. (VWP-11) |
| Middleware fail-closed | If the Hermes placeholder-injection middleware (the v0.4.4 `tool_execution` file-injection middleware) fails to register, `register()` propagates the exception and the plugin does NOT load. This prevents operating without secret injection, which would expose raw secrets in terminal commands. Consistent with the fail-closed bw version check and fail-closed auth. (VWP-03) |
| Metadata masking (opt-in) | When `metadata_masking=true`, `username` and `uris` are replaced with `***` in `list`/`search` responses. `name`, `id`, `type` are never masked. Default OFF preserves search/list usability while offering a privacy mode for environments where metadata is sensitive. (VWP-13) |
| Bootstrap secrets from secrets.yaml | Since v0.5.0, `client_secret` and `master_password` are read directly from `$HERMES_HOME/plugins/vaultwarden/secrets.yaml` (chmod 600 enforced, fail-closed `ConfigError` otherwise). They NEVER enter the OS environment or the Hermes secret_scope, closing the `printenv` and `cat .env` attack surfaces. SEC-03 (v0.5.5): on a `local`/unset terminal backend — where the LLM shares this OS user and could still `cat` the file — the plugin now REFUSES to load unless `allow_insecure_local_backend: true` is set explicitly; `docker` / `ssh` / `modal` backends are recommended for production. |
| Local-backend fail-closed policy (SEC-03) | Since v0.5.5, `register()` classifies the Hermes terminal backend (`secrets.check_terminal_backend()` returns it; resolution: `TERMINAL_ENV` override, then `terminal.backend` in `$HERMES_HOME/config.yaml`) BEFORE any tool/middleware registration. Sandboxed backends (`docker` / `ssh` / `modal`) → INFO, load proceeds. `local` or unset/unknown backend → treated as NOT privilege-separated: with `allow_insecure_local_backend` false (the default; missing key or ambiguous value also resolve to false) the plugin logs a CRITICAL naming the same-user `cat secrets.yaml` risk and returns False — no partial state is left behind. With the flag explicitly true the plugin logs a WARNING (operator assumes the risk) and continues. The flag is read ONLY through the native Hermes config API (`plugins.entries.vaultwarden.settings`, VWP-05) — there is NO `.env` / OS-environment / ad-hoc YAML channel for it, and the check performs no network calls and spawns no subprocesses. |
| Native config API only (VWP-05) | Since v0.5.2, plugin configuration is loaded exclusively through the native Hermes `PluginContext.get_config()` API. The former fallback layers (`read_user_config_raw()`, direct YAML file read) have been REMOVED — they bypassed Hermes's isolation and permission model. If the native API yields no configuration, the plugin logs a warning and does not load (fail-closed). |
| Explicit capability detection (VWP-06) | Since v0.5.2, Hermes API compatibility is determined via explicit capability detection (`inspect.signature()` for `register_tool`, `hasattr()` for `register_hook`) instead of exception-based probing. If a required API is unavailable, the plugin fails closed with a `RuntimeError` — it never silently degrades to an insecure mode. |
| Result redaction via transform_tool_result (SEC-01) | Since v0.5.4, the authoritative confidentiality boundary for injected secrets is the Hermes `transform_tool_result` transformation hook (`make_result_redactor` in `hooks.py`), whose RETURN VALUE replaces the tool result before it reaches the model. The per-execution injected-secret set is handed off from the `tool_execution` middleware via a `contextvars.ContextVar` (cleared in a `finally` block — no plaintext persists across turns); the transformer performs exact recursive `[REDACTED]` replacement over str/dict/list results and writable `.output` objects, then applies the global `RedactingFilter` pass. `post_tool_call` is observer-only (placeholder cleanup, metrics, secret-free error surfacing) and no longer mutates results. FAIL-CLOSED: hosts without `transform_tool_result` are refused at load (`register()` returns False). |

### File-injected placeholder injection (VWP-04) — crash recovery (VWP-20)

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

1.  **Node.js network codes** (`ECONNREFUSED`, `ETIMEDOUT`, `fetch failed`, …)
    — most stable, official Node.js API.
2.  **Rate-limit markers** (`too many requests`, `429`) — raised immediately,
    never retried.
3.  **bw CLI state messages** (`not logged in`, `vault is locked`, …) —
    version-dependent; reliability is anchored by the startup version check.
4.  **Server API errors** (`cannot find`, `does not exist`) — least stable,
    server-version-dependent; used only as fallback.

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

-   **Memory storage:** Registered secrets are stored in plugin memory
    (`_secrets: set[str]`) for the duration of the operation.
-   **String replacement:** Uses `str.replace()` which is not cryptographic.
-   **Known gaps:** Base64-encoded or otherwise transformed secrets may
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

| Suite | Coverage | VWP |
|-------|----------|-----|
| Concurrency tests | Placeholder registry thread-safety, atomic consumption, race conditions | VWP-18 |
| Env isolation tests | Subprocess environment allowlist enforcement, parent env never inherited | VWP-19 |
| Crash recovery tests | Startup cleanup of stale temp files after SIGKILL/SIGTERM | VWP-20 |

All CI checks (pytest, ruff) are **blocking** — a failing check prevents merge.

## Development Rules

-   Never log raw `bw` output (use structured status codes only).
-   Always call `register_secret()` before any operation that handles secrets.
-   Always call `forget_secret()` in a `finally` block.
-   Never pass secret values as log message arguments.
-   Generated passwords (via `generate=true`) must never be returned to the
    caller — only a placeholder.
-   Placeholders are user-facing as `$__VW_SECRET_x__` (registry tokens stay
    bare `__VW_SECRET_x__` internally) and must always be documented as
    double-quote-only (or unquoted) references. The middleware must inject
    secrets via a temp file ONLY (`$(< path)` rewrite); it must NEVER rewrite
    the command string with the raw secret value.
-   Never pass a raw secret in a tool call when `*_file` is available;
    the plugin warns (log + response `warning` field) on raw input. The response
    `warning` is an imperative instruction directing the agent to warn the user;
    both the log line and the response warning stay value-free.
-   All secret generation MUST route through `_generate_password` (`bw
    generate`); do not introduce parallel generators (e.g. stdlib `secrets`).
-   Neither `ssh-add` nor `ssh-keygen` may receive a passphrase via stdin
    (`input=`) or `-N` argv. OpenSSH reads passphrases through
    `read_passphrase()`, which never consumes stdin and prompts `/dev/tty`
    when a tty is present. Always use `_askpass_env()` (single implementation)
    and pass `stdin=subprocess.DEVNULL`.
-   Any future `ssh-*` subprocess call must use `_askpass_env()` /
    `_ssh_base_env()` — never hand-roll the askpass script.
-   Any future passphrase-handling subprocess must set `start_new_session=True`
    (detach from any controlling terminal so a `/dev/tty` passphrase prompt or
    hang is impossible on interactive sessions) and `stdin=subprocess.DEVNULL`.
-   Always verify a generated key is encrypted before storing it
    (`ssh-keygen -yf` with stdin=DEVNULL must fail).
-   `ssh_update` + `generate=true` is destructive (key rotation) and must
    require `confirm=true`.
-   Never retry a non-idempotent `bw` operation. When adding a new `bw` command
    wrapper, explicitly set `retryable=False` unless the command is proven
    idempotent (read-only or safe-to-repeat write).
-   The `_classify_error()` priority order (Cat-2 → rate_limit → Cat-1 → Cat-3)
    must not be changed without updating the source-category table above.
-   The middleware registration in `register()` must NEVER be wrapped in a
    try/except that swallows failures. Fail-closed is mandatory.
-   `_metadata()` must never mask `name` — it is the primary identifier.
-   When adding new metadata-exposing tools, apply the same `mask` parameter.
-   Configuration loading MUST go through `compat.extract_plugin_section()`
    (native Hermes API only). Never read `config.yaml` directly. (VWP-05)
-   API capability detection MUST use `compat.register_tool_compat()` /
    `compat.register_hook_if_available()`. Never use exception-based probing. (VWP-06)

## Supply Chain

-   Dev dependencies are pinned via `uv.lock` (committed to the repository).
    (VWP-16)
-   CI installs exclusively from the lockfile (`uv sync --frozen`).
-   All CI checks (pytest, ruff) are **blocking** — a failing check prevents
    merge. (VWP-15)

## Audit Status (20/20 VWP + SEC-01 + SEC-03 complete; AUD-01..AUD-08 partial)

| ID | Description | Implemented |
|-----|-------------|-------------|
| SEC-01 | Result redaction via authoritative `transform_tool_result` hook (ContextVar handoff; `post_tool_call` reduced to observer-only; fail-closed load without the hook) | v0.5.4 |
| SEC-03 | Fail-closed policy for local terminal backend (`allow_insecure_local_backend` opt-in; plugin refuses to load on `local`/unset backend by default) | v0.5.5 |
| AUD-03 | Secrets directory fail-closed validation at plugin load — `register()` runs `secure_fs.ensure_hardened_directory()` before any tool/hook registration; symlink / wrong owner / mode ≠ 0700 aborts activation (no partial state, no silent chmod repair) | v0.6.2 (resolved) |
| AUD-04 | `.bw-data` fail-closed validation before any `bw` invocation — shared hardened-directory validator gates `BITWARDENCLI_APPDATA_DIR` export and every `bw` subprocess call; insecure appdata dir blocks `bw` execution | v0.6.2 (resolved) |
| AUD-08 | `secrets.yaml` fail-closed filesystem validation before YAML parsing — `secure_fs.ensure_hardened_secret_file()` requires absolute path, regular non-symlink file, euid ownership, no group/other access; insecure file is NEVER parsed | v0.6.2 (resolved) |
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

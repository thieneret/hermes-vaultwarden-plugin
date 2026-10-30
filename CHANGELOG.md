# Changelog — hermes-vaultwarden-plugin

All notable changes to this project are documented in this file.
Author: **thieneret**

---

## v0.6.4

- fix(bw-cli): restore `BW_SESSION` environment variable injection for vault read/write operations
- fixes regression where `vaultwarden_list` returned empty and `vaultwarden_store` failed with exit 1 due to missing session key in subprocess environment
- improve `bw` subprocess error reporting for locked/expired session states
- add regression tests pinning: `BW_SESSION` injection (explicit + AuthManager fallback at the `_ensure_session_env()` choke point), non-inheritance of the parent environment, and absence of the session key from errors/logs (`SESSION_EXPIRED` / `SESSION_ERROR` classification)
- security properties unchanged: session key remains memory-only (never on disk, never in argv/logs), subprocess env isolation preserved; documented in SECURITY.md ("Session key in memory only", Error Classification VWP-09, Audit Status HOTFIX-01)

## v0.6.3

- feat(security): fail-closed lifecycle hook registration for critical lifecycle hooks (AUD-06)
- `register()` now refuses plugin load if required `post_tool_call` or session-end lifecycle hook cannot be registered
- existing `transform_tool_result` and `tool_execution` middleware fail-closed behavior remains unchanged
- add lifecycle-hook registration regression tests

## [0.6.2] - 2026-10-30

v0.6.2 — filesystem fail-closed hardening (AUD-03 + AUD-04 + AUD-08)
- SECURITY: new shared filesystem-hardening module `secure_fs.py` with
  `FilesystemSecurityError`, `ensure_hardened_directory()` and
  `ensure_hardened_secret_file()`. All checks use `os.lstat()` (symlinks are
  never followed), reject symlinks, require ownership by the CURRENT
  effective UID, and enforce strict permissions (directories EXACTLY 0700,
  secret files with NO group/other access bits — canonically 0600). Missing
  directories are created hardened (umask-forced 0700); insecure existing
  paths are NEVER silently repaired (the v0.5.8 implicit chmod was removed —
  a silent repair would mask an attack or misconfiguration).
- AUD-03 (resolved): the secrets directory (`$XDG_RUNTIME_DIR/vw-secrets`)
  is now validated FAIL-CLOSED at plugin LOAD time. `register()` calls
  `ensure_hardened_directory(resolve_secrets_dir_path(), create_if_missing=True)`
  BEFORE any tool or hook registration; on `FilesystemSecurityError` it logs
  a sanitized error (path + reason only, never secret values) and returns
  False — no tools exposed, no hooks registered, no partial activation.
  `_cleanup_stale_secrets()` no longer swallows validation errors, and the
  injection middleware blocks placeholder injection fail-closed (placeholders
  stay verbatim = shell-expands-empty) with a sanitized PlaceholderError.
- AUD-04 (resolved): `.bw-data` (Bitwarden appdata dir, exported to `bw` as
  `BITWARDENCLI_APPDATA_DIR`) is validated through the same hardened-directory
  validator before ANY `bw` invocation — at setup (`auth.ensure_appdata_dir()`)
  and at the single subprocess choke point (`BwCli.base_env()` feeding every
  `subprocess.run` site and the version check). An insecure appdata dir
  raises `FilesystemSecurityError`: `BITWARDENCLI_APPDATA_DIR` is not set for
  an unvalidated path and `bw` is not executed. A missing dir is created with
  mode 0700; symlink / wrong owner / group- or world-accessible dirs block
  `bw` execution.
- AUD-08 (resolved): `secrets.yaml` is validated through
  `ensure_hardened_secret_file(path, allow_missing=False)` BEFORE any YAML
  parsing in `load_secrets()`. An existing but insecure file (symlink, wrong
  owner, group/other access) raises `FilesystemSecurityError` — the YAML is
  never parsed and no bootstrap secret is loaded. The error propagates to
  `register()`, which logs it sanitized and refuses to activate the plugin.
- Fail-closed contract (all three gates): validation failure →
  `FilesystemSecurityError` → plugin activation aborts / `bw` blocked /
  secrets unparsed. The error is never caught-and-ignored, never downgraded
  to a warning-only path, and never allows partial plugin activation. Error
  messages may include paths but NEVER secret values, YAML content, or
  environment variables. RedactingFilter, session isolation, env isolation,
  and HTTPS enforcement are unchanged.
- Docs: README.md gains a "Filesystem Security Requirements" section
  (required-permissions table, operator chown/chmod remediation commands,
  symlink remediation, fail-closed breaking-change note) and three new rows
  in the Security Architecture table (AUD-03 / AUD-04 / AUD-08). SECURITY.md
  Audit Status table marks AUD-03, AUD-04 and AUD-08 resolved in v0.6.2.
- Tests: new `tests/test_secure_fs.py` (symlink rejection via lstat, wrong
  ownership, mode drift, umask-forced creation, allow_missing semantics,
  absolute-path enforcement, no-silent-repair assertions) plus updated
  crash-recovery tests for the new propagation contract.
- Bump version to 0.6.2 (plugin.yaml, pyproject.toml, README header).

## [0.6.1] - 2026-10-29

v0.6.1 (VWP-18) — hotfix: detect transform_tool_result via host VALID_HOOKS registry
- FIX: production Hermes builds that advertise hook support only through the
  module-level `hermes_cli.plugins.VALID_HOOKS` registry (and do NOT mirror
  it as a PluginContext attribute or `supported_hooks` collection) were
  misclassified as legacy hosts; the plugin refused to load with the SEC-01
  fail-closed error "host Hermes does not expose the mandatory
  'transform_tool_result' plugin hook".
- `compat.supports_transform_tool_result()` now consults
  `hermes_cli.plugins.VALID_HOOKS` as a last-resort detection layer. The
  lookup is a guarded, pure membership test: if the module is absent (older
  hosts, unit-test environments without Hermes installed) the check
  conservatively returns False — genuinely old hosts still fail closed and
  SEC-01 protection is unchanged.
- Tests: +4 regression tests in test_compat.py (registry detected; registry
  without the hook fails closed; no hermes_cli fails closed; end-to-end
  register() succeeds on a bare production-shaped context).
- Bump version to 0.6.1.

## [0.6.0] - 2026-10-29

v0.6.0 (AUD-01) — enforce HTTPS for server_url configuration
- BREAKING: `server_url` now strictly requires the `https://` scheme by
  default. Cleartext `http://` URLs are rejected with a ConfigError and
  prevent the plugin from loading.
- New config flag `allow_insecure_http` (default: false). When set to true,
  `http://` is permitted for any hostname (developer's explicit risk
  acceptance), and a WARNING is logged. This replaces the previously
  unrestricted scheme parsing.
- Invalid schemes (ftp://, file://, ws://, empty) are now explicitly rejected.
- Docs: README.md updated with the new flag and its security implications.
- Bump version to 0.6.0.

## [0.5.9] - 2026-10-29

v0.5.9 — SEC-01 E2E integration test ("Leaky Cat" scenario)
- Testing: Added End-to-End integration test simulating the full Hermes
  tool execution pipeline (`tool_execution` -> `transform_tool_result` ->
  `post_tool_call`). Verifies that a command explicitly reading and printing
  the injected temp file results in `[REDACTED]` in the final model context,
  and that the temp file is securely cleaned up.
- Testing: Added fail-closed negative test verifying the plugin refuses to
  load if the `transform_tool_result` hook cannot be registered.
- Docs: README.md updated with new test suite count and E2E coverage note.
- Bump version to 0.5.9.

## [0.5.8] - 2026-10-29

v0.5.8 — directory validation & cleanup observability
- Security: `_secrets_dir()` now strictly validates the temp directory on
  creation/use. Enforces non-symlink, correct ownership (current user or root),
  and exact 0700 permissions. Fails closed if validation fails.
- Reliability: All temp file deletions in `finally` blocks are now wrapped in
  try/except. Failures emit a sanitized WARNING log (path + error code) instead
  of failing silently, ensuring operators are alerted to leftover secret material.
- Fix: Startup stale-file cleanup now uses the configured `placeholder_ttl_seconds`
  instead of a hardcoded lifetime.
- Bump version to 0.5.8.

## [0.5.7] - 2026-10-29

v0.5.7 (SEC-02) — atomic placeholder resolution & status version exposure
- Security (SEC-02): Refactored placeholder resolution to be strictly atomic
  per unique token per command. Commands containing the same placeholder
  multiple times now correctly map all occurrences to a single injected temp
  file, preventing partial resolution or unintended reuse paths.
- Feature: `vaultwarden_status` now returns the current `plugin_version`
  in its response payload for operator and LLM visibility.
- Added `consume_and_resolve()` to PlaceholderRegistry for atomic
  consumption-before-return semantics.
- Bump version to 0.5.7.

---

## [0.5.6] - 2026-10-29

v0.5.6 — README cleanup + mypy debt resolution
- README.md: Remove inline version numbers (v0.X.X) and audit tracking
  numbers (VWP-XX, SEC-XX) from explanations, configuration descriptions,
  and security mechanism tables. Version badge at top preserved
  (operator-maintained). CHANGELOG.md unchanged (legitimately lists versions).
  Rationale: inline version references create maintenance coupling with
  release cycles.
- mypy fixes: Resolve 3 pre-existing type errors:
  - schemas.py:261 — inline custom_fields schema definition to satisfy type
    inference (or add cast() annotation)
  - security.py:190 — use getattr() for dynamic LogRecord.vw_extra attribute
    with isinstance narrowing
  - security.py:200 — add explicit recursive dict type annotation
- No behavior changes; all fixes are type-level only.
- Bump version to 0.5.6.

---

## [0.5.5] - 2026-10-29

v0.5.5 (SEC-03) — fail-closed policy for local terminal backend
- BREAKING (default behavior): plugin now REFUSES to load when the Hermes
  terminal backend is `local` (or unset), because the LLM then runs as the same
  OS user and can read secrets.yaml directly, bypassing all protections.
- New config flag `allow_insecure_local_backend` (boolean, default false) under
  plugins.entries.vaultwarden.settings. Set to true to explicitly accept the
  same-user secret-exposure risk (a WARNING is logged).
- Recommended production posture unchanged: use `docker` / `ssh` / `modal`
  terminal backends for privilege separation.
- secrets.check_terminal_backend() now returns the detected backend so
  register() can enforce the policy before any tool registration.
- Docs: README.md config table + SECURITY.md threat vector updated.
- Bump version to 0.5.5.

---

## [0.5.4] - 2026-10-28

v0.5.4 (SEC-01) — migrate result redaction to authoritative transform_tool_result hook
- BREAKING (host compatibility): plugin now requires a Hermes build that
  exposes the `transform_tool_result` plugin hook; refuses to load otherwise
  (fail-closed).
- Security: confidentiality boundary for injected secrets moved from the
  `post_tool_call` observer to the `transform_tool_result` transformer, which
  Hermes documents as the authoritative result-rewriting hook.
- New `make_result_redactor` factory in hooks.py performs exact plaintext
  replacement with `[REDACTED]` on the result before it reaches the model,
  covering both per-task injected secrets and the global RedactingFilter set.
- `post_tool_call` reduced to observer-only duties (placeholder cleanup,
  metrics, secret-free error surfacing); no longer mutates results for
  confidentiality reasons.
- ContextVar-based handoff carries the per-execution secret set from the
  tool_execution middleware into the transformer; cleared in a finally block
  so no secret values persist across turns.
- Bump version to 0.5.4.

---

## [0.5.3] - 2026-10-28

### Improvements
- **secret_source.py**: Add input validation for mappings (missing `item_id`,
  invalid structure) with warning logs
- **secret_source.py**: Add INFO logging for successful secret injections
  (count and env var names)
- **secret_source.py**: Register injected secrets with RedactingFilter
  (security improvement — ensures injected secrets are redacted from logs)
- **secret_source.py**: Lazy import `_field_value` to avoid potential
  circular dependency
- Add comprehensive unit tests for `secret_source.py` (12 test cases)

NOT a breaking change: the feature remains opt-in
(`allow_startup_secret_injection: false` by default), the public API
(`name()` / `get_secrets()`) is unchanged, and all security mechanisms
(VWP-01 path pinning, VWP-11 version check, error taxonomy, read-only
fail-safe model, redactor integration, 12-tool registration) are untouched.

---

## [0.5.2] - 2026-10-27

### Refactor
- **VWP-05**: Remove config fallback layers (read_user_config_raw, direct
  YAML read). Diagnostic testing confirmed the native Hermes
  PluginContext.get_config() API resolves config values correctly; the
  fallbacks were unnecessary and are removed.
- **VWP-06**: Replace exception-based API detection with explicit capability
  detection:
  * register_tool: use inspect.signature() to detect the check_fn parameter
  * register_hook: use hasattr() for capability detection
  * Fail closed (RuntimeError) if the required API is unavailable
- Diagnostic testing confirmed ctx.api_version does not exist, so
  signature/hasattr introspection is the correct capability-detection
  approach (version-based detection is impossible).

NOT a breaking change: VWP-01 path pinning, VWP-11 version check, error
taxonomy codes, the 12-tool registration, and all security mechanisms
(RedactingFilter, askpass delivery, temp-file cleanup, 0600/0700 permissions,
env isolation) are unchanged. Tool schemas and handler behavior are unchanged.

## [0.5.1] - 2026-10-27

### Refactor
- **VWP-17**: Centralize compatibility code into `compat.py` module
  - Hermes API version fallbacks (register_tool, register_hook)
  - Config loading fallbacks (PluginContext.get_config -> read_user_config_raw -> direct YAML)
  - YAML import fallback (PyYAML -> stdlib parser)
  - bw version parsing and minimum version enforcement
  - Exception code extraction with fallback
- Add missing `PluginError` class to `errors.py` (used by auth.py)
- Improve maintainability and security auditability by consolidating
  version-specific and API-version-specific code into a single module

NOT a breaking change: VWP-01 path pinning, VWP-11 version check, the error
taxonomy codes, the 12-tool registration, and all security mechanisms
(RedactingFilter, askpass delivery, temp-file cleanup, 0600/0700 permissions,
env isolation) are unchanged. Tool schemas and handler behavior are unchanged.

## [0.5.0] - 2026-10-27

### ⚠️ BREAKING CHANGE — bootstrap secrets now load from `secrets.yaml`, not `.env` / OS environment

- **New mechanism:** the bootstrap secrets (`client_secret`, `master_password`)
  are loaded from a plugin-private YAML file,
  `$HERMES_HOME/plugins/vaultwarden/secrets.yaml`, read DIRECTLY by the new
  `secrets.py` module (`load_secrets()`). The file MUST be chmod 600; any
  other permission mode is rejected with a `ConfigError` that suggests
  `chmod 600`. A template ships at
  `plugins/vaultwarden/secret.yaml.template`.
- **Removed config keys:** `client_secret_env` and `master_password_env` are
  REMOVED from `plugin.yaml` and `_DEFAULTS`. `config.resolve_secret()`, the
  Hermes `_hermes_get_secret` import, `PluginConfig.env_snapshot`,
  `__init__.py::_resolve_secrets()`, and `__init__.py::_cleanup_bootstrap_env()`
  are all REMOVED. There is no backward compatibility for the `.env` channel.
- **Security rationale (two attack surfaces closed):** previously the secrets
  lived in the Hermes `.env` file (readable by the LLM via
  `cat /opt/data/.env` — same OS user) and entered the OS environment before
  the plugin deleted them (dumpable via `printenv`). Now the secrets NEVER
  enter an environment variable or the Hermes secret_scope at any point.
- **Residual risk / terminal backend warning:** when the terminal backend is
  `local`, the LLM still runs as the same OS user and could `cat`
  `secrets.yaml`. New `secrets.check_terminal_backend()` logs a WARNING in
  that case ("terminal backend is 'local' ... For production, use 'docker'
  or 'ssh' backend.") and an INFO for sandboxed backends (`docker` / `ssh` /
  `modal` / etc.). Privilege separation via a non-local backend is the
  recommended production posture.
- **Migration:** copy `plugins/vaultwarden/secret.yaml.template` to
  `$HERMES_HOME/plugins/vaultwarden/secrets.yaml`, fill in `client_secret`
  and `master_password`, then `chmod 600 secrets.yaml`. Remove the old
  `VW_CLIENT_SECRET` / `VW_MASTER_PASSWORD` entries from `.env`.
- **NOT affected:** VWP-01 path pinning, VWP-11 version check, the error
  taxonomy codes, the 12-tool registration, the tool schemas and handler
  behavior, and every security mechanism (RedactingFilter, askpass delivery,
  temp-file cleanup, 0600/0700 permissions, env isolation — the `bw`
  subprocess base_env remains minimal). Only the bootstrap secret loading
  mechanism changed.
- Version bumped to 0.5.0 in `pyproject.toml` and `plugin.yaml`.

## [0.4.9] - 2026-10-25

### ⚠️ BREAKING CHANGE — `*_env` secret-input channel removed

- **Removed parameters:** the `password_env` / `pass_env` tool parameters
  (added in v0.4.0) are REMOVED from the schemas of `vaultwarden_store`,
  `vaultwarden_update`, `vaultwarden_store_ssh`, and
  `vaultwarden_update_ssh`. Rationale: in multiplex gateway mode Hermes
  loads `.env` only at startup, so a secret added to `.env` requires a
  full Hermes restart before the plugin can resolve it — impractical for
  dynamic tool use.
- **Explicit rejection (never silently ignored):** callers that still
  supply `password_env` / `pass_env` now get a clear `ConfigError`
  ("<tool>: '<param>' was removed in v0.4.9 — environment secrets require
  a Hermes restart to load.") raised at the very start of each handler
  body — BEFORE the generate branch — so the rejection fires in both
  generate and non-generate modes. The error's suggestion points to the
  supported alternatives.
- **Supported alternatives (UNCHANGED behavior):** `password_file` /
  `pass_file` (owner-only file, chmod 600, strict permission validation),
  `generate=true`, and the raw direct `password` / `pass` channels (still
  accepted, still warn). The raw-channel advisory no longer mentions the
  env channel and now recommends only the `*_file` channel.
- **Implementation:** `_reject_removed_env_channel()` added to `tools.py`;
  `_resolve_secret_input()` lost its env branch and its `env_key` /
  `config` parameters (signature is now
  `_resolve_secret_input(args, *, direct_key, file_key, tool_name)`);
  generate-mode conflict tuples dropped the env keys.
- **NOT affected:** bootstrap secrets (`client_secret_env` /
  `master_password_env` config keys, `config.resolve_secret()`, and
  `__init__.py::_resolve_secrets()`) keep working exactly as before. VWP-01
  path pinning, VWP-11 version check, the error taxonomy codes, the
  12-tool registration, and every security mechanism (RedactingFilter,
  askpass delivery, temp-file cleanup, 0600/0700 permissions, env
  isolation) are untouched. The SSH tools' `file` parameter (private key
  path) is distinct from `pass_file` and remains unchanged.

## [0.4.8] - 2026-10-24

### Bugfixes (live-container testing of v0.4.7)

- **Defects 1-2 (store_ssh KeyError):** `vaultwarden_store_ssh` upload mode
  now validates the presence of `user` and `file` BEFORE reading them from
  the args dict, raising a clear `ConfigError` ("'user'/'file' is required
  in upload mode") instead of leaking a raw `KeyError` reported as
  "Internal plugin error: KeyError".
- **Defect 3 (permanent delete):** `BwCli.delete_item` with
  `permanent=true` now performs a REAL `bw sync` and retries the delete
  exactly once when `bw` returns not_found (e.g. the item is already in the
  trash and invisible in a stale local cache). The final not_found message
  names the `item_id` ("No item matching id '<id>'.") instead of the
  misleading "No matching item for query '--permanent'" (which came from
  `args[-1]`).
- **Defect 4 (password_env in multiplex mode):** `_resolve_secret_input`'s
  env channel now resolves via `config.resolve_secret()` (get_secret-first)
  when a config is available — all four call sites (`h_store`, `h_update`,
  `h_store_ssh`, `h_update_ssh`) pass it. In multiplex gateway mode `.env`
  values are NOT in `os.environ`, so `password_env` / `pass_env` previously
  reported "not set or empty"; they now resolve correctly. The raw
  `os.environ.get()` fallback remains for callers without a config.
- **Latent AttributeError:** added the missing `errors.PluginError` class
  (code `PLUGIN_ERROR`) used by `auth._configure_server`.

### Unchanged

- VWP-01 (v0.4.7) binary path pinning, VWP-11 version check, the error
  taxonomy codes, the 12-tool registration, and every security mechanism
  (RedactingFilter, askpass env delivery, temp-file cleanup, 0600/0700
  permissions, env isolation) are untouched. No breaking changes to any
  tool schema or response shape.

---

## [0.4.7] - 2026-10-23

### Security (VWP-01 — binary path pinning for the `bw` CLI)

- **BREAKING CHANGE:** `bw` is now executed ONLY from the absolute path set in
  `plugins.entries.vaultwarden.settings.bw_cli_path`. The PATH-based discovery
  fallback (`shutil.which("bw")`) has been removed entirely — a compromised
  `PATH` or a same-named malicious binary can no longer be executed with the
  plugin's privileges.
- **BREAKING CHANGE:** `bw_cli_path` is now REQUIRED. If it is empty, the
  plugin fails closed: `register()` returns `False`, the agent continues
  without the plugin, and no binary is ever spawned.
- **BREAKING CHANGE:** The `BW_CLI_PATH` environment-variable override has
  been removed. config.yaml is the single source of truth for the binary
  location.
- New `validate_bw_path()` in `bw_cli.py` enforces, before any subprocess is
  spawned: the path must be absolute; regular file; contain NO symlink
  anywhere in its chain; be executable; NOT be group- or world-writable; and
  be owned by root or the current effective uid. Any violation logs the
  precise reason and prevents the plugin from loading.
- VWP-11 (fail-closed minimum-version check, `_MIN_BW_VERSION` /
  `_check_version()`) is UNCHANGED — path pinning complements it.
- Out of scope by design (user responsibility): cryptographic authenticity /
  hash verification of the `bw` binary, and pinning of SSH helper binaries.
- No tool-count change (12 tools).

---

## [0.4.6] - 2026-10-23

### Security (VWP-02 — SSH socket path restriction)

- **BREAKING:** Removed the `ssh_auth_sock` parameter from
  `vaultwarden_use_ssh`. The socket path is now resolved from
  developer-controlled environment variables (`$VW_SSH_SOCKET_PATH` or
  `$XDG_RUNTIME_DIR/auth.sock`), eliminating the LLM-controlled socket
  takeover attack vector. If an agent is already running at the resolved
  socket, it is reused. Stale sockets are cleaned at plugin startup.

No tool-count change (12 tools).

---

## [0.4.5] - 2026-10-22

### Security (audit findings VWP-18, VWP-19, VWP-20)

- **VWP-18 (Concurrency):** Added concurrency tests for placeholder generation
  and consumption. Validates that the single-use placeholder registry is
  thread-safe and that race conditions (e.g. two threads consuming the same
  placeholder) are handled correctly.
- **VWP-19 (Env Isolation):** Added subprocess environment isolation tests.
  Validates that `bw` and SSH subprocesses run in an isolated environment that
  does not leak sensitive variables from the parent process.
- **VWP-20 (Crash Recovery):** Added startup cleanup of stale temp files left
  behind by SIGKILL/SIGTERM (where the `finally` block did not run). On plugin
  startup, any temp files older than the placeholder TTL (5 minutes) are
  removed. Added test coverage for `KeyboardInterrupt` cleanup (which does
  trigger the `finally` block). Updated SECURITY.md with a note about
  platform-dependent risk (tmpfs on native Linux vs. persistent storage in
  Docker/Windows).

No tool-count change (12 tools). No schema change. No breaking change.

---

## [0.4.4] - 2026-10-22

### Breaking Change (VWP-04 — file-injected placeholders)

- **BREAKING, no backward compat:** secrets are now injected via a temp file
  in `$XDG_RUNTIME_DIR/vw-secrets/` (chmod 600, mkstemp) using a Hermes
  `tool_execution` middleware, instead of rewriting the command string with
  the secret. Placeholders are user-facing as `$__VW_SECRET_x__` and MUST be
  placed inside double quotes (or unquoted) so the shell expands them. The
  middleware rewrites the reference to `$(< path)` and the shell reads the
  secret at execution time. The raw secret no longer appears in the command
  string, argv, shell history, or logs.
- `vaultwarden_get_secret_ref` now returns the placeholder with a `$` prefix.
- The old bare `__VW_SECRET_x__` string-substitution path is REMOVED (no
  backward compatibility).

### Repo reorganization

- Moved `vaultwarden/` → `plugins/vaultwarden/` (git mv, history preserved).
- Removed the misplaced root `conftest.py`; the authoritative conftest is
  `plugins/vaultwarden/tests/conftest.py`.

### Skill

- Added the `vaultwarden-usage` skill at
  `skills/devops/vaultwarden-usage/` (SKILL.md v2.0.0 + references:
  examples.md, troubleshooting.md, architecture.md) describing the
  file-injection workflow.

No tool-count change (12 tools). No schema change.

## [0.4.3] - 2026-10-22

### Security (audit findings VWP-13, VWP-03)

- **VWP-03 (HIGH): Middleware fail-closed.** If the placeholder-injection
  middleware fails to register, the plugin now refuses to load (propagates
  the exception from `register()`). Previously it logged a warning and
  continued without placeholder injection, which could expose raw secrets
  in terminal commands. This is consistent with the existing fail-closed
  bw version check and fail-closed auth.
- **VWP-13 (MEDIUM): Metadata masking (opt-in).** New `metadata_masking`
  config option (default `false`). When enabled, `vaultwarden_list` and
  `vaultwarden_search` mask `username` and `uris` with `***`. `name`,
  `id`, `type`, `folder_id` are never masked. Default OFF preserves the
  current search/list usability.

### New Config Options

| Option | Default | Purpose |
|---|---|---|
| `metadata_masking` | `false` | Mask `username`/`uris` in list/search responses |

### Documentation

- **README.md:** metadata masking + middleware fail-closed documented in
  Key settings and Security Architecture.
- **SECURITY.md:** Two new primary controls, two new threat vectors,
  development rules updated.

No tool count change (12 tools). No breaking change to tool API.

## [0.4.2] - 2026-10-22

### Bugfix

- **`generate=true` no longer hangs on interactive (dashboard) sessions.**
  The post-generation safety verify `ssh-keygen -yf <key>` (run without askpass
  to confirm the key is encrypted) fell back to a `/dev/tty` passphrase prompt
  wherever a controlling tty exists, hanging until the 10s timeout. On headless
  sessions (Matrix) `/dev/tty` is unavailable, so it exited non-zero and worked
  by accident. All passphrase-handling SSH subprocesses (`ssh-keygen`
  generate/verify/fingerprint, `ssh-add`) now run with `start_new_session=True`,
  detaching the child from any controlling terminal so a tty fallback or hang is
  impossible. The verify logic itself is unchanged.

### Refinement

- **Raw-secret response warning is now an imperative instruction.** The
  `"warning"` field returned when a raw secret is passed directly to
  `store`/`update`/`store_ssh`/`update_ssh` now explicitly directs the agent to
  warn the user that direct secret input is insecure and to recommend the
  `*_env`/`*_file` channels. Still value-free; raw input is still accepted
  (accept-and-warn behavior unchanged).

No schema, tool-count (12), or response-shape change.

## [0.4.1] - 2026-10-21

### Bugfix (v0.4.0 regression — SSH keypair generation prompted the user)

- **`generate=true` no longer prompts for the passphrase.**
  `_generate_ssh_keypair()` delivered the passphrase via
  `subprocess.run(input=...)`, but OpenSSH's `ssh-keygen` reads passphrases
  through `read_passphrase()`, which never consumes stdin and prompts
  `/dev/tty` when a tty is present. The piped data was ignored and the user
  was asked. Delivery now uses the proven v0.3.4 `SSH_ASKPASS` mechanism:
  a helper script whose body is only `echo "$VW_SSH_PASS"` runs with
  `SSH_ASKPASS_REQUIRE=force`, the passphrase travels in the subprocess
  environment only (never a file, never `-N` argv), and `stdin` is
  `/dev/null` so a tty fallback or hang is impossible. Verified against
  OpenSSH 10.0p2 (`SSH_ASKPASS_REQUIRE` needs >= 8.4).
- **Encryption verify retained as the safety net.** `ssh-keygen -yf` with
  `stdin=DEVNULL` must FAIL after generation; if the askpass channel yields an
  empty passphrase the key would be unencrypted, and the operation now aborts
  instead of storing an unprotected key in the vault.
- **Deduplication:** the askpass helper script + env construction is now a
  single module-level implementation (`_make_askpass_script()` /
  `_askpass_env()`) shared by `h_use_ssh` and `_generate_ssh_keypair`, so a
  future askpass fix lands in exactly one place. `h_use_ssh` behavior is
  otherwise unchanged; its `HOME` fallback is normalized from `"/"` to
  `_ssh_base_env()`'s `Path.home()` (strictly better: the old fallback broke
  `~` expansion).
- **Documentation:** README/SECURITY no longer claim stdin passphrase
  delivery.
- **Manifest:** removed the stale version header comment from the first line
  of `plugin.yaml` (missed by the v0.3.2 header cleanup); the `version:` key
  is unchanged in role and now reads `0.4.1`.

No schema, tool-count (12), or response-shape change.

---

## [0.4.0] - 2026-10-20

### Features

- **Secret input channels (store/update + ssh_store/ssh_update):** passwords
  and SSH passphrases can now be supplied via an environment variable
  (`password_env` / `pass_env`) or an owner-only file (`password_file` /
  `pass_file`, validated chmod 600), keeping them out of the LLM context.
  Conflicting sources are rejected; raw direct input still works but emits a
  warning in BOTH the log and the tool response (the response `warning` field
  is relayed to the user).
- **SSH keypair generation (`ssh_store` / `ssh_update` + `generate=true`):**
  the plugin generates a 32-char passphrase via the SAME `bw generate` path as
  `store`/`update` `generate=true` (one consistent secret-generation
  mechanism) and an SSH keypair (default `ed25519`, optional `rsa` via
  `key_type`/`rsa_bits`, default 4096 bits) using `ssh-keygen` with the
  passphrase delivered on stdin (never argv), followed by a post-generation
  encryption verify. The private key and passphrase are stored in the vault;
  only the public key (and fingerprint) is returned. `ssh_update` +
  `generate=true` performs a key rotation and requires `confirm=true`.

### Security

- New primary controls documented in SECURITY.md (secret input channels, SSH
  key generation with stdin passphrase + encryption verify, single
  secret-generation path).
- No tool-count change (12 tools). No breaking change to existing parameters.

## [0.3.9] - 2026-10-19

### Bugfix (VWP-12 regression — `bw generate` syntax)

- **`generate=true` fix:** `_generate_password()` in `tools.py` built an
  invalid `bw generate` argument list: a positional length (`bw generate 20
  …`) in the password branch and the non-existent `-w` short alias in the
  passphrase branch. The real `bw` CLI rejects positional args
  ("too many arguments for 'generate'") and has no `-w` flag, so every
  `vaultwarden_store` / `vaultwarden_update` call with `generate=true`
  failed with `bw generate failed (exit 1)`. Corrected to
  `--length <n>` and `--words <n>`.
- **Test hardening:** added structural assertions on the `bw_args` list
  produced by `_generate_password()` (via a recording mock auth), so the
  fake-bw test blind spot that masked this regression is closed. The
  assertions enforce: no positional numeric arg, `--length`/`--words` as
  flags, no `-w` alias.

No schema, config, or tool-count change. 12 tools.

## [0.3.8] - 2026-10-19

### Security & Reliability (audit finding VWP-11)

- **VWP-11:** `bw` CLI version is now validated at plugin startup via
  `BwCli._check_version()`. Fail-closed with NO override: unsupported or
  unparseable versions raise `UnsupportedBwVersionError`, log the error,
  and prevent the plugin from loading. Minimum version is hardcoded at
  2026.9.1 (the version the plugin was developed and tested against);
  it is not a configuration option.

### Security & Reliability (audit findings VWP-09, VWP-10)

- **VWP-09:** Error classification reorganized into source-category priority
  (Node.js network codes → rate limit → bw CLI state → server API →
  unknown) via `_classify_error()`. Marker lists expanded. `bw` exposes only
  two exit codes (0/1), so marker matching remains the only viable approach,
  now hardened by stability priority and anchored by the VWP-11 version
  check. JSON parse failures fall back to raw string with a debug log
  (`_parse_output()`) instead of raising `ParseError`; unknown errors emit
  rich debug context (rc, category, redacted stderr snippet).
- **VWP-10:** Network-error retry replaced with bounded exponential backoff
  with additive jitter (`base * 2^attempt + uniform(0,1)`, capped at
  `max_delay`). Retry is restricted to idempotent operations:
  `login_apikey`, `unlock_passwordenv`, `create_attachment`, `delete_item`,
  and `delete_attachment` are explicitly `retryable=False`, preventing
  duplicate session keys, duplicate attachments, or false-negative delete
  results. Rate-limit errors are raised immediately and never retried.
  No third-party dependencies — stdlib `random` only.

#### New configuration options

| Option | Default | Description |
|---|---|---|
| `bw_max_retries` | `3` | Max retry attempts for idempotent `bw` calls on network errors |
| `bw_backoff_base` | `1.0` | Base delay (seconds) for exponential backoff |
| `bw_max_delay` | `10.0` | Maximum backoff delay cap (seconds) |

#### Scope & documentation notes

- Scope: `bw_cli.py` (markers, `_classify_error`, `_compute_backoff`,
  `_parse_output`, `run()` rewrite, `__init__` +3 params, `retryable=False`),
  `config.py` (3 options), `plugin.yaml` (3 schema entries), tests,
  README.md (3 config rows + security row), and SECURITY.md (error
  classification + retry safety subsections + dev rules).
- __init__.py (BwCli construction site only; auth.py untouched): the
  original spec assumed the `BwCli(...)` construction site was in `auth.py`;
  it is actually in `__init__.py`. `AuthManager` receives an already-built
  `BwCli` instance, so `auth.py` stays at zero diff and the 3 retry params
  (`max_retries`, `backoff_base`, `max_delay`) are wired at the real
  construction site.
- Untouched files: `auth.py`, `errors.py`, `tools.py`, `hooks.py`,
  `placeholders.py`.
- README.md: config.yaml example, key settings table, and security
  architecture row updated for the new retry options and structured error
  classification.
- SECURITY.md: added "Error Classification by Source (VWP-09)" and
  "Retry Safety (VWP-10)" subsections plus new development rules.

## [0.3.7] - 2026-10-18

### Breaking Changes

- **VWP-12:** Removed `vaultwarden_generate_password` tool (13 → 12 tools).
  Password generation is now integrated into `vaultwarden_store` and
  `vaultwarden_update` via `generate=true`. Generated passwords are stored
  directly in the vault and never returned to the LLM — only a placeholder
  is returned.
- **VWP-14:** Removed `allow_direct_secret_retrieval` config option entirely.
  `vaultwarden_get_secret_ref` always returns only a placeholder. No escape
  hatch remains for direct secret retrieval.

### Security

- **VWP-08:** SSH subprocess calls (`ssh-add`, `ssh-agent`, `ssh-keygen`)
  now use a minimal isolated environment via `_ssh_base_env()`, mirroring
  the isolation already applied to `bw` calls. The parent environment is
  no longer inherited, preventing leakage of host variables and PATH
  manipulation.

### Documentation

- **README.md:** Tool table updated (13 → 12). `allow_direct_secret_retrieval`
  removed from configuration table.
- **SECURITY.md:** Updated to reflect SSH env isolation as a primary
  control and removal of the direct retrieval escape hatch.

## [0.3.6] - 2026-10-18

### Security (audit findings VWP-07, VWP-15, VWP-16)

- **VWP-15:** CI ruff lint steps are now blocking (removed
  `continue-on-error: true` and `|| echo` fallback). Lint failures
  now prevent merge.
- **VWP-16:** Dev dependencies pinned via `uv.lock`. CI installs
  exclusively from the lockfile (`uv sync --frozen`).
- **VWP-07 (low):** Created `SECURITY.md` documenting the threat model
  and clarifying that `RedactingFilter` is defense-in-depth, not a
  primary security control.
- **VWP-07 (high):** Added `StructuredJsonFormatter` for JSON structured
  logging with automatic redaction of secret-like keys at format time.

## [0.3.5] — tools.py Deduplication

### Changed
- Eliminated duplicate definitions of SSH tool handlers in tools.py.
  Module-level functions are now the single source of truth;
  get_tools() closures are thin wrappers that bind auth/config.
- Helper functions (_validate_ssh_key_file, _resolve_socket_path)
  have exactly one module-level definition.

### Fixed
- Removed maintenance hazard where changes had to be applied to
  both closure and module-level copies of the same function.

## [0.3.4] — SSH Askpass Passphrase Delivery

### Fixed
- `vaultwarden_use_ssh` no longer times out. Root cause: `ssh-add` does
  not reliably read passphrase from stdin when loading a key from a file
  in a non-interactive container (no tty).
- Switched to SSH_ASKPASS mechanism: a dynamically generated shell script
  (`echo "$VW_SSH_PASS"`) delivers the passphrase via environment variable.
  The passphrase is never written to any file and never enters the agent's
  context window.

### Security
- Askpass script contains ONLY the echo command — no secret content
- Passphrase exists only in subprocess environment during execution
- Removed temporary debug logging added in v0.3.3 diagnostics

## [0.3.3] — SSH Passphrase Retrieval Fix

### Fixed
- `vaultwarden_use_ssh` no longer prompts the user for a passphrase.
  Root cause: `bw get item` does not return encrypted fields (password
  is null). Passphrase is now retrieved via the dedicated
  `bw get password <item_id>` command.
- Added `BwCli.get_password()` method for decrypted password retrieval.

## [0.3.2] — Version Headers Removal & Lint Cleanup

### Removed
- Per-file version header comments from all `.py` files — version is now
  declared in exactly two places: `plugin.yaml` and `pyproject.toml`
- `tests/test_version_headers.py` (per-file header assertions)

### Changed
- Plugin.yaml version check relocated to `test_integration.py` as a
  stronger test that verifies plugin.yaml and pyproject.toml versions match

### Fixed
- All ruff linting errors (I001, E401, F401, F841, E501) for a clean CI run
- Auto-sorted imports across production and test files
- Removed unused imports and local variables

### Added
- None (test count decreased due to version header test removal)

## [0.3.1] — CI Fix — 2026-10-18

### Fixed
- **GitHub Actions CI failure (exit code 1 on all Python versions).**
  Corrected the workflow so `pip install -e ".[dev]"` runs from the repo
  root (where `pyproject.toml` lives) and pytest/ruff are invoked with
  the right working directory and paths.

### Changed
- `.github/workflows/ci.yml`: pytest now runs with `-v --tb=short` for
  better error visibility (`continue-on-error: false`)
- `.github/workflows/ci.yml`: ruff lint step made explicitly
  non-blocking — guarded with `|| echo "Ruff found style issues
  (non-blocking)"` plus `continue-on-error: true`
- `.github/workflows/ci.yml`: added a step emitting ruff results in
  GitHub annotation format (`--output-format=github`) for PR feedback
- Version bumped to 0.3.1 in `plugin.yaml` and `pyproject.toml`
  (CI-only fix, no production code changes)

## [0.3.0] — Infrastructure & Developer Experience

### Added
- `pyproject.toml` — package metadata, hatchling build backend, dev
  dependencies (pytest, pytest-mock, ruff, mypy); zero runtime
  dependencies (plugin is stdlib-only by design)
- `.github/workflows/ci.yml` — automated pytest + ruff lint on push/PR
  across Python 3.10 / 3.11 / 3.12
- README: Prerequisites section; Installation split into Production
  and Development subsections

### Changed
- README: development setup documented (pip/uv editable install)
- Version bumped to 0.3.0 (infrastructure release, no production
  code logic changes)

## [0.2.9] — Test Suite Consolidation

### Changed
- Consolidated 7 version-specific test files into a clean functional
  structure (test_config, test_auth, test_tools, test_schemas,
  test_security, test_ssh_tools, etc.)
- Removed version numbers from test filenames — tests now target the
  current behavior, not a historical version
- Deduplicated all version-header assertions into a single
  data-driven test in test_version_headers.py

### Removed
- test_config_hermes_api_v018.py, test_bugfixes_v12.py,
  test_security_hardening_v022.py, test_cleanup_hardening_v023.py,
  test_guard_json_string_v024.py, test_cleanup_hardening_v026.py,
  test_ssh_tools_v028.py (contents merged into functional test files)
- Obsolete tests asserting removed behavior: `input_schema` key
  (now `parameters`), handler `dict` return (now `str`),
  `auto_unlock` config key (removed)

## [0.2.8] — SSH Key Management — 2026-10-17

### Added
- **4 new SSH tools**: `vaultwarden_store_ssh`, `vaultwarden_update_ssh`,
  `vaultwarden_delete_ssh`, `vaultwarden_use_ssh` (total: 13 tools)
- SSH private keys stored as login items with file attachment
  (username = SSH user, password = passphrase, key = attachment)
- `vaultwarden_use_ssh`: loads key into ssh-agent with socket resolution
  (direct path / env var / `$SSH_AUTH_SOCK` / fresh agent); starts
  `ssh-agent -a <socket>` when no agent is running on the resolved socket
- SSH key name uniqueness enforcement (`DUPLICATE_NAME` error)
- `bw_cli` attachment methods: `create_attachment`, `get_attachment`,
  `delete_attachment`
- `auth` wrappers: `search_items`, `create_ssh_item`, `get_ssh_key`
- New error codes: `DUPLICATE_NAME`, `AMBIGUOUS_ERROR`, `AGENT_ERROR`
- `plugin.yaml`: `provides_tools` extended with 4 SSH tools,
  description updated

### Security
- SSH passphrase delivered via `subprocess.run(input=...)` stdin pipe —
  never written to a temp file
- SSH key temp file: `tempfile.mkstemp()` (atomic), `0600` perms,
  deleted in `finally` block
- Key content and passphrase registered with `RedactingFilter`

## [0.2.7] — Base64 Encoding Fix — 2026-10-17

### Fixed
- **Root cause of `vaultwarden_store` exit 1**: `encode_item()` now
  base64-encodes the ENTIRE JSON object (per Bitwarden CLI contract),
  instead of double-encoding individual string fields
- Switched from `bw encode` subprocess to Python `base64` stdlib
  (standard RFC 4648); `encode_item()` signature simplified to
  `encode_item(item)`

### Changed
- `create_item()` / `edit_item()` pipe encoded JSON via stdin
  (ARG_MAX-safe); `edit_item()` now accepts and passes the item id
- `_build_item()` / `_apply_updates()` no longer inject explicit
  `match: None` / `passwordRevisionDate: None` nulls

## [0.2.6] — Schema Key & Status Display — 2026-10-16

### Fixed
- **All 9 tools showed empty schemas** in `tool_describe`: schemas
  switched from Anthropic-style `input_schema` to OpenAI-style
  `parameters` key (the format the Hermes registry expects)
- `status_snapshot()` lock indicator now uses internal session state
  (`bw status` always reported "locked" because it lacks `BW_SESSION`)

### Changed
- `vaultwarden_store`: `type` is now optional with default `"login"`
- `vaultwarden_generate_password`: added defaults `length=20`,
  `words=4`, `separator="-"`
- All comments/docstrings normalized to English

## [0.2.5] — Test Alignment — 2026-10-15

### Changed
- Aligned test suite with the config fallback and version headers
- Added `no_config_fallback` fixture to isolate unit tests from the
  real `config.yaml` fallback path

## [0.2.4] — Tool Return Type Fix — 2026-10-15

### Fixed
- All tool handlers now return JSON **string** instead of `dict`
  (Hermes `tool_call` requires `str`; `dict` caused
  "unsupported result type" errors)
- `_guard()` serializes all paths (success / `VaultwardenError` /
  generic exception) via `json.dumps(..., default=str)`

## [0.2.3] — Security Hardening Round 2 — 2026-10-14

### Removed
- **BREAKING**: `auto_unlock` config toggle removed — vault is always
  auto-unlocked with the master password

### Fixed
- Redaction: `RedactingFilter` now catches secrets in all log paths
- ARG_MAX: `bw encode` switched to stdin-based invocation (large
  values no longer crash with OSError)
- Config fallback: direct `config.yaml` read via
  `read_user_config_raw()` when `ctx.get_config()` returns empty

## [0.2.2] — Security Hardening Round 1 — 2026-10-14

### Fixed
- Fail-closed authentication (no silent fallback on auth failure)
- Race condition in concurrent tool calls
- Terminal tools now configurable

## [0.2.1] — Version Headers

### Added
- Version header comment on every source file
- Simplified `ctx` passing

## [0.2.0] — 2026-10-13

### Removed
- **Fallback config reading eliminated.** `_extract_section()` no longer reads
  `$HERMES_HOME/config.yaml` directly. The plugin now relies **exclusively** on
  the Hermes-native `PluginContext.get_config()` API.
- Deleted legacy helpers that only served the fallback parser:
  `_extract_mapping_section()`, `_parse_flat_mapping()`,
  `_extract_nested_section()`, `_fallback_parse_yaml()`,
  `_load_yaml_text()`, `_indent_of()`, `_clean_scalar()`.
- Removed all `DEBUG` warning lines from `__init__.py` that were added
  during troubleshooting.
- Removed `DEFAULT_SECTION_KEY` constant (legacy, unused).

### Changed
- **Version normalization:** all prior `1.x` version references in comments
  and docstrings prefixed with `0.` (e.g., `v1.8` → `v0.1.8`).
- **Author** set to `thieneret` across all files.
- `plugin.yaml` version bumped to `0.2.0`.
- Tests updated to verify `get_config()`-only behavior; fallback-related
  test cases removed.

---

## [0.1.9] — 2026-10-13

### Fixed
- **Auth flow rewritten (3-case logic).** `ensure_authenticated()` now
  queries `bw status` first and takes the minimum necessary action:
  - **Case A** (unauthenticated): configure server → login → unlock.
  - **Case B** (wrong server or wrong account): logout → configure → login → unlock.
  - **Case C** (correct session): unlock if locked; do nothing if already unlocked.
- **"Logout required" error fixed.** The plugin no longer unconditionally
  runs `bw config server` at startup when a valid session already exists.
- **10-second load timeout fixed.** Authentication is deferred to first
  tool use (lazy auth) so `register()` completes well within Hermes's
  plugin-load timeout.

### Added
- `bw_cli.py`: `status()` method — parses `bw status` JSON; degrades
  `SessionError` to `{}` so the auth flow can branch without raising.
- `bw_cli.py`: `logout()` method — idempotent; returns `True` when
  already logged out.
- `bw_cli.py`: `timeout` parameter on `run()` (default 30 s);
  `TimeoutExpired` → `NetworkError`.
- `auth.py`: `_session_state()` — normalises `bw status` payload
  (`status` / `state` key variants).
- `auth.py`: `_adopt_existing_unlocked_session()` — re-unlocks locally
  when bw reports an unlocked profile but no in-memory session key exists.
- `auth.py`: `_maybe_initial_sync()` — best-effort first sync after auth.
- `auth.py`: account verification — compares `bw status` `userId` with
  `config.client_id.removeprefix("user.")`.
- `auth.py`: `is_available()` triggers lazy `ensure_authenticated()` on
  first tool call / `check_fn` evaluation.

### Changed
- `configure_server_if_needed()` is now a pure state transition
  (`UNINITIALIZED → CONFIGURED`); no `bw` subprocess call.
- `__init__.py`: `register()` no longer calls `ensure_authenticated()`;
  tools are registered immediately with `check_fn` gating.

---

## [0.1.8] — 2026-10-13

### Changed
- **Hermes-native config API.** `_extract_section()` now calls
  `ctx.get_config(key, None)` for every key in `_DEFAULTS`, reading from
  `plugins.entries.<plugin_id>.settings.<key>`.
- `plugin.yaml`: all config keys changed from `secrets.vaultwarden.*`
  to plugin-relative keys (`enabled`, `server_url`, `client_id`, …).
- `plugin.yaml`: added `config:` section with typed schema, defaults,
  and descriptions for all keys.

### Added
- `config.py`: `_extract_mapping_section()` helper supporting both
  `plugins.entries.<id>.settings` and legacy `secrets.vaultwarden` layouts.
- `config.py`: fallback to `$HERMES_HOME/config.yaml` when `get_config()`
  yields nothing (transitional).
- Regression test file `test_config_hermes_api_v18.py` (5 tests):
  plugin-relative keys, empty settings defaults, new dict layout,
  legacy layout compat, broken `get_config` tolerance.

---

## [0.1.7] — 2026-10-13

### Changed
- **Multiplex-aware secret resolution.** `PluginConfig.resolve_secret()`
  now tries `agent.secret_scope.get_secret()` first (Hermes internal API,
  multiplex-aware, fail-closed), falling back to `env_snapshot` for
  non-multiplex modes or older Hermes versions.
- Optional import of `agent.secret_scope.get_secret` guarded by
  `try/except ImportError`.

---

## [0.1.6] — 2026-10-13

### Added
- `config.py`: `_extract_nested_section()` — indentation-based YAML
  section extractor (no PyYAML dependency) for nested
  `secrets.vaultwarden` layout.
- `_fallback_parse_yaml()` — tries targeted nested extraction first,
  then flat top-level parsing.

### Changed
- `_minimal_yaml_mapping` no longer raises on nested YAML; nested
  sections handled by `_extract_nested_section` instead.

---

## [0.1.4] — 2026-10-12

### Fixed
- **FAIL-4:** test-only hook `BW_TEST_FORCE_STDERR` lets tests inject
  synthetic stderr without smuggling non-allowlisted env keys.
- **FAIL-5:** `subprocess.run` looked up via module attribute so tests
  can monkeypatch deterministically.
- **FAIL-9:** `RedactingFilter.register_secret()` called **before** any
  attribute assignment or log call in `AuthManager.__init__`.

---

## [0.1.2] — 2026-10-12

### Added
- Initial working release.
- `BwCli` wrapper with isolated subprocess env (`PATH`, `HOME`,
  `BITWARDENCLI_APPDATA_DIR` only).
- `AuthManager` state machine:
  `UNINITIALIZED → CONFIGURED → LOGGED_OUT → LOGGED_IN → UNLOCKED`.
- Placeholder-based secret injection (`PlaceholderRegistry`,
  `tool_request` middleware, `post_tool_call` / `on_session_end` hooks).
- Network retry (single retry with 2 s delay) and rate-limit backoff
  (exponential: 1 s, 2 s, 4 s — max 3 retries).
- Session key held in plugin memory only; never written to
  `os.environ`, logs, or LLM output.
- `RedactingFilter` for log scrubbing of secrets.
- `encode_item()` pipeline — all string fields pass through
  `bw encode` before `create` / `edit`.

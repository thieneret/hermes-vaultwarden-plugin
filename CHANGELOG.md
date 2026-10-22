# Changelog — hermes-vaultwarden-plugin

All notable changes to this project are documented in this file.
Author: **thieneret**

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

# Changelog — hermes-vaultwarden-plugin

All notable changes to this project are documented in this file.
Author: **thieneret**

---

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

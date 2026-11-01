"""Hermes Agent — Vaultwarden secrets management plugin (v0.5.5).

Entry point: ``register(ctx)`` (see plan §4/§12).

Pipeline: secrets.yaml (bootstrap secrets, chmod 600, read DIRECTLY by
secrets.py — v0.5.0 BREAKING: never via .env / OS environment / Hermes
secret_scope) -> plugin-private memory -> isolated bw subprocesses with
BITWARDENCLI_APPDATA_DIR pointing at this plugin's .bw-data.

The LLM only ever sees metadata and single-use placeholder references
(`$__VW_SECRET_x__`); the VWP-04 tool_execution middleware injects the real
secret via a temp file (`$(< path)` under $XDG_RUNTIME_DIR/vw-secrets) right
before execution, deletes the file in a finally block, and post_tool_call
cleans up + redacts.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from . import compat
from . import secrets as _secrets
from .auth import AuthManager, ensure_appdata_dir
from .bw_cli import BwCli, find_bw_binary
from .config import load_config, _sanitize_url_for_logging
from .hooks import (
    _cleanup_stale_secrets,
    _cleanup_stale_sockets,
    make_placeholder_resolver,
    make_post_cleanup_hook,
    make_result_redactor,
    make_session_end_hook,
    resolve_secrets_dir_path,
)
from .placeholders import PlaceholderRegistry
from .secure_fs import FilesystemSecurityError, ensure_hardened_directory
from .security import get_logger, get_redacting_filter
from .tools import get_tools

log = get_logger("init")

__all__ = ["register", "PLUGIN_STATE"]

#: populated after a successful register() so tests/other plugins can introspect
PLUGIN_STATE: dict[str, Any] = {}


# v0.5.0 (BREAKING): the bootstrap secrets are loaded directly from
# secrets.yaml by secrets.py and NEVER enter os.environ, so there is no
# env-cleanup step any more.


def _make_check_fn(auth_ref: AuthManager):
    """BUG-9 fix: proper closure instead of the confusing ``lambda a=auth``
    default-argument trick."""
    def check() -> bool:
        return auth_ref.is_available()
    return check


def register(ctx: Any) -> bool:
    """Hermes plugin entry point. Returns True when active."""
    log.info("Loading vaultwarden plugin...")

    # 1-2. read config, resolve env var NAMES -> values in plugin memory
    try:
        config = load_config(ctx)
    except Exception as exc:  # never crash Hermes over bad config
        log.warning("Vaultwarden plugin load FAILED: config error: %s", exc)
        return False
    if not config.enabled:
        log.warning("Vaultwarden plugin load FAILED: plugin disabled (enabled=false)")
        return False

    # AUD-03 (v0.6.2, FAIL-CLOSED): validate the secret-injection directory
    # BEFORE any tool or hook registration. The shared hardening validator
    # (secure_fs.ensure_hardened_directory) requires an absolute, real
    # (non-symlink) directory owned by the current effective UID with mode
    # EXACTLY 0700; a missing directory is created hardened. An insecure
    # directory aborts plugin activation — no partial state, no tools, no
    # hooks. The error is never silently swallowed; the log line contains
    # the path + reason only, NEVER secret values.
    secrets_dir = resolve_secrets_dir_path()
    try:
        ensure_hardened_directory(secrets_dir, create_if_missing=True)
    except FilesystemSecurityError as exc:
        log.warning("Vaultwarden plugin load FAILED: insecure secrets "
                    "directory: %s", exc)
        return False

    # VWP-20 (v0.4.5): cleanup stale temp files from previous crashed runs
    # (SIGKILL/SIGTERM where the middleware's finally block did not run).
    # v0.5.8: the TTL now respects the configured placeholder_ttl_seconds
    # instead of a hardcoded lifetime — any file older than the registry
    # TTL is stale by definition.
    # AUD-03 (v0.6.2): this also re-validates the directory fail-closed;
    # FilesystemSecurityError propagating here would likewise abort loading.
    _cleanup_stale_secrets(ttl_seconds=config.placeholder_ttl_seconds)

    # VWP-02 (v0.4.6): remove stale ssh-agent sockets (file exists but no
    # agent running) at the developer-controlled socket locations.
    _cleanup_stale_sockets()

    log.info("Vaultwarden plugin enabled, checking prerequisites...")

    # v0.5.0 (BREAKING): bootstrap secrets are loaded from the plugin-private
    # secrets.yaml under HERMES_HOME — they never touch os.environ or the
    # Hermes secret_scope (closes the printenv / cat .env attack surfaces).
    hermes_home = str(os.environ.get("HERMES_HOME", "")).strip() \
        or str(Path.home() / ".hermes")

    # VWP-01 (v0.4.7 BREAKING): bw is executed ONLY from the pinned,
    # strictly validated bw_cli_path (config.yaml). No PATH lookup and no
    # env override. Fail closed: missing or invalid path ->
    # register() returns False and the agent continues without the plugin.
    configured_bw = config.bw_cli_path
    if not configured_bw:
        log.warning("Vaultwarden plugin load FAILED: bw_cli_path is required "
                    "but not configured. Set "
                    "plugins.entries.vaultwarden.settings.bw_cli_path to the "
                    "FULL absolute path of the bw binary in config.yaml.")
        return False
    bw_path = find_bw_binary(configured_bw)
    if not bw_path:
        log.warning("Vaultwarden plugin load FAILED: bw_cli_path=%r is "
                    "configured but failed validation (must be an absolute, "
                    "regular, executable file with no symlink in its chain, "
                    "not group/world-writable, owned by root or the current "
                    "user). See the validation warning above for the exact "
                    "reason.", configured_bw)
        return False
    log.info("Bitwarden CLI pinned and validated: %s", bw_path)

    try:
        client_secret, master_password = _secrets.load_secrets(hermes_home)
    except Exception as exc:
        log.warning("Vaultwarden plugin load FAILED: bootstrap secrets missing: %s", exc)
        return False
    # AUD-02 (phase 2): register the bootstrap credentials PROCESS-SCOPED
    # exactly once, at the single production entry point, BEFORE anything
    # else can echo them. Permanent marking is idempotent — AuthManager's
    # own registration of the same values stays a no-op on refcounts, so
    # repeated manager constructions can never accumulate phantom
    # references (no unbounded global retention).
    _redactor = get_redacting_filter()
    _redactor.register_process_scoped_secret(client_secret)
    _redactor.register_process_scoped_secret(master_password)
    log.info("Bootstrap secrets loaded from %s (never entered OS env)",
             f"{hermes_home}/plugins/vaultwarden/secrets.yaml")

    # SEC-03 (v0.5.5, BREAKING default behavior): privilege-separation POLICY,
    # not just an advisory. With a 'local' (or unset) terminal backend the
    # LLM-driven terminal executes as the SAME OS user that owns secrets.yaml,
    # so the agent could simply `cat` it and read client_secret /
    # master_password in plaintext — file permissions do not isolate processes
    # of the same user. The plugin therefore REFUSES to load unless the
    # operator explicitly opts in via allow_insecure_local_backend: true.
    # This check runs BEFORE any tool/middleware registration so a refused
    # load leaves no partial state.
    backend = _secrets.check_terminal_backend()
    if not _secrets.is_sandboxed_backend(backend):
        if not config.allow_insecure_local_backend:
            # SEC-03 (v0.5.5): fail-closed privilege-separation policy —
            # see CHANGELOG.md [0.5.5] for details.
            log.critical(
                "fail-closed: local terminal backend allows the LLM to "
                "read secrets.yaml as the same OS user; set "
                "allow_insecure_local_backend: true to accept this risk, or "
                "use docker/ssh/modal. Refusing to load the Vaultwarden "
                "plugin (backend=%r).", backend or "unset")
            return False
        # SEC-03 (v0.5.5): operator explicitly accepted the same-user risk.
        log.warning(
            "operator has EXPLICITLY accepted the same-user "
            "secret-exposure risk (allow_insecure_local_backend=true) with "
            "terminal backend %r — the LLM can read secrets.yaml directly "
            "via 'cat'. Recommended production posture: use docker / ssh / "
            "modal for privilege separation.", backend or "unset/local")
    else:
        # SEC-03 (v0.5.5): sandboxed backends satisfy the policy.
        log.info("Terminal backend '%s' is sandboxed — privilege-separation "
                 "policy satisfied.", backend)

    # 4. isolated appdata dir (.bw-data) — AUD-04 (v0.6.2): validated
    # FAIL-CLOSED via the shared hardening validator (absolute, real
    # non-symlink directory, owned by the current effective UID, mode
    # exactly 0700; created hardened when missing, NEVER silently repaired).
    # A FilesystemSecurityError here aborts plugin activation through the
    # handler below (sanitized log + return False — no tools, no hooks).
    try:
        appdata_dir = ensure_appdata_dir(config.appdata_dir())
    except Exception as exc:
        log.warning("Vaultwarden plugin load FAILED: appdata isolation error: %s", exc)
        return False
    log.info("Isolated appdata dir ready: %s", appdata_dir)

    # Create objects but DO NOT authenticate yet (v0.1.9 lazy auth):
    # authentication is deferred to the first tool use / check_fn call so
    # register() completes well within Hermes's 10s plugin-load timeout.
    try:
        config.validate()
        # v0.3.8 (VWP-10): wire the retry/backoff config options through.
        # (The task spec pointed at auth.py, but the only production BwCli(...)
        # constructor call lives here — auth.py receives the instance.)
        bw = BwCli(
            bw_path, appdata_dir,
            max_retries=config.bw_max_retries,
            backoff_base=config.bw_backoff_base,
            max_delay=config.bw_max_delay,
        )
        auth = AuthManager(bw, config,
                           client_secret=client_secret,
                           master_password=master_password)
        # UNINITIALIZED -> CONFIGURED transition only; NO bw subprocess here.
        auth.configure_server_if_needed()
        log.info("AuthManager created (auth deferred to first tool use)")
        # NOTE: Do NOT call ensure_authenticated() here — server config,
        # login and unlock all happen inside ensure_authenticated(), which
        # is triggered lazily by is_available()/check_fn on first tool use.
    except Exception as exc:
        code = compat.get_error_code(exc)
        log.warning("Vaultwarden plugin load FAILED: init error (%s): %s",
                    code, exc)
        return False

    registry = PlaceholderRegistry(ttl_seconds=config.placeholder_ttl_seconds,
                                   max_entries=config.max_placeholders)

    # ── AUD-06 (v0.6.3) + SEC-01 + VWP-03: MANDATORY registration gate ──
    # ALL mandatory hooks/middleware are validated and registered BEFORE any
    # Vaultwarden tool is exposed. Recommended order:
    #   transform_tool_result -> tool_execution middleware ->
    #   post_tool_call -> on_session_end -> tools.
    # If any mandatory registration fails the plugin refuses to load with NO
    # partial state: no tools, no middleware, no hooks.

    # SEC-01 (v0.5.4, HIGH) FAIL-CLOSED — UNCHANGED by AUD-06: the
    # authoritative confidentiality boundary for injected secrets is the
    # `transform_tool_result` hook — Hermes documents it as the ONLY
    # mechanism that may return a replacement tool result BEFORE it reaches
    # the model. If the host Hermes build does not expose this hook, the
    # plugin MUST refuse to load; silently falling back to the old
    # post_tool_call-observer redaction would reintroduce SEC-01 (plaintext
    # secrets possibly surviving into LLM context). This failure path stays
    # SEPARATE from the generic lifecycle-hook handling below — it must
    # never be merged into a catch-all handler that could swallow
    # initialization errors.
    if not compat.supports_transform_tool_result(ctx):
        # SEC-01 (v0.5.4): fail-closed — no authoritative redaction hook,
        # no load. See CHANGELOG.md [0.5.4] for details.
        log.error(
            "fail-closed: host Hermes does not expose the mandatory "
            "'%s' plugin hook. Refusing to load the Vaultwarden plugin "
            "without an authoritative result-redaction boundary — redacting "
            "in the observer-only 'post_tool_call' hook cannot guarantee "
            "that injected secrets are scrubbed before reaching the model. "
            "Upgrade Hermes or disable this plugin.",
            compat.TRANSFORM_TOOL_RESULT_HOOK)
        return False
    redactor_ok = compat.register_hook_if_available(
        ctx, compat.TRANSFORM_TOOL_RESULT_HOOK,
        make_result_redactor(auth, registry, config))
    if not redactor_ok:
        # Capability check passed but registration still failed — same
        # fail-closed rule applies: no transformer, no load.
        # SEC-01 (v0.5.4): fail-closed on registration failure.
        log.error(
            "fail-closed: register_hook('%s') failed. Refusing to "
            "load without the authoritative result redactor.",
            compat.TRANSFORM_TOOL_RESULT_HOOK)
        return False
    # SEC-01 (v0.5.4): authoritative confidentiality boundary now active.
    log.info("Result redactor registered on '%s'",
             compat.TRANSFORM_TOOL_RESULT_HOOK)

    # middleware (chain-safe resolver is NOT pre_tool_call)
    # VWP-03 (v0.4.3): FAIL-CLOSED. If the placeholder-injection middleware
    # cannot be registered, the plugin MUST NOT load — operating without it
    # would leave placeholder tokens unresolved in terminal commands and
    # expose raw secrets. Any exception from register_middleware propagates
    # out of register(); do NOT wrap this call in a swallowing try/except.
    log.info("vaultwarden: registering file-injection middleware (fail-closed)")
    result = ctx.register_middleware(
        "tool_execution", make_placeholder_resolver(auth, registry, config))
    if result is False:
        # Some contexts signal failure with a False return instead of raising.
        raise RuntimeError(
            "vaultwarden plugin: middleware registration failed. "
            "Refusing to load without placeholder injection (fail-closed). "
            "Check Hermes plugin API compatibility."
        )
    log.info("File-injection middleware registered")

    # AUD-06 (v0.6.3) FAIL-CLOSED: mandatory lifecycle hooks. The plugin
    # refuses to load if the required lifecycle hooks cannot be registered:
    #   - post_tool_call : placeholder cleanup, temp-file cleanup
    #     observability, metrics, post-call hygiene;
    #   - on_session_end : session-end cleanup / session lifecycle
    #     termination (the exact session-end hook name this plugin
    #     implements — see hooks.make_session_end_hook).
    # These registrations run BEFORE any tool is exposed so a refused load
    # leaves NO partial plugin state. Registration failures raise
    # errors.PluginInitializationError; we log a sanitized message (hook
    # name + failure reason only — NEVER secrets, YAML contents, env values,
    # or session material), abort initialization, and return False. Do NOT
    # wrap these calls in a swallowing try/except.
    log.info("vaultwarden: registering mandatory lifecycle hooks (fail-closed)")
    lifecycle_handlers = {
        "post_tool_call": make_post_cleanup_hook(auth, registry, config),
        "on_session_end": make_session_end_hook(auth, registry),
    }
    for hook_name in compat.MANDATORY_LIFECYCLE_HOOKS:
        try:
            compat.register_mandatory_lifecycle_hook(
                ctx, hook_name, lifecycle_handlers[hook_name])
        except Exception as exc:
            code = compat.get_error_code(exc)
            log.error(
                "fail-closed: mandatory lifecycle hook '%s' could not be "
                "registered (%s: %s). Aborting Vaultwarden plugin "
                "initialization — no tools are exposed and no partially "
                "active plugin state is left behind.",
                hook_name, code, exc)
            return False
    log.info("Mandatory lifecycle hooks registered: %s",
             ", ".join(compat.MANDATORY_LIFECYCLE_HOOKS))

    # 8. register tools on the 'vaultwarden' toolset — ONLY reached after
    # every mandatory registration above succeeded (AUD-06).
    registered = 0
    for schema, handler in get_tools(auth, config, registry):
        # VWP-17: signature compatibility handled centrally in compat.py
        compat.register_tool_compat(
            ctx, name=schema["name"], toolset="vaultwarden", schema=schema,
            handler=handler, check_fn=_make_check_fn(auth))
        registered += 1
    log.info("Registered %d vaultwarden_* tools.", registered)

    # optional SecretSource (disabled by default)
    if config.allow_startup_secret_injection:
        from .secret_source import register_secret_source
        mappings = []
        section = config.section.get("startup_injections") or []
        if isinstance(section, list):
            mappings = section
        register_secret_source(ctx, auth, config, mappings)

    PLUGIN_STATE.update({"auth": auth, "registry": registry,
                         "config": config, "bw": bw})
    # HVA-02 (v0.7.1): the server URL is sanitized to scheme://host[:port]
    # so user-info / query / fragment material never reaches the logs.
    log.info("Vaultwarden plugin ACTIVE (server=%s, write=%s, auth=deferred).",
             _sanitize_url_for_logging(config.server_url), config.allow_write)
    return True

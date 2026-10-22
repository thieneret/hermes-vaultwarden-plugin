"""Hermes Agent — Vaultwarden secrets management plugin (v0.2.3).

Entry point: ``register(ctx)`` (see plan §4/§12).

Pipeline: .env (bootstrap secrets, loaded by Hermes secret_scope) ->
plugin-private memory -> isolated bw subprocesses with
BITWARDENCLI_APPDATA_DIR pointing at this plugin's .bw-data.

The LLM only ever sees metadata and single-use placeholder tokens; the
tool_request middleware resolves them into terminal commands right before
execution and post_tool_call cleans up + redacts.
"""
from __future__ import annotations

import os
from typing import Any

from .auth import AuthManager, ensure_appdata_dir
from .bw_cli import BwCli, find_bw_binary
from .config import PluginConfig, load_config
from .hooks import make_placeholder_resolver, make_post_cleanup_hook, make_session_end_hook
from .placeholders import PlaceholderRegistry
from .security import get_logger
from .tools import get_tools

log = get_logger("init")

__all__ = ["register", "PLUGIN_STATE"]

#: populated after a successful register() so tests/other plugins can introspect
PLUGIN_STATE: dict[str, Any] = {}


def _cleanup_bootstrap_env(config: PluginConfig) -> None:
    """🚫 CRITICAL step 3: explicit removal of bootstrap secrets from os.environ.

    Secrets flow one way: .env -> plugin memory -> subprocess env. NEVER back.
    """
    for name in (config.client_secret_env_name, config.master_password_env_name):
        try:
            del os.environ[name]
            log.debug("Removed %s from process environment.", name)
        except KeyError:
            pass


def _resolve_secrets(config: PluginConfig) -> tuple[str, str]:
    client_secret = config.resolve_secret(config.client_secret_env_name)
    master_password = config.resolve_secret(config.master_password_env_name)
    return client_secret, master_password


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

    log.info("Vaultwarden plugin enabled, checking prerequisites...")

    # graceful degradation: missing bw -> tools disabled, agent continues
    bw_path = find_bw_binary(config.bw_cli_path)
    if not bw_path:
        log.warning("Vaultwarden plugin load FAILED: Bitwarden CLI ('bw') not found "
                    "(bw_cli_path=%r, BW_CLI_PATH=%r)",
                    config.bw_cli_path, os.environ.get("BW_CLI_PATH", ""))
        return False
    log.info("Bitwarden CLI found: %s", bw_path)

    try:
        client_secret, master_password = _resolve_secrets(config)
    except Exception as exc:
        log.warning("Vaultwarden plugin load FAILED: bootstrap secrets missing: %s", exc)
        return False
    log.info("Bootstrap secrets resolved successfully")

    # 3. EXPLICIT CLEANUP of bootstrap vars from the process environment
    _cleanup_bootstrap_env(config)
    log.debug("Bootstrap environment variables cleaned up")

    # 4. isolated appdata dir (chmod 700)
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
        code = getattr(exc, "code", type(exc).__name__)
        log.warning("Vaultwarden plugin load FAILED: init error (%s): %s",
                    code, exc)
        return False

    registry = PlaceholderRegistry(ttl_seconds=config.placeholder_ttl_seconds,
                                   max_entries=config.max_placeholders)

    # 8. register tools on the 'vaultwarden' toolset
    registered = 0
    for schema, handler in get_tools(auth, config, registry):
        try:
            ctx.register_tool(
                name=schema["name"],
                toolset="vaultwarden",
                schema=schema,
                handler=handler,
                check_fn=_make_check_fn(auth),  # BUG-9: proper closure
            )
            registered += 1
        except TypeError:
            # older/newer register_tool signature without check_fn
            ctx.register_tool(name=schema["name"], toolset="vaultwarden",
                              schema=schema, handler=handler)
            registered += 1
    log.info("Registered %d vaultwarden_* tools.", registered)

    # middleware + hooks (chain-safe resolver is NOT pre_tool_call)
    # VWP-03 (v0.4.3): FAIL-CLOSED. If the placeholder-injection middleware
    # cannot be registered, the plugin MUST NOT load — operating without it
    # would leave placeholder tokens unresolved in terminal commands and
    # expose raw secrets. Any exception from register_middleware propagates
    # out of register(); do NOT wrap this call in a swallowing try/except.
    log.info("vaultwarden: registering placeholder-injection middleware (fail-closed)")
    result = ctx.register_middleware(
        "tool_request", make_placeholder_resolver(auth, registry, config))
    if result is False:
        # Some contexts signal failure with a False return instead of raising.
        raise RuntimeError(
            "vaultwarden plugin: middleware registration failed. "
            "Refusing to load without placeholder injection (fail-closed). "
            "Check Hermes plugin API compatibility."
        )
    log.info("Placeholder resolver middleware registered")
    try:
        ctx.register_hook("post_tool_call", make_post_cleanup_hook(auth, registry, config))
        ctx.register_hook("on_session_end", make_session_end_hook(auth, registry))
        log.info("Cleanup hooks registered")
    except AttributeError:
        log.warning("Context lacks register_hook; cleanup hooks not installed.")

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
    log.info("Vaultwarden plugin ACTIVE (server=%s, write=%s, auth=deferred).",
             config.server_url, config.allow_write)
    return True

"""Optional SecretSource adapter (plan §12) — DISABLED BY DEFAULT.

Implements the Hermes ``SecretSource`` ABC shape without importing it, so
the plugin loads even on Hermes versions that lack the interface. When
``allow_startup_secret_injection: true``, the plugin can expose a fixed,
configured set of vault items as env-style secrets for startup injection.

Rules: read-only; only explicitly configured item ids/fields are reachable;
fail-safe (any error -> empty result + log); does NOT replace runtime
placeholder injection; secret values are registered with the redactor.
"""
from __future__ import annotations

import abc
from typing import Any

from .auth import AuthManager
from .config import PluginConfig
from .security import get_logger
from .tools import _field_value

log = get_logger("secret_source")


class SecretSourceABC(abc.ABC):
    """Local mirror of the Hermes SecretSource contract."""

    @abc.abstractmethod
    def name(self) -> str: ...

    @abc.abstractmethod
    def get_secrets(self) -> dict[str, str]: ...


class VaultwardenSecretSource(SecretSourceABC):
    """Maps configured vault fields -> {env_var_name: value} at startup."""

    def __init__(self, auth: AuthManager, config: PluginConfig,
                 mappings: list[dict] | None = None):
        self._auth = auth
        self._config = config
        # mappings: [{"item_id": ..., "field": "password", "env": "DB_PASSWORD"}, ...]
        self._mappings = [dict(m) for m in (mappings or []) if m.get("item_id")]

    def name(self) -> str:
        return "vaultwarden"

    def get_secrets(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for m in self._mappings:
            try:
                item = self._auth.get_item(str(m["item_id"]))
                value = _field_value(item, str(m.get("field", "password")),
                                     m.get("custom_field_name"))
                if value:
                    key = str(m.get("env") or f"VW_{m['item_id'][:8]}")
                    out[key] = value
            except Exception as exc:  # fail-safe: never crash agent startup
                log.warning("SecretSource mapping for %s failed (%s).",
                            m.get("item_id"), type(exc).__name__)
        return out


def register_secret_source(ctx: Any, auth: AuthManager, config: PluginConfig,
                           mappings: list[dict] | None = None) -> None:
    """Register the adapter with Hermes if the context supports it."""
    source = VaultwardenSecretSource(auth, config, mappings)
    registrar = (getattr(ctx, "register_secret_source", None)
                 or getattr(ctx, "add_secret_source", None))
    if callable(registrar):
        registrar(source)
        log.info("Vaultwarden SecretSource registered (startup injection ON).")
    else:
        log.warning("Hermes context has no SecretSource registrar; skipping.")

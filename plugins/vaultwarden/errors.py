"""Structured error types and LLM-safe error responses for the Vaultwarden plugin.

Error response format (per plan §11):
    {"error": str, "error_code": str, "recoverable": bool, "suggestion": str?}

CRITICAL: messages must NEVER contain secret values (master password,
client secret, session key, resolved credentials).

v0.2.8 error taxonomy additions:
    DUPLICATE_NAME   — store_ssh name uniqueness violation
    AMBIGUOUS_ERROR  — multiple items match a name
    AGENT_ERROR      — ssh-agent start/communication failure
"""
from __future__ import annotations

from typing import Any


class VaultwardenError(Exception):
    """Base class for all plugin errors."""

    code = "PLUGIN_ERROR"
    recoverable = False
    suggestion = ""

    def __init__(self, message: str = "", *, suggestion: str | None = None,
                 code: str | None = None, **attrs: Any):
        super().__init__(message)
        self.message = message or self.__doc__ or "Unknown plugin error"
        if suggestion is not None:
            self.suggestion = suggestion
        # v0.2.8: allow per-instance taxonomy codes (DUPLICATE_NAME,
        # AMBIGUOUS_ERROR, AGENT_ERROR, VALIDATION_ERROR, NOT_FOUND) without
        # subclassing for every call site.
        if code is not None:
            self.code = code
        # v0.7.2 (first-burst bootstrap fix, CHANGE 3): structured, sanitized
        # metadata attributes (e.g. bootstrap_stage="login") attachable to
        # any error WITHOUT changing the public to_dict() response shape —
        # consumers (the bw_cli choke point) read them via getattr. Values
        # must be fixed stage identifiers / booleans, NEVER secret material.
        for _k, _v in attrs.items():
            setattr(self, _k, _v)

    #: v0.7.2 (first-burst bootstrap fix, CHANGE 3): allowlist of structured
    #: metadata attributes that may ride into the operator-facing to_dict()
    #: response. Values are FIXED identifiers only (e.g. "login"/"unlock"),
    #: NEVER secret material — attaching them never leaks credentials.
    _TO_DICT_ATTRS = ("bootstrap_stage",)

    def to_dict(self) -> dict:
        resp = {
            "error": self.message,
            "error_code": self.code,
            "recoverable": self.recoverable,
        }
        if self.suggestion:
            resp["suggestion"] = self.suggestion
        # CHANGE 3: surface the sanitized bootstrap STAGE so consumers and
        # tests can verify a login-stage failure was never blamed on
        # master_password. Shape for all pre-existing errors is unchanged
        # (attribute absent => no new keys).
        for _k in self._TO_DICT_ATTRS:
            _v = getattr(self, _k, None)
            if isinstance(_v, str) and _v:
                resp[_k] = _v
        return resp


class ConfigError(VaultwardenError):
    code = "CONFIG_ERROR"
    recoverable = False
    suggestion = ("Fix the vaultwarden section of config.yaml or the "
                  "plugin-private secrets.yaml file (chmod 600).")


# v0.4.8 (BUGFIX): auth._configure_server raises errors.PluginError, which
# did not exist — a failed `bw config server` produced a latent
# AttributeError instead of the intended structured error.
class PluginError(VaultwardenError):
    """Generic plugin-level failure (base taxonomy code PLUGIN_ERROR)."""

    code = "PLUGIN_ERROR"


class BinaryError(VaultwardenError):
    code = "BINARY_ERROR"
    recoverable = False
    # v0.4.7 (VWP-01): the env override was removed — bw_cli_path in
    # config.yaml is the single source of truth for the binary location.
    suggestion = ("Install the Bitwarden CLI (`npm install -g @bitwarden/cli`) "
                  "and set plugins.entries.vaultwarden.settings.bw_cli_path "
                  "to its full absolute path in config.yaml.")


class AuthError(VaultwardenError):
    code = "AUTH_ERROR"
    recoverable = False
    suggestion = ("Check client_secret / master_password in "
                  "$HERMES_HOME/plugins/vaultwarden/secrets.yaml (chmod 600).")


class SessionError(VaultwardenError):
    code = "SESSION_ERROR"
    recoverable = True
    suggestion = "The plugin will attempt automatic re-unlock."


class NetworkError(VaultwardenError):
    code = "NETWORK_ERROR"
    recoverable = True
    suggestion = "Verify the Vaultwarden server URL is reachable."


class NotFoundError(VaultwardenError):
    code = "NOT_FOUND"
    recoverable = False
    suggestion = "Use vaultwarden_search or vaultwarden_list to find the correct item id."


class PermissionError_(VaultwardenError):
    """Raised when a write operation is attempted while allow_write is false."""

    code = "PERMISSION_ERROR"
    recoverable = False
    suggestion = "Set secrets.vaultwarden.allow_write: true in config.yaml to enable writes."


class ParseError(VaultwardenError):
    code = "PARSE_ERROR"
    recoverable = False
    suggestion = "Check the installed bw version (bw --version)."


class PlaceholderError(VaultwardenError):
    code = "PLACEHOLDER_ERROR"
    recoverable = True
    suggestion = "Request a fresh placeholder with vaultwarden_get_secret_ref."


class RateLimitError(VaultwardenError):
    code = "RATE_LIMIT"
    recoverable = True
    suggestion = "Plugin retries automatically with exponential backoff."


class AppdataError(VaultwardenError):
    code = "APPDATA_ERROR"
    recoverable = False
    suggestion = "Ensure the plugin directory is writable (chmod 700 on .bw-data)."


# ---------------------------------------------------- v0.2.8 error taxonomy
class DuplicateNameError(VaultwardenError):
    """store_ssh name uniqueness violation."""

    code = "DUPLICATE_NAME"
    recoverable = False
    suggestion = "Choose a different name or use vaultwarden_update_ssh."


class AmbiguousError(VaultwardenError):
    """Multiple items match a name."""

    code = "AMBIGUOUS_ERROR"
    recoverable = False
    suggestion = "Use vaultwarden_search to find the correct item_id."


class AgentError(VaultwardenError):
    """ssh-agent start/communication failure."""

    code = "AGENT_ERROR"
    recoverable = True
    suggestion = "Verify ssh-agent/ssh-add are installed and PATH is set."


# ---------------------------------------------------- v0.3.8 error taxonomy
class UnsupportedBwVersionError(VaultwardenError):
    """Raised when the bw CLI version is below the minimum supported
    threshold or cannot be parsed (VWP-11, fail-closed, no override)."""
    code = "UNSUPPORTED_BW_VERSION"

    def __init__(self, message: str, *, suggestion: str | None = None):
        super().__init__(
            message,
            suggestion=suggestion or (
                "Upgrade the Bitwarden CLI (bw) to version 2026.9.1 or "
                "later. The plugin will not start with an unsupported "
                "version."
            ),
        )


# ---------------------------------------------------- v0.5.8 error taxonomy
class SecurityError(PluginError):
    """Fail-closed security validation failure (e.g. the secrets directory
    is a symlink, owned by another user, or not exactly mode 0700).

    Raised from hooks._secrets_dir() / _validate_secrets_dir(): the plugin
    REFUSES to load or inject rather than falling back to an insecure path.
    Messages must never contain secret material.
    """

    code = "SECURITY_ERROR"
    recoverable = False


# ---------------------------------------------------- v0.6.3 error taxonomy
class PluginInitializationError(SecurityError):
    """AUD-06: fail-closed plugin-initialization failure raised when a
    MANDATORY lifecycle hook cannot be registered (unsupported by the host,
    registration raised, or registration returned an explicit failure).

    The plugin refuses to load — tools are never exposed on a partially
    initialized plugin. Messages may contain hook names and sanitized
    failure reasons ONLY — never secrets, YAML contents, environment
    variable values, or session material.
    """

    code = "PLUGIN_INITIALIZATION_ERROR"
    recoverable = False


def error_response(exc: Exception) -> dict:
    """Convert any exception into the standard, secret-free error dict."""
    if isinstance(exc, VaultwardenError):
        return exc.to_dict()
    # Unknown internal error: never echo the raw exception text to the LLM,
    # it could theoretically contain sensitive argv/env fragments.
    return {
        "error": f"Internal plugin error: {type(exc).__name__}",
        "error_code": "INTERNAL_ERROR",
        "recoverable": False,
        "suggestion": "See Hermes logs (redacted) for details.",
    }

# vaultwarden/errors.py — v0.2.8
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


class VaultwardenError(Exception):
    """Base class for all plugin errors."""

    code = "PLUGIN_ERROR"
    recoverable = False
    suggestion = ""

    def __init__(self, message: str = "", *, suggestion: str | None = None):
        super().__init__(message)
        self.message = message or self.__doc__ or "Unknown plugin error"
        if suggestion is not None:
            self.suggestion = suggestion

    def to_dict(self) -> dict:
        resp = {
            "error": self.message,
            "error_code": self.code,
            "recoverable": self.recoverable,
        }
        if self.suggestion:
            resp["suggestion"] = self.suggestion
        return resp


class ConfigError(VaultwardenError):
    code = "CONFIG_ERROR"
    recoverable = False
    suggestion = "Fix the vaultwarden section of config.yaml or the .env file."


class BinaryError(VaultwardenError):
    code = "BINARY_ERROR"
    recoverable = False
    suggestion = "Install the Bitwarden CLI (`npm install -g @bitwarden/cli`) or set BW_CLI_PATH."


class AuthError(VaultwardenError):
    code = "AUTH_ERROR"
    recoverable = False
    suggestion = "Check VW_CLIENT_SECRET / VW_MASTER_PASSWORD in your .env file."


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

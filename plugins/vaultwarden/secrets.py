"""Bootstrap secret loading for the Vaultwarden plugin (v0.5.0, BREAKING).

Prior to v0.5.0 the bootstrap secrets (``client_secret`` / ``master_password``)
were resolved from the Hermes ``.env`` file via ``config.resolve_secret()``
(Hermes secret_scope or OS environment). That design left two attack
surfaces open in multiplex gateway mode:

1. The LLM could read ``.env`` directly (``cat /opt/data/.env``) because it
   runs as the same OS user as the plugin.
2. The LLM could dump the environment (``printenv``) before the plugin
   deleted its bootstrap variables.

This module replaces that mechanism with a plugin-private YAML file:

    $HERMES_HOME/plugins/vaultwarden/secrets.yaml   (chmod 600, enforced)

The file is read DIRECTLY by the plugin — the secret values NEVER enter an
environment variable or the Hermes secret_scope at any point, which closes
both attack surfaces above.

Residual risk: when the terminal backend is ``local``, the LLM executes
commands as the same OS user and can still ``cat`` this file. The
``check_terminal_backend()`` helper below logs a WARNING in that case and
advises migrating to a sandboxed backend (``docker`` / ``ssh`` / ``modal``)
for production use (privilege separation).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from . import errors

log = logging.getLogger("hermes.plugins.vaultwarden.secrets")

#: Keys expected inside secrets.yaml.
_REQUIRED_KEYS = ("client_secret", "master_password")


def _parse_simple_yaml(text: str) -> dict[str, str]:
    """Minimal flat ``key: value`` YAML parser (fallback when PyYAML is absent).

    Handles exactly the shape of ``secret.yaml.template``: single-level
    mappings, ``#`` comments, quoted or bare scalar values. Anything more
    complex is ignored (the caller then reports the keys as missing).
    """
    data: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        if not key or key.startswith(("-", "*")):
            continue  # not a plain mapping line
        value = value.strip()
        if value.startswith(("'", '"')) and len(value) >= 2 and value[-1] == value[0]:
            value = value[1:-1]
        else:
            # strip trailing " # comment" from unquoted scalars
            hash_pos = value.find(" #")
            if hash_pos != -1:
                value = value[:hash_pos].rstrip()
        data[key] = value
    return data


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    """Parse a small YAML mapping; prefer PyYAML, fall back to stdlib.

    The fallback parser is FLAT (``key: value`` only).  For nested shapes
    such as ``terminal:\\n  backend: local`` in ``~/.hermes/config.yaml`` it
    returns nothing usable, so we additionally promote any indented child of
    a top-level mapping key into ``{"<parent>": {"<child>": ...}}``.  This
    keeps one-to-two-level nested mappings working whether or not PyYAML is
    installed (CI venvs do not have it — the project has zero runtime deps).
    """
    text = path.read_text(encoding="utf-8-sig")
    try:
        import yaml
    except ImportError:
        yaml = None  # type: ignore[assignment]
    if yaml is not None:
        data = yaml.safe_load(text)
        if isinstance(data, dict):
            return data
        return {}
    # Fallback pass (no PyYAML): rebuild one-level nested mappings from
    # indentation so that e.g. config.yaml's `terminal:\n  backend: docker`
    # survives as {"terminal": {"backend": "docker"}}.
    data: dict[str, Any] = {}
    current_parent: str | None = None
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        if not key or key.startswith(("-", "*")):
            continue
        value = value.strip()
        # Unquote scalar values (single- or double-quoted).  The open quote,
        # the closing quote at end-of-line, and any trailing " # comment" are
        # all handled — an empty quoted string correctly yields "".
        if len(value) >= 2 and value[0] in ("'", '"'):
            quote = value[0]
            end = value.find(quote, 1)
            if end != -1:
                rest = value[end + 1:].strip()
                if rest == "" or rest.startswith("#"):
                    value = value[1:end]
                else:
                    hash_pos = value.find(" #")
                    if hash_pos != -1:
                        value = value[:hash_pos].rstrip()
            else:
                hash_pos = value.find(" #")
                if hash_pos != -1:
                    value = value[:hash_pos].rstrip()
        else:
            hash_pos = value.find(" #")
            if hash_pos != -1:
                value = value[:hash_pos].rstrip()
        indented = raw_line[:1] in (" ", "\t")
        if not indented and value == "":
            # parent mapping key with no inline value -> start a nested dict
            current_parent = key
            data.setdefault(key, {})
        elif indented and current_parent is not None:
            child = data.get(current_parent)
            if isinstance(child, dict):
                child[key] = value
        else:
            current_parent = None
            data[key] = value
    return data


def load_secrets(hermes_home: str) -> tuple[str, str]:
    """Load the bootstrap secrets from the plugin-private secrets.yaml file.

    Path: ``{hermes_home}/plugins/vaultwarden/secrets.yaml``

    Raises:
        errors.ConfigError: file missing, wrong permissions (must be 0600),
            unparsable content, or an empty/missing required key.

    Returns:
        ``(client_secret, master_password)`` — loaded into plugin memory
        ONLY; never exported to os.environ or any subprocess env.
    """
    path = Path(hermes_home).expanduser() / "plugins" / "vaultwarden" / "secrets.yaml"

    if not path.is_file():
        raise errors.ConfigError(
            f"Bootstrap secrets file not found: {path}",
            suggestion=(
                "Copy plugins/vaultwarden/secret.yaml.template to "
                f"{path}, fill in 'client_secret' and 'master_password', "
                "then run: chmod 600 secrets.yaml"),
        )

    # v0.5.0: strict permission check — the file holds raw secret VALUES,
    # so owner read/write only (0600) is mandatory. Fail closed otherwise.
    mode = path.stat().st_mode & 0o777
    if mode != 0o600:
        raise errors.ConfigError(
            f"Insecure permissions on {path}: {oct(mode)} (expected 0600)",
            suggestion=f"Run: chmod 600 {path}",
        )

    try:
        data = _load_yaml_mapping(path)
    except errors.ConfigError:
        raise
    except Exception as exc:
        raise errors.ConfigError(
            f"Failed to parse {path}: {exc}",
            suggestion="Ensure secrets.yaml is a valid flat YAML mapping with "
                       "'client_secret' and 'master_password' keys.",
        )

    values: dict[str, str] = {}
    for key in _REQUIRED_KEYS:
        value = data.get(key, "")
        value = "" if value is None else str(value).strip()
        if not value:
            raise errors.ConfigError(
                f"'{key}' is missing or empty in {path}.",
                suggestion=f"Fill in '{key}' in {path} "
                           "(see secret.yaml.template), keep chmod 600.",
            )
        values[key] = value

    return values["client_secret"], values["master_password"]


def _backend_from_hermes_config() -> str:
    """Read ``terminal.backend`` from ~/.hermes/config.yaml (best effort)."""
    hermes_home = os.environ.get("HERMES_HOME", "").strip()
    config_path = (Path(hermes_home).expanduser() if hermes_home
                   else Path.home() / ".hermes") / "config.yaml"
    if not config_path.is_file():
        return ""
    try:
        data = _load_yaml_mapping(config_path)
    except Exception:
        return ""
    terminal = data.get("terminal")
    if isinstance(terminal, dict):
        return str(terminal.get("backend", "") or "").strip().lower()
    return ""


def check_terminal_backend() -> str:
    """Warn when the terminal backend lets the LLM read secrets.yaml.

    Resolution order:
      1. ``TERMINAL_ENV`` environment variable (explicit override).
      2. ``terminal.backend`` in ``~/.hermes/config.yaml``
         (or ``$HERMES_HOME/config.yaml`` when set).

    A backend of ``local`` (or unset/empty) means the agent's terminal tools
    execute as the SAME OS user that owns secrets.yaml — the LLM could then
    simply ``cat`` the file. Sandboxed backends (docker / ssh / modal / ...)
    provide privilege separation and are logged at INFO level.

    Returns the effective backend name (for tests / introspection).
    """
    backend = os.environ.get("TERMINAL_ENV", "").strip().lower()
    if not backend:
        backend = _backend_from_hermes_config()

    if backend in ("", "local"):
        log.warning(
            "WARNING: terminal backend is 'local'. The LLM can read "
            "secrets.yaml via 'cat'. For production, use 'docker' or 'ssh' "
            "backend.")
    else:
        log.info("Terminal backend is '%s' — sandboxed from the plugin's "
                 "OS user; secrets.yaml is not readable by the LLM.", backend)
    return backend

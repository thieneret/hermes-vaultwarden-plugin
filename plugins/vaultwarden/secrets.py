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
commands as the same OS user and can still ``cat`` this file. Since v0.5.5
(SEC-03) this is a fail-closed POLICY, not an advisory: ``register()``
REFUSES to load on a local/unset backend unless the operator explicitly
opts in via the ``allow_insecure_local_backend`` config flag (default
false). Sandboxed backends (``docker`` / ``ssh`` / ``modal``) provide
privilege separation and are the recommended production posture.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from . import errors
from .secure_fs import FilesystemSecurityError, ensure_hardened_secret_file

log = logging.getLogger("hermes.plugins.vaultwarden.secrets")

#: Keys expected inside secrets.yaml.
_REQUIRED_KEYS = ("client_secret", "master_password")


def _scalar_or_empty(raw_value: str) -> tuple[bool, str]:
    """Normalise one inline YAML scalar.

    Returns ``(is_valueless, processed_value)``.  A value is "valueless"
    (i.e. the line opens a nested mapping) only when everything after the
    ':' is blank or a pure ``#`` comment.  Quoted scalars are unquoted
    AFTER comment stripping so that ``key: ""`` yields ``""`` (empty
    string), NOT a nested mapping — this was the v0.5.0 CI regression:
    misclassifying ``client_secret: ""`` as a parent key silently turned
    the secret into ``{}`` and broke empty-value validation.
    """
    v = raw_value.strip()
    if v == "" or v.startswith("#"):
        return True, ""
    if v[0] in ("'", '"'):
        quote = v[0]
        end = v.find(quote, 1)
        if end != -1:
            rest = v[end + 1:].strip()
            if rest == "" or rest.startswith("#"):
                # quoted scalar: '#' inside the quotes is part of the
                # value (e.g. master_password: "p#ssw0rd")
                return False, v[1:end]
        # unterminated / junk after closing quote — fall through to the
        # generic comment-stripping path below
    # unquoted scalar: strip trailing " # comment" (only recognised when
    # preceded by whitespace)
    hash_pos = v.find(" #")
    if hash_pos != -1:
        v = v[:hash_pos].rstrip()
    return False, v


def _parse_simple_yaml(text: str) -> dict[str, str]:
    """Minimal flat ``key: value`` YAML parser (stdlib-only fallback core).

    Handles exactly the shape of ``secret.yaml.template``: single-level
    mappings, ``#`` comments, quoted or bare scalar values.  Values are
    returned as strings; a valueless key maps to ``""`` (the caller then
    reports the key as missing/empty).
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
        _, value = _scalar_or_empty(value)
        data[key] = value
    return data


def _load_yaml_mapping(path: Path) -> dict[str, Any]:
    """Parse a small YAML mapping; prefer PyYAML, fall back to stdlib.

    The stdlib fallback understands two structural forms, which cover every
    file this plugin reads:

    * flat mappings (``secrets.yaml``) — parsed by :func:`_parse_simple_yaml`;
    * block mappings nested by INDENTATION (``~/.hermes/config.yaml``, e.g.
      ``terminal:\\n  backend: local``) — rebuilt with a stack keyed on the
      column of each key, so arbitrarily deep nesting works without PyYAML
      (CI venvs have zero runtime deps and therefore no PyYAML).

    Scalars are always strings; flow collections / lists / multi-document
    YAML are out of scope and simply ignored or treated as plain scalars.
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

    # ---- stdlib fallback: indentation-based block-mapping reconstruction --
    root: dict[str, Any] = {}
    # Stack of (indent_column, dict_at_that_level); indent -1 => col 0.
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if ":" not in raw_line:
            continue
        content = raw_line.rstrip()
        indent = len(content) - len(content.lstrip(" \t"))
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        container = stack[-1][1]
        body = content.strip()
        key, _, value = body.partition(":")
        key = key.strip()
        if not key or key.startswith(("-", "*", "|", ">")):
            continue
        value = value.strip()
        is_valueless, scalar = _scalar_or_empty(value)
        if is_valueless:
            child: dict[str, Any] = {}
            container[key] = child
            stack.append((indent, child))
        else:
            container[key] = scalar
    return root


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

    # AUD-08 (v0.6.2, FAIL-CLOSED): validate the file through the SHARED
    # hardening validator BEFORE any YAML parsing or read: absolute path,
    # regular file (never a symlink — checked via os.lstat()), owned by the
    # CURRENT EFFECTIVE UID, no group/other access (mode & 0o077 == 0;
    # canonical mode 0600). An existing but insecure secrets.yaml is NEVER
    # parsed and NEVER silently repaired. FilesystemSecurityError propagates
    # to register(), which aborts plugin activation (sanitized log only —
    # path + reason, never secret values).
    try:
        ensure_hardened_secret_file(path, allow_missing=False)
    except FilesystemSecurityError as exc:
        if "does not exist" in str(exc):
            raise errors.ConfigError(
                f"Bootstrap secrets file not found: {path}",
                suggestion=(
                    "Copy plugins/vaultwarden/secret.yaml.template to "
                    f"{path}, fill in 'client_secret' and 'master_password', "
                    "then run: chmod 600 secrets.yaml"),
            ) from None
        # Insecure-but-present file: fail closed, do NOT parse. Keep the
        # dedicated error type so callers/tests can distinguish it.
        raise

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
    """
    Detect terminal backend from $HERMES_HOME/config.yaml.

    NOTE: This deviates from VWP-05 (native Hermes API only) because the
    PluginContext.get_config() API only exposes plugin-scoped settings, not
    global Hermes configuration like terminal.backend. No native API exists
    for plugins to query the active terminal backend. This is documented as
    an intentional compatibility exception in SECURITY.md.
    """
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


#: Backends that execute the LLM-driven terminal in a DIFFERENT privilege
#: domain than the plugin's OS user (SEC-03, v0.5.5). Anything else — most
#: notably ``local`` or an unset backend — means the agent runs as the same
#: OS user that owns secrets.yaml and could read it directly (`cat`).
SANDBOXED_BACKENDS = ("docker", "ssh", "modal")


def is_sandboxed_backend(backend: str) -> bool:
    """Return True when ``backend`` provides privilege separation (SEC-03).

    ``docker`` / ``ssh`` / ``modal`` run the LLM's terminal OUTSIDE this OS
    user, so secrets.yaml is not readable by the agent. ``local`` and empty
    (unset) values are NOT sandboxed. The check performs NO network calls and
    spawns NO subprocesses — pure string classification.
    """
    return str(backend or "").strip().lower() in SANDBOXED_BACKENDS


def check_terminal_backend() -> str:
    """Classify the terminal backend and log the confidentiality posture.

    Resolution order:
      1. ``TERMINAL_ENV`` environment variable (explicit override).
      2. ``terminal.backend`` in ``~/.hermes/config.yaml``
         (or ``$HERMES_HOME/config.yaml`` when set).

    A backend of ``local`` (or unset/empty) means the agent's terminal tools
    execute as the SAME OS user that owns secrets.yaml — the LLM could then
    simply ``cat`` the file. Sandboxed backends (docker / ssh / modal)
    provide privilege separation and are logged at INFO level.

    SEC-03 (v0.5.5): this helper only CLASSIFIES and LOGS; the fail-closed
    POLICY lives in ``register()`` (__init__.py), which consumes the RETURNED
    backend together with the ``allow_insecure_local_backend`` config flag
    and refuses to load on a local/unset backend unless the operator opts in.

    Returns the effective backend name ('' when unset) so the caller can
    enforce the policy (for tests / introspection as well).
    """
    backend = os.environ.get("TERMINAL_ENV", "").strip().lower()
    if not backend:
        backend = _backend_from_hermes_config()

    if is_sandboxed_backend(backend):
        log.info("Terminal backend is '%s' — sandboxed from the plugin's "
                 "OS user; secrets.yaml is not readable by the LLM.", backend)
    elif backend == "local":
        log.warning(
            "WARNING: terminal backend is 'local'. The LLM can read "
            "secrets.yaml via 'cat'. For production, use 'docker' or 'ssh' "
            "backend.")
    else:
        # unset / unknown backend: treat as NOT privilege-separated
        # (fail-closed classification — register() decides the policy).
        log.warning(
            "WARNING: terminal backend is unset/unknown (%r); treating it as "
            "'local' — the LLM may share this OS user and could read "
            "secrets.yaml via 'cat'. Configure a sandboxed backend "
            "('docker', 'ssh', or 'modal') for privilege separation.",
            backend or "")
    return backend

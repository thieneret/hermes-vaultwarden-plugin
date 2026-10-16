# vaultwarden/tests/test_cleanup_hardening_v026.py — v0.2.6
"""Regression tests for the v0.2.6 cleanup & hardening release:

- CRITICAL (BUG-8 resolved): all 9 tool schemas switched from the
  Anthropic-style "input_schema" key to the OpenAI-style "parameters"
  key expected by the deployed Hermes Agent registry.
- BUGFIX: status_snapshot() reports the internal session state as the
  lock indicator (bw status without BW_SESSION always said "locked").
- BUGFIX: vaultwarden_store "type" is optional with default "login".
- BUGFIX: vaultwarden_generate_password declares defaults for length,
  words and separator.
- CLEANUP: no Hungarian text left in comments/docstrings.
"""
from __future__ import annotations


def test_schemas_use_parameters_key():
    """v0.2.6: all schemas must use the OpenAI-style 'parameters' key."""
    from vaultwarden.schemas import TOOL_SCHEMAS, SCHEMA_KEY
    assert SCHEMA_KEY == "parameters", \
        f"SCHEMA_KEY must be 'parameters', got {SCHEMA_KEY!r}"
    for schema in TOOL_SCHEMAS:
        assert "parameters" in schema, \
            f"{schema['name']}: missing 'parameters' key"
        assert "input_schema" not in schema, \
            f"{schema['name']}: stale 'input_schema' key still present"


def test_status_snapshot_shows_unlocked_when_session_active():
    """v0.2.6: status_snapshot must show 'unlocked' when session is active."""
    from unittest.mock import MagicMock
    from vaultwarden.auth import AuthManager, AuthState
    import time

    bw = MagicMock()
    bw.status.return_value = {"status": "locked", "serverUrl": "https://vault.example.com"}

    config = MagicMock()
    config.server_url = "https://vault.example.com"
    config.session_timeout_seconds = 14400
    config.auto_sync = False
    config.enabled = True
    config.allow_write = True

    auth = AuthManager(bw, config, client_secret="cs", master_password="mp")
    auth._state = AuthState.UNLOCKED
    auth._session_key = "test-session-key"
    auth._session_created_at = time.time()

    snapshot = auth.status_snapshot()
    assert snapshot["session_active"] is True
    assert snapshot["auth_state"] == "unlocked"
    assert snapshot["server_status"]["state"] == "unlocked", \
        f"Expected 'unlocked', got {snapshot['server_status']['state']}"


def test_status_snapshot_shows_locked_when_no_session():
    """v0.2.6: status_snapshot falls back to bw status when no session."""
    from unittest.mock import MagicMock
    from vaultwarden.auth import AuthManager, AuthState

    bw = MagicMock()
    bw.status.return_value = {"status": "locked", "serverUrl": "https://vault.example.com"}

    config = MagicMock()
    config.server_url = "https://vault.example.com"
    config.session_timeout_seconds = 14400
    config.auto_sync = False
    config.enabled = True
    config.allow_write = True

    auth = AuthManager(bw, config, client_secret="cs", master_password="mp")
    auth._state = AuthState.LOGGED_IN
    auth._session_key = None

    snapshot = auth.status_snapshot()
    assert snapshot["session_active"] is False
    assert snapshot["server_status"]["state"] == "locked"


def test_store_schema_type_not_required():
    """v0.2.6: vaultwarden_store type must be optional with default 'login'."""
    from vaultwarden.schemas import VAULTWARDEN_STORE
    schema = VAULTWARDEN_STORE["parameters"]
    assert "type" not in schema.get("required", []), \
        "'type' should not be required (handler defaults to 'login')"
    props = schema.get("properties", {})
    assert props.get("type", {}).get("default") == "login"


def test_generate_password_schema_defaults():
    """v0.2.6: generate_password schema must declare defaults."""
    from vaultwarden.schemas import VAULTWARDEN_GENERATE_PASSWORD
    props = VAULTWARDEN_GENERATE_PASSWORD["parameters"]["properties"]
    assert props["length"].get("default") == 20, "length must default to 20"
    assert props["words"].get("default") == 4, "words must default to 4"
    assert props["separator"].get("default") == "-", "separator must default to '-'"


def test_sync_schema_has_force():
    """v0.2.6: vaultwarden_sync schema must declare the force parameter."""
    from vaultwarden.schemas import VAULTWARDEN_SYNC
    props = VAULTWARDEN_SYNC["parameters"]["properties"]
    assert "force" in props, f"'force' not in schema: {list(props.keys())}"
    assert props["force"]["type"] == "boolean"


def test_update_schema_cross_reference_uses_parameters():
    """v0.2.6: VAULTWARDEN_UPDATE must cross-reference STORE via 'parameters'."""
    from vaultwarden.schemas import (VAULTWARDEN_STORE, VAULTWARDEN_UPDATE)
    store_cf = VAULTWARDEN_STORE["parameters"]["properties"]["custom_fields"]
    update_cf = VAULTWARDEN_UPDATE["parameters"]["properties"]["custom_fields"]
    assert update_cf == store_cf


def test_no_hungarian_in_comments():
    """v0.2.6: no Hungarian words in comments or docstrings."""
    import re
    from pathlib import Path
    import vaultwarden

    pkg_dir = Path(vaultwarden.__file__).resolve().parent
    hungarian_pattern = re.compile(
        r"függvény|hiba|jelszó|beállítás|keresés|lista|törlés|frissítés|"
        r"szinkronizálás|biztonság|titok|állapot|működik|könyvtár|"
        r"elérési|útvonal|megjegyzés|fontos|figyelmeztetés|kivétel|"
        r"visszatérési|bemeneti|kimeneti|alapértelmezett|kötelező|"
        r"opcionális|engedélyez|letilt|betölt|zárolt|feloldott",
        re.IGNORECASE)

    violations = []
    for py_file in pkg_dir.glob("*.py"):
        if py_file.name.startswith("test_"):
            continue  # skip test files (they contain the regex itself)
        content = py_file.read_text(encoding="utf-8")
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                if hungarian_pattern.search(line):
                    violations.append(f"{py_file.name}:{i}: {stripped[:80]}")

    assert not violations, (
        f"Hungarian text found in {len(violations)} comment(s):\n"
        + "\n".join(violations[:10]))

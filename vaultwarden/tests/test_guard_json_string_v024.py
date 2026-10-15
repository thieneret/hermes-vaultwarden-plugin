# vaultwarden/tests/test_guard_json_string_v024.py — v0.2.4
"""v0.2.4 regression tests: _guard() and tool handlers must return JSON strings.

Hermes Agent's tool_call mechanism requires handlers to return `str`;
returning `dict` caused "unsupported result type: dict" for every invocation.
The fix is centralized in `_guard()` (single exit point for all 9 handlers).
"""
from __future__ import annotations


def test_guard_returns_json_string():
    """v0.2.4: _guard must return str, not dict."""
    import json
    from vaultwarden.tools import _guard

    result = _guard(lambda: {"key": "value", "count": 42})
    assert isinstance(result, str), f"Expected str, got {type(result)}"
    parsed = json.loads(result)
    assert parsed == {"key": "value", "count": 42}


def test_guard_error_returns_json_string():
    """v0.2.4: _guard error paths must also return str."""
    import json
    from vaultwarden.tools import _guard
    from vaultwarden import errors

    def failing():
        raise errors.NotFoundError("Item not found.")

    result = _guard(failing)
    assert isinstance(result, str), f"Expected str, got {type(result)}"
    parsed = json.loads(result)
    assert "error" in parsed
    assert parsed["error_code"] == "NOT_FOUND"


def test_all_handlers_return_str():
    """v0.2.4: every tool handler must return str via _guard."""
    import json
    from unittest.mock import MagicMock
    from vaultwarden.tools import get_tools
    from vaultwarden.placeholders import PlaceholderRegistry

    auth = MagicMock()
    auth.status_snapshot.return_value = {"auth_state": "unlocked"}
    auth.sync.return_value = {"synced": True}
    auth.list_items.return_value = []
    auth.generate_password.return_value = "test-password-123"

    config = MagicMock()
    config.allow_write = True
    config.allow_direct_secret_retrieval = False

    registry = PlaceholderRegistry(ttl_seconds=300, max_entries=50)

    for schema, handler in get_tools(auth, config, registry):
        tool_name = schema["name"]
        try:
            if tool_name == "vaultwarden_status":
                result = handler({})
            elif tool_name == "vaultwarden_sync":
                result = handler({"force": False})
            elif tool_name == "vaultwarden_list":
                result = handler({"limit": 10})
            elif tool_name == "vaultwarden_search":
                result = handler({"query": "test"})
            elif tool_name == "vaultwarden_generate_password":
                result = handler({"mode": "password", "length": 16})
            else:
                continue  # skip tools that need complex mocking

            assert isinstance(result, str), \
                f"{tool_name}: expected str, got {type(result).__name__}"
            json.loads(result)  # must be valid JSON
        except Exception as exc:
            raise AssertionError(f"{tool_name}: handler failed: {exc}")


def test_version_headers_v024():
    """Verify modified files have v0.2.4 version header."""
    import vaultwarden
    from pathlib import Path

    pkg_dir = Path(vaultwarden.__file__).resolve().parent
    modified = ["tools.py"]
    for name in modified:
        path = pkg_dir / name
        with open(path, 'r') as f:
            first_line = f.readline().strip()
        assert 'v0.2.4' in first_line, f"{name} missing version header: {first_line}"

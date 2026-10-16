# vaultwarden/tests/test_store_edit_v027.py — v0.2.7
"""Regression tests for the v0.2.7 store/edit BUGFIX release:

- encode_item() now base64-encodes the ENTIRE JSON object with the Python
  stdlib (root cause of `vaultwarden_store` exit 1: per-field double
  encoding produced a non-base64 blob that `bw create` rejected).
- create_item()/edit_item() pipe the encoded JSON via stdin (ARG_MAX-safe);
  edit_item() forwards the required item id positional argument.
- _build_item()/_apply_updates() no longer inject explicit
  match/passwordRevisionDate nulls into the payload.
"""
import base64
import json
import inspect
from unittest.mock import MagicMock

from vaultwarden import bw_cli
from vaultwarden.bw_cli import encode_item
from vaultwarden.tools import _build_item, _apply_updates


def test_encode_item_signature_simplified():
    """v0.2.7: encode_item takes only the item dict (no session/bw params)."""
    sig = inspect.signature(encode_item)
    assert list(sig.parameters.keys()) == ["item"], \
        f"Expected ['item'], got {list(sig.parameters.keys())}"


def test_encode_item_encodes_entire_json_with_stdlib_base64():
    """v0.2.7: encode_item produces standard base64 of the raw JSON."""
    item = {"type": 1, "name": "test",
            "login": {"username": "a", "password": "b"}}
    blob = encode_item(item)

    # Must be valid base64
    decoded = base64.b64decode(blob).decode("utf-8")
    parsed = json.loads(decoded)

    # Decoded JSON must contain RAW values (no per-field double-encoding)
    assert parsed["name"] == "test"
    assert parsed["login"]["username"] == "a"
    assert parsed["login"]["password"] == "b"


def test_encode_item_handles_unicode():
    """v0.2.7: UTF-8 round-trip must preserve non-ASCII characters."""
    item = {"type": 1, "name": "árvíztűrő tükörfúrógép",
            "login": {"username": "ü"} }
    blob = encode_item(item)
    decoded = base64.b64decode(blob).decode("utf-8")
    parsed = json.loads(decoded)
    assert parsed["name"] == "árvíztűrő tükörfúrógép"
    assert parsed["login"]["username"] == "ü"


def test_encode_item_drops_empty_values():
    """v0.2.7: None/empty values must be omitted from the payload."""
    item = {"type": 1, "name": "test", "notes": "", "folderId": None,
            "login": {"username": "a"}}
    parsed = json.loads(base64.b64decode(encode_item(item)).decode("utf-8"))
    assert "notes" not in parsed
    assert "folderId" not in parsed


def test_build_item_has_no_explicit_nulls():
    """v0.2.7: _build_item must not inject match/passwordRevisionDate nulls."""
    item = _build_item({"type": "login", "name": "x", "username": "u",
                        "password": "p", "uri": "https://example.com"})
    login = item["login"]
    assert "passwordRevisionDate" not in login
    assert login["uris"][0] == {"uri": "https://example.com"}
    assert "match" not in login["uris"][0]


def test_apply_updates_has_no_explicit_nulls():
    """v0.2.7: _apply_updates must not inject match/passwordRevisionDate nulls."""
    current = {"id": "abc", "name": "old", "login": {"username": "u"}}
    merged = _apply_updates(current, {"password": "newpw",
                                      "uri": "https://example.com"})
    login = merged["login"]
    assert "passwordRevisionDate" not in login
    assert login["uris"][0] == {"uri": "https://example.com"}
    assert "match" not in login["uris"][0]


def test_edit_item_signature_includes_item_id():
    """v0.2.7: bw_cli.edit_item must accept item_id as a positional arg."""
    sig = inspect.signature(bw_cli.BwCli.edit_item)
    params = list(sig.parameters.keys())
    assert "item_id" in params, f"edit_item params: {params}"


def test_auth_edit_item_passes_item_id():
    """v0.2.7: auth.edit_item must forward the item id to bw_cli.edit_item."""
    from vaultwarden.auth import AuthManager, AuthState
    bw = MagicMock()
    bw.edit_item.return_value = {"id": "abc"}

    config = MagicMock()
    config.session_timeout_seconds = 14400

    auth = AuthManager(bw, config, client_secret="cs", master_password="mp")
    auth._state = AuthState.UNLOCKED
    auth._session_key = "SESSION"

    auth.edit_item({"id": "abc", "name": "n"})
    args, _ = bw.edit_item.call_args
    assert args[1] == "abc", f"edit_item called with args: {args}"


def test_auth_create_item_uses_new_encode_item_signature():
    """v0.2.7: auth.create_item calls encode_item with only the item."""
    from vaultwarden.auth import AuthManager, AuthState
    bw = MagicMock()
    bw.create_item.return_value = {"id": "abc"}

    config = MagicMock()
    config.session_timeout_seconds = 14400

    auth = AuthManager(bw, config, client_secret="cs", master_password="mp")
    auth._state = AuthState.UNLOCKED
    auth._session_key = "SESSION"

    auth.create_item({"name": "n"})
    args, _ = bw.create_item.call_args
    # create_item(session, blob) — 2 args, blob is valid base64
    assert len(args) == 2
    base64.b64decode(args[1])  # must not raise

# vaultwarden/tests/test_ssh_key_v028.py — v0.2.8
"""Regression tests for v0.2.8: SSH key item support (Bitwarden type 5).

Covers:
- ITEM_TYPES / _TYPE_NUMBERS include "sshkey" -> 5
- VAULTWARDEN_STORE_SSH schema exists with the required parameters
- _build_item() produces the sshKey JSON structure
- h_store_ssh creates the item through auth.create_item (base64 blob check)
- privateKey is registered in SECRET_FIELDS so redaction covers it

SECURITY NOTE: Bitwarden/Vaultwarden stores SSH private keys WITHOUT
passphrase encryption inside the vault item; the plugin must never log them.
"""
import base64
import json
from unittest.mock import MagicMock

from vaultwarden import schemas
from vaultwarden.tools import _build_item, h_store_ssh


def test_item_types_includes_sshkey():
    """v0.2.8: ITEM_TYPES must include 'sshkey'."""
    assert "sshkey" in schemas.ITEM_TYPES
    assert schemas._TYPE_NUMBERS["sshkey"] == 5


def test_vaultwarden_store_ssh_schema_exists():
    """v0.2.8: VAULTWARDEN_STORE_SSH schema must be defined."""
    assert hasattr(schemas, "VAULTWARDEN_STORE_SSH")
    schema = schemas.VAULTWARDEN_STORE_SSH
    assert schema["name"] == "vaultwarden_store_ssh"
    assert "private_key" in schema["parameters"]["properties"]
    assert "public_key" in schema["parameters"]["properties"]
    assert "name" in schema["parameters"]["required"]
    assert "private_key" in schema["parameters"]["required"]


def test_build_item_sshkey():
    """v0.2.8: _build_item must handle sshkey type."""
    item = _build_item({
        "type": "sshkey",
        "name": "Test SSH Key",
        "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\ntest",
        "public_key": "ssh-ed25519 AAAA...",
        "key_fingerprint": "SHA256:xxx",
    })
    assert item["type"] == 5
    assert item["name"] == "Test SSH Key"
    assert "sshKey" in item
    assert item["sshKey"]["privateKey"] == "-----BEGIN OPENSSH PRIVATE KEY-----\ntest"
    assert item["sshKey"]["publicKey"] == "ssh-ed25519 AAAA..."
    assert item["sshKey"]["keyFingerprint"] == "SHA256:xxx"


def test_h_store_ssh_creates_item():
    """v0.2.8: h_store_ssh must create SSH key item via auth.create_item."""
    from vaultwarden.auth import AuthManager, AuthState
    from vaultwarden.tools import h_store_ssh

    bw = MagicMock()
    bw.create_item.return_value = {"id": "ssh-key-123"}

    config = MagicMock()
    config.session_timeout_seconds = 14400
    config.allow_write = True

    auth = AuthManager(bw, config, client_secret="cs", master_password="mp")
    auth._state = AuthState.UNLOCKED
    auth._session_key = "SESSION"
    auth._session_created_at = __import__("time").time()

    args = {
        "name": "Test SSH",
        "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\ntest",
        "public_key": "ssh-ed25519 AAAA...",
    }

    result = json.loads(h_store_ssh(args))
    assert result["created"] is True
    assert result["id"] == "ssh-key-123"

    # Verify create_item was called with correct structure
    args_call, _ = bw.create_item.call_args
    session, blob = args_call
    assert session == "SESSION"
    decoded = json.loads(base64.b64decode(blob).decode("utf-8"))
    assert decoded["type"] == 5
    assert decoded["name"] == "Test SSH"
    assert decoded["sshKey"]["privateKey"] == "-----BEGIN OPENSSH PRIVATE KEY-----\ntest"
    assert decoded["sshKey"]["publicKey"] == "ssh-ed25519 AAAA..."


def test_ssh_key_private_key_in_secret_fields():
    """v0.2.8: privateKey must be in SECRET_FIELDS for redaction."""
    assert "privateKey" in schemas.SECRET_FIELDS

"""Tests for secret_source.py — SecretSource adapter (v0.5.3)."""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from unittest.mock import Mock  # noqa: E402

from vaultwarden.secret_source import (  # noqa: E402
    VaultwardenSecretSource,
    register_secret_source,
)


class TestVaultwardenSecretSource:
    def test_valid_mapping_returns_secret(self):
        """Valid mapping should return the secret value."""
        auth = Mock()
        auth.get_item.return_value = {
            "id": "abc-123",
            "login": {"password": "secret123"}
        }
        config = Mock()

        source = VaultwardenSecretSource(
            auth, config,
            mappings=[{"item_id": "abc-123", "field": "password", "env": "DB_PASS"}]
        )

        result = source.get_secrets()
        assert result == {"DB_PASS": "secret123"}
        auth.get_item.assert_called_once_with("abc-123")

    def test_injected_secret_registered_with_redactor(self):
        """v0.5.3 security fix: injected values must reach RedactingFilter."""
        from vaultwarden.security import get_redacting_filter

        auth = Mock()
        auth.get_item.return_value = {
            "id": "abc-123",
            "login": {"password": "redact-me-value"}
        }
        config = Mock()

        source = VaultwardenSecretSource(
            auth, config,
            mappings=[{"item_id": "abc-123", "field": "password", "env": "DB_PASS"}]
        )

        filt = get_redacting_filter()
        registered: list[str] = []
        original_register = filt.register_secret

        def spy(value: str) -> None:
            registered.append(value)
            original_register(value)

        filt.register_secret = spy
        try:
            result = source.get_secrets()
        finally:
            del filt.register_secret  # restore the class-level method

        assert result == {"DB_PASS": "redact-me-value"}
        # v0.5.3 security fix: the value itself must be handed to the filter
        assert "redact-me-value" in registered
        # ...and therefore never appear raw in log records emitted afterwards
        assert "redact-me-value" not in filt.redact("password=redact-me-value")
        filt.forget_secret("redact-me-value")

    def test_missing_item_id_skips_mapping(self):
        """Mapping without item_id should be skipped."""
        auth = Mock()
        config = Mock()

        source = VaultwardenSecretSource(
            auth, config,
            mappings=[{"field": "password"}]  # missing item_id
        )

        result = source.get_secrets()
        assert result == {}
        auth.get_item.assert_not_called()

    def test_missing_field_defaults_to_password(self):
        """Mapping without field should default to 'password'."""
        auth = Mock()
        auth.get_item.return_value = {
            "id": "abc-123",
            "login": {"password": "secret123"}
        }
        config = Mock()

        source = VaultwardenSecretSource(
            auth, config,
            mappings=[{"item_id": "abc-123"}]  # missing field
        )

        result = source.get_secrets()
        assert result == {"VW_abc-123": "secret123"}

    def test_get_item_failure_returns_empty(self):
        """If get_item fails, should return empty dict (fail-safe)."""
        auth = Mock()
        auth.get_item.side_effect = Exception("Item not found")
        config = Mock()

        source = VaultwardenSecretSource(
            auth, config,
            mappings=[{"item_id": "abc-123", "field": "password"}]
        )

        result = source.get_secrets()
        assert result == {}

    def test_empty_value_not_included(self):
        """Empty secret values should not be included in result."""
        auth = Mock()
        auth.get_item.return_value = {
            "id": "abc-123",
            "login": {"password": ""}
        }
        config = Mock()

        source = VaultwardenSecretSource(
            auth, config,
            mappings=[{"item_id": "abc-123", "field": "password"}]
        )

        result = source.get_secrets()
        assert result == {}

    def test_custom_env_name_used(self):
        """Custom env name should be used as key."""
        auth = Mock()
        auth.get_item.return_value = {
            "id": "abc-123",
            "login": {"password": "secret123"}
        }
        config = Mock()

        source = VaultwardenSecretSource(
            auth, config,
            mappings=[{"item_id": "abc-123", "field": "password", "env": "MY_SECRET"}]
        )

        result = source.get_secrets()
        assert result == {"MY_SECRET": "secret123"}

    def test_name_method(self):
        """name() should return 'vaultwarden'."""
        auth = Mock()
        config = Mock()
        source = VaultwardenSecretSource(auth, config)
        assert source.name() == "vaultwarden"

    def test_non_dict_mapping_skipped(self):
        """Non-dict mapping entries should be skipped with a warning."""
        auth = Mock()
        config = Mock()
        source = VaultwardenSecretSource(
            auth, config,
            mappings=["not-a-dict", 42, {"item_id": "abc-123", "field": "password"}]
        )
        # only the one valid dict mapping survived validation
        assert len(source._mappings) == 1
        assert source._mappings[0]["item_id"] == "abc-123"
        source.get_secrets()
        auth.get_item.assert_called_once_with("abc-123")


class TestRegisterSecretSource:
    def test_register_with_register_secret_source(self):
        """Should call register_secret_source if available."""
        ctx = Mock()
        ctx.register_secret_source = Mock()
        auth = Mock()
        config = Mock()

        register_secret_source(ctx, auth, config, mappings=[])
        ctx.register_secret_source.assert_called_once()

    def test_register_with_add_secret_source(self):
        """Should fall back to add_secret_source if register_secret_source unavailable."""
        ctx = Mock(spec=["add_secret_source"])
        auth = Mock()
        config = Mock()

        register_secret_source(ctx, auth, config, mappings=[])
        ctx.add_secret_source.assert_called_once()

    def test_register_no_registrar_available(self):
        """Should log warning if no registrar available."""
        ctx = Mock(spec=[])
        auth = Mock()
        config = Mock()

        # Should not raise, just log warning
        register_secret_source(ctx, auth, config, mappings=[])

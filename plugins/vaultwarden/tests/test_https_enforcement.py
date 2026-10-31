"""AUD-01 (v0.6.9) Phase 1: HTTPS enforcement for server_url.

PluginConfig.validate() must fail closed on any non-https scheme. The
explicit ``allow_insecure_http`` override permits ONLY http:// — every
other scheme (ftp/file/ws/missing/empty) is rejected regardless of the
flag. The override WARNING must contain only the hostname — never
credentials, paths, or query strings.
"""
from __future__ import annotations

import logging

import pytest

from vaultwarden.config import load_config
from vaultwarden.errors import ConfigError

CONFIG_LOG = "hermes.plugins.vaultwarden.config"


class FakePluginContext:
    """Simulates Hermes PluginContext.get_config() behaviour."""

    def __init__(self, settings: dict):
        self._settings = settings

    def get_config(self, key: str, default=None):
        return self._settings.get(key, default)


def _cfg(**overrides) -> "object":
    settings = {
        "enabled": True,
        "server_url": "https://vault.example.com",
        "client_id": "user.abc-123",
    }
    settings.update(overrides)
    return load_config(FakePluginContext(settings), env={})


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_https_url_accepted():
    cfg = _cfg(server_url="https://vault.example.com")
    cfg.validate()  # must not raise


def test_https_url_with_path_and_port_accepted():
    cfg = _cfg(server_url="https://vault.example.com:8443/some/path")
    cfg.validate()  # must not raise


# ---------------------------------------------------------------------------
# http:// without the override -> rejected
# ---------------------------------------------------------------------------

def test_http_without_override_rejected():
    cfg = _cfg(server_url="http://vault.example.com")
    with pytest.raises(ConfigError):
        cfg.validate()


def test_default_allow_insecure_http_is_false():
    # Fail-closed: absent flag resolves to False, never True.
    assert _cfg().allow_insecure_http is False


# ---------------------------------------------------------------------------
# http:// WITH the override -> accepted + sanitized WARNING
# ---------------------------------------------------------------------------

def test_http_with_override_accepted(caplog):
    cfg = _cfg(server_url="http://localhost:8080", allow_insecure_http=True)
    with caplog.at_level(logging.WARNING, logger=CONFIG_LOG):
        cfg.validate()  # must not raise
    warnings = [r for r in caplog.records
                if r.levelno == logging.WARNING and "insecure scheme" in r.getMessage()]
    assert len(warnings) == 1


def test_http_override_warning_contains_hostname_only(caplog):
    cfg = _cfg(server_url="http://alice:sup3rs3cret@vault.example.com/"
                        "path?token=SECRETQUERYVALUE",
               allow_insecure_http=True)
    with caplog.at_level(logging.WARNING, logger=CONFIG_LOG):
        cfg.validate()
    msg = next(r.getMessage() for r in caplog.records
               if r.levelno == logging.WARNING and "insecure scheme" in r.getMessage())
    # Hostname is present; credentials / userinfo / path / query are NOT.
    assert "vault.example.com" in msg
    for leak in ("alice", "sup3rs3cret", "SECRETQUERYVALUE", "token", "/path"):
        assert leak not in msg


# ---------------------------------------------------------------------------
# Non-http schemes are ALWAYS rejected, even with the override
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "ftp://vault.example.com",
    "file:///etc/passwd",
    "ws://vault.example.com",
    "wss://vault.example.com",
])
def test_unsupported_schemes_rejected_without_override(url):
    cfg = _cfg(server_url=url)
    with pytest.raises(ConfigError):
        cfg.validate()


@pytest.mark.parametrize("url", [
    "ftp://vault.example.com",
    "file:///etc/passwd",
    "ws://vault.example.com",
])
def test_unsupported_schemes_rejected_even_with_override(url):
    # allow_insecure_http permits ONLY http:// — never ftp/file/ws.
    cfg = _cfg(server_url=url, allow_insecure_http=True)
    with pytest.raises(ConfigError):
        cfg.validate()


# ---------------------------------------------------------------------------
# Missing / empty scheme -> rejected (fail-closed on ambiguity)
# ---------------------------------------------------------------------------

def test_missing_scheme_rejected():
    cfg = _cfg(server_url="vault.example.com")
    with pytest.raises(ConfigError):
        cfg.validate()


def test_missing_scheme_rejected_even_with_override():
    cfg = _cfg(server_url="vault.example.com", allow_insecure_http=True)
    with pytest.raises(ConfigError):
        cfg.validate()


def test_empty_server_url_rejected():
    cfg = _cfg(server_url="")
    with pytest.raises(ConfigError):
        cfg.validate()


# ---------------------------------------------------------------------------
# Scheme case-insensitivity & runtime-log hygiene
# ---------------------------------------------------------------------------

def test_uppercase_https_scheme_accepted():
    # urlparse lowercases the scheme portion after netloc parsing; an
    # all-caps scheme ("HTTPS://") must still be accepted.
    cfg = _cfg(server_url="HTTPS://vault.example.com")
    cfg.validate()  # must not raise


def test_no_secrets_or_audit_codes_in_runtime_logs(caplog):
    # Rejections raise ConfigError (exception message, not a log record);
    # the only runtime log line here is the sanitized http WARNING, which
    # must not leak audit codes or version numbers.
    cfg = _cfg(server_url="http://vault.example.com", allow_insecure_http=True)
    with caplog.at_level(logging.DEBUG, logger=CONFIG_LOG):
        cfg.validate()
    for r in caplog.records:
        msg = r.getMessage()
        assert "AUD-" not in msg
        assert "v0.6" not in msg

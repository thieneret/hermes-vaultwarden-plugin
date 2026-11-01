"""AUD-01 (v0.6.9) Phase 1 + HVA-02 (v0.7.1): server_url validation.

PluginConfig.validate() must fail closed on any non-https scheme. The
explicit ``allow_insecure_http`` override permits ONLY http:// — every
other scheme (ftp/file/ws/missing/empty) is rejected regardless of the
flag. The override WARNING must contain only the hostname — never
credentials, paths, or query strings.

HVA-02: URLs containing user-info (username/password), query parameters,
or fragments are rejected outright (fail-closed). The path component
remains allowed, and log output for any server URL is sanitized down to
scheme://host[:port].
"""
from __future__ import annotations

import logging

import pytest

from vaultwarden.config import _sanitize_url_for_logging, load_config
from vaultwarden.errors import ConfigError
from vaultwarden.tests.conftest import RecordingCtx

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
    # HVA-02 (v0.7.1) UPDATE: URLs with user-info / query components are now
    # REJECTED outright by validate(), so they can never reach any later log
    # line. The AUD-01 warning itself still contains ONLY the hostname —
    # verified here with a clean override URL plus the sanitizer helper for
    # the credential-bearing case.
    cfg = _cfg(server_url="http://vault.example.com", allow_insecure_http=True)
    with caplog.at_level(logging.WARNING, logger=CONFIG_LOG):
        cfg.validate()  # must not raise
    msg = next(r.getMessage() for r in caplog.records
               if r.levelno == logging.WARNING and "insecure scheme" in r.getMessage())
    assert "vault.example.com" in msg
    for leak in ("alice", "sup3rs3cret", "SECRETQUERYVALUE", "token", "/path"):
        assert leak not in msg

    # A credential-bearing URL is now fail-closed rejected (ConfigError —
    # exception message, never a log record), and the sanitizer would strip
    # every sensitive component if such a URL ever reached a log statement.
    cfg_bad = _cfg(server_url="http://alice:sup3rs3cret@vault.example.com/"
                              "path?token=SECRETQUERYVALUE",
                   allow_insecure_http=True)
    with pytest.raises(ConfigError, match="must not contain user-info"):
        cfg_bad.validate()
    sanitized = _sanitize_url_for_logging(
        "http://alice:sup3rs3cret@vault.example.com/path?token=SECRETQUERYVALUE")
    assert sanitized == "http://vault.example.com"


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


# ---------------------------------------------------------------------------
# HVA-02 (v0.7.1): reject user-info / query / fragment components
# ---------------------------------------------------------------------------

def test_user_info_rejected():
    cfg = _cfg(server_url="https://user:pass@host")
    with pytest.raises(ConfigError, match="must not contain user-info"):
        cfg.validate()


def test_username_only_rejected():
    cfg = _cfg(server_url="https://user@host")
    with pytest.raises(ConfigError, match="must not contain user-info"):
        cfg.validate()


def test_query_rejected():
    cfg = _cfg(server_url="https://host?token=abc")
    with pytest.raises(ConfigError, match="must not contain query parameters"):
        cfg.validate()


def test_fragment_rejected():
    cfg = _cfg(server_url="https://host#section")
    with pytest.raises(ConfigError, match="must not contain fragments"):
        cfg.validate()


def test_path_accepted():
    # The path component is NOT prohibited — plain and ported URLs work.
    _cfg(server_url="https://host:8443/path").validate()  # must not raise
    _cfg(server_url="https://host:8443").validate()       # must not raise
    _cfg(server_url="https://host").validate()            # must not raise


def test_http_override_still_rejects_user_info():
    # Fail-closed: even with allow_insecure_http=true, the HVA-02 component
    # checks apply after the scheme check.
    cfg = _cfg(server_url="http://user:pass@host", allow_insecure_http=True)
    with pytest.raises(ConfigError, match="must not contain user-info"):
        cfg.validate()


# ---------------------------------------------------------------------------
# HVA-02 (v0.7.1): server_url_sanitized accessor — defence-in-depth on the
# display/log path.  The canonical ``server_url`` stays verbatim (functional
# consumers need the exact URL); ``server_url_sanitized`` is what status and
# diagnostic payloads must expose.
# ---------------------------------------------------------------------------

def test_server_url_property_is_verbatim_canonical_value():
    cfg = _cfg(server_url="https://vault.example.com/path")
    assert cfg.server_url == "https://vault.example.com/path"


def test_server_url_sanitized_strips_sensitive_components():
    # A hostile value that somehow survives validate() (e.g. the config
    # section mutated after validation) must still be reduced to
    # scheme://host[:port] by the sanitized accessor.
    cfg = _cfg(server_url="https://vault.example.com")
    cfg.section["server_url"] = (
        "https://alice:sup3rs3cret@vault.example.com/x?token=S#frag")
    assert cfg.server_url_sanitized == "https://vault.example.com"
    for leak in ("alice", "sup3rs3cret", "token", "#frag", "/x"):
        assert leak not in cfg.server_url_sanitized


def test_server_url_sanitized_keeps_nondefault_port():
    cfg = _cfg(server_url="https://vault.example.com:8443/path")
    assert cfg.server_url_sanitized == "https://vault.example.com:8443"


def test_server_url_sanitized_empty_when_unparseable():
    # Host-less / unparseable values never reach a logger through this
    # accessor — it degrades to the empty string instead of "<invalid>".
    cfg = _cfg(server_url="https://vault.example.com")
    cfg.section["server_url"] = "not a url at all"
    assert cfg.server_url_sanitized == ""


def test_server_url_sanitized_empty_stays_empty():
    cfg = _cfg(server_url="")
    assert cfg.server_url_sanitized == ""


# ---------------------------------------------------------------------------
# HVA-02 (v0.7.1): log sanitization — credentials never appear in logs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url,expected", [
    ("https://alice:sup3rs3cret@vault.example.com/p?token=S#frag",
     "https://vault.example.com"),
    ("https://host:8443/path", "https://host:8443"),
    ("https://host:443", "https://host"),          # default port dropped
    ("http://host:80", "http://host"),            # default port dropped
    ("http://host:8080", "http://host:8080"),
    ("not-a-url", "<invalid>"),                   # no hostname at all
])
def test_sanitize_url_for_logging(url, expected):
    assert _sanitize_url_for_logging(url) == expected


def test_log_sanitization_strips_credentials(tmp_path, monkeypatch,
                                              fake_bw):
    # HVA-02 defence-in-depth: register() sanitizes the server URL in its
    # ACTIVE log line down to scheme://host[:port]. The config section is
    # patched AFTER validate() runs (the real lifecycle validates first and
    # would fail closed on this URL), so the sanitizer is exercised as the
    # last line of defence on the log path.
    #
    # Log capture is wired directly onto the plugin logger hierarchy with an
    # explicit handler instead of relying on pytest's caplog fixture: the
    # plugin's get_logger() attaches a fallback StreamHandler when the root
    # logger has no handlers yet, which detaches records from propagation
    # and makes caplog ordering-dependent (flaky). A dedicated handler on
    # the 'hermes.plugins.vaultwarden' parent is hermetic and deterministic.
    import vaultwarden
    from vaultwarden.config import PluginConfig

    captured: list[str] = []

    class _CaptureHandler(logging.Handler):
        def emit(self, record):
            try:
                captured.append(record.getMessage())
            except Exception:  # pragma: no cover - capture must never raise
                pass

    plugin_logger = logging.getLogger("hermes.plugins.vaultwarden")
    handler = _CaptureHandler(level=logging.DEBUG)
    orig_level = plugin_logger.level
    orig_propagate = plugin_logger.propagate
    plugin_logger.addHandler(handler)
    plugin_logger.setLevel(logging.DEBUG)
    plugin_logger.propagate = False

    plugdir = tmp_path / "plugins" / "vaultwarden"
    plugdir.mkdir(parents=True, exist_ok=True)
    secrets_file = plugdir / "secrets.yaml"
    secrets_file.write_text("client_secret: cs-secret\nmaster_password: mp-secret\n")
    secrets_file.chmod(0o600)
    monkeypatch.delenv("BW_CLI_PATH", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("TERMINAL_ENV", "docker")  # sandboxed backend

    settings = {
        "enabled": True,
        "server_url": "https://vault.example.com",
        "client_id": "user.11111111-2222-3333-4444-555555555555",
        "bw_cli_path": fake_bw,
    }

    ctx = RecordingCtx(settings)
    orig_validate = PluginConfig.validate

    def _patched_validate(self):
        orig_validate(self)
        # Simulate a hostile value surviving an earlier layer: user-info +
        # path + query + fragment appended after validation succeeded.
        self.section["server_url"] = (
            "https://alice:sup3rs3cret@vault.example.com/x?token=S#frag")

    monkeypatch.setattr(PluginConfig, "validate", _patched_validate)

    try:
        ok = vaultwarden.register(ctx)
    finally:
        monkeypatch.setattr(PluginConfig, "validate", orig_validate)
        plugin_logger.removeHandler(handler)
        plugin_logger.setLevel(orig_level)
        plugin_logger.propagate = orig_propagate
    assert ok is True, "registration must succeed; ACTIVE line is emitted"

    active = [msg for msg in captured if "plugin ACTIVE" in msg]
    assert active, "expected the ACTIVE log line to be emitted"
    joined = "\n".join(active)
    assert "https://vault.example.com" in joined
    for leak in ("alice", "sup3rs3cret", "token", "#frag", "/x"):
        assert leak not in joined

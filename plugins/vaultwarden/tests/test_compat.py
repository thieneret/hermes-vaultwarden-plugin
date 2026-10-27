"""Unit tests for the centralized compatibility layer (VWP-17, compat.py).

Covers every function in vaultwarden.compat:
  - Hermes API capability detection: register_tool_compat (inspect.signature)
    / register_hook_if_available (hasattr) — VWP-06
  - Config extraction: extract_plugin_section — native get_config() ONLY
    (VWP-05: fallback layers removed)
  - bw CLI compatibility: parse_bw_version / require_min_bw_version
  - Exception code extraction: get_error_code
Plus regression guards proving __init__.py / config.py / bw_cli.py / auth.py
now delegate to these functions instead of carrying inline fallback code.
"""
from __future__ import annotations

import logging

import pytest

from vaultwarden import compat, errors

# ── helpers ──────────────────────────────────────────────────────────

class _CtxWithCheckFn:
    """New-style context: register_tool accepts check_fn."""

    def __init__(self):
        self.calls: list[dict] = []

    def register_tool(self, *, name, toolset, schema, handler, check_fn=None):
        self.calls.append({"name": name, "toolset": toolset, "schema": schema,
                           "handler": handler, "check_fn": check_fn})


class _CtxWithoutCheckFn:
    """Old-style context: register_tool has NO check_fn parameter —
    inspect.signature() must detect this and omit the kwarg entirely."""

    def __init__(self):
        self.calls: list[dict] = []

    def register_tool(self, *, name, toolset, schema, handler):
        self.calls.append({"name": name, "toolset": toolset, "schema": schema,
                           "handler": handler})


class _CtxWithHooks:
    def __init__(self):
        self.hooks: list[tuple[str, object]] = []

    def register_hook(self, kind, fn):
        self.hooks.append((kind, fn))


class _CtxWithoutHooks:
    """Context lacking register_hook entirely (attribute access raises)."""


_SCHEMA = {"name": "vaultwarden_demo", "parameters": {}}


def _handler(args, **kw):  # pragma: no cover - never invoked
    return "ok"


# ── register_tool_compat (VWP-06: inspect.signature capability detection) ──

def test_register_tool_compat_with_check_fn():
    """inspect.signature() sees check_fn -> the kwarg IS passed."""
    ctx = _CtxWithCheckFn()
    check = lambda: True  # noqa: E731
    compat.register_tool_compat(ctx, name="vaultwarden_demo",
                                toolset="vaultwarden", schema=_SCHEMA,
                                handler=_handler, check_fn=check)
    assert len(ctx.calls) == 1
    call = ctx.calls[0]
    assert call["name"] == "vaultwarden_demo"
    assert call["toolset"] == "vaultwarden"
    assert call["check_fn"] is check


def test_register_tool_compat_without_check_fn():
    """inspect.signature() sees NO check_fn param -> kwarg omitted entirely
    (the old-signature call never receives it)."""
    ctx = _CtxWithoutCheckFn()
    compat.register_tool_compat(ctx, name="vaultwarden_demo",
                                toolset="vaultwarden", schema=_SCHEMA,
                                handler=_handler, check_fn=lambda: True)
    assert len(ctx.calls) == 1
    assert "check_fn" not in ctx.calls[0]


def test_register_tool_compat_missing_api_fails_closed():
    """VWP-06 fail-closed: no callable register_tool -> RuntimeError."""
    class NoRegisterTool:
        pass

    with pytest.raises(RuntimeError, match="register_tool"):
        compat.register_tool_compat(NoRegisterTool(), name="x",
                                    toolset="vaultwarden", schema=_SCHEMA,
                                    handler=_handler)

    with pytest.raises(RuntimeError, match="register_tool"):
        compat.register_tool_compat(object(), name="x",
                                    toolset="vaultwarden", schema=_SCHEMA,
                                    handler=_handler)


# ── register_hook_if_available (VWP-06: hasattr capability detection) ──

def test_register_hook_if_available_success():
    ctx = _CtxWithHooks()
    fn = lambda *a, **kw: None  # noqa: E731
    assert compat.register_hook_if_available(ctx, "post_tool_call", fn) is True
    assert ctx.hooks == [("post_tool_call", fn)]


def test_register_hook_if_available_missing(caplog):
    """Context without register_hook: warning logged, False returned, no raise."""
    ctx = _CtxWithoutHooks()
    with caplog.at_level(logging.WARNING,
                         logger="hermes.plugins.vaultwarden.compat"):
        assert compat.register_hook_if_available(ctx, "on_session_end",
                                                 lambda *a: None) is False
    assert any("register_hook" in r.getMessage() for r in caplog.records)


def test_register_hook_if_available_failure_reported(caplog):
    """VWP-06 explicit failure reporting: register_hook raising -> error log,
    False returned, no exception propagates."""
    class ExplodingCtx:
        def register_hook(self, kind, fn):
            raise RuntimeError("hook registry broken")

    with caplog.at_level(logging.ERROR,
                         logger="hermes.plugins.vaultwarden.compat"):
        assert compat.register_hook_if_available(
            ExplodingCtx(), "post_tool_call", lambda *a: None) is False
    assert any("register_hook" in r.getMessage() for r in caplog.records)


# ── extract_plugin_section (VWP-05: native API only, fallbacks removed) ──

class _RecordingGetConfigCtx:
    """get_config() records every key it is asked for and returns values
    from a fixed settings dict."""

    def __init__(self, settings=None):
        self._settings = dict(settings or {})
        self.requested: list[str] = []

    def get_config(self, key, default=None):
        self.requested.append(key)
        return self._settings.get(key, default)


class _EmptyGetConfigCtx:
    """get_config() exists but yields nothing."""

    def get_config(self, key, default=None):
        return default


def test_extract_plugin_section_native_only():
    """The function calls ctx.get_config() for EVERY default key and
    assembles only the non-None values into the result dict."""
    from vaultwarden.config import _DEFAULTS

    ctx = _RecordingGetConfigCtx({
        "enabled": True,
        "server_url": "https://native-only",
        "bw_cli_path": "/usr/local/bin/bw",
    })
    result = compat.extract_plugin_section(ctx)
    assert set(ctx.requested) == set(_DEFAULTS)
    assert result == {
        "enabled": True,
        "server_url": "https://native-only",
        "bw_cli_path": "/usr/local/bin/bw",
    }


def test_extract_plugin_section_empty_and_none_sources():
    """Empty native results and None sources yield {} — the caller decides
    fail-closed. No fallback file/env reads happen any more (VWP-05)."""
    assert compat.extract_plugin_section(_EmptyGetConfigCtx()) == {}
    assert compat.extract_plugin_section(None) == {}


def test_extract_plugin_section_no_get_config(monkeypatch, caplog):
    """Source without a callable get_config: warning + empty dict. If any
    fallback remained, hermes_cli / HERMES_HOME would be consulted — they
    are not (VWP-05)."""
    monkeypatch.delenv("HERMES_HOME", raising=False)
    with caplog.at_level(logging.WARNING,
                         logger="hermes.plugins.vaultwarden.compat"):
        assert compat.extract_plugin_section(object()) == {}
    assert any("get_config" in r.getMessage() for r in caplog.records)


def test_extract_plugin_section_get_config_raises_is_tolerated():
    """A raising get_config(key) is skipped per-key; other keys still work."""
    class PartiallyBrokenCtx:
        def get_config(self, key, default=None):
            if key == "server_url":
                raise RuntimeError("no manifest")
            return {"client_id": "user.aaaa"}.get(key, default)

    result = compat.extract_plugin_section(PartiallyBrokenCtx())
    assert result == {"client_id": "user.aaaa"}


def test_compat_has_no_fallback_symbols():
    """VWP-05 regression guard: safe_load_yaml and the read_user_config_raw
    fallback are gone from compat.py."""
    assert not hasattr(compat, "safe_load_yaml")
    import inspect as _inspect

    src = _inspect.getsource(compat)
    assert "read_user_config_raw()" not in src
    assert "from hermes_cli.config import" not in src


# ── parse_bw_version / require_min_bw_version ────────────────────────

def test_parse_bw_version_valid():
    assert compat.parse_bw_version("2026.9.1") == (2026, 9, 1)
    assert compat.parse_bw_version(" 2026.9.1 \n") == (2026, 9, 1)
    assert compat.parse_bw_version("2026.10") == (2026, 10)


def test_parse_bw_version_invalid():
    with pytest.raises(ValueError):
        compat.parse_bw_version("2026")            # too few components
    with pytest.raises(ValueError):
        compat.parse_bw_version("")                # empty output
    with pytest.raises(ValueError):
        compat.parse_bw_version("not-a-version")   # non-numeric
    with pytest.raises(ValueError):
        compat.parse_bw_version("2026.9.1-nightly")  # int('1-nightly') fails


def test_require_min_bw_version_pass():
    compat.require_min_bw_version("2026.9.1")     # exactly the minimum
    compat.require_min_bw_version("2027.1.0")     # newer


def test_require_min_bw_version_fail():
    with pytest.raises(errors.UnsupportedBwVersionError) as ei:
        compat.require_min_bw_version("2026.8.0")
    assert ei.value.code == "UNSUPPORTED_BW_VERSION"
    assert "below the minimum supported version 2026.9.1" in ei.value.message


def test_min_bw_version_constant():
    assert compat.MIN_BW_VERSION == (2026, 9, 1)


# ── get_error_code ───────────────────────────────────────────────────

def test_get_error_code_vaultwarden_error():
    exc = errors.ConfigError("boom")
    assert compat.get_error_code(exc) == "CONFIG_ERROR"


def test_get_error_code_generic_exception():
    assert compat.get_error_code(RuntimeError("x")) == "RuntimeError"


# ── VWP-17 integration guards: callers must delegate to compat.py ────

def test_bw_cli_delegates_to_compat():
    """bw_cli keeps the _MIN_BW_VERSION re-export AND uses compat for parsing."""
    import inspect

    import vaultwarden.bw_cli as bw_cli_mod
    assert bw_cli_mod._MIN_BW_VERSION is compat.MIN_BW_VERSION
    src = inspect.getsource(bw_cli_mod.BwCli._check_version)
    assert "compat.parse_bw_version" in src
    assert "compat.require_min_bw_version" in src


def test_init_and_config_and_auth_delegate_to_compat():
    """No scattered inline fallbacks remain in the refactored modules."""
    import inspect

    import vaultwarden as vw_pkg
    import vaultwarden.auth as auth_mod
    import vaultwarden.config as config_mod
    init_src = inspect.getsource(vw_pkg)
    assert "compat.register_tool_compat" in init_src
    assert "compat.register_hook_if_available" in init_src
    assert "compat.get_error_code" in init_src
    config_src = inspect.getsource(config_mod)
    assert "compat.extract_plugin_section" in config_src
    auth_src = inspect.getsource(auth_mod)
    assert "compat.get_error_code" in auth_src
    assert 'getattr(exc, "code"' not in auth_src
    assert 'getattr(exc, "code"' not in init_src


def test_register_tool_compat_used_by_register(fake_bw, appdata,
                                               hermes_home_with_secrets,
                                               monkeypatch):
    """End-to-end: register() through compat still lands check_fn on the
    RecordingCtx (signature-introspection path) — behaviour unchanged by
    VWP-05/VWP-06."""
    from vaultwarden.tests.conftest import RecordingCtx

    monkeypatch.setenv("BW_TEST_VERSION", "2026.9.1")
    ctx = RecordingCtx(settings={
        "enabled": True,
        "server_url": "https://vault.example.com",
        "client_id": "user.11111111-2222-3333-4444-555555555555",
        "bw_cli_path": fake_bw,
    })
    import vaultwarden
    assert vaultwarden.register(ctx) is True
    assert len(ctx.tools) == 12
    assert all(t["check_fn"] is not None for t in ctx.tools)
    assert [h[0] for h in ctx.hooks] == ["post_tool_call", "on_session_end"]


def test_config_native_only_through_compat(monkeypatch, tmp_path):
    """VWP-05 regression: a context whose get_config() raises now yields
    PURE DEFAULTS — the former direct-YAML FALLBACK is gone, so the
    config.yaml file next door is NEVER read."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        "plugins:\n  entries:\n    vaultwarden:\n      settings:\n"
        "        server_url: https://should-not-load\n", encoding="utf-8")

    class _BrokenCtx:
        """get_config present but raises for every key -> empty section."""

        def get_config(self, key, default=None):
            raise RuntimeError("no manifest")

    from vaultwarden.config import load_config
    cfg_obj = load_config(_BrokenCtx(), env={})
    assert cfg_obj.server_url == ""       # default, NOT the YAML value
    assert cfg_obj.enabled is False


def test_plugin_error_class_exists():
    """CHANGE 6 guard: errors.PluginError present with PLUGIN_ERROR taxonomy."""
    assert issubclass(errors.PluginError, errors.VaultwardenError)
    assert errors.PluginError.code == "PLUGIN_ERROR"
    exc = errors.PluginError("boom")
    assert exc.to_dict()["error_code"] == "PLUGIN_ERROR"

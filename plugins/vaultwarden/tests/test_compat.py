"""Unit tests for the centralized compatibility layer (VWP-17, compat.py).

Covers every function in vaultwarden.compat:
  - Hermes API fallbacks: register_tool_compat / register_hook_if_available
  - Config-loading fallbacks: extract_plugin_section (layers 1-3)
  - YAML import fallback: safe_load_yaml (PyYAML + stdlib parser)
  - bw CLI compatibility: parse_bw_version / require_min_bw_version
  - Exception code extraction: get_error_code
Plus regression guards proving __init__.py / config.py / bw_cli.py / auth.py
now delegate to these functions instead of carrying inline fallback code.
"""
from __future__ import annotations

import builtins
import logging
import sys

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
    """Old-style context: register_tool has NO check_fn parameter — passing
    it raises TypeError, exactly like the real old Hermes API."""

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


# ── register_tool_compat ─────────────────────────────────────────────

def test_register_tool_compat_with_check_fn():
    """New signature is TRIED FIRST: check_fn reaches the context."""
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
    """Old signature (no check_fn kwarg) -> TypeError -> graceful retry."""
    ctx = _CtxWithoutCheckFn()
    compat.register_tool_compat(ctx, name="vaultwarden_demo",
                                toolset="vaultwarden", schema=_SCHEMA,
                                handler=_handler, check_fn=lambda: True)
    assert len(ctx.calls) == 1
    assert "check_fn" not in ctx.calls[0]


# ── register_hook_if_available ───────────────────────────────────────

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


# ── extract_plugin_section ───────────────────────────────────────────

class _EmptyGetConfigCtx:
    """get_config() exists but yields nothing (layer 1 handled by config.py)."""

    def get_config(self, key, default=None):
        return default


def test_extract_plugin_section_layer1(monkeypatch):
    """A PluginContext exposing get_config(): compat itself contributes no
    data (config.py owns that path) and both fallback layers are inert ->
    empty dict signals 'try next layer'."""
    monkeypatch.delitem(sys.modules, "hermes_cli", raising=False)
    monkeypatch.delitem(sys.modules, "hermes_cli.config", raising=False)
    monkeypatch.setenv("HERMES_HOME", "/nonexistent-hermes-home-vwp17")
    result = compat.extract_plugin_section(_EmptyGetConfigCtx())
    assert result == {}
    # None source short-circuits before any layer runs.
    assert compat.extract_plugin_section(None) == {}


def test_extract_plugin_section_layer2(monkeypatch):
    """read_user_config_raw() fallback returns the plugin settings section."""
    import types

    mod = types.ModuleType("hermes_cli.config")
    mod.read_user_config_raw = lambda: {
        "plugins": {"entries": {"vaultwarden": {
            "settings": {"server_url": "https://from-layer2"}}}}}
    pkg = types.ModuleType("hermes_cli")
    pkg.config = mod
    monkeypatch.setitem(sys.modules, "hermes_cli", pkg)
    monkeypatch.setitem(sys.modules, "hermes_cli.config", mod)
    try:
        section = compat.extract_plugin_section(_EmptyGetConfigCtx(),
                                                plugin_id="vaultwarden")
        assert section == {"server_url": "https://from-layer2"}
    finally:
        monkeypatch.delitem(sys.modules, "hermes_cli", raising=False)
        monkeypatch.delitem(sys.modules, "hermes_cli.config", raising=False)


def test_extract_plugin_section_layer3(monkeypatch, tmp_path):
    """Direct HERMES_HOME/config.yaml read fallback."""
    monkeypatch.delitem(sys.modules, "hermes_cli", raising=False)
    monkeypatch.delitem(sys.modules, "hermes_cli.config", raising=False)
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "plugins:\n  entries:\n    vaultwarden:\n      settings:\n"
        "        server_url: https://from-layer3\n"
        "        client_id: user.aaaa\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    section = compat.extract_plugin_section(_EmptyGetConfigCtx())
    assert section.get("server_url") == "https://from-layer3"
    assert section.get("client_id") == "user.aaaa"


# ── safe_load_yaml ───────────────────────────────────────────────────

_YAML_TEXT = ("plugins:\n  entries:\n    vaultwarden:\n      settings:\n"
              "        enabled: true\n")


def test_safe_load_yaml_with_pyyaml(tmp_path):
    """PyYAML present -> yaml.safe_load path."""
    pytest.importorskip("yaml")
    f = tmp_path / "config.yaml"
    f.write_text(_YAML_TEXT, encoding="utf-8")
    data = compat.safe_load_yaml(f)
    assert isinstance(data, dict)
    entry = data["plugins"]["entries"]["vaultwarden"]
    assert entry["settings"]["enabled"] is True


def test_safe_load_yaml_without_pyyaml(monkeypatch, tmp_path):
    """PyYAML absent -> stdlib parser fallback via secrets._load_yaml_mapping."""
    # sys.modules["yaml"] = None makes ``import yaml`` raise ImportError even
    # when PyYAML IS installed in the interpreter running the tests.
    monkeypatch.setitem(sys.modules, "yaml", None)
    f = tmp_path / "config.yaml"
    f.write_text(_YAML_TEXT, encoding="utf-8")
    data = compat.safe_load_yaml(f)
    assert isinstance(data, dict)
    entry = data["plugins"]["entries"]["vaultwarden"]
    # stdlib parser yields string scalars ("true", not True)
    assert entry["settings"]["enabled"] == "true"


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
    RecordingCtx (new-signature path) — behaviour unchanged by VWP-17."""
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


def _force_no_yaml(monkeypatch):
    """Make ``import yaml`` fail inside compat.py regardless of environment."""
    monkeypatch.setitem(sys.modules, "yaml", None)


def test_config_fallback_still_works_through_compat(monkeypatch, tmp_path):
    """Regression: config.py's FALLBACK 2 now flows through
    compat.extract_plugin_section + compat.safe_load_yaml — verify the
    direct-YAML arm end to end WITHOUT PyYAML (stdlib parser path)."""
    _force_no_yaml(monkeypatch)
    monkeypatch.delitem(sys.modules, "hermes_cli", raising=False)
    monkeypatch.delitem(sys.modules, "hermes_cli.config", raising=False)
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "plugins:\n  entries:\n    vaultwarden:\n      settings:\n"
        "        server_url: https://via-compat-fallback\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))

    class _BrokenCtx:
        """get_config present but raises -> layer 1 empty -> fallback layers."""

        def get_config(self, key, default=None):
            raise RuntimeError("no manifest")

    from vaultwarden.config import load_config
    cfg_obj = load_config(_BrokenCtx(), env={})
    assert cfg_obj.server_url == "https://via-compat-fallback"


def test_plugin_error_class_exists():
    """CHANGE 6 guard: errors.PluginError present with PLUGIN_ERROR taxonomy."""
    assert issubclass(errors.PluginError, errors.VaultwardenError)
    assert errors.PluginError.code == "PLUGIN_ERROR"
    exc = errors.PluginError("boom")
    assert exc.to_dict()["error_code"] == "PLUGIN_ERROR"

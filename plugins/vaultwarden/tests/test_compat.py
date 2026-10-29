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
import sys

import pytest

import vaultwarden
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
    assert [h[0] for h in ctx.hooks] == ["transform_tool_result", "post_tool_call",
                       "on_session_end"]


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


# ── VWP-18 (v0.6.0 hotfix): hermes_cli.plugins.VALID_HOOKS detection ──


class _BareCtx:
    """Minimal stand-in for the production Hermes PluginContext.

    Current host builds expose ONLY register_hook() and do NOT mirror hook
    support as a context attribute or a supported_hooks collection — the
    capability lives exclusively in the module-level VALID_HOOKS registry.
    """

    def __init__(self):
        self.hooks: list[tuple[str, object]] = []

    def register_hook(self, kind, fn):
        self.hooks.append((kind, fn))


def _install_fake_hermes_cli(monkeypatch, valid_hooks):
    import types

    plugins_mod = types.ModuleType("hermes_cli.plugins")
    plugins_mod.VALID_HOOKS = valid_hooks
    cli_mod = types.ModuleType("hermes_cli")
    cli_mod.plugins = plugins_mod
    monkeypatch.setitem(sys.modules, "hermes_cli", cli_mod)
    monkeypatch.setitem(sys.modules, "hermes_cli.plugins", plugins_mod)


PRODUCTION_VALID_HOOKS = [
    "agent_loop_stopped", "api_request_error", "gateway_platform_event",
    "post_tool_call", "pre_tool_call", "on_session_end",
    "transform_api_error_classification", "transform_llm_output",
    "transform_terminal_output", "transform_tool_result",
]


def test_vwp18_valid_hooks_registry_detected(monkeypatch):
    """VWP-18: hosts that advertise transform_tool_result ONLY via the
    hermes_cli.plugins.VALID_HOOKS registry must be detected as capable —
    this is exactly the production Hermes build that v0.6.0 initially
    misclassified and refused to load."""
    from vaultwarden.compat import supports_transform_tool_result

    _install_fake_hermes_cli(monkeypatch, PRODUCTION_VALID_HOOKS)
    assert supports_transform_tool_result(_BareCtx()) is True


def test_vwp18_valid_hooks_without_transform_fails_closed(monkeypatch):
    """VWP-18: an older registry lacking transform_tool_result still fails
    closed — the new detection layer must not weaken SEC-01."""
    from vaultwarden.compat import supports_transform_tool_result

    _install_fake_hermes_cli(
        monkeypatch, ["post_tool_call", "pre_tool_call", "on_session_end"])
    assert supports_transform_tool_result(_BareCtx()) is False


def test_vwp18_no_hermes_cli_fails_closed(monkeypatch):
    """VWP-18: no hermes_cli importable at all (unit-test envs, non-Hermes
    hosts) → conservative False; fail-closed default preserved."""
    from vaultwarden.compat import supports_transform_tool_result

    monkeypatch.delitem(sys.modules, "hermes_cli", raising=False)
    monkeypatch.delitem(sys.modules, "hermes_cli.plugins", raising=False)
    # Even if some unrelated object shadows the name, the guarded import
    # must not raise out of the capability check.
    monkeypatch.setitem(sys.modules, "hermes_cli", None)
    assert supports_transform_tool_result(_BareCtx()) is False


def test_vwp18_register_loads_on_bare_valid_hooks_host(monkeypatch, tmp_path,
                                                        fake_bw):
    """VWP-18 end-to-end: register() succeeds on a bare context whose only
    hook-capability signal is the VALID_HOOKS registry (production shape)."""
    import vaultwarden
    from vaultwarden.tests.conftest import BASE_SECTION
    from vaultwarden.tests.test_integration import _write_secrets_yaml

    _write_secrets_yaml(tmp_path)
    _install_fake_hermes_cli(monkeypatch, PRODUCTION_VALID_HOOKS)
    monkeypatch.delenv("BW_CLI_PATH", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("TERMINAL_ENV", "docker")

    class BareRecordingCtx(_BareCtx):
        def __init__(self, settings):
            super().__init__()
            self._settings = settings
            self.tools: list[dict] = []
            self.middleware: list[tuple[str, object]] = []

        def get_config(self, key, default=None):
            return self._settings.get(key, default)

        def register_middleware(self, kind, fn):
            self.middleware.append((kind, fn))

        def register_tool(self, *, name, toolset, schema, handler,
                          check_fn=None):
            self.tools.append({"name": name})

    ctx = BareRecordingCtx({**BASE_SECTION, "enabled": True,
                            "bw_cli_path": fake_bw})
    # The bare host context mirrors production: NO supported_hooks attr and
    # NO transform_tool_result attribute on the context itself.
    assert not hasattr(ctx, "supported_hooks")
    assert not hasattr(ctx, "transform_tool_result")
    assert vaultwarden.register(ctx) is True
    assert [kind for kind, _ in ctx.hooks][0] == "transform_tool_result"


# ── AUD-06 (v0.6.3): fail-closed mandatory lifecycle-hook registration ──

from vaultwarden.tests.conftest import RecordingCtx  # noqa: E402


def _vw_register_ctx(tmp_path, fake_bw, monkeypatch, cls=None):
    """Build a register()-ready stand-in host context for lifecycle tests.

    AUD-06 detection is layered: context attribute -> declared
    ``supported_hooks`` collection -> module-level VALID_HOOKS registry
    (VWP-18). The default RecordingCtx declares the hooks; subclasses that
    clear the declaration force detection onto the registry, so every test
    installs the production-shaped VALID_HOOKS registry here — tests that
    need a *reduced* registry overwrite it afterwards.
    """
    from vaultwarden.tests.conftest import BASE_SECTION as _BASE
    from vaultwarden.tests.test_integration import _write_secrets_yaml

    _write_secrets_yaml(tmp_path)
    monkeypatch.delenv("BW_CLI_PATH", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("TERMINAL_ENV", "docker")
    _install_fake_hermes_cli(monkeypatch, PRODUCTION_VALID_HOOKS)
    return (cls or RecordingCtx)({**_BASE, "enabled": True,
                                  "bw_cli_path": fake_bw})


class _NoLifecycleRegistryCtx(RecordingCtx):
    """Host whose VALID_HOOKS registry lists transform_tool_result but NOT
    the mandatory lifecycle hooks — the hook is missing from the host hook
    registry entirely."""

    supported_hooks = None  # force detection onto the VALID_HOOKS registry


class _RaisingPostToolCallCtx(RecordingCtx):
    def register_hook(self, kind, fn):
        if kind == "post_tool_call":
            raise RuntimeError("host rejects post_tool_call")
        self.hooks.append((kind, fn))


class _RaisingSessionEndCtx(RecordingCtx):
    def register_hook(self, kind, fn):
        if kind == "on_session_end":
            raise RuntimeError("host rejects on_session_end")
        self.hooks.append((kind, fn))


class _FalsePostToolCallCtx(RecordingCtx):
    """Host that signals explicit registration failure with a False return."""

    def register_hook(self, kind, fn):
        if kind == "post_tool_call":
            return False
        self.hooks.append((kind, fn))
        return None


class _FalseSessionEndCtx(RecordingCtx):
    def register_hook(self, kind, fn):
        if kind == "on_session_end":
            return False
        self.hooks.append((kind, fn))
        return None


class _NoneReturningCtx(RecordingCtx):
    """register_hook returns None explicitly — success per the host API."""

    def register_hook(self, kind, fn):
        result = super().register_hook(kind, fn)
        assert result is None          # list.append contract
        return None


# -- supports_lifecycle_hook: explicit capability detection -------------------

def test_supports_lifecycle_hook_declared_true():
    ctx = RecordingCtx()
    assert compat.supports_lifecycle_hook(ctx, "post_tool_call") is True
    assert compat.supports_lifecycle_hook(ctx, "on_session_end") is True


def test_supports_lifecycle_hook_declared_missing_false():
    """Declared supported_hooks collection WITHOUT the hook -> unsupported
    (fail-closed). No exception-based probing involved."""
    ctx = RecordingCtx()
    ctx.supported_hooks = frozenset({"transform_tool_result"})
    assert compat.supports_lifecycle_hook(ctx, "post_tool_call") is False
    assert compat.supports_lifecycle_hook(ctx, "on_session_end") is False


def test_supports_lifecycle_hook_no_register_hook_false():
    class NoHooks:
        supported_hooks = frozenset({"post_tool_call"})

    assert compat.supports_lifecycle_hook(NoHooks(), "post_tool_call") is False


def test_supports_lifecycle_hook_valid_registry(monkeypatch):
    """VWP-18-style hosts: hook support advertised ONLY via the module-level
    hermes_cli.plugins.VALID_HOOKS registry is detected explicitly."""
    _install_fake_hermes_cli(monkeypatch, PRODUCTION_VALID_HOOKS)
    ctx = _BareCtx()
    assert compat.supports_lifecycle_hook(ctx, "post_tool_call") is True
    assert compat.supports_lifecycle_hook(ctx, "on_session_end") is True


def test_supports_lifecycle_hook_valid_registry_missing_hook(monkeypatch):
    """Required lifecycle hook MISSING from the host hook registry -> False
    (fail-closed), even though transform_tool_result IS present."""
    _install_fake_hermes_cli(
        monkeypatch, ["pre_tool_call", "transform_tool_result"])
    ctx = _BareCtx()
    assert compat.supports_lifecycle_hook(ctx, "post_tool_call") is False
    assert compat.supports_lifecycle_hook(ctx, "on_session_end") is False
    assert compat.supports_lifecycle_hook(ctx, "transform_tool_result") is True


def test_supports_lifecycle_hook_no_host_signal_false(monkeypatch):
    """No attribute, no declared collection, no registry -> conservative
    False. Never raises (no exception-based capability probing)."""
    monkeypatch.delitem(sys.modules, "hermes_cli", raising=False)
    monkeypatch.delitem(sys.modules, "hermes_cli.plugins", raising=False)
    monkeypatch.setitem(sys.modules, "hermes_cli", None)
    assert compat.supports_lifecycle_hook(_BareCtx(), "post_tool_call") is False


# -- register_mandatory_lifecycle_hook ----------------------------------------

def test_register_mandatory_hook_success_none_is_not_failure():
    """A successful registration returning None must NOT be treated as
    failure (the host API does not define None as failure)."""
    ctx = _CtxWithHooks()
    # No VALID_HOOKS registry and no declared collection in this plain
    # unit-test env: opt the stand-in host in via a hook-name attribute,
    # exactly like a Hermes build exposing hooks as bound methods.
    setattr(ctx, "post_tool_call", lambda *a, **kw: None)
    fn = lambda *a, **kw: None  # noqa: E731
    compat.register_mandatory_lifecycle_hook(ctx, "post_tool_call", fn)
    assert ctx.hooks == [("post_tool_call", fn)]


def test_register_mandatory_hook_unsupported_raises():
    class LegacyCtx(_CtxWithHooks):
        supported_hooks = frozenset({"transform_tool_result"})

    with pytest.raises(errors.PluginInitializationError,
                       match="post_tool_call"):
        compat.register_mandatory_lifecycle_hook(
            LegacyCtx(), "post_tool_call", lambda *a: None)


def test_register_mandatory_hook_exception_converted(caplog):
    """Registration raising -> PluginInitializationError with a SANITIZED
    reason: original exception TYPE NAME only, never its payload."""
    class ExplodingCtx(_CtxWithHooks):
        def register_hook(self, kind, fn):
            raise ValueError("internal detail with possible secret leak")

    exploding = ExplodingCtx()
    # Attribute-based opt-in so capability detection succeeds and the
    # registration call itself is what explodes.
    setattr(exploding, "on_session_end", lambda *a, **kw: None)
    with pytest.raises(errors.PluginInitializationError) as ei:
        compat.register_mandatory_lifecycle_hook(
            exploding, "on_session_end", lambda *a: None)
    msg = str(ei.value)
    assert "on_session_end" in msg
    assert "ValueError" in msg                    # type name kept
    assert "possible secret leak" not in msg      # payload sanitized away


def test_register_mandatory_hook_explicit_false_raises():
    class FalseCtx(_CtxWithHooks):
        def register_hook(self, kind, fn):
            return False

    false_ctx = FalseCtx()
    # Attribute-based opt-in so detection succeeds and the host's explicit
    # False return is what trips the fail-closed path.
    setattr(false_ctx, "post_tool_call", lambda *a, **kw: None)
    with pytest.raises(errors.PluginInitializationError,
                       match="explicit failure"):
        compat.register_mandatory_lifecycle_hook(
            false_ctx, "post_tool_call", lambda *a: None)


def test_plugin_initialization_error_taxonomy():
    """AUD-06 error type: dedicated fail-closed initialization/security
    error with its own taxonomy code."""
    assert issubclass(errors.PluginInitializationError, errors.SecurityError)
    assert errors.PluginInitializationError.code == "PLUGIN_INITIALIZATION_ERROR"
    exc = errors.PluginInitializationError("boom")
    assert exc.to_dict()["error_code"] == "PLUGIN_INITIALIZATION_ERROR"
    assert compat.get_error_code(exc) == "PLUGIN_INITIALIZATION_ERROR"


# -- register(): lifecycle hooks are MANDATORY (fail-closed) ------------------

def test_aud06_post_tool_call_unsupported_refuses_load(tmp_path, fake_bw,
                                                       monkeypatch):
    ctx = _vw_register_ctx(tmp_path, fake_bw, monkeypatch,
                           _NoLifecycleRegistryCtx)
    _install_fake_hermes_cli(
        monkeypatch, ["pre_tool_call", "transform_tool_result"])
    assert compat.TRANSFORM_TOOL_RESULT_HOOK in \
        set(sys.modules["hermes_cli.plugins"].VALID_HOOKS)
    ok = vaultwarden.register(ctx)
    assert ok is False
    kinds = [k for k, _ in ctx.hooks]
    assert "post_tool_call" not in kinds
    # NO partial state: tools are never exposed when a required lifecycle
    # hook cannot be registered.
    assert ctx.tools == []


def test_aud06_on_session_end_unsupported_refuses_load(tmp_path, fake_bw,
                                                       monkeypatch):
    ctx = _vw_register_ctx(tmp_path, fake_bw, monkeypatch,
                           _NoLifecycleRegistryCtx)
    _install_fake_hermes_cli(
        monkeypatch,
        ["pre_tool_call", "transform_tool_result", "post_tool_call"])
    ok = vaultwarden.register(ctx)
    assert ok is False
    kinds = [k for k, _ in ctx.hooks]
    assert "post_tool_call" in kinds       # first hook landed...
    assert "on_session_end" not in kinds   # ...second one refused the load
    assert ctx.tools == []                 # ...and tools were never exposed


def test_aud06_post_tool_call_registration_raises_refuses_load(tmp_path,
                                                               fake_bw,
                                                               monkeypatch,
                                                               caplog):
    ctx = _vw_register_ctx(tmp_path, fake_bw, monkeypatch,
                           _RaisingPostToolCallCtx)
    with caplog.at_level(logging.ERROR):
        ok = vaultwarden.register(ctx)
    assert ok is False
    assert "post_tool_call" in caplog.text
    assert ctx.tools == []
    assert all(k != "post_tool_call" for k, _ in ctx.hooks)


def test_aud06_on_session_end_registration_raises_refuses_load(tmp_path,
                                                               fake_bw,
                                                               monkeypatch,
                                                               caplog):
    ctx = _vw_register_ctx(tmp_path, fake_bw, monkeypatch,
                           _RaisingSessionEndCtx)
    with caplog.at_level(logging.ERROR):
        ok = vaultwarden.register(ctx)
    assert ok is False
    assert "on_session_end" in caplog.text
    assert ctx.tools == []


def test_aud06_post_tool_call_explicit_false_refuses_load(tmp_path, fake_bw,
                                                          monkeypatch):
    ctx = _vw_register_ctx(tmp_path, fake_bw, monkeypatch,
                           _FalsePostToolCallCtx)
    assert vaultwarden.register(ctx) is False
    assert ctx.tools == []


def test_aud06_on_session_end_explicit_false_refuses_load(tmp_path, fake_bw,
                                                          monkeypatch):
    ctx = _vw_register_ctx(tmp_path, fake_bw, monkeypatch,
                           _FalseSessionEndCtx)
    assert vaultwarden.register(ctx) is False
    assert ctx.tools == []


def test_aud06_all_hooks_registered_none_success_loads(tmp_path, fake_bw,
                                                       monkeypatch):
    """Happy path: all mandatory hooks supported and registration succeeds
    (including a register_hook that returns None) -> plugin loads and the
    12 tools are exposed AFTER the hooks landed."""
    ctx = _vw_register_ctx(tmp_path, fake_bw, monkeypatch, _NoneReturningCtx)
    assert vaultwarden.register(ctx) is True
    assert [k for k, _ in ctx.hooks] == ["transform_tool_result",
                                         "post_tool_call", "on_session_end"]
    assert len(ctx.tools) == 12


def test_aud06_tools_exposed_only_after_mandatory_hooks(tmp_path, fake_bw,
                                                        monkeypatch):
    """Ordering guard: every mandatory registration completes BEFORE the
    first tool is exposed (tools appended last on the recording ctx)."""
    events: list[str] = []

    class OrderedCtx(RecordingCtx):
        def register_hook(self, kind, fn):
            events.append(f"hook:{kind}")
            super().register_hook(kind, fn)

        def register_middleware(self, kind, fn):
            events.append(f"middleware:{kind}")
            super().register_middleware(kind, fn)

        def register_tool(self, *, name, toolset, schema, handler,
                          check_fn=None):
            events.append(f"tool:{name}")
            super().register_tool(name=name, toolset=toolset, schema=schema,
                                  handler=handler, check_fn=check_fn)

    ctx = _vw_register_ctx(tmp_path, fake_bw, monkeypatch, OrderedCtx)
    assert vaultwarden.register(ctx) is True
    first_tool = next(i for i, e in enumerate(events) if e.startswith("tool:"))
    for required in ("hook:transform_tool_result", "middleware:tool_execution",
                     "hook:post_tool_call", "hook:on_session_end"):
        assert required in events[:first_tool], f"{required} after tools!"
    assert sum(1 for e in events if e.startswith("tool:")) == 12


def test_aud06_sanitized_failure_logs_contain_no_secrets(tmp_path, fake_bw,
                                                         monkeypatch, caplog):
    """Failure logs carry the hook name + sanitized reason only — never
    secrets, YAML contents, env values, or session material."""
    ctx = _vw_register_ctx(tmp_path, fake_bw, monkeypatch,
                           _RaisingPostToolCallCtx)
    with caplog.at_level(logging.ERROR):
        assert vaultwarden.register(ctx) is False
    text = caplog.text
    assert "post_tool_call" in text
    assert "PLUGIN_INITIALIZATION_ERROR" in text
    for forbidden in ("cs-secret", "mp-secret", "client_secret",
                      "master_password", "session"):
        assert forbidden not in text.lower()


def test_aud06_transform_tool_result_fail_closed_unchanged(tmp_path,
                                                           fake_bw,
                                                           monkeypatch):
    """SEC-01 regression: transform_tool_result failure handling stays a
    SEPARATE, dedicated path (not merged into the generic lifecycle
    catch-all) and still refuses the load FIRST — before middleware and
    lifecycle hooks are even attempted."""
    events: list[str] = []

    class LegacyCtx(RecordingCtx):
        supported_hooks = frozenset({"post_tool_call", "on_session_end"})

        def register_hook(self, kind, fn):
            events.append(kind)
            super().register_hook(kind, fn)

        def register_middleware(self, kind, fn):
            events.append(kind)
            super().register_middleware(kind, fn)

    ctx = _vw_register_ctx(tmp_path, fake_bw, monkeypatch, LegacyCtx)
    assert vaultwarden.register(ctx) is False
    # Refused before ANY middleware/hook registration was attempted.
    assert events == []
    assert ctx.tools == []

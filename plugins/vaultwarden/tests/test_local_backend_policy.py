"""SEC-03 (v0.5.5): fail-closed policy for the local terminal backend.

Audit background: with the Hermes terminal backend set to ``local`` (or
unset), the LLM-driven terminal executes as the SAME OS user that owns
``$HERMES_HOME/plugins/vaultwarden/secrets.yaml`` (chmod 600). File
permissions only isolate ACROSS users, so the agent could simply run
``cat ~/.hermes/plugins/vaultwarden/secrets.yaml`` and read client_secret /
master_password in plaintext, bypassing every protection the plugin has.

Since v0.5.5 a logged WARNING is no longer enough: ``register()`` REFUSES to
load on a local/unset backend unless the operator explicitly opts in via the
native config flag ``allow_insecure_local_backend`` (default false — any
ambiguity resolves to false, never fail open).

Covered here:
  - config model: default false, string parsing, _DEFAULTS registry entry
  - register(): local + flag false -> False (CRITICAL log, no partial state)
  - register(): local + flag true  -> loads with WARNING
  - register(): docker / ssh / modal -> loads regardless of the flag
  - register(): unset backend -> refused by default (fail-closed)
  - register(): local backend refused BEFORE any tool/middleware registration
  - 12-tool registration invariant still holds when the plugin does load
"""
from __future__ import annotations

import logging

import pytest

import vaultwarden
from vaultwarden.tests.conftest import BASE_SECTION, RecordingCtx
from vaultwarden.tests.test_integration import _write_secrets_yaml


def _setup_env(monkeypatch, tmp_path, backend):
    """Isolated HERMES_HOME with valid secrets.yaml; TERMINAL_ENV pinned.

    ``backend=None`` simulates an UNSET backend (no TERMINAL_ENV, empty
    HERMES_HOME/config.yaml).
    """
    _write_secrets_yaml(tmp_path)
    monkeypatch.delenv("BW_CLI_PATH", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    if backend is None:
        monkeypatch.delenv("TERMINAL_ENV", raising=False)
    else:
        monkeypatch.setenv("TERMINAL_ENV", backend)


# ── config model: allow_insecure_local_backend ──────────────────────────────

def test_flag_defaults_to_false_fail_closed():
    """Missing key in the native config resolves to False (never fail open)."""
    from vaultwarden.config import load_config
    from vaultwarden.tests.conftest import SettingsContext

    cfg = load_config(SettingsContext(dict(BASE_SECTION)))
    assert cfg.allow_insecure_local_backend is False


def test_flag_parses_true_and_string_variants():
    from vaultwarden.tests.conftest import make_config

    assert make_config(
        section={"allow_insecure_local_backend": True}
    ).allow_insecure_local_backend is True
    assert make_config(
        section={"allow_insecure_local_backend": "true"}
    ).allow_insecure_local_backend is True
    assert make_config(
        section={"allow_insecure_local_backend": "false"}
    ).allow_insecure_local_backend is False
    # garbage / ambiguous values must resolve to False (fail-closed)
    assert make_config(
        section={"allow_insecure_local_backend": "maybe"}
    ).allow_insecure_local_backend is False


def test_flag_registered_in_defaults_and_plugin_yaml():
    from pathlib import Path

    from vaultwarden.config import _DEFAULTS

    assert "allow_insecure_local_backend" in _DEFAULTS
    assert _DEFAULTS["allow_insecure_local_backend"] is False

    yaml_path = Path(vaultwarden.__file__).resolve().parent / "plugin.yaml"
    text = yaml_path.read_text(encoding="utf-8")
    assert "allow_insecure_local_backend:" in text
    assert "type: boolean" in text


def test_flag_has_no_environment_variable_channel(monkeypatch):
    """Native-config-only (VWP-05): no env var may set/override the flag."""
    from vaultwarden.config import load_config
    from vaultwarden.tests.conftest import SettingsContext

    monkeypatch.setenv("ALLOW_INSECURE_LOCAL_BACKEND", "true")
    monkeypatch.setenv("VW_ALLOW_INSECURE_LOCAL_BACKEND", "true")
    cfg = load_config(SettingsContext(dict(BASE_SECTION)),
                      env={"ALLOW_INSECURE_LOCAL_BACKEND": "true"})
    assert cfg.allow_insecure_local_backend is False


# ── register(): SEC-03 enforcement ──────────────────────────────────────────

def test_register_local_backend_default_refused(monkeypatch, tmp_path, fake_bw,
                                                caplog):
    """local backend + default config (flag absent) -> register() False."""
    _setup_env(monkeypatch, tmp_path, "local")
    ctx = RecordingCtx({**BASE_SECTION, "bw_cli_path": fake_bw})
    with caplog.at_level(logging.CRITICAL):
        ok = vaultwarden.register(ctx)
    assert ok is False
    # refusal leaves NO partial state: nothing registered at all
    assert ctx.tools == []
    assert ctx.middleware == []
    assert ctx.hooks == []
    crit = [r for r in caplog.records if r.levelno == logging.CRITICAL]
    blob = " ".join(r.getMessage() for r in crit)
    assert "allow_insecure_local_backend" in blob
    assert "secrets.yaml" in blob
    assert "docker" in blob and "ssh" in blob and "modal" in blob


def test_register_local_backend_flag_false_refused(monkeypatch, tmp_path,
                                                   fake_bw, caplog):
    """Explicit flag false behaves exactly like the missing-flag default."""
    _setup_env(monkeypatch, tmp_path, "local")
    ctx = RecordingCtx({**BASE_SECTION, "bw_cli_path": fake_bw,
                        "allow_insecure_local_backend": False})
    with caplog.at_level(logging.CRITICAL):
        assert vaultwarden.register(ctx) is False
    assert ctx.tools == []


def test_register_unset_backend_default_refused(monkeypatch, tmp_path, fake_bw):
    """Unset backend is treated as 'local' -> refused by default (fail-closed)."""
    _setup_env(monkeypatch, tmp_path, None)
    ctx = RecordingCtx({**BASE_SECTION, "bw_cli_path": fake_bw})
    assert vaultwarden.register(ctx) is False
    assert ctx.tools == []


def test_register_local_backend_optin_loads_with_warning(monkeypatch, tmp_path,
                                                          fake_bw, caplog):
    """local backend + allow_insecure_local_backend=true -> loads + WARNING."""
    _setup_env(monkeypatch, tmp_path, "local")
    ctx = RecordingCtx({**BASE_SECTION, "bw_cli_path": fake_bw,
                        "allow_insecure_local_backend": True})
    with caplog.at_level(logging.WARNING):
        ok = vaultwarden.register(ctx)
    assert ok  # truthy — plugin loaded
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    blob = " ".join(r.getMessage() for r in warnings)
    assert "accepted" in blob.lower()
    assert "risk" in blob.lower()
    # acceptance must NOT downgrade the rest of the load: 12 tools intact
    assert len(ctx.tools) == 12


@pytest.mark.parametrize("backend", ["docker", "ssh", "modal"])
def test_register_sandboxed_backends_load_regardless_of_flag(
        monkeypatch, tmp_path, fake_bw, backend):
    """Secure backends are unaffected by the flag (false, true, or absent)."""
    for flag in (None, False, True):
        _setup_env(monkeypatch, tmp_path, backend)
        section = dict(BASE_SECTION)
        section["bw_cli_path"] = fake_bw
        if flag is not None:
            section["allow_insecure_local_backend"] = flag
        ctx = RecordingCtx(section)
        assert vaultwarden.register(ctx) is True, (backend, flag)
        assert len(ctx.tools) == 12


def test_local_backend_refusal_happens_before_tool_registration(
        monkeypatch, tmp_path, fake_bw):
    """The refused load must short-circuit BEFORE any get_tools()/middleware
    work — verified by making tool registration explode if it is ever called."""
    _setup_env(monkeypatch, tmp_path, "local")
    ctx = RecordingCtx({**BASE_SECTION, "bw_cli_path": fake_bw})

    def _boom(**kwargs):
        raise AssertionError(
            "SEC-03 violation: register() touched tool registration on the "
            "refused local-backend path")

    ctx.register_tool = _boom
    ctx.register_middleware = _boom
    ctx.register_hook = _boom
    assert vaultwarden.register(ctx) is False


def test_12_tools_still_registered_on_secure_backend(monkeypatch, tmp_path,
                                                     fake_bw):
    """Hard constraint re-check: the 12-tool contract is unchanged by SEC-03."""
    _setup_env(monkeypatch, tmp_path, "docker")
    ctx = RecordingCtx({**BASE_SECTION, "bw_cli_path": fake_bw})
    assert vaultwarden.register(ctx) is True
    assert len(ctx.tools) == 12
    names = {t["name"] for t in ctx.tools}
    assert len(names) == 12
    from vaultwarden.tools import get_tools
    pairs = get_tools(vaultwarden.PLUGIN_STATE["auth"],
                      vaultwarden.PLUGIN_STATE["config"],
                      vaultwarden.PLUGIN_STATE["registry"])
    assert len(list(pairs)) == 12

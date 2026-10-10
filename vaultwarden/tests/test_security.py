"""Security tests (plan §13): redaction, env hygiene, escaping, opacity."""
from __future__ import annotations

import logging
import os

import pytest

from vaultwarden.security import (BW_ENV_ALLOWLIST, RedactingFilter,
                                  audit_subprocess_env, escape_for_context,
                                  placeholder_tokens, shell_escape, url_escape)


# ---------------------------------------------------------------- redaction
def test_redacting_filter_scrubs_registered_secrets():
    f = RedactingFilter()
    f.register_secret("s3cret-value")
    rec = logging.LogRecord("x", logging.INFO, "", 0,
                            "connecting with s3cret-value now", (), None)
    assert f.filter(rec) is True
    assert "s3cret-value" not in rec.getMessage()
    assert "[REDACTED]" in rec.getMessage()


def test_session_key_shape_masked():
    f = RedactingFilter()
    msg = 'bw unlock output: 2f4c9a7b-1d2e-3f4a-5b6c-7d8e9fa0b1c2:' + "A" * 40
    rec = logging.LogRecord("x", logging.INFO, "", 0, msg, (), None)
    f.filter(rec)
    assert "[SESSION:****]" in rec.getMessage()
    assert "A" * 40 not in rec.getMessage()


def test_plugin_loggers_carry_shared_filter():
    from vaultwarden.security import get_logger, get_redacting_filter
    lg = get_logger("demo")
    assert any(isinstance(fl, RedactingFilter) for fl in lg.filters)
    shared = get_redacting_filter()
    shared.register_secret("topsecret-mp")
    rec = logging.LogRecord("x", logging.ERROR, "", 0, "pw=topsecret-mp", (), None)
    list(lg.filters)[0].filter(rec)
    assert "topsecret-mp" not in rec.getMessage()


# ------------------------------------------------------------- env hygiene
def test_audit_flags_disallowed_keys():
    bad = {"PATH": "/x", "HOME": "/h", "BITWARDENCLI_APPDATA_DIR": "/d",
           "VW_MASTER_PASSWORD": "leak", "AWS_SECRET_ACCESS_KEY": "k"}
    v = audit_subprocess_env(bad)
    assert "VW_MASTER_PASSWORD" in v and "AWS_SECRET_ACCESS_KEY" in v
    assert audit_subprocess_env(
        {"PATH": "", "HOME": "", "BITWARDENCLI_APPDATA_DIR": "",
         "BW_SESSION": "s", "BW_CLIENTID": "c", "BW_CLIENTSECRET": "x",
         "BW_MP": "m"}) == []
    assert BW_ENV_ALLOWLIST == {"PATH", "HOME", "BITWARDENCLI_APPDATA_DIR",
                                "BW_SESSION", "BW_CLIENTID", "BW_CLIENTSECRET", "BW_MP"}


def test_no_bootstrap_secrets_in_os_environ_after_register(monkeypatch, tmp_path, fake_bw):
    monkeypatch.setenv("VW_CLIENT_SECRET", "cs-secret")
    monkeypatch.setenv("VW_MASTER_PASSWORD", "mp-secret")
    monkeypatch.setenv("BW_CLI_PATH", fake_bw)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    import vaultwarden
    from vaultwarden.tests.conftest import RecordingCtx, BASE_SECTION
    ctx = RecordingCtx({"secrets": {"vaultwarden": {**BASE_SECTION, "enabled": True}}})
    vaultwarden.register(ctx)
    assert "VW_CLIENT_SECRET" not in os.environ
    assert "VW_MASTER_PASSWORD" not in os.environ
    assert "BW_SESSION" not in os.environ   # session key NEVER exported globally


def test_master_password_never_logged(caplog, bw_cli):
    from vaultwarden.auth import AuthManager
    from vaultwarden.tests.conftest import make_config
    caplog.set_level(logging.DEBUG)
    mgr = AuthManager(bw_cli, make_config(), client_secret="cs-secret",
                      master_password="SUPER-DUPER-MP")
    with pytest.raises(Exception):
        pass
    mgr.configure_server_if_needed()
    try:
        mgr.ensure_authenticated()          # wrong client secret -> fails
    except Exception:
        pass
    joined = " ".join(r.getMessage() for r in caplog.records)
    assert "SUPER-DUPER-MP" not in joined
    assert "cs-secret" not in joined


# ---------------------------------------------------------------- escaping
def test_shell_escape_blocks_injection():
    evil = "p@ss$(rm -rf /)`x`;"
    esc = shell_escape(evil)
    assert esc.startswith("'") or "\\" in esc
    assert "$(" not in esc.strip("'") or esc.count("'") >= 2


def test_url_escape_encodes_at_and_slash():
    assert url_escape("a@b/c?d=e") == "a%40b%2Fc%3Fd%3De"


def test_escape_context_detection():
    cmd_url = "psql 'postgres://user:__VW_SECRET_aaaaaaaaaaaa__@host/db'"
    assert looks(cmd_url, "__VW_SECRET_aaaaaaaaaaaa__") is True
    cmd_shell = "export X=__VW_SECRET_bbbbbbbbbbbb__; run"
    assert looks(cmd_shell, "__VW_SECRET_bbbbbbbbbbbb__") is False


def looks(cmd, tok):
    from vaultwarden.security import looks_like_url_context
    return looks_like_url_context(cmd, tok)


def test_unknown_context_double_escaped():
    val = "p@ss word"
    out = escape_for_context(val, "echo __VW_SECRET_cccccccccccc__ tail",
                             "__VW_SECRET_cccccccccccc__")
    assert "'" in out or "%" in out      # quoted at minimum


# ------------------------------------------------------------ placeholder opacity
def test_placeholder_tokens_parsing():
    toks = placeholder_tokens("a __VW_SECRET_0123456789ab__ b __VW_SECRET_ffffffffffff__ c")
    assert toks == ["__VW_SECRET_0123456789ab__", "__VW_SECRET_ffffffffffff__"]
    assert placeholder_tokens("__VW_SECRET_short__") == []
    assert placeholder_tokens("no tokens here") == []


def test_tool_outputs_contain_no_vault_secrets(tools_by_name):
    secrets = ("sup3r-s3cret-pg!", "gr@f-pass", "JBSWY3DPEHPK3PXP",
               "custom-key-value", "sk_live_XXXX")
    outputs = [
        tools_by_name["vaultwarden_status"]({}),
        tools_by_name["vaultwarden_list"]({}),
        tools_by_name["vaultwarden_search"]({"query": "keys"}),
        tools_by_name["vaultwarden_get_secret_ref"](
            {"item_id": "Postgres prod", "field": "password"}),
    ]
    blob = str(outputs)
    for s in secrets:
        assert s not in blob


def test_config_contains_no_secret_values():
    from vaultwarden.config import _DEFAULTS
    blob = str(_DEFAULTS).lower()
    for forbidden in ("secret-value", "password=", "master_password: "):
        assert forbidden not in blob
    # defaults store NAMES only:
    assert _DEFAULTS["client_secret_env"] == "VW_CLIENT_SECRET"
    assert _DEFAULTS["master_password_env"] == "VW_MASTER_PASSWORD"


def test_session_key_not_persisted_to_disk(bw_cli, tmp_path):
    from vaultwarden.auth import AuthManager
    from vaultwarden.tests.conftest import make_config
    mgr = AuthManager(bw_cli, make_config(), client_secret="cs-secret",
                      master_password="mp-secret")
    mgr.configure_server_if_needed()
    mgr.ensure_authenticated()
    key = mgr.get_session()
    for f in tmp_path.rglob("*"):
        if f.is_file():
            content = f.read_bytes()
            assert key.encode() not in content, f
    # plugin state dir contains no session key file of ours:
    appdata_files = list((tmp_path / ".bw-data").rglob("*"))
    assert all("session" not in p.name.lower() for p in appdata_files)


def test_error_messages_are_secret_free(bw_cli):
    from vaultwarden.auth import AuthManager
    from vaultwarden.tests.conftest import make_config
    from vaultwarden import errors as E
    mgr = AuthManager(bw_cli, make_config(), client_secret="cs-secret",
                      master_password="BAD-PW")
    with pytest.raises(E.VaultwardenError) as ei:
        mgr.ensure_authenticated()
    resp = ei.value.to_dict()
    assert "BAD-PW" not in str(resp)
    assert resp["error_code"] in ("AUTH_ERROR", "PLUGIN_ERROR", "NETWORK_ERROR")

# vaultwarden/tests/test_cleanup_hardening_v023.py — v0.2.3
"""Regression tests for the v0.2.3 cleanup & hardening release:

- BREAKING: auto_unlock config key removed entirely — the vault is ALWAYS
  auto-unlocked with the master password (mandatory).
- SECURITY: complete log redaction in the write tools via recursive string
  extraction (_collect_secret_strings) used by both h_store and h_update.
- BUGFIX:   `bw encode` reads its value from stdin instead of a CLI argument
  (fixes ARG_MAX overflow for SSH keys / certificates / long notes).
"""
from __future__ import annotations


def test_auto_unlock_removed():
    """v0.2.3: auto_unlock key must not exist in config defaults or plugin.yaml."""
    from vaultwarden.config import _DEFAULTS
    assert "auto_unlock" not in _DEFAULTS

    from pathlib import Path
    import vaultwarden
    yaml_path = Path(vaultwarden.__file__).resolve().parent / "plugin.yaml"
    text = yaml_path.read_text()
    assert "auto_unlock" not in text


def test_collect_secret_strings():
    """Bug #1 fix: recursive string extraction for redaction."""
    from vaultwarden.tools import _collect_secret_strings
    args = {
        "name": "test",
        "password": "s3cr3t",
        "username": "api-key-12345",
        "notes": "recovery seed phrase here",
        "custom_fields": [{"name": "token", "value": "jwt-abc"}],
        "empty": "",
        "number": 42,
    }
    collected = _collect_secret_strings(args)
    assert "s3cr3t" in collected
    assert "api-key-12345" in collected
    assert "recovery seed phrase here" in collected
    assert "jwt-abc" in collected
    assert "" not in collected
    assert "42" not in collected


def test_encode_uses_stdin():
    """Bug #2 fix: bw encode must use stdin, not CLI argument."""
    import inspect
    from vaultwarden.bw_cli import BwCli
    src = inspect.getsource(BwCli.encode)
    assert "input=value" in src or "input=" in src
    assert '["encode", value]' not in src


def test_version_headers_v023():
    """Verify all modified files have v0.2.3 version header."""
    import vaultwarden
    from pathlib import Path

    pkg_dir = Path(vaultwarden.__file__).resolve().parent
    modified = ["__init__.py", "config.py", "auth.py", "tools.py", "bw_cli.py"]
    for name in modified:
        path = pkg_dir / name
        with open(path, 'r') as f:
            first_line = f.readline().strip()
        assert 'v0.2.3' in first_line, f"{name} missing version header: {first_line}"


# ---------------------------------------------------------------------------
# Additional behavioural coverage for the three changes above.
# ---------------------------------------------------------------------------

def test_master_password_mandatory_via_resolve():
    """v0.2.3: missing master password VALUE must fail at resolve_secret()."""
    from vaultwarden.config import PluginConfig
    from vaultwarden import errors

    cfg = PluginConfig(
        section={"server_url": "https://vault.example.com",
                 "client_id": "user.12345678-1234-1234-1234-123456789abc"},
        env_snapshot={},  # ← nincs VW_MASTER_PASSWORD
    )
    try:
        cfg.resolve_secret(cfg.master_password_env_name, required=True)
        assert False, "Should have raised ConfigError"
    except errors.ConfigError as e:
        assert "VW_MASTER_PASSWORD" in str(e.message)


def test_master_password_env_name_defaults():
    """v0.2.3: env var NAME always has a sensible default."""
    from vaultwarden.config import PluginConfig
    cfg = PluginConfig(section={})
    assert cfg.master_password_env_name == "VW_MASTER_PASSWORD"


def test_do_unlock_has_no_early_return_guard():
    """v0.2.3: _do_unlock() must ALWAYS attempt the unlock (no toggle guard)."""
    import ast
    import inspect
    import textwrap
    from vaultwarden.auth import AuthManager
    body = ast.parse(textwrap.dedent(inspect.getsource(AuthManager._do_unlock)))
    fn = body.body[0]
    # No conditional early-return at the top of the method body.
    for stmt in fn.body:
        assert not isinstance(stmt, ast.If), "unexpected guard in _do_unlock"
        assert not isinstance(stmt, ast.Return), "unexpected early return in _do_unlock"


def test_store_and_update_register_all_string_args(write_tools_by_name):
    """SECURITY: every non-empty string arg is redacted during store/update."""
    from vaultwarden.security import get_redacting_filter
    redactor = get_redacting_filter()

    res = write_tools_by_name["vaultwarden_store"]({
        "name": "svc-login", "username": "api-user-leakme",
        "password": "pw-leakme", "notes": "note-secret-leakme"})
    assert res.get("created") is True, res
    # after completion everything must be unregistered again...
    for s in ("api-user-leakme", "pw-leakme", "note-secret-leakme"):
        assert s not in redactor._secrets
    # ...and DURING the operation they were registered (spy proves it):
    registered: list[str] = []
    orig_reg = redactor.register_secret
    orig_forget = redactor.forget_secret
    redactor.register_secret = lambda v: (registered.append(v), orig_reg(v))[1]
    redactor.forget_secret = lambda v: (orig_forget(v),)[0]
    try:
        res2 = write_tools_by_name["vaultwarden_update"]({
            "item_id": res["id"],
            "username": "upd-user-leakme", "uri": "https://upd-leakme.example"})
        assert res2.get("updated") is True, res2
        assert "upd-user-leakme" in registered
        assert "https://upd-leakme.example" in registered
    finally:
        redactor.register_secret = orig_reg
        redactor.forget_secret = orig_forget
    for s in registered:
        assert s not in redactor._secrets


def test_encode_roundtrip_via_fake_bw(bw_cli, appdata):
    """Functional proof of the stdin path against the fake bw binary."""
    import base64
    enc = bw_cli.encode("sess", "hello stdin world")
    assert base64.b64decode(enc).decode() == "hello stdin world"

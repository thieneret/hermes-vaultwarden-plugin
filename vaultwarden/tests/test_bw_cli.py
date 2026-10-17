"""Unit tests: bw CLI wrapper — isolated env, JSON parsing, error mapping."""
from __future__ import annotations

import pytest

from vaultwarden import errors
from vaultwarden.bw_cli import BwCli, encode_item, find_bw_binary


def test_find_bw_binary_explicit(fake_bw):
    assert find_bw_binary(fake_bw) == fake_bw


def test_find_bw_binary_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))  # empty dir -> no bw
    monkeypatch.delenv("BW_CLI_PATH", raising=False)
    assert find_bw_binary("") is None


def test_base_env_is_minimal_and_allowlisted(bw_cli):
    env = bw_cli.base_env({"BW_SESSION": "x"})
    assert set(env) <= {"PATH", "HOME", "BITWARDENCLI_APPDATA_DIR", "BW_SESSION"}
    assert env["BITWARDENCLI_APPDATA_DIR"] == bw_cli.appdata_dir
    from vaultwarden.security import audit_subprocess_env
    assert audit_subprocess_env(env) == []


def test_base_env_never_inherits_parent(bw_cli, monkeypatch):
    monkeypatch.setenv("VW_MASTER_PASSWORD", "leaky")
    env = bw_cli.base_env()
    assert "VW_MASTER_PASSWORD" not in env


def test_status_unauthenticated(bw_cli, appdata):
    st = bw_cli.status()
    assert st["status"] == "unauthenticated"


def test_login_wrong_secret_raises_auth_mapped_error(bw_cli):
    with pytest.raises(errors.VaultwardenError) as ei:
        bw_cli.login_apikey("user.x", "WRONG")
    # "incorrect" path exits 1 with generic failure -> PLUGIN_ERROR w/ suggestion
    assert ei.value.code in ("AUTH_ERROR", "PLUGIN_ERROR")


def test_login_and_unlock_roundtrip(bw_cli, appdata):
    bw_cli.login_apikey("user.abc", "cs-secret")
    key = bw_cli.unlock_passwordenv("mp-secret")
    assert "sessionkey" in key
    st = bw_cli.status()
    assert st["status"] == "unlocked"


def test_list_and_get_json(bw_cli, appdata):
    bw_cli.login_apikey("user.abc", "cs-secret")
    key = bw_cli.unlock_passwordenv("mp-secret")
    items = bw_cli.list_items(key)
    assert len(items) == 3 and items[0]["id"].startswith("aaaa")
    item = bw_cli.item_get(key, "Postgres prod")
    assert item["login"]["password"] == "sup3r-s3cret-pg!"


def test_get_missing_item_not_found(bw_cli, appdata):
    bw_cli.login_apikey("user.abc", "cs-secret")
    key = bw_cli.unlock_passwordenv("mp-secret")
    with pytest.raises(errors.NotFoundError):
        bw_cli.item_get(key, "does-not-exist")


def test_encode_pipeline(bw_cli, appdata):
    import base64
    enc = bw_cli.encode("s", "hello world")
    assert base64.b64decode(enc).decode() == "hello world"


def test_encode_item_encodes_entire_json(bw_cli, appdata):
    # v0.2.7: encode_item now base64-encodes the WHOLE JSON object with the
    # Python stdlib (no per-field double encoding, no bw subprocess needed).
    import base64, json
    item = {"name": "N", "login": {"username": "u", "password": "p"}, "type": 1}
    blob = encode_item(item)
    parsed = json.loads(base64.b64decode(blob).decode("utf-8"))
    assert parsed["name"] == "N"            # raw values, NOT field-wise base64
    assert parsed["login"]["password"] == "p"
    assert parsed["type"] == 1              # ints untouched


def test_locked_session_marker_maps_to_session_error(bw_cli, appdata, monkeypatch):
    # v0.1.4 (FAIL-4): inject the stale-session marker through the test-only
    # BW_TEST_FORCE_STDERR hook instead of smuggling a non-allowlisted env key
    # (BW_FORCE_LOCKED) into the isolated subprocess environment.
    monkeypatch.setenv("BW_TEST_FORCE_STDERR", "vault is locked")
    with pytest.raises(errors.SessionError):
        bw_cli.run(["list", "items"], env={"BW_SESSION": "stale"})


def test_network_error_retry_once(fake_bw, appdata, monkeypatch):
    """ECONNREFUSED -> exactly one retry after 2s, then NETWORK_ERROR."""
    import subprocess as sp
    calls = {"n": 0}
    real_run = sp.run

    def counting_run(*a, **k):
        calls["n"] += 1
        # v0.1.4 (FAIL-5): BOTH attempts simulate the unreachable server — the
        # first attempt AND the single retry must fail for the contract
        # "retry once, then NETWORK_ERROR" to hold. (The old mock let the
        # retry succeed, so no error was raised.)
        from unittest.mock import MagicMock
        m = MagicMock(); m.returncode = 1; m.stdout = ""
        m.stderr = "connect ECONNREFUSED 10.0.0.1:443"
        return m

    monkeypatch.setattr(sp, "run", counting_run)
    sleeps: list[float] = []
    monkeypatch.setattr("time.sleep", lambda s=None, *_: sleeps.append(s))
    cli = BwCli(fake_bw, appdata)
    with pytest.raises(errors.NetworkError):
        cli.status()
    assert calls["n"] == 2  # initial + single retry
    assert sleeps == [2]    # exactly one backoff delay of 2 seconds
    del real_run


def test_parse_error_on_malformed_json(fake_bw, appdata, monkeypatch):
    import subprocess as sp
    from unittest.mock import MagicMock
    def bad_run(*a, **k):
        m = MagicMock(); m.returncode = 0; m.stderr = ""
        m.stdout = "{not json at all"
        return m
    monkeypatch.setattr(sp, "run", bad_run)
    cli = BwCli(fake_bw, appdata)
    with pytest.raises(errors.ParseError):
        cli.list_items("sess")


# ---------------------------------------------------------------------------
# Consolidated from test_cleanup_hardening_v023.py (encode stdin part)
# ---------------------------------------------------------------------------

def test_encode_uses_stdin():
    """Bug #2 fix (v0.2.3): bw encode must use stdin, not CLI argument."""
    import inspect
    from vaultwarden.bw_cli import BwCli
    src = inspect.getsource(BwCli.encode)
    assert "input=value" in src or "input=" in src
    assert '["encode", value]' not in src


def test_encode_roundtrip_via_fake_bw(bw_cli, appdata):
    """Functional proof of the stdin path against the fake bw binary."""
    import base64
    enc = bw_cli.encode("sess", "hello stdin world")
    assert base64.b64decode(enc).decode() == "hello stdin world"


# ---------------------------------------------------------------------------
# Consolidated from test_store_edit_v027.py (encode_item parts)
# ---------------------------------------------------------------------------

def test_encode_item_signature_simplified():
    """v0.2.7: encode_item takes only the item dict (no session/bw params)."""
    import inspect
    sig = inspect.signature(encode_item)
    assert list(sig.parameters.keys()) == ["item"], \
        f"Expected ['item'], got {list(sig.parameters.keys())}"


def test_encode_item_encodes_entire_json_with_stdlib_base64():
    """v0.2.7: encode_item produces standard base64 of the raw JSON."""
    import base64
    import json
    item = {"type": 1, "name": "test",
            "login": {"username": "a", "password": "b"}}
    blob = encode_item(item)

    # Must be valid base64
    decoded = base64.b64decode(blob).decode("utf-8")
    parsed = json.loads(decoded)

    # Decoded JSON must contain RAW values (no per-field double-encoding)
    assert parsed["name"] == "test"
    assert parsed["login"]["username"] == "a"
    assert parsed["login"]["password"] == "b"


def test_encode_item_handles_unicode():
    """v0.2.7: UTF-8 round-trip must preserve non-ASCII characters."""
    import base64
    import json
    item = {"type": 1, "name": "árvíztűrő tükörfúrógép",
            "login": {"username": "ü"}}
    blob = encode_item(item)
    decoded = base64.b64decode(blob).decode("utf-8")
    parsed = json.loads(decoded)
    assert parsed["name"] == "árvíztűrő tükörfúrógép"
    assert parsed["login"]["username"] == "ü"


def test_encode_item_drops_empty_values():
    """v0.2.7: None/empty values must be omitted from the payload."""
    import base64
    import json
    item = {"type": 1, "name": "test", "notes": "", "folderId": None,
            "login": {"username": "a"}}
    parsed = json.loads(base64.b64decode(encode_item(item)).decode("utf-8"))
    assert "notes" not in parsed
    assert "folderId" not in parsed


def test_edit_item_signature_includes_item_id():
    """v0.2.7: bw_cli.edit_item must accept item_id as a positional arg."""
    import inspect
    sig = inspect.signature(BwCli.edit_item)
    params = list(sig.parameters.keys())
    assert "item_id" in params, f"edit_item params: {params}"

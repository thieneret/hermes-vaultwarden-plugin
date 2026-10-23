"""Unit tests: bw CLI wrapper — isolated env, JSON parsing, error mapping."""
from __future__ import annotations

import os

import pytest

from vaultwarden import errors
from vaultwarden.bw_cli import (
    BwCli,
    encode_item,
    find_bw_binary,
    validate_bw_path,
)


def test_find_bw_binary_explicit(fake_bw):
    assert find_bw_binary(fake_bw) == fake_bw


def test_find_bw_binary_missing(tmp_path, monkeypatch):
    """VWP-01: empty path -> None. No PATH fallback, no BW_CLI_PATH env."""
    monkeypatch.setenv("PATH", str(tmp_path))  # empty dir -> no bw
    monkeypatch.delenv("BW_CLI_PATH", raising=False)
    assert find_bw_binary("") is None


def test_find_bw_binary_no_path_fallback(tmp_path, monkeypatch):
    """VWP-01 BREAKING: even with a valid 'bw' on PATH, lookup must not find it."""
    planted = tmp_path / "bw"
    planted.write_text("#!/bin/sh\necho ok\n")
    planted.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("BW_CLI_PATH", str(planted))
    assert find_bw_binary("") is None       # env override removed too
    assert find_bw_binary(str(planted)) == str(planted)  # explicit still works


# ------------------------------------------------------------- VWP-01 rules
class TestValidateBwPath:
    """validate_bw_path(): strict binary-path pinning rules (VWP-01)."""

    def test_valid_path_accepted(self, fake_bw):
        assert validate_bw_path(fake_bw) == os.path.abspath(fake_bw)

    def test_empty_rejected(self):
        with pytest.raises(errors.ConfigError, match="required"):
            validate_bw_path("")
        with pytest.raises(errors.ConfigError, match="required"):
            validate_bw_path("   ")

    def test_relative_rejected(self, fake_bw):
        with pytest.raises(errors.BinaryError, match="absolute"):
            validate_bw_path("./bw")

    def test_file_symlink_rejected(self, fake_bw, tmp_path):
        link = tmp_path / "bw-link"
        link.symlink_to(fake_bw)
        with pytest.raises(errors.BinaryError, match="symlink"):
            validate_bw_path(str(link))

    def test_parent_dir_symlink_rejected(self, fake_bw, tmp_path):
        realdir = tmp_path / "realbin"
        realdir.mkdir()
        moved = realdir / "bw"
        os.rename(fake_bw, moved)
        dirlink = tmp_path / "binlink"
        dirlink.symlink_to(realdir, target_is_directory=True)
        with pytest.raises(errors.BinaryError, match="symlink"):
            validate_bw_path(str(dirlink / "bw"))

    def test_not_regular_file_rejected(self, tmp_path):
        with pytest.raises(errors.BinaryError, match="regular file"):
            validate_bw_path(str(tmp_path))          # directory

    def test_non_executable_rejected(self, tmp_path):
        p = tmp_path / "bw-noexec"
        p.write_text("#!/bin/sh\n")
        p.chmod(0o644)
        with pytest.raises(errors.BinaryError, match="executable"):
            validate_bw_path(str(p))

    def test_group_writable_rejected(self, tmp_path):
        p = tmp_path / "bw-grp"
        p.write_text("#!/bin/sh\n")
        p.chmod(0o775)
        with pytest.raises(errors.BinaryError, match="group/world-writable"):
            validate_bw_path(str(p))

    def test_world_writable_rejected(self, tmp_path):
        p = tmp_path / "bw-oth"
        p.write_text("#!/bin/sh\n")
        p.chmod(0o777)
        with pytest.raises(errors.BinaryError, match="group/world-writable"):
            validate_bw_path(str(p))

    @pytest.mark.skipif(os.geteuid() != 0, reason="needs root to chown")
    def test_wrong_owner_rejected(self, tmp_path):
        nobody = None
        try:
            import pwd
            nobody = pwd.getpwnam("nobody").pw_uid
        except KeyError:
            pass
        if nobody is None or nobody in (0, os.geteuid()):
            pytest.skip("no usable foreign uid available")
        p = tmp_path / "bw-owner"
        p.write_text("#!/bin/sh\n")
        p.chmod(0o755)
        os.chown(p, nobody, -1)
        with pytest.raises(errors.BinaryError, match="owner"):
            validate_bw_path(str(p))

    @pytest.mark.skipif(os.geteuid() != 0, reason="needs root to chown")
    def test_euid_owner_accepted(self, tmp_path):
        p = tmp_path / "bw-euid"
        p.write_text("#!/bin/sh\n")
        p.chmod(0o755)
        os.chown(p, os.geteuid(), -1)
        assert validate_bw_path(str(p)) == str(p)

    def test_find_bw_binary_returns_none_on_invalid(self, tmp_path):
        bad = tmp_path / "bw"           # nonexistent absolute path
        assert find_bw_binary(str(bad)) is None

    def test_find_bw_binary_uses_no_shutil_which(self):
        """VWP-01: shutil.which must be gone from bw_cli entirely."""
        import inspect
        import vaultwarden.bw_cli as mod
        src = inspect.getsource(mod)
        assert "shutil.which" not in src
        assert not hasattr(mod, "shutil")


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
    import base64
    import json
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


def test_network_error_retries_with_backoff(fake_bw, appdata, monkeypatch):
    """VWP-10: ECONNREFUSED -> up to max_retries attempts with backoff delays."""
    import subprocess as sp

    calls = {"n": 0}

    def counting_run(cmd, *a, **k):
        # VWP-11: __init__ runs `bw --version` first — satisfy the startup
        # version check with a mock so the retry counter only sees the
        # actual command invocations.
        if str(cmd[0]) == fake_bw and list(cmd[1:]) == ["--version"]:
            from unittest.mock import MagicMock
            v = MagicMock()
            v.returncode = 0
            v.stdout = "2026.9.1"
            v.stderr = ""
            return v
        calls["n"] += 1
        # Every attempt simulates the unreachable server: initial call plus
        # all bw_max_retries retries must fail for the contract
        # "retry N times, then NETWORK_ERROR" to hold.
        from unittest.mock import MagicMock
        m = MagicMock()
        m.returncode = 1
        m.stdout = ""
        m.stderr = "connect ECONNREFUSED 10.0.0.1:443"
        return m

    monkeypatch.setattr(sp, "run", counting_run)
    sleeps: list[float] = []
    monkeypatch.setattr("time.sleep", lambda s=None, *_: sleeps.append(s))
    cli = BwCli(fake_bw, appdata)
    with pytest.raises(errors.NetworkError):
        cli.status()
    # default max_retries=3 → initial + 3 retries = 4 subprocess calls
    assert calls["n"] == 4
    assert len(sleeps) == 3
    # bounded exponential backoff with additive jitter: base=1.0, cap=10.0
    assert 1.0 <= sleeps[0] < 2.0
    assert 2.0 <= sleeps[1] < 3.0
    assert 4.0 <= sleeps[2] < 5.0


def test_malformed_json_falls_back_to_raw(fake_bw, appdata, monkeypatch):
    """VWP-09: JSON-prefixed garbage no longer raises ParseError — run()
    falls back to the raw string (logged at debug level)."""
    import subprocess as sp
    from unittest.mock import MagicMock

    real_run = sp.run

    def bad_run(*a, **k):
        # VWP-11: let the `bw --version` startup check through via the real
        # fake binary; every other command returns malformed JSON.
        # run() passes the command positionally as a list; _check_version
        # passes it as the `cmd=` keyword — handle both shapes.
        cmd = a[0] if a else k.get("cmd")
        if cmd is not None and str(cmd[0]) == fake_bw and list(cmd[1:]) == ["--version"]:
            return real_run(*a, **k)
        m = MagicMock()
        m.returncode = 0
        m.stderr = ""
        m.stdout = "{not json at all"
        return m

    monkeypatch.setattr(sp, "run", bad_run)
    cli = BwCli(fake_bw, appdata)
    # non-list payload degrades to [] in list_items — no exception raised
    assert cli.list_items("sess") == []


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


# ---------------------------------------------------------------------------
# VWP-11 (v0.3.8): bw CLI version enforcement at startup (fail-closed, no
# override). The minimum version is a hardcoded module constant — NOT a
# configuration option. base_env() is a strict allowlist, so the fake bw's
# version output is steered via a marker PATH dir ("<ver>=VWFAKEVERSION").
# ---------------------------------------------------------------------------

def _fake_version_path(tmp_path, monkeypatch, version: str) -> None:
    """Make the fake bw binary report `version` for `bw --version`."""
    marker = tmp_path / f"{version}=VWFAKEVERSION"
    marker.mkdir(exist_ok=True)
    monkeypatch.setenv("PATH", f"{marker}{os.pathsep}{os.environ['PATH']}")


def _version_run(monkeypatch, stdout: str = "2026.9.1", returncode: int = 0,
                 side_effect=None):
    """Patch subprocess.run so ONLY the `bw --version` startup check runs."""
    import subprocess as sp
    from unittest.mock import MagicMock

    calls = []

    def fake_run(cmd, **kw):
        calls.append((cmd, kw))
        if side_effect is not None:
            raise side_effect
        m = MagicMock()
        m.returncode = returncode
        m.stdout = stdout
        m.stderr = ""
        return m

    monkeypatch.setattr(sp, "run", fake_run)
    return calls


class TestBwVersionValidation:
    def test_valid_version_passes(self, fake_bw, appdata, tmp_path, monkeypatch):
        _fake_version_path(tmp_path, monkeypatch, "2026.9.1")
        cli = BwCli(fake_bw, appdata)  # no exception
        assert cli.bw_version == "2026.9.1"

    def test_newer_version_passes(self, fake_bw, appdata, tmp_path, monkeypatch):
        _fake_version_path(tmp_path, monkeypatch, "2027.1.0")
        cli = BwCli(fake_bw, appdata)
        assert cli.bw_version == "2027.1.0"

    def test_version_below_minimum_raises(self, fake_bw, appdata, tmp_path, monkeypatch):
        _fake_version_path(tmp_path, monkeypatch, "2026.8.0")
        with pytest.raises(errors.UnsupportedBwVersionError) as ei:
            BwCli(fake_bw, appdata)
        assert ei.value.code == "UNSUPPORTED_BW_VERSION"

    def test_much_older_version_raises(self, fake_bw, appdata, tmp_path, monkeypatch):
        _fake_version_path(tmp_path, monkeypatch, "2024.1.0")
        with pytest.raises(errors.UnsupportedBwVersionError):
            BwCli(fake_bw, appdata)

    def test_unparseable_version_raises(self, fake_bw, appdata, tmp_path, monkeypatch):
        _fake_version_path(tmp_path, monkeypatch, "not-a-version")
        with pytest.raises(errors.UnsupportedBwVersionError):
            BwCli(fake_bw, appdata)

    def test_nightly_suffix_raises(self, fake_bw, appdata, tmp_path, monkeypatch):
        # int("1-nightly") fails -> fail-closed, no override.
        _fake_version_path(tmp_path, monkeypatch, "2026.9.1-nightly")
        with pytest.raises(errors.UnsupportedBwVersionError):
            BwCli(fake_bw, appdata)

    def test_empty_version_raises(self, fake_bw, appdata, monkeypatch):
        calls = _version_run(monkeypatch, stdout="")  # rc=0, empty stdout
        with pytest.raises(errors.UnsupportedBwVersionError):
            BwCli(fake_bw, appdata)
        assert len(calls) == 1

    def test_single_component_raises(self, fake_bw, appdata, tmp_path, monkeypatch):
        # "2026" has fewer than 2 dot-separated components -> unparseable.
        _fake_version_path(tmp_path, monkeypatch, "2026")
        with pytest.raises(errors.UnsupportedBwVersionError):
            BwCli(fake_bw, appdata)

    def test_version_check_uses_isolated_env(self, fake_bw, appdata, monkeypatch):
        calls = _version_run(monkeypatch, stdout="2026.9.1\n")
        monkeypatch.setenv("VW_MASTER_PASSWORD", "leaky")
        cli = BwCli(fake_bw, appdata)
        assert len(calls) == 1
        cmd, kw = calls[0]
        assert cmd == [fake_bw, "--version"]
        env = kw["env"]
        # base_env(): minimal allowlist, parent env NEVER inherited.
        assert set(env) <= {"PATH", "HOME", "BITWARDENCLI_APPDATA_DIR"}
        assert env["BITWARDENCLI_APPDATA_DIR"] == str(appdata)
        assert "VW_MASTER_PASSWORD" not in env
        assert kw["timeout"] == 5
        assert cli.bw_version == "2026.9.1"

    def test_version_check_timeout(self, fake_bw, appdata, monkeypatch):
        import subprocess as sp
        calls = _version_run(monkeypatch,
                             side_effect=sp.TimeoutExpired(cmd="bw", timeout=5))
        with pytest.raises(errors.BinaryError):
            BwCli(fake_bw, appdata)
        assert len(calls) == 1

    def test_version_check_nonzero_exit(self, fake_bw, appdata, monkeypatch):
        calls = _version_run(monkeypatch, stdout="", returncode=1)
        with pytest.raises(errors.BinaryError):
            BwCli(fake_bw, appdata)
        assert len(calls) == 1

    def test_version_property_exposed(self, fake_bw, appdata, tmp_path, monkeypatch):
        _fake_version_path(tmp_path, monkeypatch, "2026.9.1")
        cli = BwCli(fake_bw, appdata)
        assert isinstance(BwCli.bw_version, property)
        assert cli.bw_version == "2026.9.1"

    def test_min_version_is_constant_not_config(self):
        from vaultwarden import config
        from vaultwarden.bw_cli import _MIN_BW_VERSION
        assert _MIN_BW_VERSION == (2026, 9, 1)
        assert not hasattr(config, "min_bw_version")
        assert not hasattr(config.PluginConfig, "min_bw_version")

    def test_no_break_glass_option(self):
        from vaultwarden import config
        assert not hasattr(config, "allow_untested_bw_version")
        assert not hasattr(config.PluginConfig, "allow_untested_bw_version")
        # No packaging dependency: parsing is manual tuple(int(...)).
        import inspect

        import vaultwarden.bw_cli as mod
        src = inspect.getsource(mod)
        assert "import packaging" not in src
        assert "from packaging" not in src


# ---------------------------------------------------------------------------
# VWP-09 (v0.3.8): structured error classification by source category.
# Priority: Cat-2 Node.js network → rate_limit → Cat-1 bw state →
# Cat-3 server API → unknown. Fail-closed fallback is "unknown".
# ---------------------------------------------------------------------------

class TestErrorClassification:
    @pytest.mark.parametrize("msg,expected", [
        ("ECONNREFUSED", "network"),
        ("connect ETIMEDOUT 1.2.3.4:443", "network"),
        ("fetch failed", "network"),
        ("socket hang up", "network"),
        ("502 Bad Gateway", "network"),
        ("503 Service Unavailable", "network"),
        ("504 Gateway Timeout", "network"),
        ("Too many requests", "rate_limit"),
        ("429", "rate_limit"),
        ("You are not logged in", "session"),
        ("Vault is locked", "session"),
        ("Session has timed out.", "session"),
        ("Please log in first", "session"),
        ("Invalid master password.", "session"),
        ("Cannot find", "not_found"),
        ("does not exist", "not_found"),
        ("some random error", "unknown"),
    ])
    def test_classify_error(self, bw_cli, msg, expected):
        assert bw_cli._classify_error(msg.lower()) == expected

    def test_network_priority_over_session(self, bw_cli):
        # Cat-2 wins over Cat-1 markers in the same message.
        combined = "connect econnrefused ... vault is locked".lower()
        assert bw_cli._classify_error(combined) == "network"

    def test_rate_limit_priority_over_session(self, bw_cli):
        combined = "429 too many requests ... you are not logged in".lower()
        assert bw_cli._classify_error(combined) == "rate_limit"

    def test_marker_lists_expanded(self):
        from vaultwarden import bw_cli as mod
        assert len(mod._SESSION_INVALID_MARKERS) >= 10
        assert len(mod._NODE_NETWORK_MARKERS) >= 10

    def test_parse_output_valid_json(self, bw_cli):
        assert bw_cli._parse_output('{"a": 1}', ["get"]) == {"a": 1}
        assert bw_cli._parse_output('[1, 2]', ["list"]) == [1, 2]

    def test_parse_output_invalid_json_fallback(self, bw_cli, caplog):
        with caplog.at_level("DEBUG"):
            result = bw_cli._parse_output('{"broken', ["list"])
        assert result == '{"broken'  # raw string, NO ParseError raised
        assert any("non-JSON" in r.getMessage() for r in caplog.records)

    def test_parse_output_non_json_prefix(self, bw_cli):
        assert bw_cli._parse_output("plain text", ["unlock"]) == "plain text"

    def test_parse_output_empty(self, bw_cli):
        assert bw_cli._parse_output("", ["status"]) is None

    def test_unknown_error_rich_debug(self, bw_cli, monkeypatch, caplog):
        import subprocess as sp
        from unittest.mock import MagicMock
        m = MagicMock()
        m.returncode = 7
        m.stdout = ""
        m.stderr = "some random failure detail"
        monkeypatch.setattr(sp, "run", lambda *a, **k: m)
        monkeypatch.delenv("BW_TEST_FORCE_STDERR", raising=False)
        with caplog.at_level("DEBUG"), pytest.raises(errors.VaultwardenError):
            bw_cli.run(["report", "xyz"])
        msgs = [r.getMessage() for r in caplog.records]
        joined = " | ".join(msgs)
        assert "rc=7" in joined
        assert "category=unknown" in joined
        assert "some random failure detail" in joined


# ---------------------------------------------------------------------------
# VWP-10 (v0.3.8): bounded exponential backoff + jitter, restricted to
# idempotent operations. Non-idempotent callers pass retryable=False.
# ---------------------------------------------------------------------------

def _mk_run(version_stdout="2026.9.1", cmd_results=None, default_rc=0,
            default_out="", default_err=""):
    """subprocess.run stand-in: first call = bw --version, then sequenced."""
    from unittest.mock import MagicMock

    seq = list(cmd_results or [])
    calls = []

    def fake_run(cmd, *a, **k):
        calls.append(list(cmd))
        m = MagicMock()
        if list(cmd)[1:] == ["--version"]:
            m.returncode = 0
            m.stdout = version_stdout
            m.stderr = ""
            return m
        if seq:
            spec = seq.pop(0)
        else:
            spec = {}
        m.returncode = spec.get("rc", default_rc)
        m.stdout = spec.get("out", default_out)
        m.stderr = spec.get("err", default_err)
        return m

    return fake_run, calls


_NET_ERR = {"rc": 1, "out": "", "err": "connect ECONNREFUSED 10.0.0.1:443"}
_SESS_ERR = {"rc": 1, "out": "", "err": "You are not logged in."}
_RL_ERR = {"rc": 1, "out": "", "err": "429 Too Many Requests"}
_OK = {"rc": 0, "out": '{"status": "unauthenticated"}', "err": ""}
_OK_RAW = {"rc": 0, "out": "sessionkey123", "err": ""}


class TestExponentialBackoff:
    def _cli(self, fake_bw, appdata, monkeypatch, **kw):
        import subprocess as sp
        fake_run, calls = _mk_run(default_err="")
        monkeypatch.setattr(sp, "run", fake_run)
        monkeypatch.setattr("time.sleep", lambda s=None, *_: None)
        cli = BwCli(fake_bw, appdata, **kw)
        return cli, calls

    def test_backoff_formula_attempt_0(self, fake_bw, appdata, monkeypatch):
        cli, _ = self._cli(fake_bw, appdata, monkeypatch)
        d = cli._compute_backoff(0)
        assert 1.0 <= d < 2.0

    def test_backoff_formula_attempt_1(self, fake_bw, appdata, monkeypatch):
        cli, _ = self._cli(fake_bw, appdata, monkeypatch)
        d = cli._compute_backoff(1)
        assert 2.0 <= d < 3.0

    def test_backoff_formula_attempt_2(self, fake_bw, appdata, monkeypatch):
        cli, _ = self._cli(fake_bw, appdata, monkeypatch)
        d = cli._compute_backoff(2)
        assert 4.0 <= d < 5.0

    def test_backoff_bounded_by_max_delay(self, fake_bw, appdata, monkeypatch):
        cli, _ = self._cli(fake_bw, appdata, monkeypatch)
        assert cli._compute_backoff(10) <= 10.0

    def test_retry_only_on_network(self, fake_bw, appdata, monkeypatch):
        import subprocess as sp
        fake_run, calls = _mk_run(cmd_results=[dict(_SESS_ERR)])
        monkeypatch.setattr(sp, "run", fake_run)
        sleeps: list[float] = []
        monkeypatch.setattr("time.sleep", lambda s=None, *_: sleeps.append(s))
        cli = BwCli(fake_bw, appdata)
        with pytest.raises(errors.SessionError):
            cli.run(["list", "items"])
        assert sleeps == []           # session errors never retried
        assert len(calls) == 2        # version check + single attempt

    def test_retry_only_when_idempotent(self, fake_bw, appdata, monkeypatch):
        import subprocess as sp
        fake_run, calls = _mk_run(cmd_results=[dict(_NET_ERR)])
        monkeypatch.setattr(sp, "run", fake_run)
        sleeps: list[float] = []
        monkeypatch.setattr("time.sleep", lambda s=None, *_: sleeps.append(s))
        cli = BwCli(fake_bw, appdata)
        with pytest.raises(errors.NetworkError):
            cli.run(["status"], retryable=False)
        assert sleeps == []           # retryable=False → no retry at all
        assert len(calls) == 2

    def test_max_retries_respected(self, fake_bw, appdata, monkeypatch):
        import subprocess as sp
        # 3 retries allowed → initial + 3 failing attempts, then NetworkError
        fake_run, calls = _mk_run(cmd_results=[dict(_NET_ERR) for _ in range(4)])
        monkeypatch.setattr(sp, "run", fake_run)
        sleeps: list[float] = []
        monkeypatch.setattr("time.sleep", lambda s=None, *_: sleeps.append(s))
        cli = BwCli(fake_bw, appdata, max_retries=3)
        with pytest.raises(errors.NetworkError):
            cli.run(["status"])
        assert len(calls) == 5        # version + 1 initial + 3 retries
        assert len(sleeps) == 3

    def test_retry_succeeds_after_transient_network_error(self, fake_bw, appdata, monkeypatch):
        import subprocess as sp
        fake_run, calls = _mk_run(cmd_results=[dict(_NET_ERR), dict(_OK)])
        monkeypatch.setattr(sp, "run", fake_run)
        sleeps: list[float] = []
        monkeypatch.setattr("time.sleep", lambda s=None, *_: sleeps.append(s))
        cli = BwCli(fake_bw, appdata)
        data = cli.run(["status"])
        assert data == {"status": "unauthenticated"}
        assert len(sleeps) == 1
        assert 1.0 <= sleeps[0] < 2.0

    @pytest.mark.parametrize("call_fn,cmd_seq", [
        pytest.param(lambda cli: cli.login_apikey("id", "secret"),
                     [dict(_NET_ERR)], id="login_apikey"),
        pytest.param(lambda cli: cli.unlock_passwordenv("mp"),
                     [dict(_NET_ERR)], id="unlock_passwordenv"),
        pytest.param(lambda cli: cli.create_attachment("sess", "/tmp/f", "item1"),
                     [dict(_NET_ERR)], id="create_attachment"),
        pytest.param(lambda cli: cli.delete_item("sess", "item1"),
                     [dict(_NET_ERR)], id="delete_item"),
        pytest.param(lambda cli: cli.delete_attachment("sess", "att1", "item1"),
                     [dict(_NET_ERR)], id="delete_attachment"),
    ])
    def test_non_idempotent_callers_not_retried(self, fake_bw, appdata,
                                                monkeypatch, call_fn, cmd_seq):
        import subprocess as sp
        fake_run, calls = _mk_run(cmd_results=list(cmd_seq))
        monkeypatch.setattr(sp, "run", fake_run)
        sleeps: list[float] = []
        monkeypatch.setattr("time.sleep", lambda s=None, *_: sleeps.append(s))
        cli = BwCli(fake_bw, appdata)
        with pytest.raises(errors.NetworkError):
            call_fn(cli)
        assert sleeps == []           # VWP-10: never retried
        assert len(calls) == 2        # version check + exactly one attempt

    @pytest.mark.parametrize("call_fn", [
        pytest.param(lambda cli: cli.status(), id="status"),
        pytest.param(lambda cli: cli.sync("sess"), id="sync"),
    ])
    def test_idempotent_callers_retried(self, fake_bw, appdata, monkeypatch, call_fn):
        import subprocess as sp
        fake_run, calls = _mk_run(cmd_results=[dict(_NET_ERR), dict(_OK)])
        monkeypatch.setattr(sp, "run", fake_run)
        sleeps: list[float] = []
        monkeypatch.setattr("time.sleep", lambda s=None, *_: sleeps.append(s))
        cli = BwCli(fake_bw, appdata)
        call_fn(cli)
        assert len(sleeps) == 1       # retried once, then succeeded
        assert len(calls) == 3        # version + initial + retry

    def test_rate_limit_not_retried(self, fake_bw, appdata, monkeypatch):
        import subprocess as sp
        fake_run, calls = _mk_run(cmd_results=[dict(_RL_ERR)])
        monkeypatch.setattr(sp, "run", fake_run)
        sleeps: list[float] = []
        monkeypatch.setattr("time.sleep", lambda s=None, *_: sleeps.append(s))
        cli = BwCli(fake_bw, appdata)
        with pytest.raises(errors.RateLimitError):
            cli.run(["status"])
        assert sleeps == []           # raised immediately, never retried
        assert len(calls) == 2

    def test_bw_test_force_stderr_hook_still_works(self, bw_cli, monkeypatch):
        # v0.1.4 hook preserved: injected stderr is classified by VWP-09.
        monkeypatch.setenv("BW_TEST_FORCE_STDERR", "vault is locked")
        with pytest.raises(errors.SessionError):
            bw_cli.run(["list", "items"], env={"BW_SESSION": "stale"})

    def test_init_signature_has_retry_params(self):
        import inspect
        sig = inspect.signature(BwCli.__init__)
        for name in ("max_retries", "backoff_base", "max_delay"):
            assert name in sig.parameters, f"missing param: {name}"
        # Step-2 invariant: NO version-related constructor params.
        assert "min_bw_version" not in sig.parameters
        assert "allow_untested_bw_version" not in sig.parameters

    def test_no_forbidden_retry_deps(self):
        import inspect

        import vaultwarden.bw_cli as mod
        src = inspect.getsource(mod)
        assert "tenacity" not in src
        assert "import random" in src

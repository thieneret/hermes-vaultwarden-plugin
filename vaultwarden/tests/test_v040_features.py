"""v0.4.0 feature tests: secret input channels + SSH keypair generation.

Feature 1 (_resolve_secret_input): raw / *_env / *_file channels with a
dual-channel warning (log + response field) on raw direct input, strict
owner-only file permission validation, conflicts rejected as ConfigError.

Feature 2 (_generate_ssh_keypair + generate=true on store_ssh/update_ssh):
passphrase delivered to ssh-keygen via the SSH_ASKPASS mechanism (never
stdin, never -N argv — v0.4.1 hotfix), post-generation encryption verify
aborts on an unencrypted key, single secret-generation path
(_generate_password -> `bw generate`), public key + fingerprint returned,
private key/passphrase NEVER returned, rotation requires confirm=true.
"""
import json
import os
import stat
from unittest.mock import MagicMock, patch

import pytest

from vaultwarden import errors
from vaultwarden.auth import AuthManager, AuthState
from vaultwarden.placeholders import PlaceholderRegistry
from vaultwarden.tests.conftest import make_config
from vaultwarden.tools import (
    _ASKPASS_SCRIPT_BODY,
    _DIRECT_SECRET_WARNING,
    _askpass_env,
    _generate_ssh_keypair,
    _make_askpass_script,
    _resolve_secret_input,
)

GEN_PW = "Zk9#xQ2vLm8pRt4wYb7nKp3mQs8vXc1d"   # deterministic fake passphrase


def _dict_tools(auth, cfg, registry):
    from vaultwarden.tools import get_tools as gt

    def wrap(handler):
        def inner(args, **kw):
            result = handler(args, **kw)
            return json.loads(result) if isinstance(result, str) else result
        return inner

    return {schema["name"]: wrap(handler) for schema, handler in
            gt(auth, cfg, registry)}


class FakeBw:
    """Minimal bw stand-in capturing generate/create/edit calls."""

    def __init__(self, items=None):
        self._items = list(items or [])
        self.generate_calls: list[list[str]] = []
        self.created_items: list[dict] = []
        self.edited_items: list[dict] = []
        self.attach_created: list[tuple[str, str]] = []
        self.attach_deleted: list[tuple[str, str]] = []

    def list_items(self, session, filters=None):
        return [dict(i) for i in self._items]

    def generate_password(self, session_key, args):
        self.generate_calls.append(list(args))
        return GEN_PW

    def create_item(self, session, blob):
        import base64
        item = json.loads(base64.b64decode(blob).decode("utf-8"))
        item["id"] = "new-item-id-0001"
        self.created_items.append(item)
        return item

    def edit_item(self, session, item_id, blob):
        import base64
        item = json.loads(base64.b64decode(blob).decode("utf-8"))
        item["id"] = item_id
        self.edited_items.append(item)
        return item

    def create_attachment(self, session, file_path, item_id):
        self.attach_created.append((file_path, item_id))
        return {"id": "att-new"}

    def delete_attachment(self, session, att_id, item_id):
        self.attach_deleted.append((att_id, item_id))


def _fake_auth(existing_items=None):
    """AuthManager wired to FakeBw + monkeypatched high-level methods.

    edit_item is bound to the *real* AuthManager method so tests can assert
    on what actually reaches the (fake) bw layer via bw.edited_items.
    """
    bw = FakeBw(existing_items)
    cfg = make_config(section={"allow_write": True})
    auth = AuthManager.__new__(AuthManager)
    auth._bw = bw                                    # noqa: SLF001
    auth._config = cfg                               # noqa: SLF001
    auth._state = AuthState.UNLOCKED                 # noqa: SLF001
    auth._session_key = "SESSION"                    # noqa: SLF001
    auth.run_with_recovery = lambda fn: fn("sess")   # type: ignore[attr-defined]
    auth.get_session = lambda: "sess"                # type: ignore[attr-defined]
    auth.create_item = lambda item: dict(item, id="new-item-id-0001")
    auth.get_item = lambda iid: {"id": iid, "name": "svc", "login": {}}
    auth.edit_item = AuthManager.edit_item.__get__(auth)  # real path -> FakeBw
    created = {}

    def _create_ssh_item(name, user, password, key_path):
        created["args"] = (name, user, password, key_path)
        return {"id": "ssh-item-1", "name": name}
    auth.create_ssh_item = _create_ssh_item          # type: ignore[attr-defined]
    auth._created_ssh = created                      # noqa: SLF001
    return auth


# ── _resolve_secret_input: unit ──────────────────────────────────────────

def test_rsi_direct_returns_value_and_warning():
    secret = "raw-secret-value-XYZ"
    with patch("vaultwarden.tools.log.warning") as mock_warn:
        val, warning = _resolve_secret_input(
            {"password": secret}, direct_key="password",
            env_key="password_env", file_key="password_file",
            tool_name="vaultwarden_store")
    assert val == secret
    assert warning is not None
    # dual channel: log.warning fired AND non-secret advisory returned
    mock_warn.assert_called_once()
    assert secret not in warning
    assert "password_env" in warning and "password_file" in warning


def test_rsi_env_set(monkeypatch):
    monkeypatch.setenv("VW_TEST_PW", "from-env")
    val, warning = _resolve_secret_input(
        {"password_env": "VW_TEST_PW"}, direct_key="password",
        env_key="password_env", file_key="password_file",
        tool_name="vaultwarden_store")
    assert val == "from-env"
    assert warning is None


def test_rsi_env_unset(monkeypatch):
    monkeypatch.delenv("VW_MISSING_VAR", raising=False)
    with pytest.raises(errors.ConfigError):
        _resolve_secret_input(
            {"password_env": "VW_MISSING_VAR"}, direct_key="password",
            env_key="password_env", file_key="password_file",
            tool_name="vaultwarden_store")


def test_rsi_file_good_mode(tmp_path):
    f = tmp_path / "secret.txt"
    f.write_text("  file-secret\n")
    f.chmod(0o600)
    val, warning = _resolve_secret_input(
        {"password_file": str(f)}, direct_key="password",
        env_key="password_env", file_key="password_file",
        tool_name="vaultwarden_store")
    assert val == "file-secret"
    assert warning is None


def test_rsi_file_bad_mode_group_readable(tmp_path):
    f = tmp_path / "secret.txt"
    f.write_text("nope")
    f.chmod(0o644)
    with pytest.raises(errors.ConfigError) as exc_info:
        _resolve_secret_input(
            {"password_file": str(f)}, direct_key="password",
            env_key="password_env", file_key="password_file",
            tool_name="vaultwarden_store")
    assert "readable only by the owner" in exc_info.value.message


def test_rsi_file_owner_unreadable(tmp_path):
    f = tmp_path / "secret.txt"
    f.write_text("nope")
    f.chmod(0o600)          # create readable, then strip owner read
    f.chmod(0o200)
    with pytest.raises(errors.ConfigError) as exc_info:
        _resolve_secret_input(
            {"password_file": str(f)}, direct_key="password",
            env_key="password_env", file_key="password_file",
            tool_name="vaultwarden_store")
    assert "not readable by the owner" in exc_info.value.message


def test_rsi_file_missing(tmp_path):
    with pytest.raises(errors.NotFoundError):
        _resolve_secret_input(
            {"password_file": str(tmp_path / "nope.txt")},
            direct_key="password", env_key="password_env",
            file_key="password_file", tool_name="vaultwarden_store")


def test_rsi_file_empty(tmp_path):
    f = tmp_path / "secret.txt"
    f.write_text("   \n")
    f.chmod(0o600)
    with pytest.raises(errors.ConfigError) as exc_info:
        _resolve_secret_input(
            {"password_file": str(f)}, direct_key="password",
            env_key="password_env", file_key="password_file",
            tool_name="vaultwarden_store")
    assert "is empty" in exc_info.value.message


def test_rsi_conflict_two_sources():
    with pytest.raises(errors.ConfigError) as exc_info:
        _resolve_secret_input(
            {"password": "x", "password_env": "Y"}, direct_key="password",
            env_key="password_env", file_key="password_file",
            tool_name="vaultwarden_store")
    assert "provide only ONE of" in exc_info.value.message


def test_rsi_none_provided():
    val, warning = _resolve_secret_input(
        {}, direct_key="password", env_key="password_env",
        file_key="password_file", tool_name="vaultwarden_store")
    assert val is None and warning is None


# ── _generate_ssh_keypair: mocked subprocess ─────────────────────────────

def _kp_run_factory(unencrypted=False, pub="ssh-ed25519 AAAAC3 public comment"):
    calls: list[tuple[list, dict]] = []

    def fake_run(cmd, **kw):
        calls.append((list(cmd), kw))
        if cmd[:2] == ["ssh-keygen", "-yf"]:
            rc = 0 if unencrypted else 1
            return MagicMock(returncode=rc, stdout="", stderr="")
        if "-lf" in cmd:
            return MagicMock(returncode=0,
                             stdout="256 SHA256:abc123fp comment (ed25519)\n")
        # main generation call: write the fake .pub file where -f points
        key_path = cmd[cmd.index("-f") + 1]
        with open(key_path + ".pub", "w", encoding="utf-8") as f:
            f.write(pub + "\n")
        with open(key_path, "w", encoding="utf-8") as f:
            f.write("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n")
        return MagicMock(returncode=0, stdout="", stderr="")

    fake_run.calls = calls
    return fake_run


def test_gen_keypair_passphrase_via_askpass_not_stdin_or_argv():
    """v0.4.1: keygen passphrase via SSH_ASKPASS env; stdin is DEVNULL."""
    import subprocess as _sp

    fake = _kp_run_factory()
    with patch("vaultwarden.tools.subprocess.run", side_effect=fake):
        tmpdir, key_path, public_key, fp = _generate_ssh_keypair(
            "ed25519", 4096, "comment", "the-passphrase-123")
    try:
        gen_cmd, gen_kw = fake.calls[0]
        dash_n = "-" + "N"  # argv passphrase flag is prohibited
        assert dash_n not in gen_cmd  # passphrase never delivered via argv
        assert "input" not in gen_kw                 # NO stdin delivery
        assert gen_kw["stdin"] is _sp.DEVNULL        # tty fallback impossible
        env = gen_kw["env"]
        assert env["SSH_ASKPASS_REQUIRE"] == "force"
        assert env["VW_SSH_PASS"] == "the-passphrase-123"
        # askpass script removed on the success path
        assert not os.path.exists(env["SSH_ASKPASS"])
        assert "-yf" in " ".join(fake.calls[1][0])       # verify call made
        assert fake.calls[1][1]["stdin"] is _sp.DEVNULL
        assert fake.calls[2][1]["stdin"] is _sp.DEVNULL  # fingerprint too
        assert public_key == "ssh-ed25519 AAAAC3 public comment"
        assert fp == "SHA256:abc123fp"
        assert os.path.isdir(tmpdir)                     # caller owns cleanup
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_gen_keypair_rsa_adds_bits_default_4096():
    fake = _kp_run_factory()
    with patch("vaultwarden.tools.subprocess.run", side_effect=fake):
        tmpdir, _, _, _ = _generate_ssh_keypair(
            "rsa", 4096, "c", "pp1234")
    try:
        gen_cmd = fake.calls[0][0]
        assert "-b" in gen_cmd and gen_cmd[gen_cmd.index("-b") + 1] == "4096"
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_gen_keypair_rsa_custom_bits():
    fake = _kp_run_factory(pub="ssh-rsa AAAAB3 public comment")
    with patch("vaultwarden.tools.subprocess.run", side_effect=fake):
        tmpdir, _, _, _ = _generate_ssh_keypair("rsa", 2048, "c", "pp1234")
    try:
        gen_cmd = fake.calls[0][0]
        assert gen_cmd[gen_cmd.index("-b") + 1] == "2048"
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_gen_keypair_unencrypted_key_aborts():
    """Verify rc==0 means UNENCRYPTED -> VaultwardenError, never stored."""
    fake = _kp_run_factory(unencrypted=True)
    with patch("vaultwarden.tools.subprocess.run", side_effect=fake):
        with pytest.raises(errors.VaultwardenError) as exc_info:
            _generate_ssh_keypair("ed25519", 4096, "c", "pp1234")
    assert "UNENCRYPTED" in exc_info.value.message


def test_gen_keypair_ssh_keygen_failure_raises():
    def fake_run(cmd, **kw):
        return MagicMock(returncode=1, stdout="", stderr="boom")
    with patch("vaultwarden.tools.subprocess.run", side_effect=fake_run):
        with pytest.raises(errors.VaultwardenError):
            _generate_ssh_keypair("ed25519", 4096, "c", "pp1234")


# ── single generation path (decision 1) ──────────────────────────────────

def test_no_secrets_module_in_tools():
    import inspect

    import vaultwarden.tools as t
    src = inspect.getsource(t)
    assert "secrets.token_urlsafe" not in src
    assert "_generate_passphrase" not in src
    assert 'import secrets' not in src


def test_ssh_generate_uses_bw_generate_path():
    """Both ssh generate branches route the passphrase through
    _generate_password(auth, {"mode": "password", "length": 32})."""
    import inspect

    import vaultwarden.tools as t
    src = inspect.getsource(t)
    assert src.count(
        '_generate_password(auth, {"mode": "password", "length": 32})'
    ) >= 2


# ── h_store_ssh generate=true ────────────────────────────────────────────

def _store_ssh_tools():
    auth = _fake_auth()
    tools = _dict_tools(auth, auth._config, PlaceholderRegistry())  # noqa: SLF001
    return auth, tools


def test_store_ssh_generate_forbids_secret_inputs():
    auth, tools = _store_ssh_tools()
    for k in ("pass", "pass_env", "pass_file", "file"):
        res = tools["vaultwarden_store_ssh"](
            {"name": "SSH - Gen", "generate": True, k: "x"})
        assert res["error_code"] == "CONFIG_ERROR", k
        assert "conflicts with" in res["error"]


def test_store_ssh_generate_bad_key_type():
    auth, tools = _store_ssh_tools()
    res = tools["vaultwarden_store_ssh"](
        {"name": "SSH - Gen", "generate": True, "key_type": "dsa"})
    assert res["error_code"] == "CONFIG_ERROR"
    assert "unsupported key_type" in res["error"]


def test_store_ssh_generate_success_response():
    auth, tools = _store_ssh_tools()
    fake = _kp_run_factory()
    with patch("vaultwarden.tools.subprocess.run", side_effect=fake):
        res = tools["vaultwarden_store_ssh"](
            {"name": "SSH - Gen", "user": "deploy", "generate": True})
    assert res["created"] is True
    assert res["public_key"].startswith("ssh-ed25519 ")
    assert res["fingerprint"] == "SHA256:abc123fp"
    assert res["passphrase_generated"] is True
    assert res["key_type"] == "ed25519"
    assert res["ssh_user"] == "deploy"
    assert "warning" not in res
    # private key + passphrase NEVER returned
    dumped = json.dumps(res)
    assert GEN_PW not in dumped
    assert "PRIVATE KEY" not in dumped or "public" in dumped
    assert "-----BEGIN OPENSSH PRIVATE KEY-----" not in dumped
    # create_ssh_item called with the GENERATED key path + generated pw
    name, user, pw, key_path = auth._created_ssh["args"]  # noqa: SLF001
    assert pw == GEN_PW
    assert "vw_sshgen_" in key_path
    assert not os.path.isdir(os.path.dirname(key_path))   # tmpdir cleaned up
    # bw generate flag syntax: --length 32
    assert auth._bw.generate_calls[-1][:2] == ["--length", "32"]  # noqa: SLF001


def test_store_ssh_upload_requires_passphrase_channel():
    auth, tools = _store_ssh_tools()
    res = tools["vaultwarden_store_ssh"]({"name": "SSH - Up", "user": "u",
                                          "file": "/tmp/k"})
    assert res["error_code"] == "CONFIG_ERROR"
    assert "requires pass, pass_env, pass_file" in res["error"]


def test_store_ssh_upload_raw_pass_dual_warning(tmp_path):
    key = tmp_path / "id_ed25519"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"
                   "-----END OPENSSH PRIVATE KEY-----\n")
    auth, tools = _store_ssh_tools()
    with patch("vaultwarden.tools.log.warning") as mock_warn:
        res = tools["vaultwarden_store_ssh"](
            {"name": "SSH - Up", "user": "deploy", "file": str(key),
             "pass": "raw-pass-123"})
    mock_warn.assert_called_once()
    assert "warning" in res
    assert "raw-pass-123" not in json.dumps(res)
    assert "pass_env" in res["warning"] and "pass_file" in res["warning"]
    assert res["created"] is True


def test_store_ssh_upload_pass_env(tmp_path, monkeypatch):
    key = tmp_path / "id_ed25519"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"
                   "-----END OPENSSH PRIVATE KEY-----\n")
    monkeypatch.setenv("VW_SSH_PASS", "env-pass")
    auth, tools = _store_ssh_tools()
    res = tools["vaultwarden_store_ssh"](
        {"name": "SSH - Up", "user": "deploy", "file": str(key),
         "pass_env": "VW_SSH_PASS"})
    assert res["created"] is True
    assert "warning" not in res
    assert auth._created_ssh["args"][2] == "env-pass"  # noqa: SLF001


def test_store_ssh_upload_pass_file(tmp_path):
    key = tmp_path / "id_ed25519"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"
                   "-----END OPENSSH PRIVATE KEY-----\n")
    pwfile = tmp_path / "pass.txt"
    pwfile.write_text("file-pass\n")
    pwfile.chmod(0o600)
    auth, tools = _store_ssh_tools()
    res = tools["vaultwarden_store_ssh"](
        {"name": "SSH - Up", "user": "deploy", "file": str(key),
         "pass_file": str(pwfile)})
    assert res["created"] is True
    assert auth._created_ssh["args"][2] == "file-pass"  # noqa: SLF001


# ── h_update_ssh ─────────────────────────────────────────────────────────

EXISTING_SSH = [{"id": "ssh-item-1", "name": "SSH - Rot",
                 "attachments": [{"id": "att-old", "name": "key"}]}]


def _update_ssh_tools():
    auth = _fake_auth(EXISTING_SSH)
    tools = _dict_tools(auth, auth._config, PlaceholderRegistry())  # noqa: SLF001
    return auth, tools


def test_update_ssh_generate_requires_confirm():
    auth, tools = _update_ssh_tools()
    res = tools["vaultwarden_update_ssh"]({"name": "SSH - Rot",
                                           "generate": True})
    assert res["error_code"] == "PERMISSION_ERROR"
    assert "confirm=true to rotate" in res["suggestion"]


def test_update_ssh_generate_forbids_secret_inputs():
    auth, tools = _update_ssh_tools()
    for k in ("pass", "pass_env", "pass_file", "file"):
        res = tools["vaultwarden_update_ssh"](
            {"name": "SSH - Rot", "generate": True, "confirm": True, k: "x"})
        assert res["error_code"] == "CONFIG_ERROR", k


def test_update_ssh_generate_rotates_key():
    auth, tools = _update_ssh_tools()
    fake = _kp_run_factory()
    with patch("vaultwarden.tools.subprocess.run", side_effect=fake):
        res = tools["vaultwarden_update_ssh"](
            {"name": "SSH - Rot", "generate": True, "confirm": True})
    assert res["updated"] is True
    assert res["public_key"].startswith("ssh-ed25519 ")
    assert res["passphrase_rotated"] is True
    assert "warning" not in res
    assert GEN_PW not in json.dumps(res)
    bw = auth._bw                                        # noqa: SLF001
    # attachment replaced: old deleted, new created
    assert bw.attach_deleted == [("att-old", "ssh-item-1")]
    assert len(bw.attach_created) == 1 and "vw_sshgen_" in bw.attach_created[0][0]
    # password updated to the generated passphrase
    assert bw.edited_items[0]["login"]["password"] == GEN_PW
    assert bw.generate_calls[-1][:2] == ["--length", "32"]


def test_update_ssh_upload_raw_pass_warning():
    auth, tools = _update_ssh_tools()
    with patch("vaultwarden.tools.log.warning") as mock_warn:
        res = tools["vaultwarden_update_ssh"](
            {"name": "SSH - Rot", "pass": "raw-new-pass"})
    mock_warn.assert_called_once()
    assert "warning" in res
    assert "raw-new-pass" not in json.dumps(res)
    assert auth._bw.edited_items[0]["login"]["password"] == "raw-new-pass"  # noqa: SLF001


def test_update_ssh_upload_pass_env(monkeypatch):
    auth, tools = _update_ssh_tools()
    monkeypatch.setenv("VW_ROT_PASS", "env-new-pass")
    res = tools["vaultwarden_update_ssh"](
        {"name": "SSH - Rot", "pass_env": "VW_ROT_PASS"})
    assert "warning" not in res
    assert auth._bw.edited_items[0]["login"]["password"] == "env-new-pass"  # noqa: SLF001


# ── h_store / h_update wiring (Feature 1) ────────────────────────────────

def test_store_password_env_resolved():
    auth = _fake_auth()
    tools = _dict_tools(auth, auth._config, PlaceholderRegistry())  # noqa: SLF001
    captured: dict = {}
    orig_create = auth.create_item

    def _create(item):
        captured["item"] = item
        return orig_create(item)
    auth.create_item = _create                           # type: ignore[attr-defined]
    with patch.dict(os.environ, {"GH_TOKEN": "gh-secret-xyz"}):
        res = tools["vaultwarden_store"](
            {"type": "login", "name": "env-test", "username": "u",
             "password_env": "GH_TOKEN"})
    assert res["created"] is True
    assert "warning" not in res
    assert captured["item"]["login"]["password"] == "gh-secret-xyz"
    assert "gh-secret-xyz" not in json.dumps(res)


def test_store_password_file_resolved(tmp_path):
    auth = _fake_auth()
    tools = _dict_tools(auth, auth._config, PlaceholderRegistry())  # noqa: SLF001
    captured: dict = {}
    orig_create = auth.create_item

    def _create(item):
        captured["item"] = item
        return orig_create(item)
    auth.create_item = _create                           # type: ignore[attr-defined]
    f = tmp_path / "pw.txt"
    f.write_text("file-pw\n")
    f.chmod(0o600)
    res = tools["vaultwarden_store"](
        {"type": "login", "name": "file-test", "username": "u",
         "password_file": str(f)})
    assert res["created"] is True
    assert captured["item"]["login"]["password"] == "file-pw"


def test_store_raw_password_response_warning():
    auth = _fake_auth()
    tools = _dict_tools(auth, auth._config, PlaceholderRegistry())  # noqa: SLF001
    with patch("vaultwarden.tools.log.warning") as mock_warn:
        res = tools["vaultwarden_store"](
            {"type": "login", "name": "raw-test", "username": "u",
             "password": "x-raw-secret"})
    mock_warn.assert_called_once()
    assert "warning" in res
    assert "x-raw-secret" not in json.dumps(res)
    assert "password_env" in res["warning"]


def test_store_password_conflict():
    auth = _fake_auth()
    tools = _dict_tools(auth, auth._config, PlaceholderRegistry())  # noqa: SLF001
    res = tools["vaultwarden_store"](
        {"type": "login", "name": "c", "username": "u",
         "password": "p", "password_env": "E"})
    assert res["error_code"] == "CONFIG_ERROR"
    assert "provide only ONE of" in res["error"]


def test_store_generate_conflicts_with_password_channels():
    auth = _fake_auth()
    tools = _dict_tools(auth, auth._config, PlaceholderRegistry())  # noqa: SLF001
    for k in ("password", "password_env", "password_file"):
        res = tools["vaultwarden_store"](
            {"type": "login", "name": "g", "generate": True, k: "x"})
        assert res["error_code"] == "CONFIG_ERROR", k
        assert "generate=true conflicts" in res["error"]


def test_update_generate_conflicts_with_password_channels():
    auth = _fake_auth()
    tools = _dict_tools(auth, auth._config, PlaceholderRegistry())  # noqa: SLF001
    for k in ("password", "password_env", "password_file"):
        res = tools["vaultwarden_update"](
            {"item_id": "i", "generate": True, k: "x"})
        assert res["error_code"] == "CONFIG_ERROR", k


def test_update_password_env_resolved():
    auth = _fake_auth()
    tools = _dict_tools(auth, auth._config, PlaceholderRegistry())  # noqa: SLF001
    captured: dict = {}
    orig_edit = auth.edit_item

    def _edit(item):
        captured["item"] = item
        return orig_edit(item)
    auth.edit_item = _edit                               # type: ignore[attr-defined]
    with patch.dict(os.environ, {"VW_UPD_PW": "upd-env-pw"}):
        res = tools["vaultwarden_update"](
            {"item_id": "aaaa1111-0000-0000-0000-000000000001",
             "password_env": "VW_UPD_PW"})
    assert res["updated"] is True
    assert captured["item"]["login"]["password"] == "upd-env-pw"


def test_update_raw_password_warning():
    auth = _fake_auth()
    tools = _dict_tools(auth, auth._config, PlaceholderRegistry())  # noqa: SLF001
    with patch("vaultwarden.tools.log.warning") as mock_warn:
        res = tools["vaultwarden_update"](
            {"item_id": "aaaa1111-0000-0000-0000-000000000001",
             "password": "raw-upd-secret"})
    mock_warn.assert_called_once()
    assert "warning" in res
    assert "raw-upd-secret" not in json.dumps(res)


# ── warning template safety ──────────────────────────────────────────────

def test_direct_warning_template_has_no_value_slot():
    # The template only interpolates parameter NAMES, never values.
    for slot in ("{key!r}", "{tool}", "{env_key!r}", "{file_key!r}"):
        assert slot in _DIRECT_SECRET_WARNING
    assert "{}" not in _DIRECT_SECRET_WARNING.replace("{key!r}", "") \
        .replace("{tool}", "").replace("{env_key!r}", "") \
        .replace("{file_key!r}", "")

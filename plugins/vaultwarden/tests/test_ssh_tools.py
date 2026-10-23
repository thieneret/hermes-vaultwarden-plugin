"""SSH tool tests: key validation, socket resolution, store/use safety.

Renamed from test_ssh_tools_v028.py in the v0.2.9 test consolidation.
"""
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vaultwarden import errors
from vaultwarden.auth import AuthManager, AuthState
from vaultwarden.placeholders import PlaceholderRegistry
from vaultwarden.tests.conftest import make_config
from vaultwarden.tools import (
    _ASKPASS_SCRIPT_BODY,
    _askpass_env,
    _generate_ssh_keypair,
    _make_askpass_script,
    _resolve_socket_path,
    _validate_ssh_key_file,
)

# ── SSH key file validation ──────────────────────────────────────────────

def test_validate_ssh_key_file_valid(tmp_path):
    key = tmp_path / "id_ed25519"
    key.write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA...\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )
    _validate_ssh_key_file(str(key))  # should not raise


def test_validate_ssh_key_file_not_found():
    with pytest.raises(errors.VaultwardenError) as exc_info:
        _validate_ssh_key_file("/nonexistent/key")
    assert exc_info.value.code == "NOT_FOUND"


def test_validate_ssh_key_file_not_ssh_key(tmp_path):
    f = tmp_path / "notakey.txt"
    f.write_text("Hello, this is not an SSH key.")
    with pytest.raises(errors.VaultwardenError) as exc_info:
        _validate_ssh_key_file(str(f))
    assert exc_info.value.code == "VALIDATION_ERROR"


# ── Socket resolution (VWP-02: developer-controlled, parameter-less) ─────

def test_resolve_socket_vw_env_var_running(tmp_path):
    """$VW_SSH_SOCKET_PATH set, agent running → reuse, no new agent."""
    sock_path = str(tmp_path / "vw-agent.sock")
    with patch.dict(os.environ, {"VW_SSH_SOCKET_PATH": sock_path}, clear=False):
        with patch("vaultwarden.tools.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)  # ssh-add -l OK
            sock, started = _resolve_socket_path()
            assert sock == os.path.abspath(sock_path)
            assert started is False
            # only the ssh-add probe ran — no ssh-agent spawn
            assert mock_run.call_count == 1
            assert mock_run.call_args_list[0][0][0] == ["ssh-add", "-l"]


def test_resolve_socket_vw_env_var_not_running(tmp_path):
    """$VW_SSH_SOCKET_PATH set, no agent → start agent at that path."""
    sock_path = str(tmp_path / "sub" / "vw-agent.sock")
    with patch.dict(os.environ, {"VW_SSH_SOCKET_PATH": sock_path}, clear=False):
        with patch("vaultwarden.tools.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=2),  # ssh-add -l → no agent
                MagicMock(returncode=0),  # ssh-agent -a → started
            ]
            sock, started = _resolve_socket_path()
            assert sock == os.path.abspath(sock_path)
            assert started is True
            agent_call = mock_run.call_args_list[1]
            assert agent_call[0][0][:2] == ["ssh-agent", "-a"]
            assert sock in agent_call[0][0]


def test_resolve_socket_fallback_xdg_runtime(tmp_path):
    """$VW_SSH_SOCKET_PATH unset → falls back to $XDG_RUNTIME_DIR/auth.sock."""
    with patch.dict(os.environ, {
            "VW_SSH_SOCKET_PATH": "",
            "XDG_RUNTIME_DIR": str(tmp_path)}, clear=False):
        with patch("vaultwarden.tools.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)  # agent running (no keys)
            sock, started = _resolve_socket_path()
            assert sock == os.path.join(str(tmp_path), "auth.sock")
            assert started is False


def test_resolve_socket_symlink_rejected(tmp_path):
    """Symlinked socket path → SECURITY_ERROR (path redirection guard)."""
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    link_dir = tmp_path / "link"
    link_dir.symlink_to(real_dir)
    sock_path = str(link_dir / "agent.sock")
    with patch.dict(os.environ, {"VW_SSH_SOCKET_PATH": sock_path}, clear=False):
        with patch("vaultwarden.tools.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=2)  # no agent → try start
            with pytest.raises(errors.VaultwardenError) as exc_info:
                _resolve_socket_path()
            assert exc_info.value.code == "SECURITY_ERROR"


# ── Stale socket cleanup (plugin startup) ────────────────────────────────

def test_cleanup_stale_sockets_removes_stale(tmp_path):
    """Socket file exists but no agent running → removed at startup."""
    from vaultwarden.hooks import _cleanup_stale_sockets
    stale = tmp_path / "auth.sock"
    stale.write_text("")  # placeholder file standing in for the socket
    with patch.dict(os.environ, {
            "VW_SSH_SOCKET_PATH": str(stale),
            "XDG_RUNTIME_DIR": ""}, clear=False):
        with patch("vaultwarden.hooks.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=2)  # agent not running
            _cleanup_stale_sockets()
    assert not stale.exists()


def test_cleanup_stale_sockets_keeps_active(tmp_path):
    """Agent running on the socket → file is NOT removed."""
    from vaultwarden.hooks import _cleanup_stale_sockets
    active = tmp_path / "auth.sock"
    active.write_text("")
    with patch.dict(os.environ, {
            "VW_SSH_SOCKET_PATH": str(active),
            "XDG_RUNTIME_DIR": ""}, clear=False):
        with patch("vaultwarden.hooks.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)  # agent running
            _cleanup_stale_sockets()
    assert active.exists()


# ── store_ssh name uniqueness ────────────────────────────────────────────

def test_store_ssh_rejects_duplicate_name():
    """store_ssh must reject if name already exists."""
    from vaultwarden.auth import AuthManager, AuthState
    bw = MagicMock()
    bw.list_items.return_value = [{"id": "existing", "name": "SSH - Prod"}]

    config = MagicMock()
    config.allow_write = True
    config.session_timeout_seconds = 14400

    auth = AuthManager(bw, config, client_secret="cs", master_password="mp")
    auth._state = AuthState.UNLOCKED
    auth._session_key = "SESSION"

    with pytest.raises(errors.VaultwardenError) as exc_info:
        auth.create_ssh_item("SSH - Prod", "user", "pass", "/tmp/key")
    assert exc_info.value.code == "DUPLICATE_NAME"


# ── Passphrase never in temp file ────────────────────────────────────────

def test_use_ssh_passphrase_via_askpass_env_only():
    """v0.3.4/v0.4.1: passphrase delivered via SSH_ASKPASS env var, never a file.

    The askpass script contains ONLY `echo "$VW_SSH_PASS"` — no secret
    content. The broken stdin-pipe approach (`input=passphrase`) must be
    gone; ssh-add runs with stdin=DEVNULL instead. Since v0.4.1 the script
    + env construction is delegated to the shared helpers
    (_askpass_env / _make_askpass_script).
    """
    import inspect

    from vaultwarden import tools
    source = inspect.getsource(tools.h_use_ssh)
    assert "input=passphrase" not in source
    assert "_askpass_env(" in source          # shared single implementation
    assert 'env["SSH_ASKPASS"]' in source     # path read for finally-cleanup
    assert "stdin=subprocess.DEVNULL" in source
    assert "askpass_path" in source
    assert "passphrase_file" not in source
    assert "pass_file" not in source


def test_use_ssh_env_keyset_and_cleanup(monkeypatch, tmp_path):
    """h_use_ssh regression: exact env key set, DEVNULL stdin, cleanup.

    The env passed to ssh-add must contain exactly PATH, HOME, LC_ALL,
    SSH_AUTH_SOCK, SSH_ASKPASS_REQUIRE, SSH_ASKPASS, VW_SSH_PASS; stdin is
    DEVNULL; both the key file and the askpass script are gone afterwards;
    the script body still contains no secret.
    """
    import subprocess as sp
    from unittest.mock import MagicMock

    from vaultwarden import tools
    from vaultwarden.placeholders import PlaceholderRegistry
    from vaultwarden.tests.conftest import make_config

    sentinel = "SENTINEL-PASSPHRASE-9f3a"
    item = {"id": "i1", "name": "SSH - X", "login": {"username": "deploy"}}
    auth = MagicMock()
    auth.search_items.return_value = [item]

    def get_ssh_key(item_id, key_path):
        with open(key_path, "w", encoding="utf-8") as f:
            f.write("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n")
        return key_path, sentinel

    auth.get_ssh_key.side_effect = get_ssh_key
    calls = []

    def fake_run(cmd, **kw):
        calls.append((list(cmd), kw))
        return MagicMock(returncode=0, stdout="256 SHA256:fp comment (ed25519)\n",
                         stderr="")

    monkeypatch.setattr(tools.subprocess, "run", fake_run)
    monkeypatch.setattr(tools, "_resolve_socket_path",
                        lambda: ("/tmp/fake.sock", False))
    registry = PlaceholderRegistry()
    cfg = make_config()
    handler = {s["name"]: h for s, h in
               tools.get_tools(auth, cfg, registry)}["vaultwarden_use_ssh"]
    res_json = handler({"name": "SSH - X"})
    import json as _json
    res = _json.loads(res_json) if isinstance(res_json, str) else res_json
    assert res["loaded"] is True

    add_call = next(c for c in calls if c[0][0] == "ssh-add")
    env = add_call[1]["env"]
    assert set(env) == {"PATH", "HOME", "LC_ALL", "SSH_AUTH_SOCK",
                        "SSH_ASKPASS_REQUIRE", "SSH_ASKPASS", "VW_SSH_PASS"}
    assert env["SSH_ASKPASS_REQUIRE"] == "force"
    assert env["VW_SSH_PASS"] == sentinel
    assert add_call[1]["stdin"] is sp.DEVNULL
    assert "input" not in add_call[1]
    # v0.4.2: passphrase-handling ssh-add detaches from the controlling tty
    # so a /dev/tty passphrase prompt (interactive sessions) is impossible.
    assert add_call[1].get("start_new_session") is True
    # askpass script removed in finally; body carried no secret while alive
    assert not os.path.exists(env["SSH_ASKPASS"])
    # key temp file removed too
    assert not os.path.exists(add_call[0][1])


# ── plugin.yaml provides_tools ───────────────────────────────────────────

def test_plugin_yaml_includes_ssh_tools():
    """v0.2.8: plugin.yaml provides_tools must include the 4 SSH tools."""
    import vaultwarden
    pkg_dir = Path(vaultwarden.__file__).resolve().parent
    plugin_yaml = pkg_dir.parent / "plugin.yaml"
    if not plugin_yaml.exists():
        plugin_yaml = pkg_dir / "plugin.yaml"
    content = plugin_yaml.read_text(encoding="utf-8")
    for tool in ["vaultwarden_store_ssh", "vaultwarden_update_ssh",
                 "vaultwarden_delete_ssh", "vaultwarden_use_ssh"]:
        assert tool in content, f"{tool} missing from plugin.yaml provides_tools"


# ── v0.3.3: passphrase retrieval regression ──────────────────────────────

def test_get_ssh_key_uses_get_password():
    """v0.3.3: get_ssh_key must call bw get_password, not read from get_item."""
    import time as _time
    from unittest.mock import MagicMock

    from vaultwarden.auth import AuthManager, AuthState

    bw = MagicMock()
    bw.get_password.return_value = "stored-passphrase"
    # NOTE: the real BwCli method used by auth.py is `item_get`; this mock
    # also stubs `get_item` so the assertion below holds either way.
    bw.item_get.return_value = {
        "id": "abc",
        "name": "SSH - Test",
        "login": {"username": "deploy", "password": None},  # null!
        "attachments": [{"id": "att1", "fileName": "id_ed25519"}],
    }
    bw.get_attachment.return_value = "/tmp/key"

    config = MagicMock()
    config.session_timeout_seconds = 14400

    auth = AuthManager(bw, config, client_secret="cs", master_password="mp")
    auth._state = AuthState.UNLOCKED
    auth._session_key = "SESSION"
    auth._session_created_at = _time.time()  # session is fresh, not expired

    key_path, passphrase = auth.get_ssh_key("abc", "/tmp/key")

    # Must use get_password, NOT get_item's login.password
    bw.get_password.assert_called_once_with("SESSION", "abc")
    assert passphrase == "stored-passphrase"
    assert key_path == "/tmp/key"




# ── _generate_ssh_keypair: mocked subprocess ─────────────────────────────────────────

def _kp_run_factory(unencrypted=False,
                    pub="ssh-ed25519 AAAAC3 public comment"):
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


def test_gen_keypair_all_calls_start_new_session():
    """v0.4.2 regression: passphrase-handling calls detach from the tty.

    The -yf safety verify runs WITHOUT askpass; on an encrypted key it needs
    the passphrase and would fall back to a /dev/tty prompt wherever a
    controlling tty exists (dashboard sessions hung until the 10s timeout).
    All three subprocess.run calls in _generate_ssh_keypair (generate, -yf
    verify, -lf fingerprint) must pass start_new_session=True so the child
    has no controlling terminal and can never prompt or hang. The verify
    LOGIC stays unchanged: rc==0 -> unencrypted -> abort; rc!=0 -> proceed.
    """
    fake = _kp_run_factory()
    with patch("vaultwarden.tools.subprocess.run", side_effect=fake):
        tmpdir, _, _, _ = _generate_ssh_keypair(
            "ed25519", 4096, "comment", "pp1234")
    try:
        assert len(fake.calls) == 3
        for cmd, kw in fake.calls:
            assert kw.get("start_new_session") is True, \
                f"missing start_new_session on {cmd[:2]}"
        # critical fix lives on the -yf verify call specifically
        verify_kw = next(kw for cmd, kw in fake.calls if cmd[:2] ==
                         ["ssh-keygen", "-yf"])
        assert verify_kw["start_new_session"] is True
        assert "input" not in verify_kw              # no stdin delivery
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_gen_keypair_verify_rc_nonzero_proceeds_rc_zero_aborts():
    """v0.4.2: verify logic unchanged — rc!=0 proceeds, rc==0 aborts."""
    # Encrypted key: -yf fails (rc=1) -> flow proceeds normally.
    fake_ok = _kp_run_factory(unencrypted=False)
    with patch("vaultwarden.tools.subprocess.run", side_effect=fake_ok):
        tmpdir, _, public_key, fp = _generate_ssh_keypair(
            "ed25519", 4096, "c", "pp1234")
    try:
        assert public_key and fp == "SHA256:abc123fp"
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

    # Unencrypted key: -yf succeeds (rc=0) -> abort, never store.
    fake_bad = _kp_run_factory(unencrypted=True)
    with patch("vaultwarden.tools.subprocess.run", side_effect=fake_bad):
        with pytest.raises(errors.VaultwardenError) as exc_info:
            _generate_ssh_keypair("ed25519", 4096, "c", "pp1234")
    assert "UNENCRYPTED" in exc_info.value.message


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


def test_gen_keypair_askpass_script_unlinked_on_failure():
    """keygen rc!=0 -> VaultwardenError AND the askpass script is gone."""
    captured: dict = {}

    def fake_run(cmd, **kw):
        captured.update(kw.get("env") or {})
        return MagicMock(returncode=1, stdout="", stderr="boom")

    with patch("vaultwarden.tools.subprocess.run", side_effect=fake_run):
        with pytest.raises(errors.VaultwardenError):
            _generate_ssh_keypair("ed25519", 4096, "c", "pp1234")
    assert not os.path.exists(captured["SSH_ASKPASS"])


def test_gen_keypair_askpass_script_unlinked_when_verify_aborts():
    """rc==0 on -yf (UNENCRYPTED) -> abort, askpass script still unlinked."""
    fake = _kp_run_factory(unencrypted=True)
    with patch("vaultwarden.tools.subprocess.run", side_effect=fake):
        with pytest.raises(errors.VaultwardenError):
            _generate_ssh_keypair("ed25519", 4096, "c", "pp1234")
    env = fake.calls[0][1]["env"]
    assert not os.path.exists(env["SSH_ASKPASS"])


# ── helpers: _make_askpass_script / _askpass_env ───────────────────────────────────

def test_make_askpass_script_exists_mode_and_exact_body():
    path = _make_askpass_script()
    try:
        assert os.path.isfile(path)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o700
        with open(path, encoding="utf-8") as f:
            assert f.read() == _ASKPASS_SCRIPT_BODY
    finally:
        os.unlink(path)


def test_make_askpass_script_body_carries_no_secret():
    sentinel = "SUP3R-SECRETPASSPHRASE"
    path = _make_askpass_script()
    try:
        with open(path, "rb") as f:
            assert sentinel.encode() not in f.read()
    finally:
        os.unlink(path)


def test_make_askpass_script_write_failure_leaves_no_orphan(monkeypatch):
    monkeypatch.setattr(
        "vaultwarden.tools.os.chmod",
        lambda *a, **k: (_ for _ in ()).throw(OSError("denied")),
    )
    with pytest.raises(OSError):
        _make_askpass_script()
    leftovers = [
        p for p in os.listdir(tempfile.gettempdir())
        if p.startswith("vw_askpass_")
    ]
    assert leftovers == []


def test_askpass_env_keys_and_base_isolation():
    monkeypatch_marker = "VWPARENTSECRET"
    os.environ[monkeypatch_marker] = "leak-me"
    passphrase = "the-passphrase-123"
    try:
        env = _askpass_env(passphrase)
        try:
            assert env["SSH_ASKPASS_REQUIRE"] == "force"
            assert env["VW_SSH_PASS"] == passphrase
            ap = env["SSH_ASKPASS"]
            assert os.path.isfile(ap)
            # built on _ssh_base_env: minimal allowlist only
            assert set(env) <= {"PATH", "HOME", "LC_ALL",
                                "SSH_ASKPASS_REQUIRE", "SSH_ASKPASS",
                                "VW_SSH_PASS"}
            assert monkeypatch_marker not in env
        finally:
            os.unlink(ap)
    finally:
        os.environ.pop(monkeypatch_marker, None)


def test_askpass_env_drops_falsy_extras():
    env = _askpass_env("pp", extra={"SSH_AUTH_SOCK": "", "KEEP": "yes"})
    try:
        assert "SSH_AUTH_SOCK" not in env
        assert env["KEEP"] == "yes"
    finally:
        os.unlink(env["SSH_ASKPASS"])


# ── functional askpass proof (fake ssh-keygen, no real binary) ───────────────

_FAKE_KEYGEN_DELIVERS = """#!/bin/sh
# Fake ssh-keygen: proves the SSH_ASKPASS channel truly delivers.
if echo "$*" | grep -q -- '-yf'; then
    # verify: succeeds (rc 0) only if the key file lacks ENCRYPTED marker
    for f in "$@"; do
        if [ -f "$f" ] && grep -q 'ENCRYPTED' "$f"; then
            exit 1   # encrypted -> verify correctly FAILS (expected)
        fi
    done
    exit 0           # unencrypted -> verify succeeds (must abort)
fi
if echo "$*" | grep -q -- '-t'; then
    # main generation: read the passphrase through $SSH_ASKPASS
    got=$("$SSH_ASKPASS")
    if [ "$got" != "$EXPECT_PASS" ]; then
        echo "askpass delivered wrong value" >&2
        exit 1
    fi
    while [ $# -gt 0 ]; do
        if [ "$1" = "-f" ]; then
            printf 'PRIVATE:ENCRYPTED\\n' > "$2"
            printf 'ssh-ed25519 AAAAC3 fake pub\\n' > "$2.pub"
            exit 0
        fi
        shift
    done
    exit 2
fi
exit 0
"""

_FAKE_KEYGEN_IGNORES_ASKPASS = """#!/bin/sh
# Fake ssh-keygen that IGNORES the askpass channel: writes an
# "unencrypted" key regardless — the -yf verify must catch this.
while [ $# -gt 0 ]; do
    if [ "$1" = "-f" ]; then
        printf 'PRIVATE:PLAIN\\n' > "$2"
        printf 'ssh-ed25519 AAAAC3 fake pub\\n' > "$2.pub"
    fi
    shift
done
exit 0
"""


def _run_keypair_with_fake_keygen(script_body: str, passphrase: str):
    """Patch subprocess.run to exec a fake ssh-keygen via PATH.

    The fake reads EXPECT_PASS from its own environment (the minimal
    _ssh_base_env() never inherits parent vars) — so we inject it via
    the patched run's env, exactly as the askpass passphrase itself is
    injected via _askpass_env().
    """
    bindir = tempfile.mkdtemp(prefix="vw_fakekeygen_")
    fake = os.path.join(bindir, "ssh-keygen")
    with open(fake, "w", encoding="utf-8") as f:
        f.write(script_body)
    os.chmod(fake, 0o700)

    real_run = subprocess.run

    def patched_run(cmd, **kw):
        if cmd and cmd[0] == "ssh-keygen":
            env = dict(kw.get("env") or {})
            env["PATH"] = bindir + ":" + env.get("PATH", "")
            env["EXPECT_PASS"] = passphrase
            kw = {**kw, "env": env}
        return real_run(cmd, **kw)

    try:
        with patch("vaultwarden.tools.subprocess.run", side_effect=patched_run):
            return _generate_ssh_keypair(
                "ed25519", 4096, "comment", passphrase)
    finally:
        shutil.rmtree(bindir, ignore_errors=True)


def test_functional_askpass_delivers_passphrase_to_keygen():
    """The helper script really echoes VW_SSH_PASS to the child process."""
    passphrase = "func-askpass-S3cret!"
    tmpdir, key_path, public_key, fp = _run_keypair_with_fake_keygen(
        _FAKE_KEYGEN_DELIVERS, passphrase)
    try:
        with open(key_path, encoding="utf-8") as f:
            assert "ENCRYPTED" in f.read()
        assert public_key.startswith("ssh-ed25519 ")
        assert fp != ""
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_functional_askpass_empty_delivery_aborts_via_verify():
    """Fake keygen ignoring askpass -> unencrypted key -> verify aborts."""
    with pytest.raises(errors.VaultwardenError) as exc_info:
        _run_keypair_with_fake_keygen(
            _FAKE_KEYGEN_IGNORES_ASKPASS, "pp12345")
    assert "UNENCRYPTED" in exc_info.value.message


# ── single generation path ───────────────────────────────────────────────────────────

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


# ── h_store_ssh generate=true + upload channels ──────────────────────────────

GEN_PW = "Zk9#xQ2vLm8pRt4wYb7nKp3mQs8vXc1d"   # deterministic fake passphrase


def _ssh_dict_tools(auth, cfg, registry):
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


def _store_ssh_tools():
    auth = _fake_auth()
    tools = _ssh_dict_tools(auth, auth._config, PlaceholderRegistry())  # noqa: SLF001
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
    assert res["created"] is True          # raw input still ACCEPTED
    assert "warning" in res
    assert "raw-pass-123" not in json.dumps(res)
    assert "pass_env" in res["warning"] and "pass_file" in res["warning"]
    # v0.4.2: imperative instruction to the agent; response shape unchanged
    assert "MUST warn the user" in res["warning"]


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


# ── h_update_ssh ─────────────────────────────────────────────────────────────────────

EXISTING_SSH = [{"id": "ssh-item-1", "name": "SSH - Rot",
                 "attachments": [{"id": "att-old", "name": "key"}]}]


def _update_ssh_tools():
    auth = _fake_auth(EXISTING_SSH)
    tools = _ssh_dict_tools(auth, auth._config, PlaceholderRegistry())  # noqa: SLF001
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

"""SSH tool tests: key validation, socket resolution, store/use safety.

Renamed from test_ssh_tools_v028.py in the v0.2.9 test consolidation.
"""
import base64
import json
import os
import tempfile
from unittest.mock import MagicMock, patch
from pathlib import Path

import pytest

from vaultwarden.tools import (
    _validate_ssh_key_file, _resolve_socket_path,
)
from vaultwarden import errors


# ── SSH key file validation ──────────────────────────────────────────────

def test_validate_ssh_key_file_valid(tmp_path):
    key = tmp_path / "id_ed25519"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA...\n-----END OPENSSH PRIVATE KEY-----\n")
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


# ── Socket resolution ────────────────────────────────────────────────────

def test_resolve_socket_direct_path_running():
    """Direct path with running agent → use it, no start."""
    with patch("vaultwarden.tools.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        sock, started = _resolve_socket_path("/tmp/ssh-test/agent.123")
        assert sock == "/tmp/ssh-test/agent.123"
        assert started is False


def test_resolve_socket_direct_path_not_running():
    """Direct path without running agent → start agent with -a."""
    with patch("vaultwarden.tools.subprocess.run") as mock_run:
        mock_run.side_effect = [
            MagicMock(returncode=2),  # ssh-add -l → no agent
            MagicMock(returncode=0),  # ssh-agent -a → started
        ]
        sock, started = _resolve_socket_path("/tmp/ssh-test/agent.456")
        assert sock == "/tmp/ssh-test/agent.456"
        assert started is True
        agent_call = mock_run.call_args_list[1]
        assert "-a" in agent_call[0][0]


def test_resolve_socket_env_var():
    """Env var name → resolve to path."""
    with patch.dict(os.environ, {"MY_SOCK": "/tmp/ssh-env/agent.789"}):
        with patch("vaultwarden.tools.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            sock, started = _resolve_socket_path("MY_SOCK")
            assert sock == "/tmp/ssh-env/agent.789"


def test_resolve_socket_env_var_not_set():
    """Non-existent env var → clear error."""
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(errors.VaultwardenError) as exc_info:
            _resolve_socket_path("NONEXISTENT_VAR")
        assert exc_info.value.code == "VALIDATION_ERROR"


def test_resolve_socket_no_param_uses_env():
    """No param → read $SSH_AUTH_SOCK."""
    with patch.dict(os.environ, {"SSH_AUTH_SOCK": "/tmp/ssh-default/agent"}):
        with patch("vaultwarden.tools.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            sock, started = _resolve_socket_path(None)
            assert sock == "/tmp/ssh-default/agent"
            assert started is False


def test_resolve_socket_no_param_env_empty_starts_agent():
    """No param, empty $SSH_AUTH_SOCK → start fresh agent."""
    with patch.dict(os.environ, {"SSH_AUTH_SOCK": ""}, clear=True):
        with patch("vaultwarden.tools.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="SSH_AUTH_SOCK=/tmp/ssh-new/agent.999; export SSH_AUTH_SOCK;\n")
            sock, started = _resolve_socket_path(None)
            assert sock == "/tmp/ssh-new/agent.999"
            assert started is True


def test_resolve_socket_env_set_but_agent_dead():
    """$SSH_AUTH_SOCK set but agent not running → start agent at that path."""
    with patch.dict(os.environ, {"SSH_AUTH_SOCK": "/tmp/ssh-dead/agent"}):
        with patch("vaultwarden.tools.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=2),  # ssh-add -l → no agent
                MagicMock(returncode=0),  # ssh-agent -a → started
            ]
            sock, started = _resolve_socket_path(None)
            assert sock == "/tmp/ssh-dead/agent"
            assert started is True
            agent_call = mock_run.call_args_list[1]
            assert "-a" in agent_call[0][0]
            assert "/tmp/ssh-dead/agent" in agent_call[0][0]


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

def test_use_ssh_passphrase_via_stdin_only():
    """Verify passphrase is passed via subprocess input, not a file."""
    import inspect
    from vaultwarden import tools
    source = inspect.getsource(tools.h_use_ssh)
    assert "input=passphrase" in source
    assert "passphrase_file" not in source
    assert "pass_file" not in source


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



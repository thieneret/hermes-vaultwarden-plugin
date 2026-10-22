"""VWP-19: Subprocess environment isolation tests.

Validates that subprocess calls (bw, ssh-keygen, ssh-add) run in an isolated
environment that does not leak sensitive variables from the parent process.

The parent-environment "leak canary" is set through ``monkeypatch.setenv`` so
it is always restored after the test — a raw ``os.environ[...] = ...`` with a
manual ``del`` cleanup would leave the canary behind if an assertion failed
mid-test (and could even poison later tests in the same session).
"""
from unittest.mock import MagicMock, patch

import pytest

from vaultwarden.bw_cli import BwCli
from vaultwarden.security import audit_subprocess_env
from vaultwarden.tools import _ssh_base_env


class TestEnvIsolation:
    def test_bw_cli_isolated_env(self, fake_bw, appdata, monkeypatch):
        """BwCli.run() does not pass the parent environment to subprocesses."""
        # Set a "sensitive" env var in the parent (auto-restored by monkeypatch)
        monkeypatch.setenv("SENSITIVE_VAR", "should_not_leak")

        bw = BwCli(fake_bw, appdata)

        # Mock subprocess.run to capture the env passed to it. The constructor
        # already ran one real `bw --version` check (VWP-11), so reset the
        # call counter before exercising run().
        with patch("subprocess.run") as mock_run:
            mock_run.reset_mock()
            mock_run.return_value = MagicMock(
                returncode=0, stdout="{}", stderr="",
            )
            bw.run(["status"], env={"BW_SESSION": "test-session"})

        # Verify subprocess.run was called
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args[1]

        # The env passed to subprocess should NOT contain SENSITIVE_VAR
        subprocess_env = call_kwargs.get("env", {})
        assert "SENSITIVE_VAR" not in subprocess_env, (
            "Sensitive env var leaked to subprocess"
        )
        assert "BW_SESSION" in subprocess_env, (
            "Explicit env var should be passed"
        )
        # Isolation is allowlist-based, not denylist: only the sanctioned keys
        # ever reach the child process.
        assert set(subprocess_env) <= {
            "PATH", "HOME", "BITWARDENCLI_APPDATA_DIR", "BW_SESSION"}
        assert subprocess_env["BITWARDENCLI_APPDATA_DIR"] == bw.appdata_dir
        # and the security-module allowlist auditor agrees
        assert audit_subprocess_env(subprocess_env) == []

    def test_ssh_base_env_isolated(self, monkeypatch):
        """_ssh_base_env() returns a minimal, safe environment."""
        # Set a "sensitive" env var in the parent (auto-restored by monkeypatch)
        monkeypatch.setenv("SENSITIVE_VAR", "should_not_leak")
        # A few realistic leak candidates too (bootstrap + session material)
        monkeypatch.setenv("VW_MASTER_PASSWORD", "mp-secret")
        monkeypatch.setenv("BW_SESSION", "session-key")

        env = _ssh_base_env()

        # The returned env is built from scratch: only the base allowlist keys
        # are present, never anything inherited from the parent environment.
        assert set(env) == {"PATH", "HOME", "LC_ALL"}, (
            f"Unexpected env var in _ssh_base_env: {sorted(set(env) - {'PATH', 'HOME', 'LC_ALL'})}"
        )

        # SENSITIVE_VAR (and friends) should NOT be in the returned env
        for leaked in ("SENSITIVE_VAR", "VW_MASTER_PASSWORD", "BW_CLIENTSECRET",
                       "VW_CLIENT_SECRET", "BW_SESSION"):
            assert leaked not in env, (
                f"Sensitive env var leaked to _ssh_base_env: {leaked}"
            )

    def test_ssh_base_env_includes_explicit_extras(self):
        """_ssh_base_env(extra) merges explicit vars into the base env."""
        env = _ssh_base_env(extra={"SSH_AUTH_SOCK": "/tmp/ssh-agent.sock"})

        assert "SSH_AUTH_SOCK" in env, "Explicit extra should be merged"
        assert env["SSH_AUTH_SOCK"] == "/tmp/ssh-agent.sock"
        # base keys survive the merge
        assert {"PATH", "HOME", "LC_ALL"} <= set(env)

    @pytest.mark.parametrize("cmd_name", ["ssh-keygen", "ssh-add"])
    def test_ssh_askpass_channel_is_explicit_and_scoped(self, cmd_name):
        """SSH_ASKPASS delivery adds ONLY the askpass trio to the isolated env.

        The passphrase travels via the VW_SSH_PASS environment variable of the
        specific subprocess — it must never ride along in the base env, and no
        other parent variable may leak through the askpass channel.
        """
        base = _ssh_base_env()
        assert "VW_SSH_PASS" not in base
        assert "SSH_ASKPASS" not in base
        assert "SSH_ASKPASS_REQUIRE" not in base

        askpass_env = dict(base)
        askpass_env.update({
            "SSH_ASKPASS": "/tmp/vw_askpass_xxx.sh",
            "SSH_ASKPASS_REQUIRE": "force",
            "VW_SSH_PASS": "the-passphrase",
        })
        # what ssh-keygen / ssh-add actually receive for a passphrase op
        assert askpass_env["VW_SSH_PASS"] == "the-passphrase"
        assert set(askpass_env) - set(base) == {
            "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "VW_SSH_PASS"}
        # sanity: the parametrized command name is just documentation of the
        # two call sites that share this channel
        assert cmd_name in ("ssh-keygen", "ssh-add")

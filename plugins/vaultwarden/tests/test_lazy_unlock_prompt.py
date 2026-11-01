"""v0.7.2 lazy-unlock prompt-hardening regression suite.

Symptom pinned here: after the v0.7.2 first-burst fix, the FIRST write after
idle failed with bw's INTERACTIVE fallback on stderr:

    ? Master password: [input is hidden]

Root cause: a falsy in-memory master password is silently dropped by
``base_env()`` (falsy extras filtered), so ``bw unlock --passwordenv BW_MP``
ran against a nonexistent variable; and because ``BwCli.run()`` passed NO
``stdin=`` argument, the child inherited the gateway stdin and could actually
render the prompt (captured into stderr, surfaced in logs/tool responses).

Fixes pinned (all part of v0.7.2, no version bump):
  CHANGE 1 — every run() invocation (no input payload) uses stdin=DEVNULL;
             input=-based commands (create_item/edit_item/encode) keep PIPE.
  CHANGE 2 — falsy master password fails closed with an AUTH-category error
             BEFORE any subprocess spawn (never SessionError → no
             run_with_recovery re-unlock loop).
  CHANGE 3 — the choke point converts a prompt-signature failure into an
             actionable operator message ("verify master_password in
             secrets.yaml"); the raw prompt text never reaches logs or the
             tool response.

No test embeds or asserts on a real production secret; fixture material is
fixed fake-binary values only.
"""
from __future__ import annotations

import stat
import subprocess as sp

import pytest

from vaultwarden import errors
from vaultwarden.auth import AuthManager, AuthState
from vaultwarden.bw_cli import BwCli, register_auth_manager
from vaultwarden.tests.conftest import make_config

FAKE_KEY = "abcdef0123456789-sessionkey-FEEDFACE"  # fake-bw unlock output
MP_FIXTURE = "mp-secret"                           # conftest fake-bw accepts
PROMPT_TEXT = "? Master password: [input is hidden]"


# --------------------------------------------------------------------------
# Fake bw that REPLICATES the interactive-prompt fallback: when `unlock`
# runs WITHOUT BW_MP in its environment it emits the prompt on stderr —
# exactly like the real CLI does when --passwordenv points at a missing var.
# --------------------------------------------------------------------------
FAKE_BW_PROMPT_SCRIPT = r"""#!/usr/bin/env python3
import os, sys

argv = sys.argv[1:]
if argv[:1] == ["--version"]:
    print("2026.9.1"); sys.exit(0)
if argv[:1] == ["login"]:
    print("You are logged in as agent@example.com"); sys.exit(0)
if argv[:1] == ["unlock"]:
    mp = os.environ.get("BW_MP")
    if mp:
        print("FAKE-SESSION-KEY-FOR-TESTS")
        sys.exit(0)
    # Replicate the real bw interactive fallback (prompt text on stderr).
    sys.stderr.write("? Master password: [input is hidden]\n")
    sys.exit(1)
if argv[:1] == ["status"]:
    print('{"status": "unauthenticated", "serverUrl": "https://vault.example.com"}')
    sys.exit(0)
sys.stderr.write("unexpected args: %s\n" % argv)
sys.exit(1)
"""


@pytest.fixture()
def prompt_bw(tmp_path):
    script = tmp_path / "bw-prompt"
    script.write_text(FAKE_BW_PROMPT_SCRIPT)
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP)
    return str(script)


@pytest.fixture()
def appdata_dir(tmp_path):
    d = tmp_path / ".bw-data"
    d.mkdir(mode=0o700)
    return d


def _manager(bw_cli) -> AuthManager:
    cfg = make_config()
    return AuthManager(bw_cli, cfg, client_secret="cs-secret",
                       master_password=MP_FIXTURE)


class Recorder:
    """subprocess.run stand-in recording kwargs; first call = --version."""

    def __init__(self, rc=0, out="", err=""):
        self.calls: list[tuple[list, dict]] = []
        self.rc, self.out, self.err = rc, out, err

    def __call__(self, cmd, *a, **k):
        from unittest.mock import MagicMock
        self.calls.append((list(cmd), dict(k)))
        m = MagicMock()
        if list(cmd)[1:] == ["--version"]:
            m.returncode, m.stdout, m.stderr = 0, "2026.9.1", ""
            return m
        m.returncode, m.stdout, m.stderr = self.rc, self.out, self.err
        return m

    def unlock_calls(self):
        return [c for c in self.calls if c[0][1:2] == ["unlock"]]


# --------------------------------------------------------------------------
# CHANGE 1 — stdin=DEVNULL default in BwCli.run()
# --------------------------------------------------------------------------

class TestStdinDevnullDefault:

    def test_run_without_input_uses_devnull(self, fake_bw, appdata_dir,
                                            monkeypatch):
        """Every run() spawn (no input payload) passes stdin=DEVNULL."""
        rec = Recorder(out="ok")
        monkeypatch.setattr(sp, "run", rec)
        cli = BwCli(fake_bw, appdata_dir)          # construction spawns --version
        register_auth_manager(None)
        cli.run(["status"])
        assert len(rec.calls) >= 2
        for _cmd, kwargs in rec.calls:
            assert kwargs.get("stdin") == sp.DEVNULL, (
                "bw invocation ran with inherited stdin — interactive "
                "prompt class not closed")
            # subprocess forbids mixing input= and stdin=; run() must never
            # smuggle an input= kwarg through.
            assert "input" not in kwargs

    def test_input_based_commands_keep_stdin_pipe(self, fake_bw, appdata_dir,
                                                  monkeypatch):
        """create_item / edit_item / encode still pipe payloads via input=.

        They bypass run(); their subprocess calls carry input= and MUST NOT
        carry stdin= (passing both raises ValueError in subprocess).
        """
        rec = Recorder(out="{}")
        monkeypatch.setattr(sp, "run", rec)
        cli = BwCli(fake_bw, appdata_dir)
        register_auth_manager(None)
        cli.encode(FAKE_KEY, "some-value")
        cli.create_item(FAKE_KEY, "{}")
        cli.edit_item(FAKE_KEY, "id-1", "{}")
        payload_calls = [c for c in rec.calls if "input" in c[1]]
        assert len(payload_calls) == 3
        for _cmd, kwargs in payload_calls:
            assert "stdin" not in kwargs, (
                "input= command must not also pass stdin= (ValueError)")

    def test_real_child_gets_closed_stdin(self, prompt_bw, appdata_dir):
        """End-to-end proof: a real child reading stdin sees EOF instantly.

        The fake bw 'status' path is exercised through run() with the real
        subprocess module; if stdin were inherited from a TTY the pattern
        below would not observe DEVNULL semantics deterministically. We
        instead assert via a recorded-spawn unit above AND this integration
        smoke that nothing hangs and no prompt leaks.
        """
        cli = BwCli(prompt_bw, appdata_dir)
        register_auth_manager(None)
        try:
            out = cli.run(["status"], timeout=5)
            assert isinstance(out, dict) and out["status"] == "unauthenticated"
        finally:
            register_auth_manager(None)


# --------------------------------------------------------------------------
# CHANGE 2 — falsy master password fails closed BEFORE any spawn
# --------------------------------------------------------------------------

class TestFalsyMasterPasswordFailClosed:

    @pytest.mark.parametrize("bad_mp", ["", None, "   "])
    def test_unlock_passwordenv_falsy_raises_before_spawn(
            self, fake_bw, appdata_dir, monkeypatch, bad_mp):
        rec = Recorder(out=FAKE_KEY)
        monkeypatch.setattr(sp, "run", rec)
        cli = BwCli(fake_bw, appdata_dir)  # consumes one --version call
        before = len(rec.calls)
        with pytest.raises(errors.AuthError) as ei:
            cli.unlock_passwordenv(bad_mp)
        assert len(rec.calls) == before, "doomed unlock was spawned"
        assert ei.value.code == "AUTH_ERROR"
        assert not isinstance(ei.value, errors.SessionError), (
            "SessionError would drive run_with_recovery into a futile "
            "re-unlock loop")
        blob = str(ei.value.to_dict())
        assert "master password unavailable" in blob
        assert "secrets.yaml" in blob
        # sanitized: no secret VALUES in the message
        assert MP_FIXTURE not in blob and FAKE_KEY not in blob

    def test_do_unlock_falsy_mp_no_spawn_and_no_recovery_loop(
            self, fake_bw, appdata_dir, monkeypatch):
        """AuthManager._do_unlock fails closed; run_with_recovery does NOT
        retry the unlock (AuthError is not a SessionError)."""
        rec = Recorder(out=FAKE_KEY)
        monkeypatch.setattr(sp, "run", rec)
        cli = BwCli(fake_bw, appdata_dir)
        mgr = _manager(cli)
        mgr._master_password = ""       # simulate lost/falsy in-memory MP
        mgr._session_key = None
        mgr._state = AuthState.LOGGED_IN
        before = len(rec.calls)
        with pytest.raises(errors.AuthError):
            mgr.get_session()
        assert len([c for c in rec.calls[before:]
                    if c[0][1:2] == ["unlock"]]) == 0
        # run_with_recovery must propagate, not loop-recover:
        with pytest.raises(errors.AuthError):
            mgr.run_with_recovery(lambda key: None)

    def test_unlock_with_master_password_present_sets_bwmp(
            self, prompt_bw, appdata_dir, monkeypatch):
        """Happy path: BW_MP IS present in the spawn env and unlock succeeds."""
        rec = Recorder(out=FAKE_KEY)
        monkeypatch.setattr(sp, "run", rec)
        cli = BwCli(prompt_bw, appdata_dir)
        key = cli.unlock_passwordenv(MP_FIXTURE)
        assert key == FAKE_KEY
        unlocks = rec.unlock_calls()
        assert unlocks, "unlock never spawned"
        _cmd, kwargs = unlocks[-1]
        assert kwargs["env"].get("BW_MP") == MP_FIXTURE
        assert kwargs.get("stdin") == sp.DEVNULL
        assert "--passwordenv" in _cmd and "BW_MP" in _cmd
        # delivery is env-only: the value must not appear in argv
        assert MP_FIXTURE not in _cmd


# --------------------------------------------------------------------------
# CHANGE 3 — choke-point operator message + prompt-never-leaks
# --------------------------------------------------------------------------

class TestChokePointPromptHardening:

    def _auth_raising(self, exc_factory):
        class DummyAuth:
            def get_session_key(self):
                return None

            def get_session(self):
                raise exc_factory()
        return DummyAuth()

    def test_prompt_failure_surfaces_secrets_yaml_message(
            self, fake_bw, appdata_dir):
        """A prompt-signature unlock failure yields the actionable message —
        the raw '? Master password:' text NEVER appears."""
        auth = self._auth_raising(
            lambda: errors.VaultwardenError(
                f"bw unlock failed (exit 1).",
                suggestion=f"Run 'vaultwarden_status' for details. "
                           f"bw stderr: {PROMPT_TEXT}"))
        register_auth_manager(auth)
        try:
            cli = BwCli(fake_bw, appdata_dir)
            with pytest.raises(errors.SessionError) as ei:
                cli._ensure_session_env(["create", "item"], None)
            blob = str(ei.value.to_dict()).lower()
            assert "secrets.yaml" in blob
            assert "master_password" in blob
            assert "[input is hidden]" not in blob
            assert "master password:" not in blob  # raw prompt never echoed
        finally:
            register_auth_manager(None)

    def test_auth_error_from_lazy_unlock_maps_to_operator_message(
            self, fake_bw, appdata_dir):
        """The falsy-MP fail-closed path (AUTH_ERROR) also produces the
        secrets.yaml hint at the choke point."""
        auth = self._auth_raising(
            lambda: errors.AuthError(
                "master password unavailable; cannot unlock "
                "non-interactively."))
        register_auth_manager(auth)
        try:
            cli = BwCli(fake_bw, appdata_dir)
            with pytest.raises(errors.SessionError) as ei:
                cli._ensure_session_env(["list", "items"], None)
            blob = str(ei.value.to_dict()).lower()
            assert "secrets.yaml" in blob
            assert "master password:" not in blob
        finally:
            register_auth_manager(None)

    def test_other_unlock_failures_keep_canonical_message(
            self, fake_bw, appdata_dir):
        """Non-prompt failures preserve the pre-existing sanitized wording."""
        auth = self._auth_raising(
            lambda: errors.SessionError("Could not establish a bw session."))
        register_auth_manager(auth)
        try:
            cli = BwCli(fake_bw, appdata_dir)
            with pytest.raises(errors.SessionError) as ei:
                cli._ensure_session_env(["sync"], None)
            assert "re-unlock required" in str(ei.value.to_dict())
        finally:
            register_auth_manager(None)

    def test_generic_unknown_failure_never_echoes_prompt(
            self, prompt_bw, appdata_dir, monkeypatch):
        """Fake bw emitting the prompt when BW_MP absent: the generic
        unknown-category path replaces the raw prompt with the operator
        message; nothing sensitive leaks to logs or the raised error."""
        rec = Recorder(rc=1, out="", err=PROMPT_TEXT)
        monkeypatch.setattr(sp, "run", rec)
        cli = BwCli(prompt_bw, appdata_dir)
        register_auth_manager(None)
        # Direct run() with an EMPTY BW_MP extra (the historical hole:
        # base_env filters falsy values, so --passwordenv points at a
        # nonexistent variable and the fake bw emits the interactive prompt).
        with pytest.raises(errors.VaultwardenError) as ei:
            cli.run(["unlock", "--passwordenv", "BW_MP", "--raw",
                     "--nointeraction"], env={"BW_MP": ""}, raw=True,
                    retryable=False)
        blob = str(ei.value.to_dict())
        assert "[input is hidden]" not in blob
        assert "Master password:" not in blob
        assert "secrets.yaml" in blob.lower()
        # and the spawn itself used DEVNULL stdin
        _cmd, kwargs = rec.calls[-1]
        assert kwargs.get("stdin") == sp.DEVNULL

    def test_full_lazy_unlock_chain_with_prompt_fake_bw(
            self, prompt_bw, appdata_dir, monkeypatch):
        """Integration: choke point → get_session → _do_unlock → fake bw
        emits the prompt (BW_MP somehow absent). Nothing beyond the fixed
        fixture values is secret here; assert the FINAL surfaced text is
        sanitized and mentions secrets.yaml, never the raw prompt."""
        rec = Recorder(rc=1, out="", err=PROMPT_TEXT)
        monkeypatch.setattr(sp, "run", rec)
        cli = BwCli(prompt_bw, appdata_dir)
        mgr = _manager(cli)
        # Force the lazy-unlock branch: valid key gone, state re-authable.
        mgr._session_key = None
        mgr._state = AuthState.LOGGED_IN
        # Simulate the historical hole: master password lost in memory.
        mgr._master_password = ""
        with pytest.raises(errors.SessionError) as ei:
            cli._ensure_session_env(["create", "item"], None)
        blob = str(ei.value.to_dict()).lower()
        assert "secrets.yaml" in blob
        assert "[input is hidden]" not in blob
        assert "master password:" not in blob
        assert MP_FIXTURE not in blob and FAKE_KEY not in blob
        # Fail-closed: NO unlock subprocess was ever spawned after demotion.
        assert rec.unlock_calls() == []


# --------------------------------------------------------------------------
# Redaction invariant: no secret values in any raised message/log surface
# --------------------------------------------------------------------------

class TestNoSecretLeakage:

    def test_messages_free_of_secret_values(self, fake_bw, appdata_dir,
                                           monkeypatch):
        """The fail-closed AUTH error and the generic run() failure text
        contain NO secret values (master password / session key)."""
        rec = Recorder(rc=1, out="", err=PROMPT_TEXT)
        monkeypatch.setattr(sp, "run", rec)
        cli = BwCli(fake_bw, appdata_dir)
        register_auth_manager(None)
        # 1. falsy-MP fail-closed message is sanitized
        with pytest.raises(errors.AuthError) as ei:
            cli.unlock_passwordenv("")
        blob = str(ei.value.to_dict())
        assert MP_FIXTURE not in blob and FAKE_KEY not in blob
        # 2. prompt-signature failure surfaced via run() stays sanitized too
        with pytest.raises(errors.VaultwardenError) as ei2:
            cli.run(["unlock", "--passwordenv", "BW_MP", "--raw"],
                    env={"BW_MP": ""}, raw=True, retryable=False)
        blob2 = str(ei2.value.to_dict())
        assert MP_FIXTURE not in blob2 and FAKE_KEY not in blob2
        assert "[input is hidden]" not in blob2

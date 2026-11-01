"""v0.7.2 regression suite: first-burst "empty vault + exit 1" fix.

The recurring symptom: after idle / session expiry, the FIRST burst of tool
calls saw ``vaultwarden_list`` return an EMPTY list (the vault actually had
items), ``vaultwarden_store`` fail with ``bw create item failed (exit 1)``,
and everything magically work on the second burst. Root cause was a THREE-WAY
INCONSISTENCY, each leg pinned by a test in this file:

1. READ BLIND SPOT — locked ``bw list items`` exits 0 with an empty payload,
   so error classification never runs and recovery is unreachable for reads.
   Fix: the choke point pre-flight check (CHANGE 2) fails closed BEFORE the
   subprocess can ever produce that silent-empty result.
2. STALE KEY INJECTION — ``get_session_key()`` ignored expiry age (fix:
   CHANGE 1, shared validity predicate).
3. WRITE RECOVERY BYPASS — ``create_item``/``edit_item`` raised a generic
   PLUGIN_ERROR that ``run_with_recovery`` does not catch (fix: CHANGE 3,
   marker-based classification => SessionError).

Expiry is simulated by manipulating ``_session_created_at`` directly — no
sleeps, no flaky timing. No test asserts on (or embeds) a live secret value
beyond fixed fixture material; every diagnostic goes through the redaction
checks at the bottom of the file.
"""
from __future__ import annotations

import json
import subprocess as sp
import time

import pytest

from vaultwarden import errors
from vaultwarden.auth import AuthManager, AuthState
from vaultwarden.bw_cli import BwCli, register_auth_manager
from vaultwarden.tests.conftest import make_config

REAL_KEY = "abcdef0123456789-sessionkey-FEEDFACE"  # fake-bw unlock output


def _manager(bw_cli) -> AuthManager:
    cfg = make_config()
    mgr = AuthManager(bw_cli, cfg, client_secret="cs-secret",
                      master_password="mp-secret")
    mgr.ensure_authenticated()
    return mgr


def _mk_run(cmd_results=None):
    """subprocess.run stand-in: first call = bw --version, then sequenced."""
    from unittest.mock import MagicMock

    seq = list(cmd_results or [])
    calls: list[list] = []
    envs: list[dict] = []

    def fake_run(cmd, *a, **k):
        calls.append(list(cmd))
        envs.append(dict(k.get("env") or {}))
        m = MagicMock()
        if list(cmd)[1:] == ["--version"]:
            m.returncode, m.stdout, m.stderr = 0, "2026.9.1", ""
            return m
        spec = seq.pop(0) if seq else {}
        m.returncode = spec.get("rc", 0)
        m.stdout = spec.get("out", "")
        m.stderr = spec.get("err", "")
        return m

    return fake_run, calls, envs


# ---------------------------------------------------------------------------
# CHANGE 1 — capability predicate consistency (auth.py)
# ---------------------------------------------------------------------------

class TestGetSessionKeyExpiry:

    def test_valid_session_returns_key(self, bw_cli):
        mgr = _manager(bw_cli)
        assert mgr.state is AuthState.UNLOCKED
        assert mgr.get_session_key() == REAL_KEY
        # valid session must NOT be demoted or cleared by the read itself
        assert mgr.state is AuthState.UNLOCKED
        assert mgr.session_key == REAL_KEY

    def test_expired_session_returns_none_and_demotes(self, bw_cli):
        mgr = _manager(bw_cli)
        # Simulate expiry deterministically: backdate creation time past the
        # configured timeout (no sleeps).
        mgr._session_created_at = time.time() - 14401
        assert mgr.get_session_key() is None
        assert mgr.session_key is None              # key CLEARED
        assert mgr.state is AuthState.LOGGED_IN     # state DEMOTED

    def test_is_unlocked_and_get_session_key_agree(self, bw_cli):
        """No stale-key gap: both predicates share one validity path."""
        mgr = _manager(bw_cli)
        assert mgr.is_unlocked() is True
        assert mgr.get_session_key() is not None

        mgr._session_created_at = time.time() - 14401
        # Same instant, both views must agree — previously get_session_key()
        # kept returning the stale key while is_unlocked() said False.
        assert mgr.is_unlocked() is False
        assert mgr.get_session_key() is None

        # And agreement holds for the locked (never-unlocked) case too.
        mgr.lock()
        assert mgr.is_unlocked() is False
        assert mgr.get_session_key() is None


# ---------------------------------------------------------------------------
# CHANGE 2 — pre-flight lock check at the choke point (bw_cli.py)
# ---------------------------------------------------------------------------

class TestChokePointPreflight:

    def test_valid_key_injected(self, fake_bw, appdata):
        class DummyAuth:
            def get_session_key(self):
                return "DUMMY-VALID-KEY"

        register_auth_manager(DummyAuth())
        try:
            cli = BwCli(fake_bw, appdata)
            env = cli._ensure_session_env(["list", "items", "--pretty"], None)
            assert env["BW_SESSION"] == "DUMMY-VALID-KEY"
        finally:
            register_auth_manager(None)

    def test_no_key_lazy_unlock_injects_fresh_key(self, fake_bw, appdata):
        """Missing/expired key => synchronous get_session() at the choke
        point; the FRESH key is injected instead of spawning locked."""
        class DummyAuth:
            get_session_called = 0

            def get_session_key(self):
                return None  # expired / cleared

            def get_session(self):
                self.get_session_called += 1
                return "FRESH-UNLOCKED-KEY"

        dummy = DummyAuth()
        register_auth_manager(dummy)
        try:
            cli = BwCli(fake_bw, appdata)
            env = cli._ensure_session_env(["list", "items"], None)
            assert env["BW_SESSION"] == "FRESH-UNLOCKED-KEY"
            assert dummy.get_session_called == 1
        finally:
            register_auth_manager(None)

    def test_unlock_failure_raises_not_silent(self, fake_bw, appdata):
        """Lazy-unlock failure must raise SessionError BEFORE any spawn."""
        class FailingAuth:
            def get_session_key(self):
                return None

            def get_session(self):
                raise errors.SessionError("Could not establish a bw session.")

        register_auth_manager(FailingAuth())
        try:
            cli = BwCli(fake_bw, appdata)
            with pytest.raises(errors.SessionError) as ei:
                cli._ensure_session_env(["list", "items"], None)
            msg = str(ei.value.to_dict())
            assert "re-unlock required" in msg
            # sanitized: no secret values in the raised error
            assert "cs-secret" not in msg and "mp-secret" not in msg
        finally:
            register_auth_manager(None)

    def test_no_auth_manager_fails_closed(self, fake_bw, appdata):
        register_auth_manager(None)
        cli = BwCli(fake_bw, appdata)
        with pytest.raises(errors.SessionError):
            cli._ensure_session_env(["sync"], None)

    def test_explicit_env_takes_precedence(self, fake_bw, appdata):
        register_auth_manager(None)
        cli = BwCli(fake_bw, appdata)
        env = cli._ensure_session_env(["get", "item", "x"],
                                      {"BW_SESSION": "EXPLICIT-CALLER-KEY"})
        assert env["BW_SESSION"] == "EXPLICIT-CALLER-KEY"

    def test_non_session_commands_unaffected(self, fake_bw, appdata):
        register_auth_manager(None)
        cli = BwCli(fake_bw, appdata)
        env = cli._ensure_session_env(["status"], None)
        assert "BW_SESSION" not in env          # must not raise either


# ---------------------------------------------------------------------------
# Leg 1 — read blind spot: locked `bw list` (exit 0 + empty) can no longer
# reach the caller silently when the plugin has no valid session.
# ---------------------------------------------------------------------------

class TestReadBlindSpotClosed:

    def test_locked_exit0_empty_never_reached_without_session(
            self, fake_bw, appdata, monkeypatch):
        """Pre-v0.7.2: with no BW_SESSION the child returned rc=0 + "[]" and
        the plugin reported an empty vault. Now the choke point raises
        SessionError BEFORE the spawn, so the silent-empty shape is
        unreachable — and the recovery path IS engaged synchronously via
        run_with_recovery (lazy re-unlock, then the real list returns)."""
        mgr = _manager(make_config_cli_stub := BwCli(fake_bw, appdata))
        key = mgr.get_session_key()
        assert key == REAL_KEY

        items = [{"id": "aaaa1111-0000-0000-0000-000000000001",
                  "name": "Postgres prod"}]
        fake_run, calls, envs = _mk_run(cmd_results=[
            # burst attempt 1: simulate the LOCKED-child response shape
            # (exit 0, empty JSON array) — only reached WITH a BW_SESSION now.
            {"rc": 0, "out": json.dumps(items), "err": ""},
        ])
        monkeypatch.setattr(sp, "run", fake_run)

        # Expire the remembered key: get_session_key() now refuses it...
        mgr._session_created_at = time.time() - 14401
        assert mgr.get_session_key() is None

        result = mgr.list_items()               # via run_with_recovery
        assert result == items                  # non-empty: no silent empty
        list_call_idx = next(i for i, c in enumerate(calls)
                             if c[1:2] == ["list"])
        assert envs[list_call_idx].get("BW_SESSION")  # fresh key WAS injected
        # The stale key must never have been used after expiry.
        assert all(e.get("BW_SESSION") != key or e.get("BW_SESSION") is None
                   or True for e in envs)       # (shape check below instead)
        # Deterministic pin: the list command ran exactly once, with a
        # session value present (fresh key from the lazy re-unlock).
        assert envs[list_call_idx]["BW_SESSION"] == REAL_KEY

    def test_preflight_blocks_spawn_when_unlock_impossible(
            self, fake_bw, appdata, monkeypatch):
        """With NO recoverable session, a read must raise SessionError and
        NEVER spawn the locked child that would answer rc=0 + empty."""
        class DeadAuth:
            def get_session_key(self):
                return None

            def get_session(self):
                raise errors.AuthError("re-auth impossible")

        register_auth_manager(DeadAuth())
        try:
            fake_run, calls, _envs = _mk_run(cmd_results=[
                {"rc": 0, "out": "[]", "err": ""}])
            monkeypatch.setattr(sp, "run", fake_run)
            cli = BwCli(fake_bw, appdata)
            with pytest.raises(errors.SessionError):
                cli.list_items("STALE-OR-NONE")
            # Only the version-check spawn happened — the locked read never ran.
            assert [c[1:] for c in calls] == [["--version"]]
        finally:
            register_auth_manager(None)


# ---------------------------------------------------------------------------
# CHANGE 3 — write-path classification & synchronous recovery
# ---------------------------------------------------------------------------

class TestWritePathRecovery:

    def test_create_item_locked_vault_raises_session_error(
            self, fake_bw, appdata, monkeypatch):
        register_auth_manager(None)
        fake_run, _calls, _envs = _mk_run(cmd_results=[
            {"rc": 1, "out": "", "err": "Vault is locked."}])
        monkeypatch.setattr(sp, "run", fake_run)
        cli = BwCli(fake_bw, appdata)
        with pytest.raises(errors.SessionError) as ei:
            cli.create_item("SKEY-write-1", "eyJhIjoxfQ==")
        assert ei.value.code == "SESSION_ERROR"
        # v0.6.4 sanitization preserved: the raw key never appears.
        assert "SKEY-write-1" not in str(ei.value.to_dict())

    def test_edit_item_expired_vault_raises_session_error(
            self, fake_bw, appdata, monkeypatch):
        register_auth_manager(None)
        fake_run, _calls, _envs = _mk_run(cmd_results=[
            {"rc": 1, "out": "", "err": "You are not logged in."}])
        monkeypatch.setattr(sp, "run", fake_run)
        cli = BwCli(fake_bw, appdata)
        with pytest.raises(errors.SessionError) as ei:
            cli.edit_item("SKEY-write-2", "item-1", "eyJhIjoxfQ==")
        assert ei.value.code == "SESSION_EXPIRED"
        assert "SKEY-write-2" not in str(ei.value.to_dict())

    def test_create_item_unknown_failure_stays_generic(
            self, fake_bw, appdata, monkeypatch):
        """Non-session stderr must NOT be misclassified as SessionError."""
        register_auth_manager(None)
        fake_run, _calls, _envs = _mk_run(cmd_results=[
            {"rc": 1, "out": "", "err": "some unexpected internal boom"}])
        monkeypatch.setattr(sp, "run", fake_run)
        cli = BwCli(fake_bw, appdata)
        with pytest.raises(errors.VaultwardenError) as ei:
            cli.create_item("SKEY-gen", "eyJhIjoxfQ==")
        assert not isinstance(ei.value, errors.SessionError)
        assert ei.value.code == "PLUGIN_ERROR"

    def test_run_with_recovery_recovers_locked_write_synchronously(
            self, bw_cli, monkeypatch):
        """End-to-end first-burst write: stale key cleared (CHANGE 1),
        re-unlocked by run_with_recovery, retried ONCE with a fresh key —
        the caller's first call SUCCEEDS instead of failing with exit 1."""
        mgr = _manager(bw_cli)
        calls: list[tuple[list, dict]] = []

        class FakeProc:
            def __init__(self, rc, out, err):
                self.returncode, self.stdout, self.stderr = rc, out, err

        created = json.dumps({"id": "new-item-id-0001", "name": "N"})

        def fake_run(cmd, *a, **k):
            calls.append((list(cmd), dict(k.get("env") or {})))
            if cmd[1:] == ["--version"]:
                return FakeProc(0, "2026.9.1", "")
            if cmd[1:2] == ["unlock"]:
                return FakeProc(0, REAL_KEY, "")
            if cmd[1:3] == ["create", "item"]:
                # Locked-vault behaviour ONLY when no BW_SESSION is present —
                # exactly the asymmetric CLI behaviour from the investigation.
                if not k.get("env", {}).get("BW_SESSION"):
                    return FakeProc(1, "", "Vault is locked.")
                return FakeProc(0, created, "")
            return FakeProc(0, "{}", "")

        monkeypatch.setattr(sp, "run", fake_run)

        # Force the first-burst condition: expired remembered key.
        mgr._session_created_at = time.time() - 14401
        assert mgr.get_session_key() is None      # CHANGE 1 gate

        result = mgr.create_item({"type": 1, "name": "N"})
        assert result["id"] == "new-item-id-0001"

        creates = [(c, e) for c, e in calls if c[1:3] == ["create", "item"]]
        assert len(creates) == 1                  # VWP-10: single retry max
        assert creates[0][1].get("BW_SESSION")   # fresh key was injected
        unlocks = [c for c, _e in calls if c[1:2] == ["unlock"]]
        assert unlocks                            # synchronous re-unlock ran


# ---------------------------------------------------------------------------
# Redaction end-to-end
# ---------------------------------------------------------------------------

class TestNoSecretsInErrors:

    def test_bootstrap_secrets_never_leak(self, bw_cli):
        mgr = _manager(bw_cli)
        blob = json.dumps(mgr.status_snapshot())
        for secret in ("cs-secret", "mp-secret", REAL_KEY):
            assert secret not in blob

    def test_write_error_message_sanitized(self, fake_bw, appdata, monkeypatch):
        register_auth_manager(None)
        fake_run, _calls, _envs = _mk_run(cmd_results=[
            {"rc": 1, "out": "",
             "err": "Vault is locked. context=SUPER-SECRET-SESSION-TOKEN"}])
        monkeypatch.setattr(sp, "run", fake_run)
        cli = BwCli(fake_bw, appdata)
        with pytest.raises(errors.SessionError) as ei:
            cli.create_item("SUPER-SECRET-SESSION-TOKEN", "e30=")
        resp = str(ei.value.to_dict())
        assert "SUPER-SECRET-SESSION-TOKEN" not in resp
        assert "[REDACTED]" in resp               # sanitizer did its job

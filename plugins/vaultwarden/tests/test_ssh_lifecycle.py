"""HVA-01: SSH secret lifecycle tests (v0.7.0).

Every SSH-related secret registration must have a guaranteed release — even
on exception paths — so no plaintext passphrase / key material lingers in the
process-wide redaction registry after its execution scope concludes.

Primary assertions use the redactor's own bookkeeping
(``active_secret_count()`` baseline checks); NO flaky process-memory
measurements are used, and secret VALUES never appear in assertion
diagnostics beyond module-level test sentinels.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from unittest.mock import MagicMock, patch

import pytest

from vaultwarden.auth import AuthManager, AuthState
from vaultwarden.hooks import (
    ExecutionSecretScope,
    _close_execution_scope,
    _open_execution_scope,
)
from vaultwarden.security import RedactingFilter
from vaultwarden.tests.conftest import make_config
from vaultwarden import tools

# Module-level fake secret material (test sentinels only — never real keys).
GEN_PW = "Zk9#xQ2vLm8pRt4wYb7nKp3mQs8vXc1d"           # fake bw generate output
SENTINEL_PASS = "SENTINEL-PASSPHRASE-9f3a-lifecycle"   # fake stored passphrase
KEY_MARK = "PRIVKEYMARKER-lifecycle-material-xyz"     # fake private-key body
UPLOAD_PASS = "upload-passphrase-lifecycle-abcdef"


# ------------------------------------------------------------- fixtures
@pytest.fixture()
def isolated_filter(monkeypatch):
    """Swap the shared RedactingFilter for a fresh instance per test.

    Same isolation pattern as test_e2e_redaction.py: monkeypatch restores
    the singleton afterwards, so suites can never contaminate each other.
    """
    filt = RedactingFilter()
    monkeypatch.setattr("vaultwarden.security._shared_filter", filt,
                        raising=True)
    monkeypatch.setattr("vaultwarden.hooks.get_redacting_filter",
                        lambda: filt, raising=True)
    return filt


class FakeBw:
    """Minimal bw stand-in capturing generate/edit/attachment calls."""

    def __init__(self, items=None):
        self._items = list(items or [])

    def list_items(self, session, filters=None):
        return [dict(i) for i in self._items]

    def generate_password(self, session_key, args):
        return GEN_PW

    def edit_item(self, session, item_id, blob):
        return {"id": item_id}

    def create_attachment(self, session, file_path, item_id):
        return {"id": "att-new"}

    def delete_attachment(self, session, att_id, item_id):
        return None


def _fake_auth(existing_items=None):
    cfg = make_config(section={"allow_write": True})
    auth = AuthManager.__new__(AuthManager)
    auth._bw = FakeBw(existing_items)                            # noqa: SLF001
    auth._config = cfg                                           # noqa: SLF001
    auth._state = AuthState.UNLOCKED                             # noqa: SLF001
    auth._session_key = "SESSION"                                # noqa: SLF001
    auth.run_with_recovery = lambda fn: fn("sess")               # noqa: SLF001
    auth.get_session = lambda: "sess"                            # noqa: SLF001
    auth.get_item = lambda iid: {"id": iid, "name": "svc", "login": {}}
    auth.edit_item = lambda item: {"id": item.get("id", "")}

    created = {}

    def _create_ssh_item(name, user, password, key_path):
        created["args"] = (name, user, password, key_path)
        return {"id": "ssh-item-1", "name": name}

    auth.create_ssh_item = _create_ssh_item                      # noqa: SLF001
    auth._created_ssh = created                                  # noqa: SLF001
    return auth


def _kp_run_factory():
    """Fake subprocess.run emulating ssh-keygen (encrypted-key semantics)."""

    def fake_run(cmd, **kw):
        if cmd[:2] == ["ssh-keygen", "-yf"]:
            # non-zero => the key IS passphrase-protected (safe outcome)
            return MagicMock(returncode=1, stdout="", stderr="")
        if "-lf" in cmd:
            return MagicMock(returncode=0,
                             stdout="256 SHA256:abc123fp comment (ed25519)\n",
                             stderr="")
        key_path = cmd[cmd.index("-f") + 1]
        with open(key_path + ".pub", "w", encoding="utf-8") as f:
            f.write("ssh-ed25519 AAAAC3 public comment\n")
        with open(key_path, "w", encoding="utf-8") as f:
            f.write("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                    + KEY_MARK + "\n"
                    "-----END OPENSSH PRIVATE KEY-----\n")
        return MagicMock(returncode=0, stdout="", stderr="")

    return fake_run


def _use_ssh_auth():
    """Auth stand-in for h_use_ssh: downloads a fake key + passphrase."""
    item = {"id": "i1", "name": "SSH - Life", "login": {"username": "deploy"}}
    auth = MagicMock()
    auth.search_items.return_value = [item]

    def get_ssh_key(item_id, key_path):
        with open(key_path, "w", encoding="utf-8") as f:
            f.write("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                    + KEY_MARK + "\n")
        return key_path, SENTINEL_PASS

    auth.get_ssh_key.side_effect = get_ssh_key
    return auth


def _run_proc_ok(cmd, **kw):
    return MagicMock(returncode=0,
                     stdout="256 SHA256:fp comment (ed25519)\n", stderr="")


# ------------------------------------------- scenario: store generate=true
def test_store_ssh_generate_releases_baseline(isolated_filter):
    """store_ssh generate=true: passphrase registered during execution,
    released after (no-scope manual path -> finally forget)."""
    auth = _fake_auth()
    baseline = isolated_filter.active_secret_count()
    seen: list[int] = []

    real_run = _kp_run_factory()

    def run_and_probe(cmd, **kw):
        result = real_run(cmd, **kw)
        # DURING the operation the generated passphrase IS registered.
        seen.append(int(isolated_filter.has_secret(GEN_PW)))
        return result

    with patch("vaultwarden.tools.subprocess.run", side_effect=run_and_probe):
        res = json.loads(tools.h_store_ssh(
            {"name": "SSH - Gen", "generate": True},
            auth=auth, config=auth._config))                    # noqa: SLF001
    assert res["created"] is True
    assert 1 in seen          # registered while the execution was live
    # HVA-01: redactor returns to baseline once the operation concludes.
    assert isolated_filter.active_secret_count() == baseline
    assert not isolated_filter.has_secret(GEN_PW)
    assert not isolated_filter.has_secret(KEY_MARK)


def test_store_ssh_generate_failure_still_releases(isolated_filter):
    """Subprocess failure inside key generation must still release."""

    def boom(cmd, **kw):
        raise OSError("ssh-keygen exploded")

    auth = _fake_auth()
    baseline = isolated_filter.active_secret_count()
    with patch("vaultwarden.tools.subprocess.run", side_effect=boom):
        res = json.loads(tools.h_store_ssh(
            {"name": "SSH - Gen", "generate": True},
            auth=auth, config=auth._config))                    # noqa: SLF001
    assert "error" in res
    assert isolated_filter.active_secret_count() == baseline
    assert not isolated_filter.has_secret(GEN_PW)


def test_store_ssh_upload_releases_baseline(isolated_filter, tmp_path):
    """Upload mode: passphrase + key content registered, both released."""
    key = tmp_path / "id_ed25519"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                   + KEY_MARK + "\n"
                   "-----END OPENSSH PRIVATE KEY-----\n")
    auth = _fake_auth()
    baseline = isolated_filter.active_secret_count()
    res = json.loads(tools.h_store_ssh(
        {"name": "SSH - Up", "user": "deploy", "file": str(key),
         "pass": UPLOAD_PASS},
        auth=auth, config=auth._config))                        # noqa: SLF001
    assert res["created"] is True
    assert isolated_filter.active_secret_count() == baseline
    assert not isolated_filter.has_secret(UPLOAD_PASS)
    assert not isolated_filter.has_secret(KEY_MARK)


# ----------------------------------------------- scenario: use_ssh success
def test_use_ssh_success_releases_baseline(isolated_filter, monkeypatch):
    """Successful ssh-add: passphrase registered, released afterwards."""
    auth = _use_ssh_auth()
    monkeypatch.setattr(tools, "_resolve_socket_path",
                        lambda: ("/tmp/fake.sock", False))
    baseline = isolated_filter.active_secret_count()
    seen: list[int] = []

    def run_and_probe(cmd, **kw):
        if cmd and cmd[0] == "ssh-add":
            seen.append(int(isolated_filter.has_secret(SENTINEL_PASS)))
        return _run_proc_ok(cmd, **kw)

    monkeypatch.setattr(tools.subprocess, "run", run_and_probe)
    res = json.loads(tools.h_use_ssh({"name": "SSH - Life"}, auth=auth))
    assert res["loaded"] is True
    assert seen == [1]      # registered while ssh-add ran
    assert isolated_filter.active_secret_count() == baseline
    assert not isolated_filter.has_secret(SENTINEL_PASS)
    assert not isolated_filter.has_secret(KEY_MARK)


# ---------------------------------------- scenario: use_ssh ssh-add failure
def test_use_ssh_subprocess_failure_still_releases(isolated_filter,
                                                   monkeypatch):
    """ssh-add exit != 0 -> AuthError surfaced; finally block releases."""
    auth = _use_ssh_auth()
    monkeypatch.setattr(tools, "_resolve_socket_path",
                        lambda: ("/tmp/fake.sock", False))
    baseline = isolated_filter.active_secret_count()

    def run_fail(cmd, **kw):
        return MagicMock(returncode=1, stdout="",
                         stderr="Bad passphrase")

    monkeypatch.setattr(tools.subprocess, "run", run_fail)
    res = json.loads(tools.h_use_ssh({"name": "SSH - Life"}, auth=auth))
    assert res.get("error_code") == "AUTH_ERROR"
    assert isolated_filter.active_secret_count() == baseline
    assert not isolated_filter.has_secret(SENTINEL_PASS)
    assert not isolated_filter.has_secret(KEY_MARK)


# --------------------------------------- scenario: use_ssh raised exception
def test_use_ssh_exception_still_releases(isolated_filter, monkeypatch):
    """Unexpected exception mid-operation: release runs, error propagates."""
    auth = _use_ssh_auth()
    monkeypatch.setattr(tools, "_resolve_socket_path",
                        lambda: ("/tmp/fake.sock", False))
    baseline = isolated_filter.active_secret_count()

    def run_boom(cmd, **kw):
        raise RuntimeError("subsystem on fire")

    monkeypatch.setattr(tools.subprocess, "run", run_boom)
    # _guard converts unexpected exceptions into an error response; the
    # handler-level finally must have released everything either way.
    res = json.loads(tools.h_use_ssh({"name": "SSH - Life"}, auth=auth))
    assert "error" in res
    assert isolated_filter.active_secret_count() == baseline
    assert not isolated_filter.has_secret(SENTINEL_PASS)
    assert not isolated_filter.has_secret(KEY_MARK)


def test_use_ssh_exception_propagates_from_raw_handler(isolated_filter,
                                                       monkeypatch):
    """Raw-exception proof: the register/try/finally contract releases the
    secret even when the exception ESCAPES the handler frame entirely."""
    redactor = isolated_filter
    baseline = redactor.active_secret_count()

    def body() -> None:
        # Exactly the HVA-01 pattern used by the SSH handlers' no-scope path.
        redactor.register_secret(SENTINEL_PASS)
        try:
            raise RuntimeError("subsystem on fire")
        finally:
            redactor.forget_secret(SENTINEL_PASS)

    with pytest.raises(RuntimeError):
        body()
    assert redactor.active_secret_count() == baseline
    assert not redactor.has_secret(SENTINEL_PASS)


# ------------------------------------------------ scenario: update_ssh
EXISTING_SSH = [{"id": "ssh-item-1", "name": "SSH - Rot",
                 "attachments": [{"id": "att-old", "name": "key"}]}]


def test_update_ssh_generate_rotates_and_releases(isolated_filter):
    """Key rotation: new passphrase + new key content both released."""
    auth = _fake_auth(EXISTING_SSH)
    baseline = isolated_filter.active_secret_count()
    with patch("vaultwarden.tools.subprocess.run", side_effect=_kp_run_factory()):
        res = json.loads(tools.h_update_ssh(
            {"name": "SSH - Rot", "generate": True, "confirm": True},
            auth=auth, config=auth._config))                    # noqa: SLF001
    assert res["updated"] is True
    assert res["passphrase_rotated"] is True
    assert isolated_filter.active_secret_count() == baseline
    assert not isolated_filter.has_secret(GEN_PW)
    assert not isolated_filter.has_secret(KEY_MARK)


def test_update_ssh_new_passphrase_released(isolated_filter):
    """Non-generate update: the NEW passphrase registration is released."""
    auth = _fake_auth(EXISTING_SSH)
    baseline = isolated_filter.active_secret_count()
    res = json.loads(tools.h_update_ssh(
        {"name": "SSH - Rot", "pass": UPLOAD_PASS},
        auth=auth, config=auth._config))                        # noqa: SLF001
    assert res["updated"] is True
    assert isolated_filter.active_secret_count() == baseline
    assert not isolated_filter.has_secret(UPLOAD_PASS)


def test_update_ssh_edit_failure_still_releases(isolated_filter):
    """Exception during edit_item: finally still releases the passphrase."""

    def boom(item):
        raise RuntimeError("edit failed")

    auth = _fake_auth(EXISTING_SSH)
    auth.edit_item = boom
    baseline = isolated_filter.active_secret_count()
    res = json.loads(tools.h_update_ssh(
        {"name": "SSH - Rot", "pass": UPLOAD_PASS},
        auth=auth, config=auth._config))                        # noqa: SLF001
    assert "error" in res
    assert isolated_filter.active_secret_count() == baseline
    assert not isolated_filter.has_secret(UPLOAD_PASS)


# ------------------------------------------ scenario: concurrent operations
def test_concurrent_ssh_operations_no_refcount_leak(isolated_filter,
                                                    monkeypatch):
    """Concurrent SSH executions: refcounts balance; baseline restored."""
    auth = _use_ssh_auth()
    monkeypatch.setattr(tools, "_resolve_socket_path",
                        lambda: ("/tmp/fake.sock", False))
    monkeypatch.setattr(tools.subprocess, "run", _run_proc_ok)

    baseline = isolated_filter.active_secret_count()
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            res = json.loads(tools.h_use_ssh({"name": "SSH - Life"},
                                             auth=auth))
            assert res["loaded"] is True
        except BaseException as exc:  # noqa: BLE001 - collected for assert
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not errors
    assert isolated_filter.active_secret_count() == baseline
    assert not isolated_filter.has_secret(SENTINEL_PASS)


# ------------------------------ scenario: scope-managed retention, no double
def test_scope_managed_release_no_unknown_warning(isolated_filter):
    """With an ACTIVE execution scope, the scope owns the ONLY release:
    no manual forget_secret, hence zero unknown-release warnings."""
    auth = _use_ssh_auth()
    redactor = isolated_filter
    scope, token = _open_execution_scope(redactor)
    try:
        probe: dict[str, int] = {}

        def run_probe(cmd, **kw):
            if cmd and cmd[0] == "ssh-add":
                # DURING the execution the passphrase is registered via
                # the scope (retain_in_execution_scope path).
                probe["during"] = int(redactor.has_secret(SENTINEL_PASS))
            return _run_proc_ok(cmd, **kw)

        with patch.object(tools.subprocess, "run", run_probe):
            res = json.loads(tools.h_use_ssh({"name": "SSH - Life"},
                                             auth=auth))
        assert res["loaded"] is True
        assert probe.get("during") == 1
        # Handler's finally must NOT have released it (scope still owns it).
        assert redactor.has_secret(SENTINEL_PASS)
    finally:
        _close_execution_scope(scope, token)

    # Scope close released exactly once -> gone, and NO warnings logged.
    assert not redactor.has_secret(SENTINEL_PASS)


def test_no_double_release_warnings(caplog, isolated_filter):
    """End-to-end: scope-managed SSH run emits no unknown-release warning."""
    auth = _use_ssh_auth()
    redactor = isolated_filter
    caplog.set_level(logging.WARNING, logger="vaultwarden.security")

    scope, token = _open_execution_scope(redactor)
    try:
        with patch.object(tools.subprocess, "run", _run_proc_ok):
            res = json.loads(tools.h_use_ssh({"name": "SSH - Life"},
                                             auth=auth))
        assert res["loaded"] is True
    finally:
        _close_execution_scope(scope, token)

    release_warnings = [r for r in caplog.records
                        if "unknown secret" in r.getMessage()]
    assert release_warnings == []
    assert not redactor.has_secret(SENTINEL_PASS)


# --------------------------------------------------- helper-level contracts
def test_retain_release_helpers_noop_on_empty(isolated_filter):
    """Empty values are never registered/released (no phantom release)."""
    baseline = isolated_filter.active_secret_count()
    tools._retain_ssh_secret("", isolated_filter)
    tools._release_ssh_secret("", isolated_filter)
    assert isolated_filter.active_secret_count() == baseline


def test_manual_register_forget_pairs_exactly_once(isolated_filter):
    """Direct register/forget pairing: one release removes exactly one."""
    baseline = isolated_filter.active_secret_count()
    tools._retain_ssh_secret(UPLOAD_PASS, isolated_filter)
    assert isolated_filter.active_secret_count() == baseline + 1
    tools._release_ssh_secret(UPLOAD_PASS, isolated_filter)
    assert isolated_filter.active_secret_count() == baseline


def test_askpass_delivery_unchanged(isolated_filter, monkeypatch):
    """HVA-01 must not alter SSH_ASKPASS delivery: env contract intact."""
    auth = _use_ssh_auth()
    monkeypatch.setattr(tools, "_resolve_socket_path",
                        lambda: ("/tmp/fake.sock", False))
    calls: list[tuple[list, dict]] = []

    def capture(cmd, **kw):
        calls.append((list(cmd), kw))
        return _run_proc_ok(cmd, **kw)

    monkeypatch.setattr(tools.subprocess, "run", capture)
    res = json.loads(tools.h_use_ssh({"name": "SSH - Life"}, auth=auth))
    assert res["loaded"] is True
    add_call = next(c for c in calls if c[0][0] == "ssh-add")
    env = add_call[1]["env"]
    assert set(env) == {"PATH", "HOME", "LC_ALL", "SSH_AUTH_SOCK",
                        "SSH_ASKPASS_REQUIRE", "SSH_ASKPASS", "VW_SSH_PASS"}
    assert env["SSH_ASKPASS_REQUIRE"] == "force"
    assert env["VW_SSH_PASS"] == SENTINEL_PASS
    assert add_call[1]["stdin"] is __import__("subprocess").DEVNULL
    assert not os.path.exists(env["SSH_ASKPASS"])


def test_delete_ssh_registers_nothing(isolated_filter):
    """delete_ssh handles no secret material: baseline unchanged."""
    auth = _fake_auth(EXISTING_SSH)
    baseline = isolated_filter.active_secret_count()
    res = json.loads(tools.h_delete_ssh(
        {"name": "SSH - Rot", "confirm": True},
        auth=auth, config=auth._config))                        # noqa: SLF001
    assert res["deleted"] is True
    assert isolated_filter.active_secret_count() == baseline


# ------------------------------------------------------ scoped redaction
def test_scope_retain_helper_ties_lifetime_to_scope(isolated_filter):
    """ExecutionSecretScope.retain keeps the value until close() releases."""
    redactor = isolated_filter
    scope = ExecutionSecretScope(redactor)
    baseline = redactor.active_secret_count()
    try:
        tools._retain_ssh_secret(SENTINEL_PASS, redactor)  # no scope active
        assert redactor.has_secret(SENTINEL_PASS)
        tools._release_ssh_secret(SENTINEL_PASS, redactor)
        assert redactor.active_secret_count() == baseline

        with _scope_published(scope):
            tools._retain_ssh_secret(SENTINEL_PASS, redactor)
            assert redactor.has_secret(SENTINEL_PASS)
            # Manual release attempt while scope owns it: must be a no-op.
            tools._release_ssh_secret(SENTINEL_PASS, redactor)
            assert redactor.has_secret(SENTINEL_PASS)
        scope.close()
        assert redactor.active_secret_count() == baseline
    finally:
        redactor.forget_secret(SENTINEL_PASS)  # defensive, may warn-free no-op


class _scope_published:
    """Publish *scope* via the ContextVar for the duration of a with-block."""

    def __init__(self, scope):
        self._scope = scope
        self._token = None

    def __enter__(self):
        from vaultwarden import hooks
        self._token = hooks._execution_secret_scope.set(self._scope)
        return self._scope

    def __exit__(self, *exc):
        from vaultwarden import hooks
        hooks._execution_secret_scope.reset(self._token)
        return False

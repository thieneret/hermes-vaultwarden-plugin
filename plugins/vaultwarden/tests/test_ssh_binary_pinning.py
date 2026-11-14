"""SSH binary path-pinning tests (HVA-079-03 BREAKING; Option C schema).

Covers the mandatory-pinning contract end to end:

* binary validator unit rules (missing key, relative path, nonexistent,
  non-regular, non-executable, group/world-writable, symlink chain, wrong
  owner),
* ssh_binary_dir validator rules (unset, relative, nonexistent, not a
  directory, symlink, world-writable, wrong owner, accepted),
* resolve_ssh_binaries: dir-default resolution, override precedence,
  fail-closed on every invalid input,
* handler gate fail-closed + get_tools registration surface: SSH group
  dropped + sanitized WARNING, 8 non-SSH tools fully intact,
* no subprocess (hence no PATH lookup) is ever reached unpinned.

Hermetic: only inert executable stubs under tmp_path; subprocess.run mocked
wherever a probe would otherwise run.
"""
from __future__ import annotations

import json
import logging
import os
from unittest.mock import MagicMock, patch

import pytest

from vaultwarden import errors
from vaultwarden.tests.conftest import make_config, write_fake_ssh_binaries
from vaultwarden.tools import (
    _SSH_BINARY_KEYS,
    _require_ssh_binaries,
    get_tools,
    h_delete_ssh,
    h_use_ssh,
    resolve_ssh_binaries,
    validate_ssh_binary_dir,
    validate_ssh_binary_path,
)

NON_SSH_TOOLS = {
    "vaultwarden_status", "vaultwarden_sync", "vaultwarden_list",
    "vaultwarden_search", "vaultwarden_get_secret_ref", "vaultwarden_store",
    "vaultwarden_update", "vaultwarden_delete",
}
SSH_TOOLS = {"vaultwarden_store_ssh", "vaultwarden_update_ssh",
             "vaultwarden_delete_ssh", "vaultwarden_use_ssh"}


def _mk_stub(tmp_path, name="ssh-add", mode=0o755):
    p = tmp_path / name
    p.write_text("#!/bin/sh\nexit 0\n")
    p.chmod(mode)
    return str(p)


# ------------------------------------------------------------- validator

def test_missing_key_is_required_error():
    # missing/empty key = configuration issue (ConfigError), an invalid
    # on-disk binary = BINARY_ERROR — different classes by design.
    with pytest.raises(errors.ConfigError) as ei:
        validate_ssh_binary_path("", "ssh_add_path")
    assert "required" in ei.value.message
    assert ei.value.code == "CONFIG_ERROR"


def test_relative_path_rejected():
    with pytest.raises(errors.BinaryError) as ei:
        validate_ssh_binary_path("ssh-add", "ssh_add_path")
    assert "absolute path" in ei.value.message


def test_nonexistent_path_rejected(tmp_path):
    missing = str(tmp_path / "no-such-ssh-add")
    with pytest.raises(errors.BinaryError) as ei:
        validate_ssh_binary_path(missing, "ssh_add_path")
    assert "not found" in ei.value.message


def test_non_regular_file_rejected(tmp_path):
    d = tmp_path / "dir"
    d.mkdir()
    with pytest.raises(errors.BinaryError) as ei:
        validate_ssh_binary_path(str(d), "ssh_add_path")
    assert "not a regular file" in ei.value.message


def test_non_executable_rejected(tmp_path):
    p = _mk_stub(tmp_path, mode=0o644)
    with pytest.raises(errors.BinaryError) as ei:
        validate_ssh_binary_path(p, "ssh_add_path")
    assert "not executable" in ei.value.message


def test_group_writable_rejected(tmp_path):
    p = _mk_stub(tmp_path, mode=0o775)
    with pytest.raises(errors.BinaryError) as ei:
        validate_ssh_binary_path(p, "ssh_add_path")
    assert "group/world-writable" in ei.value.message


def test_world_writable_rejected(tmp_path):
    p = _mk_stub(tmp_path, mode=0o757)
    with pytest.raises(errors.BinaryError) as ei:
        validate_ssh_binary_path(p, "ssh_add_path")
    assert "group/world-writable" in ei.value.message


def test_symlink_rejected(tmp_path):
    real = _mk_stub(tmp_path, name="real-add")
    link = tmp_path / "ssh-add"
    link.symlink_to(real)
    with pytest.raises(errors.BinaryError) as ei:
        validate_ssh_binary_path(str(link), "ssh_add_path")
    assert "symlink" in ei.value.message


def test_directory_component_symlink_rejected(tmp_path):
    real = tmp_path / "realbin"
    real.mkdir()
    stub = real / "ssh-add"
    stub.write_text("#!/bin/sh\nexit 0\n")
    stub.chmod(0o755)
    linkdir = tmp_path / "bin"
    linkdir.symlink_to(real)
    with pytest.raises(errors.BinaryError) as ei:
        validate_ssh_binary_path(str(linkdir / "ssh-add"), "ssh_add_path")
    assert "symlink" in ei.value.message


def test_wrong_owner_rejected(tmp_path, monkeypatch):
    # Hermetic foreign-owner simulation: the validator compares the file's
    # st_uid to os.geteuid(); faking the euid one step up makes the test's
    # own uid look foreign — no real chown, no root required.
    p = _mk_stub(tmp_path)
    real = os.geteuid
    monkeypatch.setattr(os, "geteuid", lambda: real() + 1)
    with pytest.raises(errors.BinaryError) as ei:
        validate_ssh_binary_path(p, "ssh_add_path")
    assert "owner" in ei.value.message


def test_valid_stub_accepted_and_normalized(tmp_path):
    p = _mk_stub(tmp_path)
    out = validate_ssh_binary_path(p, "ssh_add_path")
    assert out == os.path.abspath(p)


# ------------------------------------------------------- resolve/gate

# ------------------------------------------------------- ssh_binary_dir

def test_dir_unset_is_required_error():
    with pytest.raises(errors.ConfigError) as ei:
        validate_ssh_binary_dir("")
    assert "ssh_binary_dir is required" in ei.value.message
    assert ei.value.code == "CONFIG_ERROR"


def test_dir_relative_rejected():
    with pytest.raises(errors.BinaryError) as ei:
        validate_ssh_binary_dir("usr/bin")
    assert "absolute path" in ei.value.message


def test_dir_nonexistent_rejected(tmp_path):
    with pytest.raises(errors.BinaryError) as ei:
        validate_ssh_binary_dir(str(tmp_path / "no-such-dir"))
    assert "not found" in ei.value.message


def test_dir_not_a_directory_rejected(tmp_path):
    f = tmp_path / "regular-file"
    f.write_text("x")
    with pytest.raises(errors.BinaryError) as ei:
        validate_ssh_binary_dir(str(f))
    assert "not a directory" in ei.value.message


def test_dir_symlink_rejected(tmp_path):
    real = tmp_path / "realdir"
    real.mkdir()
    link = tmp_path / "linkdir"
    link.symlink_to(real)
    with pytest.raises(errors.BinaryError) as ei:
        validate_ssh_binary_dir(str(link))
    assert "symlink" in ei.value.message


def test_dir_world_writable_rejected(tmp_path):
    d = tmp_path / "writedir"
    d.mkdir()
    d.chmod(0o757)
    with pytest.raises(errors.BinaryError) as ei:
        validate_ssh_binary_dir(str(d))
    assert "group/world-writable" in ei.value.message


def test_dir_wrong_owner_rejected(tmp_path, monkeypatch):
    d = tmp_path / "owndir"
    d.mkdir()
    real = os.geteuid
    monkeypatch.setattr(os, "geteuid", lambda: real() + 1)
    with pytest.raises(errors.BinaryError) as ei:
        validate_ssh_binary_dir(str(d))
    assert "owner" in ei.value.message


def test_dir_accepted_returns_abspath(tmp_path):
    d = tmp_path / "bins"
    d.mkdir()
    assert validate_ssh_binary_dir(str(d)) == os.path.abspath(str(d))


# ------------------------------------------- resolve: dir + overrides

def test_resolve_all_three_from_dir(tmp_path):
    bins = write_fake_ssh_binaries(str(tmp_path / "bins"))
    resolved, err = resolve_ssh_binaries(make_config(section=bins))
    assert err is None
    assert set(resolved) == set(_SSH_BINARY_KEYS)
    d = os.path.abspath(str(tmp_path / "bins"))
    assert resolved["ssh_add_path"] == os.path.join(d, "ssh-add")
    assert resolved["ssh_keygen_path"] == os.path.join(d, "ssh-keygen")
    assert resolved["ssh_agent_path"] == os.path.join(d, "ssh-agent")


def test_override_wins_others_stay_on_dir(tmp_path):
    bins = write_fake_ssh_binaries(str(tmp_path / "bins"))
    alt = tmp_path / "altbin"
    alt.mkdir()
    custom = _mk_stub(alt, name="custom-add")
    cfg = make_config(section={**bins, "ssh_add_path": custom})
    resolved, err = resolve_ssh_binaries(cfg)
    assert err is None
    d = os.path.abspath(str(tmp_path / "bins"))
    assert resolved["ssh_add_path"] == os.path.abspath(custom)
    assert resolved["ssh_keygen_path"] == os.path.join(d, "ssh-keygen")
    assert resolved["ssh_agent_path"] == os.path.join(d, "ssh-agent")


def test_resolve_missing_dir_fails_closed():
    resolved, err = resolve_ssh_binaries(make_config())
    assert resolved is None
    assert "ssh_binary_dir" in err.message


def test_resolve_binary_missing_from_dir_fails_closed(tmp_path):
    d = tmp_path / "bins"
    d.mkdir()
    _mk_stub(d, name="ssh-add")      # only two of the three present
    _mk_stub(d, name="ssh-keygen")
    cfg = make_config(section={"ssh_binary_dir": str(d)})
    resolved, err = resolve_ssh_binaries(cfg)
    assert resolved is None
    assert "ssh-agent" in err.message and "not found" in err.message


def test_resolve_invalid_override_fails_closed(tmp_path):
    bins = write_fake_ssh_binaries(str(tmp_path / "bins"))
    bad = _mk_stub(tmp_path, name="bad-override", mode=0o644)
    cfg = make_config(section={**bins, "ssh_keygen_path": bad})
    resolved, err = resolve_ssh_binaries(cfg)
    assert resolved is None
    assert "not executable" in err.message


def test_resolve_symlinked_dir_fails_closed(tmp_path):
    real = tmp_path / "realbins"
    write_fake_ssh_binaries(str(real))
    link = tmp_path / "linkbins"
    link.symlink_to(real)
    cfg = make_config(section={"ssh_binary_dir": str(link)})
    resolved, err = resolve_ssh_binaries(cfg)
    assert resolved is None
    assert "symlink" in err.message


def test_require_gate_raises_sanitized_config_error():
    with pytest.raises(errors.ConfigError) as ei:
        _require_ssh_binaries(make_config())  # nothing pinned
    assert "fail-closed" in ei.value.message
    # sanitized: no secrets obviously impossible here, but no PATH-style
    # bare binary names either — the suggestion names the config keys.
    assert "ssh_binary_dir" in (ei.value.suggestion or "")


# ------------------------------------------------- registration surface

def _auth_stub():
    auth = MagicMock()
    auth.get_session.return_value = None
    auth.status_snapshot.return_value = {"operational": True}
    return auth


def test_get_tools_unpinned_drops_ssh_group_with_warning(tmp_path, caplog):
    with caplog.at_level(logging.WARNING,
                         logger="hermes.plugins.vaultwarden"):
        pairs = get_tools(_auth_stub(), make_config(), MagicMock())
    names = {schema["name"] for schema, _ in pairs}
    assert names == NON_SSH_TOOLS
    assert not (names & SSH_TOOLS)
    # get_tools()'s own registration-surface wording (the register() layer
    # in __init__ uses "DISABLED"; get_tools itself logs "NOT registered").
    assert "NOT registered (fail-closed)" in caplog.text
    # the WARNING carries config-key guidance, no secrets/paths leak
    assert "ssh_add_path" in caplog.text


def test_get_tools_invalid_stub_drops_ssh_group(tmp_path):
    bins = write_fake_ssh_binaries(str(tmp_path / "bins"))
    bad = tmp_path / "bins" / "ssh-keygen"
    bad.chmod(0o644)  # world-visible but non-executable -> invalid
    cfg = make_config(section=bins)
    pairs = get_tools(_auth_stub(), cfg, MagicMock())
    names = {schema["name"] for schema, _ in pairs}
    assert names == NON_SSH_TOOLS


def test_get_tools_pinned_registers_all_twelve(tmp_path):
    cfg = make_config(section=write_fake_ssh_binaries(str(tmp_path / "bins")))
    pairs = get_tools(_auth_stub(), cfg, MagicMock())
    names = {schema["name"] for schema, _ in pairs}
    assert names == NON_SSH_TOOLS | SSH_TOOLS


# ------------------------------------------- handler gates, no PATH path

def test_use_ssh_gate_fails_closed_without_subprocess(tmp_path):
    auth = MagicMock()  # gate must fire before any vault/subprocess work
    cfg = make_config(section={"allow_write": True})  # no ssh_binary_dir
    with patch("vaultwarden.tools.subprocess.run") as mock_run:
        res = json.loads(h_use_ssh({"name": "SSH - X"}, auth=auth, config=cfg))
    assert res["error_code"] == "CONFIG_ERROR"
    assert "fail-closed" in res["error"]
    mock_run.assert_not_called()
    auth.search_items.assert_not_called()


def test_delete_ssh_gate_precedes_confirm_check(tmp_path):
    auth = MagicMock()
    cfg = make_config(section={"allow_write": True})  # no ssh_binary_dir
    res = json.loads(h_delete_ssh({"name": "SSH - X"}, auth=auth, config=cfg))
    assert res["error_code"] == "CONFIG_ERROR"
    # SSH gate wording, NOT the confirm=true wording (gate runs first).
    assert "fail-closed" in res["error"]
    assert "confirm" not in res["error"]


def test_non_ssh_handlers_unaffected_by_missing_ssh_keys(tmp_path):
    # The gate belongs to the SSH tool group only: status must still work.
    cfg = make_config()  # nothing pinned at all
    handler = {s["name"]: h for s, h in
               get_tools(_auth_stub(), cfg, MagicMock())}["vaultwarden_status"]
    res = json.loads(handler({}))
    assert "status" in res


# -------------------------------------------- ssh_tools_status report

def _status_handler(cfg):
    return {s["name"]: h for s, h in
            get_tools(_auth_stub(), cfg, MagicMock())}["vaultwarden_status"]


def test_ssh_status_available_true_when_pinned_valid(tmp_path):
    cfg = make_config(section=write_fake_ssh_binaries(str(tmp_path / "bins")))
    rep = json.loads(_status_handler(cfg)({}))["ssh_tools"]
    assert rep["available"] is True
    d = os.path.abspath(str(tmp_path / "bins"))
    assert rep["ssh_binary_dir"] == d
    assert rep["binaries"] == {"ssh_add": "valid", "ssh_keygen": "valid",
                               "ssh_agent": "valid"}
    assert "reason" not in rep


def test_ssh_status_unset_dir_reports_reason():
    rep = json.loads(_status_handler(make_config())({}))["ssh_tools"]
    assert rep["available"] is False
    assert rep["reason"] == "ssh_binary_dir not configured"


def test_ssh_status_invalid_binary_per_binary_detail(tmp_path):
    bins = write_fake_ssh_binaries(str(tmp_path / "bins"))
    (tmp_path / "bins" / "ssh-agent").chmod(0o644)  # not executable
    rep = json.loads(_status_handler(make_config(section=bins))({}))["ssh_tools"]
    assert rep["available"] is False
    assert rep["binaries"]["ssh_add"] == "valid"
    assert rep["binaries"]["ssh_agent"] == "invalid"
    assert "ssh-agent" in rep["reason"]
    assert "not executable" in rep["reason"]


def test_ssh_status_bad_directory_skips_binaries(tmp_path):
    d = tmp_path / "worldwritable"
    d.mkdir()
    d.chmod(0o757)
    cfg = make_config(section={"ssh_binary_dir": str(d)})
    rep = json.loads(_status_handler(cfg)({}))["ssh_tools"]
    assert rep["available"] is False
    assert "group/world-writable" in rep["reason"]
    assert "binaries" not in rep  # directory failed: per-binary unchecked


def test_ssh_status_spawns_no_subprocess(tmp_path):
    cfg = make_config(section=write_fake_ssh_binaries(str(tmp_path / "bins")))
    with patch("vaultwarden.tools.subprocess.run") as mock_run, \
         patch("vaultwarden.tools.subprocess.Popen") as mock_popen:
        rep = json.loads(_status_handler(cfg)({}))["ssh_tools"]
    assert rep["available"] is True
    mock_run.assert_not_called()
    mock_popen.assert_not_called()


def test_ssh_status_needs_no_unlocked_session(tmp_path):
    # Fully failed auth reconciliation: status degrades to the
    # observational snapshot but the SSH report must still be present.
    auth = _auth_stub()
    auth.get_session.side_effect = RuntimeError("locked")
    auth.ensure_authenticated.side_effect = RuntimeError("locked")
    auth.status_snapshot.return_value = {"operational": False}
    cfg = make_config(section=write_fake_ssh_binaries(str(tmp_path / "bins")))
    handler = {s["name"]: h for s, h in
               get_tools(auth, cfg, MagicMock())}["vaultwarden_status"]
    res = json.loads(handler({}))
    assert res["status"]["operational"] is False
    assert res["ssh_tools"]["available"] is True
    assert res["ssh_tools"]["binaries"]["ssh_agent"] == "valid"

"""Generic unknown-parameter rejection across all 12 tool handlers.

The Hermes core performs no call-time schema validation of tool arguments,
so every handler enforces its declared-parameter set itself: any undeclared
key aborts the call with a CONFIG_ERROR naming the offending key(s), before
any other handler logic (including generate branches and write gating)
runs.

Note: the rejection check runs BEFORE any auth/bw usage, so these tests
intentionally use a duck-typed auth stub instead of the bw-binary fixture
chain — the stub is never reached on the probe path, and the minimal
method set below covers the two valid-call paths exercised.
"""
from __future__ import annotations

import re

from vaultwarden.placeholders import PlaceholderRegistry
from vaultwarden.tests.conftest import _dict_tools as _conftest_dict_tools
from vaultwarden.tests.conftest import make_config, write_fake_ssh_binaries

# Built at runtime from parts so this module's own literals can never match
# the forbidden token patterns (mirrors the version-coupling guard style).
_VERSION_PAT = re.compile("v" + r"\d+\.\d+")
_AUDIT_PAT = re.compile("(?:" + "|".join(("HAV", "AUD", "SEC", "VWP")) + r")-?\d")

_PROBE = "zzz_unknown_probe"

_ALL_TOOLS = (
    "vaultwarden_status", "vaultwarden_sync", "vaultwarden_list",
    "vaultwarden_search", "vaultwarden_get_secret_ref", "vaultwarden_store",
    "vaultwarden_update", "vaultwarden_delete", "vaultwarden_store_ssh",
    "vaultwarden_update_ssh", "vaultwarden_delete_ssh", "vaultwarden_use_ssh",
)


class _StubAuth:
    """Duck-typed auth: only the two valid-call paths touch these."""

    def get_session(self):
        return None

    def status_snapshot(self) -> dict:
        return {"plugin": "vaultwarden", "operational": True}

    def list_items(self, filters=None) -> list:
        return []


def _tools(tmp_path):
    # SSH pinning: pin valid stub binaries so the SSH tool group registers
    # and all twelve handlers are present for the unknown-param probe.
    cfg = make_config(section=write_fake_ssh_binaries(str(tmp_path / "ssh-bins")))
    return _conftest_dict_tools(_StubAuth(), cfg, PlaceholderRegistry())


def test_all_twelve_tools_covered(tmp_path):
    assert len(_ALL_TOOLS) == 12


def _probe_rejection(tools, tool):
    res = tools[tool]({_PROBE: "x"})
    assert res["error_code"] == "CONFIG_ERROR", (tool, res)
    assert _PROBE in res["error"], (tool, res)
    return res["error"]


def test_unknown_param_rejected_by_every_handler(tmp_path):
    tools = _tools(tmp_path)
    for tool in _ALL_TOOLS:
        _probe_rejection(tools, tool)


def test_error_message_free_of_version_and_audit_tokens(tmp_path):
    tools = _tools(tmp_path)
    for tool in _ALL_TOOLS:
        msg = _probe_rejection(tools, tool)
        assert not _VERSION_PAT.search(msg), (tool, msg)
        assert not _AUDIT_PAT.search(msg), (tool, msg)


def test_declared_params_still_accepted(tmp_path):
    # list/status are non-SSH tools: they stay available even with stub
    # binaries pinned.
    tools = _tools(tmp_path)
    res = tools["vaultwarden_list"]({"type": "login", "limit": 5})
    assert "error_code" not in res, res
    assert res["items"] == []
    res = tools["vaultwarden_status"]({})
    assert "status" in res, res

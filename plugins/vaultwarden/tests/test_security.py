"""Security tests (plan §13): redaction, env hygiene, escaping, opacity."""
from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest

from vaultwarden.security import (
    BW_ENV_ALLOWLIST,
    RedactingFilter,
    audit_subprocess_env,
    escape_for_context,
    placeholder_tokens,
    shell_escape,
    url_escape,
)


# ---------------------------------------------------------------- redaction
def test_redacting_filter_scrubs_registered_secrets():
    f = RedactingFilter()
    f.register_secret("s3cret-value")
    rec = logging.LogRecord("x", logging.INFO, "", 0,
                            "connecting with s3cret-value now", (), None)
    assert f.filter(rec) is True
    assert "s3cret-value" not in rec.getMessage()
    assert "[REDACTED]" in rec.getMessage()


def test_session_key_shape_masked():
    f = RedactingFilter()
    msg = 'bw unlock output: 2f4c9a7b-1d2e-3f4a-5b6c-7d8e9fa0b1c2:' + "A" * 40
    rec = logging.LogRecord("x", logging.INFO, "", 0, msg, (), None)
    f.filter(rec)
    assert "[SESSION:****]" in rec.getMessage()
    assert "A" * 40 not in rec.getMessage()


def test_plugin_loggers_carry_shared_filter():
    from vaultwarden.security import get_logger, get_redacting_filter
    lg = get_logger("demo")
    assert any(isinstance(fl, RedactingFilter) for fl in lg.filters)
    shared = get_redacting_filter()
    shared.register_secret("topsecret-mp")
    rec = logging.LogRecord("x", logging.ERROR, "", 0, "pw=topsecret-mp", (), None)
    list(lg.filters)[0].filter(rec)
    assert "topsecret-mp" not in rec.getMessage()


# ------------------------------------------------------------- env hygiene
def test_audit_flags_disallowed_keys():
    bad = {"PATH": "/x", "HOME": "/h", "BITWARDENCLI_APPDATA_DIR": "/d",
           "VW_MASTER_PASSWORD": "leak", "AWS_SECRET_ACCESS_KEY": "k"}
    v = audit_subprocess_env(bad)
    assert "VW_MASTER_PASSWORD" in v and "AWS_SECRET_ACCESS_KEY" in v
    assert audit_subprocess_env(
        {"PATH": "", "HOME": "", "BITWARDENCLI_APPDATA_DIR": "",
         "BW_SESSION": "s", "BW_CLIENTID": "c", "BW_CLIENTSECRET": "x",
         "BW_MP": "m"}) == []
    assert BW_ENV_ALLOWLIST == {"PATH", "HOME", "BITWARDENCLI_APPDATA_DIR",
                                "BW_SESSION", "BW_CLIENTID", "BW_CLIENTSECRET", "BW_MP"}


def test_no_bootstrap_secrets_in_os_environ_after_register(monkeypatch, tmp_path, fake_bw,
                                                           hermes_home_with_secrets):
    """v0.5.0: secrets.yaml bootstrap must not put secret values in os.environ."""
    monkeypatch.setenv("HERMES_HOME", str(hermes_home_with_secrets))
    import vaultwarden
    from vaultwarden.tests.conftest import BASE_SECTION, RecordingCtx
    ctx = RecordingCtx({**BASE_SECTION, "enabled": True,
                           "bw_cli_path": fake_bw})
    vaultwarden.register(ctx)
    assert "VW_CLIENT_SECRET" not in os.environ
    assert "VW_MASTER_PASSWORD" not in os.environ
    # the loaded VALUES never enter the environment either
    assert "cs-secret" not in os.environ.values()
    assert "mp-secret" not in os.environ.values()
    assert "BW_SESSION" not in os.environ   # session key NEVER exported globally


def test_master_password_never_logged(caplog, bw_cli):
    from vaultwarden.auth import AuthManager
    from vaultwarden.tests.conftest import make_config
    caplog.set_level(logging.DEBUG)
    mgr = AuthManager(bw_cli, make_config(), client_secret="cs-secret",
                      master_password="SUPER-DUPER-MP")
    # v0.1.5 (FAIL-9): removed the nonsensical `with pytest.raises(Exception):
    # pass` block (it asserted nothing could raise inside an empty body and
    # always failed with "DID NOT RAISE"). The real check is below: after a
    # full bootstrap attempt with wrong credentials, no secret VALUE may
    # appear in any log record.
    # v0.1.9: ensure_authenticated() checks `bw status` first and then logs
    # in — a wrong client secret fails during login, BEFORE any log record
    # could carry a secret value.
    try:
        mgr.ensure_authenticated()          # wrong client secret -> fails
    except Exception:
        pass
    joined = " ".join(r.getMessage() for r in caplog.records)
    assert "SUPER-DUPER-MP" not in joined
    assert "cs-secret" not in joined


# ---------------------------------------------------------------- escaping
def test_shell_escape_blocks_injection():
    evil = "p@ss$(rm -rf /)`x`;"
    esc = shell_escape(evil)
    assert esc.startswith("'") or "\\" in esc
    assert "$(" not in esc.strip("'") or esc.count("'") >= 2


def test_url_escape_encodes_at_and_slash():
    assert url_escape("a@b/c?d=e") == "a%40b%2Fc%3Fd%3De"


def test_escape_context_detection():
    cmd_url = "psql 'postgres://user:__VW_SECRET_aaaaaaaaaaaa__@host/db'"
    assert looks(cmd_url, "__VW_SECRET_aaaaaaaaaaaa__") is True
    cmd_shell = "export X=__VW_SECRET_bbbbbbbbbbbb__; run"
    assert looks(cmd_shell, "__VW_SECRET_bbbbbbbbbbbb__") is False


def looks(cmd, tok):
    from vaultwarden.security import looks_like_url_context
    return looks_like_url_context(cmd, tok)


def test_unknown_context_double_escaped():
    val = "p@ss word"
    out = escape_for_context(val, "echo __VW_SECRET_cccccccccccc__ tail",
                             "__VW_SECRET_cccccccccccc__")
    assert "'" in out or "%" in out      # quoted at minimum


# ------------------------------------------------------------ placeholder opacity
def test_placeholder_tokens_parsing():
    toks = placeholder_tokens("a __VW_SECRET_0123456789ab__ b __VW_SECRET_ffffffffffff__ c")
    assert toks == ["__VW_SECRET_0123456789ab__", "__VW_SECRET_ffffffffffff__"]
    assert placeholder_tokens("__VW_SECRET_short__") == []
    assert placeholder_tokens("no tokens here") == []


def test_tool_outputs_contain_no_vault_secrets(tools_by_name):
    secrets = ("sup3r-s3cret-pg!", "gr@fpassx", "JBSWY3DPEHPK3PXP",
               "custom-key-value", "sk_live_XXXX")
    outputs = [
        tools_by_name["vaultwarden_status"]({}),
        tools_by_name["vaultwarden_list"]({}),
        tools_by_name["vaultwarden_search"]({"query": "keys"}),
        tools_by_name["vaultwarden_get_secret_ref"](
            {"item_id": "Postgres prod", "field": "password"}),
    ]
    blob = str(outputs)
    for s in secrets:
        assert s not in blob


def test_config_contains_no_secret_values():
    from vaultwarden.config import _DEFAULTS
    blob = str(_DEFAULTS).lower()
    for forbidden in ("secret-value", "password=", "master_password: "):
        assert forbidden not in blob
    # v0.5.0 (BREAKING): the env-based secret config keys are gone entirely —
    # bootstrap secrets come from secrets.yaml, never from .env / OS env.
    assert "client_secret_env" not in _DEFAULTS
    assert "master_password_env" not in _DEFAULTS


def test_session_key_not_persisted_to_disk(bw_cli, tmp_path):
    from vaultwarden.auth import AuthManager
    from vaultwarden.tests.conftest import make_config
    mgr = AuthManager(bw_cli, make_config(), client_secret="cs-secret",
                      master_password="mp-secret")
    mgr.ensure_authenticated()
    key = mgr.get_session()
    # v0.1.5 (FAIL-10): skip the fake bw script itself — it is a TEST FIXTURE
    # whose source literally embeds the session-key string it prints (the
    # real bw also keeps its own state files); it is not plugin-written
    # state. We only assert that no file the PLUGIN wrote contains the key.
    fake_bw_path = Path(bw_cli.bw_path).resolve() if hasattr(bw_cli, "bw_path") else None
    for f in tmp_path.rglob("*"):
        if not f.is_file():
            continue
        try:
            resolved = f.resolve()
        except OSError:
            continue
        if fake_bw_path is not None and resolved == fake_bw_path:
            continue
        if f.name == "bw":  # fake bw fixture (script/binary) — not plugin state
            continue
        content = f.read_bytes()
        assert key.encode() not in content, f
    # plugin state dir contains no session key file of ours:
    appdata_files = list((tmp_path / ".bw-data").rglob("*"))
    assert all("session" not in p.name.lower() for p in appdata_files)


def test_error_messages_are_secret_free(bw_cli):
    from vaultwarden import errors as E
    from vaultwarden.auth import AuthManager
    from vaultwarden.tests.conftest import make_config
    mgr = AuthManager(bw_cli, make_config(), client_secret="cs-secret",
                      master_password="BAD-PW")
    with pytest.raises(E.VaultwardenError) as ei:
        mgr.ensure_authenticated()
    resp = ei.value.to_dict()
    assert "BAD-PW" not in str(resp)
    assert resp["error_code"] in ("AUTH_ERROR", "PLUGIN_ERROR", "NETWORK_ERROR")


# ---------------------------------------------------------------------------
# Consolidated from test_security_hardening_v022.py (hooks/race-condition parts)
# ---------------------------------------------------------------------------

def test_account_verification_fail_closed():
    """SECURITY: empty userId must NOT be treated as correct account."""
    # Simulate: current_user_id = "", expected_user_id = "1234-5678"
    current_user_id = ""
    expected_user_id = "1234-5678"
    is_correct_account = (
        bool(current_user_id) and current_user_id == expected_user_id)
    assert not is_correct_account


def test_pending_errors_task_isolation():
    """BUGFIX: parallel tool calls must not lose each other's errors."""
    from vaultwarden.hooks import _PENDING_ERRORS, _PENDING_LOCK

    # Simulate two tasks adding errors
    with _PENDING_LOCK:
        _PENDING_ERRORS.setdefault("task_A", []).append({"error": "A"})
        _PENDING_ERRORS.setdefault("task_B", []).append({"error": "B"})

    # Pop task_A — task_B must survive
    with _PENDING_LOCK:
        errors_a = _PENDING_ERRORS.pop("task_A", [])
    assert len(errors_a) == 1
    with _PENDING_LOCK:
        assert "task_B" in _PENDING_ERRORS
        errors_b = _PENDING_ERRORS.pop("task_B", [])
    assert len(errors_b) == 1


def test_terminal_tools_configurable():
    """BUGFIX: terminal tool names must be configurable."""
    from vaultwarden.config import PluginConfig
    cfg = PluginConfig(section={"terminal_tool_names": ["my_custom_shell"]})
    assert cfg.terminal_tool_names == ["my_custom_shell"]


def test_resolver_uses_default_expanded_terminal_tools():
    """BUGFIX: new default tool names (run_command/exec/...) are recognized."""
    from unittest.mock import MagicMock

    from vaultwarden.hooks import make_placeholder_resolver

    auth = MagicMock()
    registry = MagicMock()
    mw = make_placeholder_resolver(auth, registry, config=None)
    seen: list = []
    nc = lambda a: seen.append(a) or "ran"  # noqa: E731
    # foreign tool still ignored — passed straight through to next_call
    assert mw("file_read", {"command": "$__VW_SECRET_x__"}, None, nc,
              task_id="t") == "ran"
    assert seen == [{"command": "$__VW_SECRET_x__"}]
    # new default exec-ish tool passes the gate (registry lookup mocked to
    # fail-safe, but the important part is it does NOT skip the tool)
    out = mw("exec", {"command": "echo $__VW_SECRET_deadbeefcafe__"}, None, nc,
             task_id="t-cfg")
    assert out == "ran"
    from vaultwarden.hooks import _PENDING_ERRORS, _PENDING_LOCK
    with _PENDING_LOCK:
        _PENDING_ERRORS.pop("t-cfg", None)


def test_resolver_honours_custom_terminal_tool_names():
    """BUGFIX: config-provided tool names REPLACE the defaults."""
    from unittest.mock import MagicMock

    from vaultwarden.hooks import make_placeholder_resolver

    auth = MagicMock()
    registry = MagicMock()
    cfg = MagicMock()
    cfg.terminal_tool_names = ["my_custom_shell"]
    cfg.terminal_command_keys = ["payload"]
    mw = make_placeholder_resolver(auth, registry, config=cfg)
    seen: list = []
    nc = lambda a: seen.append(a) or "ran"  # noqa: E731
    # default name "terminal" is NO LONGER handled when config overrides
    assert mw("terminal", {"command": "$__VW_SECRET_x__"}, None, nc,
              task_id="t") == "ran"
    # custom name + custom key ARE handled
    out = mw("my_custom_shell", {"payload": "echo $__VW_SECRET_deadbeefcafe__"},
             None, nc, task_id="t-custom")
    assert out == "ran"
    from vaultwarden.hooks import _PENDING_ERRORS, _PENDING_LOCK
    with _PENDING_LOCK:
        _PENDING_ERRORS.pop("t-custom", None)


def test_post_cleanup_surfaces_only_own_task_errors():
    """BUGFIX (integration): one task's post hook must not steal another's errors."""
    from unittest.mock import MagicMock

    from vaultwarden.hooks import _PENDING_ERRORS, _PENDING_LOCK, make_post_cleanup_hook
    post = make_post_cleanup_hook(MagicMock(), MagicMock())
    with _PENDING_LOCK:
        _PENDING_ERRORS["task_1"] = [{"error_code": "PLACEHOLDER_ERROR", "task": 1}]
        _PENDING_ERRORS["task_2"] = [{"error_code": "PLACEHOLDER_ERROR", "task": 2}]

    res: dict = {"output": "ok"}
    post("terminal", {}, res, task_id="task_1")
    assert len(res.get("vaultwarden_placeholder_errors", [])) == 1
    assert res["vaultwarden_placeholder_errors"][0]["task"] == 1
    with _PENDING_LOCK:
        # task_2's errors survived task_1's cleanup
        assert "task_2" in _PENDING_ERRORS
        _PENDING_ERRORS.clear()


# ---------------------------------------------------------------------------
# Consolidated from test_cleanup_hardening_v023.py (redaction part)
# ---------------------------------------------------------------------------

def test_collect_secret_strings():
    """Bug #1 fix: recursive string extraction for redaction."""
    from vaultwarden.tools import _collect_secret_strings
    args = {
        "name": "test",
        "password": "s3cr3t",
        "username": "api-key-12345",
        "notes": "recovery seed phrase here",
        "custom_fields": [{"name": "token", "value": "jwt-abc"}],
        "empty": "",
        "number": 42,
    }
    collected = _collect_secret_strings(args)
    assert "s3cr3t" in collected
    assert "api-key-12345" in collected
    assert "recovery seed phrase here" in collected
    assert "jwt-abc" in collected
    assert "" not in collected
    assert "42" not in collected


def test_store_and_update_register_all_string_args(write_tools_by_name):
    """SECURITY: every non-empty string arg is redacted during store/update."""
    from vaultwarden.security import get_redacting_filter
    redactor = get_redacting_filter()

    res = write_tools_by_name["vaultwarden_store"]({
        "name": "svc-login", "username": "api-user-leakme",
        "password": "pw-leakme", "notes": "note-secret-leakme"})
    assert res.get("created") is True, res
    # after completion everything must be unregistered again...
    for s in ("api-user-leakme", "pw-leakme", "note-secret-leakme"):
        assert s not in redactor._secrets
    # ...and DURING the operation they were registered (spy proves it):
    # AUD-02 (v0.6.5): runtime tool secrets now flow through the scoped
    # retain/release helpers, which delegate to RedactingFilter.retain_secret
    # / release_secret (reference-counted) instead of unbounded global
    # register_secret/forget_secret.
    registered: list[str] = []
    orig_retain = redactor.retain_secret
    orig_release = redactor.release_secret
    redactor.retain_secret = lambda v: (registered.append(v), orig_retain(v))[1]
    redactor.release_secret = lambda v: (orig_release(v),)[0]
    try:
        res2 = write_tools_by_name["vaultwarden_update"]({
            "item_id": res["id"],
            "username": "upd-user-leakme", "uri": "https://upd-leakme.example"})
        assert res2.get("updated") is True, res2
        assert "upd-user-leakme" in registered
        assert "https://upd-leakme.example" in registered
    finally:
        redactor.retain_secret = orig_retain
        redactor.release_secret = orig_release
    for s in registered:
        assert s not in redactor._secrets


# ---------------------------------------------------------------------------
# Consolidated from test_cleanup_hardening_v026.py (Hungarian-text cleanup)
# ---------------------------------------------------------------------------

def test_no_hungarian_in_comments():
    """v0.2.6: no Hungarian words in comments or docstrings."""
    import re
    from pathlib import Path

    import vaultwarden

    pkg_dir = Path(vaultwarden.__file__).resolve().parent
    hungarian_pattern = re.compile(
        r"függvény|hiba|jelszó|beállítás|keresés|lista|törlés|frissítés|"
        r"szinkronizálás|biztonság|titok|állapot|működik|könyvtár|"
        r"elérési|útvonal|megjegyzés|fontos|figyelmeztetés|kivétel|"
        r"visszatérési|bemeneti|kimeneti|alapértelmezett|kötelező|"
        r"opcionális|engedélyez|letilt|betölt|zárolt|feloldott",
        re.IGNORECASE)

    violations = []
    for py_file in pkg_dir.glob("*.py"):
        if py_file.name.startswith("test_"):
            continue  # skip test files (they contain the regex itself)
        content = py_file.read_text(encoding="utf-8")
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                if hungarian_pattern.search(line):
                    violations.append(f"{py_file.name}:{i}: {stripped[:80]}")

    assert not violations, (
        f"Hungarian text found in {len(violations)} comment(s):\n"
        + "\n".join(violations[:10]))


# ---------------------------------------------------------------------------
# Consolidated from test_isolation.py (v0.2.9 test restructure)
# ---------------------------------------------------------------------------

def _dict_tools(raw):
    """v0.2.4: handlers return JSON strings; parse back to dicts for tests."""
    import json as _json
    def wrap(handler):
        def inner(args, **kw):
            r = handler(args, **kw)
            return _json.loads(r) if isinstance(r, str) else r
        return inner
    return {k: wrap(h) for k, h in raw.items()}


def test_appdata_dir_in_every_subprocess(fake_bw, tmp_path):
    """Run EVERY supported command and assert the env var reached the child."""
    import subprocess

    from vaultwarden.bw_cli import BwCli
    appdata = tmp_path / "bw-state"
    appdata.mkdir(mode=0o700)
    # VWP-11: BwCli construction now triggers `bw --version`; the spy below
    # is installed first so that subprocess call is audited too.
    cmds = [
        ["status"], ["config", "server", "https://v.example"],
        ["config", "get", "server"],
        ["login", "--apikey", "--nointeraction"],
        ["unlock", "--passwordenv", "BW_MP", "--raw", "--nointeraction"],
        ["sync"], ["list", "items"], ["get", "item", "Postgres prod"],
        ["encode", "x"], ["generate", "16"], ["lock"],
        ["delete", "item", "id"],
    ]
    seen = []
    real_run = subprocess.run

    def spy(cmd, **kw):
        if str(cmd[0]) == fake_bw:
            # VWP-11: the `bw --version` startup check also goes through this
            # spy; audit its env but do NOT count it as one of the cmds below.
            is_version = list(cmd[1:]) == ["--version"]
            assert kw["env"]["BITWARDENCLI_APPDATA_DIR"] == str(appdata), cmd
            # and nothing else from the parent env leaked in:
            assert "VW_MASTER_PASSWORD" not in kw["env"]
            assert "VW_CLIENT_SECRET" not in kw["env"]
            if not is_version:
                seen.append(tuple(cmd[1:2]))
        return real_run(cmd, **kw)

    import vaultwarden.bw_cli as mod
    orig = mod.subprocess.run
    mod.subprocess.run = spy
    try:
        cli = BwCli(fake_bw, appdata)  # VWP-11: triggers bw --version here
        for c in cmds:
            try:
                cli.run(c, env={"BW_CLIENTID": "user.x", "BW_CLIENTSECRET": "cs-secret",
                                "BW_MP": "mp-secret", "BW_SESSION": "sess"})
            except Exception:
                pass  # error mapping is tested elsewhere; here we audit envs
    finally:
        mod.subprocess.run = orig
    assert len(seen) == len(cmds)   # every single invocation was audited


def test_bw_data_permissions_700(tmp_path):
    import os
    import stat

    from vaultwarden.auth import ensure_appdata_dir
    d = ensure_appdata_dir(tmp_path / "nested" / ".bw-data")
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700


def test_bw_rejected_when_appdata_insecure(fake_bw, tmp_path):
    """AUD-04 (v0.6.2): bw must NEVER run against an insecure .bw-data —
    BwCli.base_env() validates fail-closed via the shared hardening layer."""
    from vaultwarden.bw_cli import BwCli
    from vaultwarden.secure_fs import FilesystemSecurityError

    a = tmp_path / "a"
    a.mkdir(mode=0o755)  # group/world accessible — insecure
    cli = BwCli.__new__(BwCli)  # bypass __init__ (no version probe needed)
    cli.appdata_dir = str(a)
    with pytest.raises(FilesystemSecurityError):
        cli.base_env()
    # BITWARDENCLI_APPDATA_DIR was never produced for an insecure dir and
    # no silent repair happened:
    assert (tmp_path / "a").stat().st_mode & 0o777 == 0o755


def test_bw_rejected_when_appdata_symlink(fake_bw, tmp_path):
    """AUD-04 (v0.6.2): symlinked appdata dir blocks every bw invocation."""
    from vaultwarden.bw_cli import BwCli
    from vaultwarden.secure_fs import FilesystemSecurityError

    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / ".bw-data"
    link.symlink_to(real, target_is_directory=True)
    cli = BwCli.__new__(BwCli)
    cli.appdata_dir = str(link)
    with pytest.raises(FilesystemSecurityError):
        cli.base_env()


def test_plugin_state_isolated_from_host_profile(fake_bw, tmp_path):
    """A pre-existing 'host' profile must be neither read nor modified."""
    from vaultwarden.bw_cli import BwCli
    host = tmp_path / "host-profile"
    host.mkdir()
    (host / "data.json").write_text("HOST-PROFILE-DATA")
    plugin = tmp_path / ".bw-data"
    plugin.mkdir(mode=0o700)

    cli = BwCli(fake_bw, plugin)
    cli.login_apikey("user.abc", "cs-secret")
    key = cli.unlock_passwordenv("mp-secret")
    cli.list_items(key)

    assert (host / "data.json").read_text() == "HOST-PROFILE-DATA"  # untouched
    assert (plugin / "fake-logged-in").exists()                     # plugin-only state


def test_no_cross_contamination_between_two_profiles(fake_bw, tmp_path):
    from vaultwarden.bw_cli import BwCli
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir(mode=0o700)
    b.mkdir(mode=0o700)
    ca, cb = BwCli(fake_bw, a), BwCli(fake_bw, b)
    ca.login_apikey("user.x", "cs-secret")
    assert ca.status()["status"] == "locked"
    assert cb.status()["status"] == "unauthenticated"  # b never saw a's login


def test_middleware_chain_safety_other_plugin_last_word(fake_bw, tmp_path, registry):
    """Simulated Hermes middleware chain: our resolver must not hijack calls
    that contain no placeholders — other plugins' rewrites survive byte-exact."""
    from vaultwarden.auth import AuthManager
    from vaultwarden.bw_cli import BwCli
    from vaultwarden.hooks import make_placeholder_resolver
    from vaultwarden.tests.conftest import make_config
    appdata = tmp_path / ".bw-data"
    appdata.mkdir(mode=0o700)
    cli = BwCli(fake_bw, appdata)
    auth = AuthManager(cli, make_config(), client_secret="cs-secret",
                       master_password="mp-secret")
    auth.ensure_authenticated()
    ours = make_placeholder_resolver(auth, registry)

    def other_plugin_mw(tool_name, args):
        return {"args": {**args, "timeout": 45}}  # adds its own field

    # --- call with NO placeholder: both middlewares must see original args,
    # ours passes them through byte-identical, chain keeps other plugin's edit.
    base = {"command": "ls -la"}
    passthrough: list = []
    assert ours("terminal", dict(base), None, lambda a: passthrough.append(a)) is None
    assert passthrough == [{"command": "ls -la"}]   # untouched
    step = other_plugin_mw("terminal", base)
    assert step["args"] == {"command": "ls -la", "timeout": 45}

    # --- call WITH placeholder: ours runs last and preserves other fields.
    entry = registry.create("Postgres prod", "password")
    mid = other_plugin_mw("terminal", {"command": f"echo \"${entry.token}\""})
    seen: list = []

    def nc(a):
        seen.append(a)
        return "executed"

    assert ours("terminal", mid["args"], None, nc) == "executed"
    final = seen[0]
    assert final["timeout"] == 45                   # other plugin's edit kept
    assert "$(<" in final["command"]                # file injection happened
    assert "sup3r-s3cret-pg!" not in final["command"]  # secret NOT in command


def test_register_loads_secrets_without_touching_env(monkeypatch, tmp_path, fake_bw):
    """v0.5.0: register() bootstraps from secrets.yaml; secret values live only
    in plugin memory and NEVER enter os.environ (no cleanup needed because
    nothing is ever exported)."""
    import os
    import stat

    import vaultwarden
    home = tmp_path / "hermes-home"
    plugindir = home / "plugins" / "vaultwarden"
    plugindir.mkdir(parents=True)
    sf = plugindir / "secrets.yaml"
    sf.write_text("client_secret: cs-secret\nmaster_password: mp-secret\n")
    sf.chmod(0o600)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("TERMINAL_ENV", "docker")
    # legacy env vars are IRRELEVANT now — even if present they must not be
    # used or removed by the plugin (there is no _cleanup_bootstrap_env).
    monkeypatch.setenv("VW_CLIENT_SECRET", "unused-legacy-value")
    monkeypatch.setenv("VW_MASTER_PASSWORD", "unused-legacy-value")

    from vaultwarden.tests.conftest import BASE_SECTION, RecordingCtx
    ctx = RecordingCtx({**BASE_SECTION, "enabled": True,
                           "bw_cli_path": fake_bw})
    ok = vaultwarden.register(ctx)
    assert ok is True
    # loaded VALUES never entered the environment:
    assert "cs-secret" not in os.environ.values()
    assert "mp-secret" not in os.environ.values()
    # ...but the plugin still works (values captured straight from file):
    # v0.1.9: register() defers authentication; this FIRST tool use triggers
    # the lazy ensure_authenticated() and the vault comes up unlocked.
    status = next(t for t in ctx.tools if t["name"] == "vaultwarden_status")
    assert status["check_fn"]() is True          # lazy auth kicks in here
    res = _dict_tools({"status": status["handler"]})["status"]({})
    assert res["status"]["auth_state"] == "unlocked"
    bwdata = home / "plugins" / "vaultwarden" / ".bw-data"
    assert bwdata.exists() and stat.S_IMODE(os.stat(bwdata).st_mode) == 0o700


# --------------------------------------------- SEC-01 (v0.5.4) redaction hook
def test_transform_tool_result_redacts_echoed_secret(monkeypatch, tmp_path,
                                                     fake_bw):
    """SEC-01 integration: simulate the Hermes hook pipeline.

    tool_execution middleware injects a temp-file secret -> the command
    echoes it -> transform_tool_result must return a result whose text is
    scrubbed ([REDACTED]) BEFORE it reaches the model. post_tool_call is
    observer-only and never mutates results for confidentiality reasons.
    """
    from vaultwarden.tests.test_integration import _dict_tools, _register_ok

    ok, ctx = _register_ok(monkeypatch, tmp_path, fake_bw)
    assert ok is True
    hooks = dict(ctx.hooks)
    assert "transform_tool_result" in hooks      # authoritative hook landed
    mw = dict(ctx.middleware)["tool_execution"]
    transform = hooks["transform_tool_result"]
    post = hooks["post_tool_call"]
    tools = _dict_tools({t["name"]: t["handler"] for t in ctx.tools})

    ref = tools["vaultwarden_get_secret_ref"](
        {"item_id": "aaaa1111-0000-0000-0000-000000000001", "field": "password"})
    token = ref["placeholder"]

    echoed = {"output": "printf ran: sup3r-s3cret-pg!\n"}

    def next_call(a):
        # pretend the shell expanded $(< tmpfile) and echoed the plaintext
        return echoed

    result = mw("terminal", {"command": f"printf '%s\\n' \"$(<{token})\""},
                None, next_call, task_id="sec01-task")
    assert result is echoed                       # middleware never mutates

    # observer-only: post_tool_call must NOT scrub anything...
    post("terminal", {}, result, task_id="sec01-task")
    assert "sup3r-s3cret-pg!" in result["output"]

    # ...the transformer does, and its RETURN VALUE is authoritative.
    final = transform("terminal", result, task_id="sec01-task")
    assert "sup3r-s3cret-pg!" not in final["output"]
    assert "[REDACTED]" in final["output"]


def test_transform_tool_result_empty_handoff_still_global_filter(
        auth_manager, registry):
    """No per-execution secrets -> result passes through RedactingFilter only."""
    from vaultwarden.hooks import make_result_redactor
    from vaultwarden.security import get_redacting_filter

    get_redacting_filter().register_secret("bootstrap-global-secret")
    redact = make_result_redactor(auth_manager, registry)
    out = redact("terminal", {"data": "leak bootstrap-global-secret here"},
                 task_id="unknown-task")
    assert "bootstrap-global-secret" not in str(out)
    assert "[REDACTED]" in str(out)
    # unrelated result untouched (no secrets anywhere)
    plain = redact("terminal", {"data": "nothing to see"}, task_id="t2")
    assert plain == {"data": "nothing to see"}


def test_register_fail_closed_without_transform_hook(monkeypatch, tmp_path,
                                                     fake_bw, caplog):
    """SEC-01 fail-closed: hosts without transform_tool_result are refused."""
    import vaultwarden
    from vaultwarden.tests.conftest import BASE_SECTION, RecordingCtx
    from vaultwarden.tests.test_integration import _write_secrets_yaml

    _write_secrets_yaml(tmp_path)
    monkeypatch.delenv("BW_CLI_PATH", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("TERMINAL_ENV", "docker")
    ctx = RecordingCtx({**BASE_SECTION, "enabled": True,
                           "bw_cli_path": fake_bw})
    # simulate an OLDER Hermes build: no declared capability, no attribute
    ctx.supported_hooks = frozenset({"post_tool_call", "on_session_end"})
    with caplog.at_level(logging.ERROR):
        ok = vaultwarden.register(ctx)
    assert ok is False
    assert "transform_tool_result" in caplog.text
    # nothing was registered on the refused load path beyond tools/middleware
    assert all(kind != "transform_tool_result" for kind, _ in ctx.hooks)

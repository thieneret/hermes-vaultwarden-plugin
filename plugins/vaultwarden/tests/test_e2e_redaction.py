"""SEC-01 (v0.5.9) E2E integration tests: the "Leaky Cat" scenario and the
fail-closed registration guarantee.

These tests simulate the FULL Hermes Agent tool execution pipeline against
the fake ``bw`` binary from conftest.py:

    tool_execution middleware  ->  (simulated shell / terminal)
    transform_tool_result      ->  post_tool_call

Unit tests elsewhere verify each hook in isolation; this module wires the
three hooks together exactly the way Hermes dispatches them, so a malicious
or accidental "leaky" command that explicitly prints an injected secret can
never exfiltrate plaintext into the LLM context:

- the ``tool_execution`` middleware resolves the single-use placeholder and
  rewrites ``$__VW_SECRET_x__`` to ``$(< /path/to/temp_file)``;
- the simulated terminal reads the temp file (like ``cat`` would), producing
  raw stdout that contains the PLAINTEXT secret;
- the authoritative ``transform_tool_result`` redactor scrubs the plaintext
  from the result BEFORE it reaches the model (exact replacement with the
  literal ``[REDACTED]``);
- the temp file is deleted (middleware ``finally`` block; verified again by
  the observer-only ``post_tool_call`` hook).

The second test locks in the fail-closed behaviour introduced in v0.5.4: if
the host Hermes build cannot register the ``transform_tool_result`` hook,
``register()`` MUST refuse to load the plugin rather than silently falling
back to the insecure observer-only redaction model.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import pytest

import vaultwarden
from vaultwarden.auth import AuthManager
from vaultwarden.config import PluginConfig
from vaultwarden.hooks import (
    make_placeholder_resolver,
    make_post_cleanup_hook,
    make_result_redactor,
)
from vaultwarden.placeholders import PlaceholderRegistry
from vaultwarden.tests.conftest import BASE_SECTION, RecordingCtx

#: The known test secret used by the E2E scenario. It is registered as the
#: "password" field of the fake item below (see _seed_fake_item) — i.e. it
#: lives inside the (fake) vault and only ever leaves it through the temp
#: file injection path exercised by the middleware.
LEAKY_CAT_SECRET = "SUPER_SECRET_TEST_TOKEN_123"

#: Fake vault item carrying LEAKY_CAT_SECRET as its login password.
FAKE_ITEM_ID = "aaaa1111-0000-0000-0000-000000000001"

#: ``$__VW_SECRET_<12 hex>__`` command reference form (what the middleware
#: scans for inside terminal commands).
CMD_REF_RE = re.compile(r"\$(__VW_SECRET_[0-9a-f]{12}__)")

#: ``$(< '/abs/path/to/temp/file')`` shell substitution produced by the
#: middleware rewrite (AUD-05 phase 2: the path is shlex-quoted; the bare
#: form is still accepted for robustness).
SUBST_RE = re.compile(r"\$\(<\s*(?:'([^']+)'|\"([^\"]+)\"|(/[^)\s]+))\)")


def _subst_path(command: str) -> str | None:
    """Extract the temp-file path from a $(< '...') substitution fragment."""
    m = SUBST_RE.search(command)
    if m is None:
        return None
    return m.group(1) or m.group(2) or m.group(3)


class _RaisingTransformCtx(RecordingCtx):
    """Stand-in Hermes PluginContext whose register_hook RAISES for the
    ``transform_tool_result`` hook (simulating a host that advertises the
    capability but cannot actually install it — e.g. an older/patched
    Hermes build).

    Every other hook registers normally, so the failure is specifically the
    confidentiality boundary, not a blanket failure.
    """

    def register_hook(self, kind: str, fn: Any) -> None:
        if kind == "transform_tool_result":
            raise RuntimeError("host Hermes rejects transform_tool_result")
        super().register_hook(kind, fn)


def _seed_fake_item(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the fake ``bw`` item FAKE_ITEM_ID carry LEAKY_CAT_SECRET.

    Production code is untouched: we only patch ``AuthManager.get_item`` so
    the middleware's resolution path returns a vault item whose password is
    the known E2E secret.
    """
    real_get_item = AuthManager.get_item

    def patched_get_item(self: AuthManager, query: str) -> dict:
        item = dict(real_get_item(self, query))
        if item.get("id") == FAKE_ITEM_ID:
            login = dict(item.get("login") or {})
            # The temp file is written with the value verbatim (no trailing
            # newline); the simulated shell's `cat` below appends the "\n"
            # that shows up in raw_stdout.
            login["password"] = LEAKY_CAT_SECRET
            item["login"] = login
        return item

    monkeypatch.setattr(AuthManager, "get_item", patched_get_item)


def test_e2e_leaky_cat_redaction(auth_manager: AuthManager, registry: PlaceholderRegistry,
                                 plugin_config: PluginConfig,
                                 monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
                                 request: pytest.FixtureRequest) -> None:
    """E2E "Leaky Cat": full pipeline middleware -> transform -> post cleanup.

    Scenario: the agent runs ``echo "$__VW_SECRET_T1__"``-style command that
    ends up printing the content of the injected temp file (exactly what a
    ``cat`` of the temp file would do). The raw terminal stdout therefore
    contains the plaintext secret; the authoritative ``transform_tool_result``
    hook must scrub it down to ``[REDACTED]`` before the result reaches the
    model, and the temp file must be gone afterwards.
    """
    # Isolate the global RedactingFilter for the duration of this test: the
    # middleware registers the injected plaintext globally (hooks.py), so a
    # fresh filter instance keeps the E2E secret from leaking into unrelated
    # suites while still participating in the transform pass exactly like a
    # production host would. monkeypatch restores the singleton afterwards.
    from vaultwarden.security import RedactingFilter, get_redacting_filter

    assert LEAKY_CAT_SECRET not in get_redacting_filter().snapshot_secrets()

    def _forget_leaky_secret() -> None:
        # Belt-and-braces: drop any leftover global registration of the E2E
        # plaintext so it can never influence other tests.
        get_redacting_filter().forget_secret(LEAKY_CAT_SECRET)
    request.addfinalizer(_forget_leaky_secret)

    isolated_filter = RedactingFilter()
    monkeypatch.setattr("vaultwarden.security._shared_filter", isolated_filter,
                        raising=True)
    monkeypatch.setattr("vaultwarden.hooks.get_redacting_filter",
                        lambda: isolated_filter, raising=True)

    # Isolate the secrets dir on tmp_path (hooks._secrets_dir honours
    # XDG_RUNTIME_DIR; mode 700 satisfies the strict v0.5.8 validation).
    xdg = tmp_path / "xdg-runtime"
    xdg.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))

    # ---------------- Setup phase ----------------
    _seed_fake_item(monkeypatch)

    entry = registry.create(FAKE_ITEM_ID, "password")
    cmd_ref = f"${entry.token}"  # command form: $__VW_SECRET_<12 hex>__
    assert CMD_REF_RE.fullmatch(cmd_ref), cmd_ref  # exact command-reference shape

    middleware = make_placeholder_resolver(auth_manager, registry, plugin_config)
    transform = make_result_redactor(auth_manager, registry, plugin_config)
    post = make_post_cleanup_hook(auth_manager, registry, plugin_config)

    captured: dict[str, Any] = {}
    task_id = "e2e-leaky-cat"

    def fake_terminal(args: dict) -> dict:
        """Simulated Hermes terminal tool: parses the rewritten command,
        reads the injected temp file (what ``cat``/shell substitution would
        do) and returns the raw stdout."""
        command = args["command"]
        path = _subst_path(command)
        assert path is not None, f"no $(< path) substitution in rewritten command: {command!r}"
        captured["rewritten_command"] = command
        captured["temp_file_path"] = path
        assert os.path.exists(path), "middleware must create the temp file before next_call"
        # Simulate `cat "$(< tmpfile)"` — the leaky part of the scenario:
        # the shell reads the injected temp file and echoes the PLAINTEXT
        # secret onto stdout (cat terminates the line with "\n").
        with open(path, encoding="utf-8") as fh:
            raw_stdout = fh.read() + "\n"
        captured["raw_stdout"] = raw_stdout
        return {"output": raw_stdout}

    # ---------------- Execution phase (the pipeline) ----------------
    # 1. tool_execution middleware wraps the actual tool invocation. The
    #    "leaky cat" command explicitly reads and prints the placeholder —
    #    after injection the shell will read the temp file itself.
    result = middleware(
        "terminal",
        {"command": f'cat "{cmd_ref}"'},
        None,
        fake_terminal,
        task_id=task_id,
    )

    # 2. Capture: the rewritten command carries $(< /path/to/temp_file) and
    #    NEVER the plaintext secret.
    rewritten = captured["rewritten_command"]
    temp_file_path = captured["temp_file_path"]
    assert "$(<" in rewritten
    assert LEAKY_CAT_SECRET not in rewritten
    assert entry.token not in rewritten  # placeholder consumed, replaced by file ref

    # 3. The simulated terminal really printed the plaintext secret.
    raw_stdout = result["output"]
    assert raw_stdout == f"{LEAKY_CAT_SECRET}\n"

    # 4. transform_tool_result: the AUTHORITATIVE confidentiality boundary.
    transformed = transform("terminal", result, task_id=task_id)
    assert transformed["output"] == "[REDACTED]\n"
    assert LEAKY_CAT_SECRET not in str(transformed)

    # 5. post_tool_call: observer-only cleanup pass (must not resurrect or
    #    mutate the already-redacted result).
    post("terminal", {"command": rewritten}, transformed, task_id=task_id)
    assert transformed["output"] == "[REDACTED]\n"

    # ---------------- Assertions ----------------
    assert raw_stdout == f"{LEAKY_CAT_SECRET}\n"      # plaintext reached the shell
    assert transformed["output"] == "[REDACTED]\n"    # model sees only [REDACTED]
    # The middleware's finally block deleted the temp file; nothing left for
    # post_tool_call to clean up.
    assert not os.path.exists(temp_file_path)
    # No plaintext lingers in either handoff store after the execution.
    from vaultwarden.hooks import peek_task_secrets

    assert peek_task_secrets(task_id) == []
    assert LEAKY_CAT_SECRET not in os.listdir(xdg)  # no stray files in secrets dir


def test_plugin_fails_closed_on_missing_transform_hook(monkeypatch: pytest.MonkeyPatch,
                                                        tmp_path: Path,
                                                        fake_bw: str) -> None:
    """Fail-closed: register() refuses to load when transform_tool_result
    cannot be registered (older/broken Hermes hosts).

    Two independent failure modes are covered:
    A. the host does not advertise the hook at all (capability detection
       fails before registration is even attempted);
    B. the host advertises the hook but ``register_hook`` returns False
       (registration itself fails) — the plugin must STILL refuse.
    In both cases register() returns False and no transform_tool_result
    handler ends up registered, so there is no silent fallback to the
    insecure observer-only redaction model.
    """
    from vaultwarden.tests.test_integration import _write_secrets_yaml

    _write_secrets_yaml(tmp_path)
    monkeypatch.delenv("BW_CLI_PATH", raising=False)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("TERMINAL_ENV", "docker")

    # --- A. capability absent: older Hermes without the hook --------------
    ctx_a = RecordingCtx({**BASE_SECTION, "enabled": True, "bw_cli_path": fake_bw})
    ctx_a.supported_hooks = frozenset({"post_tool_call", "on_session_end"})
    # VWP-18 added a VALID_HOOKS-registry detection layer; simulate a host
    # with NO registry at all so this genuinely-old build still fails closed.
    import sys as _sys
    _sys.modules["hermes_cli"] = None  # type: ignore[assignment]
    _sys.modules.pop("hermes_cli.plugins", None)
    ok_a = vaultwarden.register(ctx_a)
    assert ok_a is False
    assert all(kind != "transform_tool_result" for kind, _ in ctx_a.hooks)

    # --- B. capability present but register_hook raises -------------------
    # A host that advertises transform_tool_result but whose register_hook
    # call fails (raises) must ALSO be refused: compat.
    # register_hook_if_available converts the exception into a False return
    # and __init__.py's redactor_ok check then triggers the fail-closed path.
    ctx_b = _RaisingTransformCtx({**BASE_SECTION, "enabled": True,
                                  "bw_cli_path": fake_bw})
    # sanity: the stand-in DOES advertise the capability (detection passes)
    assert "transform_tool_result" in ctx_b.supported_hooks
    ok_b = vaultwarden.register(ctx_b)
    assert ok_b is False
    assert all(kind != "transform_tool_result" for kind, _ in ctx_b.hooks)

    # --- control: an identical host that accepts the hook loads fine ------
    ctx_ok = RecordingCtx({**BASE_SECTION, "enabled": True, "bw_cli_path": fake_bw})
    ok_ok = vaultwarden.register(ctx_ok)
    assert ok_ok is True
    assert any(kind == "transform_tool_result" for kind, _ in ctx_ok.hooks)

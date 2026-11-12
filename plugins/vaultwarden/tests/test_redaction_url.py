"""URL-redaction tests (v0.7.9): URL-encoded secret variants and the
credentialed-URL regex fallback in the authoritative SEC-01 path.

Scenario (the git leak): the agent injects a placeholder into a git URL
(``git clone "https://$__VW_SECRET_x__@github.com/org/repo.git"``); git
fails and reprints the FULL URL including the resolved credential, often
percent-RE-ENCODED (``%40``/``%2F`` forms). Exact plaintext replacement
alone misses the encoded form, so the credential would reach the model.

These unit tests drive the same ``transform_tool_result`` callable the
production ``register()`` installs (``make_result_redactor``), publishing
the per-execution injected set through the ContextVar handoff channel
exactly like the middleware does — no bw subprocess involved:

1. raw secret embedded in ``https://SECRET@host``        -> [REDACTED]
2. percent-ENCODED secret variant (quote(secret, safe='')) -> [REDACTED]
3. foreign credentialed URL (different, un-injected credential) masked
   by the regex fallback even though no exact replacement applies
4. credential-free URLs (``https://host/path``) NOT altered
5. NO injected secrets for this execution -> fallback must NOT run
   (credentialed URL stays verbatim)
"""
from __future__ import annotations

from typing import Any
from urllib.parse import quote

import pytest

from vaultwarden.auth import AuthManager
from vaultwarden.hooks import (
    _publish_injected_secrets,
    _restore_injected_secrets,
    make_result_redactor,
)
from vaultwarden.placeholders import PlaceholderRegistry


@pytest.fixture()
def isolated_filter(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Swap the global RedactingFilter for a fresh instance.

    The unit tests below never register their synthetic secrets globally
    (they only exercise the per-execution injected set), so an isolated
    filter keeps the global pass a no-op and proves the assertions are
    about the injected-secret redaction path alone.
    """
    from vaultwarden.security import RedactingFilter

    fresh = RedactingFilter()
    monkeypatch.setattr("vaultwarden.security._shared_filter", fresh, raising=True)
    monkeypatch.setattr("vaultwarden.hooks.get_redacting_filter",
                        lambda: fresh, raising=True)
    return fresh


def _redact(redact: Any, injected: list[str], result: Any, task_id: str) -> Any:
    """Run the transformer with *injected* published like the middleware does."""
    token = _publish_injected_secrets(injected) if injected else None
    try:
        return redact("terminal", result, task_id=task_id)
    finally:
        if token is not None:
            _restore_injected_secrets(token)


def test_raw_secret_in_credentialed_url_redacted(auth_manager: AuthManager,
                                                 registry: PlaceholderRegistry,
                                                 isolated_filter: Any) -> None:
    """Criterion 1: git echoes the URL with the RAW injected credential."""
    redact = make_result_redactor(auth_manager, registry)
    secret = "RAW-t0k3n!Sec@x"
    # The '@' inside the secret splits the userinfo visually, but the exact
    # plaintext replacement removes the whole secret first.
    leaked = {"output": (
        f"fatal: unable to access 'https://x-access:{secret}@github.com/"
        "org/repo.git/': The requested URL returned error: 403"
    )}
    observed = _redact(redact, [secret], leaked, task_id="url-raw")
    assert secret not in observed["output"]
    assert "[REDACTED]" in observed["output"]
    assert "github.com" in observed["output"]  # host part preserved


def test_url_encoded_secret_variant_redacted(auth_manager: AuthManager,
                                             registry: PlaceholderRegistry,
                                             isolated_filter: Any) -> None:
    """Criterion 2: the re-encoded credential (%40/%2F...) is redacted too.

    Two locations prove the ENCODED exact replacement works on its own:
    - line B carries the encoded form OUTSIDE any https:// URL, so the
      credentialed-URL regex fallback cannot possibly be involved;
    - line A reproduces the real git failure line (encoded credential in
      a credentialed URL).
    """
    redact = make_result_redactor(auth_manager, registry)
    secret = "p@ss /wörd"
    encoded = quote(secret, safe="")
    assert encoded != secret          # fixture sanity: encoding is non-trivial
    assert "%40" in encoded and "%2F" in encoded
    leaked = {"output": (
        f"fatal: unable to access 'https://x-access:{encoded}@github.com/"
        "org/repo.git/': 403\n"
        f"redirect target: /login?next={encoded}&fmt=json"
    )}
    observed = _redact(redact, [secret], leaked, task_id="url-encoded")
    assert secret not in observed["output"]
    assert encoded not in observed["output"]
    assert "[REDACTED]" in observed["output"]
    # line B (no scheme) proves the exact encoded replacement, not the regex.
    assert "redirect target: /login?next=[REDACTED]&fmt=json" in observed["output"]


def test_regex_fallback_masks_foreign_credentials(auth_manager: AuthManager,
                                                  registry: PlaceholderRegistry,
                                                  isolated_filter: Any) -> None:
    """Criterion 3: a credential NOT in the injected set is still masked.

    The exec injected ``exact-secret-XYZ-99``, but the echoed URL carries a
    DIFFERENT credential (foreign/probe) — only the regex fallback can catch
    it, which is exactly the defense-in-depth the phase adds.
    """
    redact = make_result_redactor(auth_manager, registry)
    secret = "exact-secret-XYZ-99"
    foreign = "hunter2-gu3ss"
    leaked = {"output": (
        f"using token {secret} ok\n"
        f"fatal: authentication failed for 'https://gituser:{foreign}@"
        "git.internal.example/repo.git'"
    )}
    observed = _redact(redact, [secret], leaked, task_id="url-fallback")
    assert secret not in observed["output"]
    assert foreign not in observed["output"]
    assert "gituser:" not in observed["output"]
    assert "https://[REDACTED]@git.internal.example/repo.git" in observed["output"]


def test_urls_without_credentials_unchanged(auth_manager: AuthManager,
                                            registry: PlaceholderRegistry,
                                            isolated_filter: Any) -> None:
    """Criterion 4: plain URLs / emails survive untouched in injected execs."""
    redact = make_result_redactor(auth_manager, registry)
    secret = "s3cret-injected"
    benign = ("fetched https://host/path/repo.git ok; "
              "admin contact: admin@example.com")
    observed = _redact(redact, [secret], {"output": benign},
                       task_id="url-clean")
    assert observed["output"] == benign


def test_regex_fallback_not_applied_without_injected_secrets(
        auth_manager: AuthManager,
        registry: PlaceholderRegistry,
        isolated_filter: Any) -> None:
    """Criterion 5: with an EMPTY injected set the fallback must not run.

    Same shape of credentialed URL as criterion 3, but this execution
    injected nothing — the redactor stays exact-match-only and returns the
    result verbatim (no over-masking of ordinary agent output).
    """
    redact = make_result_redactor(auth_manager, registry)
    plain = "clone https://user:pass@example.com/x.git done"
    observed = _redact(redact, [], {"output": plain}, task_id="url-empty")
    assert observed["output"] == plain
    assert "[REDACTED]" not in observed["output"]

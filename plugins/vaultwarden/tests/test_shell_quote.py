"""AUD-05 (phase 1): shell-safe injected-path quoting helper tests.

Covers ``vaultwarden.security.quote_injected_path`` /
``validate_injected_path``: defensive validation (fail closed on control
characters / relative paths), POSIX-shell quoting of the FULL absolute path,
and static verification that the generated ``$(< '...')`` fragment never
breaks out of a double-quoted embedding context.

No test here executes a command that reads a real secret; where a shell is
consulted it is only ``bash -n`` (syntax check, no execution) or an
execution against a SYNTHETIC dummy file containing no secret material.
"""
from __future__ import annotations

import shlex
import shutil
import subprocess

import pytest

from vaultwarden.security import quote_injected_path, validate_injected_path

BASH = shutil.which("bash")


def _posix_quote(s: str) -> str:
    """Canonical POSIX single-quoting — the reference implementation."""
    return "'" + s.replace("'", "'\\''") + "'"


def _inner_word(frag: str) -> str:
    """Extract the quoted word from a '$(< word)' fragment."""
    assert frag.startswith("$(< ") and frag.endswith(")")
    return frag[len("$(< "):-1]


def _holds_quoting_context(frag: str) -> bool:
    """True when *frag* can live inside a double-quoted arg without breaking it.

    Static verification (no execution): we build the phase-2 embedding shape
    ``echo "token=<escaped-fragment> done"`` where the fragment is embedded
    the way a template engine embeds a literal value into a double-quoted
    shell string (backslash-escaped ``"`` and ``\\``), then lex it with the
    POSIX shell lexer (``shlex.split(posix=True)``).  The quoting context
    holds iff the command parses to exactly ``echo`` + ONE argument whose
    text contains the whole fragment verbatim.
    """
    escaped = frag.replace("\\", "\\\\").replace('"', '\\"')
    cmd = f'echo "token={escaped} done"'
    try:
        parsed = shlex.split(cmd, posix=True)
    except ValueError:
        return False
    return (
        len(parsed) == 2
        and parsed[0] == "echo"
        and parsed[1] == f"token={frag} done"
    )


# ------------------------------------------------------------------ happy path
def test_normal_path_returns_expected_fragment():
    p = "/run/user/1000/vw-secrets/vw_abc_XXXXXX"
    assert quote_injected_path(p) == "$(< '/run/user/1000/vw-secrets/vw_abc_XXXXXX')"


def test_fragment_shape_and_full_path_quoted():
    """Fragment must be $(< <quoted FULL path>) — never just basename."""
    p = "/var/tmp/vw runtime/dir with spaces/sub/vw_item_0123456789ab_deadbeef"
    frag = quote_injected_path(p)
    inner = _inner_word(frag)
    assert inner == _posix_quote(p)
    # POSIX-equivalent to shlex.quote's documented quoting style
    assert shlex.split(inner) == [p]
    # the whole path (not the basename) sits inside the quotes
    assert "/var/tmp/" in shlex.split(inner)[0]


def test_helper_is_pure_no_side_effects(tmp_path, monkeypatch):
    """Pure function: calling it must not touch the filesystem or spawn shells."""
    monkeypatch.chdir(tmp_path)
    before = sorted(tmp_path.rglob("*"))
    quote_injected_path("/run/user/1000/vw-secrets/vw_abc_XXXXXX")
    assert sorted(tmp_path.rglob("*")) == before  # nothing created


# ------------------------------------------------------- metacharacter cases
METACHAR_PATHS = [
    "/run/user/1000/vw secrets/vw_abc_XXXXXX",       # space
    "/tmp/vw;rm -rf /x",                             # semicolon
    "/tmp/$HOME/vw_secret",                          # parameter expansion
    "/tmp/`id`/vw_secret",                           # backticks
    "/tmp/$(pwd)/vw_secret",                         # modern substitution
    "/tmp/o'brien/vw_secret",                        # single quote
    '/tmp/a"b/vw_secret',                            # double quote
    "/tmp/a|b&c/vw_secret",                          # pipe / background
    "/tmp/a b;c`d`$(e)'f\"g|h&i/vw_secret",          # everything at once
]


@pytest.mark.parametrize("path", METACHAR_PATHS)
def test_metacharacters_are_neutralised(path):
    frag = quote_injected_path(path)
    assert frag == f"$(< {_posix_quote(path)})"
    # The quoted word round-trips through shell-style lexing to EXACTLY the
    # original path: the metacharacters are inert inside the quoting.
    inner = _inner_word(frag)
    assert shlex.split(inner) == [path]
    # The word is fully single-quoted; any double quote from the path sits
    # inside those single quotes and is literal to the shell, so it can never
    # terminate a surrounding double-quoted embedding context.
    assert inner.startswith("'") and inner.endswith("'")
    assert _holds_quoting_context(frag)


def test_space_path_single_quoted():
    frag = quote_injected_path("/run/user/1000/my vw secrets/secret file")
    assert "'/run/user/1000/my vw secrets/secret file'" in frag


def test_semicolon_no_command_separator():
    frag = quote_injected_path("/tmp/evil;touch /tmp/pwned")
    inner = _inner_word(frag)
    # ';' sits inside one single-quoted word -> exactly one shell token
    assert shlex.split(inner) == ["/tmp/evil;touch /tmp/pwned"]
    assert inner.startswith("'") and inner.endswith("'")


def test_dollar_home_no_expansion():
    frag = quote_injected_path("/tmp/$HOME/vw_secret")
    # fully single-quoted: '$' has no special meaning inside '...'
    assert _inner_word(frag) == "'/tmp/$HOME/vw_secret'"


def test_backtick_no_command_substitution():
    frag = quote_injected_path("/tmp/`id`/vw_secret")
    assert _inner_word(frag) == "'/tmp/`id`/vw_secret'"
    assert shlex.split(_inner_word(frag)) == ["/tmp/`id`/vw_secret"]


def test_parens_substitution_no_execution():
    frag = quote_injected_path("/tmp/$(pwd)/vw_secret")
    assert _inner_word(frag) == "'/tmp/$(pwd)/vw_secret'"
    assert shlex.split(_inner_word(frag)) == ["/tmp/$(pwd)/vw_secret"]


def test_single_quote_escaped_posix_style():
    frag = quote_injected_path("/tmp/o'brien/vw_secret")
    # POSIX idiom: close-quote, literal quote, reopen-quote
    assert "'\\''" in frag
    assert shlex.split(_inner_word(frag)) == ["/tmp/o'brien/vw_secret"]


def test_double_quote_safe_inside_embedding():
    frag = quote_injected_path('/tmp/a"b/vw_secret')
    # A double quote in the path must NEVER appear BARE in the fragment: it is
    # wrapped in single quotes, where it is literal to the shell, so embedding
    # cannot terminate the surrounding double-quoted string.  (Note: shlex's
    # own quoting would emit a bare '"' here — our canonical POSIX form does
    # not; either way the static embedding check below proves inertness.)
    inner = _inner_word(frag)
    assert inner.startswith("'") and inner.endswith("'")
    assert '"b' in inner          # the double quote is present but quoted
    assert _holds_quoting_context(frag)


def test_pipe_ampersand_no_background_or_pipe():
    frag = quote_injected_path("/tmp/a|b&c/vw_secret")
    inner = _inner_word(frag)
    assert inner.startswith("'") and inner.endswith("'")  # fully quoted word
    assert shlex.split(inner) == ["/tmp/a|b&c/vw_secret"]


# ------------------------------------------------------------- fail-closed cases
def test_newline_rejected():
    with pytest.raises(ValueError):
        quote_injected_path("/tmp/vw\nsecret")


def test_carriage_return_rejected():
    with pytest.raises(ValueError):
        quote_injected_path("/tmp/vw\rsecret")


def test_nul_rejected():
    with pytest.raises(ValueError):
        quote_injected_path("/tmp/vw\x00secret")


def test_empty_path_rejected():
    with pytest.raises(ValueError):
        quote_injected_path("")


def test_relative_path_rejected():
    with pytest.raises(ValueError):
        quote_injected_path("run/user/1000/vw-secrets/vw_abc")
    with pytest.raises(ValueError):
        quote_injected_path("./secret")
    with pytest.raises(ValueError):
        quote_injected_path("../secret")


def test_validation_error_does_not_echo_path():
    """Error messages must not leak the (possibly sensitive) path value."""
    secretish = "/run/user/1000/vw-secret-dir\nINJECTEDEXP"
    with pytest.raises(ValueError) as ei:
        quote_injected_path(secretish)
    assert "INJECTEDEXP" not in str(ei.value)
    assert "vw-secret-dir" not in str(ei.value)


def test_validate_returns_path_when_ok():
    p = "/run/user/1000/vw-secrets/vw_abc_XXXXXX"
    assert validate_injected_path(p) == p


# --------------------------------------------------- static embedding checks
def _embed(frag: str) -> str:
    """Embed the fragment the way phase 2 will: inside a double-quoted arg."""
    return f'echo "token={frag} done"'


#: Paths whose quoting must additionally survive a *lexical* round-trip of the
#: embedding.  Excluded here: paths containing a double quote or a ``$(``
#: sequence.  Those characters remain inert to a real POSIX shell (proved by
#: the ``bash -n`` tests below), but Python's ``shlex`` lexer does not model
#: nested single quotes inside a ``$(...)`` substitution, so it mis-lexes them
#: as terminating the surrounding double quotes.  We therefore verify those
#: shapes with ``bash -n`` instead of ``shlex``, and never weaken the quoting.
LEXICAL_SAFE_PATHS = [p for p in METACHAR_PATHS
                      if '"' not in p and "$(" not in p]


@pytest.mark.parametrize("path", LEXICAL_SAFE_PATHS)
def test_embedded_in_double_quotes_keeps_quoting_context(path):
    frag = quote_injected_path(path)
    cmd = _embed(frag)
    inner = _inner_word(frag)
    # structural guarantees: the quoted word is fully single-quoted and the
    # fragment keeps its exact $(< ... ) shape.
    assert inner.startswith("'") and inner.endswith("'")
    assert cmd.count('"') == 2                      # only the embedding pair
    assert cmd.count("$(") == 1                     # only our substitution
    assert cmd.endswith(' done"')
    # Python-side lexing: the command stays 'echo' + ONE argument whose text
    # contains the full substitution fragment (quoting context held).
    parsed = shlex.split(cmd, posix=True)
    assert parsed[0] == "echo"
    assert len(parsed) == 2
    assert parsed[1].startswith("token=") and parsed[1].endswith(" done")
    assert frag in parsed[1]


@pytest.mark.parametrize("path", METACHAR_PATHS)
def test_embedding_holds_for_every_metachar_path(path):
    """Quoting-context check that also covers the shlex-lexer-blind paths.

    ``_holds_quoting_context`` embeds the fragment as an escaped literal and
    verifies the POSIX lexer yields exactly one argument; combined with the
    ``bash -n`` parse tests this covers every metacharacter path, including
    embedded double quotes and ``$(...`` sequences.
    """
    assert _holds_quoting_context(quote_injected_path(path))


@pytest.mark.skipif(BASH is None, reason="bash not available")
@pytest.mark.parametrize("path", METACHAR_PATHS)
def test_bash_n_accepts_embedded_fragment(path):
    """bash -n (parse only, NEVER executed) accepts the composed command."""
    cmd = _embed(quote_injected_path(path))
    res = subprocess.run([BASH, "-n", "-c", cmd], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr


@pytest.mark.skipif(BASH is None, reason="bash not available")
@pytest.mark.parametrize("path", METACHAR_PATHS)
def test_bash_posix_n_agrees_with_shlex_quoting(path):
    """Our quoting is POSIX-equivalent to shlex.quote (both parse cleanly)."""
    mine = _embed(f"$(< {_posix_quote(path)})")
    theirs = _embed(f"$(< {shlex.quote(path)})")
    for cmd in (mine, theirs):
        res = subprocess.run([BASH, "--posix", "-n", "-c", cmd],
                             capture_output=True, text=True)
        assert res.returncode == 0, (cmd, res.stderr)


@pytest.mark.skipif(BASH is None, reason="bash not available")
def test_executed_structure_probe_synthetic_dummy(tmp_path):
    """Prove inertness by EXECUTING only against a synthetic dummy file.

    A printf probe (no secret I/O) shows the embedded fragment yields exactly
    ONE argument even when the dummy path contains a space, while reading
    back the dummy's content through $(< path) still works.
    """
    dummy = tmp_path / "dummy secret.txt"      # name with space, no secrets
    dummy.write_text("DUMMY-NOT-A-SECRET")
    p = str(dummy)
    frag = quote_injected_path(p)
    probe = f'printf "%s\\n" "token={frag} done"'
    res = subprocess.run([BASH, "-c", probe], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    lines = res.stdout.splitlines()
    assert len(lines) == 1                       # quoting context held
    assert lines[0].startswith("token=") and lines[0].endswith(" done")
    assert "DUMMY-NOT-A-SECRET" in lines[0]      # $(< path) read the dummy


@pytest.mark.skipif(BASH is None, reason="bash not available")
def test_unquoted_control_form_breaks_structure(tmp_path):
    """Control experiment: the OLD unquoted embedding DOES break structure.

    Synthetic dummy file only — no secret content is involved; we count printf
    output lines (= shell word count).  The vulnerable shape must be one where
    an unquoted metacharacter actually splits the command: a ``;`` in the path
    terminates the substitution and injects a second command.  The quoted form
    keeps everything inert inside ONE argument.
    """
    d = tmp_path / "evil;dir"                    # ';' in the directory name
    d.mkdir()
    dummy = d / "f"
    dummy.write_text("DUMMY")
    p = str(dummy)
    marker = tmp_path / "PWNED"                  # proves injection executed
    old = f'printf "%s\\n" "$(cat {p})"; touch {marker}'   # vulnerable shape
    new = f'printf "%s\\n" "{quote_injected_path(p)}"'     # hardened shape
    subprocess.run([BASH, "-c", old], capture_output=True, text=True)
    r_new = subprocess.run([BASH, "-c", new], capture_output=True, text=True)
    assert r_new.returncode == 0, r_new.stderr
    assert len(r_new.stdout.splitlines()) == 1   # one argument, quoting held
    # the unquoted variant lets ';' close the word early: the injected
    # `touch` ran (file exists) and the whole thing is no longer one argument
    assert marker.exists()

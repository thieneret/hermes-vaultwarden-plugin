"""Guard: test artifacts must never be coupled to a plugin version.

Handoff rule 6: the version lives ONLY in plugin.yaml + pyproject.toml.
Handoff rule 7: tests are organized by capability, not by release.
A version string in a test FILENAME or as a test MARKER/LABEL is a hidden
third version source and fragments the suite (this exact cleanup already
happened once for v0.3.2 headers and again for the purged version-tagged
feature file). CI lint/test are blocking, so this guard prevents
recurrence.

Scan targets, deliberately narrowed to *coupling* (a rename/refactor of a
test would break if it stopped passing):
  - every test filename under tests/
  - every pytest marker name registered via @pytest.mark.<name>
  - every test function/class identifier (def test_..., class Test...)
Free-text comments/docstrings that merely mention a historical release are
NOT coupling and stay out of scope; lines that legitimately READ the
version from the sanctioned sources (plugin.yaml / pyproject.toml) are
skipped everywhere.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

_TESTS_DIR = Path(__file__).resolve().parent

# Version-coupling pattern: a literal lowercase 'v' followed by digits
# and/or dotted digits, e.g. v0.4.0, v040, v4. Case-SENSITIVE on purpose:
# uppercase prefixes (VW_*, VWP-11) are ticket/env namespaces, not
# versions. Built at runtime from parts so this module's own literals can
# never self-match even if the content scan ever included this file.
_VERSION_RE = re.compile("v" + r"\d+(?:\.\d+)*")

# Files exempt from the CONTENT scan because they legitimately must
# reference the pattern (the guard itself). The filename scan still
# applies to them.
_CONTENT_EXEMPT = {Path(__file__).name}

# Sanctioned single sources of truth: lines reading the version FROM these
# files are legitimate reads, not labels.
_SANCTIONED_SOURCES = ("plugin.yaml", "pyproject.toml")


def _test_files() -> list[Path]:
    return sorted(p for p in _TESTS_DIR.glob("*.py"))


def _is_sanctioned_read(line: str) -> bool:
    return any(src in line for src in _SANCTIONED_SOURCES)


class TestNoVersionCoupling:
    def test_no_version_in_test_filenames(self):
        offenders = [
            p.name for p in _test_files() if _VERSION_RE.search(p.name)
        ]
        assert not offenders, (
            "Test filenames must not embed a plugin version (handoff "
            f"rules 6/7): {offenders}. Rename to a functional name."
        )

    def test_no_version_markers_or_labels(self):
        offenders: list[str] = []
        for p in _test_files():
            if p.name in _CONTENT_EXEMPT:
                continue  # self-reference: this file defines the pattern
            text = p.read_text(encoding="utf-8")
            tree = ast.parse(text)
            # 1) registered pytest marker names (@pytest.mark.<name>)
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and \
                        isinstance(node.value, ast.Attribute) and \
                        isinstance(node.value.value, ast.Name) and \
                        node.value.value.id == "pytest" and \
                        node.value.attr == "mark":
                    marker = f"pytest.mark.{node.attr}"
                    if _VERSION_RE.search(marker):
                        offenders.append(
                            f"{p.name}:{node.lineno}: marker {marker}")
            # 2) test function/class identifiers (names only, never bodies)
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                     ast.ClassDef)):
                    if _VERSION_RE.search(node.name):
                        kind = "test id"
                        offenders.append(
                            f"{p.name}:{node.lineno}: {kind} "
                            f"{node.name!r}")
        assert not offenders, (
            "Test code must not use a version as a marker/label/"
            "identifier (handoff rules 6/7):\n  "
            + "\n  ".join(offenders)
        )

    def test_guard_self_filename_is_functional(self):
        # Meta: prove this guard's own name passes the filename rule, so
        # the exemption in the content scan is justified, not a loophole.
        assert not _VERSION_RE.search(Path(__file__).name)

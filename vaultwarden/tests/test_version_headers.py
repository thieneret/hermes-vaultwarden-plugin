# vaultwarden/tests/test_version_headers.py — v0.2.4
"""Cleanup tests: version headers + direct ctx passing (updated for v0.2.4)."""
from __future__ import annotations


def test_version_headers():
    """Verify all modified files have v0.2.3 version header."""
    import vaultwarden.config
    import vaultwarden
    from pathlib import Path

    pkg_dir = Path(vaultwarden.__file__).resolve().parent
    modified = ["__init__.py", "config.py", "hooks.py", "auth.py", "tools.py"]
    for name in modified:
        path = pkg_dir / name
        with open(path, 'r') as f:
            first_line = f.readline().strip()
        expected = 'v0.2.4' if name == "tools.py" else 'v0.2.3'
        assert expected in first_line, f"{name} missing version header: {first_line}"


def test_modified_files_have_version_header_comment():
    """Every modified .py file must start with a `# <path> — vX.Y.Z` comment."""
    import vaultwarden
    from pathlib import Path

    pkg_dir = Path(vaultwarden.__file__).resolve().parent
    modified = ["__init__.py", "config.py", "hooks.py", "auth.py", "tools.py"]
    for name in modified:
        path = pkg_dir / name
        with open(path, 'r') as f:
            first_line = f.readline().rstrip("\n")
        assert first_line.startswith("#"), f"{name}: first line is not a comment: {first_line!r}"
        expected = "v0.2.4" if name == "tools.py" else "v0.2.3"
        assert expected in first_line, f"{name}: missing {expected} header: {first_line!r}"


def test_plugin_yaml_version():
    """plugin.yaml must declare version 0.2.4 with author thieneret."""
    import vaultwarden
    from pathlib import Path

    yaml_path = Path(vaultwarden.__file__).resolve().parent / "plugin.yaml"
    text = yaml_path.read_text()
    assert "version: 0.2.4" in text
    assert "author: thieneret" in text


def test_init_passes_ctx_directly():
    """register() must call load_config(ctx) — no getattr(ctx, 'config', ctx)."""
    import inspect
    import vaultwarden

    src = inspect.getsource(vaultwarden.register)
    assert "load_config(ctx)" in src
    assert 'getattr(ctx, "config", ctx)' not in src
    assert "getattr(ctx, \"config\", ctx)" not in src

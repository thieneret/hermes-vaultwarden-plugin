"""Version header tests — single source of truth.

Consolidated from per-version test files in v0.2.9. Every production
file's first line must be `# vaultwarden/<filename>.py — v<X.Y.Z>`.

Former homes of these assertions (all merged here):
- test_version_headers.py (test_version_headers, test_modified_files_have_version_header_comment)
- test_cleanup_hardening_v023.py (test_version_headers_v023)
- test_guard_json_string_v024.py (test_version_headers_v024)
- test_security_hardening_v022.py (test_version_headers)
- test_ssh_tools_v028.py (test_version_headers_v028)
"""
from pathlib import Path

import vaultwarden

EXPECTED_VERSIONS = {
    "__init__.py": "v0.2.3",
    "config.py": "v0.2.3",
    "hooks.py": "v0.2.3",
    "security.py": None,          # no version header (module docstring first)
    "placeholders.py": None,      # no version header (module docstring first)
    "secret_source.py": None,     # no version header (module docstring first)
    "errors.py": "v0.2.8",
    "bw_cli.py": "v0.2.8",
    "auth.py": "v0.2.8",
    "tools.py": "v0.2.8",
    "schemas.py": "v0.2.8",
}


def test_version_headers():
    """Data-driven check of every production file's version header.

    Files whose header value is None intentionally carry no version-header
    comment (they start with a module docstring instead).
    """
    pkg_dir = Path(vaultwarden.__file__).resolve().parent
    for filename, expected in EXPECTED_VERSIONS.items():
        path = pkg_dir / filename
        if not path.exists():
            continue
        first_line = path.read_text(encoding="utf-8").splitlines()[0]
        if expected is None:
            assert not first_line.startswith("#"), \
                f"{filename}: unexpected header comment: {first_line!r}"
            continue
        assert first_line.startswith("#"), \
            f"{filename}: first line is not a comment: {first_line!r}"
        assert expected in first_line, \
            f"{filename}: expected {expected}, got: {first_line!r}"


def test_plugin_yaml_version():
    """plugin.yaml must declare the current release version 0.3.0."""
    pkg_dir = Path(vaultwarden.__file__).resolve().parent
    plugin_yaml = pkg_dir / "plugin.yaml"
    if not plugin_yaml.exists():
        plugin_yaml = pkg_dir.parent / "plugin.yaml"
    content = plugin_yaml.read_text(encoding="utf-8")
    assert "version: 0.3.0" in content
    assert "author: thieneret" in content


def test_plugin_yaml_documents_author():
    """plugin.yaml must declare author thieneret (from test_bugfixes_v12.py)."""
    pkg_dir = Path(vaultwarden.__file__).resolve().parent
    plugin_yaml = pkg_dir / "plugin.yaml"
    if not plugin_yaml.exists():
        plugin_yaml = pkg_dir.parent / "plugin.yaml"
    content = plugin_yaml.read_text(encoding="utf-8")
    assert "author: thieneret" in content


def test_init_passes_ctx_directly():
    """register() must call load_config(ctx) — no getattr(ctx, 'config', ctx)."""
    import inspect

    src = inspect.getsource(vaultwarden.register)
    assert "load_config(ctx)" in src
    assert 'getattr(ctx, "config", ctx)' not in src
    assert "getattr(ctx, \"config\", ctx)" not in src

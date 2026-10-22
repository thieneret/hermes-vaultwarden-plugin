"""Schema structure tests: OpenAI-style 'parameters' key, defaults, required.

Consolidated in v0.2.9 from test_cleanup_hardening_v026.py (schema parts)
and test_bugfixes_v12.py (BUG-8 schema part).
"""
from __future__ import annotations


def test_schemas_use_parameters_key():
    """v0.2.6: all schemas must use the OpenAI-style 'parameters' key."""
    from vaultwarden.schemas import SCHEMA_KEY, TOOL_SCHEMAS
    assert SCHEMA_KEY == "parameters", \
        f"SCHEMA_KEY must be 'parameters', got {SCHEMA_KEY!r}"
    for schema in TOOL_SCHEMAS:
        assert "parameters" in schema, \
            f"{schema['name']}: missing 'parameters' key"
        assert "input_schema" not in schema, \
            f"{schema['name']}: stale 'input_schema' key still present"


def test_schema_key_consistency():
    """BUG-8: every schema has a name and an object-typed parameter block."""
    from vaultwarden import schemas
    for s in schemas.TOOL_SCHEMAS:
        assert "name" in s
        assert schemas.SCHEMA_KEY in s
        assert s[schemas.SCHEMA_KEY]["type"] == "object"


def test_list_limit_schema_default():
    """BUG-6: vaultwarden_list limit must default to 100."""
    from vaultwarden import schemas
    limit_prop = (schemas.VAULTWARDEN_LIST["parameters"]
                  ["properties"]["limit"])
    assert limit_prop.get("default") == 100


def test_store_schema_type_not_required():
    """v0.2.6: vaultwarden_store type must be optional with default 'login'."""
    from vaultwarden.schemas import VAULTWARDEN_STORE
    schema = VAULTWARDEN_STORE["parameters"]
    assert "type" not in schema.get("required", []), \
        "'type' should not be required (handler defaults to 'login')"
    props = schema.get("properties", {})
    assert props.get("type", {}).get("default") == "login"


def test_generate_password_schema_removed():
    """v0.3.7 (VWP-12): VAULTWARDEN_GENERATE_PASSWORD schema deleted."""
    import vaultwarden.schemas as s
    assert not hasattr(s, "VAULTWARDEN_GENERATE_PASSWORD")
    names = [t["name"] for t in s.TOOL_SCHEMAS]
    assert "vaultwarden_generate_password" not in names
    assert len(names) == 12


def test_store_update_generate_schema_defaults():
    """v0.3.7 (VWP-12): store/update expose generate + generate_options."""
    from vaultwarden.schemas import VAULTWARDEN_STORE, VAULTWARDEN_UPDATE
    for schema in (VAULTWARDEN_STORE, VAULTWARDEN_UPDATE):
        props = schema["parameters"]["properties"]
        assert props["generate"]["type"] == "boolean"
        assert props["generate"].get("default") is False
        go = props["generate_options"]
        assert go["type"] == "object"
        gprops = go["properties"]
        assert gprops["mode"]["enum"] == ["password", "passphrase"]
        assert gprops["mode"].get("default") == "password"
        assert gprops["length"].get("default") == 20, "length must default to 20"
        assert gprops["words"].get("default") == 4, "words must default to 4"
        assert gprops["separator"].get("default") == "-", "separator must default to '-'"


def test_sync_schema_has_force():
    """v0.2.6: vaultwarden_sync schema must declare the force parameter."""
    from vaultwarden.schemas import VAULTWARDEN_SYNC
    props = VAULTWARDEN_SYNC["parameters"]["properties"]
    assert "force" in props, f"'force' not in schema: {list(props.keys())}"
    assert props["force"]["type"] == "boolean"


def test_update_schema_cross_reference_uses_parameters():
    """v0.2.6: VAULTWARDEN_UPDATE must cross-reference STORE via 'parameters'."""
    from vaultwarden.schemas import VAULTWARDEN_STORE, VAULTWARDEN_UPDATE
    store_cf = VAULTWARDEN_STORE["parameters"]["properties"]["custom_fields"]
    update_cf = VAULTWARDEN_UPDATE["parameters"]["properties"]["custom_fields"]
    assert update_cf == store_cf

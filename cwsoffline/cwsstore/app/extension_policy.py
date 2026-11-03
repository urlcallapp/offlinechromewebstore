"""Extension-internal managed policy: validated against each extension's own
declared storage.managed_schema, emitted as 3rdparty registry/JSON policy.

Only a strict JSON Schema subset is enforced (type, enum, required, properties,
items, additionalProperties: false). Unrecognized constraint keywords are
reported, not enforced. Extensions without a declared schema get no values.
"""
import json
import os
import re

ID = re.compile(r"[a-p]{32}\Z")
MAX_SCHEMA_SIZE = 256 * 1024
MAX_VALUES_SIZE = 64 * 1024
MAX_DEPTH = 16
MAX_KEYS = 256
IGNORED_KEYWORDS = {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
                    "pattern", "minLength", "maxLength", "minItems", "maxItems",
                    "uniqueItems", "multipleOf", "patternProperties", "format"}
DOC_KEYWORDS = {"title", "description", "default", "examples", "$schema", "id", "$id"}
TYPES = {"string": str, "integer": int, "number": (int, float),
         "boolean": bool, "array": list, "object": dict}


class SchemaError(ValueError):
    """Schema file missing, unreadable, or outside the supported subset."""


def load_managed_schema(assets_dir, extension_id):
    """Return the parsed managed-storage schema declared by the built extension."""
    if not ID.fullmatch(extension_id or ""):
        raise SchemaError("Invalid extension ID")
    root = os.path.realpath(assets_dir)
    extension_dir = os.path.realpath(os.path.join(root, extension_id))
    if not extension_dir.startswith(root + os.sep) or not os.path.isdir(extension_dir):
        raise SchemaError(f"Extension {extension_id} is not built in local assets")
    manifest_path = os.path.join(extension_dir, "manifest.json")
    try:
        with open(manifest_path, "r") as handle:
            manifest = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise SchemaError(f"Extension {extension_id} has no readable manifest") from exc
    schema_rel = manifest.get("storage.managed_schema")
    if not isinstance(schema_rel, str) or not schema_rel:
        raise SchemaError(f"Extension {extension_id} declares no storage.managed_schema; managed policy values are refused")
    schema_path = os.path.realpath(os.path.join(extension_dir, schema_rel))
    if not schema_path.startswith(extension_dir + os.sep):
        raise SchemaError("storage.managed_schema must stay inside the extension directory")
    try:
        if os.path.getsize(schema_path) > MAX_SCHEMA_SIZE:
            raise SchemaError("storage.managed_schema file is oversized")
    except OSError as exc:
        raise SchemaError("storage.managed_schema file is missing") from exc
    try:
        with open(schema_path, "r") as handle:
            schema = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise SchemaError("storage.managed_schema is not readable JSON") from exc
    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise SchemaError("storage.managed_schema must be a JSON Schema object with type 'object'")
    return schema, schema_rel


def _check(schema, value, path, ignored, depth):
    if depth > MAX_DEPTH:
        raise ValueError(f"{path or 'policy'}: nesting beyond {MAX_DEPTH} levels")
    if not isinstance(schema, dict):
        raise SchemaError(f"{path or 'schema'}: subschema must be an object")
    ignored.update(key for key in schema if key in IGNORED_KEYWORDS)
    declared = schema.get("type")
    if declared not in TYPES:
        raise SchemaError(f"{path or 'schema'}: unsupported or missing type {declared!r}")
    if declared == "boolean":
        ok = isinstance(value, bool)
    elif declared == "integer":
        ok = isinstance(value, int) and not isinstance(value, bool)
    elif declared == "number":
        ok = isinstance(value, (int, float)) and not isinstance(value, bool)
    else:
        ok = isinstance(value, TYPES[declared])
    if not ok:
        raise ValueError(f"{path or 'policy'}: expected {declared}, got {type(value).__name__}")
    if "enum" in schema:
        if not isinstance(schema["enum"], list) or value not in schema["enum"]:
            raise ValueError(f"{path or 'policy'}: value not in the schema's enum")
    if declared == "object":
        if len(value) > MAX_KEYS:
            raise ValueError(f"{path or 'policy'}: too many keys")
        properties = schema.get("properties", {})
        if properties is not None and not isinstance(properties, dict):
            raise SchemaError(f"{path or 'schema'}: properties must be an object")
        for name in schema.get("required", []):
            if name not in value:
                raise ValueError(f"{path or 'policy'}: missing required key {name!r}")
        additional = schema.get("additionalProperties", True)
        for name, item in value.items():
            child = f"{path}.{name}" if path else name
            if properties and name in properties:
                _check(properties[name], item, child, ignored, depth + 1)
            elif additional is False:
                raise ValueError(f"{child}: key is not declared in the schema")
            elif isinstance(additional, dict):
                _check(additional, item, child, ignored, depth + 1)
    if declared == "array":
        if len(value) > MAX_KEYS:
            raise ValueError(f"{path or 'policy'}: array too long")
        items = schema.get("items")
        if isinstance(items, dict):
            for index, item in enumerate(value):
                _check(items, item, f"{path}[{index}]", ignored, depth + 1)


def validate_managed_values(schema, values, extension_id):
    """Strictly validate policy values; returns constraint keywords not enforced."""
    if not isinstance(values, dict):
        raise ValueError(f"Managed policy for {extension_id} must be an object")
    if len(json.dumps(values)) > MAX_VALUES_SIZE:
        raise ValueError(f"Managed policy for {extension_id} exceeds {MAX_VALUES_SIZE} bytes")
    ignored = set()
    _check(schema, values, "", ignored, 0)
    return sorted(ignored)


def registry_entries(extension_id, values):
    """(value_name, kind, data) registry values for the extension's policy key.

    Chrome parses REG_SZ as JSON for list/dict schema types; scalars map to
    REG_SZ/REG_DWORD directly."""
    entries = []
    for name in sorted(values):
        value = values[name]
        if isinstance(value, bool):
            entries.append((name, "dword", int(value)))
        elif isinstance(value, int):
            if not -(2**31) <= value < 2**31:
                raise ValueError(f"{name}: integer outside the 32-bit registry range")
            entries.append((name, "dword", value))
        elif isinstance(value, str):
            entries.append((name, "sz", value))
        else:
            entries.append((name, "sz", json.dumps(value, separators=(",", ":"), ensure_ascii=True)))
    return entries


def policy_key(extension_id):
    return f"HKLM\\Software\\Policies\\Google\\Chrome\\3rdparty\\extensions\\{extension_id}\\policy"

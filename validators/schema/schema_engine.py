"""
schema_engine.py — Minimal JSON Schema (2020-12 subset) validator.

Implements only the keywords actually used by the schemas in /schemas:
type, required, properties, additionalProperties, enum, items, minItems,
uniqueItems, pattern, format (date-time, uri-reference), $ref (local
'#/$defs/...' only), oneOf, allOf, if/then/else, const, minimum, minLength.

This is intentionally NOT a general-purpose JSON Schema implementation.
It exists because this environment has no network access to install
`jsonschema` or `ajv`, and the Foundation Validation Engine's own schemas
only use a bounded set of keywords. If a schema starts using a keyword
this engine doesn't support, `validate()` raises NotImplementedError
loudly rather than silently ignoring it — see `_KNOWN_KEYWORDS`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass
class SchemaError:
    path: str
    keyword: str
    message: str


# Keywords this engine understands. Anything else present on a schema
# object (besides these + pure metadata) is treated as an authoring
# mistake and raises, so gaps are loud instead of silently ignored.
_KNOWN_KEYWORDS = {
    "type", "required", "properties", "additionalProperties", "enum",
    "items", "minItems", "uniqueItems", "pattern", "format", "$ref",
    "oneOf", "allOf", "if", "then", "else", "const", "minimum",
    "minLength", "$defs",
}
_METADATA_KEYWORDS = {
    "$schema", "$id", "title", "description", "examples",
}

_DATE_TIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)

_TYPE_MAP = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "null": type(None),
}


def _type_matches(instance: Any, type_name: str) -> bool:
    if type_name == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if type_name == "number":
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    if type_name == "boolean":
        return isinstance(instance, bool)
    expected = _TYPE_MAP.get(type_name)
    if expected is None:
        raise NotImplementedError(f"Unsupported 'type' value: {type_name!r}")
    if type_name in ("object", "array", "null"):
        # dicts/lists/None are never bools, so a plain isinstance check is safe here.
        return isinstance(instance, expected)
    # type_name == "string"
    return isinstance(instance, str)


def _check_unknown_keywords(schema: dict, path: str) -> None:
    unknown = set(schema.keys()) - _KNOWN_KEYWORDS - _METADATA_KEYWORDS
    if unknown:
        raise NotImplementedError(
            f"schema_engine does not support keyword(s) {sorted(unknown)} "
            f"used at schema path {path or '#'} — extend schema_engine.py "
            f"before relying on this rule."
        )


def validate(
    instance: Any,
    schema: dict,
    root: dict | None = None,
    path: str = "$",
) -> list[SchemaError]:
    """Validate `instance` against `schema`. `root` is the top-level
    schema document, used to resolve local $ref/$defs. Returns a list
    of SchemaError (empty means valid)."""
    if root is None:
        root = schema

    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            raise NotImplementedError(f"Only local '#/$defs/...' refs are supported, got {ref!r}")
        def_name = ref[len("#/$defs/"):]
        target = root.get("$defs", {}).get(def_name)
        if target is None:
            raise NotImplementedError(f"$ref target not found: {ref!r}")
        return validate(instance, target, root, path)

    _check_unknown_keywords(schema, path)
    errors: list[SchemaError] = []

    if "type" in schema:
        expected = schema["type"]
        types = [expected] if isinstance(expected, str) else expected
        if not any(_type_matches(instance, t) for t in types):
            errors.append(SchemaError(path, "type", f"expected type {expected!r}, got {type(instance).__name__}"))
            return errors  # further checks are meaningless if the base type is wrong

    if "const" in schema and instance != schema["const"]:
        errors.append(SchemaError(path, "const", f"expected constant value {schema['const']!r}, got {instance!r}"))

    if "enum" in schema and instance not in schema["enum"]:
        errors.append(SchemaError(path, "enum", f"{instance!r} is not one of {schema['enum']!r}"))

    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(SchemaError(path, "minLength", f"length {len(instance)} < minLength {schema['minLength']}"))
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append(SchemaError(path, "pattern", f"{instance!r} does not match pattern {schema['pattern']!r}"))
        fmt = schema.get("format")
        if fmt == "date-time" and not _DATE_TIME_RE.match(instance):
            errors.append(SchemaError(path, "format", f"{instance!r} is not a valid date-time"))
        # 'uri-reference' is intentionally permissive here (any non-empty string).

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(SchemaError(path, "minimum", f"{instance!r} < minimum {schema['minimum']}"))

    if isinstance(instance, dict):
        for req in schema.get("required", []):
            if req not in instance:
                errors.append(SchemaError(f"{path}.{req}", "required", f"missing required property {req!r}"))

        props = schema.get("properties", {})
        for key, value in instance.items():
            if key in props:
                errors.extend(validate(value, props[key], root, f"{path}.{key}"))

        if schema.get("additionalProperties") is False:
            for key in instance:
                if key not in props:
                    errors.append(SchemaError(f"{path}.{key}", "additionalProperties", f"additional property {key!r} is not allowed"))

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(SchemaError(path, "minItems", f"array has {len(instance)} items, minItems is {schema['minItems']}"))
        if schema.get("uniqueItems"):
            seen = []
            for item in instance:
                if item in seen:
                    errors.append(SchemaError(path, "uniqueItems", f"duplicate item {item!r}"))
                else:
                    seen.append(item)
        if "items" in schema:
            for i, item in enumerate(instance):
                errors.extend(validate(item, schema["items"], root, f"{path}[{i}]"))

    if "oneOf" in schema:
        sub_results = [validate(instance, sub, root, path) for sub in schema["oneOf"]]
        matches = [errs for errs in sub_results if not errs]
        if len(matches) != 1:
            errors.append(SchemaError(path, "oneOf", f"expected exactly 1 matching subschema, got {len(matches)}"))
            if len(matches) == 0:
                # No subschema matched cleanly. Surface the errors of the
                # closest-matching one (fewest errors) so the real violation
                # is diagnosable instead of only "0 matched".
                closest = min(sub_results, key=len)
                errors.extend(closest)

    if "allOf" in schema:
        for sub in schema["allOf"]:
            errors.extend(validate(instance, sub, root, path))

    if "if" in schema:
        if_errors = validate(instance, schema["if"], root, path)
        if not if_errors and "then" in schema:
            errors.extend(validate(instance, schema["then"], root, path))
        elif if_errors and "else" in schema:
            errors.extend(validate(instance, schema["else"], root, path))

    return errors

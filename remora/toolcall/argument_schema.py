# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The JSON Schema profile a signed ToolSpec's ``argument_schema`` may use.

A validator that skips a keyword it does not understand validates less
strictly than the spec's author expects, and nothing tells either of them.
Version 1 of ``ToolSpecBundle.validate_arguments`` did exactly that: an
``enum``, a ``minimum`` or a nested object was signed, trusted and never
checked (found reviewing an external MCP adapter, 2026-10-12).

So the profile is closed. :func:`check_schema` runs when a spec is loaded and
refuses any keyword outside :data:`ENFORCED` or :data:`ANNOTATIONS`, and
:func:`validate` enforces every keyword in :data:`ENFORCED`. A schema either
means what it says here or does not load.

Left out on purpose:

- ``pattern``: Python ``re`` and ECMAScript regular expressions disagree,
  so a pattern would pass in one runtime and fail in another;
- ``format``: an annotation in JSON Schema 2020-12 unless a validator opts
  in, so an author cannot tell from the schema whether it is enforced;
- ``$ref`` and ``$defs``: resolution would put the meaning of a signed
  schema outside the signed bytes.

Types follow the JSON domain, not Python's: ``True`` is a boolean and never
an integer or a number, and ``1.0`` is not an integer (the canonical call
binding keeps the int/float distinction, see ``remora.federation.canonical``).
"""
from __future__ import annotations

import math
from typing import Any, Mapping

__all__ = ["ANNOTATIONS", "ENFORCED", "check_schema", "validate"]

#: Keywords :func:`validate` enforces.
ENFORCED = frozenset({
    "type", "enum", "const",
    "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
    "minLength", "maxLength",
    "properties", "required", "additionalProperties", "dependentRequired",
    "items", "minItems", "maxItems",
    "anyOf", "oneOf",
})
#: Keywords that carry no constraint, by the JSON Schema specification.
ANNOTATIONS = frozenset({"title", "description", "examples", "$comment"})

_TYPES = frozenset({"string", "integer", "number", "boolean", "object",
                    "array", "null"})
_NUMERIC_BOUNDS = ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum")
_COUNTS = ("minLength", "maxLength", "minItems", "maxItems")


def _is_number(value: Any) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and (not isinstance(value, float) or math.isfinite(value)))


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def check_schema(schema: Any, pointer: str = "") -> list[str]:
    """Why ``schema`` is outside the profile; an empty list means it is inside."""
    where = pointer or "/"
    if not isinstance(schema, Mapping):
        return [f"{where}: a schema is an object, got {type(schema).__name__}"]
    problems: list[str] = []
    for keyword in schema:
        if keyword not in ENFORCED and keyword not in ANNOTATIONS:
            problems.append(f"{where}: keyword {keyword!r} is not enforced")
    declared = schema.get("type")
    if declared is not None:
        names = declared if isinstance(declared, list) else [declared]
        if not names or any(not isinstance(n, str) or n not in _TYPES for n in names):
            problems.append(f"{where}: type {declared!r} is not a JSON type")
        elif len(set(names)) != len(names):
            problems.append(f"{where}: type {declared!r} repeats a type")
    if "enum" in schema and (not isinstance(schema["enum"], list) or not schema["enum"]):
        problems.append(f"{where}: enum is a non-empty list")
    for keyword in _NUMERIC_BOUNDS:
        if keyword in schema and not _is_number(schema[keyword]):
            problems.append(f"{where}: {keyword} is a finite number")
    for keyword in _COUNTS:
        if keyword in schema and not _is_count(schema[keyword]):
            problems.append(f"{where}: {keyword} is a non-negative integer")
    required = schema.get("required", [])
    if not isinstance(required, list) or any(not isinstance(n, str) for n in required):
        problems.append(f"{where}: required is a list of names")
    dependent = schema.get("dependentRequired", {})
    if not isinstance(dependent, Mapping) or any(
            not isinstance(v, list) or any(not isinstance(n, str) for n in v)
            for v in dependent.values()):
        problems.append(f"{where}: dependentRequired maps names to lists of names")
    additional = schema.get("additionalProperties", True)
    if not isinstance(additional, bool):
        # A schema here would be a second, unnamed property contract.
        problems.append(f"{where}: additionalProperties is true or false")
    properties = schema.get("properties", {})
    if not isinstance(properties, Mapping):
        problems.append(f"{where}: properties is an object")
    else:
        for name, sub in properties.items():
            problems += check_schema(sub, f"{pointer}/properties/{name}")
    if "items" in schema:
        problems += check_schema(schema["items"], f"{pointer}/items")
    for keyword in ("anyOf", "oneOf"):
        if keyword in schema:
            branches = schema[keyword]
            if not isinstance(branches, list) or not branches:
                problems.append(f"{where}: {keyword} is a non-empty list")
                continue
            for index, sub in enumerate(branches):
                problems += check_schema(sub, f"{pointer}/{keyword}/{index}")
    return problems


def _has_type(value: Any, name: str) -> bool:
    if name == "null":
        return value is None
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return _is_number(value)
    if name == "string":
        return isinstance(value, str)
    if name == "object":
        return isinstance(value, Mapping)
    return isinstance(value, (list, tuple))


def _same(a: Any, b: Any) -> bool:
    """JSON equality: ``True`` is not ``1``, and ``1`` equals ``1.0``."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if _is_number(a) and _is_number(b):
        return a == b
    if isinstance(a, Mapping) and isinstance(b, Mapping):
        return a.keys() == b.keys() and all(_same(a[k], b[k]) for k in a)
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


def validate(schema: Mapping[str, Any], value: Any, pointer: str = "") -> list[str]:
    """Why ``value`` fails ``schema``; an empty list means it validates.

    ``schema`` must already have passed :func:`check_schema`.
    """
    where = pointer or "/"
    declared = schema.get("type")
    if declared is not None:
        names = declared if isinstance(declared, list) else [declared]
        if not any(_has_type(value, n) for n in names):
            kind = "boolean" if isinstance(value, bool) else (
                "null" if value is None else type(value).__name__)
            # Type decides what the remaining keywords mean; stop here.
            return [f"{where}: expected {declared}, got {kind}"]
    problems: list[str] = []
    if "enum" in schema and not any(_same(value, v) for v in schema["enum"]):
        problems.append(f"{where}: {value!r} is not one of {schema['enum']!r}")
    if "const" in schema and not _same(value, schema["const"]):
        problems.append(f"{where}: {value!r} is not {schema['const']!r}")
    if _is_number(value):
        if "minimum" in schema and value < schema["minimum"]:
            problems.append(f"{where}: {value!r} is below minimum {schema['minimum']!r}")
        if "maximum" in schema and value > schema["maximum"]:
            problems.append(f"{where}: {value!r} is above maximum {schema['maximum']!r}")
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            problems.append(f"{where}: {value!r} is not above {schema['exclusiveMinimum']!r}")
        if "exclusiveMaximum" in schema and value >= schema["exclusiveMaximum"]:
            problems.append(f"{where}: {value!r} is not below {schema['exclusiveMaximum']!r}")
    if isinstance(value, str):
        # Length in code points, as JSON Schema defines it.
        if "minLength" in schema and len(value) < schema["minLength"]:
            problems.append(f"{where}: shorter than {schema['minLength']} characters")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            problems.append(f"{where}: longer than {schema['maxLength']} characters")
    if isinstance(value, Mapping):
        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                problems.append(f"{where}: missing required argument {name!r}")
        for name, needs in schema.get("dependentRequired", {}).items():
            if name in value:
                for other in needs:
                    if other not in value:
                        problems.append(f"{where}: {name!r} requires {other!r}")
        if schema.get("additionalProperties") is False:
            for name in value:
                if name not in properties:
                    problems.append(f"{where}: unexpected argument {name!r}")
        for name, sub in properties.items():
            if name in value:
                problems += validate(sub, value[name], f"{pointer}/{name}")
    if isinstance(value, (list, tuple)) and not isinstance(value, str):
        if "minItems" in schema and len(value) < schema["minItems"]:
            problems.append(f"{where}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            problems.append(f"{where}: more than {schema['maxItems']} items")
        if "items" in schema:
            for index, item in enumerate(value):
                problems += validate(schema["items"], item, f"{pointer}/{index}")
    if "anyOf" in schema and not any(
            not validate(sub, value, pointer) for sub in schema["anyOf"]):
        problems.append(f"{where}: matches none of anyOf")
    if "oneOf" in schema:
        matched = sum(1 for sub in schema["oneOf"] if not validate(sub, value, pointer))
        if matched != 1:
            problems.append(f"{where}: matches {matched} of oneOf, not exactly one")
    return problems

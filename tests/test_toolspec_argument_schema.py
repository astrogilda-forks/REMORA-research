# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The argument_schema profile: what a signed schema says is what is checked.

Before 2026-10-12 ``validate_arguments`` enforced required,
additionalProperties and top-level scalar types, and skipped everything else
without saying so. Reviewing an external MCP adapter showed what that let
through: an out-of-range enum, a negative count, a nested object of any
shape, and ``True`` where a number was declared (``bool`` is an ``int`` in
Python). These tests pin both halves of the fix: the validator enforces the
profile, and a schema outside the profile does not load.
"""
from __future__ import annotations

import pytest

from remora.toolcall.argument_schema import ENFORCED, check_schema, validate
from remora.toolcall.toolspec import ToolSpecRefused
from tests.test_toolspec_runtime import _bundle, _load, _spec


def _with_schema(schema: dict):
    return _load(_bundle([_spec(argument_schema=schema)]))


def _refused(loaded, arguments: dict) -> str:
    with pytest.raises(ToolSpecRefused) as exc:
        loaded.validate_arguments("store_artifact", arguments)
    assert exc.value.reason_code == "toolspec_arguments_schema_invalid"
    return str(exc.value)


# ── The finding that started this ──────────────────────────────────────────

def test_a_boolean_is_not_a_number() -> None:
    loaded = _with_schema({"type": "object",
                           "properties": {"ratio": {"type": "number"}}})
    assert "expected number, got boolean" in _refused(loaded, {"ratio": True})
    loaded.validate_arguments("store_artifact", {"ratio": 0.5})
    loaded.validate_arguments("store_artifact", {"ratio": 2})


def test_a_boolean_is_not_an_integer_and_an_integral_float_is_not_either() -> None:
    schema = {"type": "integer"}
    assert validate(schema, True)
    assert validate(schema, 1.0)
    assert not validate(schema, 1)


@pytest.mark.parametrize("value", [float("nan"), float("inf")])
def test_a_non_finite_float_is_not_a_json_number(value: float) -> None:
    assert validate({"type": "number"}, value)


# ── What the profile enforces, through the signed bundle ───────────────────

def test_enum_minimum_and_nested_objects_are_enforced() -> None:
    loaded = _with_schema({
        "type": "object",
        "properties": {
            "mode": {"enum": ["read", "write"]},
            "count": {"type": "integer", "minimum": 0, "maximum": 100},
            "options": {
                "type": "object",
                "properties": {"depth": {"type": "integer"}},
                "required": ["depth"],
                "additionalProperties": False,
            },
        },
        "additionalProperties": False,
    })
    loaded.validate_arguments(
        "store_artifact", {"mode": "read", "count": 3, "options": {"depth": 1}})
    assert "not one of" in _refused(loaded, {"mode": "delete"})
    assert "below minimum" in _refused(loaded, {"count": -1})
    assert "above maximum" in _refused(loaded, {"count": 101})
    assert "/options: missing required argument 'depth'" in _refused(
        loaded, {"options": {}})
    assert "/options: unexpected argument 'path'" in _refused(
        loaded, {"options": {"depth": 1, "path": "/"}})
    assert "/options/depth: expected integer, got str" in _refused(
        loaded, {"options": {"depth": "1"}})


def test_enum_compares_json_values_not_python_values() -> None:
    """``True == 1`` in Python; in JSON they are different values."""
    assert validate({"enum": [1, 2]}, True)
    assert validate({"enum": [True]}, 1)
    assert not validate({"enum": [1]}, 1.0)
    assert not validate({"const": {"a": [1]}}, {"a": [1]})


def test_contradictory_fields_are_refused_by_dependent_required() -> None:
    schema = {"type": "object",
              "properties": {"overwrite": {"type": "boolean"},
                             "backup_path": {"type": "string"}},
              "dependentRequired": {"overwrite": ["backup_path"]}}
    assert "'overwrite' requires 'backup_path'" in "; ".join(
        validate(schema, {"overwrite": True}))
    assert not validate(schema, {"overwrite": True, "backup_path": "b"})
    assert not validate(schema, {})


def test_one_of_means_exactly_one() -> None:
    schema = {"oneOf": [{"type": "integer"}, {"type": "number", "minimum": 0}]}
    assert validate(schema, 3)          # both branches match
    assert not validate(schema, -3)     # only the integer branch
    assert not validate(schema, 0.5)    # only the number branch
    assert validate(schema, "3")        # neither


def test_any_of_and_nullable_types() -> None:
    assert not validate({"type": ["string", "null"]}, None)
    assert validate({"type": ["string", "null"]}, 0)
    assert not validate({"anyOf": [{"type": "string"}, {"type": "null"}]}, None)
    assert validate({"anyOf": [{"type": "string"}, {"type": "null"}]}, 0)


def test_lengths_and_array_items() -> None:
    schema = {"type": "array", "minItems": 1, "maxItems": 2,
              "items": {"type": "string", "minLength": 1, "maxLength": 3}}
    assert not validate(schema, ["a", "abc"])
    assert validate(schema, [])
    assert validate(schema, ["a", "b", "c"])
    assert "/1: shorter than 1 characters" in validate(schema, ["a", ""])[0]
    assert validate(schema, ["abcd"])


# ── A schema outside the profile does not load ─────────────────────────────

@pytest.mark.parametrize("schema, reason", [
    ({"type": "object", "properties": {"u": {"type": "string", "pattern": "^a"}}},
     "keyword 'pattern' is not enforced"),
    ({"type": "object", "properties": {"u": {"type": "string", "format": "uri"}}},
     "keyword 'format' is not enforced"),
    ({"$ref": "#/$defs/x", "$defs": {"x": {}}}, "keyword '$ref' is not enforced"),
    ({"type": "object", "properties": {"n": {"type": "float"}}},
     "is not a JSON type"),
    ({"type": "object", "additionalProperties": {"type": "string"}},
     "additionalProperties is true or false"),
    ({"type": "object", "properties": {"n": {"minimum": "0"}}},
     "minimum is a finite number"),
    ({"type": "object", "properties": {"n": {"minimum": True}}},
     "minimum is a finite number"),
    ({"enum": []}, "enum is a non-empty list"),
    ({"oneOf": []}, "oneOf is a non-empty list"),
    ({"type": "array", "items": {"maxItems": -1}}, "maxItems is a non-negative integer"),
])
def test_a_schema_outside_the_profile_is_refused_at_load(schema: dict, reason: str) -> None:
    with pytest.raises(ToolSpecRefused) as exc:
        _with_schema(schema)
    assert exc.value.reason_code == "toolspec_argument_schema_unsupported"
    assert reason in str(exc.value)


def test_annotations_load_and_constrain_nothing() -> None:
    loaded = _with_schema({"title": "t", "description": "d", "$comment": "c",
                           "type": "object", "examples": [{}]})
    loaded.validate_arguments("store_artifact", {"anything": 1})


def test_every_enforced_keyword_is_exercised_by_check_schema() -> None:
    """A keyword added to ENFORCED without validation logic would load and be
    ignored, which is the bug this profile exists to prevent. Each one here
    has a schema that only it makes fail."""
    failing = {
        "type": ({"type": "string"}, 1),
        "enum": ({"enum": ["a"]}, "b"),
        "const": ({"const": "a"}, "b"),
        "minimum": ({"minimum": 1}, 0),
        "maximum": ({"maximum": 1}, 2),
        "exclusiveMinimum": ({"exclusiveMinimum": 1}, 1),
        "exclusiveMaximum": ({"exclusiveMaximum": 1}, 1),
        "minLength": ({"minLength": 2}, "a"),
        "maxLength": ({"maxLength": 1}, "ab"),
        "properties": ({"properties": {"a": {"type": "string"}}}, {"a": 1}),
        "required": ({"required": ["a"]}, {}),
        "additionalProperties": ({"additionalProperties": False}, {"a": 1}),
        "dependentRequired": ({"dependentRequired": {"a": ["b"]}}, {"a": 1}),
        "items": ({"items": {"type": "string"}}, [1]),
        "minItems": ({"minItems": 1}, []),
        "maxItems": ({"maxItems": 0}, [1]),
        "anyOf": ({"anyOf": [{"type": "string"}]}, 1),
        "oneOf": ({"oneOf": [{"type": "string"}]}, 1),
    }
    assert set(failing) == ENFORCED
    for keyword, (schema, value) in failing.items():
        assert not check_schema(schema), keyword
        assert validate(schema, value), keyword

# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The signed ``postcondition`` block of ToolSpec schema version 5 (CAPR-07).

Design: ``docs/design/compositional-authority-preservation-v1.md`` §4.3.

Until version 5 a ToolSpec signed only the NAME of a postcondition reader.
The contract a verifier compared against was built by the deployment's own
code, so REMORA could not re-run the comparison and recorded digests instead.
Version 5 signs the contract template itself:

- ``target_selector``: which object the call changes;
- ``expected_fields``: the declared delta;
- ``comparison_rules``: the frozen vocabulary of
  ``schemas/postcondition_contract_v1.yaml``.

A value may be a literal, or ``{"$arg": "<argument>"}``, which is filled from
the APPROVED call's argument of that name. The arguments come from the server,
which checks them against the dispatched call hash; the receipt contributes
only the observation. Under a ``hash`` rule an argument template is filled with
the argument's canonical digest, because that is what the rule compares.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from remora import frozen_json
from remora.governance.effect_verification import (
    PostconditionContract,
    effect_digest,
    validate_comparison_rules,
)

__all__ = ["PostconditionSpec", "PostconditionSpecError", "parse_postcondition"]

_KEYS = frozenset({"target_selector", "expected_fields", "comparison_rules",
                   "observation_deadline_seconds", "repeatable",
                   "evidence_fields"})
_ARG = "$arg"


class PostconditionSpecError(ValueError):
    """The block cannot be parsed or cannot be instantiated for a call."""


def _template_arg(value: Any, *, where: str) -> str | None:
    """The argument a template names, None for a literal."""
    if isinstance(value, Mapping) and _ARG in value:
        if set(value) != {_ARG} or not isinstance(value[_ARG], str):
            raise PostconditionSpecError(
                f"{where}: a template is exactly {{\"$arg\": <argument name>}}")
        return str(value[_ARG])
    return None


@dataclass(frozen=True)
class PostconditionSpec:
    """A parsed, linted postcondition template."""

    target_selector: Mapping[str, Any]
    expected_fields: Mapping[str, Any]
    comparison_rules: Mapping[str, str]
    observation_deadline_seconds: int = 30
    repeatable: bool = True
    evidence_fields: tuple[str, ...] = ()

    def instantiate(self, *, tool_id: str, reader: str,
                    arguments: Mapping[str, Any]) -> PostconditionContract:
        """The contract for one approved call. Raises when an argument is absent."""
        def fill(field: str, value: Any, *, hashed: bool) -> Any:
            name = _template_arg(value, where=field)
            if name is None:
                return frozen_json.thaw(value)
            if name not in arguments:
                raise PostconditionSpecError(
                    f"{field}: the approved call has no argument {name!r}")
            return effect_digest(arguments[name]) if hashed else arguments[name]

        selector = {k: fill(f"target_selector.{k}", v, hashed=False)
                    for k, v in self.target_selector.items()}
        expected = {k: fill(f"expected_fields.{k}", v,
                            hashed=self.comparison_rules.get(k) == "hash")
                    for k, v in self.expected_fields.items()}
        return PostconditionContract(
            tool_id=tool_id, reader=reader, target_selector=selector,
            expected_fields=expected,
            comparison_rules=dict(self.comparison_rules),
            observation_deadline_seconds=self.observation_deadline_seconds,
            repeatable=self.repeatable, evidence_fields=self.evidence_fields,
        )


def parse_postcondition(raw: Any, *,
                        argument_schema: Mapping[str, Any]) -> PostconditionSpec:
    """Parse and lint a block; every template must name a declared argument."""
    if not isinstance(raw, Mapping):
        raise PostconditionSpecError("the postcondition block is a mapping")
    unknown = sorted(set(raw) - _KEYS)
    if unknown:
        raise PostconditionSpecError(f"unknown postcondition keys: {unknown}")
    properties = set((argument_schema or {}).get("properties", {}) or {})

    def section(name: str) -> Mapping[str, Any]:
        value = raw.get(name)
        if not isinstance(value, Mapping) or not value:
            raise PostconditionSpecError(f"{name} is a non-empty mapping")
        for field, item in value.items():
            arg = _template_arg(item, where=f"{name}.{field}")
            if arg is not None and arg not in properties:
                raise PostconditionSpecError(
                    f"{name}.{field}: argument {arg!r} is not in the argument "
                    "schema")
        return value

    selector = section("target_selector")
    expected = section("expected_fields")
    rules = raw.get("comparison_rules", {}) or {}
    if not isinstance(rules, Mapping):
        raise PostconditionSpecError("comparison_rules is a mapping")
    try:
        validate_comparison_rules(expected, rules)
    except ValueError as exc:
        raise PostconditionSpecError(str(exc)) from exc
    deadline = raw.get("observation_deadline_seconds", 30)
    if isinstance(deadline, bool) or not isinstance(deadline, int) or deadline <= 0:
        raise PostconditionSpecError(
            "observation_deadline_seconds is a positive integer")
    repeatable = raw.get("repeatable", True)
    if not isinstance(repeatable, bool):
        raise PostconditionSpecError("repeatable is a boolean")
    evidence = raw.get("evidence_fields", [])
    if not isinstance(evidence, list) or not all(isinstance(e, str) for e in evidence):
        raise PostconditionSpecError("evidence_fields is a list of field names")
    return PostconditionSpec(
        target_selector=frozen_json.freeze(selector),
        expected_fields=frozen_json.freeze(expected),
        comparison_rules=frozen_json.freeze({str(k): str(v) for k, v in rules.items()}),
        observation_deadline_seconds=deadline,
        repeatable=repeatable,
        evidence_fields=tuple(evidence),
    )

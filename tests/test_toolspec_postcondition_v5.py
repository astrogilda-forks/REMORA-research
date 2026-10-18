# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""ToolSpec schema version 5: the signed ``postcondition`` block (CAPR-07).

SDD ``docs/design/compositional-authority-preservation-v1.md`` §4.3. The
contract a verdict is computed against comes from the signed spec and the
approved arguments, never from the receipt. These tests pin the block's
parse rules, its version gate, and how a contract is instantiated.
"""
from __future__ import annotations

import pytest

from remora.governance.effect_verification import (
    EffectStatus,
    effect_digest,
    verify_declared_delta,
)
from remora.toolcall.postcondition_spec import (
    PostconditionSpec,
    PostconditionSpecError,
    parse_postcondition,
)
from remora.toolcall.toolspec import ToolSpecBundle, ToolSpecRefused, sign_bundle

KEY = "v5-test-key"
IDENTITY = "deploy@test"

SCHEMA = {
    "type": "object",
    "properties": {"artifact_id": {"type": "string"},
                   "content": {"type": "object"}},
    "required": ["artifact_id"],
    "additionalProperties": False,
}

BLOCK = {
    "target_selector": {"artifact_id": {"$arg": "artifact_id"}},
    "expected_fields": {"stored": True, "content": {"$arg": "content"}},
    "comparison_rules": {"content": "hash"},
    "observation_deadline_seconds": 30,
}


def _spec(**over) -> dict:
    spec = {
        "tool_id": "store_artifact", "version": 1, "callable_digest": "d" * 64,
        "implementation_identity": "test", "description": "Store an artifact.",
        "argument_schema": SCHEMA, "risk_tier": "medium", "action_type": "write",
        "domain": "general", "capabilities": ["artifact_management"],
        "semantic_contract": {}, "credential_scope": ["artifacts:write"],
        "allowed_targets": ["prod"], "idempotency_contract": {},
        "postcondition_reader": "artifact_reader", "compensation_tool": None,
        "timeout_policy": {}, "network_policy": {}, "signing_identity": IDENTITY,
        "postcondition": BLOCK,
    }
    spec.update(over)
    return spec


def _load(schema_version: int, spec: dict) -> ToolSpecBundle:
    bundle = sign_bundle({"schema_version": schema_version, "tool_specs": [spec]},
                         key=KEY, signing_identity=IDENTITY,
                         signed_at="2026-10-18T00:00:00Z")
    return ToolSpecBundle.load(bundle, key=KEY, trusted_identities={IDENTITY})


def test_a_v5_bundle_loads_its_postcondition() -> None:
    spec = _load(5, _spec()).get("store_artifact")
    assert isinstance(spec.postcondition, PostconditionSpec)


def test_the_block_is_refused_below_v5() -> None:
    with pytest.raises(ToolSpecRefused) as exc:
        _load(4, _spec())
    assert exc.value.reason_code == "toolspec_postcondition_requires_v5"


def test_a_v4_spec_without_the_block_still_loads() -> None:
    spec = _spec()
    del spec["postcondition"]
    assert _load(4, spec).get("store_artifact").postcondition is None
    assert _load(5, spec).get("store_artifact").postcondition is None


def test_the_block_is_covered_by_the_spec_hash() -> None:
    a = _load(5, _spec()).get("store_artifact")
    b = _load(5, _spec(postcondition={**BLOCK, "expected_fields": {
        "stored": False, "content": {"$arg": "content"}}}))
    assert a.toolspec_hash != b.get("store_artifact").toolspec_hash


@pytest.mark.parametrize("block, needle", [
    ({**BLOCK, "expected_fields": {}}, "expected_fields"),
    ({**BLOCK, "target_selector": {}}, "target_selector"),
    ({**BLOCK, "comparison_rules": {"content": "excat"}}, "unsupported_comparison_rule"),
    ({**BLOCK, "comparison_rules": {"other": "exact"}}, "undeclared"),
    ({**BLOCK, "target_selector": {"artifact_id": {"$arg": "missing"}}}, "missing"),
    ({**BLOCK, "target_selector": {"artifact_id": {"$arg": "artifact_id", "x": 1}}}, "$arg"),
    ({**BLOCK, "surprise": 1}, "surprise"),
    ({**BLOCK, "observation_deadline_seconds": 0}, "observation_deadline_seconds"),
    ("not-a-mapping", "mapping"),
])
def test_a_malformed_block_is_refused(block, needle) -> None:
    with pytest.raises(PostconditionSpecError) as exc:
        parse_postcondition(block, argument_schema=SCHEMA)
    assert needle in str(exc.value)


def test_a_malformed_block_refuses_the_bundle() -> None:
    with pytest.raises(ToolSpecRefused) as exc:
        _load(5, _spec(postcondition={**BLOCK, "expected_fields": {}}))
    assert exc.value.reason_code == "toolspec_postcondition_invalid"


def test_the_block_needs_a_reader() -> None:
    with pytest.raises(ToolSpecRefused) as exc:
        _load(5, _spec(postcondition_reader=None))
    assert exc.value.reason_code == "toolspec_postcondition_invalid"


def _contract(arguments: dict):
    block = parse_postcondition(BLOCK, argument_schema=SCHEMA)
    return block.instantiate(tool_id="store_artifact", reader="artifact_reader",
                             arguments=arguments)


def test_instantiation_fills_templates_from_the_approved_arguments() -> None:
    content = {"n": 1}
    contract = _contract({"artifact_id": "rec-1", "content": content})
    assert dict(contract.target_selector) == {"artifact_id": "rec-1"}
    # A hash rule over an argument compares against the argument's digest.
    assert contract.expected_fields["content"] == effect_digest(content)
    assert contract.expected_fields["stored"] is True


def test_a_missing_argument_cannot_be_instantiated() -> None:
    with pytest.raises(PostconditionSpecError) as exc:
        _contract({"artifact_id": "rec-1"})
    assert "content" in str(exc.value)


def test_the_instantiated_contract_computes_the_verdict() -> None:
    content = {"n": 1}
    contract = _contract({"artifact_id": "rec-1", "content": content})
    common = dict(proposal_id="p", execution_id="e", toolspec_hash="h",
                  verifier_identity="v")
    good = {"artifact_id": "rec-1", "stored": True, "content": content}
    assert verify_declared_delta(contract, good, **common).status is EffectStatus.VERIFIED
    wrong = {**good, "content": {"n": 2}}
    assert verify_declared_delta(contract, wrong, **common).status is EffectStatus.MISMATCH
    other = {**good, "artifact_id": "rec-999"}
    assert verify_declared_delta(contract, other, **common).status is EffectStatus.UNOBSERVABLE

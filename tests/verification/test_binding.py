# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1-09 and WS1-10 at the record level (A17, part of A18).

The golden digest pins the canonical encoding and the domain tag: a change to
either must be a deliberate, versioned change, not a side effect. Only the
Python implementation exists, so this is a golden vector, not a
cross-language one.
"""
from __future__ import annotations

from dataclasses import fields, replace

import pytest

from remora.evidence.admission.canonical import canonical_bytes
from remora.verification.compose import compose_authorized_decision
from remora.verification.preconditions import (
    LogicalState,
    ProposalContext,
    derive_preconditions,
    tagged_digest,
)
from remora.verification.records import verify_record_hash
from tests.verification._ws1 import NOW_S, PROFILE, REGISTRY, base_report, context, h, scripted_checked

GOLDEN_CONTEXT = ProposalContext(
    proposal_id="p-1", tenant_id="t1", principal_id="agent-7", tool_name="set_port_profile",
    call_hash=h("call"), intent_authority_hash=h("wo"), policy_bundle_hash=h("policy"),
    toolspec_hash=h("toolspec"), profile_hash=h("profile"), capability_hash=h("caps"),
    flow_digest=h("flow"), flow_epoch=3, context_version=1)
#: Pinned on purpose: guards the WS1 commitment encoding against silent drift.
GOLDEN_CONTEXT_HASH = "705c8b3211cda997ff53332c24b69d87d731f77e1484bc249b04d7697d18f0df"


def test_canonical_record_roundtrip_and_golden_vector():
    assert tagged_digest("x", {"b": 1, "a": [True, None, "s"]}) == tagged_digest(
        "x", {"a": [True, None, "s"], "b": 1})
    assert tagged_digest("x", {"a": 1}) != tagged_digest("y", {"a": 1})  # domain separation
    assert GOLDEN_CONTEXT.context_hash == GOLDEN_CONTEXT_HASH
    with pytest.raises(ValueError):
        canonical_bytes({"score": 0.5})  # a float never enters a commitment


def _record():
    ctx, args = context()
    reqs = derive_preconditions(ctx, args, REGISTRY)
    checked = scripted_checked(ctx, reqs, {"target_belongs_to_work_order": LogicalState.PROVED,
                                           "customer_relation": LogicalState.PROVED})
    return compose_authorized_decision(base_report(), ctx, reqs, checked, None, PROFILE,
                                       now_s=NOW_S), ctx, reqs, checked


def test_a_record_verifies_and_a_tampered_one_does_not():
    rec, *_ = _record()
    import json
    stored = json.loads(rec.canonical())
    assert verify_record_hash(stored)
    for key, value in (("final_action", "accept"), ("review_class", "review"),
                       ("reason_codes", []), ("parent_record_hash", h("x"))):
        assert not verify_record_hash({**stored, key: value if stored[key] != value else "x"})


def test_change_of_any_bound_field_changes_the_context_and_refuses():
    """Part of A18: each bound field moves the context hash, and a record composed
    for one context cannot be reused for another."""
    rec, ctx, reqs, checked = _record()
    for f in fields(ctx):
        value = getattr(ctx, f.name)
        if isinstance(value, int):
            changed = replace(ctx, **{f.name: value + 1})
        elif f.name.endswith("_hash") or f.name == "flow_digest":
            changed = replace(ctx, **{f.name: h(value)})
        else:
            changed = replace(ctx, **{f.name: value + "x"})
        assert changed.context_hash != ctx.context_hash, f.name
        moved = compose_authorized_decision(base_report(), changed, reqs, checked, None, PROFILE,
                                            now_s=NOW_S)
        assert moved.final_action == "abstain" and "binding_mismatch" in moved.reason_codes, f.name


def test_records_chain_to_their_parent():
    rec, ctx, reqs, checked = _record()
    child = compose_authorized_decision(base_report(), ctx, reqs, checked, None, PROFILE,
                                        now_s=NOW_S, parent_record_hash=rec.record_hash)
    assert child.parent_record_hash == rec.record_hash
    assert child.record_hash != rec.record_hash

# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1 composition on top of the real engine (A03, A04; WS1 §8.1).

``PRECONDITION_CAP`` enters the engine like ``MONITOR_CAP``: it can only lower
a decision. A WS1 record composed from an engine refusal keeps the refusal
whatever the monitor and the preconditions say.
"""
from __future__ import annotations

import dataclasses

import pytest

from remora.decision_providers.composition_adapter import MonitorMode, assess_monitor_response
from remora.policy.composition import EXTERNAL_CAP_REASONS, Cap
from remora.policy.decision_engine import RemoraDecisionEngine
from remora.policy.observation import PolicyObservation
from remora.policy.report import DecisionAction, DecisionReason
from remora.verification.compose import compose_authorized_decision
from remora.verification.preconditions import LogicalState, derive_preconditions
from tests.verification._ws1 import NOW_S, REGISTRY, context, h, profile, response, scripted_checked

A, V, E, AB = (DecisionAction.ACCEPT, DecisionAction.VERIFY, DecisionAction.ESCALATE,
               DecisionAction.ABSTAIN)
ENGINE = RemoraDecisionEngine()
CLEAN = PolicyObservation(question="read service metrics", risk_tier="low", action_type="read",
                          phase="ordered", trust_score=0.92)
PROVED = {"target_belongs_to_work_order": LogicalState.PROVED,
          "customer_relation": LogicalState.PROVED}


def test_precondition_cap_is_an_external_cap_that_only_lowers():
    assert DecisionReason.PRECONDITION_CAP in EXTERNAL_CAP_REASONS
    assert ENGINE.decide(CLEAN).action is A
    for action in (V, E, AB):
        report = ENGINE.decide(CLEAN, caps=[Cap("precondition:x", action,
                                                DecisionReason.PRECONDITION_CAP)])
        assert report.action is action and report.reasons[-1] is DecisionReason.PRECONDITION_CAP
    lifted = ENGINE.decide(dataclasses.replace(CLEAN, argument_scope_valid=False),
                           caps=[Cap("precondition:x", A, DecisionReason.PRECONDITION_CAP)])
    assert lifted.action is AB


def _outcomes(prof, ctx, checked):
    clean = response(ctx, checked.evidence_digest, prof=prof)
    hostile = response(ctx, checked.evidence_digest, prof=prof,
                       hint_precondition_ids=["approve", "override"])
    for raw, err in ((None, "timeout"), (clean, None), (hostile, None), (b"{}", None)):
        yield assess_monitor_response(raw, profile=prof, context_hash=ctx.context_hash,
                                      evidence_digest=checked.evidence_digest,
                                      input_digest=h("in"), now_s=NOW_S, error=err)
    yield None


@pytest.mark.parametrize("field, value", [("argument_scope_valid", False),
                                          ("intent_provenance_required", True)])
def test_non_approvable_refusal_survives_every_monitor_and_review_outcome(field, value):
    """A03: cross-tenant and unauthorised intent stay refused with no review route."""
    base = ENGINE.decide(dataclasses.replace(CLEAN, **{field: value}))
    assert base.action is AB
    for mode in MonitorMode:
        prof = profile(mode)
        ctx, args = context(monitor_profile=prof)
        reqs = derive_preconditions(ctx, args, REGISTRY)
        checked = scripted_checked(ctx, reqs, PROVED)
        for assessment in _outcomes(prof, ctx, checked):
            for veto in (False, True):
                rec = compose_authorized_decision(base, ctx, reqs, checked, assessment, prof,
                                                  now_s=NOW_S, monitor_veto_on_record=veto)
                assert (rec.final_action, rec.review_class) == ("abstain", "none")
                assert not next(c for c in rec.all_caps if c.source == "engine").approvable


def test_f4_requires_declassification_grant():
    """A04: approval, score or a missing monitor do not lift F4; the grant route stays."""
    flagged = dataclasses.replace(CLEAN, flow_status="evaluated",
                                  flow_confidentiality_violation=True)
    base = ENGINE.decide(flagged)
    assert base.action is E and DecisionReason.FLOW_CONFIDENTIALITY_VIOLATION in base.reasons
    for mode in MonitorMode:
        prof = profile(mode)
        ctx, args = context(monitor_profile=prof)
        reqs = derive_preconditions(ctx, args, REGISTRY)
        checked = scripted_checked(ctx, reqs, PROVED)
        for assessment in _outcomes(prof, ctx, checked):
            rec = compose_authorized_decision(base, ctx, reqs, checked, assessment, prof,
                                              now_s=NOW_S)
            assert rec.final_action != "accept" and rec.review_class == "grant"
    # The grant changes the verdict, so the rung stops firing; a fresh decision
    # then still needs every other requirement.
    granted = ENGINE.decide(dataclasses.replace(flagged, flow_confidentiality_violation=False))
    prof = profile(MonitorMode.OPTIONAL)
    ctx, args = context(monitor_profile=prof)
    reqs = derive_preconditions(ctx, args, REGISTRY)
    open_ = scripted_checked(ctx, reqs, {"target_belongs_to_work_order": LogicalState.PROVED})
    assert compose_authorized_decision(granted, ctx, reqs, open_, None, prof,
                                       now_s=NOW_S).final_action != "accept"
    done = scripted_checked(ctx, reqs, PROVED)
    assert compose_authorized_decision(granted, ctx, reqs, done, None, prof,
                                       now_s=NOW_S).final_action == "accept"

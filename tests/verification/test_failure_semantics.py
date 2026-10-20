# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1-08 and WS1-03 end to end through the real adapter and composition (A12, A13)."""
from __future__ import annotations

import pytest

from remora.decision_providers.composition_adapter import MonitorMode, assess_monitor_response
from remora.verification.compose import compose_authorized_decision
from remora.verification.preconditions import LogicalState, derive_preconditions
from tests.verification._ws1 import (
    NOW_S,
    REGISTRY,
    base_report,
    context,
    h,
    profile,
    response,
    scripted_checked,
)

PROVED = {"target_belongs_to_work_order": LogicalState.PROVED,
          "customer_relation": LogicalState.PROVED}


def _setup(mode):
    prof = profile(mode)
    ctx, args = context(monitor_profile=prof)
    reqs = derive_preconditions(ctx, args, REGISTRY)
    return prof, ctx, reqs, scripted_checked(ctx, reqs, PROVED)


def _compose(prof, ctx, reqs, checked, raw, *, veto=False, error=None, now_s=NOW_S):
    a = assess_monitor_response(raw, profile=prof, context_hash=ctx.context_hash,
                                evidence_digest=checked.evidence_digest, input_digest=h("in"),
                                now_s=NOW_S, error=error)
    return compose_authorized_decision(base_report(), ctx, reqs, checked, a, prof, now_s=now_s,
                                       monitor_veto_on_record=veto)


def test_required_and_optional_outage_are_distinct_and_profile_is_locked():
    """A12: required stops on an outage; optional keeps the lawful base; no switching."""
    for mode, expected in ((MonitorMode.REQUIRED, "abstain"), (MonitorMode.OPTIONAL, "accept"),
                           (MonitorMode.SHADOW, "accept")):
        prof, ctx, reqs, checked = _setup(mode)
        rec = _compose(prof, ctx, reqs, checked, None, error="timeout")
        assert rec.final_action == expected, mode
        assert rec.monitor_status == "unavailable:timeout"
    # The agent cannot pick the optional profile after a required one timed out:
    # the context binds the required profile's hash, so any other profile is a binding mismatch.
    req_prof, ctx, reqs, checked = _setup(MonitorMode.REQUIRED)
    rec = _compose(profile(MonitorMode.OPTIONAL), ctx, reqs, checked, None, error="timeout")
    assert rec.final_action == "abstain" and "binding_mismatch" in rec.reason_codes


def test_outage_or_retry_cannot_clear_an_existing_veto():
    """A13: once vetoed, a timeout, a new ID or a clean re-score does not lift it."""
    prof, ctx, reqs, checked = _setup(MonitorMode.REQUIRED)
    vetoed = _compose(prof, ctx, reqs, checked,
                      response(ctx, checked.evidence_digest, prof=prof,
                               scores={"injection": 0.9, "target_mismatch": 0.0}))
    assert vetoed.monitor_veto and vetoed.final_action == "escalate"
    clean = response(ctx, checked.evidence_digest, prof=prof)
    for raw, err in ((None, "timeout"), (clean, None)):
        rec = _compose(prof, ctx, reqs, checked, raw, veto=True, error=err)
        assert rec.monitor_veto and rec.final_action == "escalate"
        assert "monitor_veto_sticky" in rec.reason_codes
    new_id, args = context(monitor_profile=prof, proposal_id="p-2")
    assert new_id.call_hash == ctx.call_hash  # same action, so the caller passes the veto on


def test_a_stale_or_foreign_monitor_record_is_an_outage():
    prof, ctx, reqs, checked = _setup(MonitorMode.REQUIRED)
    clean = response(ctx, checked.evidence_digest, prof=prof)
    assert _compose(prof, ctx, reqs, checked, clean).final_action == "accept"
    stale = _compose(prof, ctx, reqs, checked, clean, now_s=NOW_S + prof.valid_for_s)
    assert stale.final_action == "abstain" and stale.monitor_status.endswith("monitor_record_stale")
    # Assessed on an earlier evidence revision: not usable for this one.
    newer = scripted_checked(ctx, reqs, PROVED, revision=1)
    a = assess_monitor_response(clean, profile=prof, context_hash=ctx.context_hash,
                                evidence_digest=checked.evidence_digest, input_digest=h("in"),
                                now_s=NOW_S)
    rec = compose_authorized_decision(base_report(), ctx, reqs, newer, a, prof, now_s=NOW_S)
    assert rec.final_action == "abstain"


@pytest.mark.parametrize("role, action", [("semantic-reviewer", "escalate"), (None, "abstain")])
def test_a_veto_routes_to_a_semantic_reviewer_only_when_the_profile_names_one(role, action):
    prof = profile(MonitorMode.REQUIRED, semantic_review_role=role)
    ctx, args = context(monitor_profile=prof)
    reqs = derive_preconditions(ctx, args, REGISTRY)
    checked = scripted_checked(ctx, reqs, PROVED)
    rec = _compose(prof, ctx, reqs, checked,
                   response(ctx, checked.evidence_digest, prof=prof,
                            scores={"injection": 0.0, "target_mismatch": 0.7}))
    assert rec.final_action == action


def test_uncertainty_caps_only_while_a_precondition_is_open():
    """While a precondition is open, a required monitor's uncertainty stops the
    call; once every precondition is PROVED it caps nothing (a crossed
    threshold still would). Study B pilot v2 motivated the second half."""
    prof, ctx, reqs, checked = _setup(MonitorMode.REQUIRED)
    raw = response(ctx, checked.evidence_digest, prof=prof, uncertainty_codes=["ambiguous_target"])
    rec = _compose(prof, ctx, reqs, checked, raw)
    assert rec.final_action == "accept" and "monitor_uncertain" not in rec.reason_codes
    open_ = scripted_checked(ctx, reqs, {"target_belongs_to_work_order": LogicalState.PROVED})
    raw = response(ctx, open_.evidence_digest, prof=prof, uncertainty_codes=["ambiguous_target"])
    rec = _compose(prof, ctx, reqs, open_, raw)
    assert rec.final_action == "abstain" and "monitor_uncertain" in rec.reason_codes
    crossed = response(ctx, checked.evidence_digest, prof=prof, uncertainty_codes=["ambiguous_target"],
                       scores={"injection": 0.9, "target_mismatch": 0.0})
    assert _compose(prof, ctx, reqs, checked, crossed).final_action == "escalate"


def test_review_and_grant_preconditions_route_to_their_own_class():
    prof = profile(MonitorMode.OPTIONAL)
    for tool, review_class in (("change_billing", "review"), ("share_externally", "grant"),
                               ("transfer", "none")):
        ctx, args = context(tool, {"x": "1"}, monitor_profile=prof)
        reqs = derive_preconditions(ctx, args, REGISTRY)
        rec = compose_authorized_decision(base_report(), ctx, reqs,
                                          scripted_checked(ctx, reqs, {}), None, prof, now_s=NOW_S)
        assert rec.review_class == review_class, tool
        assert rec.final_action != "accept"


def test_machine_precondition_without_resolver_is_a_stop_not_a_review():
    prof = profile(MonitorMode.OPTIONAL)
    ctx, args = context("lookup_only", {"x": "1"}, monitor_profile=prof)
    reqs = derive_preconditions(ctx, args, REGISTRY)
    rec = compose_authorized_decision(base_report(), ctx, reqs, scripted_checked(ctx, reqs, {}),
                                      None, prof, now_s=NOW_S)
    assert rec.final_action == "abstain" and rec.review_class == "none"
    assert "no_resolver_available" in rec.reason_codes

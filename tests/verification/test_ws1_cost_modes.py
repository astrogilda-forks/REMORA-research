# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""H_COST and H_AR as runtime planner modes of the WS1 gate (review finding 3).

Both modes existed in ``planner.py`` and were refused by the gate. They need
deployment-owned estimates and a cost budget. Estimates are declared per
(predicate, resolver), because a precondition ID carries a per-call binding
digest; the gate expands them for each call. What these tests pin:

* without estimates or a cost budget the deployment is refused at construction;
* estimates must cover every (predicate, resolver) pair the registry declares;
* a lookup the cost budget covers runs, and the call can be accepted;
* a lookup the cost budget does not cover never runs, and the call abstains;
* estimates and the cost budget are bound, so changing them changes the binding;
* H_AR asks the monitor for hints and H_COST does not.

Cost here is estimated, not metered (SDD v2 AR-025).
"""
from __future__ import annotations

import hashlib

import pytest

from remora.execution.service import _ws1_regate_base
from remora.policy.observation import PolicyObservation
from remora.policy.report import DecisionAction
from remora.verification.execution_gate import Ws1Gate
from remora.verification.planner import LookupEstimate, PlannerMode
from tests.verification import ws1_deployment_fixture as fixture

INTENT = hashlib.sha256(b"work-order-17").hexdigest()
ESTIMATES = {("asset_registered", "assets"): LookupEstimate(cost_units=3, settle_ppm=900_000)}


def _deployment(mode=PlannerMode.H_COST, **overrides):
    fields = dict(planner_mode=mode, estimates=ESTIMATES, cost_budget_units=10)
    fields.update(overrides)
    return fixture.build_ws1_deployment(**fields)


def _evaluate(deployment):
    gate = Ws1Gate("enforce", deployment, flow_control=True)
    outcome = gate.evaluate(
        proposal_id="p", tenant="acme", principal="agent-1", tool_name="read_telemetry",
        arguments={"asset": "P-1"}, intent_authority_hash=INTENT, policy_bundle_hash="b" * 64,
        toolspec_hash="c" * 64, capability=None, flow_digest=None, flow_epoch=0,
        attempt_family_id=None, base=_ws1_regate_base(PolicyObservation(question="q")))
    return outcome, len(deployment.resolvers["assets"].calls)


@pytest.mark.parametrize("mode", [PlannerMode.H_COST, PlannerMode.H_AR])
@pytest.mark.parametrize("missing", ["estimates", "cost_budget_units"])
def test_a_cost_mode_without_estimates_or_budget_is_refused(mode, missing):
    with pytest.raises(ValueError, match="requires deployment estimates"):
        _deployment(mode, **{missing: None})


def test_estimates_must_cover_every_declared_lookup():
    with pytest.raises(ValueError, match="missing deployment estimate"):
        _deployment(estimates={("asset_registered", "elsewhere"): ESTIMATES[
            ("asset_registered", "assets")]})


@pytest.mark.parametrize("mode", [PlannerMode.H_COST, PlannerMode.H_AR])
def test_a_covered_lookup_runs_and_the_call_can_be_accepted(mode):
    outcome, lookups = _evaluate(_deployment(mode))
    assert lookups == 1 and outcome.final_action is DecisionAction.ACCEPT
    assert outcome.stop_reason == "machine_preconditions_settled"


@pytest.mark.parametrize("mode", [PlannerMode.H_COST, PlannerMode.H_AR])
def test_a_lookup_the_cost_budget_does_not_cover_never_runs(mode):
    outcome, lookups = _evaluate(_deployment(mode, cost_budget_units=2))
    assert lookups == 0 and outcome.final_action is DecisionAction.ABSTAIN
    assert outcome.stop_reason == "cost_budget_exhausted"


def test_estimates_and_cost_budget_are_bound():
    base, _ = _evaluate(_deployment())
    cheaper = {k: LookupEstimate(cost_units=1, settle_ppm=900_000) for k in ESTIMATES}
    for changed in (_deployment(estimates=cheaper), _deployment(cost_budget_units=11)):
        outcome, _ = _evaluate(changed)
        assert outcome.binding_hash and outcome.binding_hash != base.binding_hash


def test_h_ar_asks_the_monitor_for_hints_and_h_cost_does_not():
    asked = {}
    for mode in (PlannerMode.H_COST, PlannerMode.H_AR):
        calls = []
        _evaluate(_deployment(mode, monitor=lambda context, checked: calls.append(1)))
        asked[mode] = len(calls)
    # One final assessment for both; H_AR also asks once for hints first.
    assert asked == {PlannerMode.H_COST: 1, PlannerMode.H_AR: 2}


def test_h_random_stays_a_research_control():
    with pytest.raises(ValueError, match="research control"):
        _deployment(PlannerMode.H_RANDOM)


def test_the_audit_records_lookups_and_the_units_charged():
    """Declared units, not metered ones: the audit gives both, so a deployment
    can reconcile its estimates with what its sources bill."""
    outcome, lookups = _evaluate(_deployment())
    block = outcome.audit_block()
    assert block["lookups"] == {"assets": lookups} and block["cost_units_charged"] == 3
    det, _ = _evaluate(fixture.build_ws1_deployment())
    assert det.audit_block()["cost_units_charged"] is None

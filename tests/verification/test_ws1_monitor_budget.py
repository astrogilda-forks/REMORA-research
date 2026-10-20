# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The final monitor assessment always has a call left (NEGATIVE_RESULTS §95).

Under H_EDV each round asks the monitor for hints, charged to the same
per-call cap as the final assessment. With as many rounds as the cap allows,
the hints spent every call, the final assessment read
``monitor_budget_exhausted``, and a required monitor turned that into an
outage that refused a call whose preconditions were all PROVED.
"""
from __future__ import annotations

from dataclasses import replace

from remora.decision_providers.composition_adapter import MonitorMode
from remora.execution.service import _ws1_regate_base
from remora.policy.observation import PolicyObservation
from remora.policy.report import DecisionAction
from remora.verification.execution_gate import Ws1Gate
from remora.verification.planner import PlannerMode, VerificationBudget
from tests.verification import ws1_deployment_fixture as fixture
from tests.verification._ws1 import response
from tests.verification.test_ws1_typed_uncertainty import INTENT, WITH_INTENT

BUDGET = VerificationBudget(max_rounds=3, max_resolver_calls=3, max_monitor_calls=2,
                            requests_per_round=1)


def test_hints_leave_the_last_monitor_call_for_the_final_assessment():
    fixture.ASSETS["acme"][INTENT] = {"tenant": "acme"}
    try:
        prof = replace(fixture.PROFILE, mode=MonitorMode.REQUIRED, calibration_hash="1" * 64)
        asked = []

        def monitor(context, checked):
            asked.append(checked.evidence_revision)
            return response(context, checked.evidence_digest, prof=prof,
                            scores={"injection": 0.1})

        gate = Ws1Gate("enforce", fixture.build_ws1_deployment(
            registry=WITH_INTENT, monitor=monitor, monitor_profile=prof,
            planner_mode=PlannerMode.H_EDV, budget=BUDGET), flow_control=True)
        outcome = gate.evaluate(
            proposal_id="p", tenant="acme", principal="agent-1", tool_name="read_telemetry",
            arguments={"asset": "P-1"}, intent_authority_hash=INTENT,
            policy_bundle_hash="b" * 64, toolspec_hash="c" * 64, capability=None,
            flow_digest=None, flow_epoch=0, attempt_family_id=None,
            base=_ws1_regate_base(PolicyObservation(question="q")))
        record = outcome.audit_block()["record"]
        assert outcome.final_action is DecisionAction.ACCEPT, record["reason_codes"]
        assert len(asked) == 2 and record["monitor_status"].startswith("assessed")
    finally:
        fixture.ASSETS["acme"].pop(INTENT, None)

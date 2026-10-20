# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Typed monitor uncertainty on the WS1 gate (review finding 4).

After Study B pilot v2 a required monitor's uncertainty stopped capping a
call once every required precondition was PROVED. That dropped every code,
including those the evidence says nothing about. On the gate the rule is
now typed: PROVED evidence settles only the codes it covers.

* ``missing_context`` and ``ambiguous_intent``: a PROVED precondition on the
  server-resolved intent authority;
* ``ambiguous_target`` and ``unverified_value``: every argument is the subject
  of a PROVED precondition.

A code that stays open caps the call: ESCALATE to the semantic review role
when the profile names one, ABSTAIN otherwise. The untyped rule stays the
library default, which the sealed Study B harness uses.
"""
from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from remora.decision_providers.composition_adapter import MonitorMode
from remora.execution.service import _ws1_regate_base
from remora.policy.observation import PolicyObservation
from remora.policy.report import DecisionAction
from remora.verification.execution_gate import Ws1Gate
from remora.verification.preconditions import INTENT_SUBJECT, ResolutionClass
from remora.verification.registry import PredicateSpec, PreconditionRegistry, ResolverSpec
from tests.verification import ws1_deployment_fixture as fixture
from tests.verification._ws1 import response

INTENT = hashlib.sha256(b"work-order-17").hexdigest()
ASSET = PredicateSpec("asset_registered", ResolutionClass.MACHINE, "asset-verifier",
                      ("assets",), "asset")
WITH_INTENT = PreconditionRegistry(
    tools={"read_telemetry": (ASSET, PredicateSpec(
        "work_order_known", ResolutionClass.MACHINE, "asset-verifier", ("assets",),
        INTENT_SUBJECT))},
    resolvers={"assets": ResolverSpec("assets", "asset-inventory",
                                      frozenset({"asset_registered", "work_order_known"}),
                                      "resolve:assets")})


@pytest.fixture(autouse=True)
def _assets():
    fixture.ASSETS["acme"][INTENT] = {"tenant": "acme"}  # the work order is on record
    yield
    fixture.ASSETS["acme"].pop(INTENT, None)


def _evaluate(codes, *, arguments=None, registry=None, role=None):
    prof = replace(fixture.PROFILE, mode=MonitorMode.REQUIRED, calibration_hash="1" * 64,
                   semantic_review_role=role)

    def monitor(context, checked):
        return response(context, checked.evidence_digest, prof=prof,
                        scores={"injection": 0.1}, uncertainty_codes=list(codes))

    overrides = {"registry": registry} if registry is not None else {}
    gate = Ws1Gate("enforce", fixture.build_ws1_deployment(
        monitor=monitor, monitor_profile=prof, **overrides), flow_control=True)
    outcome = gate.evaluate(
        proposal_id="p", tenant="acme", principal="agent-1", tool_name="read_telemetry",
        arguments=arguments or {"asset": "P-1"}, intent_authority_hash=INTENT,
        policy_bundle_hash="b" * 64, toolspec_hash="c" * 64, capability=None,
        flow_digest=None, flow_epoch=0, attempt_family_id=None,
        base=_ws1_regate_base(PolicyObservation(question="q")))
    assert outcome.status == "evaluated", outcome.status
    return outcome.final_action, outcome.audit_block()["record"]["reason_codes"]


@pytest.mark.parametrize("code", ["ambiguous_target", "unverified_value"])
def test_a_proved_subject_for_every_argument_settles_target_and_value(code):
    action, reasons = _evaluate([code])
    assert action is DecisionAction.ACCEPT and "monitor_uncertain_unsettled" not in reasons


@pytest.mark.parametrize("code", ["ambiguous_target", "unverified_value"])
def test_an_argument_no_precondition_is_about_leaves_them_open(code):
    action, reasons = _evaluate([code], arguments={"asset": "P-1", "note": "see ticket"})
    assert action is DecisionAction.ABSTAIN and "monitor_uncertain_unsettled" in reasons


@pytest.mark.parametrize("code", ["missing_context", "ambiguous_intent"])
def test_intent_codes_need_a_proved_intent_precondition(code):
    action, reasons = _evaluate([code])
    assert action is DecisionAction.ABSTAIN and "monitor_uncertain_unsettled" in reasons
    action, reasons = _evaluate([code], registry=WITH_INTENT)
    assert action is DecisionAction.ACCEPT and "monitor_uncertain_unsettled" not in reasons


def test_one_open_code_is_enough_and_routes_to_the_semantic_role():
    action, _ = _evaluate(["unverified_value", "ambiguous_intent"])
    assert action is DecisionAction.ABSTAIN
    action, _ = _evaluate(["ambiguous_intent"], role="semantic-reviewer")
    assert action is DecisionAction.ESCALATE


def test_no_uncertainty_is_unchanged():
    assert _evaluate([])[0] is DecisionAction.ACCEPT

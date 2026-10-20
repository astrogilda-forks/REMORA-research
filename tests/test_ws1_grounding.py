# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Grounding from proofs on the WS1 execution path (step 2 of the #953 evaluation).

Before this, WS1 could only lower a decision on the execution API: the
evidence its lookups gathered never reached the engine, so a read the engine
abstains on for lack of grounding stayed refused however much WS1 proved.
Study B coupled the two in study code only (isp_study/defence.py).

With ``Ws1Deployment.grounding`` the deployment declares which engine
grounding signals each predicate's PROVED state establishes. At assessment
the engine re-decides on the observation plus those signals, under the same
loop-safety and capability adjustments; the WS1 caps then apply to that
decision. What these tests pin, through ``/v1/execution/assess``:

* a grounded read that the engine abstains on becomes ACCEPT with a token;
* an argument no precondition is about grounds no argument signal;
* an unproved or refuted precondition grounds nothing and the call refuses;
* a monitor veto still caps the re-decided ACCEPT;
* in shadow mode nothing changes, and the audit says what grounding would do;
* without a declared grounding map nothing changes.
"""
from __future__ import annotations

import dataclasses

import pytest

pytest.importorskip("fastapi")

from remora.policy.decision_engine import RemoraDecisionEngine  # noqa: E402
from remora.verification.execution_gate import (  # noqa: E402
    GROUNDING_FIELDS,
    Ws1Gate,
)
from tests.test_ws1_execution_binding import CALL, _events, _mod  # noqa: E402
from tests.test_ws1_execution_binding import (  # noqa: E402,F401  (the route fixture)
    client as _route_client,
)
from tests.verification import ws1_deployment_fixture as fixture  # noqa: E402

READ = dict(CALL, target_environment="staging")
GROUNDING = {"asset_registered": GROUNDING_FIELDS}


@pytest.fixture()
def client(_route_client, monkeypatch):  # noqa: F811  (pytest injects the imported fixture)
    exec_mod = _mod()
    monkeypatch.setattr(exec_mod, "_ENGINE", RemoraDecisionEngine(
        grounded_read_accept=True, execution_profile=True))
    original = exec_mod._observation_with_context

    def resolved(tool_call, tenant):
        # The deployment's intent source recognised the work order.
        obs, semantic = original(tool_call, tenant)
        return dataclasses.replace(obs, intent_authority_present=True), semantic

    monkeypatch.setattr(exec_mod, "_observation_with_context", resolved)
    return _route_client


@pytest.fixture(autouse=True)
def _assets():
    import json

    saved = json.loads(json.dumps(fixture.ASSETS))
    yield
    fixture.ASSETS.clear()
    fixture.ASSETS.update(saved)


def _install(monkeypatch, mode="enforce", **deployment):
    gate = Ws1Gate(mode, fixture.build_ws1_deployment(**deployment), flow_control=True)
    monkeypatch.setattr(_mod(), "_ws1_gate", lambda: gate)
    return gate


def _assess(client, call=READ):
    r = client.post("/v1/execution/assess", json=call)
    assert r.status_code == 200, r.text
    return r.json()


def _ws1():
    return _events("assessed")[-1]["ws1"]


def test_a_grounded_read_becomes_accept_and_executes(client, monkeypatch):
    """The recovery: VERIFY without grounding, ACCEPT with it, and the token
    redeems through the re-gate and the real dispatcher."""
    from tests.test_ws1_execution_binding import _redeem

    _install(monkeypatch)
    assert _assess(client)["decision"] == "verify"
    _install(monkeypatch, grounding=GROUNDING)
    body = _assess(client)
    assert (body["decision"], body["reasons"]) == ("accept", ["grounded_read_accept"])
    assert _ws1()["grounding"] == sorted(GROUNDING_FIELDS)
    assert _ws1()["grounded_action"] == "accept"
    r = _redeem(client, body["execution_token"], READ)
    assert r.status_code == 200, r.text
    assert r.json()["tool_execution"]["executed"] is True


def test_an_unproved_precondition_grounds_nothing(client, monkeypatch):
    _install(monkeypatch, grounding=GROUNDING)
    fixture.ASSETS["acme"].clear()
    body = _assess(client)
    assert body["decision"] == "abstain" and "execution_token" not in body
    assert "grounding" not in _ws1()
    fixture.ASSETS["acme"]["P-1"] = {"tenant": "other"}  # refuted
    assert _assess(client)["decision"] == "abstain" and "grounding" not in _ws1()


def test_a_monitor_veto_still_caps_the_grounded_decision(client, monkeypatch):
    from dataclasses import replace

    from remora.decision_providers.composition_adapter import MonitorMode
    from tests.verification._ws1 import response

    prof = replace(fixture.PROFILE, mode=MonitorMode.REQUIRED, calibration_hash="1" * 64)

    def monitor(context, checked):
        return response(context, checked.evidence_digest, prof=prof, scores={"injection": 0.9})

    _install(monkeypatch, grounding=GROUNDING, monitor=monitor, monitor_profile=prof)
    body = _assess(client)
    assert body["decision"] == "abstain" and "execution_token" not in body
    assert _ws1()["grounded_action"] == "accept" and _ws1()["monitor_veto"] is True


def test_shadow_changes_nothing_and_records_what_grounding_would_do(client, monkeypatch):
    _install(monkeypatch, "shadow", grounding=GROUNDING)
    body = _assess(client)
    assert body["decision"] == "verify" and "execution_token" not in body
    assert _ws1()["grounded_action"] == "accept"


def test_a_free_text_argument_grounds_no_argument_signal():
    from remora.policy.observation import canonical_tool_call_hash
    from remora.verification.execution_gate import grounding_facts
    from remora.verification.preconditions import (
        LogicalState,
        ProposalContext,
        derive_preconditions,
    )

    d = fixture.build_ws1_deployment(grounding=GROUNDING)

    class Proved:
        def state(self, _pid):
            return LogicalState.PROVED

    for args, expected in (({"asset": "P-1"}, set(GROUNDING_FIELDS)),
                           ({"asset": "P-1", "note": "see ticket"},
                            {"tool_matches_goal", "expected_effect_matches"})):
        ctx = ProposalContext(
            proposal_id="p", tenant_id="acme", principal_id="a", tool_name="read_telemetry",
            call_hash=canonical_tool_call_hash(name="read_telemetry", arguments=args,
                                               tenant="acme"),
            intent_authority_hash="1" * 64, policy_bundle_hash="2" * 64, toolspec_hash="3" * 64,
            profile_hash=d.monitor_profile.profile_hash, capability_hash="4" * 64,
            flow_digest="5" * 64, flow_epoch=0, context_version=1)
        reqs = derive_preconditions(ctx, args, d.registry)
        facts = grounding_facts(d.grounding, d.registry.tools["read_telemetry"], reqs,
                                Proved(), args)
        assert set(facts) == expected and all(v is True for v in facts.values())


@pytest.mark.parametrize("grounding", [{"no_such_predicate": GROUNDING_FIELDS},
                                       {"asset_registered": ("risk_tier",)},
                                       {"asset_registered": ()}])
def test_an_invalid_grounding_map_is_refused_at_construction(grounding):
    with pytest.raises(ValueError, match="invalid grounding"):
        fixture.build_ws1_deployment(grounding=grounding)

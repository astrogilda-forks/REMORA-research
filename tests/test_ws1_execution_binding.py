# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1 WP5 on the canonical execution path (A18-A23; WS1 SDD §13.2-13.3).

The gate is built from ``tests/verification/ws1_deployment_fixture.py``. The
research profile resolves no intent authority, so the fixture's semantic
block is given one; it is the same at assessment and redemption.
"""
from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("fastapi")

from remora.policy.composition import Cap, meet  # noqa: E402
from remora.policy.report import DecisionAction, DecisionReason  # noqa: E402
from remora.verification.execution_gate import Ws1Gate  # noqa: E402
from remora.verification.records import verify_record_hash  # noqa: E402
from tests.test_execute_accepted_toolspec import CALL, PRINCIPAL, READ_SPEC  # noqa: E402
from tests.test_toolspec_execution_wiring import _bundle_file, _client, _spec  # noqa: E402
from tests.verification import ws1_deployment_fixture as fixture  # noqa: E402

INTENT = hashlib.sha256(b"work-order-17").hexdigest()


def _mod():
    import servers.execution_api as exec_mod

    return exec_mod


@pytest.fixture(autouse=True)
def _assets():
    saved = json.loads(json.dumps(fixture.ASSETS))
    yield
    fixture.ASSETS.clear()
    fixture.ASSETS.update(saved)


def _install(monkeypatch, mode: str, **deployment):
    exec_mod = _mod()
    gate = Ws1Gate(mode, fixture.build_ws1_deployment(**deployment), flow_control=True)
    monkeypatch.setattr(exec_mod, "_ws1_gate", lambda: gate)
    return gate


@pytest.fixture()
def client(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path, bundle_path=_bundle_file(
        tmp_path, [_spec(), dict(_spec(**READ_SPEC), version=1)], name="ws1-bundle.json"))
    exec_mod = _mod()
    original = exec_mod._observation_with_context

    def with_intent(tool_call, tenant):
        obs, semantic = original(tool_call, tenant)
        return obs, {**semantic, "intent_authority_hash": INTENT}

    monkeypatch.setattr(exec_mod, "_observation_with_context", with_intent)
    return c


def _mint(gate, *, proposal_id="p-ws1-1"):
    """An ACCEPT token as the assess branch mints it under WS1 enforce, and
    the ``assessed`` record the re-gate reads back."""
    from remora.enforcement.token import PolicyDecisionToken
    from remora.execution.service import authorization_context

    exec_mod = _mod()
    tool_call = exec_mod.ToolCallRequest(**CALL)
    obs, semantic = exec_mod._observation_with_context(tool_call, "acme")
    identity = exec_mod._resolve_toolspec(
        tool_call.tool_name, tool_call.arguments, tool_call.target_environment)
    outcome = gate.evaluate(
        proposal_id=proposal_id, tenant="acme", principal=PRINCIPAL,
        tool_name=tool_call.tool_name, arguments=tool_call.arguments,
        intent_authority_hash=INTENT,
        policy_bundle_hash=exec_mod._current_policy_bundle_hash(),
        toolspec_hash=str(identity["hash"]), capability=None,
        flow_digest=obs.flow_digest, flow_epoch=obs.flow_epoch, attempt_family_id=None,
        base=_accept(obs))
    assert outcome.final_action is DecisionAction.ACCEPT, outcome.audit_block()
    exec_mod._CHAIN.append("acme", {"event": "assessed", "proposal_id": proposal_id,
                                    "actor": PRINCIPAL, "decision": "accept",
                                    "toolspec_hash": identity["hash"],
                                    "ws1": outcome.audit_block()})
    now = datetime.now(UTC)
    token = PolicyDecisionToken.issue(
        action="accept", observation_hash=obs.tool_call_hash or "", request_id=proposal_id,
        issued_at=now.isoformat(), expires_at=(now + timedelta(seconds=300)).isoformat(),
        audience=exec_mod.PEP_AUDIENCE,
        context=authorization_context(
            tenant="acme", principal=PRINCIPAL, semantic=semantic,
            target_environment=tool_call.target_environment or "",
            policy_bundle_hash=exec_mod._current_policy_bundle_hash(),
            toolspec_hash=str(identity["hash"]), ws1_binding_hash=outcome.binding_hash))
    return token.to_dict()


def _accept(obs):
    from remora.execution.service import _ws1_regate_base

    return _ws1_regate_base(obs)


def _redeem(client, token, call=CALL):
    return client.post("/v1/execution/execute-accepted",
                       json={"execution_token": token, "tool_call": call})


def _events(name):
    return [e.payload for e in _mod()._CHAIN.entries("acme") if e.payload.get("event") == name]


# ── redemption: fresh re-gate, binding in the context ───────────────────


def test_a_ws1_bound_grant_executes_when_the_preconditions_still_hold(client, monkeypatch):
    gate = _install(monkeypatch, "enforce")
    r = _redeem(client, _mint(gate))
    assert r.status_code == 200, r.text
    assert r.json()["tool_execution"]["executed"] is True


def test_expired_or_revoked_evidence_is_rechecked_at_dispatch(client, monkeypatch):
    """A19: the asset record is withdrawn after ACCEPT; redemption refuses
    before consumption, and the untouched grant works once it is back."""
    gate = _install(monkeypatch, "enforce")
    token = _mint(gate)
    record = fixture.ASSETS["acme"].pop("P-1")
    r = _redeem(client, token)
    assert (r.status_code, r.json()["detail"]) == (409, "ws1_regate_refused")
    assert _events("execution_ws1_refused") and not _events("execution_authorized")
    fixture.ASSETS["acme"]["P-1"] = {"tenant": "other"}  # now refuting, not just unknown
    assert _redeem(client, token).json()["detail"] == "ws1_regate_refused"
    fixture.ASSETS["acme"]["P-1"] = record
    assert _redeem(client, token).status_code == 200


@pytest.mark.parametrize("change", ["registry", "monitor_profile", "budget", "planner"])
def test_change_of_any_bound_field_refuses_before_dispatch(client, monkeypatch, change):
    """A18 for the WS1 terms; tenant, principal, call, intent, policy, ToolSpec
    and task are bound by the existing context fields and tested there."""
    from dataclasses import replace

    from remora.decision_providers.composition_adapter import MonitorMode
    from remora.verification.planner import PlannerMode, VerificationBudget
    from remora.verification.registry import PredicateSpec, PreconditionRegistry
    from remora.verification.preconditions import ResolutionClass

    token = _mint(_install(monkeypatch, "enforce"))
    moved = {
        "registry": dict(registry=PreconditionRegistry(
            tools={"read_telemetry": (*fixture.REGISTRY.tools["read_telemetry"],
                                      PredicateSpec("asset_live", ResolutionClass.MACHINE,
                                                    "asset-verifier", ("assets",), "asset",
                                                    required=False))},
            resolvers={"assets": replace(fixture.REGISTRY.resolvers["assets"],
                                         predicate_ids=frozenset({"asset_registered",
                                                                  "asset_live"}))})),
        "monitor_profile": dict(monitor_profile=replace(fixture.PROFILE, profile_id="other")),
        "budget": dict(budget=VerificationBudget(max_resolver_calls=2)),
        "planner": dict(planner_mode=PlannerMode.H_EDV),
    }[change]
    _install(monkeypatch, "enforce", **moved)
    r = _redeem(client, token)
    assert r.status_code == 409 and r.json()["detail"] == "context_mismatch", r.text
    assert not _events("execution_authorized")
    assert MonitorMode.SHADOW  # imported for the profile replace above


def test_a_changed_argument_refuses_without_spending_the_grant(client, monkeypatch):
    gate = _install(monkeypatch, "enforce")
    token = _mint(gate)
    r = _redeem(client, token, dict(CALL, arguments={"asset": "P-2"}))
    assert r.status_code == 409 and r.json()["detail"] == "binding_refused"
    assert _redeem(client, token).status_code == 200


def test_a_pep_without_ws1_does_not_accept_a_ws1_grant(client, monkeypatch):
    """Rollback (WS1 SDD §13.3): a WS1-bound grant is not honoured once WS1
    is off; the binding it carries cannot be recomputed."""
    token = _mint(_install(monkeypatch, "enforce"))
    monkeypatch.setattr(_mod(), "_ws1_gate", lambda: None)
    r = _redeem(client, token)
    assert (r.status_code, r.json()["detail"]) == (409, "context_mismatch")


def test_crash_retry_and_concurrent_redemption_preserve_existing_single_use_contract(
        client, monkeypatch):
    """A20: two concurrent redemptions of one WS1 grant dispatch at most once.
    This checks the existing single-use contract under WS1; it does not claim
    exactly-once effects."""
    token = _mint(_install(monkeypatch, "enforce"))
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _redeem(client, token), range(2)))
    executed = [r for r in results if r.status_code == 200
                and r.json()["tool_execution"]["executed"]]
    assert len(executed) == 1, [r.text for r in results]
    assert len(_events("execution_authorized")) == 1


# ── assessment: shadow changes nothing, enforce only lowers ────────────


def _assess(client):
    r = client.post("/v1/execution/assess", json=CALL)
    assert r.status_code == 200, r.text
    return r.json()


def test_shadow_is_observationally_equal_to_baseline(client, monkeypatch):
    """A23 at the route: same decision and reasons, no token difference in kind;
    the WS1 record is audited."""
    monkeypatch.setattr(_mod(), "_ws1_gate", lambda: None)
    off = _assess(client)
    _install(monkeypatch, "shadow")
    fixture.ASSETS["acme"].clear()  # WS1 would refuse; shadow must not
    shadow = _assess(client)
    assert (shadow["decision"], shadow["reasons"]) == (off["decision"], off["reasons"])
    assert ("execution_token" in shadow) == ("execution_token" in off)
    assert shadow["ws1"]["mode"] == "shadow"
    assert _events("assessed")[-1]["ws1"]["final_action"] == "abstain"


def test_enforce_refuses_an_unproved_precondition_at_assessment(client, monkeypatch):
    _install(monkeypatch, "enforce")
    fixture.ASSETS["acme"].clear()
    body = _assess(client)
    assert body["decision"] == "abstain"
    assert body["reasons"][-1] == DecisionReason.PRECONDITION_CAP.value
    assert "review_item_id" not in body and "execution_token" not in body


def test_enforce_leaves_the_engines_decision_when_ws1_is_clean(client, monkeypatch):
    monkeypatch.setattr(_mod(), "_ws1_gate", lambda: None)
    off = _assess(client)
    _install(monkeypatch, "enforce")
    on = _assess(client)
    assert (on["decision"], on["reasons"]) == (off["decision"], off["reasons"])
    assert on["ws1"]["status"] == "evaluated"
    caps = _events("assessed")[-1]["ws1"]["record"]["all_caps"]
    assert [c["source"] for c in caps] == ["engine"]  # WS1 added no cap


def test_replay_reconstructs_caps_preconditions_and_failure_status(client, monkeypatch):
    """A22: the audited block verifies by hash, its caps' meet is its final
    action, and a tampered copy does not verify."""
    _install(monkeypatch, "enforce")
    fixture.ASSETS["acme"].clear()
    _assess(client)
    block = _events("assessed")[-1]["ws1"]
    record = block["record"]
    assert verify_record_hash(record)
    caps = [Cap(c["source"], DecisionAction(c["action"]), DecisionReason(c["reason"]),
                approvable=c["approvable"]) for c in record["all_caps"]]
    assert meet(caps).action.value == record["final_action"] == block["final_action"]
    assert [r["logical_state"] for r in record["all_precondition_results"]] == ["unknown"]
    assert not verify_record_hash({**record, "final_action": "accept"})


def test_monitor_and_resolver_cannot_receive_unreadable_data_or_exfiltrate_via_errors(
        client, monkeypatch):
    """A21 for what WS1 itself passes on: the monitor gets hashes, IDs and
    states, never argument values; a resolver's error text never reaches the
    record, only its type."""
    from dataclasses import replace

    from remora.decision_providers.composition_adapter import MonitorMode

    seen = []

    def monitor(context, checked):
        seen.append(repr(context) + repr(checked))
        return None

    class Leaky:
        resolver_id = "assets"

        def fetch(self, request, tenant_id, now_s):
            raise RuntimeError("secret customer record CUST-991 for P-1")

    profile = replace(fixture.PROFILE, mode=MonitorMode.OPTIONAL, calibration_hash="1" * 64)
    _install(monkeypatch, "enforce", monitor=monitor, monitor_profile=profile,
             resolvers={"assets": Leaky()})
    body = _assess(client)
    assert seen and not any("P-1" in s for s in seen)
    dumped = json.dumps(_events("assessed")[-1]) + json.dumps(body)
    assert "CUST-991" not in dumped and "secret" not in dumped
    assert body["decision"] == "abstain"


# ── configuration ───────────────────────────────────────────────────────


def test_mode_and_dependencies_are_refused_at_construction(monkeypatch):
    with pytest.raises(ValueError, match="FLOW_CONTROL"):
        Ws1Gate("enforce", fixture.build_ws1_deployment(), flow_control=False)
    with pytest.raises(ValueError, match="evidence"):
        Ws1Gate("enforce", fixture.build_ws1_deployment(enforce_dependencies={}),
                flow_control=True)
    for mode in ("off", "research", "ENFORCE"):
        with pytest.raises(ValueError):
            Ws1Gate(mode, fixture.build_ws1_deployment(), flow_control=True)
    assert Ws1Gate("shadow", fixture.build_ws1_deployment(enforce_dependencies={}),
                   flow_control=False).mode == "shadow"


def test_the_server_reads_its_mode_from_the_deployment_only(monkeypatch):
    exec_mod = _mod()
    monkeypatch.setattr(exec_mod, "_WS1_GATE", None)
    monkeypatch.delenv("REMORA_WS1_MODE", raising=False)
    assert exec_mod._ws1_gate() is None
    monkeypatch.setenv("REMORA_WS1_MODE", "research")
    with pytest.raises(ValueError, match="not one of"):
        exec_mod._ws1_gate()
    monkeypatch.setenv("REMORA_WS1_MODE", "shadow")
    monkeypatch.delenv("REMORA_WS1_DEPLOYMENT_MODULE", raising=False)
    with pytest.raises(ValueError, match="DEPLOYMENT_MODULE"):
        exec_mod._ws1_gate()
    monkeypatch.setenv("REMORA_WS1_DEPLOYMENT_MODULE", "tests.verification.ws1_deployment_fixture")
    assert exec_mod._ws1_gate().mode == "shadow"
    monkeypatch.setenv("REMORA_WS1_MODE", "enforce")
    monkeypatch.delenv("REMORA_FLOW_CONTROL", raising=False)
    with pytest.raises(ValueError, match="FLOW_CONTROL"):
        exec_mod._ws1_gate()


# ── review path and async worker ───────────────────────────────────────

from tests.test_toolspec_execution_wiring import CALL as WRITE_CALL  # noqa: E402



def _reviewed_item(client):
    body = client.post("/v1/execution/assess", json=WRITE_CALL).json()
    item_id = body.get("review_item_id")
    if item_id is None:
        pytest.skip(f"the engine gives {body['decision']} here, no review item")
    assert client.post("/v1/execution/approve", json={"item_id": item_id}).status_code == 200
    return item_id


def test_an_approval_never_stands_in_for_a_ws1_precondition(client, monkeypatch):
    """The approval lifts the engine's route only. A precondition withdrawn
    after approval refuses before the queue is touched, and the approval stands."""
    _install(monkeypatch, "enforce")
    item_id = _reviewed_item(client)
    record = fixture.ASSETS["acme"].pop("wired-1")
    r = client.post("/v1/execution/execute", json={"item_id": item_id, "tool_call": WRITE_CALL})
    assert (r.status_code, r.json()["detail"]) == (409, "ws1_regate_refused")
    assert _events("execution_ws1_refused") and not _events("execution_authorized")
    fixture.ASSETS["acme"]["wired-1"] = record
    r = client.post("/v1/execution/execute", json={"item_id": item_id, "tool_call": WRITE_CALL})
    assert r.status_code == 200, r.text


def test_the_async_worker_runs_the_ws1_regate_before_minting(client, monkeypatch):
    monkeypatch.setenv("REMORA_ASYNC_DISPATCH", "1")
    _install(monkeypatch, "enforce")
    item_id = _reviewed_item(client)
    r = client.post("/v1/execution/execute", json={"item_id": item_id, "tool_call": WRITE_CALL})
    assert r.status_code in (200, 202), r.text
    fixture.ASSETS["acme"].clear()
    results = _mod().dispatch_pending_intents("acme", worker_id="w-1")
    assert results, "the worker found no pending row"
    assert not _events("execution_authorized")
    rows = [e for e in _mod()._CHAIN.entries("acme")]
    assert "ws1_regate_refused" in json.dumps([e.payload for e in rows]) or \
        "ws1_regate_refused" in json.dumps(results)


# ── the WS1 review route ───────────────────────────────────────────────


def _review_deployment():
    from remora.verification.preconditions import ResolutionClass
    from remora.verification.registry import PredicateSpec, PreconditionRegistry

    tools = dict(fixture.REGISTRY.tools)
    tools["store_artifact"] = (*tools["store_artifact"],
                               PredicateSpec("change_approved", ResolutionClass.REVIEW,
                                             "review", review_role="change-manager"))
    return {"registry": PreconditionRegistry(tools=tools, resolvers=fixture.REGISTRY.resolvers)}


def _as_role(monkeypatch, role):
    import servers.api as api_mod

    monkeypatch.setattr(api_mod, "_authenticate", lambda request: ("acme", role))


def _assess_write(client):
    body = client.post("/v1/execution/assess", json=WRITE_CALL).json()
    assert body["decision"] == "escalate", body
    return body


def test_a_review_precondition_opens_a_review_route_with_its_role(client, monkeypatch):
    _install(monkeypatch, "enforce", **_review_deployment())
    body = _assess_write(client)
    block = _events("assessed")[-1]["ws1"]
    assert block["review_role"] == "change-manager"
    assert body["review_item_id"]


def test_an_approval_in_another_role_does_not_close_it(client, monkeypatch):
    _install(monkeypatch, "enforce", **_review_deployment())
    item_id = _assess_write(client)["review_item_id"]
    _as_role(monkeypatch, "reviewer")
    assert client.post("/v1/execution/approve", json={"item_id": item_id}).status_code == 200
    r = client.post("/v1/execution/execute", json={"item_id": item_id, "tool_call": WRITE_CALL})
    assert (r.status_code, r.json()["detail"]) == (409, "ws1_regate_refused")
    refused = _events("execution_ws1_refused")[-1]["ws1"]["record"]
    states = {p["precondition_id"].split(":")[0]: p for p in refused["all_precondition_results"]}
    assert states["change_approved"]["reason_code"] == "review_by_another_role"


def test_an_approval_in_the_named_role_closes_it_and_executes(client, monkeypatch):
    _install(monkeypatch, "enforce", **_review_deployment())
    item_id = _assess_write(client)["review_item_id"]
    _as_role(monkeypatch, "change-manager")
    assert client.post("/v1/execution/approve", json={"item_id": item_id}).status_code == 200
    r = client.post("/v1/execution/execute", json={"item_id": item_id, "tool_call": WRITE_CALL})
    assert r.status_code == 200, r.text


def test_an_approval_never_closes_a_machine_precondition(client, monkeypatch):
    _install(monkeypatch, "enforce", **_review_deployment())
    item_id = _assess_write(client)["review_item_id"]
    _as_role(monkeypatch, "change-manager")
    assert client.post("/v1/execution/approve", json={"item_id": item_id}).status_code == 200
    fixture.ASSETS["acme"].pop("wired-1")
    r = client.post("/v1/execution/execute", json={"item_id": item_id, "tool_call": WRITE_CALL})
    assert (r.status_code, r.json()["detail"]) == (409, "ws1_regate_refused")


def test_without_a_review_role_an_unproved_machine_precondition_still_refuses(client, monkeypatch):
    """The route exists only when every WS1 cap is a REVIEW precondition of one role."""
    _install(monkeypatch, "enforce", **_review_deployment())
    fixture.ASSETS["acme"].pop("wired-1")
    body = client.post("/v1/execution/assess", json=WRITE_CALL).json()
    assert body["decision"] == "abstain" and "review_item_id" not in body
    assert _events("assessed")[-1]["ws1"]["review_role"] == ""


def test_the_shadow_report_counts_what_enforce_would_change(client, monkeypatch):
    """WP6: a shadow chain read back says what enforce would have done."""
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from ws1_shadow_report import report

    _install(monkeypatch, "shadow")
    client.post("/v1/execution/assess", json=CALL)
    fixture.ASSETS["acme"].clear()
    client.post("/v1/execution/assess", json=CALL)
    out = report(e.payload for e in _mod()._CHAIN.entries("acme"))
    assert out["assessed_with_ws1"] == 2 and out["modes"] == {"shadow": 2}
    assert out["records_failing_hash_check"] == 0
    counts = out["by_tool"]["read_telemetry"]
    assert counts.get("unchanged") == 1 and sum(counts.values()) == 2
    assert "verification_budget_exhausted" in out["ws1_reason_codes"] or \
        "lookup_did_not_prove" in out["ws1_reason_codes"]


@pytest.mark.parametrize("expired", [False, True])
def test_monitor_cannot_clear_a_hint_veto_or_outlive_authority(expired):
    from remora.verification.execution_gate import ENFORCE_DEPENDENCIES, Ws1Deployment
    from remora.verification.planner import PlannerMode
    from tests.verification import _ws1 as lib

    now = [lib.NOW_MS]
    calls = []

    def monitor(ctx, checked):
        calls.append(checked.evidence_revision)
        if expired:
            now[0] += 60_000
        return lib.response(ctx, checked.evidence_digest,
                            scores={"injection": 0.9 if not expired and len(calls) == 1 else 0.1,
                                    "target_mismatch": 0.1})

    deployment = Ws1Deployment(
        lib.REGISTRY, lib.VERIFIERS, lib.sources(), lib.PROFILE,
        lambda tenant, principal: lib.ALL_CAPS, lambda: now[0], monitor=monitor,
        planner_mode=PlannerMode.H_DET if expired else PlannerMode.H_EDV,
        enforce_dependencies=dict.fromkeys(ENFORCE_DEPENDENCIES, "test-only"))
    gate = Ws1Gate("enforce", deployment, flow_control=True)
    outcome = gate.evaluate(
        proposal_id="p-monitor-lifecycle", tenant="t1", principal="agent-7",
        tool_name="set_port_profile",
        arguments={"port": "sw1/p4", "customer": "C-1", "profile": "gold"},
        intent_authority_hash=lib.WORK_ORDER, policy_bundle_hash=lib.h("policy"),
        toolspec_hash=lib.h("tool"), capability=None, flow_digest=None, flow_epoch=0,
        attempt_family_id=None, base=lib.base_report())
    assert outcome.final_action is not DecisionAction.ACCEPT
    assert outcome.apply(lib.base_report()).action is DecisionAction.ABSTAIN
    assert not outcome.binding_hash
    if expired:
        assert "evidence_expired" in outcome.record.reason_codes
    else:
        assert len(calls) == 2 and outcome.monitor_veto


@pytest.mark.parametrize("async_dispatch", [False, True])
@pytest.mark.parametrize("change", ["registry", "monitor_profile", "budget", "planner",
                                    "off", "shadow"])
def test_review_binds_ws1_configuration_before_consumption(client, monkeypatch,
                                                          async_dispatch, change):
    from dataclasses import replace

    from remora.verification.planner import PlannerMode, VerificationBudget

    original = _review_deployment()
    _install(monkeypatch, "enforce", **original)
    item_id = _assess_write(client)["review_item_id"]
    _as_role(monkeypatch, "change-manager")
    assert client.post("/v1/execution/approve", json={"item_id": item_id}).status_code == 200
    request = {"item_id": item_id, "tool_call": WRITE_CALL}
    if async_dispatch:
        monkeypatch.setenv("REMORA_ASYNC_DISPATCH", "1")
        assert client.post("/v1/execution/execute", json=request).status_code in (200, 202)
    changed = dict(original)
    if change == "registry":
        tools = dict(original["registry"].tools)
        predicates = tools["store_artifact"]
        tools["store_artifact"] = (replace(predicates[0], max_age_s=20), *predicates[1:])
        changed["registry"] = replace(original["registry"], tools=tools)
    elif change == "monitor_profile":
        changed["monitor_profile"] = replace(fixture.PROFILE, profile_id="new-profile")
    elif change == "budget":
        changed["budget"] = VerificationBudget(max_resolver_calls=2)
    elif change == "planner":
        changed["planner_mode"] = PlannerMode.H_EDV
    if change == "off":
        monkeypatch.setattr(_mod(), "_ws1_gate", lambda: None)
    else:
        _install(monkeypatch, "shadow" if change == "shadow" else "enforce", **changed)
    if async_dispatch:
        results = _mod().dispatch_pending_intents("acme", worker_id="ws1-binding-test")
        assert "ws1_regate_refused" in json.dumps(results)
    else:
        r = client.post("/v1/execution/execute", json=request)
        assert (r.status_code, r.json().get("detail")) == (409, "ws1_regate_refused")
    assert not _events("execution_authorized")

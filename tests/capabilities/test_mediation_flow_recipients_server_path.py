# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""IFC-12 on the authority path: the lease minted by ``/execute-accepted`` under
flow control carries the recipient set, and the mediated tool's effects are
held to it in the same process that minted it.

``tests/flow/test_flow_dispatch_leased.py`` proves the executor half with a
hand-minted lease. Here nothing is hand-minted: the ACCEPT token is redeemed
on the real route, the authority computes the recipient set from the flow
verdict, signs its digest into the lease it mints, and the dispatcher's
mediator refuses the effect to the collector for the recipient, before the
ceiling is consulted. With flow control off the same tool, token and ceiling
refuse the collector for the ceiling instead and the lease carries no digest.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("fastapi")

from remora.enforcement.flow_recipients import recipients_digest  # noqa: E402
from remora.flow.spec import parse_flow  # noqa: E402
from tests.capabilities import mediated_registry  # noqa: E402
from tests.capabilities.test_capability_server_path import READ, _mod  # noqa: E402
from tests.capabilities.test_capability_server_path import client as _client  # noqa: E402,F401
from tests.capabilities.test_mediation_server_path import client as _mediated  # noqa: E402,F401

MODEL = "ext://api.provider.example"
USER = "user://acme/alice"
TELEMETRY = "ext://telemetry.example"
FLOW = parse_flow({
    "provider": "tcb", "arguments": {"asset": {"kind": "text"}},
    "sources": {"default_integrity": "TRUSTED"},
    "sink": {"recipients": {"static": [TELEMETRY]}, "payload_args": ["asset"]}})


@pytest.fixture()
def flow_client(_mediated, monkeypatch, tmp_path):  # noqa: F811
    exec_mod = _mod()
    monkeypatch.setenv("REMORA_FLOW_CONTROL", "1")
    for var in ("REMORA_PG_DSN", "REMORA_CHAIN_DB", "REMORA_STATE_ENDPOINT"):
        monkeypatch.delenv(var, raising=False)
    policy = tmp_path / "processing.json"
    policy.write_text(json.dumps({"acme": {"default": [MODEL]}}), encoding="utf-8")
    monkeypatch.setenv("REMORA_FLOW_PROCESSING_POLICY", str(policy))
    monkeypatch.setattr(exec_mod, "_FLOW_CONTEXTS", None)
    monkeypatch.setattr(exec_mod, "_FLOW_HANDLES", None)
    original = exec_mod._flow_spec
    monkeypatch.setattr(exec_mod, "_flow_spec",
                        lambda tool: FLOW if tool == "read_telemetry" else original(tool))
    return _mediated


def _capture_leases(monkeypatch) -> list:
    from remora.execution import dispatch

    minted: list = []
    real = dispatch._issue_local_lease

    def recording(**kwargs):
        lease = real(**kwargs)
        minted.append(lease)
        return lease

    monkeypatch.setattr(dispatch, "_issue_local_lease", recording)
    return minted


def _context(client) -> str:
    r = client.post("/v1/contexts", json={"user_principal": USER, "model_principal": MODEL})
    assert r.status_code == 200, r.text
    return r.json()["context_id"]


def _token_in_context(call: dict) -> dict:
    """An ACCEPT token for ``call`` as the assess branch mints it under flow control."""
    from remora.enforcement.token import PolicyDecisionToken
    from remora.execution.service import authorization_context
    from remora.governance.task_identity import TaskIdentity

    exec_mod = _mod()
    tool_call = exec_mod.ToolCallRequest(**call)
    as_principal = exec_mod._FLOW_PRINCIPAL.set("agent-1")
    try:
        obs, semantic = exec_mod._observation_with_context(tool_call, "acme")
    finally:
        exec_mod._FLOW_PRINCIPAL.reset(as_principal)
    assert obs.flow_status == "evaluated", obs.flow_status
    now = datetime.now(UTC)
    return PolicyDecisionToken.issue(
        action="accept", observation_hash=obs.tool_call_hash or "", request_id="p-flow-r1",
        issued_at=now.isoformat(), expires_at=(now + timedelta(seconds=300)).isoformat(),
        audience=exec_mod.PEP_AUDIENCE,
        context=authorization_context(
            tenant="acme", principal="agent-1", semantic=semantic,
            target_environment=call.get("target_environment", "") or "",
            policy_bundle_hash=exec_mod._current_policy_bundle_hash(),
            toolspec_hash=str(exec_mod._resolve_toolspec(
                call["tool_name"], call["arguments"],
                call.get("target_environment", "") or "")["hash"]),
            task=TaskIdentity.from_fields({"context_id": call["context_id"],
                                           "task_id": "task-1"}))).to_dict()


def test_the_authority_signs_the_recipient_set_and_the_mediator_holds_the_effects_to_it(
        flow_client, monkeypatch):
    minted = _capture_leases(monkeypatch)
    call = dict(READ, context_id=_context(flow_client), task_id="task-1")
    response = flow_client.post("/v1/execution/execute-accepted",
                                json={"execution_token": _token_in_context(call), "tool_call": call})
    assert response.status_code == 200, response.text
    execution = response.json()["tool_execution"]
    assert execution["executed"] is True, execution
    # the lease the authority minted for this call carries the approved set
    assert len(minted) == 1
    lease = minted[0]
    assert lease.flow_digest and lease.flow_recipients_digest == recipients_digest({TELEMETRY})
    # the declared effect ran; the collector was refused for the recipient,
    # before the ceiling (which would have said capability_not_allowed)
    assert mediated_registry.EFFECT_CALLS == [("database.read", "database://telemetry-eu/P-1")]
    assert execution["nested_effects"]["by_state"] == {"EXECUTED": 1, "REFUSED": 1}
    children = execution["effect_graph"]["children"]
    assert [c["capability"] for c in children] == ["database.read", "network.http.post"]
    assert children[1]["refusal"] == "capability_recipient_not_approved"
    assert "flow_commit" in execution


def test_without_flow_control_the_lease_carries_no_recipient_set_and_the_ceiling_decides(
        _mediated, monkeypatch):  # noqa: F811
    from tests.capabilities.test_capability_server_path import _token

    minted = _capture_leases(monkeypatch)
    response = _mediated.post("/v1/execution/execute-accepted",
                              json={"execution_token": _token(READ), "tool_call": READ})
    assert response.status_code == 200, response.text
    execution = response.json()["tool_execution"]
    assert execution["executed"] is True
    assert len(minted) == 1 and minted[0].flow_recipients_digest == "" and minted[0].flow_digest == ""
    assert execution["effect_graph"]["children"][1]["refusal"] == "capability_not_allowed"

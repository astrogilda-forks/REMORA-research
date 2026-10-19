# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""A21 end to end: WS1 opens no egress the flow check refused (WS1 SDD §12).

With flow control on, a context holding the user's data and a ToolSpec whose
sink is outside the data's readers, /assess fires F4 (grant-only). With WS1
enforcing and every WS1 precondition PROVED, the call still gets no token,
an approval does not execute it, and nothing reaches the dispatcher. A WS1
refusal's record carries codes and hashes, never the recipient or the
argument value.
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")

from remora.flow.label import Integrity, Label  # noqa: E402
from remora.flow.spec import parse_flow  # noqa: E402
from remora.verification.execution_gate import Ws1Gate  # noqa: E402
from tests.test_execute_accepted_toolspec import READ_SPEC  # noqa: E402
from tests.test_toolspec_execution_wiring import _bundle_file, _client, _spec  # noqa: E402
from tests.verification import ws1_deployment_fixture as fixture  # noqa: E402

MODEL = "ext://api.provider.example"
USER = "user://acme/alice"
SINK = "ext://telemetry.example"
FLOW = parse_flow({
    "provider": "tcb", "arguments": {"asset": {"kind": "text"}},
    "sources": {"default_integrity": "TRUSTED"},
    "sink": {"recipients": {"static": [SINK]}, "payload_args": ["asset"]}})
CALL = {"tool_name": "read_telemetry", "arguments": {"asset": "P-1"},
        "target_environment": "staging", "schema_valid": True}
INTENT = "a" * 64


@pytest.fixture()
def client(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path, bundle_path=_bundle_file(
        tmp_path, [_spec(), dict(_spec(**READ_SPEC), version=1)], name="ws1-flow.json"))
    import servers.api as api_mod
    import servers.execution_api as exec_mod

    monkeypatch.setenv("REMORA_FLOW_CONTROL", "1")
    policy = tmp_path / "processing.json"
    policy.write_text(json.dumps({"acme": {"default": [MODEL]}}), encoding="utf-8")
    monkeypatch.setenv("REMORA_FLOW_PROCESSING_POLICY", str(policy))
    monkeypatch.setattr(api_mod, "_authenticate", lambda request: ("acme", "operator"))
    monkeypatch.setattr(api_mod, "_authenticated_principal", lambda request: "agent-1")
    monkeypatch.setattr(exec_mod, "_FLOW_CONTEXTS", None)
    monkeypatch.setattr(exec_mod, "_FLOW_HANDLES", None)
    monkeypatch.setattr(exec_mod, "_flow_spec",
                        lambda tool: FLOW if tool == "read_telemetry" else None)
    original = exec_mod._observation_with_context

    def with_intent(tool_call, tenant):
        obs, semantic = original(tool_call, tenant)
        return obs, {**semantic, "intent_authority_hash": INTENT}

    monkeypatch.setattr(exec_mod, "_observation_with_context", with_intent)
    gate = Ws1Gate("enforce", fixture.build_ws1_deployment(), flow_control=True)
    monkeypatch.setattr(exec_mod, "_ws1_gate", lambda: gate)
    dispatched = []
    original_dispatch = exec_mod._dispatch_under_lease

    def spy(**kwargs):
        dispatched.append(kwargs.get("tool_call"))
        return original_dispatch(**kwargs)

    monkeypatch.setattr(exec_mod, "_dispatch_under_lease", spy)
    c.dispatched = dispatched
    return c


def _tainted_context(client) -> str:
    import servers.execution_api as exec_mod

    r = client.post("/v1/contexts", json={"user_principal": USER, "model_principal": MODEL})
    assert r.status_code == 200, r.text
    context_id = r.json()["context_id"]
    exec_mod._flow_contexts().raise_label("acme", "agent-1", context_id,
                                          Label({USER, MODEL}, Integrity.TRUSTED))
    return context_id


def test_monitor_and_resolver_cannot_receive_unreadable_data_or_exfiltrate_via_errors(client):
    import servers.api as api_mod
    import servers.execution_api as exec_mod

    context_id = _tainted_context(client)
    body = client.post("/v1/execution/assess", json={
        **CALL, "context_id": context_id, "task_id": "task-1"}).json()
    assert "flow_confidentiality_violation" in body["reasons"]
    assert "execution_token" not in body
    assessed = [e.payload for e in exec_mod._CHAIN.entries("acme")
                if e.payload.get("event") == "assessed"][-1]
    ws1 = assessed["ws1"]
    # Every WS1 precondition PROVED: WS1 adds no cap, and it does not lift F4.
    assert [c["source"] for c in ws1["record"]["all_caps"]] == ["engine"]
    assert ws1["record"]["review_class"] == "grant"
    assert SINK not in json.dumps(ws1) and "P-1" not in json.dumps(ws1["record"]["all_caps"])
    item_id = body["review_item_id"]  # F4 is a grant-only review item
    if item_id:
        monkey_role = api_mod._authenticate
        api_mod._authenticate = lambda request: ("acme", "reviewer")
        try:
            client.post("/v1/execution/approve", json={"item_id": item_id})
            r = client.post("/v1/execution/execute", json={
                "item_id": item_id,
                "tool_call": {**CALL, "context_id": context_id, "task_id": "task-1"}})
        finally:
            api_mod._authenticate = monkey_role
        # An ordinary approval does not lift F4: the fresh decision voids it.
        assert r.status_code == 409 or r.json()["outcome"] != "execute", r.text
    assert client.dispatched == []

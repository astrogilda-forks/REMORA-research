# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Flow control at dispatch and the label commit (SDD v2 WP-04, review finding 2).

Through ``/v1/execution/execute-accepted`` and the real governed dispatcher.
The flow decision is checked again right before the tool runs, and an
executed call's result is labelled and committed before any of it is
returned. What these tests pin:

* a clean call executes and reports the commit (raw digest, new epoch);
* a label raised after the decision refuses before the dispatcher runs;
* a commit that fails withholds the result, and the call counts as executed;
* a label raised while the tool runs withholds the result as well;
* the review path and the async worker check flow as the proposer;
* with flow control off nothing changes.

* a flow violation at ACCEPT redemption refuses before the grant is spent.

The execution domain's check (/dispatch-leased) is in
tests/flow/test_flow_dispatch_leased.py.
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")

from remora.flow.label import Integrity, Label  # noqa: E402
from remora.flow.spec import parse_flow  # noqa: E402
from tests.test_execute_accepted_toolspec import CALL, PRINCIPAL, _specs  # noqa: E402
from tests.test_toolspec_execution_wiring import _bundle_file, _client  # noqa: E402

MODEL = "ext://api.provider.example"
USER = "user://acme/alice"
FLOW = parse_flow({
    "provider": "tcb", "arguments": {"asset": {"kind": "text"}},
    "sources": {"default_integrity": "TRUSTED"},
    "sink": {"recipients": {"static": ["ext://telemetry.example"]}, "payload_args": ["asset"]}})


def _mod():
    import servers.execution_api as exec_mod

    return exec_mod


@pytest.fixture()
def client(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path, bundle_path=_bundle_file(
        tmp_path, _specs(), name="flow-dispatch-bundle.json"))
    monkeypatch.setenv("REMORA_FLOW_CONTROL", "1")
    for var in ("REMORA_PG_DSN", "REMORA_CHAIN_DB", "REMORA_STATE_ENDPOINT"):
        monkeypatch.delenv(var, raising=False)
    policy = tmp_path / "processing.json"
    policy.write_text(json.dumps({"acme": {"default": [MODEL]}}), encoding="utf-8")
    monkeypatch.setenv("REMORA_FLOW_PROCESSING_POLICY", str(policy))
    exec_mod = _mod()
    monkeypatch.setattr(exec_mod, "_FLOW_CONTEXTS", None)
    monkeypatch.setattr(exec_mod, "_FLOW_HANDLES", None)
    original = exec_mod._flow_spec
    monkeypatch.setattr(exec_mod, "_flow_spec",
                        lambda tool: FLOW if tool == "read_telemetry" else original(tool))
    return c


def _context(client) -> str:
    r = client.post("/v1/contexts", json={"user_principal": USER, "model_principal": MODEL})
    assert r.status_code == 200, r.text
    return r.json()["context_id"]


def _mint(context_id: str, *, proposal_id: str = "p-flow-1") -> tuple[dict, dict]:
    """An ACCEPT token for a call in ``context_id``, as the assess branch mints it."""
    from datetime import UTC, datetime, timedelta

    from remora.enforcement.token import PolicyDecisionToken
    from remora.execution.service import authorization_context
    from remora.governance.task_identity import TaskIdentity

    exec_mod = _mod()
    call = dict(CALL, context_id=context_id, task_id="task-1")
    tool_call = exec_mod.ToolCallRequest(**call)
    as_principal = exec_mod._FLOW_PRINCIPAL.set(PRINCIPAL)  # what _auth sets in a request
    try:
        obs, semantic = exec_mod._observation_with_context(tool_call, "acme")
    finally:
        exec_mod._FLOW_PRINCIPAL.reset(as_principal)
    assert obs.flow_status == "evaluated"
    identity = exec_mod._resolve_toolspec(
        tool_call.tool_name, tool_call.arguments, tool_call.target_environment)
    exec_mod._CHAIN.append("acme", {"event": "assessed", "proposal_id": proposal_id,
                                    "actor": PRINCIPAL, "decision": "accept",
                                    "toolspec_hash": identity["hash"]})
    now = datetime.now(UTC)
    token = PolicyDecisionToken.issue(
        action="accept", observation_hash=obs.tool_call_hash or "", request_id=proposal_id,
        issued_at=now.isoformat(), expires_at=(now + timedelta(seconds=300)).isoformat(),
        audience=exec_mod.PEP_AUDIENCE,
        context=authorization_context(
            tenant="acme", principal=PRINCIPAL, semantic=semantic,
            target_environment=tool_call.target_environment or "",
            policy_bundle_hash=exec_mod._current_policy_bundle_hash(),
            toolspec_hash=str(identity["hash"]),
            task=TaskIdentity.from_fields({"context_id": context_id, "task_id": "task-1"})))
    return token.to_dict(), call


def _redeem(client, token, call):
    r = client.post("/v1/execution/execute-accepted",
                    json={"execution_token": token, "tool_call": call})
    assert r.status_code == 200, r.text
    return r.json()["tool_execution"]


def test_a_clean_call_executes_and_commits_before_returning(client):
    context_id = _context(client)
    before = _mod()._flow_contexts().load("acme", PRINCIPAL, context_id).epoch
    execution = _redeem(client, *_mint(context_id))
    assert execution["executed"] is True and "result" in execution
    commit = execution["flow_commit"]
    assert len(commit["raw_result_sha256"]) == 64 and commit["epoch"] >= before


def test_a_label_raised_after_the_decision_refuses_before_the_tool_runs(client, monkeypatch):
    """The re-gate at redemption saw the old label; a raise between it and
    dispatch is caught by the dispatch-time check, and the tool never runs."""
    exec_mod = _mod()
    context_id = _context(client)
    original = exec_mod._flow_at_dispatch

    def raised_first(tenant, tool_call, expected, proposal_id):
        exec_mod._flow_contexts().raise_label("acme", PRINCIPAL, context_id,
                                              Label({USER, MODEL}, Integrity.TRUSTED))
        return original(tenant, tool_call, expected, proposal_id)

    ran = []
    real = exec_mod._local_dispatcher
    monkeypatch.setattr(exec_mod, "_flow_at_dispatch", raised_first)
    monkeypatch.setattr(exec_mod, "_local_dispatcher",
                        lambda lease: ran.append(1) or real(lease))
    execution = _redeem(client, *_mint(context_id))
    assert execution == {"executed": False, "refusal_reason": "flow_epoch_changed",
                         "proposal_id": execution["proposal_id"]}
    assert ran == []


def test_a_failed_commit_withholds_the_result(client, monkeypatch):
    """The effect happened, so the call is executed; nothing of the result is
    returned, and the store's error text reaches neither response nor chain."""
    exec_mod = _mod()
    context_id = _context(client)
    token, call = _mint(context_id)
    store = exec_mod._flow_contexts()

    def down(*args, **kwargs):
        raise RuntimeError("store down while holding telemetry-for-P-1")

    monkeypatch.setattr(store, "raise_label", down)
    execution = _redeem(client, token, call)
    assert execution["executed"] is True
    assert execution["result_withheld"] == "flow_result_commit_failed"
    assert "result" not in execution and "result_envelope" not in execution
    chain = json.dumps([e.payload for e in exec_mod._CHAIN.entries("acme")])
    assert "telemetry-for-P-1" not in json.dumps(execution) + chain


def test_with_flow_control_off_nothing_changes(client, monkeypatch):
    minted = _mint(_context(client))
    monkeypatch.delenv("REMORA_FLOW_CONTROL")
    execution = _redeem(client, *minted)
    assert execution["executed"] is True and "result" in execution
    assert "flow_commit" not in execution


def test_a_forwarded_preview_is_not_committed_as_the_result(monkeypatch):
    """Custody split: the authority domain receives a preview. Labels need the
    whole result, so a truncated preview is withheld."""
    from datetime import UTC, datetime

    import remora.execution.dispatch as dispatch

    monkeypatch.setattr(dispatch, "execution_endpoint", lambda: "https://exec.example")
    monkeypatch.setattr(dispatch, "_issue_local_lease", lambda **kw: object())
    committed = []

    def commit(raw):
        committed.append(raw)
        return raw, {}

    for truncated, expect in ((True, None), (False, {"a": 1})):
        monkeypatch.setattr(dispatch, "remote_dispatch", lambda **kw: {
            "executed": True, "result": {"a": 1},
            "result_envelope": {"truncated": truncated}})
        out = dispatch.dispatch_under_lease(
            tenant="acme", principal=PRINCIPAL,
            tool_call=_mod().ToolCallRequest(**CALL), semantic={}, now=datetime.now(UTC),
            dispatcher=None, policy_bundle_hash="b" * 64, result_commit=commit)
        assert out["executed"] is True and out.get("result") == expect
        if truncated:
            assert out["result_withheld"] == "flow_result_truncated" and committed == []
    assert committed == [{"a": 1}]


def test_a_label_raised_during_dispatch_withholds_the_result(client, monkeypatch):
    """The race the dispatch check cannot see: another call in the same
    context raises the label while this one runs. The commit finds a new
    epoch, so the effect counts and its result is not released."""
    exec_mod = _mod()
    context_id = _context(client)
    real = exec_mod._local_dispatcher

    class Racing:
        def __init__(self, inner):
            self.inner = inner

        def dispatch(self, *args, **kwargs):
            exec_mod._flow_contexts().raise_label("acme", PRINCIPAL, context_id,
                                                  Label({USER, MODEL}, Integrity.TRUSTED))
            return self.inner.dispatch(*args, **kwargs)

    monkeypatch.setattr(exec_mod, "_local_dispatcher", lambda lease: Racing(real(lease)))
    execution = _redeem(client, *_mint(context_id))
    assert execution["executed"] is True
    assert execution["result_withheld"] == "flow_epoch_changed_during_dispatch"
    assert "result" not in execution


STORE_FLOW = parse_flow({
    "provider": "tcb", "arguments": {"artifact_id": {"kind": "text"}, "content": {"kind": "text"}},
    "sources": {"default_integrity": "TRUSTED"},
    "sink": {"recipients": {"static": ["ext://artifact-store.example"]},
             "payload_args": ["content"]}})


def _reviewed(client, monkeypatch):
    """A write in a flow context, assessed into review by the proposer and
    approved by another principal. Returns the item and the call."""
    import servers.api as api_mod
    from tests.test_toolspec_execution_wiring import CALL as WRITE_CALL

    monkeypatch.setattr(_mod(), "_flow_spec",
                        lambda tool: {"read_telemetry": FLOW, "store_artifact": STORE_FLOW}.get(tool))
    call = dict(WRITE_CALL, context_id=_context(client), task_id="task-1")
    item = client.post("/v1/execution/assess", json=call).json()["review_item_id"]
    monkeypatch.setattr(api_mod, "_authenticated_principal", lambda request: "reviewer-2")
    assert client.post("/v1/execution/approve", json={"item_id": item}).status_code == 200
    monkeypatch.setattr(api_mod, "_authenticated_principal", lambda request: PRINCIPAL)
    return item, call


def test_the_review_path_checks_flow_and_commits_labels(client, monkeypatch):
    item, call = _reviewed(client, monkeypatch)
    r = client.post("/v1/execution/execute", json={"item_id": item, "tool_call": call})
    assert r.status_code == 200, r.text
    execution = r.json()["tool_execution"]
    assert execution["executed"] is True and "flow_commit" in execution


def test_the_async_worker_checks_flow_as_the_proposer(client, monkeypatch):
    """The worker has no authenticated principal. It reads the proposer's
    flow context, so the dispatch-time check and the label commit run."""
    item, call = _reviewed(client, monkeypatch)
    monkeypatch.setenv("REMORA_ASYNC_DISPATCH", "1")
    r = client.post("/v1/execution/execute", json={"item_id": item, "tool_call": call})
    assert r.status_code == 202, r.text
    [out] = _mod().dispatch_pending_intents("acme", worker_id="w1")
    execution = out["tool_execution"]
    assert execution["executed"] is True and "flow_commit" in execution


def test_a_flow_violation_at_redemption_refuses_before_the_grant_is_spent(client):
    """The ACCEPT path does not re-decide, so a label raised after the token
    was issued is checked before consumption: the refusal leaves the grant
    unspent and no authorization record."""
    exec_mod = _mod()
    context_id = _context(client)
    token, call = _mint(context_id)
    exec_mod._flow_contexts().raise_label("acme", PRINCIPAL, context_id,
                                          Label({USER, MODEL}, Integrity.TRUSTED))
    for _ in range(2):  # the same answer twice: nothing was consumed
        r = client.post("/v1/execution/execute-accepted",
                        json={"execution_token": token, "tool_call": call})
        assert (r.status_code, r.json()["detail"]) == (409, "flow_confidentiality_violation")
    events = [e.payload["event"] for e in exec_mod._CHAIN.entries("acme")]
    assert "execution_flow_refused" in events and "execution_authorized" not in events

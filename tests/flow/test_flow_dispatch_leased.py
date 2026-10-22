# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Flow control in the execution domain: /v1/execution/dispatch-leased.

With REMORA_FLOW_CONTROL=1 the executing process reads the call's flow
context from its own store, as the lease's actor, refuses unless the verdict
is clean, and commits the result's labels before returning it. A domain that
does not share the authority's flow store sees an unknown context and
refuses. The lease's nonce is untouched by a flow refusal.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")

from remora.execution.dispatch import issue_execution_lease  # noqa: E402
from remora.flow.label import Integrity, Label  # noqa: E402
from remora.flow.spec import parse_flow  # noqa: E402
from remora.governance.task_identity import TaskIdentity  # noqa: E402
from tests.test_dispatch_leased_endpoint import CALL, SEMANTIC, _post  # noqa: E402
from tests.test_dispatch_leased_endpoint import executor as _executor  # noqa: E402,F401

MODEL = "ext://api.provider.example"
USER = "user://acme/alice"
WO_FLOW = parse_flow({
    "provider": "tcb",
    "arguments": {"work_order_id": {"kind": "text"}, "status": {"kind": "text"}},
    "sources": {"default_integrity": "TRUSTED"},
    "sink": {"recipients": {"static": ["ext://work-orders.example"]},
             "payload_args": ["status"]}})


@pytest.fixture()
def executor(_executor, monkeypatch, tmp_path):  # noqa: F811
    import servers.execution_api as exec_mod

    monkeypatch.setenv("REMORA_FLOW_CONTROL", "1")
    for var in ("REMORA_PG_DSN", "REMORA_CHAIN_DB", "REMORA_STATE_ENDPOINT"):
        monkeypatch.delenv(var, raising=False)
    policy = tmp_path / "processing.json"
    policy.write_text(json.dumps({"acme": {"default": [MODEL]}}), encoding="utf-8")
    monkeypatch.setenv("REMORA_FLOW_PROCESSING_POLICY", str(policy))
    monkeypatch.setattr(exec_mod, "_FLOW_CONTEXTS", None)
    monkeypatch.setattr(exec_mod, "_FLOW_HANDLES", None)
    monkeypatch.setattr(exec_mod, "_flow_spec",
                        lambda tool: WO_FLOW if tool == CALL["tool_name"] else None)
    return _executor


def _context(executor) -> str:
    r = executor.client.post("/v1/contexts",
                             json={"user_principal": USER, "model_principal": MODEL})
    assert r.status_code == 200, r.text
    return r.json()["context_id"]


def _lease(executor, call):
    return issue_execution_lease(
        tenant="acme", principal="employee-1", tool_call=SimpleNamespace(**call),
        semantic=SEMANTIC, now=datetime.now(UTC), policy_bundle_hash=executor.bundle,
        task_identity=TaskIdentity.from_fields(
            {"context_id": call["context_id"], "task_id": "task-1"}))


def _call(context_id):
    return dict(CALL, context_id=context_id, task_id="task-1")


def test_a_clean_flow_executes_and_commits_labels(executor):
    call = _call(_context(executor))
    body = _post(executor, _lease(executor, call), call=call).json()
    assert body["tool_execution"]["executed"] is True, body
    assert "flow_commit" in body["tool_execution"]


def test_an_unknown_context_refuses_before_the_tool_runs(executor):
    call = _call("ctx_" + "a" * 26)
    body = _post(executor, _lease(executor, call), call=call).json()
    assert body["tool_execution"]["refusal_reason"] == "flow_context_unknown"
    assert executor.registry.CALLS == []


def test_a_flow_violation_refuses_and_leaves_the_lease_unspent(executor):
    import servers.execution_api as exec_mod

    context_id = _context(executor)
    call = _call(context_id)
    lease = _lease(executor, call)
    exec_mod._flow_contexts().raise_label("acme", "employee-1", context_id,
                                          Label({USER, MODEL}, Integrity.TRUSTED))
    body = _post(executor, lease, call=call).json()
    assert body["tool_execution"]["refusal_reason"] == "flow_confidentiality_violation"
    assert executor.registry.CALLS == []


# ── IFC-06: the tool receives the values the flow check judged ─────────────
#
# An external review of 265abfbe (2026-10-21) found that the dispatch-time
# flow check resolved handles and then discarded the result, so the tool
# received the opaque handle token. The lease still binds the handle form
# the approver saw; the tool now gets the resolved values.

def _handle(executor, context_id: str, value, *, type_tag: str = "text") -> str:
    import time

    import servers.execution_api as exec_mod
    from remora.flow.handles import HandleRecord, handle_token, new_handle_id

    state = exec_mod._flow_contexts().load("acme", "employee-1", context_id)
    hid = new_handle_id()
    exec_mod._flow_handles().put_all([HandleRecord(
        handle_id=hid, tenant_id="acme", context_id=context_id, value=value,
        label=state.label, type_tag=type_tag, created_by_proposal="p-src",
        expires_at=time.time() + 600)])
    return handle_token(hid)


def _call_with(context_id: str, status) -> dict:
    return dict(_call(context_id),
                arguments={"work_order_id": "WO-1", "status": status})


@pytest.mark.parametrize("form", ["whole", "reference", "embedded"])
def test_the_tool_receives_the_resolved_handle_value(executor, form):
    context_id = _context(executor)
    token = _handle(executor, context_id, "closed")
    status = {"whole": token,
              "reference": {"$handle": token, "$type": "text"},
              "embedded": f"now {token}"}[form]
    call = _call_with(context_id, status)
    body = _post(executor, _lease(executor, call), call=call).json()
    assert body["tool_execution"]["executed"] is True, body
    assert executor.registry.CALLS == [
        {"work_order_id": "WO-1",
         "status": "now closed" if form == "embedded" else "closed"}]


def test_an_unknown_handle_refuses_before_the_tool_runs(executor):
    from remora.flow.handles import handle_token, new_handle_id

    context_id = _context(executor)
    call = _call_with(context_id, handle_token(new_handle_id()))
    body = _post(executor, _lease(executor, call), call=call).json()
    assert body["tool_execution"]["refusal_reason"] == "flow_handle_invalid"
    assert executor.registry.CALLS == []


def test_the_lease_still_binds_the_handle_form(executor):
    """A lease for the resolved value is not a lease for the handle."""
    context_id = _context(executor)
    token = _handle(executor, context_id, "closed")
    lease = _lease(executor, _call_with(context_id, "closed"))
    body = _post(executor, lease, call=_call_with(context_id, token)).json()
    assert body["tool_execution"]["executed"] is False
    assert executor.registry.CALLS == []

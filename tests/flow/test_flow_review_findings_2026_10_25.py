# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Findings of the external review of 2026-10-25, reproduced and fixed.

F-01  a delegate redeeming an ACCEPT token under flow control read its own
      flow context instead of the proposer's and was refused as
      flow_context_unknown;
F-03  under the custody split the authority committed a result the execution
      domain had already committed, and withheld it when that first commit
      had raised the label;
F-04  /dispatch-leased under flow control took the context's dispatch fence
      (a write to its event stream) before the lease's signature was checked.

F-02 and F-05 are in tests/capabilities/test_flow_recipients.py.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

pytest.importorskip("fastapi")

from remora.flow.spec import parse_flow  # noqa: E402
from tests.test_delegated_execution_and_approval_policy import (  # noqa: E402,F401
    READ,
    SERVICE,
    _assess,
    _delegated,
    _redeem,
    accept_world,
    world,
)
from tests.flow.test_flow_dispatch_leased import executor  # noqa: E402,F401
from tests.test_dispatch_leased_endpoint import executor as _executor  # noqa: E402,F401
from tests.test_review_path_binding import AGENT, TENANT  # noqa: E402

MODEL = "ext://api.provider.example"
USER = "user://acme/alice"
READ_FLOW = parse_flow({
    "provider": "tcb", "arguments": {"record_id": {"kind": "text"}},
    "sources": {"default_integrity": "TRUSTED", "fields": [
        {"path": "$", "return_mode": "BY_VALUE", "type": "object",
         "readers": {"static": [USER, MODEL]}},
        {"path": "$.value", "return_mode": "BY_VALUE", "type": "string",
         "readers": {"static": [USER, MODEL]}}]},
    "sink": {"recipients": "none"}})


@pytest.fixture()
def flow_world(accept_world, tmp_path):  # noqa: F811
    deployment = accept_world
    deployment.mp.setenv("REMORA_FLOW_CONTROL", "1")
    for var in ("REMORA_PG_DSN", "REMORA_CHAIN_DB", "REMORA_STATE_ENDPOINT"):
        deployment.mp.delenv(var, raising=False)
    policy = tmp_path / "processing.json"
    policy.write_text(json.dumps({TENANT: {"default": [MODEL]}}), encoding="utf-8")
    deployment.mp.setenv("REMORA_FLOW_PROCESSING_POLICY", str(policy))
    deployment.mp.setattr(deployment.exec, "_FLOW_CONTEXTS", None)
    deployment.mp.setattr(deployment.exec, "_FLOW_HANDLES", None)
    original = deployment.exec._flow_spec
    deployment.mp.setattr(deployment.exec, "_flow_spec",
                     lambda tool: READ_FLOW if tool == "read_record" else original(tool))
    return deployment


def _context_of(w, principal: str = AGENT) -> str:
    with w.acting_as(principal=principal):
        r = w.client.post("/v1/contexts",
                              json={"user_principal": USER, "model_principal": MODEL})
    assert r.status_code == 200, r.text
    return r.json()["context_id"]


def _token(w, call: dict[str, Any]) -> dict[str, Any]:
    r = _assess(w, call)
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == "accept", r.json()
    return dict(r.json()["execution_token"])


def test_f01_a_named_delegate_redeems_in_the_proposers_flow_context(flow_world):
    call = _delegated({**READ, "context_id": _context_of(flow_world), "task_id": "task-1"})
    r = _redeem(flow_world, _token(flow_world, call), call, principal=SERVICE)
    assert r.status_code == 200, r.text
    assert r.ran
    assert "flow_commit" in r.json()["tool_execution"]


def test_f01_the_proposer_still_redeems_in_its_own_context(flow_world):
    call = {**READ, "context_id": _context_of(flow_world), "task_id": "task-1"}
    r = _redeem(flow_world, _token(flow_world, call), call, principal=AGENT)
    assert r.status_code == 200, r.text
    assert r.ran


def test_f01_an_actor_the_proposal_did_not_name_gets_no_proposer_context(flow_world):
    """The proposer's context is used only for the delegate the assessed
    record names. Another actor reads its own context, does not find the
    proposer's, and nothing runs."""
    from tests.test_delegated_execution_and_approval_policy import OTHER_SERVICE

    call = _delegated({**READ, "context_id": _context_of(flow_world), "task_id": "task-1"})
    token = _token(flow_world, call)
    r = _redeem(flow_world, token, call, principal=OTHER_SERVICE)
    assert not r.ran
    assert r.status_code == 409, r.text


def test_f03_the_authority_does_not_commit_what_the_execution_domain_committed(monkeypatch):
    from types import SimpleNamespace

    from remora.execution import dispatch

    committed: list[Any] = []

    def result_commit(raw):
        committed.append(raw)
        return raw, {"epoch": 2}

    monkeypatch.setattr(dispatch, "execution_endpoint", lambda: "https://exec.internal")
    monkeypatch.setattr(dispatch, "_issue_local_lease", lambda **kw: SimpleNamespace(
        proposal_id="p-1", grant_jti="g", to_dict=lambda: {}))
    answers = {
        "committed": {"executed": True, "result": "rendered", "flow_commit": {"epoch": 2}},
        "withheld": {"executed": True, "result_withheld": "flow_epoch_changed_during_dispatch"},
    }
    for name, answer in answers.items():
        monkeypatch.setattr(dispatch, "remote_dispatch", lambda answer=answer, **kw: dict(answer))
        out = dispatch.dispatch_under_lease(
            tenant="acme", principal="agent-1",
            tool_call=SimpleNamespace(tool_name="t", arguments={}, target_environment="prod"),
            semantic={"tool_contract_bundle_hash": "", "intent_authority_hash": ""},
            now=__import__("datetime").datetime.now(__import__("datetime").UTC),
            dispatcher=None, policy_bundle_hash="b", result_commit=result_commit)
        assert out == answers[name], (name, out)
    assert committed == []


def test_f04_an_unauthentic_lease_writes_nothing_to_the_flow_stream(executor):  # noqa: F811
    """A lease whose signature does not verify is refused on /dispatch-leased
    before the flow check takes the fence: the context's sequence does not
    move, and the authentic lease still runs."""
    import servers.execution_api as exec_mod
    from remora.enforcement.lease import ExecutionLease
    from tests.flow.test_flow_dispatch_leased import _call, _context, _lease
    from tests.test_dispatch_leased_endpoint import _post

    context_id = _context(executor)
    call = _call(context_id)
    lease = _lease(executor, call)
    forged = ExecutionLease.from_dict({**lease.to_dict(), "signature": "0" * 128})
    before = exec_mod._flow_contexts().load("acme", "employee-1", context_id).seq
    body = _post(executor, forged, call=call).json()["tool_execution"]
    assert body["executed"] is False
    assert body["refusal_reason"] == "signature_invalid", body
    assert exec_mod._flow_contexts().load("acme", "employee-1", context_id).seq == before
    assert executor.registry.CALLS == []
    # the authentic lease still runs
    assert _post(executor, lease, call=call).json()["tool_execution"]["executed"] is True

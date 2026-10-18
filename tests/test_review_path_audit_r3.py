# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Review-path findings from external audit R3 (run against b64e3cc1).

Each was reproduced on this branch before it was fixed:

- RMR-AUD-002, ``escalate_regate_deadlock``: an approved ESCALATE re-decided
  on the same observation is ESCALATE again, and the re-gate treated every
  fresh ESCALATE as "not executable", so an approved escalation could never
  execute. An approved ESCALATE now survives a fresh ACCEPT, VERIFY or
  ESCALATE whose reasons are a subset of the reasons the reviewer approved. A
  new reason, or a fresh ABSTAIN, still voids it.
- RMR-AUD-001 (binding part), ``abstain_to_escalate_laundering``: the
  request-side fields outside ``canonical_tool_call_hash`` (``schema_valid``,
  ``rollback_available``, ``untrusted_context``, ``intent_ref``,
  ``derivations`` and the rest of the proposal outside the payload hash) could
  differ between assess and execute. A call assessed as ESCALATE could be approved and then executed as
  a VERIFY by dropping the downgrade and adding a different one. The assessed
  record now carries a hash over those fields (the idempotency key excepted),
  and ``/execute`` refuses a different proposal with 409
  ``binding_refused`` before the queue is touched.
- RMR-AUD-006 part 3, ``intent_ref_swap_on_review``: the review path did not
  bind ``intent_authority_hash``, so an item approved under one intent executed
  under another. It is now part of the context compared with the assessed
  record, as the ACCEPT token compares it.
"""
from __future__ import annotations

import json
import types
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest

pytest.importorskip("fastapi")

from tests.test_delegated_execution_and_approval_policy import (  # noqa: E402
    _refusals,
)
from tests.test_review_path_binding import (  # noqa: E402
    METADATA,
    TENANT,
    WRITE,
    Deployment,
    _approved,
    _chain_events,
    _obs,
)


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> Iterator[Deployment]:
    from remora.toolcall.deployment_registry import reset_deployment_tool_metadata

    deployment = Deployment(monkeypatch, tmp_path)
    yield deployment
    monkeypatch.undo()
    reset_deployment_tool_metadata()
    deployment.reset_runtime()


def _declare_tool(world: Deployment, *, tier: str, action_type: str) -> None:
    from remora.toolcall.deployment_registry import reset_deployment_tool_metadata

    metadata = json.loads(json.dumps(METADATA))
    metadata["update_record"].update(risk_tier=tier, action_type=action_type)
    path = world.tmp / f"metadata-{tier}-{action_type}.json"
    path.write_text(json.dumps({"version": 1, "tools": metadata}), encoding="utf-8")
    world.mp.setenv("REMORA_TOOL_METADATA_FILE", str(path))
    reset_deployment_tool_metadata()
    world.reset_runtime()


def _propose(world: Deployment, call: dict[str, Any], decision: str) -> str:
    r = world.client.post("/v1/execution/assess", json=call)
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == decision, r.json()
    return str(r.json()["review_item_id"])


def _status(world: Deployment, item_id: str) -> str:
    return world.exec._QUEUES[TENANT].item(item_id).status.value


# ── RMR-AUD-002: escalate_regate_deadlock ──────────────────────────────────

DELETE_PROD = {**WRITE, "target_environment": "prod"}


def test_escalate_regate_deadlock_an_approved_escalation_executes(
        world: Deployment) -> None:
    _declare_tool(world, tier="critical", action_type="delete")
    item_id = _propose(world, DELETE_PROD, "escalate")
    approved = world.approve(item_id, role="senior_authority", principal="senior-1")
    assert approved.status_code == 200, approved.text
    r = world.execute(item_id, DELETE_PROD)
    assert r.status_code == 200, r.text
    assert r.json()["outcome"] == "execute", r.json()
    assert r.ran


def test_escalate_regate_deadlock_the_approval_records_its_reasons(
        world: Deployment) -> None:
    _declare_tool(world, tier="critical", action_type="delete")
    item_id = _propose(world, DELETE_PROD, "escalate")
    world.approve(item_id, role="senior_authority", principal="senior-1")
    approval = world.exec._QUEUES[TENANT].item(item_id).approval
    assessed = next(e for e in _chain_events(world) if e.get("event") == "assessed")
    assert approval.approved_reasons == tuple(sorted(assessed["reasons"]))


class _Engine:
    """Re-decides whatever the test sets, so only the survival rule decides."""

    def __init__(self) -> None:
        from remora.policy.report import DecisionAction

        self.action = DecisionAction.ESCALATE
        self.reasons: tuple[Any, ...] = ()

    def decide(self, observation: Any) -> Any:
        return types.SimpleNamespace(action=self.action, reasons=self.reasons)


def _reason(value: str) -> Any:
    return types.SimpleNamespace(value=value)


def _escalated(engine: _Engine, reasons: tuple[str, ...]) -> tuple[Any, Any]:
    from remora.governance.review_queue import ReviewQueue
    from remora.policy.report import DecisionAction

    queue = ReviewQueue(engine=engine)  # type: ignore[arg-type]
    item = queue.enqueue(_obs("critical"), DecisionAction.ESCALATE, reasons=reasons)
    queue.approve(item.item_id, "senior-1", timedelta(minutes=5))
    return queue, item


@pytest.mark.parametrize("fresh", [(), ("evidence_insufficient",),
                                   ("evidence_insufficient", "schema_unverified_verify")])
def test_an_approved_escalation_survives_the_same_or_fewer_reasons(
        fresh: tuple[str, ...]) -> None:
    from remora.governance.review_queue import ExecutionDecision

    engine = _Engine()
    queue, item = _escalated(engine, ("evidence_insufficient", "schema_unverified_verify"))
    engine.reasons = tuple(_reason(r) for r in fresh)
    assert queue.execute(item.item_id, _obs("critical")).decision is ExecutionDecision.EXECUTE


def test_a_new_escalation_reason_invalidates_the_approval() -> None:
    from remora.governance.review_queue import ExecutionDecision

    engine = _Engine()
    queue, item = _escalated(engine, ("evidence_insufficient",))
    engine.reasons = (_reason("evidence_insufficient"), _reason("malformed_call_blocked"))
    outcome = queue.execute(item.item_id, _obs("critical"))
    assert outcome.decision is ExecutionDecision.APPROVAL_INVALIDATED


@pytest.mark.parametrize("action", ["verify", "accept"])
def test_a_lower_action_with_a_new_reason_invalidates_an_approved_escalation(
        action: str) -> None:
    """The subset rule holds for every executable fresh action."""
    from remora.governance.review_queue import ExecutionDecision
    from remora.policy.report import DecisionAction

    engine = _Engine()
    queue, item = _escalated(engine, ("malformed_call_blocked",))
    engine.action = DecisionAction(action)
    engine.reasons = (_reason("tainted_argument_verify"),)
    outcome = queue.execute(item.item_id, _obs("critical"))
    assert outcome.decision is ExecutionDecision.APPROVAL_INVALIDATED


def test_a_fresh_abstain_still_invalidates_an_approved_escalation() -> None:
    from remora.governance.review_queue import ExecutionDecision
    from remora.policy.report import DecisionAction

    engine = _Engine()
    queue, item = _escalated(engine, ("evidence_insufficient",))
    engine.action = DecisionAction.ABSTAIN
    engine.reasons = ()
    outcome = queue.execute(item.item_id, _obs("critical"))
    assert outcome.decision is ExecutionDecision.APPROVAL_INVALIDATED


def test_an_escalation_without_recorded_reasons_keeps_the_old_rule() -> None:
    """Enqueued without reasons (library use): a fresh ESCALATE never executes."""
    from remora.governance.review_queue import ExecutionDecision, ReviewQueue
    from remora.policy.report import DecisionAction

    engine = _Engine()
    queue = ReviewQueue(engine=engine)  # type: ignore[arg-type]
    item = queue.enqueue(_obs("critical"), DecisionAction.ESCALATE)
    queue.approve(item.item_id, "senior-1", timedelta(minutes=5))
    outcome = queue.execute(item.item_id, _obs("critical"))
    assert outcome.decision is ExecutionDecision.APPROVAL_INVALIDATED


def test_the_dispatch_regate_applies_the_same_rule() -> None:
    from remora.governance.review_queue import ExecutionDecision

    engine = _Engine()
    queue, item = _escalated(engine, ("evidence_insufficient",))
    engine.reasons = (_reason("evidence_insufficient"),)
    assert queue.execute(item.item_id, _obs("critical")).decision is ExecutionDecision.EXECUTE
    assert queue.regate_authorized(
        item.item_id, _obs("critical")).decision is ExecutionDecision.EXECUTE
    engine.reasons = (_reason("malformed_call_blocked"),)
    assert queue.regate_authorized(
        item.item_id, _obs("critical")).decision is ExecutionDecision.APPROVAL_INVALIDATED


def test_approved_reasons_round_trip_through_the_durable_encoding() -> None:
    from remora.governance.review_queue import PendingReview
    from remora.persistence.execution_state import from_dict, to_dict

    queue, item = _escalated(_Engine(), ("evidence_insufficient",))
    restored = from_dict(to_dict(queue.item(item.item_id)), PendingReview)
    assert restored.requested_reasons == ("evidence_insufficient",)
    assert restored.approval is not None
    assert restored.approval.approved_reasons == ("evidence_insufficient",)

# ── RMR-AUD-001 (binding part): abstain_to_escalate_laundering ─────────────

def test_abstain_to_escalate_laundering_is_refused(world: Deployment) -> None:
    """Assess with a downgrade, get it approved, execute with another one."""
    assessed_call = {**WRITE, "schema_valid": False}
    item_id = _propose(world, assessed_call, "escalate")
    assert world.approve(item_id).status_code == 200
    laundered = {**WRITE, "untrusted_context": "benign note"}
    r = world.execute(item_id, laundered)
    assert not r.ran
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "binding_refused"
    assert _refusals(world)[-1]["detail"] == "binding_refused"
    # Refused before the queue was touched: the approval is still there.
    assert _status(world, item_id) == "approved"


@pytest.mark.parametrize("change", [
    {"schema_valid": False},
    {"rollback_available": False},
    {"untrusted_context": "note"},
    {"intent_ref": "WO-9"},
    {"task_type": "maintenance"},
    {"derivations": [{"argument": "value", "source_tool": "read_record",
                      "source_call": {"record_id": "pub-1"}, "source_path": "value",
                      "transform": "identity"}]},
])
def test_any_proposal_field_added_at_execute_is_refused(
        world: Deployment, change: dict[str, Any]) -> None:
    item_id = _approved(world, WRITE)
    r = world.execute(item_id, {**WRITE, **change})
    assert not r.ran
    assert r.status_code in (409, 422), r.text
    if r.status_code == 409:
        assert r.json()["detail"] in ("binding_refused", "context_mismatch")
    assert world.execute(item_id, WRITE).ran


def test_a_different_idempotency_key_is_not_a_different_proposal(
        world: Deployment) -> None:
    item_id = _approved(world, {**WRITE, "idempotency_key": "k-assess"})
    r = world.execute(item_id, {**WRITE, "idempotency_key": "k-execute"})
    assert r.status_code == 200, r.text
    assert r.ran


def test_the_proposal_hash_covers_every_proposal_field() -> None:
    """A field added to the wire model must be bound or deliberately exempt."""
    from remora.execution.service import PROPOSAL_ENVELOPE_FIELDS
    from servers.execution_contracts import ToolCallRequest

    payload = {"tool_name", "arguments", "target_environment"}  # tool_call_hash
    assert set(ToolCallRequest.model_fields) - {"idempotency_key"} - payload == set(
        PROPOSAL_ENVELOPE_FIELDS)


def test_an_item_whose_assessment_carries_no_proposal_hash_is_refused(
        world: Deployment) -> None:
    """Fail closed: an assessed record from before the binding cannot match."""
    item_id = _approved(world, WRITE)
    for entry in world.exec._CHAIN.entries(TENANT):
        if entry.payload.get("event") == "assessed":
            entry.payload.pop("proposal_envelope_hash", None)
    r = world.execute(item_id, WRITE)
    assert not r.ran
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "binding_refused"


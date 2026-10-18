# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Delegated execution bound at proposal time, and approvals bound to the
approval policy that set their required role.

Builds on the review-path binding (#935, ``tests/test_review_path_binding.py``),
which made an approved item executable only by its proposer, and leaves two
follow-ups the owner decided on 2026-10-18:

1. **Delegated execution.** A proposal may name ``delegated_executor``, a
   service identity the deployment declares for the proposing agent in the
   proposer's own tenant (``tenant_access.<tenant>.delegated_executors`` in the
   risk-profile config). The delegate is recorded in the ``assessed`` record,
   bound into the ``AuthorizationContext`` hash, shown to the reviewer and
   cannot be added or changed after approval. Without a delegation nothing
   changes: a second actor is still ``context_mismatch``.
2. **Approval policy binding.** An approval records the approver's role, the
   role the tier required and a hash of that requirement. At execution a
   requirement that changed (for example ``schemas/risk-profiles.yaml`` edited
   and the server restarted, with the item in a durable queue) voids the
   approval and re-queues the item; an approval without the record is voided
   too.

The delegation-abuse cases at the end are attacks on (1), kept here and not in
the #932 evaluation artifact.
"""
from __future__ import annotations

import copy
import dataclasses
from datetime import timedelta
from typing import Any

import pytest

pytest.importorskip("fastapi")

from tests.test_review_path_binding import (  # noqa: E402
    AGENT,
    EFFECTS,
    OTHER_AGENT,
    REVIEWER,
    TASK_A,
    TASK_B,
    TENANT,
    WRITE,
    Deployment,
    _AlwaysVerify,
    _approved,
    _chain_events,
    _obs,
)

SERVICE = "svc-runner"
OTHER_SERVICE = "svc-other"
OTHER_TENANT = "globex"


def _declare(world: Deployment, declared: dict[str, dict[str, list[str]]]) -> None:
    """Declare delegated executors per tenant in the risk-profile config.

    ``declared`` maps tenant -> {service identity -> [agents it may execute for]}.
    """
    import servers.api as api_mod

    config = copy.deepcopy(api_mod._RISK_PROFILE_CONFIG)
    access = config.setdefault("tenant_access", {})
    for tenant, delegates in declared.items():
        access.setdefault(tenant, {})["delegated_executors"] = delegates
    world.mp.setattr(api_mod, "_RISK_PROFILE_CONFIG", config)


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> Any:
    from remora.toolcall.deployment_registry import reset_deployment_tool_metadata

    deployment = Deployment(monkeypatch, tmp_path)
    _declare(deployment, {TENANT: {SERVICE: [AGENT], OTHER_SERVICE: [AGENT]}})
    yield deployment
    monkeypatch.undo()
    reset_deployment_tool_metadata()
    deployment.reset_runtime()


def _assess(world: Deployment, call: dict[str, Any], *,
            principal: str = AGENT) -> Any:
    with world.acting_as(principal=principal):
        return world.client.post("/v1/execution/assess", json=call)


def _delegated(call: dict[str, Any], delegate: str = SERVICE) -> dict[str, Any]:
    return {**call, "delegated_executor": delegate}


def _refusals(world: Deployment) -> list[dict[str, Any]]:
    return [e for e in _chain_events(world)
            if e.get("event") == "execution_context_refused"]


# ── 1. delegation: the named delegate executes ─────────────────────────────

def test_a_delegate_named_at_proposal_can_execute(world: Deployment) -> None:
    call = _delegated(WRITE)
    item_id = _approved(world, call)
    r = world.execute(item_id, call, principal=SERVICE)
    assert r.status_code == 200, r.text
    assert r.ran and r.json()["tool_execution"]["executed"] is True


def test_the_delegated_execution_is_recorded_in_the_chain(world: Deployment) -> None:
    call = _delegated(WRITE)
    item_id = _approved(world, call)
    assert world.execute(item_id, call, principal=SERVICE).ran
    events = _chain_events(world)
    assessed = next(e for e in events if e.get("event") == "assessed")
    assert assessed["actor"] == AGENT
    assert assessed["delegated_executor"] == SERVICE
    authorized = [e for e in events if e.get("event") == "execution_authorized"]
    assert authorized[-1]["actor"] == SERVICE
    assert authorized[-1]["acting_for"] == AGENT


def test_the_proposer_can_still_execute_a_delegated_item(world: Deployment) -> None:
    call = _delegated(WRITE)
    item_id = _approved(world, call)
    r = world.execute(item_id, call)
    assert r.status_code == 200, r.text
    assert r.ran


def test_an_unnamed_second_actor_still_gets_context_mismatch(world: Deployment) -> None:
    call = _delegated(WRITE)
    item_id = _approved(world, call)
    r = world.execute(item_id, call, principal=OTHER_AGENT)
    assert not r.ran
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "context_mismatch"
    assert _refusals(world)[-1]["mismatched"] == ["principal"]


def test_without_a_delegation_a_declared_service_is_still_refused(
        world: Deployment) -> None:
    """Declaring a service identity grants nothing until a proposal names it."""
    item_id = _approved(world, WRITE)
    r = world.execute(item_id, WRITE, principal=SERVICE)
    assert not r.ran
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "context_mismatch"


# ── 1. delegation: bound at proposal, not after ────────────────────────────

def test_a_delegate_cannot_be_added_after_approval(world: Deployment) -> None:
    item_id = _approved(world, WRITE)
    r = world.execute(item_id, _delegated(WRITE), principal=SERVICE)
    assert not r.ran
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "context_mismatch"
    assert "delegated_executor" in _refusals(world)[-1]["mismatched"]


def test_the_proposer_cannot_add_a_delegate_after_approval(world: Deployment) -> None:
    item_id = _approved(world, WRITE)
    r = world.execute(item_id, _delegated(WRITE))
    assert not r.ran
    assert r.status_code == 409, r.text
    assert _refusals(world)[-1]["mismatched"] == ["delegated_executor"]
    # The refusal touched nothing: the approval still serves its proposer.
    assert world.execute(item_id, WRITE).ran


def test_a_delegate_cannot_be_changed_after_approval(world: Deployment) -> None:
    item_id = _approved(world, _delegated(WRITE))
    swapped = _delegated(WRITE, OTHER_SERVICE)
    r = world.execute(item_id, swapped, principal=OTHER_SERVICE)
    assert not r.ran
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "context_mismatch"


def test_a_delegate_cannot_be_stripped_by_the_delegate(world: Deployment) -> None:
    item_id = _approved(world, _delegated(WRITE))
    r = world.execute(item_id, WRITE, principal=SERVICE)
    assert not r.ran
    assert r.status_code == 409, r.text


# ── 1. delegation: declared, same tenant ───────────────────────────────────

def test_an_undeclared_delegate_is_refused_at_proposal(world: Deployment) -> None:
    r = _assess(world, _delegated(WRITE, "svc-unknown"))
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "delegate_not_declared"
    assert not [e for e in _chain_events(world) if e.get("event") == "assessed"]


def test_a_delegate_declared_for_another_agent_is_refused(world: Deployment) -> None:
    _declare(world, {TENANT: {SERVICE: ["agent-3"]}})
    r = _assess(world, _delegated(WRITE))
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "delegate_not_declared"


def test_a_cross_tenant_delegate_is_refused_at_proposal(world: Deployment) -> None:
    _declare(world, {TENANT: {}, OTHER_TENANT: {SERVICE: [AGENT]}})
    r = _assess(world, _delegated(WRITE))
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "delegate_cross_tenant"


def test_a_delegate_authenticated_in_another_tenant_cannot_execute(
        world: Deployment) -> None:
    call = _delegated(WRITE)
    item_id = _approved(world, call)
    world.identity["tenant"] = OTHER_TENANT
    try:
        r = world.execute(item_id, call, principal=SERVICE)
    finally:
        world.identity["tenant"] = TENANT
    assert not r.ran
    assert r.status_code == 404, r.text


def test_no_delegation_is_declared_by_default(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """Fail closed: the shipped risk-profile config declares no delegate."""
    from remora.toolcall.deployment_registry import reset_deployment_tool_metadata

    deployment = Deployment(monkeypatch, tmp_path)
    try:
        r = _assess(deployment, _delegated(WRITE))
        assert r.status_code == 409, r.text
        assert r.json()["detail"] == "delegate_not_declared"
    finally:
        monkeypatch.undo()
        reset_deployment_tool_metadata()
        deployment.reset_runtime()


# ── 1. delegation: visible to the reviewer ─────────────────────────────────

def test_the_reviewer_sees_the_delegate(world: Deployment) -> None:
    call = _delegated(WRITE)
    item_id = world.propose(call)
    proposal_id = next(e["proposal_id"] for e in _chain_events(world)
                       if e.get("event") == "assessed")
    with world.acting_as(role="reviewer", principal=REVIEWER):
        seen = world.client.get(f"/v1/execution/proposals/{proposal_id}")
    assert seen.status_code == 200, seen.text
    assert seen.json()["delegated_executor"] == SERVICE
    assert seen.json()["actor"] == AGENT

    approved = world.approve(item_id)
    assert approved.status_code == 200, approved.text
    assert approved.json()["delegated_executor"] == SERVICE
    record = next(e for e in _chain_events(world) if e.get("event") == "approved")
    assert record["delegated_executor"] == SERVICE


def test_an_undelegated_proposal_shows_no_delegate(world: Deployment) -> None:
    item_id = world.propose(WRITE)
    approved = world.approve(item_id)
    assert approved.status_code == 200, approved.text
    assert "delegated_executor" not in approved.json()


# ── 1. the hashed authorization context ────────────────────────────────────

def test_a_context_without_a_delegate_hashes_as_before() -> None:
    from remora.enforcement.token import AuthorizationContext

    plain = AuthorizationContext(tenant=TENANT, principal=AGENT)
    pinned = AuthorizationContext(tenant=TENANT, principal=AGENT, delegated_executor="")
    assert plain.hash() == pinned.hash()
    bound = dataclasses.replace(plain, delegated_executor=SERVICE)
    assert bound.hash() != plain.hash()
    assert plain.differences(bound) == ["delegated_executor"]


# ── 1. the ACCEPT token binds the delegate the same way ────────────────────

READ = {"tool_name": "read_record", "arguments": {"record_id": "pub-1"},
        "target_environment": "staging"}


def read_record(arguments: dict[str, Any]) -> dict[str, Any]:
    """Read a record."""
    EFFECTS.append(dict(arguments))
    return {"value": "ok"}


@pytest.fixture()
def accept_world(world: Deployment) -> Deployment:
    """``world`` with a low-risk read the engine ACCEPTs."""
    import json
    import sys

    from remora.toolcall.deployment_registry import reset_deployment_tool_metadata
    from tests.test_review_path_binding import METADATA, REGISTRY_MODULE

    registry = sys.modules[REGISTRY_MODULE]

    def register_tools(register: Any) -> None:
        from tests.test_review_path_binding import update_record

        register("update_record", update_record)
        register("read_record", read_record)

    world.mp.setattr(registry, "register_tools", register_tools)
    metadata = json.loads(json.dumps(METADATA))
    metadata["read_record"] = {"risk_tier": "low", "domain": "general",
                               "action_type": "read",
                               "target_environment": "staging"}
    path = world.tmp / "metadata-accept.json"
    path.write_text(json.dumps({"version": 1, "tools": metadata}), encoding="utf-8")
    world.mp.setenv("REMORA_TOOL_METADATA_FILE", str(path))
    reset_deployment_tool_metadata()
    world.mp.setenv("REMORA_LOW_CONSEQUENCE_ACCEPT", "1")
    world.mp.setattr(world.exec, "_ENGINE", world.exec._engine_from_env())
    world.reset_runtime()
    return world


def _token(world: Deployment, call: dict[str, Any]) -> dict[str, Any]:
    r = _assess(world, call)
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == "accept", r.json()
    return dict(r.json()["execution_token"])


def _redeem(world: Deployment, token: dict[str, Any], call: dict[str, Any], *,
            principal: str) -> Any:
    before = len(EFFECTS)
    with world.acting_as(principal=principal):
        r = world.client.post("/v1/execution/execute-accepted",
                              json={"execution_token": token, "tool_call": call})
    r.ran = len(EFFECTS) > before  # type: ignore[attr-defined]
    return r


def test_a_delegate_named_at_proposal_can_redeem_the_accept_token(
        accept_world: Deployment) -> None:
    call = _delegated(READ)
    r = _redeem(accept_world, _token(accept_world, call), call, principal=SERVICE)
    assert r.status_code == 200, r.text
    assert r.ran


def test_an_unnamed_actor_cannot_redeem_a_delegated_accept_token(
        accept_world: Deployment) -> None:
    call = _delegated(READ)
    r = _redeem(accept_world, _token(accept_world, call), call, principal=OTHER_AGENT)
    assert not r.ran
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "context_mismatch"


def test_a_delegate_cannot_be_added_to_an_accept_token(
        accept_world: Deployment) -> None:
    token = _token(accept_world, READ)
    r = _redeem(accept_world, token, _delegated(READ), principal=SERVICE)
    assert not r.ran
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "context_mismatch"


def test_a_delegated_accept_redemption_leases_to_the_delegate(
        accept_world: Deployment) -> None:
    """The lease binds the actor the authority admitted: the delegate."""
    call = _delegated(READ)
    r = _redeem(accept_world, _token(accept_world, call), call, principal=SERVICE)
    assert r.status_code == 200, r.text
    authorized = [e for e in _chain_events(accept_world)
                  if e.get("event") == "execution_authorized"]
    assert authorized[-1]["actor"] == SERVICE
    assert authorized[-1]["acting_for"] == AGENT


# ── 2. approval bound to the policy that set its required role ─────────────

def test_the_approval_records_the_roles_it_was_granted_under(world: Deployment) -> None:
    item_id = _approved(world, WRITE)
    record = next(e for e in _chain_events(world) if e.get("event") == "approved")
    assert record["approver_role"] == "reviewer"
    assert record["required_role"] is None
    assert len(record["approval_policy_hash"]) == 64
    approval = world.exec._QUEUES[TENANT].item(item_id).approval
    assert approval.approver_role == "reviewer"
    assert approval.approval_policy_hash == record["approval_policy_hash"]


def _require_role(world: Deployment, profile: str, role: str) -> None:
    """Edit the loaded risk-profile config, as a changed file read at restart."""
    import servers.api as api_mod

    config = copy.deepcopy(api_mod._RISK_PROFILE_CONFIG)
    config["profiles"][profile].setdefault("action", {})["approval_role"] = role
    world.mp.setattr(api_mod, "_RISK_PROFILE_CONFIG", config)


def _restart(world: Deployment) -> None:
    """Drop every in-process queue; the durable store is all that remains."""
    world.exec._QUEUES.clear()
    world.exec._ITEM_TENANT.clear()
    world.reset_runtime()


@pytest.fixture()
def durable_world(world: Deployment) -> Deployment:
    world.mp.setenv("REMORA_CHAIN_DB", str(world.tmp / "state.db"))
    _restart(world)
    return world


def test_a_required_role_change_voids_the_approval(world: Deployment) -> None:
    item_id = _approved(world, WRITE)
    _require_role(world, "medium_risk", "domain_expert")
    r = world.execute(item_id, WRITE)
    assert not r.ran
    assert r.status_code == 200, r.text
    assert r.json()["outcome"] == "approval_invalidated", r.json()


def test_a_role_change_across_a_restart_voids_a_durable_approval(
        durable_world: Deployment) -> None:
    world = durable_world
    item_id = _approved(world, WRITE)
    _require_role(world, "medium_risk", "domain_expert")
    _restart(world)

    r = world.execute(item_id, WRITE)
    assert not r.ran
    assert r.status_code == 200, r.text
    assert r.json()["outcome"] == "approval_invalidated", r.json()

    # Re-queued under the current rule: the old role no longer suffices.
    refused = world.approve(item_id)
    assert refused.status_code == 403, refused.text
    assert "domain_expert" in refused.json()["detail"]
    granted = world.approve(item_id, role="domain_expert", principal="expert-1")
    assert granted.status_code == 200, granted.text
    _restart(world)
    r = world.execute(item_id, WRITE)
    assert r.status_code == 200, r.text
    assert r.ran


def test_an_unchanged_policy_survives_a_restart(durable_world: Deployment) -> None:
    world = durable_world
    item_id = _approved(world, WRITE)
    _restart(world)
    r = world.execute(item_id, WRITE)
    assert r.status_code == 200, r.text
    assert r.ran


def test_an_approval_without_a_policy_record_is_voided(
        durable_world: Deployment) -> None:
    """An approval persisted before the binding existed fails closed."""
    world = durable_world
    item_id = _approved(world, WRITE)
    with world.exec.db_transaction_state(TENANT) as q:
        item = q.item(item_id)
        item.approval = dataclasses.replace(
            item.approval, approver_role=None, required_role=None,
            approval_policy_hash=None)
    _restart(world)
    r = world.execute(item_id, WRITE)
    assert not r.ran
    assert r.json()["outcome"] == "approval_invalidated", r.json()


# ── 2. the queue rule, without the server ──────────────────────────────────

def _policy_queue() -> tuple[Any, Any]:
    from remora.governance.review_queue import ReviewQueue
    from remora.policy.report import DecisionAction

    queue = ReviewQueue(engine=_AlwaysVerify())  # type: ignore[arg-type]
    item = queue.enqueue(_obs("medium"), DecisionAction.VERIFY)
    queue.approve(item.item_id, "reviewer-1", timedelta(minutes=5),
                  approver_role="reviewer", required_role=None,
                  approval_policy_hash="a" * 64)
    return queue, item


def test_queue_voids_an_approval_when_the_approval_policy_changed() -> None:
    from remora.governance.review_queue import ExecutionDecision, ItemStatus

    queue, item = _policy_queue()
    outcome = queue.execute(item.item_id, _obs("medium"),
                            approval_policy_hash="b" * 64)
    assert outcome.decision is ExecutionDecision.APPROVAL_INVALIDATED
    assert queue.item(item.item_id).status is ItemStatus.PENDING
    assert queue.events[-1].payload["reason"] == "approval_policy_changed"


def test_queue_voids_an_approval_with_no_policy_record() -> None:
    from remora.governance.review_queue import ExecutionDecision, ReviewQueue
    from remora.policy.report import DecisionAction

    queue = ReviewQueue(engine=_AlwaysVerify())  # type: ignore[arg-type]
    item = queue.enqueue(_obs("medium"), DecisionAction.VERIFY)
    queue.approve(item.item_id, "reviewer-1", timedelta(minutes=5))
    outcome = queue.execute(item.item_id, _obs("medium"),
                            approval_policy_hash="a" * 64)
    assert outcome.decision is ExecutionDecision.APPROVAL_INVALIDATED
    assert queue.events[-1].payload["reason"] == "approval_policy_unbound"


def test_queue_keeps_an_approval_under_the_same_policy() -> None:
    from remora.governance.review_queue import ExecutionDecision

    queue, item = _policy_queue()
    outcome = queue.execute(item.item_id, _obs("medium"),
                            approval_policy_hash="a" * 64)
    assert outcome.decision is ExecutionDecision.EXECUTE


def test_queue_regate_at_dispatch_refuses_a_changed_policy() -> None:
    from remora.governance.review_queue import ExecutionDecision

    queue, item = _policy_queue()
    assert queue.execute(item.item_id, _obs("medium"),
                         approval_policy_hash="a" * 64).decision is ExecutionDecision.EXECUTE
    outcome = queue.regate_authorized(item.item_id, _obs("medium"),
                                      approval_policy_hash="b" * 64)
    assert outcome.decision is ExecutionDecision.APPROVAL_INVALIDATED


def test_the_approval_policy_round_trips_through_the_durable_encoding() -> None:
    from remora.governance.review_queue import PendingReview
    from remora.persistence.execution_state import from_dict, to_dict

    queue, item = _policy_queue()
    restored = from_dict(to_dict(queue.item(item.item_id)), PendingReview)
    assert restored.approval is not None
    assert restored.approval.approval_policy_hash == "a" * 64
    assert restored.approval.approver_role == "reviewer"


# ── delegation abuse ───────────────────────────────────────────────────────

def test_abuse_an_agent_cannot_name_another_agent_as_its_delegate(
        world: Deployment) -> None:
    """Only a declared service identity can be named; a peer agent cannot."""
    r = _assess(world, _delegated(WRITE, OTHER_AGENT))
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "delegate_not_declared"


def test_abuse_a_declared_service_cannot_be_borrowed_by_another_agent(
        world: Deployment) -> None:
    """SERVICE executes for AGENT only; OTHER_AGENT cannot name it."""
    r = _assess(world, _delegated(WRITE), principal=OTHER_AGENT)
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "delegate_not_declared"


def test_abuse_the_delegate_cannot_approve_what_it_will_execute(
        world: Deployment) -> None:
    item_id = world.propose(_delegated(WRITE))
    r = world.approve(item_id, principal=SERVICE)
    assert r.status_code == 403, r.text
    assert r.json()["detail"] == "approver_is_delegated_executor"


def test_abuse_a_delegate_cannot_move_the_item_to_another_task(
        world: Deployment) -> None:
    item_id = _approved(world, _delegated({**WRITE, **TASK_A}))
    r = world.execute(item_id, _delegated({**WRITE, **TASK_B}), principal=SERVICE)
    assert not r.ran
    assert r.status_code == 409, r.text
    assert _refusals(world)[-1]["mismatched"] == ["task_id"]


def test_abuse_a_delegate_cannot_execute_twice(world: Deployment) -> None:
    call = _delegated(WRITE)
    item_id = _approved(world, call)
    assert world.execute(item_id, call, principal=SERVICE).ran
    again = world.execute(item_id, call, principal=SERVICE)
    assert not again.ran


def test_abuse_a_delegate_cannot_outlive_a_risk_raise(world: Deployment) -> None:
    call = _delegated(WRITE)
    item_id = _approved(world, call)
    world.relabel("high")
    world.reset_runtime()
    r = world.execute(item_id, call, principal=SERVICE)
    assert not r.ran
    assert r.json()["outcome"] == "approval_invalidated", r.json()



# ── the async path: worker dispatch after a 202 ────────────────────────────

def _execute_async(world: Deployment, item_id: str, call: dict[str, Any], *,
                   principal: str) -> Any:
    world.mp.setenv("REMORA_ASYNC_DISPATCH", "1")
    r = world.execute(item_id, call, principal=principal)
    assert r.status_code == 202, r.text
    return r


def test_the_worker_records_the_delegate_and_whom_it_acts_for(
        world: Deployment) -> None:
    call = _delegated(WRITE)
    item_id = _approved(world, call)
    _execute_async(world, item_id, call, principal=SERVICE)
    results = world.exec.dispatch_pending_intents(TENANT, worker_id="w-1")
    assert results and results[0]["tool_execution"]["executed"] is True, results
    authorized = [e for e in _chain_events(world)
                  if e.get("event") == "execution_authorized"]
    assert authorized[-1]["actor"] == SERVICE
    assert authorized[-1]["acting_for"] == AGENT


def test_the_worker_refuses_after_the_approval_policy_changed(
        world: Deployment) -> None:
    """Between the 202 and the worker the requirement moved: nothing runs."""
    item_id = _approved(world, WRITE)
    _execute_async(world, item_id, WRITE, principal=AGENT)
    _require_role(world, "medium_risk", "domain_expert")
    before = len(EFFECTS)
    results = world.exec.dispatch_pending_intents(TENANT, worker_id="w-1")
    assert len(EFFECTS) == before
    assert results and results[0]["tool_execution"]["executed"] is False, results

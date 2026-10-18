# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The review path binds actor, task and reviewed authority like the ACCEPT path.

The execution-chain attack evaluation (PR #932,
``scripts/execution_chain_attack_eval.py``) measured two defects on the
VERIFY -> human approval -> ``/v1/execution/execute`` path that the ACCEPT
token and the lease do not have:

1. Actor and task were not bound. An item proposed by agent-1 executed when
   agent-2 presented it, and an item approved under task A executed under
   task B. The ACCEPT token's ``AuthorizationContext`` binds both.
2. An approval survived a risk raise. Raising the tool's deployment risk tier
   from medium to high or critical after approval kept the approval, because
   the fresh decision was still VERIFY, although high and critical reserve
   approval for ``domain_expert`` and ``senior_authority``.

The setup mirrors the evaluation's: a deployment tool registry, deployment
risk metadata and real FastAPI routes. Unlike the evaluation it leaves the
approver-role check (``_enforce_review_approval_role``) and the tenant
capability check enabled, so the fix is exercised with both in force.
"""
from __future__ import annotations

import contextlib
import dataclasses
import json
import sys
import types
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

TENANT = "acme"
AGENT = "agent-1"
OTHER_AGENT = "agent-2"
REVIEWER = "reviewer-1"
REGISTRY_MODULE = "_remora_review_binding_registry"

EFFECTS: list[dict[str, Any]] = []


def update_record(arguments: dict[str, Any]) -> dict[str, Any]:
    """Write a value into a record."""
    EFFECTS.append(dict(arguments))
    return {"updated": True}


METADATA: dict[str, dict[str, Any]] = {
    "update_record": {"risk_tier": "medium", "domain": "general",
                      "action_type": "write"},
}
WRITE = {"tool_name": "update_record",
         "arguments": {"record_id": "pub-1", "value": "closed on 24 Dec"},
         "target_environment": "staging"}
TASK_A = {"context_id": "ctx-1", "task_id": "task-a"}
TASK_B = {"context_id": "ctx-1", "task_id": "task-b"}


class Deployment:
    """One isolated execution deployment, driven through the real routes."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        import servers.api as api_mod
        import servers.execution_api as exec_mod
        from remora.governance.tenant_chain import TenantAuditChain

        self.mp = monkeypatch
        self.tmp = tmp_path
        self.exec = exec_mod
        self.identity = {"tenant": TENANT, "role": "operator", "principal": AGENT}
        EFFECTS.clear()

        registry = types.ModuleType(REGISTRY_MODULE)
        registry.register_tools = (  # type: ignore[attr-defined]
            lambda register: register("update_record", update_record))
        monkeypatch.setitem(sys.modules, REGISTRY_MODULE, registry)
        for key, value in {
            "REMORA_ENV": "development",
            "REMORA_RUNTIME_PROFILE": "research",
            "REMORA_PDP_SIGNING_KEY": "review-binding-pdp-key",
            "REMORA_LEASE_SIGNING_KEY": "review-binding-lease-key",
            "REMORA_TOOL_REGISTRY_MODULE": REGISTRY_MODULE,
        }.items():
            monkeypatch.setenv(key, value)
        self.relabel("medium")

        ident = self.identity
        monkeypatch.setattr(api_mod, "_authenticate",
                            lambda request: (ident["tenant"], ident["role"]))
        monkeypatch.setattr(api_mod, "_authenticated_principal",
                            lambda request: ident["principal"])
        with contextlib.suppress(AttributeError):
            api_mod._rate_limiter._buckets.clear()
        exec_mod._QUEUES.clear()
        exec_mod._ITEM_TENANT.clear()
        monkeypatch.setattr(exec_mod, "_CHAIN", TenantAuditChain())
        monkeypatch.setattr(exec_mod, "_GATE", exec_mod.EnforcementGate(
            strict=True, audience=exec_mod.PEP_AUDIENCE))
        monkeypatch.setattr(exec_mod, "_LOOP_SAFETY", None)
        monkeypatch.setattr(exec_mod, "_IDEMPOTENCY_STORE", None)
        self.reset_runtime()
        self.client = TestClient(api_mod.app)

    def relabel(self, tier: str) -> None:
        """Change the deployment's declared risk tier for update_record."""
        from remora.toolcall.deployment_registry import reset_deployment_tool_metadata

        metadata = json.loads(json.dumps(METADATA))
        metadata["update_record"]["risk_tier"] = tier
        path = self.tmp / f"metadata-{tier}.json"
        path.write_text(json.dumps({"version": 1, "tools": metadata}), encoding="utf-8")
        self.mp.setenv("REMORA_TOOL_METADATA_FILE", str(path))
        reset_deployment_tool_metadata()

    def reset_runtime(self) -> None:
        self.exec._reset_toolspec_bundle()
        self.exec._reset_semantic_bundle()
        self.exec._reset_tool_dispatcher()
        self.exec._reset_outbox()

    @contextlib.contextmanager
    def acting_as(self, *, role: str = "operator", principal: str = AGENT) -> Iterator[None]:
        saved = dict(self.identity)
        self.identity.update(role=role, principal=principal)
        try:
            yield
        finally:
            self.identity.update(saved)

    def propose(self, call: dict[str, Any]) -> str:
        r = self.client.post("/v1/execution/assess", json=call)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["decision"] == "verify", body
        return str(body["review_item_id"])

    def approve(self, item_id: str, *, role: str = "reviewer",
                principal: str = REVIEWER) -> Any:
        with self.acting_as(role=role, principal=principal):
            return self.client.post("/v1/execution/approve", json={"item_id": item_id})

    def execute(self, item_id: str, call: dict[str, Any], *,
                principal: str = AGENT) -> Any:
        before = len(EFFECTS)
        with self.acting_as(principal=principal):
            r = self.client.post("/v1/execution/execute",
                                 json={"item_id": item_id, "tool_call": call})
        r.ran = len(EFFECTS) > before  # type: ignore[attr-defined]
        return r


@pytest.fixture()
def world(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> Iterator[Deployment]:
    from remora.toolcall.deployment_registry import reset_deployment_tool_metadata

    deployment = Deployment(monkeypatch, tmp_path)
    yield deployment
    monkeypatch.undo()
    reset_deployment_tool_metadata()
    deployment.reset_runtime()


def _approved(world: Deployment, call: dict[str, Any]) -> str:
    item_id = world.propose(call)
    r = world.approve(item_id)
    assert r.status_code == 200, r.text
    return item_id


def _chain_events(world: Deployment) -> list[dict[str, Any]]:
    return [e.payload for e in world.exec._CHAIN.entries(TENANT)]


# ── control ────────────────────────────────────────────────────────────────

def test_the_proposer_executes_its_approved_item_once(world: Deployment) -> None:
    item_id = _approved(world, {**WRITE, **TASK_A})
    r = world.execute(item_id, {**WRITE, **TASK_A})
    assert r.status_code == 200, r.text
    assert r.ran and r.json()["tool_execution"]["executed"] is True


# ── defect 1: actor ────────────────────────────────────────────────────────

def test_another_actor_cannot_execute_an_approved_item(world: Deployment) -> None:
    item_id = _approved(world, WRITE)
    r = world.execute(item_id, WRITE, principal=OTHER_AGENT)
    assert not r.ran
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "context_mismatch"
    refusal = [e for e in _chain_events(world)
               if e.get("event") == "execution_context_refused"]
    assert refusal and refusal[-1]["actor"] == OTHER_AGENT
    assert refusal[-1]["mismatched"] == ["principal"]


def test_a_refused_actor_does_not_burn_the_proposers_approval(world: Deployment) -> None:
    """Checked before the queue consumes anything, like the ACCEPT path."""
    item_id = _approved(world, WRITE)
    assert not world.execute(item_id, WRITE, principal=OTHER_AGENT).ran
    r = world.execute(item_id, WRITE)
    assert r.status_code == 200, r.text
    assert r.ran


def test_an_unknown_item_still_answers_not_found(world: Deployment) -> None:
    """The binding check must not turn a 404 into a context refusal."""
    r = world.execute("never-issued", WRITE)
    assert not r.ran
    assert r.status_code == 404, r.text


def test_an_item_whose_assessment_cannot_be_read_back_is_refused(
        world: Deployment, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail closed: nothing to compare against is not a match."""
    item_id = _approved(world, WRITE)
    monkeypatch.setattr(world.exec, "_assessed_record", lambda tenant, item: ("", ""))
    r = world.execute(item_id, WRITE)
    assert not r.ran
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "context_unbound"


# ── defect 1: task ─────────────────────────────────────────────────────────

def test_an_item_approved_under_one_task_cannot_execute_under_another(
        world: Deployment) -> None:
    item_id = _approved(world, {**WRITE, **TASK_A})
    r = world.execute(item_id, {**WRITE, **TASK_B})
    assert not r.ran
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "context_mismatch"
    refusal = [e for e in _chain_events(world)
               if e.get("event") == "execution_context_refused"]
    assert refusal[-1]["mismatched"] == ["task_id"]


def test_an_item_approved_under_a_task_cannot_execute_with_the_task_stripped(
        world: Deployment) -> None:
    item_id = _approved(world, {**WRITE, **TASK_A})
    r = world.execute(item_id, WRITE)
    assert not r.ran
    assert r.status_code == 409, r.text


def test_an_item_approved_without_a_task_cannot_gain_one(world: Deployment) -> None:
    item_id = _approved(world, WRITE)
    r = world.execute(item_id, {**WRITE, **TASK_A})
    assert not r.ran
    assert r.status_code == 409, r.text


# ── defect 2: authority ────────────────────────────────────────────────────

@pytest.mark.parametrize("tier", ["high", "critical"])
def test_a_risk_raise_after_approval_invalidates_the_approval(
        world: Deployment, tier: str) -> None:
    item_id = _approved(world, WRITE)
    world.relabel(tier)
    world.reset_runtime()
    r = world.execute(item_id, WRITE)
    assert not r.ran
    assert r.status_code == 200, r.text
    assert r.json()["outcome"] == "approval_invalidated", r.json()


def test_after_a_risk_raise_the_reviewer_role_no_longer_suffices(
        world: Deployment) -> None:
    """With the approver-role check enabled, the re-queued item needs the
    authority the raised tier requires (high -> domain_expert)."""
    item_id = _approved(world, WRITE)
    world.relabel("high")
    world.reset_runtime()
    assert world.execute(item_id, WRITE).json()["outcome"] == "approval_invalidated"

    refused = world.approve(item_id)
    assert refused.status_code == 403, refused.text
    assert "domain_expert" in refused.json()["detail"]

    granted = world.approve(item_id, role="domain_expert", principal="expert-1")
    assert granted.status_code == 200, granted.text
    r = world.execute(item_id, WRITE)
    assert r.status_code == 200, r.text
    assert r.ran


def test_an_unchanged_tier_keeps_the_approval(world: Deployment) -> None:
    item_id = _approved(world, WRITE)
    world.relabel("medium")
    world.reset_runtime()
    r = world.execute(item_id, WRITE)
    assert r.status_code == 200, r.text
    assert r.ran


# ── the queue rule, without the server ─────────────────────────────────────

class _AlwaysVerify:
    """An engine that re-decides VERIFY, so only the tier rule can void."""

    def decide(self, observation: Any) -> Any:
        from remora.policy.report import DecisionAction

        return types.SimpleNamespace(action=DecisionAction.VERIFY, reasons=())


def _obs(tier: str | None) -> Any:
    from remora.policy.observation import PolicyObservation

    return dataclasses.replace(PolicyObservation.minimal(
        "write a record", risk_tier=tier), tool_call_hash="h" * 64)


@pytest.mark.parametrize(("approved", "fresh"), [
    ("medium", "high"), ("medium", "critical"), ("high", "medium"),
    ("medium", None), (None, "medium"),
])
def test_queue_voids_an_approval_when_the_reviewed_tier_changed(
        approved: str | None, fresh: str | None) -> None:
    from remora.governance.review_queue import ExecutionDecision, ItemStatus, ReviewQueue
    from remora.policy.report import DecisionAction

    queue = ReviewQueue(engine=_AlwaysVerify())  # type: ignore[arg-type]
    item = queue.enqueue(_obs(approved), DecisionAction.VERIFY)
    queue.approve(item.item_id, "reviewer-1", timedelta(minutes=5))
    outcome = queue.execute(item.item_id, _obs(fresh))
    assert outcome.decision is ExecutionDecision.APPROVAL_INVALIDATED
    stored = queue.item(item.item_id)
    assert stored.status is ItemStatus.PENDING
    assert stored.observation.risk_tier == fresh
    assert queue.events[-1].payload["reason"] == "reviewed_risk_tier_changed"


def test_queue_regate_at_dispatch_refuses_a_changed_tier() -> None:
    from remora.governance.review_queue import ExecutionDecision, ReviewQueue
    from remora.policy.report import DecisionAction

    queue = ReviewQueue(engine=_AlwaysVerify())  # type: ignore[arg-type]
    item = queue.enqueue(_obs("medium"), DecisionAction.VERIFY)
    queue.approve(item.item_id, "reviewer-1", timedelta(minutes=5))
    assert queue.execute(item.item_id, _obs("medium")).decision is ExecutionDecision.EXECUTE
    outcome = queue.regate_authorized(item.item_id, _obs("high"))
    assert outcome.decision is ExecutionDecision.APPROVAL_INVALIDATED

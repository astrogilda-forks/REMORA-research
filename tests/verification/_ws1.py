# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Shared WS1 test builders. Plain functions, so each test states what it varies."""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import Any

from remora.decision_providers.composition_adapter import (
    MONITOR_RESPONSE_SCHEMA,
    MonitorMode,
    MonitorProfile,
)
from remora.policy.observation import PolicyObservation, canonical_tool_call_hash
from remora.policy.report import DecisionAction, DecisionReason, DecisionReport
from remora.verification.preconditions import (
    LogicalState,
    ProposalContext,
    ResolutionClass,
)
from remora.verification.registry import PredicateSpec, PreconditionRegistry, ResolverSpec
from remora.verification.resolvers import InMemorySource


def h(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


WORK_ORDER = h("work-order:WO-17")
NOW_MS = 1_800_000_000_000
NOW_S = NOW_MS // 1000

MACHINE, REVIEW, GRANT, TERMINAL = (ResolutionClass.MACHINE, ResolutionClass.REVIEW,
                                    ResolutionClass.GRANT, ResolutionClass.TERMINAL)

REGISTRY = PreconditionRegistry(
    tools={
        # The ISP example of WS1 §7.4: the port must belong to the work order.
        "set_port_profile": (
            PredicateSpec("target_belongs_to_work_order", MACHINE, "wo-verifier",
                          ("inventory",), subject_argument="port"),
            PredicateSpec("customer_relation", MACHINE, "wo-verifier",
                          ("crm",), subject_argument="customer"),
        ),
        "send_report": (
            PredicateSpec("recipient_may_read", MACHINE, "acl-verifier", ("acl",),
                          subject_argument="recipient"),
        ),
        "share_externally": (
            PredicateSpec("declassification", GRANT, "grant-verifier"),
        ),
        "change_billing": (
            PredicateSpec("change_window_approved", REVIEW, "review-verifier"),
        ),
        "transfer": (
            PredicateSpec("intent_authority", TERMINAL, "intent-verifier"),
        ),
        "lookup_only": (
            PredicateSpec("orphan_check", MACHINE, "wo-verifier"),
        ),
        "nothing_required": (),
    },
    resolvers={
        "inventory": ResolverSpec("inventory", "inventory-db", frozenset({"target_belongs_to_work_order"}),
                                  "resolve:inventory"),
        "crm": ResolverSpec("crm", "crm-db", frozenset({"customer_relation"}), "resolve:crm"),
        "acl": ResolverSpec("acl", "acl-service", frozenset({"recipient_may_read"}), "resolve:acl"),
    },
)
ALL_CAPS = frozenset({"resolve:inventory", "resolve:crm", "resolve:acl"})


class WorkOrderVerifier:
    """PROVED when the system of record ties the subject to this context's work order."""

    verifier_id = "wo-verifier"
    version = "1.0.0"

    def verify(self, precondition: Any, payload: Any, context: ProposalContext):
        if not payload.get("found"):
            return LogicalState.UNKNOWN, "subject_not_in_source"
        record = payload["record"]
        if record.get("tenant") != context.tenant_id:
            return LogicalState.REFUTED, "subject_in_another_tenant"
        if record.get("work_order_hash") != context.intent_authority_hash:
            return LogicalState.REFUTED, "subject_bound_to_another_work_order"
        return LogicalState.PROVED, "bound_to_work_order"


class AclVerifier:
    verifier_id = "acl-verifier"
    version = "1.0.0"

    def verify(self, precondition: Any, payload: Any, context: ProposalContext):
        if not payload.get("found"):
            return LogicalState.UNKNOWN, "recipient_unknown"
        readers = payload["record"].get("readers", [])
        if precondition.subject_ref in readers:
            return LogicalState.PROVED, "recipient_is_reader"
        return LogicalState.REFUTED, "recipient_not_reader"


VERIFIERS = {"wo-verifier": WorkOrderVerifier(), "acl-verifier": AclVerifier()}


def sources(**overrides: Any) -> dict[str, InMemorySource]:
    bound = {"tenant": "t1", "work_order_hash": WORK_ORDER}
    base = {
        "inventory": InMemorySource("inventory", "inventory-db",
                                    {"t1": {"sw1/p4": bound, "sw1/p9": {**bound, "work_order_hash": h("other")}}}),
        "crm": InMemorySource("crm", "crm-db", {"t1": {"C-1": bound}}),
        "acl": InMemorySource("acl", "acl-service", {"t1": {"ops@isp": {"readers": ["ops@isp"]},
                                                            "x@evil": {"readers": ["ops@isp"]}}}),
    }
    base.update(overrides)
    return base


PROFILE = MonitorProfile(
    profile_id="ws1-test", mode=MonitorMode.REQUIRED, model_id="jev-1.13.0",
    question_set_hash=h("qset"), thresholds={"injection": 0.5, "target_mismatch": 0.5},
    language="en", calibration_hash=h("calibration"), semantic_review_role="semantic-reviewer")


def profile(mode: MonitorMode = MonitorMode.REQUIRED, **kw: Any) -> MonitorProfile:
    return replace(PROFILE, mode=mode, **kw)


def context(tool: str = "set_port_profile", args: dict[str, Any] | None = None, *,
            tenant: str = "t1", monitor_profile: MonitorProfile = PROFILE,
            proposal_id: str = "p-1", **overrides: Any) -> tuple[ProposalContext, dict[str, Any]]:
    args = {"port": "sw1/p4", "customer": "C-1", "profile": "gold"} if args is None else args
    fields = dict(proposal_id=proposal_id, tenant_id=tenant, principal_id="agent-7",
                  tool_name=tool,
                  call_hash=canonical_tool_call_hash(name=tool, arguments=args, tenant=tenant),
                  intent_authority_hash=WORK_ORDER, policy_bundle_hash=h("policy"),
                  toolspec_hash=h("toolspec"), profile_hash=monitor_profile.profile_hash,
                  capability_hash=h("caps"), flow_digest=h("flow-absent"), flow_epoch=0,
                  context_version=1)
    fields.update(overrides)
    return ProposalContext(**fields), args


def base_report(action: DecisionAction = DecisionAction.ACCEPT,
                reasons: tuple[DecisionReason, ...] = (DecisionReason.GROUNDED_READ_ACCEPT,)
                ) -> DecisionReport:
    return DecisionReport(action=action, reasons=reasons, risk_estimate=None, confidence=None,
                          coverage_policy="test", evidence_required=False,
                          human_review_required=False, audit_root=None, explanation="",
                          raw_observation=PolicyObservation(question="ws1"))


def response(ctx: ProposalContext, digest: str, *, prof: MonitorProfile = PROFILE,
             scores: dict[str, Any] | None = None, **overrides: Any) -> bytes:
    scores = {"injection": 0.1, "target_mismatch": 0.1} if scores is None else scores
    body: dict[str, Any] = {
        "schema": MONITOR_RESPONSE_SCHEMA, "model_id": prof.model_id,
        "question_set_hash": prof.question_set_hash, "calibration_hash": prof.calibration_hash,
        "language": prof.language, "context_hash": ctx.context_hash,
        "evidence_digest": digest,
        "answers": [{"question_id": q, "score": s} for q, s in scores.items()],
        "uncertainty_codes": [], "hint_precondition_ids": [], "out_of_scope": False}
    body.update(overrides)
    return json.dumps(body).encode()


class ScriptedVerifier:
    """Returns the state named in the payload. For driving every state in a test."""

    version = "test"

    def __init__(self, verifier_id: str) -> None:
        self.verifier_id = verifier_id

    def verify(self, precondition: Any, payload: Any, context: ProposalContext):
        return LogicalState(payload["record"]["state"]), "scripted"


def scripted_checked(ctx: ProposalContext, reqs: Any, states: dict[str, LogicalState],
                     *, revision: int = 0):
    """A real ``check_preconditions`` result whose states are *states* (UNKNOWN if absent)."""
    from remora.verification.check import (
        ResolverEvidence,
        VerificationRequest,
        check_preconditions,
    )

    issued, evidence = {}, []
    for pre in reqs.preconditions:
        state = states.get(pre.predicate_id, LogicalState.UNKNOWN)
        if state is LogicalState.UNKNOWN or not pre.resolver_ids:
            continue
        rid = pre.resolver_ids[0]
        wanted = [LogicalState.PROVED, LogicalState.REFUTED] if state is LogicalState.CONFLICT else [state]
        for i, s in enumerate(wanted):
            req = VerificationRequest(f"{pre.predicate_id}:{i}", ctx.context_hash, revision,
                                      pre.precondition_id, rid, pre.subject_ref, NOW_MS + 1000, "b")
            payload = json.dumps({"found": True, "record": {"state": s.value}}).encode()
            issued[req.request_id] = req
            evidence.append(ResolverEvidence(
                req.request_id, rid, REGISTRY.resolvers[rid].source_id, pre.subject_ref, "v1",
                ctx.tenant_id, NOW_S - 1, NOW_S + 30, payload,
                hashlib.sha256(payload).hexdigest(), "test"))
    verifiers = {p.verifier_id: ScriptedVerifier(p.verifier_id) for p in reqs.preconditions}
    return check_preconditions(ctx, reqs, evidence, issued=issued, registry=REGISTRY,
                               verifiers=verifiers, now_s=NOW_S, evidence_revision=revision)

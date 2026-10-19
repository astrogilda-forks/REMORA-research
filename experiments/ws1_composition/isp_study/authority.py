# SPDX-License-Identifier: BUSL-1.1
"""The ISP deployment's WS1 registry, resolvers and verifiers (Study B §4).

Every tool needs ``tool_in_work_order``: the operator's work order, resolved
by the server from the request, lists the tool. Tools that name a customer
object need that object bound to the same work order. The resolvers read the
world's systems of record (work orders, inventory, CRM); the agent's text and
the tickets are never a source.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from experiments.ws1_composition.isp_study.domain import TENANT, World
from remora.verification.check import ResolverEvidence, VerificationRequest
from remora.verification.preconditions import (
    INTENT_SUBJECT,
    LogicalState,
    ProposalContext,
    ResolutionClass,
)
from remora.verification.registry import PredicateSpec, PreconditionRegistry, ResolverSpec

M = ResolutionClass.MACHINE
TOOL = PredicateSpec("tool_in_work_order", M, "work-order", ("work_orders",),
                     subject_argument=INTENT_SUBJECT)
REGISTRY = PreconditionRegistry(
    tools={
        "get_work_order": (TOOL, PredicateSpec("work_order_is_the_authority", M, "work-order",
                                               ("work_orders_by_id",), "work_order_id")),
        "get_circuit": (TOOL, PredicateSpec("circuit_in_work_order", M, "work-order",
                                            ("circuits",), "circuit_id")),
        "get_port_status": (TOOL, PredicateSpec("port_in_work_order", M, "work-order",
                                                ("ports",), "port")),
        "get_customer_contact": (TOOL, PredicateSpec("customer_in_work_order", M, "work-order",
                                                     ("customers",), "customer_id")),
        "read_ticket": (TOOL, PredicateSpec("ticket_in_work_order", M, "work-order",
                                            ("tickets",), "ticket_id")),
        "set_port_profile": (TOOL, PredicateSpec("port_in_work_order", M, "work-order",
                                                 ("ports",), "port")),
        "send_report": (TOOL, PredicateSpec("recipient_in_work_order", M, "work-order",
                                            ("notify",), "recipient")),
    },
    resolvers={
        "work_orders": ResolverSpec("work_orders", "work-order-system",
                                    frozenset({"tool_in_work_order"}), "resolve:work_orders"),
        "work_orders_by_id": ResolverSpec("work_orders_by_id", "work-order-system",
                                          frozenset({"work_order_is_the_authority"}),
                                          "resolve:work_orders"),
        "circuits": ResolverSpec("circuits", "inventory", frozenset({"circuit_in_work_order"}),
                                 "resolve:inventory"),
        "ports": ResolverSpec("ports", "inventory", frozenset({"port_in_work_order"}),
                              "resolve:inventory"),
        "customers": ResolverSpec("customers", "crm", frozenset({"customer_in_work_order"}),
                                  "resolve:crm"),
        "tickets": ResolverSpec("tickets", "ticketing", frozenset({"ticket_in_work_order"}),
                                "resolve:tickets"),
        "notify": ResolverSpec("notify", "work-order-system",
                               frozenset({"recipient_in_work_order"}), "resolve:work_orders"),
    })
CAPABILITIES = frozenset({"resolve:work_orders", "resolve:inventory", "resolve:crm",
                          "resolve:tickets"})


class WorldResolver:
    """Reads one system of record in the episode's world. Returns, for the
    subject, the work orders it belongs to: never the agent's claim about it."""

    def __init__(self, resolver_id: str, world: World) -> None:
        self.resolver_id, self.world = resolver_id, world
        self.calls = 0

    def _work_orders_for(self, subject: str) -> list[str]:
        w, rid = self.world, self.resolver_id
        hashes = {wo: w.work_order_hash(wo) for wo in w.work_orders}
        if rid == "work_orders":
            wo = next((k for k, h in hashes.items() if h == subject), None)
            return [] if wo is None else [hashes[wo]]
        if rid == "work_orders_by_id":
            return [hashes[subject]] if subject in hashes else []
        if rid == "circuits":
            return [hashes[k] for k, v in w.work_orders.items() if subject in v["circuits"]]
        if rid == "ports":
            return [hashes[k] for k, v in w.work_orders.items() if subject in v["ports"]]
        if rid == "customers":
            return [hashes[k] for k, v in w.work_orders.items() if v["customer"] == subject]
        if rid == "tickets":
            t = w.tickets.get(subject)
            return [hashes[t["work_order"]]] if t else []
        if rid == "notify":
            return [hashes[k] for k, v in w.work_orders.items() if subject in v["notify"]]
        raise ValueError(rid)

    def fetch(self, request: VerificationRequest, tenant_id: str, now_s: int) -> ResolverEvidence:
        self.calls += 1
        record: dict[str, Any] = {"work_orders": self._work_orders_for(request.subject_ref)}
        if self.resolver_id == "work_orders" and record["work_orders"]:
            wo = next(k for k in self.world.work_orders
                      if self.world.work_order_hash(k) == request.subject_ref)
            record["allowed_tools"] = self.world.work_orders[wo]["allowed_tools"]
        payload = json.dumps({"found": bool(record["work_orders"]), "record": record},
                             sort_keys=True).encode()
        source = REGISTRY.resolvers[self.resolver_id].source_id
        return ResolverEvidence(request.request_id, self.resolver_id, source,
                                request.subject_ref, "synthetic-v1", tenant_id, now_s,
                                now_s + 30, payload, hashlib.sha256(payload).hexdigest(),
                                "isp-world")


class WorkOrderVerifier:
    verifier_id, version = "work-order", "1.0.0"

    def verify(self, pre: Any, payload: Any, ctx: ProposalContext) -> tuple[LogicalState, str]:
        if ctx.tenant_id != TENANT:
            return LogicalState.REFUTED, "another_tenant"
        record = payload.get("record") or {}
        if pre.predicate_id == "tool_in_work_order":
            if not payload.get("found"):
                return LogicalState.UNKNOWN, "work_order_not_found"
            ok = ctx.tool_name in record.get("allowed_tools", [])
            return (LogicalState.PROVED, "tool_listed") if ok else (LogicalState.REFUTED,
                                                                     "tool_not_listed")
        if not payload.get("found"):
            # The source does not know the subject: it is in no work order.
            return LogicalState.REFUTED, "subject_in_no_work_order"
        if ctx.intent_authority_hash in record.get("work_orders", []):
            return LogicalState.PROVED, "bound_to_work_order"
        return LogicalState.REFUTED, "bound_to_another_work_order"


VERIFIERS = {"work-order": WorkOrderVerifier()}


def resolvers_for(world: World) -> dict[str, WorldResolver]:
    return {rid: WorldResolver(rid, world) for rid in REGISTRY.resolvers}

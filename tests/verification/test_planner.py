# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1-07: bounded verification, hints that only reorder, families (A08, A09, A14-A16)."""
from __future__ import annotations

import itertools

import pytest

from remora.verification.planner import (
    FamilyLedger,
    PlannerMode,
    VerificationBudget,
    plan_verification,
    run_verification,
)
from remora.verification.preconditions import LogicalState, derive_preconditions
from remora.verification.resolvers import InMemorySource
from tests.verification._ws1 import (
    ALL_CAPS,
    NOW_MS,
    REGISTRY,
    VERIFIERS,
    context,
    scripted_checked,
    sources,
)


class Clock:
    def __init__(self, start: int = NOW_MS, step: int = 10) -> None:
        self.now, self.step = start, step

    def __call__(self) -> int:
        self.now += self.step
        return self.now


def _run(mode=PlannerMode.H_DET, ctx_args=None, budget=None, caps=ALL_CAPS, srcs=None,
         hints=None, clock=None):
    ctx, args = ctx_args or context()
    reqs = derive_preconditions(ctx, args, REGISTRY)
    srcs = srcs or sources()
    run = run_verification(ctx, reqs, registry=REGISTRY, verifiers=VERIFIERS, resolvers=srcs,
                           held_capabilities=caps, mode=mode,
                           budget=budget or VerificationBudget(), clock_ms=clock or Clock(),
                           hints_for=(lambda _c: hints) if hints is not None else None)
    return run, reqs, srcs


def test_h_det_recovers_a_resolvable_call():
    run, reqs, _ = _run()
    assert run.stop_reason == "machine_preconditions_settled"
    assert all(run.checked.state(p.precondition_id) is LogicalState.PROVED for p in reqs.preconditions)
    assert run.budget.spent_calls == 2


def test_h0_makes_no_lookup():
    run, _, srcs = _run(PlannerMode.H0)
    assert run.stop_reason == "no_verification_in_h0"
    assert not any(s.calls for s in srcs.values())


def test_a_refuted_target_stays_refused():
    run, reqs, _ = _run(ctx_args=context(args={"port": "sw1/p9", "customer": "C-1", "profile": "g"}))
    assert run.stop_reason == "refuted_or_conflict"


def test_verification_makes_progress_or_stops_within_limits():
    """A14: no call past the budget, the round limit or the deadline; none after stop."""
    for calls, rounds, per in itertools.product(range(4), range(3), range(1, 3)):
        budget = VerificationBudget(max_rounds=rounds, max_resolver_calls=calls,
                                    requests_per_round=per)
        run, _, srcs = _run(budget=budget)
        made = sum(len(s.calls) for s in srcs.values())
        assert made <= calls and made <= rounds * per
        assert run.budget.rounds <= rounds
    # A source that never has the record: lookups stop when nothing is left to try.
    empty = {k: InMemorySource(k, v.source_id, {}) for k, v in sources().items()}
    run, _, srcs = _run(srcs=empty)
    assert run.stop_reason in ("no_progress", "no_candidate")
    assert sum(len(s.calls) for s in srcs.values()) == 2  # one per resolver, deduplicated
    # The wall deadline stops the loop before any lookup.
    run, _, srcs = _run(clock=Clock(step=10_000))
    assert run.stop_reason == "deadline" and not any(s.calls for s in srcs.values())


def test_advisory_priority_cannot_change_requirement_or_verifier():
    """A15: hints reorder open preconditions; they do not add, remove or redefine one."""
    ctx, args = context()
    reqs = derive_preconditions(ctx, args, REGISTRY)
    checked = scripted_checked(ctx, reqs, {})
    port, customer = (p.precondition_id for p in reqs.preconditions)
    budget = VerificationBudget(requests_per_round=1)
    det, _ = plan_verification(reqs, checked, budget, PlannerMode.H_DET)
    edv, rejected = plan_verification(reqs, checked, budget, PlannerMode.H_EDV, hints=[customer])
    assert det == [(port, "inventory")] and edv == [(customer, "crm")] and rejected == ()
    # A hint for a settled precondition, or for an ID not in the set, is dropped.
    settled = scripted_checked(ctx, reqs, {"customer_relation": LogicalState.PROVED})
    edv, rejected = plan_verification(reqs, settled, budget, PlannerMode.H_EDV,
                                      hints=[customer, "new_predicate"])
    assert edv == [(port, "inventory")] and set(rejected) == {customer, "new_predicate"}
    for mode in (PlannerMode.H_DET, PlannerMode.H_EDV, PlannerMode.H_RANDOM):
        plan, _ = plan_verification(reqs, checked, VerificationBudget(), mode, hints=[customer])
        assert {pid for pid, _ in plan} <= {port, customer}
        assert all(rid in reqs.by_id(pid).resolver_ids for pid, rid in plan)


def test_hints_cannot_introduce_url_query_tenant_or_credential():
    """A08: anything outside the open precondition IDs is dropped before any egress."""
    hostile = ["https://evil.example/x", "SELECT * FROM users", "tenant:t2", "Bearer abc",
               "../../etc/passwd", "inventory"]
    run, _, srcs = _run(PlannerMode.H_EDV, hints=hostile)
    assert set(run.rejected_hints) == set(hostile)
    assert {r for s in srcs.values() for r in s.calls} == set(run.issued)
    assert {req.resolver_id for req in run.issued.values()} <= {"inventory", "crm"}
    assert run.stop_reason == "machine_preconditions_settled"


def test_read_lookup_needs_its_own_bounded_capability():
    """A09: no resolve capability, no lookup; the read capability is not the write one."""
    run, _, srcs = _run(caps=frozenset())
    assert not any(s.calls for s in srcs.values())
    assert {why for _, why in run.refused_requests} == {"resolve_capability_not_held"}
    only_inventory, _, srcs = _run(caps=frozenset({"resolve:inventory"}))
    assert srcs["inventory"].calls and not srcs["crm"].calls
    assert only_inventory.checked.state(
        only_inventory.requirements.preconditions[1].precondition_id) is LogicalState.UNKNOWN


def test_family_budget_cannot_be_reset_by_equivalent_proposals():
    """A16: a new client ID for the same call is the same attempt; a fourth distinct call is refused."""
    ledger = FamilyLedger()
    for i in range(10):
        assert ledger.admit("fam-1", context(proposal_id=f"p-{i}")[0])
    for port in ("sw1/p5", "sw1/p6"):
        assert ledger.admit("fam-1", context(args={"port": port, "customer": "C-1",
                                                   "profile": "gold"})[0])
    assert not ledger.admit("fam-1", context(args={"port": "sw1/p7", "customer": "C-1",
                                                   "profile": "gold"})[0])
    assert ledger.admit("fam-2", context(args={"port": "sw1/p7", "customer": "C-1",
                                               "profile": "gold"})[0])


def test_random_order_is_seeded():
    ctx, args = context()
    reqs = derive_preconditions(ctx, args, REGISTRY)
    checked = scripted_checked(ctx, reqs, {})
    plans = {tuple(plan_verification(reqs, checked, VerificationBudget(), PlannerMode.H_RANDOM,
                                     seed=20261019)[0]) for _ in range(5)}
    assert len(plans) == 1


@pytest.mark.parametrize("field", ["max_rounds", "max_resolver_calls", "wall_deadline_ms"])
def test_budget_refuses_negative_or_non_integer_limits(field):
    with pytest.raises(ValueError):
        VerificationBudget(**{field: -1})
    with pytest.raises(ValueError):
        VerificationBudget(**{field: 1.5})


def test_hint_requests_are_charged_to_the_monitor_budget():
    asked = []

    def hints(checked):
        asked.append(checked.evidence_revision)
        return ()

    ctx, args = context()
    reqs = derive_preconditions(ctx, args, REGISTRY)
    run = run_verification(ctx, reqs, registry=REGISTRY, verifiers=VERIFIERS, resolvers=sources(),
                           held_capabilities=ALL_CAPS, mode=PlannerMode.H_EDV,
                           budget=VerificationBudget(max_monitor_calls=1, requests_per_round=1),
                           clock_ms=Clock(), hints_for=hints)
    assert len(asked) == 1 and run.budget.spent_monitor_calls == 1
    assert run.stop_reason == "machine_preconditions_settled"  # ran on in H_DET order


def test_monitor_time_does_not_spend_the_lookup_deadline():
    """A slow hint request (Study B pilot v2: several seconds of Opus) must not
    push the next lookup past the wall deadline."""
    clock = Clock(step=10)

    def slow_hints(checked):
        clock.now += 8_000  # longer than the 5-second wall budget
        return ()

    ctx, args = context()
    reqs = derive_preconditions(ctx, args, REGISTRY)
    run = run_verification(ctx, reqs, registry=REGISTRY, verifiers=VERIFIERS, resolvers=sources(),
                           held_capabilities=ALL_CAPS, mode=PlannerMode.H_EDV,
                           budget=VerificationBudget(requests_per_round=1), clock_ms=clock,
                           hints_for=slow_hints)
    assert run.stop_reason == "machine_preconditions_settled"
    assert not [r for _, r in run.refused_requests if r == "resolver_timeout"]

# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1-07: bounded verification, hints that only reorder, families (A08, A09, A14-A16)."""
from __future__ import annotations

import itertools

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import sqlite3

import pytest

from remora.verification.check import check_preconditions
from remora.verification.planner import (
    FamilyLedger,
    LookupEstimate,
    PlannerMode,
    TaskCallLedger,
    VerificationBudget,
    choose_next_by_cost,
    plan_verification,
    run_verification,
)
from remora.verification.preconditions import LogicalState, derive_preconditions
from remora.verification.resolvers import InMemorySource
from tests.verification._ws1 import (
    ALL_CAPS,
    NOW_MS,
    NOW_S,
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


# ── SDD v2 F-01, F-02 and AR-025 (H_COST) regressions ──────────────────


def test_f01_deadline_stops_second_lookup_within_round_and_boundary_is_closed():
    """SDD v2 F-01 (AR-009): when the first lookup advances past or to the
    deadline, the second planned lookup in the same round must not start."""
    for advance_ms, expected_evidence in ((101, 0), (100, 0), (0, 2)):
        clock_val = [NOW_MS]
        called: list[str] = []
        deployed = sources()

        class SlowSource:
            def __init__(self, delegate, adv=advance_ms):
                self.delegate = delegate
                self.resolver_id = delegate.resolver_id
                self._adv = adv

            def fetch(self, request, tenant_id, now_s):
                called.append(self.resolver_id)
                result = self.delegate.fetch(request, tenant_id, now_s)
                clock_val[0] += self._adv
                return result

        ctx, args = context()
        req = derive_preconditions(ctx, args, REGISTRY)
        run = run_verification(
            ctx, req, registry=REGISTRY, verifiers=VERIFIERS,
            resolvers={k: SlowSource(v) for k, v in deployed.items()},
            held_capabilities=ALL_CAPS, mode=PlannerMode.H_DET,
            budget=VerificationBudget(
                wall_deadline_ms=100, resolver_timeout_ms=100, requests_per_round=2,
            ),
            clock_ms=lambda c=clock_val: c[0],
        )
        if advance_ms >= 100:
            assert len(called) == 1
            assert run.budget.spent_calls == 1
            assert len(run.evidence) == expected_evidence
            assert run.stop_reason == "deadline"
        else:
            assert len(called) == 2
            assert len(run.evidence) == 2
            assert run.stop_reason == "machine_preconditions_settled"


@pytest.mark.parametrize("field", ["spent_calls", "spent_monitor_calls", "rounds"])
@pytest.mark.parametrize("bad_value", [-1, True, 100])
def test_f02_budget_refuses_corrupt_consumption_counters(field, bad_value):
    """SDD v2 F-02 (AR-009): negative, boolean or over-limit consumption counters fail closed."""
    with pytest.raises(ValueError):
        VerificationBudget(**{field: bad_value})


def _cost_fixture(tool: str = "set_port_profile", args: dict | None = None):
    ctx, arguments = context(tool, args)
    req = derive_preconditions(ctx, arguments, REGISTRY)
    checked = check_preconditions(
        ctx, req, (), issued={}, registry=REGISTRY,
        verifiers=VERIFIERS, now_s=NOW_S, evidence_revision=0,
    )
    prices = {
        (p.precondition_id, r): LookupEstimate(10, 500_000)
        for p in req.preconditions for r in p.resolver_ids
    }
    return req, checked, prices


def test_h_cost_ranks_by_cost_per_settlement_and_respects_registered_bounds():
    """SDD v2 AR-025: H_COST ranks registered MACHINE/UNKNOWN candidates by
    cost_units / settle_ppm and refuses unregistered, unpriced or out-of-bounds inputs."""
    req, checked, prices = _cost_fixture()
    # Extra attacker estimate key cannot introduce an unregistered candidate
    prices[("attacker-predicate", "https://attacker.invalid")] = LookupEstimate(1, 1_000_000)
    result = choose_next_by_cost(req, checked, VerificationBudget(), prices, remaining_cost_units=30)
    assert len(result) == 2
    assert all(req.by_id(pid) is not None for pid, _ in result)

    # Cheaper resolver is chosen first and capped by remaining_cost_units
    cheaper = next(k for k in prices if k[1] == "crm")
    prices[cheaper] = LookupEstimate(2, 500_000)
    assert choose_next_by_cost(
        req, checked, VerificationBudget(), prices, remaining_cost_units=2
    ) == (cheaper,)
    plan, _ = plan_verification(
        req, checked, VerificationBudget(), PlannerMode.H_COST,
        estimates=prices, remaining_cost_units=2,
    )
    assert plan == [cheaper]

    # Zero budget or zero remaining cost returns empty
    assert choose_next_by_cost(
        req, checked, VerificationBudget(max_resolver_calls=0), prices, remaining_cost_units=100
    ) == ()
    assert choose_next_by_cost(
        req, checked, VerificationBudget(), prices, remaining_cost_units=0
    ) == ()

    # Missing estimate or mismatched context raises ValueError
    with pytest.raises(ValueError, match="missing deployment estimate"):
        choose_next_by_cost(req, checked, VerificationBudget(), {}, remaining_cost_units=100)
    with pytest.raises(ValueError, match="checked state does not belong"):
        choose_next_by_cost(
            replace(req, context_hash="f" * 64), checked, VerificationBudget(),
            prices, remaining_cost_units=100,
        )

    # Terminal and review preconditions never become machine lookups
    for tool_name in ("transfer", "change_billing"):
        t_req, t_checked, t_prices = _cost_fixture(tool_name, {})
        assert choose_next_by_cost(
            t_req, t_checked, VerificationBudget(), t_prices, remaining_cost_units=100
        ) == ()

    # Invalid LookupEstimate bounds refused
    for cost, prob in ((0, 1), (True, 1), (1, 0), (1, 1_000_001), (1, True)):
        with pytest.raises(ValueError):
            LookupEstimate(cost, prob)


def test_task_call_ledger_atomic_reservation_and_persistence(tmp_path):
    """SDD v2 WP-03 (AR-013..016): durable task-wide reservation with concurrency,
    restart persistence, idempotency-key binding and no-reset protection."""
    db = tmp_path / "task_ledger.sqlite"
    ledger = TaskCallLedger(db)
    binding = "tenant-policy-intent-binding"
    ledger.create("task-1", binding, 3)

    # 1. Concurrent reservations cannot exceed cap=3
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(
            pool.map(lambda i: ledger.reserve("task-1", binding, f"op-{i}", "req-1"), range(32))
        )
    assert sum(outcomes) == 3
    assert ledger.spent("task-1") == 3

    # 2. Reopening preserves consumption and refuses replay as a second dispatch
    ledger2 = TaskCallLedger(db)
    assert ledger2.spent("task-1") == 3
    assert ledger2.reserve("task-1", binding, "op-0", "req-1") is False

    # 3. Same operation_id with changed request_hash raises ValueError
    ledger2.create("task-2", binding, 3)
    assert ledger2.reserve("task-2", binding, "one", "req-1") is True
    assert ledger2.reserve("task-2", binding, "one", "req-1") is False
    with pytest.raises(ValueError, match="idempotency key reused"):
        ledger2.reserve("task-2", binding, "one", "different-request")
    assert ledger2.spent("task-2") == 1

    # 4. Wrong binding refused and no-reset on create
    with pytest.raises(ValueError, match="binding mismatch"):
        ledger2.reserve("task-2", "different-tenant", "two", "req-1")
    with pytest.raises(sqlite3.IntegrityError):
        ledger2.create("task-2", binding, 999)
    assert ledger2.spent("task-2") == 1

    # 5. Invalid units refused and closed task stops new reservations
    for bad_units in (-1, 0, True):
        with pytest.raises(ValueError, match="invalid units"):
            ledger2.reserve("task-2", binding, "two", "req-1", bad_units)
    ledger2.close("task-2", binding)
    assert ledger2.reserve("task-2", binding, "two", "req-1") is False



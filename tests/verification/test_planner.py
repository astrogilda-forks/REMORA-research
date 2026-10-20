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
    choose_next_lookahead,
    diagnose_refusal_causes,
    plan_verification,
    run_verification,
    check_recovery_bundle_consistency,
)
from remora.verification.preconditions import LogicalState, derive_preconditions
from remora.verification.resolvers import (
    BoundedResolverAdapter,
    InMemorySource,
    ResolverAdapterContract,
    ResolverRefused,
    TransportResponse,
)
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


def test_bounded_resolver_adapter_enforces_clocks_destinations_and_limits():
    """SDD v2 WP-02 (AR-010..012): separate monotonic and wall clocks, destination
    allowlist, redirect refusal, raw URL refusal, byte cap, tenant filter and
    source-version pin."""
    from remora.verification.check import VerificationRequest

    contract = ResolverAdapterContract(
        resolver_id="inventory",
        source_id="netbox",
        allowed_destinations=frozenset({"https://netbox.internal.example/api"}),
        required_capability="resolve:inventory",
        expected_source_version="v2",
        max_response_bytes=64,
        connect_timeout_ms=100,
        read_timeout_ms=200,
        total_timeout_ms=300,
    )
    mono = [1_000]
    wall = [1_800_000_500]

    def make_req(subject: str = "sw1/p1", deadline_ms: int = 1_500) -> VerificationRequest:
        return VerificationRequest(
            request_id="req-1", context_hash="c" * 64, evidence_revision=0,
            precondition_id="port_in_work_order", resolver_id="inventory",
            subject_ref=subject, deadline_ms=deadline_ms, budget_ref="p-1",
        )

    # 1. Valid response uses wall_clock_s (not mono_clock_ms // 1000) for acquired_at
    adapter_ok = BoundedResolverAdapter(
        contract=contract,
        transport=lambda _req, _t, _to: TransportResponse(
            destination="https://netbox.internal.example/api",
            tenant_id="tenant-a",
            source_version="v2",
            payload=b'{"found":true}',
            connect_ms=20,
            read_ms=40,
        ),
        mono_clock_ms=lambda: mono[0],
        wall_clock_s=lambda: wall[0],
        ttl_s=90,
    )
    ev = adapter_ok.fetch(make_req(), "tenant-a", now_s=1)
    assert ev.acquired_at == 1_800_000_500
    assert ev.valid_until == 1_800_000_590
    assert len(adapter_ok.calls) == 1

    # 2. Raw URL in subject_ref is refused before transport is called
    calls_url: list[str] = []
    adapter_url = BoundedResolverAdapter(
        contract=contract,
        transport=lambda _r, _t, _to: calls_url.append("called") or TransportResponse(  # type: ignore[func-returns-value]
            destination="https://netbox.internal.example/api",
            tenant_id="tenant-a", source_version="v2", payload=b"{}",
        ),
        mono_clock_ms=lambda: mono[0],
        wall_clock_s=lambda: wall[0],
    )
    with pytest.raises(ResolverRefused, match="raw_url_in_subject_refused"):
        adapter_url.fetch(make_req(subject="https://attacker.invalid/pwn"), "tenant-a", 0)
    assert calls_url == []

    # 3. Redirect, wrong destination, oversized payload, wrong tenant, wrong version, and timeouts
    cases = [
        ("redirect_refused", TransportResponse("https://netbox.internal.example/api", "tenant-a", "v2", b"{}", redirected=True)),
        ("destination_not_allowed", TransportResponse("https://evil.example/api", "tenant-a", "v2", b"{}")),
        ("response_too_large", TransportResponse("https://netbox.internal.example/api", "tenant-a", "v2", b"x" * 65)),
        ("tenant_mismatch", TransportResponse("https://netbox.internal.example/api", "tenant-b", "v2", b"{}")),
        ("source_version_mismatch", TransportResponse("https://netbox.internal.example/api", "tenant-a", "v1", b"{}")),
        ("transport_timeout", TransportResponse("https://netbox.internal.example/api", "tenant-a", "v2", b"{}", connect_ms=150)),
        ("transport_timeout", TransportResponse("https://netbox.internal.example/api", "tenant-a", "v2", b"{}", read_ms=250)),
    ]
    for expected_reason, resp in cases:
        ad = BoundedResolverAdapter(
            contract=contract,
            transport=lambda _r, _t, _to, r=resp: r,
            mono_clock_ms=lambda: mono[0],
            wall_clock_s=lambda: wall[0],
        )
        with pytest.raises(ResolverRefused, match=expected_reason):
            ad.fetch(make_req(), "tenant-a", 0)

    # 4. Expired request deadline refused before transport
    with pytest.raises(ResolverRefused, match="request_deadline_expired"):
        adapter_ok.fetch(make_req(deadline_ms=1_000), "tenant-a", 0)


def test_h_ar_bounded_lookahead_and_multi_cause_diagnostics():
    """SDD v2 WP-05/WP-06 (AR-023, AR-026..028):
    - H_AR selects a feasible joint plan when H_COST's greedy choice would leave
      insufficient budget for the second required precondition;
    - H_AR never mutates CheckedPreconditions and respects CPU deadlines and bounds;
    - diagnose_refusal_causes preserves multiple simultaneous refusal causes."""
    import types
    from remora.verification.registry import (
        PreconditionRegistry,
        PredicateSpec,
        ResolverSpec,
    )
    from remora.verification.preconditions import ResolutionClass

    # Build a 2-predicate requirement set where p1 has two resolvers (cheap=4, expensive=7)
    # and p2 has one resolver (cost=5), with total remaining_cost_units=9:
    # Greedy H_COST picks p2 (cost=5, settle=900k -> 5/0.9=5.55) if p1_exp has (cost=7, settle=1M)
    # and p1_cheap has (cost=4, settle=700k -> 4/0.7=5.71), which leaves 9-5=4 so p1_cheap still fits;
    # whereas if p2 has two resolvers: p2_greedy (cost=6, settle=950k -> 6/0.95=6.31) and
    # p2_frugal (cost=4, settle=600k -> 4/0.6=6.66), and p1 only has r1 (cost=5, settle=700k -> 5/0.7=7.14):
    # At remaining_cost_units=9:
    # - Greedy H_COST picks (p2, r_greedy) first (ratio 6.31 < 6.66 < 7.14), spending 6 and leaving 3 < 5,
    #   so p1 CANNOT be resolved in round 2!
    # - Lookahead H_AR sees that only ((p2, r_frugal), (p1, r1)) or ((p1, r1), (p2, r_frugal))
    #   has total cost 4 + 5 = 9 <= 9 and settles both required preconditions!
    reg = PreconditionRegistry(
        tools={
            "set_port_profile": (
                PredicateSpec("p1", ResolutionClass.MACHINE, "v_port", ("r1",), subject_argument="port"),
                PredicateSpec("p2", ResolutionClass.MACHINE, "v_cust", ("r_frugal", "r_greedy"), subject_argument="customer"),
            )
        },
        resolvers={
            "r1": ResolverSpec("r1", "s1", frozenset({"p1"}), "cap:1"),
            "r_frugal": ResolverSpec("r_frugal", "s2", frozenset({"p2"}), "cap:2"),
            "r_greedy": ResolverSpec("r_greedy", "s3", frozenset({"p2"}), "cap:3"),
        },
    )
    ctx, args = context()
    reqs = derive_preconditions(ctx, args, reg)
    checked = check_preconditions(
        ctx, reqs, (), issued={}, registry=reg,
        verifiers=VERIFIERS, now_s=NOW_S, evidence_revision=0,
    )
    p1_id, p2_id = (p.precondition_id for p in reqs.preconditions)
    estimates = {
        (p1_id, "r1"): LookupEstimate(5, 700_000),
        (p2_id, "r_greedy"): LookupEstimate(6, 950_000),
        (p2_id, "r_frugal"): LookupEstimate(4, 600_000),
    }
    budget1 = VerificationBudget(requests_per_round=1, max_resolver_calls=2)

    greedy_choice = choose_next_by_cost(reqs, checked, budget1, estimates, remaining_cost_units=9)
    assert greedy_choice == ((p2_id, "r_greedy"),)

    ar_choice = choose_next_lookahead(reqs, checked, budget1, estimates, remaining_cost_units=9)
    assert ar_choice in (((p2_id, "r_frugal"),), ((p1_id, "r1"),))
    # And checked state is untouched (AR-026)
    assert checked.state(p1_id) is LogicalState.UNKNOWN
    assert checked.state(p2_id) is LogicalState.UNKNOWN

    # plan_verification dispatches H_AR
    plan_ar, _ = plan_verification(
        reqs, checked, budget1, PlannerMode.H_AR,
        estimates=estimates, remaining_cost_units=9,
    )
    assert tuple(plan_ar) == ar_choice

    # Bounds checks on H_AR parameters
    for kw in (
        {"max_candidates": 65},
        {"max_depth": 4},
        {"beam_width": 17},
        {"remaining_cost_units": -1},
    ):
        with pytest.raises(ValueError):
            choose_next_lookahead(reqs, checked, budget1, estimates, **{"remaining_cost_units": 9, **kw})

    # AR-023: multi-cause refusal diagnostic keeps all simultaneous causes
    fake_rec = types.SimpleNamespace(
        base_reasons=("cross_tenant_argument_blocked",),
        review_class="review",
        monitor_veto=True,
        monitor_status="assessed:veto",
    )
    causes = diagnose_refusal_causes(reqs, checked, fake_rec, agent_error=True)
    assert causes == (
        "hard_deny",
        "machine_uncertainty",
        "review_required",
        "monitor_veto_or_outage",
        "agent_error",
    )


def test_self_reported_recovery_bundle_consistency_and_tamper_suite():
    """Self-reported consistency only: these unsigned fixture bytes establish no
    authority, signature authenticity or independent effect verification."""
    import copy
    import hashlib

    grant_bytes = b'{"jti":"g-1","context_hash":"ctx-1","sig":"ed25519"}'
    payload_bytes = b'{"found":true,"port":"sw1/p1"}'
    valid_bundle = {
        "context_hash": "c" * 64,
        "requirements_hash": "r" * 64,
        "evidence_digest": "e" * 64,
        "profile_hash": "p" * 64,
        "policy_bundle_hash": "b" * 64,
        "toolspec_hash": "t" * 64,
        "key_id": "key-ed25519-1",
        "signed_grant_bytes": grant_bytes,
        "expected_grant_sha256": hashlib.sha256(grant_bytes).hexdigest(),
        "tenant_id": "tenant-a",
        "proposal_id": "prop-1",
        "verified_at_s": 1_800_000_010,
        "requirements": {
            "context_hash": "c" * 64,
            "requirements_hash": "r" * 64,
            "authorizable": True,
            "preconditions": [
                {
                    "precondition_id": "pre_port",
                    "required": True,
                    "resolution_class": "machine",
                    "subject_ref": "sw1/p1",
                    "expected_source_version": "v2",
                },
                {
                    "precondition_id": "pre_review",
                    "required": True,
                    "resolution_class": "review",
                    "review_role": "senior_authority",
                },
            ],
        },
        "evidence_records": [
            {
                "precondition_id": "pre_port",
                "tenant_id": "tenant-a",
                "subject_ref": "sw1/p1",
                "source_version": "v2",
                "acquired_at": 1_800_000_000,
                "valid_until": 1_800_000_060,
                "payload": payload_bytes,
                "payload_hash": hashlib.sha256(payload_bytes).hexdigest(),
                "proved": True,
            }
        ],
        "review_attestation": {
            "proposal_id": "prop-1",
            "approver": "alice",
            "approver_role": "senior_authority",
        },
        "observer_report": {
            "observer_complete": True,
            "desired_delta_matched": True,
            "unauthorized_side_effects": [],
        },
    }

    ok, problems = check_recovery_bundle_consistency(valid_bundle)
    assert ok and problems == ()

    # Single-change internal-consistency checks; not independent verification.
    def tamper(mutator):
        b = copy.deepcopy(valid_bundle)
        mutator(b)
        return check_recovery_bundle_consistency(b)

    tampers = [
        ("grant_bytes_digest_mismatch", lambda b: b.__setitem__("signed_grant_bytes", grant_bytes + b"x")),
        ("context_hash_mismatch", lambda b: b["requirements"].__setitem__("context_hash", "0" * 64)),
        ("requirements_hash_mismatch", lambda b: b["requirements"].__setitem__("requirements_hash", "0" * 64)),
        ("requirements_not_authorizable", lambda b: b["requirements"].__setitem__("authorizable", False)),
        ("evidence_tenant_mismatch:pre_port", lambda b: b["evidence_records"][0].__setitem__("tenant_id", "tenant-b")),
        ("evidence_subject_mismatch:pre_port", lambda b: b["evidence_records"][0].__setitem__("subject_ref", "sw1/p9")),
        ("evidence_source_version_mismatch:pre_port", lambda b: b["evidence_records"][0].__setitem__("source_version", "v1")),
        ("evidence_stale_or_future:pre_port", lambda b: b["evidence_records"][0].__setitem__("valid_until", 1_800_000_010)),
        ("evidence_payload_hash_mismatch:pre_port", lambda b: b["evidence_records"][0].__setitem__("payload", b"tampered")),
        ("precondition_not_proved:pre_port", lambda b: b["evidence_records"][0].__setitem__("proved", False)),
        ("review_role_mismatch:pre_review", lambda b: b["review_attestation"].__setitem__("approver_role", "reviewer")),
        ("review_proposal_mismatch:pre_review", lambda b: b["review_attestation"].__setitem__("proposal_id", "other-prop")),
        ("observer_incomplete", lambda b: b["observer_report"].__setitem__("observer_complete", False)),
        ("postcondition_delta_mismatch", lambda b: b["observer_report"].__setitem__("desired_delta_matched", False)),
        ("unauthorized_side_effect_observed", lambda b: b["observer_report"].__setitem__("unauthorized_side_effects", ["contact_exported"])),
        ("missing_field:observer_report", lambda b: b.pop("observer_report")),
    ]
    for expected_problem, fn in tampers:
        is_ok, probs = tamper(fn)
        assert not is_ok, f"tamper {expected_problem} was not caught"
        assert expected_problem in probs, (expected_problem, probs)


@pytest.mark.parametrize("mode", [PlannerMode.H_DET, PlannerMode.H_COST])
@pytest.mark.parametrize("call_cap,cost_cap", [(1, 10), (3, 5)])
def test_post_transport_refusal_consumes_call_and_cost_budget(mode, call_cap, cost_cap):
    ctx, args = context()
    reqs = derive_preconditions(ctx, args, REGISTRY)
    adapters = {}
    for rid, spec in REGISTRY.resolvers.items():
        adapters[rid] = BoundedResolverAdapter(
            ResolverAdapterContract(rid, spec.source_id, frozenset({"https://source.invalid"}),
                                    spec.capability_id),
            lambda _req, tenant, _timeout: TransportResponse(
                "https://source.invalid", tenant, "wrong-version", b"{}"),
            mono_clock_ms=lambda: NOW_MS, wall_clock_s=lambda: NOW_S,
        )
    estimates = {(p.precondition_id, rid): LookupEstimate(5, 1_000_000)
                 for p in reqs.preconditions for rid in p.resolver_ids}
    run = run_verification(
        ctx, reqs, registry=REGISTRY, verifiers=VERIFIERS, resolvers=adapters,
        held_capabilities=ALL_CAPS, mode=mode,
        budget=VerificationBudget(max_rounds=3, max_resolver_calls=call_cap, requests_per_round=1),
        clock_ms=lambda: NOW_MS, estimates=estimates, cost_budget_units=cost_cap,
    )
    assert sum(len(a.calls) for a in adapters.values()) == 1
    assert run.budget.spent_calls == 1


@pytest.mark.parametrize("mode", list(PlannerMode))
def test_cost_budget_applies_to_every_planner_and_whole_round(mode):
    ctx, args = context()
    reqs = derive_preconditions(ctx, args, REGISTRY)
    estimates = {(p.precondition_id, rid): LookupEstimate(2, 1_000_000)
                 for p in reqs.preconditions for rid in p.resolver_ids}
    srcs = sources()
    run = run_verification(
        ctx, reqs, registry=REGISTRY, verifiers=VERIFIERS, resolvers=srcs,
        held_capabilities=ALL_CAPS, mode=mode,
        budget=VerificationBudget(max_rounds=3, max_resolver_calls=3, requests_per_round=2),
        clock_ms=lambda: NOW_MS, estimates=estimates, cost_budget_units=3,
    )
    assert 2 * sum(len(s.calls) for s in srcs.values()) <= 3
    assert 2 * run.budget.spent_calls <= 3


@pytest.mark.parametrize("age_s", [0, 60])
def test_bounded_adapters_use_wall_evidence_time_and_monotonic_deadlines(age_s):
    ctx, args = context()
    reqs = derive_preconditions(ctx, args, REGISTRY)
    srcs = sources()
    adapters = {}
    for rid in ("inventory", "crm"):
        spec = REGISTRY.resolvers[rid]

        def transport(req, tenant, _timeout, source=srcs[rid]):
            # Pure in-memory fixture: no network transport is involved.
            payload = source.fetch(req, tenant, NOW_S).payload
            return TransportResponse("https://source.invalid", tenant, "v1", payload)

        adapters[rid] = BoundedResolverAdapter(
            ResolverAdapterContract(rid, spec.source_id, frozenset({"https://source.invalid"}),
                                    spec.capability_id),
            transport, mono_clock_ms=lambda: 100_000, wall_clock_s=lambda: NOW_S,
            ttl_s=60,
        )
    run = run_verification(
        ctx, reqs, registry=REGISTRY, verifiers=VERIFIERS, resolvers=adapters,
        held_capabilities=ALL_CAPS, mode=PlannerMode.H_DET, budget=VerificationBudget(),
        clock_ms=lambda: 100_000, wall_clock_s=lambda: NOW_S + age_s,
    )
    expected = LogicalState.PROVED if age_s == 0 else LogicalState.UNKNOWN
    assert all(run.checked.state(p.precondition_id) is expected for p in reqs.preconditions)
    assert all(ev.acquired_at == NOW_S for ev in run.evidence)
    assert run.budget.spent_calls == 2





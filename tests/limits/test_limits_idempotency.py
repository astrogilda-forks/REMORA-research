# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Cumulative limits: one operation is charged once, and only what ran stays charged.

Two weaknesses the Horizon #55 stress runs recorded, closed here:

* the same payment proposed twice was charged (and paid) twice. A tool may
  now declare ``idempotency.key_arguments``; a second call with the same key
  refuses while the first is in flight, after it ran and while its outcome
  is unknown, and runs only once the first provably did not;
* a payment that failed kept its reservation for good, so a legitimate
  retry was refused. A reservation is now returned when the call provably
  did not run (the tool raised ``ToolDidNotExecute``, the lease expired
  before the tool started, or a reviewer resolved the outcome), and held
  while the outcome is unknown.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from remora.enforcement import cumulative_limits as cl
from remora.enforcement.lease import ToolDidNotExecute
from remora.execution.outcome import DispatchOutcome, classify_outcome

T0 = 1_800_000_000.0
METERS = {
    "pay": [{"quantity": "spend", "kind": "sum", "argument": "amount", "unit": "JPY"}],
    "move": [{"quantity": "movement", "kind": "change", "argument": "value", "scale": 10,
              "unit": "degC", "resource_argument": "unit"}],
}
LIMITS = [
    {"limit_id": "spend", "tenant": "t", "quantity": "spend", "unit": "JPY", "max": 20000,
     "principal": "p"},
    {"limit_id": "move", "tenant": "t", "quantity": "movement", "unit": "degC", "max": 20,
     "principal": "*", "resource": "*"},
]
IDEMPOTENCY = {"pay": {"key_arguments": ["payee", "amount", "reference"]}}


def policy(idempotency=IDEMPOTENCY, **changes):
    data = {"schema": cl.SCHEMA, "meters": METERS, "limits": LIMITS,
            "baselines": [{"tenant": "t", "quantity": "movement", "resource": "AHU-1",
                           "value": 19.0, "seed_id": "s1"}]}
    if idempotency is not None:
        data["idempotency"] = idempotency
    data.update(changes)
    return cl.LimitPolicy.from_dict(data)


@pytest.fixture()
def guard(tmp_path):
    return cl.LimitGuard(policy(), cl.LimitLedger(tmp_path / "ledger.db"))


def pay(guard, op, reference="INV-1", amount=7000, now=T0, expires_at=None):
    return guard.reserve(tenant="t", principal="p", tool_name="pay",
                         arguments={"payee": "acme", "amount": amount, "reference": reference},
                         operation_id=op, request_hash=f"h-{op}", now=now,
                         expires_at=expires_at)


def spent(guard) -> int:
    return sum(a for op in ("A", "B", "C", "D") for _, a in guard.ledger.charges(op))


# ── idempotency ───────────────────────────────────────────────────────────


def test_the_same_payment_in_flight_refuses_and_is_not_charged(guard):
    assert pay(guard, "A") is None
    assert pay(guard, "B") == cl.DUPLICATE_IN_FLIGHT
    assert guard.ledger.charges("B") == [] and spent(guard) == 7000


def test_the_same_payment_after_it_ran_refuses(guard):
    assert pay(guard, "A") is None
    assert guard.begin("A") is None
    guard.settle("A", ok=True)
    assert pay(guard, "B") == cl.DUPLICATE
    assert guard.preview(tenant="t", principal="p", tool_name="pay",
                         arguments={"payee": "acme", "amount": 7000,
                                    "reference": "INV-1"}) == cl.DUPLICATE


def test_the_same_payment_with_an_unknown_outcome_refuses(guard):
    assert pay(guard, "A") is None
    guard.settle("A", ok=False)
    assert pay(guard, "B") == cl.OUTCOME_UNKNOWN


def test_the_same_payment_runs_again_once_the_first_provably_did_not(guard):
    assert pay(guard, "A") is None
    guard.release("A")
    assert pay(guard, "B") is None
    assert spent(guard) == 7000


def test_another_reference_is_another_operation(guard):
    assert pay(guard, "A") is None
    assert pay(guard, "B", reference="INV-2") is None
    assert spent(guard) == 14000


def test_a_retry_of_the_same_lease_is_not_a_duplicate(guard):
    assert pay(guard, "A") is None
    assert pay(guard, "A") is None
    assert spent(guard) == 7000


@pytest.mark.parametrize("arguments", [
    {"payee": "acme", "amount": 7000},
    {"payee": "acme", "amount": 7000, "reference": ""},
    {"payee": "acme", "amount": 7000, "reference": True},
    {"payee": "acme", "amount": 7000, "reference": ["INV-1"]},
])
def test_a_payment_that_cannot_be_identified_does_not_run(guard, arguments):
    assert guard.reserve(tenant="t", principal="p", tool_name="pay", arguments=arguments,
                         operation_id="A", request_hash="h", now=T0) == \
        cl.IDEMPOTENCY_KEY_INVALID


def test_without_a_declared_key_two_calls_are_two_operations(tmp_path):
    guard = cl.LimitGuard(policy(idempotency=None), cl.LimitLedger(tmp_path / "l.db"))
    assert pay(guard, "A") is None and pay(guard, "B") is None
    assert spent(guard) == 14000


@pytest.mark.parametrize("idempotency", [
    {"refund": {"key_arguments": ["reference"]}},
    {"pay": {"key_arguments": []}},
    {"pay": {"key_arguments": ["reference", "reference"]}},
    {"pay": ["reference"]},
    ["pay"],
])
def test_a_malformed_idempotency_declaration_refuses_at_load(idempotency):
    with pytest.raises(cl.LimitPolicyError):
        policy(idempotency=idempotency)


# ── a reservation is held only while the call may have run ───────────────


def test_an_unknown_outcome_holds_the_budget_until_resolved(guard):
    assert pay(guard, "A") is None and guard.begin("A") is None
    guard.settle("A", ok=False)
    assert [o["operation_id"] for o in guard.unresolved("t")] == ["A"]
    assert pay(guard, "B", reference="INV-2", amount=14000) == cl.EXCEEDED
    assert guard.resolve(tenant="t", operation_id="A", executed=False,
                         resolved_by="reviewer-1", reason="rail: no such transfer") is None
    assert guard.unresolved("t") == []
    assert pay(guard, "B", reference="INV-2", amount=13000) is None
    assert pay(guard, "C") is None  # A's key is free again: it never ran
    assert spent(guard) == 20000


def test_an_outcome_resolved_as_executed_stays_charged_and_blocks_a_duplicate(guard):
    assert pay(guard, "A") is None and guard.begin("A") is None
    guard.settle("A", ok=False)
    assert guard.resolve(tenant="t", operation_id="A", executed=True,
                         resolved_by="reviewer-1") is None
    assert pay(guard, "B") == cl.DUPLICATE
    assert spent(guard) == 7000


@pytest.mark.parametrize("tenant, op, by, want", [
    ("t", "A", "p", cl.RESOLVER_IS_PRINCIPAL),       # the agent cannot free its own budget
    ("t", "A", "", cl.RESOLVER_IS_PRINCIPAL),
    ("other", "A", "reviewer-1", cl.NOT_FOUND),       # another tenant's operation
    ("t", "Z", "reviewer-1", cl.NOT_FOUND),
])
def test_resolving_is_refused_to_the_wrong_party(guard, tenant, op, by, want):
    assert pay(guard, "A") is None
    guard.settle("A", ok=False)
    assert guard.resolve(tenant=tenant, operation_id=op, executed=False, resolved_by=by) == want
    assert spent(guard) == 7000


@pytest.mark.parametrize("state", ["reserved", "settled", "released"])
def test_only_an_unknown_outcome_can_be_resolved(guard, state):
    assert pay(guard, "A") is None
    if state == "settled":
        guard.settle("A", ok=True)
    if state == "released":
        guard.release("A")
    assert guard.resolve(tenant="t", operation_id="A", executed=False,
                         resolved_by="reviewer-1") == cl.NOT_UNKNOWN


def test_a_lease_that_expired_before_the_tool_started_gives_its_reservation_back(guard):
    assert pay(guard, "A", expires_at=T0 + 120) is None
    # The next reservation after expiry releases it, and A can no longer start.
    assert pay(guard, "B", reference="INV-2", amount=14000, now=T0 + 121) is None
    assert guard.begin("A") == cl.RESERVATION_RELEASED
    assert pay(guard, "A", now=T0 + 122) == cl.RESERVATION_RELEASED
    assert spent(guard) == 14000


def test_a_started_operation_is_never_released_by_time(guard):
    assert pay(guard, "A", expires_at=T0 + 120) is None
    assert guard.begin("A") is None
    assert pay(guard, "B", reference="INV-2", amount=14000, now=T0 + 10_000) == cl.EXCEEDED


def test_resolving_a_change_puts_the_value_back(guard):
    move = {"unit": "AHU-1", "value": 20.0}
    assert guard.reserve(tenant="t", principal="p", tool_name="move", arguments=move,
                         operation_id="A", request_hash="h", now=T0) is None
    guard.settle("A", ok=False)                        # the controller did not answer
    nxt = {"unit": "AHU-1", "value": 19.5}
    assert guard.reserve(tenant="t", principal="p", tool_name="move", arguments=nxt,
                         operation_id="B", request_hash="h", now=T0) == cl.BASELINE_UNKNOWN
    assert guard.resolve(tenant="t", operation_id="A", executed=False,
                         resolved_by="reviewer-1") is None
    # Measured from 19.0 again: 0.5, not from the unwritten 20.0.
    assert guard.reserve(tenant="t", principal="p", tool_name="move", arguments=nxt,
                         operation_id="B", request_hash="h", now=T0) is None
    assert guard.ledger.charges("B") == [("move\x1f*\x1fAHU-1", 5)]


# ── the dispatcher and the outcome ────────────────────────────────────────


def _dispatcher(guard):
    from remora.enforcement.lease import GovernedToolDispatcher

    d = GovernedToolDispatcher.__new__(GovernedToolDispatcher)
    d._limit_guard = guard
    return d


def _lease(nonce):
    return SimpleNamespace(tenant_id="t", actor_identity="p", nonce=nonce, expires_at=None,
                           tool_args_hash="h" * 64, proposal_id="prop")


def test_tool_did_not_execute_needs_its_evidence():
    with pytest.raises(ValueError):
        ToolDidNotExecute("", "refused")
    with pytest.raises(ValueError):
        ToolDidNotExecute("rail", "")


def test_the_dispatcher_begin_refuses_a_released_reservation(guard):
    d = _dispatcher(guard)
    args = {"payee": "acme", "amount": 7000, "reference": "INV-1"}
    assert d._limit_refusal(_lease("n1"), "pay", args, args, None) is None
    assert d._limit_begin(_lease("n1"), "pay") is None
    assert d._limit_begin(_lease("n0"), "unmetered") is None
    guard.ledger.release("lease:n1")
    assert d._limit_begin(_lease("n1"), "pay") == cl.RESERVATION_RELEASED


def test_an_adapters_proof_makes_the_outcome_failed_not_unknown():
    base = {"executed": False, "dispatch_began": True}
    assert classify_outcome(base) is DispatchOutcome.UNKNOWN
    proof = {**base, "pre_effect_proof": {"source": "rail", "detail": "refused: 402"}}
    assert classify_outcome(proof) is DispatchOutcome.FAILED
    half = {**base, "pre_effect_proof": {"source": "rail", "detail": ""}}
    assert classify_outcome(half) is DispatchOutcome.UNKNOWN

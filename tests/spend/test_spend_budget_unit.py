# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""SpendPolicy validation, SpendGuard reservation and the dispatcher hook."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from remora.enforcement import spend_budget as sb

TOOLS = {"pay": {"amount_argument": "amount", "unit_argument": "unit"}}
BUDGET = {"budget_id": "b1", "tenant": "t", "principal": "p", "unit": "JPY", "limit": 20000}


def policy(**changes):
    data = {"schema": sb.SCHEMA, "tools": TOOLS, "budgets": [BUDGET]}
    data.update(changes)
    return sb.SpendPolicy.from_dict(data)


@pytest.fixture()
def guard(tmp_path):
    return sb.SpendGuard(policy(), sb.SpendLedger(tmp_path / "ledger.db"))


def reserve(guard, amount, op, principal="p", unit="JPY"):
    return guard.reserve(tenant="t", principal=principal, tool_name="pay",
                         arguments={"amount": amount, "unit": unit},
                         operation_id=op, request_hash=f"h-{op}")


@pytest.mark.parametrize("changes", [
    {"schema": "other"},
    {"tools": {}},
    {"tools": {"pay": {"amount_argument": "x", "unit_argument": "x"}}},
    {"budgets": [dict(BUDGET, limit=-1)]},
    {"budgets": [dict(BUDGET, limit=1.5)]},
    {"budgets": [dict(BUDGET, limit=10 ** 7)]},
    {"budgets": [BUDGET, dict(BUDGET, unit="USD")]},
    {"budgets": [BUDGET, dict(BUDGET, budget_id="b2")]},
    {"budgets": [dict(BUDGET, principal="")]},
])
def test_a_malformed_policy_refuses(changes):
    with pytest.raises(sb.SpendPolicyError):
        policy(**changes)


def test_three_times_7000_against_20000(guard):
    assert [reserve(guard, 7000, op) for op in ("A", "B", "C")] == \
        [None, None, sb.BUDGET_EXHAUSTED]
    budget = guard.policy.budgets[0]
    assert guard.remaining(budget) == 6000


def test_an_exact_fit_is_allowed_and_one_more_unit_is_not(guard):
    assert reserve(guard, 20000, "all") is None
    assert reserve(guard, 1, "one-more") == sb.BUDGET_EXHAUSTED


def test_a_retry_of_one_lease_is_not_charged_twice(guard):
    assert reserve(guard, 7000, "lease-1") is None
    assert reserve(guard, 7000, "lease-1") is None
    assert guard.remaining(guard.policy.budgets[0]) == 13000


def test_a_reused_operation_with_another_amount_is_refused(guard):
    assert reserve(guard, 7000, "lease-1") is None
    assert reserve(guard, 1, "lease-1") == sb.BUDGET_CHANGED


def test_preview_reserves_nothing(guard):
    args = {"amount": 7000, "unit": "JPY"}
    for _ in range(5):
        assert guard.preview(tenant="t", principal="p", tool_name="pay", arguments=args) is None
    assert guard.remaining(guard.policy.budgets[0]) == 20000


def test_an_unreadable_ledger_refuses(guard, monkeypatch):
    def broken(*a, **k):
        raise OSError("disk gone")
    monkeypatch.setattr(guard.ledger, "reserve", broken)
    assert reserve(guard, 7000, "A") == sb.LEDGER_UNAVAILABLE


def _dispatcher(guard):
    from remora.enforcement.lease import GovernedToolDispatcher

    d = GovernedToolDispatcher(expected_policy_bundle_hash="b" * 64)
    d.bind_spend_guard(guard)
    return d


def _lease(nonce="n1"):
    return SimpleNamespace(tenant_id="t", actor_identity="p", nonce=nonce,
                           tool_args_hash="h" * 64)


def test_the_dispatcher_ignores_tools_without_a_budget(guard):
    d = _dispatcher(guard)
    assert d._spend_refusal(_lease(), "read", {"amount": 10 ** 9}, {"amount": 10 ** 9}) is None


def test_the_dispatcher_refuses_a_resolved_amount_the_wire_form_does_not_name(guard):
    d = _dispatcher(guard)
    wire = {"amount": 7000, "unit": "JPY"}
    assert d._spend_refusal(_lease(), "pay", wire, {"amount": 19000, "unit": "JPY"}) == \
        "spend_invocation_differs"
    assert guard.remaining(guard.policy.budgets[0]) == 20000


def test_the_dispatcher_keys_the_reservation_by_lease(guard):
    d = _dispatcher(guard)
    args = {"amount": 7000, "unit": "JPY"}
    assert d._spend_refusal(_lease("n1"), "pay", args, args) is None
    assert d._spend_refusal(_lease("n1"), "pay", args, args) is None  # the same lease again
    assert d._spend_refusal(_lease("n2"), "pay", args, args) is None
    assert d._spend_refusal(_lease("n3"), "pay", args, args) == sb.BUDGET_EXHAUSTED


def test_a_closed_budget_refuses(guard):
    budget = guard.policy.budgets[0]
    assert reserve(guard, 7000, "A") is None
    guard.ledger.close(budget.ledger_key, budget.binding)
    assert reserve(guard, 1, "B") == sb.BUDGET_CLOSED
    assert guard.remaining(budget) == 0


def test_the_ledger_refuses_an_in_memory_database():
    with pytest.raises(Exception):
        sb.SpendLedger(":memory:")

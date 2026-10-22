# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""LimitPolicy validation, LimitGuard reservation and the dispatcher hooks."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from remora.enforcement import cumulative_limits as cl

T0 = 1_800_000_000.0
METERS = {
    "pay": [{"quantity": "spend", "kind": "sum", "argument": "amount", "unit_argument": "cur"}],
    "move": [{"quantity": "movement", "kind": "change", "argument": "value", "scale": 10,
              "unit": "degC", "resource_argument": "unit"}],
    "start": [{"quantity": "starts", "kind": "count", "unit": "starts",
               "resource_argument": "unit"}],
}
LIMITS = [
    {"limit_id": "spend", "tenant": "t", "quantity": "spend", "unit": "JPY", "max": 20000,
     "principal": "p"},
    {"limit_id": "move", "tenant": "t", "quantity": "movement", "unit": "degC", "max": 20,
     "window_seconds": 3600, "principal": "*", "resource": "*"},
    {"limit_id": "starts", "tenant": "t", "quantity": "starts", "unit": "starts", "max": 2,
     "window_seconds": 3600, "principal": "*", "resource": "*"},
]
BASELINES = [{"tenant": "t", "quantity": "movement", "resource": "AHU-1", "value": 19.0,
              "seed_id": "s1"}]


def policy(**changes):
    data = {"schema": cl.SCHEMA, "meters": METERS, "limits": LIMITS, "baselines": BASELINES}
    data.update(changes)
    return cl.LimitPolicy.from_dict(data)


@pytest.fixture()
def guard(tmp_path):
    return cl.LimitGuard(policy(), cl.LimitLedger(tmp_path / "ledger.db"))


def reserve(guard, tool, op, now=T0, principal="p", **arguments):
    return guard.reserve(tenant="t", principal=principal, tool_name=tool, arguments=arguments,
                         operation_id=op, request_hash=f"h-{op}", now=now)


def settle(guard, op, ok=True):
    guard.settle(op, ok)


@pytest.mark.parametrize("changes", [
    {"schema": "other"},
    {"coverage": "some"},
    {"meters": {}},
    {"meters": {"pay": []}},
    {"meters": {"pay": ["x"]}},
    {"meters": {"pay": [{"quantity": "q", "kind": "avg", "argument": "a", "unit": "u"}]}},
    {"meters": {"pay": [{"quantity": "q", "kind": "sum", "unit": "u"}]}},
    {"meters": {"pay": [{"quantity": "q", "kind": "count", "argument": "a", "unit": "u"}]}},
    {"meters": {"pay": [{"quantity": "q", "kind": "sum", "argument": "a"}]}},
    {"meters": {"pay": [{"quantity": "q", "kind": "sum", "argument": "a", "unit": "u",
                         "unit_argument": "c"}]}},
    {"meters": {"pay": [{"quantity": "q", "kind": "change", "argument": "a", "unit": "u"}]}},
    {"meters": {"pay": [{"quantity": "q", "kind": "sum", "argument": "a", "unit": "u"},
                        {"quantity": "q", "kind": "count", "unit": "u"}]}},
    {"meters": {"a": [{"quantity": "q", "kind": "sum", "argument": "x", "unit": "u"}],
                "b": [{"quantity": "q", "kind": "sum", "argument": "x", "unit": "u",
                       "scale": 10}]}},
    {"meters": {"pay": [{"quantity": "q", "kind": "sum", "argument": "a", "unit": "u",
                         "scale": 0}]}},
    {"limits": ["x"]},
    {"limits": [dict(LIMITS[0], max=-1)]},
    {"limits": [dict(LIMITS[0], max=1.5)]},
    {"limits": [dict(LIMITS[0], window_seconds=0)]},
    {"limits": [LIMITS[0], LIMITS[0]]},
    {"baselines": ["x"]},
    {"baselines": [dict(BASELINES[0], quantity="spend2")]},
    {"baselines": [dict(BASELINES[0], value=19.05)]},
    {"baselines": [BASELINES[0], dict(BASELINES[0], seed_id="s2")]},
])
def test_a_malformed_policy_refuses(changes):
    with pytest.raises(cl.LimitPolicyError):
        policy(**changes)


def test_three_times_7000_against_20000(guard):
    assert [reserve(guard, "pay", op, amount=7000, cur="JPY") for op in "ABC"] == \
        [None, None, cl.EXCEEDED]


def test_a_window_slides(guard):
    assert reserve(guard, "start", "1", now=T0, unit="AHU-1") is None
    assert reserve(guard, "start", "2", now=T0 + 1000, unit="AHU-1") is None
    assert reserve(guard, "start", "3", now=T0 + 3599, unit="AHU-1") == cl.EXCEEDED
    assert reserve(guard, "start", "4", now=T0 + 3601, unit="AHU-1") is None  # "1" left
    assert reserve(guard, "start", "5", now=T0 + 3700, unit="AHU-1") == cl.EXCEEDED


def test_an_iso_clock_is_read(guard):
    assert reserve(guard, "start", "1", now="2027-01-15T10:00:00+00:00", unit="AHU-1") is None
    assert reserve(guard, "start", "2", now="2027-01-15T10:30:00+00:00", unit="AHU-1") is None
    assert reserve(guard, "start", "3", now="2027-01-15T10:59:00+00:00",
                   unit="AHU-1") == cl.EXCEEDED


def test_without_a_clock_the_wall_clock_is_used(tmp_path):
    guard = cl.LimitGuard(policy(), cl.LimitLedger(tmp_path / "wall.db"))
    assert [reserve(guard, "start", op, now=None, unit="AHU-1") for op in "123"] == \
        [None, None, cl.EXCEEDED]


def test_a_limit_added_after_a_reservation_refuses_its_retry(tmp_path):
    ledger = cl.LimitLedger(tmp_path / "l.db")
    first = cl.LimitGuard(policy(), ledger)
    assert reserve(first, "pay", "A", amount=7000, cur="JPY") is None
    extra = dict(LIMITS[0], limit_id="spend-shared", principal="*")
    second = cl.LimitGuard(policy(limits=[*LIMITS, extra]), ledger)
    assert reserve(second, "pay", "A", amount=7000, cur="JPY") == cl.CHANGED


def test_movement_is_measured_from_the_last_value(guard):
    assert reserve(guard, "move", "1", unit="AHU-1", value=20.0) is None
    settle(guard, "1")
    assert reserve(guard, "move", "2", unit="AHU-1", value=19.5) is None  # 1.0 + 0.5
    settle(guard, "2")
    assert reserve(guard, "move", "3", unit="AHU-1", value=20.5) == cl.EXCEEDED
    assert reserve(guard, "move", "4", unit="AHU-1", value=20.0) is None  # exactly 2.0


def test_a_pending_move_makes_the_unit_busy(guard):
    assert reserve(guard, "move", "1", unit="AHU-1", value=19.5) is None
    assert reserve(guard, "move", "2", unit="AHU-1", value=19.5) == cl.RESOURCE_BUSY
    settle(guard, "1")
    assert reserve(guard, "move", "2", unit="AHU-1", value=19.5) is None  # no movement


def test_a_failed_move_needs_a_new_seed(guard, tmp_path):
    assert reserve(guard, "move", "1", unit="AHU-1", value=19.5) is None
    settle(guard, "1", ok=False)
    assert reserve(guard, "move", "2", unit="AHU-1", value=19.5) == cl.BASELINE_UNKNOWN
    reseeded = cl.LimitGuard(policy(baselines=[dict(BASELINES[0], value=19.5, seed_id="s2")]),
                             guard.ledger)
    assert reserve(reseeded, "move", "2", unit="AHU-1", value=19.5) is None


def test_a_retry_of_one_operation_is_not_charged_twice(guard):
    assert reserve(guard, "pay", "A", amount=7000, cur="JPY") is None
    assert reserve(guard, "pay", "A", amount=7000, cur="JPY") is None
    assert reserve(guard, "move", "M", unit="AHU-1", value=20.0) is None
    assert reserve(guard, "move", "M", unit="AHU-1", value=20.0) is None  # still pending
    settle(guard, "M")
    assert reserve(guard, "move", "M", unit="AHU-1", value=20.0) is None  # after it ran
    assert reserve(guard, "pay", "B", amount=7000, cur="JPY") is None
    assert reserve(guard, "pay", "C", amount=6000, cur="JPY") is None
    assert reserve(guard, "pay", "D", amount=1, cur="JPY") == cl.EXCEEDED


def test_a_reused_operation_with_another_request_is_refused(guard):
    assert reserve(guard, "pay", "A", amount=7000, cur="JPY") is None
    assert reserve(guard, "pay", "A", amount=1, cur="JPY") == cl.CHANGED


def test_preview_reserves_nothing(guard):
    for _ in range(5):
        assert guard.preview(tenant="t", principal="p", tool_name="pay",
                             arguments={"amount": 7000, "cur": "JPY"}, now=T0) is None
    assert reserve(guard, "pay", "A", amount=20000, cur="JPY") is None


@pytest.mark.parametrize("tool, arguments, reason", [
    ("pay", {"amount": 7000}, cl.UNIT_INVALID),
    ("pay", {"amount": 7000, "cur": ""}, cl.UNIT_INVALID),
    ("pay", {"amount": 10 ** 13, "cur": "JPY"}, cl.AMOUNT_INVALID),
    ("pay", {"amount": float("nan"), "cur": "JPY"}, cl.AMOUNT_INVALID),
    ("pay", {"amount": float("inf"), "cur": "JPY"}, cl.AMOUNT_INVALID),
    ("pay", "not-a-mapping", cl.UNIT_INVALID),
    ("move", {"value": 20.0}, cl.RESOURCE_INVALID),
    ("move", {"unit": "AHU-1", "value": 20.04}, cl.AMOUNT_INVALID),
    ("move", {"unit": "AHU-1"}, cl.AMOUNT_INVALID),
])
def test_an_unreadable_call_is_refused_before_the_ledger(guard, tool, arguments, reason):
    assert guard.reserve(tenant="t", principal="p", tool_name=tool, arguments=arguments,
                         operation_id="op", request_hash="h", now=T0) == reason


def test_a_call_without_a_principal_is_refused(guard):
    assert reserve(guard, "pay", "A", principal="", amount=7000, cur="JPY") == \
        cl.PRINCIPAL_MISSING


def test_unmetered_tools_under_each_coverage(tmp_path):
    ledger = cl.LimitLedger(tmp_path / "l.db")
    listed = cl.LimitGuard(policy(), ledger)
    assert not listed.governs("reset") and listed.preview(
        tenant="t", principal="p", tool_name="reset", arguments={}) is None
    writes = {"reset": True, "read": False}
    strict = cl.LimitGuard(policy(coverage="all_writes"), ledger,
                           is_write=lambda name: writes.get(name))
    assert strict.governs("reset")
    assert reserve(strict, "reset", "1") == cl.TOOL_UNMETERED
    assert reserve(strict, "read", "2") is None
    assert reserve(strict, "unknown", "3") == cl.COVERAGE_UNKNOWN
    assert reserve(cl.LimitGuard(policy(coverage="all_writes"), ledger), "read", "4") == \
        cl.COVERAGE_UNKNOWN

    def broken(name):
        raise RuntimeError("bundle unreadable")
    assert reserve(cl.LimitGuard(policy(coverage="all_writes"), ledger, is_write=broken),
                   "read", "5") == cl.COVERAGE_UNKNOWN


def test_compare_refuses_a_resolved_invocation_that_meters_differently(guard):
    wire = {"amount": 7000, "cur": "JPY"}
    assert guard.compare("pay", wire, dict(wire)) is None
    assert guard.compare("pay", wire, {"amount": 19000, "cur": "JPY"}) == cl.INVOCATION_DIFFERS
    assert guard.compare("pay", wire, {"amount": "x", "cur": "JPY"}) == cl.AMOUNT_INVALID
    assert guard.compare("other", wire, {}) is None


def test_an_unreadable_ledger_refuses(guard, monkeypatch):
    def broken(*a, **k):
        raise OSError("disk gone")
    monkeypatch.setattr(guard.ledger, "transaction", broken)
    assert reserve(guard, "pay", "A", amount=7000, cur="JPY") == cl.LEDGER_UNAVAILABLE


def test_the_ledger_refuses_an_in_memory_database():
    with pytest.raises(Exception):
        cl.LimitLedger(":memory:")


def _dispatcher(guard):
    from remora.enforcement.lease import GovernedToolDispatcher

    d = GovernedToolDispatcher(expected_policy_bundle_hash="b" * 64)
    d.bind_limit_guard(guard)
    return d


def _lease(nonce="n1"):
    return SimpleNamespace(tenant_id="t", actor_identity="p", nonce=nonce,
                           tool_args_hash="h" * 64, proposal_id="prop")


def test_the_dispatcher_ignores_tools_without_a_meter(guard):
    d = _dispatcher(guard)
    assert d._limit_refusal(_lease(), "read", {"amount": 10 ** 9}, {}, None) is None
    d._limit_settle(_lease(), "read", ok=True)  # nothing to settle


def test_the_dispatcher_refuses_a_resolved_amount_the_wire_form_does_not_name(guard):
    d = _dispatcher(guard)
    wire = {"amount": 7000, "cur": "JPY"}
    assert d._limit_refusal(_lease(), "pay", wire, {"amount": 19000, "cur": "JPY"},
                            None) == cl.INVOCATION_DIFFERS


def test_the_dispatcher_keys_the_reservation_by_lease_and_settles_it(guard):
    d = _dispatcher(guard)
    args = {"unit": "AHU-1", "value": 20.0}
    assert d._limit_refusal(_lease("n1"), "move", args, args, None) is None
    assert d._limit_refusal(_lease("n1"), "move", args, args, None) is None  # same lease
    assert d._limit_refusal(_lease("n2"), "move", args, args, None) == cl.RESOURCE_BUSY
    d._limit_settle(_lease("n1"), "move", ok=True)
    assert d._limit_refusal(_lease("n2"), "move", args, args, None) is None


def test_a_settle_that_fails_leaves_the_unit_closed(guard, monkeypatch):
    d = _dispatcher(guard)
    args = {"unit": "AHU-1", "value": 20.0}
    assert d._limit_refusal(_lease("n1"), "move", args, args, None) is None

    def broken(*a, **k):
        raise OSError("disk gone")
    monkeypatch.setattr(guard, "settle", broken)
    d._limit_settle(_lease("n1"), "move", ok=True)
    monkeypatch.undo()
    assert d._limit_refusal(_lease("n2"), "move", args, args, None) == cl.RESOURCE_BUSY

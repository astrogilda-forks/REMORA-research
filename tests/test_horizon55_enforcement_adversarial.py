# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Horizon #55 row, part 2 under P1 stress: concurrency, crashes, retries.

The set-2 payments and the signed budget, taken from the verified log as in
``enforce.py``, sent through REMORA's execution API with the sandboxed
payment tool. Each test varies one thing the replay keeps fixed: the
payments run at once, an approved payment is executed twice, the same
payment is proposed twice, the tool fails before or after paying, the
process restarts, or the order changes. The invariant is the same in every
case: the total that reaches the payment tool never passes 20000. These are
the author's own controls on a public sequence, not external adversarial
coverage, and they say nothing about how often legitimate calls are refused.
"""
from __future__ import annotations

import importlib.util
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("cryptography")

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "integrations" / "horizon55"
sys.path.insert(0, str(PKG))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"h55_{name}", PKG / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


enforce = _load("enforce")
import payment_tool  # noqa: E402  (the module the registry loads)

SEQ = enforce.signed_sequence()
BUDGET = SEQ["budget"]["max_total"]
A, B, C = SEQ["payments"]


@pytest.fixture()
def start(tmp_path):
    """A fresh API on ``tmp_path``; calling it again is a restart on the same ledger."""
    with enforce.isolated():
        yield lambda: enforce._Api(tmp_path, SEQ, enforce._limit_policy(SEQ))


def _paid() -> int:
    return sum(r["amount"] for r in payment_tool.REACHED)


def _approved(api, payment):
    assessed = api.assess(payment)
    assert assessed["status"] == 200, assessed
    assert api.approve(assessed["item_id"]) == 200
    return assessed["item_id"]


def _run(api, payment):
    assessed = api.assess(payment)
    if assessed["status"] != 200:
        return f"refused at assess: {assessed['refusal']}"
    api.approve(assessed["item_id"])
    result = api.execute(assessed["item_id"], payment)
    return "executed" if result["executed"] else f"refused at dispatch: {result['refusal']}"


def _again(payment, n):
    """The same payment proposed again, as a new request."""
    return {**payment, "occurrence_id": f"{payment['occurrence_id']}-again-{n}"}


def test_a_b_and_c_executed_at_once_run_two(start):
    api = start()
    items = [(_approved(api, p), p) for p in (A, B, C)]
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda x: api.execute(*x), items))
    assert sum(r["executed"] for r in results) == 2
    assert [r["refusal"] for r in results if not r["executed"]] == ["limit_exceeded"]
    assert _paid() == 14000


def test_six_approved_payments_raced_never_pass_the_budget(start):
    api = start()
    payments = [A, B, C, _again(A, 1), _again(B, 1), _again(C, 1)]
    items = [(_approved(api, p), p) for p in payments]
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda x: api.execute(*x), items))
    assert sum(r["executed"] for r in results) == 2
    assert _paid() == 14000 <= BUDGET


def test_an_approved_payment_executed_twice_runs_and_is_charged_once(start):
    api = start()
    item = _approved(api, A)
    assert api.execute(item, A)["executed"] is True
    replay = api.execute(item, A)
    assert replay["executed"] is False
    assert api.reached() == [A["occurrence_id"]]
    # The replay charged nothing: B still fits, C still does not.
    assert [_run(api, B), _run(api, C)] == ["executed", "refused at assess: limit_exceeded"]


def test_an_approved_payment_executed_twice_at_once_runs_once(start):
    api = start()
    item = _approved(api, A)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: api.execute(item, A), range(4)))
    assert sum(r["executed"] for r in results) == 1
    assert _paid() == 7000


def test_the_same_payment_proposed_twice_runs_once(start):
    """Same payee, amount, unit and reference: one operation (``idempotency``)."""
    api = start()
    assert [_run(api, A), _run(api, A), _run(api, B)] == [
        "executed", "refused at assess: limit_duplicate_operation", "executed"]
    assert _paid() == 14000


def test_the_same_payment_approved_twice_before_either_ran_runs_once(start):
    api = start()
    items = [_approved(api, A), _approved(api, A)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda item: api.execute(item, A), items))
    assert sorted(r["executed"] for r in results) == [False, True]
    assert {r["refusal"] for r in results} - {None} <= {"limit_duplicate_in_flight",
                                                       "limit_duplicate_operation"}
    assert _paid() == 7000


def test_a_payment_under_a_new_reference_is_a_new_payment(start):
    """The key names the payment; a new reference is a second payment of 7000."""
    api = start()
    assert [_run(api, A), _run(api, _again(A, 1)), _run(api, B)] == [
        "executed", "executed", "refused at assess: limit_exceeded"]
    assert _paid() == 14000


def test_a_payment_that_failed_after_paying_cannot_be_paid_again(start):
    """The rail moved the money but REMORA never heard back: the reservation stays."""
    api = start()
    assert _run(api, A) == "executed"
    payment_tool.FAIL_NEXT.append("after")
    assert _run(api, B).startswith("refused at dispatch")
    assert api.reached() == [A["occurrence_id"], B["occurrence_id"]]
    assert _run(api, B) == "refused at assess: limit_outcome_unknown"   # never paid twice
    assert _run(api, _again(B, 1)) == "refused at assess: limit_exceeded"
    assert _run(api, C) == "refused at assess: limit_exceeded"
    assert _paid() == 14000


def test_a_payment_the_rail_refused_can_be_retried_at_once(start):
    """The tool knows nothing moved (``ToolDidNotExecute``): the budget comes back."""
    api = start()
    assert _run(api, A) == "executed"
    payment_tool.FAIL_NEXT.append("refused")
    assert _run(api, B) == "refused at dispatch: tool_did_not_execute"
    assert [_run(api, B), _run(api, C)] == ["executed", "refused at assess: limit_exceeded"]
    assert _paid() == 14000


def _resolve(api, executed, payment=None, expect=200):
    """A reviewer resolves the one held payment; the sandbox rail checks the statement."""
    import servers.api as api_mod

    [held] = api.client.get("/v1/execution/limits/unresolved").json()["operations"]
    payer = api_mod._authenticated_principal
    api_mod._authenticated_principal = lambda request: "treasury-reviewer"
    try:
        r = api.client.post("/v1/execution/limits/resolve", json={
            "operation_id": held["operation_id"], "executed": executed,
            "evidence_ref": f"sandbox-rail:{(payment or B)['occurrence_id']}",
            "reason": "checked against the rail"})
    finally:
        api_mod._authenticated_principal = payer
    assert r.status_code == expect, r.text
    return r.json()


def test_a_reviewer_contradicted_by_the_rail_frees_nothing(start):
    """The rail paid B; a reviewer saying it did not is refused and the budget stays held."""
    api = start()
    assert _run(api, A) == "executed"
    payment_tool.FAIL_NEXT.append("after")
    assert _run(api, B).startswith("refused at dispatch")
    assert _resolve(api, executed=False, expect=409)["detail"] == "limit_evidence_disputed"
    assert _run(api, B) == "refused at assess: limit_outcome_unknown"
    assert _run(api, C) == "refused at assess: limit_exceeded"
    assert _paid() == 14000


def test_a_payment_whose_outcome_is_unknown_holds_until_resolved(start):
    """The tool could not tell (it raised without paying): held, then resolved."""
    api = start()
    assert _run(api, A) == "executed"
    payment_tool.FAIL_NEXT.append("before")
    assert _run(api, B).startswith("refused at dispatch")
    assert _run(api, B) == "refused at assess: limit_outcome_unknown"
    _resolve(api, executed=False)   # the rail shows no transfer
    assert [_run(api, B), _run(api, C)] == ["executed", "refused at assess: limit_exceeded"]
    assert _paid() == 14000


def test_a_payment_resolved_as_made_is_not_made_again(start):
    api = start()
    assert _run(api, A) == "executed"
    payment_tool.FAIL_NEXT.append("after")
    assert _run(api, B).startswith("refused at dispatch")
    _resolve(api, executed=True)    # the rail shows the transfer
    assert [_run(api, B), _run(api, C)] == ["refused at assess: limit_duplicate_operation",
                                            "refused at assess: limit_exceeded"]
    assert _paid() == 14000


def test_a_restart_between_b_and_c_does_not_reset_the_budget(start):
    api = start()
    assert [_run(api, A), _run(api, B)] == ["executed", "executed"]
    assert _paid() == 14000
    api = start()  # new process state, same ledger
    assert _run(api, C) == "refused at assess: limit_exceeded"
    assert api.reached() == []


def test_a_restart_after_c_was_approved_still_refuses_it_at_dispatch(start):
    api = start()
    items = [(_approved(api, p), p) for p in (A, B, C)]
    for item, payment in items[:2]:
        assert api.execute(item, payment)["executed"] is True
    api.exec_mod._reset_tool_dispatcher()  # the dispatcher and its guard are rebuilt
    result = api.execute(*items[2])
    assert (result["executed"], result["refusal"]) == (False, "limit_exceeded")
    assert _paid() == 14000


@pytest.mark.parametrize("order", [(C, A, B), (B, C, A), (C, B, A)])
def test_whichever_payment_comes_third_is_refused(start, order):
    api = start()
    outcomes = [_run(api, p) for p in order]
    assert outcomes == ["executed", "executed", "refused at assess: limit_exceeded"]
    assert _paid() == 14000

# SPDX-License-Identifier: BUSL-1.1
"""Deterministic derivation-receipt proposer: finds only what the verifier accepts."""
from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from remora.toolcall.routing.compatibility import StateIndex, argument_grounding
from remora.toolcall.routing.derivation import DerivationReceipt, verify_receipt
from remora.toolcall.routing.derivation_search import MAX_RECEIPTS, propose_receipts

EMPTY = StateIndex.from_values(set(), scopes=())


def _receipts(raw):
    return tuple(DerivationReceipt(**r) for r in raw)


def _grounded(task, args):
    return argument_grounding(
        args, task_text=task, state=EMPTY, domain="", receipts=_receipts(propose_receipts(task, args))
    )


def test_a_month_name_date_grounds_its_iso_form():
    task = "Check the weather in Fremont on March 1st 2023."
    raw = propose_receipts(task, {"date": "2023-03-01"})
    assert [r["transform"] for r in raw] == ["en_date_to_iso"]
    assert task[raw[0]["source_start"]:raw[0]["source_end"]] == "March 1st 2023"
    assert _grounded(task, {"city": "Fremont", "date": "2023-03-01"}).grounded is True


def test_a_case_change_grounds():
    task = "Retrieve the status for the Ethernet interface on fabric 'Global-Fabric'"
    raw = propose_receipts(task, {"interfaceType": "ethernet"})
    assert raw[0]["transform"] == "lowercase"
    assert raw[0]["source_span"] == "Ethernet"


def test_a_formatted_number_grounds():
    task = "Transfer $1,200.50 to the savings account"
    raw = propose_receipts(task, {"amount": 1200.5})
    assert raw[0]["transform"] == "number_normalize"


def test_values_already_in_the_task_get_no_receipt():
    assert propose_receipts("Weather in Boston on 2023-03-01", {"date": "2023-03-01", "n": 2023}) == ()


def test_a_foreign_value_stays_ungrounded():
    task = "Check the weather in Fremont on March 1st 2023."
    assert propose_receipts(task, {"date": "2023-03-02", "city": "Paris"}) == ()
    assert _grounded(task, {"city": "Fremont", "date": "2023-03-02"}).grounded is False


def test_impossible_dates_are_not_derived():
    assert propose_receipts("Book it for April 31st 2023", {"date": "2023-04-31"}) == ()


def test_booleans_and_none_are_never_searched():
    assert propose_receipts("true or false, 1 or 0", {"a": True, "b": None, "c": False}) == ()


def test_receipt_count_is_bounded():
    task = " ".join(f"Item{i}" for i in range(80))
    args = {f"a{i}": f"item{i}" for i in range(80)}
    assert len(propose_receipts(task, args)) == MAX_RECEIPTS


@settings(max_examples=200, deadline=None)
@given(
    task=st.text(alphabet="abcABC0123456789 ,.$-", max_size=60),
    value=st.one_of(st.text(alphabet="abcABC0123456789-", max_size=12),
                    st.integers(-10_000, 10_000),
                    st.floats(-1e4, 1e4, allow_nan=False, allow_infinity=False)),
)
def test_every_proposed_receipt_verifies_against_the_task(task, value):
    for raw in propose_receipts(task, {"x": value}):
        assert verify_receipt(DerivationReceipt(**raw), task_text=task)
        assert task[raw["source_start"]:raw["source_end"]] == raw["source_span"]

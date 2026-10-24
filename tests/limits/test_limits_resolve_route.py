# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Duplicate payments and failed payments through the execution API.

The payment sequence of ``test_limits_payments.py`` with the policy's
``idempotency`` declared for ``transfer_payment``. A repeated payment
refuses instead of being paid twice. A payment whose outcome is unknown
holds its budget until a reviewer, not the payer, resolves it on
``POST /v1/execution/limits/resolve``, and the reviewer's statement is
checked against the sandboxed rail (``tests/limits/rail.py``,
``REMORA_LIMITS_EVIDENCE_MODULE``) before anything is released. A payment
the tool says it never made (``ToolDidNotExecute``) gives its budget back
at once only when the policy trusts the source of that statement.
"""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from remora.enforcement.lease import ToolDidNotExecute  # noqa: E402
from tests.limits import rail, registry  # noqa: E402
from tests.limits.harness import assess, make_client, ran, run  # noqa: E402
from tests.limits.test_limits_payments import pay, policy  # noqa: E402

IDEMPOTENT = {"transfer_payment": {"key_arguments": ["payee", "amount", "unit", "reference"]}}
TRUST_RAIL = {"transfer_payment": {"trusted_sources": ["rail"]}}
RAIL = "tests.limits.rail"
STATEMENT = "rail-statement-2026-10-24"


def idempotent_policy(**kw):
    return {**policy(**kw), "idempotency": IDEMPOTENT, "non_execution": TRUST_RAIL}


@pytest.fixture(autouse=True)
def _rail_forgets():
    rail.STATEMENTS.clear()
    rail.ASKED.clear()
    yield
    rail.STATEMENTS.clear()
    rail.ASKED.clear()


def _fail_next(monkeypatch, exc):
    """The next payment raises ``exc`` before anything is logged as paid."""
    real = registry._log
    state = {"armed": True}

    def log(tool, arguments):
        if state.pop("armed", False):
            raise exc
        return real(tool, arguments)
    monkeypatch.setattr(registry, "_log", log)


def _as(monkeypatch, principal):
    import servers.api as api_mod

    monkeypatch.setattr(api_mod, "_authenticated_principal", lambda request: principal)


def _unresolved(client):
    r = client.get("/v1/execution/limits/unresolved")
    assert r.status_code == 200, r.text
    return r.json()["operations"]


def _resolve(client, operation_id, executed, evidence_ref=STATEMENT):
    return client.post("/v1/execution/limits/resolve", json={
        "operation_id": operation_id, "executed": executed,
        "evidence_ref": evidence_ref, "reason": "checked with the rail"})


def _resolved_events(tenant="acme"):
    import servers.execution_api as exec_mod

    return [e.payload for e in exec_mod._CHAIN.entries(tenant)
            if e.payload.get("event") == "limit_operation_resolved"]


def test_the_same_payment_proposed_again_is_refused_not_paid_twice(monkeypatch, tmp_path):
    client = make_client(monkeypatch, tmp_path, idempotent_policy())
    assert run(client, pay("A"))["executed"] is True
    r = assess(client, pay("A"))
    assert (r.status_code, r.json()["detail"]) == (409, "limit_duplicate_operation")
    assert run(client, pay("B"))["executed"] is True
    assert [p["reference"] for p in ran(tmp_path)] == ["hs51-musubi-2-A", "hs51-musubi-2-B"]


def test_two_approvals_of_one_payment_run_once(monkeypatch, tmp_path):
    """Both assessed and approved before either runs: only dispatch can stop the second."""
    client = make_client(monkeypatch, tmp_path, idempotent_policy())
    items = [assess(client, pay("A")).json()["review_item_id"] for _ in range(2)]
    results = []
    for item in items:
        client.post("/v1/execution/approve", json={"item_id": item, "approval_ttl_seconds": 600})
        results.append(client.post("/v1/execution/execute",
                                   json={"item_id": item, "tool_call": pay("A")}).json())
    assert [r["tool_execution"]["executed"] for r in results] == [True, False]
    assert results[1]["tool_execution"]["refusal_reason"] == "limit_duplicate_operation"
    assert len(ran(tmp_path)) == 1


def test_a_payment_the_trusted_rail_says_it_never_made_gives_its_budget_back(monkeypatch,
                                                                             tmp_path):
    client = make_client(monkeypatch, tmp_path, idempotent_policy())
    assert run(client, pay("A"))["executed"] is True
    _fail_next(monkeypatch, ToolDidNotExecute("rail", "refused: insufficient funds"))
    assert run(client, pay("B")) == {"stage": "execute", "executed": False,
                                     "refusal": "tool_did_not_execute"}
    assert _unresolved(client) == []
    assert run(client, pay("B"))["executed"] is True   # the retry is not refused
    assert run(client, pay("C"))["detail"] == "limit_exceeded"


@pytest.mark.parametrize("source", ["adapter", "Rail", "rail-mock"])
def test_the_same_statement_from_an_undeclared_source_holds_the_budget(monkeypatch, tmp_path,
                                                                        source):
    """NEGATIVE_RESULTS section 97: an adapter's word alone no longer frees spent budget."""
    client = make_client(monkeypatch, tmp_path, idempotent_policy())
    assert run(client, pay("A"))["executed"] is True
    _fail_next(monkeypatch, ToolDidNotExecute(source, "refused: insufficient funds"))
    assert run(client, pay("B")) == {"stage": "execute", "executed": False,
                                     "refusal": "tool_did_not_execute"}
    [held] = _unresolved(client)
    assert held["tool"] == "transfer_payment" and held["charges"][0]["amount"] == 7000
    assert run(client, pay("B"))["detail"] == "limit_outcome_unknown"   # not until resolved
    assert run(client, pay("C"))["detail"] == "limit_exceeded"          # 7000 + 7000 held
    assert len(ran(tmp_path)) == 1


def test_a_policy_that_names_no_source_never_frees_on_the_adapters_word(monkeypatch, tmp_path):
    client = make_client(monkeypatch, tmp_path, {**policy(), "idempotency": IDEMPOTENT})
    _fail_next(monkeypatch, ToolDidNotExecute("rail", "refused"))
    assert run(client, pay("A"))["refusal"] == "tool_did_not_execute"
    assert len(_unresolved(client)) == 1


def test_an_unknown_outcome_holds_the_budget_until_a_reviewer_resolves_it(monkeypatch,
                                                                          tmp_path):
    client = make_client(monkeypatch, tmp_path, idempotent_policy(), evidence_module=RAIL)
    assert run(client, pay("A"))["executed"] is True
    _fail_next(monkeypatch, TimeoutError("no reply from the rail"))
    assert run(client, pay("B"))["executed"] is False
    assert run(client, pay("B"))["detail"] == "limit_outcome_unknown"   # not paid twice
    [held] = _unresolved(client)
    assert held["principal"] == "employee-1" and held["charges"][0]["amount"] == 7000

    rail.STATEMENTS[STATEMENT] = False
    r = _resolve(client, held["operation_id"], executed=False)    # the payer may not
    assert (r.status_code, r.json()["detail"]) == (409, "limit_resolver_is_principal")
    assert rail.ASKED == []                                        # and the rail is not asked

    _as(monkeypatch, "treasury-reviewer")
    assert _resolve(client, held["operation_id"], executed=False).status_code == 200
    assert rail.ASKED == [("acme", held["operation_id"], STATEMENT)]
    [event] = _resolved_events()
    assert event["resolved_by"] == "treasury-reviewer" and event["executed"] is False
    assert event["evidence_ref"] == STATEMENT and event["evidence_checked_by"] == RAIL
    assert _resolve(client, held["operation_id"], executed=False).json()["detail"] == \
        "limit_operation_not_unknown"

    _as(monkeypatch, "employee-1")
    assert run(client, pay("B"))["executed"] is True
    assert run(client, pay("C"))["detail"] == "limit_exceeded"
    assert len(ran(tmp_path)) == 2


def test_an_unknown_outcome_resolved_as_executed_stays_charged(monkeypatch, tmp_path):
    client = make_client(monkeypatch, tmp_path, idempotent_policy(), evidence_module=RAIL)
    _fail_next(monkeypatch, TimeoutError("no reply from the rail"))
    assert run(client, pay("A"))["executed"] is False
    [held] = _unresolved(client)
    _as(monkeypatch, "treasury-reviewer")
    rail.STATEMENTS[STATEMENT] = True
    assert _resolve(client, held["operation_id"], executed=True).status_code == 200
    _as(monkeypatch, "employee-1")
    assert run(client, pay("A"))["detail"] == "limit_duplicate_operation"
    assert run(client, pay("B"))["executed"] is True
    assert run(client, pay("C"))["detail"] == "limit_exceeded"   # 7000 + 7000 + 7000


# ── the reviewer's evidence is checked before anything is released ────────


def _held_payment(monkeypatch, tmp_path, evidence_module):
    client = make_client(monkeypatch, tmp_path, idempotent_policy(),
                         evidence_module=evidence_module)
    _fail_next(monkeypatch, TimeoutError("no reply from the rail"))
    assert run(client, pay("A"))["executed"] is False
    [held] = _unresolved(client)
    _as(monkeypatch, "treasury-reviewer")
    return client, held["operation_id"]


def test_without_an_evidence_checker_nothing_can_be_resolved(monkeypatch, tmp_path):
    """NEGATIVE_RESULTS section 97: the reviewer's word alone no longer releases budget."""
    client, op = _held_payment(monkeypatch, tmp_path, None)
    for executed in (False, True):
        r = _resolve(client, op, executed=executed)
        assert (r.status_code, r.json()["detail"]) == (409, "limit_evidence_unchecked")
    assert len(_unresolved(client)) == 1 and _resolved_events() == []


def test_evidence_the_rail_disputes_is_refused(monkeypatch, tmp_path):
    client, op = _held_payment(monkeypatch, tmp_path, RAIL)
    rail.STATEMENTS[STATEMENT] = True                      # the rail says it settled
    r = _resolve(client, op, executed=False)               # the reviewer says it did not
    assert (r.status_code, r.json()["detail"]) == (409, "limit_evidence_disputed")
    assert len(_unresolved(client)) == 1 and _resolved_events() == []
    _as(monkeypatch, "employee-1")
    assert run(client, pay("A"))["detail"] == "limit_outcome_unknown"


def test_evidence_the_rail_cannot_speak_to_is_refused(monkeypatch, tmp_path):
    client, op = _held_payment(monkeypatch, tmp_path, RAIL)
    r = _resolve(client, op, executed=False, evidence_ref="no-such-statement")
    assert (r.status_code, r.json()["detail"]) == (409, "limit_evidence_unavailable")
    assert len(_unresolved(client)) == 1


def test_an_evidence_module_without_the_hook_refuses_at_startup(monkeypatch, tmp_path):
    import servers.execution_api as exec_mod

    make_client(monkeypatch, tmp_path, idempotent_policy(), evidence_module="tests.limits.registry")
    with pytest.raises(ValueError, match="check_limit_evidence"):
        exec_mod._limit_guard()


def test_an_unknown_operation_or_no_limits_is_not_found(monkeypatch, tmp_path):
    client = make_client(monkeypatch, tmp_path, idempotent_policy())
    _as(monkeypatch, "treasury-reviewer")
    assert _resolve(client, "lease:nope", executed=False).status_code == 404
    client = make_client(monkeypatch, tmp_path, None)
    assert client.get("/v1/execution/limits/unresolved").status_code == 404


def test_resolving_needs_the_review_capability(monkeypatch, tmp_path):
    import servers.api as api_mod

    client = make_client(monkeypatch, tmp_path, idempotent_policy())
    asked = []

    def require(role, tenant, cap):
        asked.append(cap)
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="capability not granted")
    monkeypatch.setattr(api_mod, "_require_tenant_capability", require)
    assert client.get("/v1/execution/limits/unresolved").status_code == 403
    assert _resolve(client, "lease:x", executed=False).status_code == 403
    assert asked == ["review", "review"]


# ── a crash between the ledger and the chain loses no record (SDD P0 item 4) ─


def test_a_resolution_the_chain_missed_is_recorded_on_the_next_call(monkeypatch, tmp_path):
    import servers.execution_api as exec_mod

    client, op = _held_payment(monkeypatch, tmp_path, RAIL)
    rail.STATEMENTS[STATEMENT] = False
    real = exec_mod._CHAIN.append_once
    broken = {"armed": True}

    def append_once(tenant, key, payload):
        if broken.pop("armed", False):
            raise OSError("chain store unreachable")       # the crash window
        return real(tenant, key, payload)
    monkeypatch.setattr(exec_mod._CHAIN, "append_once", append_once)

    r = _resolve(client, op, executed=False)
    assert r.status_code == 200 and r.json()["audit_recorded"] is False
    assert _resolved_events() == []                          # not on the chain yet
    assert _unresolved(client) == []                         # the next limits call recorded it
    [event] = _resolved_events()
    assert event["operation_id"] == op and event["executed"] is False
    assert event["resolved_by"] == "treasury-reviewer" and event["evidence_ref"] == STATEMENT
    assert event["resolved_at"] > 0
    assert _unresolved(client) == [] and len(_resolved_events()) == 1   # recorded once
    _as(monkeypatch, "employee-1")
    assert run(client, pay("A"))["executed"] is True          # the release itself held


def test_a_recorded_resolution_is_never_appended_twice(monkeypatch, tmp_path):
    import servers.execution_api as exec_mod

    client, op = _held_payment(monkeypatch, tmp_path, RAIL)
    rail.STATEMENTS[STATEMENT] = True
    r = _resolve(client, op, executed=True)
    assert r.status_code == 200 and r.json()["audit_recorded"] is True
    # The mark failed after the append: the key is claimed, so the sweep
    # re-projects nothing and then marks it.
    guard = exec_mod._limit_guard()
    with guard.ledger._connect() as conn:
        conn.execute("UPDATE limit_operation SET audit_recorded=0 WHERE operation_id=?", (op,))
    assert _unresolved(client) == []
    assert len(_resolved_events()) == 1
    assert guard.unrecorded_resolutions("acme") == []

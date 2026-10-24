# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Duplicate payments and failed payments through the execution API.

The payment sequence of ``test_limits_payments.py`` with the policy's
``idempotency`` declared for ``transfer_payment``. A repeated payment
refuses instead of being paid twice. A payment whose outcome is unknown
holds its budget until a reviewer, not the payer, resolves it on
``POST /v1/execution/limits/resolve``. A payment the tool knows it never
made (``ToolDidNotExecute``) gives its budget back at once.
"""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from remora.enforcement.lease import ToolDidNotExecute  # noqa: E402
from tests.limits import registry  # noqa: E402
from tests.limits.harness import assess, make_client, ran, run  # noqa: E402
from tests.limits.test_limits_payments import pay, policy  # noqa: E402

IDEMPOTENT = {"transfer_payment": {"key_arguments": ["payee", "amount", "unit", "reference"]}}


def idempotent_policy(**kw):
    return {**policy(**kw), "idempotency": IDEMPOTENT}


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


def _resolve(client, operation_id, executed):
    return client.post("/v1/execution/limits/resolve", json={
        "operation_id": operation_id, "executed": executed,
        "evidence_ref": "rail-statement-2026-10-24", "reason": "checked with the rail"})


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


def test_a_payment_the_tool_never_made_gives_its_budget_back(monkeypatch, tmp_path):
    client = make_client(monkeypatch, tmp_path, idempotent_policy())
    assert run(client, pay("A"))["executed"] is True
    _fail_next(monkeypatch, ToolDidNotExecute("rail", "refused: insufficient funds"))
    assert run(client, pay("B")) == {"stage": "execute", "executed": False,
                                     "refusal": "tool_did_not_execute"}
    assert _unresolved(client) == []
    assert run(client, pay("B"))["executed"] is True   # the retry is not refused
    assert run(client, pay("C"))["detail"] == "limit_exceeded"


def test_an_unknown_outcome_holds_the_budget_until_a_reviewer_resolves_it(monkeypatch,
                                                                          tmp_path):
    client = make_client(monkeypatch, tmp_path, idempotent_policy())
    assert run(client, pay("A"))["executed"] is True
    _fail_next(monkeypatch, TimeoutError("no reply from the rail"))
    assert run(client, pay("B"))["executed"] is False
    assert run(client, pay("B"))["detail"] == "limit_outcome_unknown"   # not paid twice
    [held] = _unresolved(client)
    assert held["principal"] == "employee-1" and held["charges"][0]["amount"] == 7000

    r = _resolve(client, held["operation_id"], executed=False)    # the payer may not
    assert (r.status_code, r.json()["detail"]) == (409, "limit_resolver_is_principal")

    _as(monkeypatch, "treasury-reviewer")
    assert _resolve(client, held["operation_id"], executed=False).status_code == 200
    import servers.execution_api as exec_mod

    events = [e.payload for e in exec_mod._CHAIN.entries("acme")
              if e.payload.get("event") == "limit_operation_resolved"]
    assert events[0]["resolved_by"] == "treasury-reviewer" and events[0]["executed"] is False
    assert _resolve(client, held["operation_id"], executed=False).json()["detail"] == \
        "limit_operation_not_unknown"

    _as(monkeypatch, "employee-1")
    assert run(client, pay("B"))["executed"] is True
    assert run(client, pay("C"))["detail"] == "limit_exceeded"
    assert len(ran(tmp_path)) == 2


def test_an_unknown_outcome_resolved_as_executed_stays_charged(monkeypatch, tmp_path):
    client = make_client(monkeypatch, tmp_path, idempotent_policy())
    _fail_next(monkeypatch, TimeoutError("no reply from the rail"))
    assert run(client, pay("A"))["executed"] is False
    [held] = _unresolved(client)
    _as(monkeypatch, "treasury-reviewer")
    assert _resolve(client, held["operation_id"], executed=True).status_code == 200
    _as(monkeypatch, "employee-1")
    assert run(client, pay("A"))["detail"] == "limit_duplicate_operation"
    assert run(client, pay("B"))["executed"] is True
    assert run(client, pay("C"))["detail"] == "limit_exceeded"   # 7000 + 7000 + 7000


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

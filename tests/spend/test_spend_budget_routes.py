# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Does REMORA stop the third 7000 payment against a 20000 budget?

The Horizon Shield #51 set-2 sequence (cases A, B and C: three payments of
7000 JPY-testnet under one 20000 budget) replayed through REMORA's own
execution API: ``/v1/execution/assess``, ``/approve`` and ``/execute``, the
governed dispatcher and a sandboxed payment tool that records every call that
reaches it. Nothing is paid; ``tests/spend/payment_registry.py`` appends a
line per call.

Without a declared budget REMORA executes all three (21000). With one, the
third is refused before it reaches the tool, on every path that leads there.
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest

pytest.importorskip("fastapi")

from remora.toolcall.callable_digest import source_digest  # noqa: E402
from tests.spend import payment_registry  # noqa: E402
from tests.test_toolspec_execution_wiring import _bundle_file, _client, _spec  # noqa: E402

PRINCIPAL = "employee-1"
UNIT = "JPY-testnet"
PAY_SPEC = dict(
    tool_id="transfer_payment",
    callable_digest=source_digest(payment_registry.transfer_payment),
    description="Transfer a test payment to a payee.",
    risk_tier="medium", action_type="write", domain="finance", capabilities=["payments"],
    argument_schema={"type": "object",
                     "properties": {"payee": {"type": "string"}, "amount": {"type": "integer"},
                                    "unit": {"type": "string"}, "reference": {"type": "string"}},
                     "required": ["payee", "amount", "unit"], "additionalProperties": False},
    semantic_contract={"capability": "payments", "effect": "transfer",
                       "resource_type": "payment", "mutation": True,
                       "argument_roles": {"payee": "target_resource"}},
    credential_scope=["payments:write"])


def _policy(limit=20000, budget_id="hs51-set2", principal=PRINCIPAL):
    return {"schema": "remora-spend-budget/v1",
            "tools": {"transfer_payment": {"amount_argument": "amount", "unit_argument": "unit"}},
            "budgets": [{"budget_id": budget_id, "tenant": "acme", "principal": principal,
                         "unit": UNIT, "limit": limit}]}


def call(case, amount=7000, task_id="task-set2", unit=UNIT):
    return {"tool_name": "transfer_payment",
            "arguments": {"payee": "responder-1", "amount": amount, "unit": unit,
                          "reference": f"hs51-musubi-2-{case}"},
            "target_environment": "prod", "schema_valid": True,
            "context_id": "ctx-hs51", "task_id": task_id}


@pytest.fixture()
def paid(monkeypatch, tmp_path):
    path = tmp_path / "paid.jsonl"
    monkeypatch.setenv("REMORA_SPEND_LEDGER_FILE", str(path))

    def read():
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]
    return read


def _app(monkeypatch, tmp_path, policy=None):
    import servers.execution_api as exec_mod

    for var in ("REMORA_SPEND_BUDGET_FILE", "REMORA_SPEND_LEDGER"):
        monkeypatch.delenv(var, raising=False)
    if policy is not None:
        (tmp_path / "spend.json").write_text(json.dumps(policy))
        monkeypatch.setenv("REMORA_SPEND_BUDGET_FILE", str(tmp_path / "spend.json"))
        monkeypatch.setenv("REMORA_SPEND_LEDGER", str(tmp_path / "spend-ledger.db"))
    client = _client(monkeypatch, tmp_path,
                     bundle_path=_bundle_file(tmp_path, [_spec(**PAY_SPEC)], name="pay.json"))
    monkeypatch.setenv("REMORA_TOOL_REGISTRY_MODULE", "tests.spend.payment_registry")
    exec_mod._reset_tool_dispatcher()
    return client


def assess(client, c):
    return client.post("/v1/execution/assess", json=c)


def approve_and_execute(client, item_id, c):
    approved = client.post("/v1/execution/approve",
                           json={"item_id": item_id, "approval_ttl_seconds": 600})
    assert approved.status_code == 200, approved.text
    return client.post("/v1/execution/execute", json={"item_id": item_id, "tool_call": c})


def run_case(client, case, **kw):
    """Assess, approve and execute one case; the outcome a caller sees."""
    c = call(case, **kw)
    r = assess(client, c)
    if r.status_code != 200:
        return {"stage": "assess", "status": r.status_code, "detail": r.json()["detail"]}
    body = r.json()
    assert body["decision"] == "verify", body  # a write with no evidence goes to review
    e = approve_and_execute(client, body["review_item_id"], c).json()
    execution = e.get("tool_execution") or {}
    return {"stage": "execute", "outcome": e.get("outcome"),
            "executed": execution.get("executed"), "refusal": execution.get("refusal_reason")}


def test_baseline_remora_as_shipped_pays_all_three(monkeypatch, tmp_path, paid):
    """The measured baseline: no declared budget, all three payments run."""
    client = _app(monkeypatch, tmp_path)
    outcomes = [run_case(client, case) for case in "ABC"]
    assert [o["executed"] for o in outcomes] == [True, True, True]
    assert sum(p["amount"] for p in paid()) == 21000


def test_with_a_declared_budget_c_is_refused_before_review(monkeypatch, tmp_path, paid):
    client = _app(monkeypatch, tmp_path, _policy())
    a, b, c = (run_case(client, case) for case in "ABC")
    assert a["executed"] and b["executed"]
    assert c == {"stage": "assess", "status": 409, "detail": "spend_budget_exhausted"}
    assert [p["reference"] for p in paid()] == ["hs51-musubi-2-A", "hs51-musubi-2-B"]
    import servers.execution_api as exec_mod

    events = [e.payload for e in exec_mod._CHAIN.entries("acme")
              if e.payload.get("event") == "spend_refused"]
    assert [e["detail"] for e in events] == ["spend_budget_exhausted"]


def test_c_approved_before_a_and_b_ran_is_refused_at_dispatch(monkeypatch, tmp_path, paid):
    """The assess check is advisory. All three are assessed and approved while
    the budget is untouched; the reservation at dispatch still stops C."""
    client = _app(monkeypatch, tmp_path, _policy())
    items = {}
    for case in "ABC":
        body = assess(client, call(case)).json()
        items[case] = body["review_item_id"]
    results = {case: approve_and_execute(client, items[case], call(case)).json()
               for case in "ABC"}
    assert results["A"]["tool_execution"]["executed"] is True
    assert results["B"]["tool_execution"]["executed"] is True
    refused = results["C"]["tool_execution"]
    assert refused["executed"] is False
    assert refused["refusal_reason"] == "spend_budget_exhausted"
    assert sum(p["amount"] for p in paid()) == 14000


def test_concurrent_execution_never_spends_past_the_limit(monkeypatch, tmp_path, paid):
    client = _app(monkeypatch, tmp_path, _policy())
    pending = []
    for i in range(6):
        c = call(f"P{i}")
        pending.append((assess(client, c).json()["review_item_id"], c))
    for item_id, _ in pending:
        client.post("/v1/execution/approve", json={"item_id": item_id,
                                                    "approval_ttl_seconds": 600})
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda p: client.post("/v1/execution/execute",
                                            json={"item_id": p[0], "tool_call": p[1]}),
                      pending))
    assert len(paid()) == 2 and sum(p["amount"] for p in paid()) == 14000


def test_the_spend_survives_a_restart(monkeypatch, tmp_path, paid):
    client = _app(monkeypatch, tmp_path, _policy())
    run_case(client, "A")
    run_case(client, "B")
    client = _app(monkeypatch, tmp_path, _policy())  # new guard and dispatcher, same ledger
    assert run_case(client, "C")["detail"] == "spend_budget_exhausted"
    assert len(paid()) == 2


def test_a_new_task_or_context_does_not_reset_the_budget(monkeypatch, tmp_path, paid):
    client = _app(monkeypatch, tmp_path, _policy())
    run_case(client, "A", task_id="task-1")
    run_case(client, "B", task_id="task-2")
    assert run_case(client, "C", task_id="task-3")["detail"] == "spend_budget_exhausted"


def test_a_principal_without_a_budget_cannot_spend(monkeypatch, tmp_path, paid):
    client = _app(monkeypatch, tmp_path, _policy(principal="someone-else"))
    assert run_case(client, "A")["detail"] == "spend_budget_undeclared"
    assert paid() == []


@pytest.mark.parametrize("amount", ["7000", 7000.0, -7000, 0, True])
def test_an_amount_that_is_not_a_positive_integer_is_refused(monkeypatch, tmp_path, paid,
                                                            amount):
    client = _app(monkeypatch, tmp_path, _policy())
    r = assess(client, call("A", amount=amount))
    assert r.status_code in (409, 422), r.text
    if r.status_code == 409:
        assert r.json()["detail"] == "spend_amount_invalid"
    assert paid() == []


def test_another_unit_has_no_budget(monkeypatch, tmp_path, paid):
    client = _app(monkeypatch, tmp_path, _policy())
    assert run_case(client, "A", unit="JPY")["detail"] == "spend_budget_undeclared"


def test_a_limit_raised_in_place_is_refused(monkeypatch, tmp_path, paid):
    client = _app(monkeypatch, tmp_path, _policy())
    run_case(client, "A")
    client = _app(monkeypatch, tmp_path, _policy(limit=10 ** 6))
    assert run_case(client, "B")["detail"] == "spend_budget_changed"
    client = _app(monkeypatch, tmp_path, _policy(limit=10 ** 6, budget_id="hs51-set2-raised"))
    assert run_case(client, "B")["executed"] is True  # a new budget is a new id


def test_half_a_configuration_refuses(monkeypatch, tmp_path):
    import servers.execution_api as exec_mod

    monkeypatch.setenv("REMORA_SPEND_BUDGET_FILE", str(tmp_path / "spend.json"))
    monkeypatch.delenv("REMORA_SPEND_LEDGER", raising=False)
    exec_mod._reset_tool_dispatcher()
    with pytest.raises(ValueError, match="set together"):
        exec_mod._spend_guard()

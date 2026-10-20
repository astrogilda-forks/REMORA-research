# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""A durable task budget on the WS1 execution path (SDD v2 WP-03, review finding 1).

Through the routes, not the helpers: ``/v1/execution/assess`` and
``/v1/execution/execute-accepted`` run the WS1 gate, which reserves every
resolver lookup against the call's task in a SQLite ledger before the lookup
runs. What these tests pin:

* a lookup is reserved before it runs, and at the cap it does not run at all;
* the spend survives a new ledger object (a process restart);
* a reformulated proposal and every re-gate draw on the same task budget;
* a re-gate without budget refuses before the grant is consumed;
* with a ledger configured, a call that names no task is refused;
* another intent authority cannot draw on a task's budget.

The guarantee is local: an atomic reservation on one host. It is not
exactly-once for the external lookup; a reservation that was made and whose
lookup never completed stays spent.
"""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from remora.policy.report import DecisionAction  # noqa: E402
from remora.verification.execution_gate import Ws1Gate  # noqa: E402
from remora.verification.planner import TaskCallLedger  # noqa: E402
from tests.test_ws1_execution_binding import (  # noqa: E402
    CALL,
    INTENT,
    PRINCIPAL,
    _accept,
    _events,
    _mod,
    _redeem,
)
from tests.test_ws1_execution_binding import (  # noqa: E402,F401  (the route fixture)
    client as _route_client,
)
from tests.verification import ws1_deployment_fixture as fixture  # noqa: E402

TASKED = dict(CALL, context_id="ctx-budget-1", task_id="task-1")


@pytest.fixture()
def client(_route_client):  # noqa: F811  (pytest injects the imported fixture)
    """The WS1 route client of tests/test_ws1_execution_binding.py."""
    return _route_client


@pytest.fixture(autouse=True)
def _assets():
    import json

    saved = json.loads(json.dumps(fixture.ASSETS))
    yield
    fixture.ASSETS.clear()
    fixture.ASSETS.update(saved)


def _gate(monkeypatch, ledger_path, cap):
    deployment = fixture.build_ws1_deployment(task_ledger=TaskCallLedger(ledger_path),
                                              task_call_cap=cap)
    gate = Ws1Gate("enforce", deployment, flow_control=True)
    monkeypatch.setattr(_mod(), "_ws1_gate", lambda: gate)
    return gate


def _lookups(gate):
    return len(gate.deployment.resolvers["assets"].calls)


def _assess(client, call=TASKED):
    r = client.post("/v1/execution/assess", json=call)
    assert r.status_code == 200, r.text
    return r.json()


def _ws1_block():
    return _events("assessed")[-1]["ws1"]


def test_a_lookup_is_reserved_before_it_runs_and_stops_at_the_cap(client, monkeypatch, tmp_path):
    gate = _gate(monkeypatch, tmp_path / "ledger.db", cap=2)
    for expected in (1, 2):
        _assess(client)
        assert _lookups(gate) == expected and _ws1_block()["stop_reason"] != \
            "task_budget_exhausted"
    body = _assess(client)
    assert _lookups(gate) == 2  # the third lookup never ran
    assert _ws1_block()["stop_reason"] == "task_budget_exhausted"
    assert body["decision"] == "abstain" and "execution_token" not in body


def test_the_spend_survives_a_restart(client, monkeypatch, tmp_path):
    path = tmp_path / "ledger.db"
    _gate(monkeypatch, path, cap=1)
    _assess(client)
    gate = _gate(monkeypatch, path, cap=1)  # a new process: a new ledger object, same file
    _assess(client)
    assert _lookups(gate) == 0 and _ws1_block()["stop_reason"] == "task_budget_exhausted"


def test_a_reformulated_proposal_draws_on_the_same_task_budget(client, monkeypatch, tmp_path):
    gate = _gate(monkeypatch, tmp_path / "ledger.db", cap=1)
    _assess(client)
    _assess(client, dict(TASKED, arguments={"asset": "P-1"}, target_environment="staging"))
    assert _lookups(gate) == 1 and _ws1_block()["stop_reason"] == "task_budget_exhausted"
    other_task = _gate(monkeypatch, tmp_path / "ledger.db", cap=1)
    _assess(client, dict(TASKED, task_id="task-2"))
    assert _lookups(other_task) == 1  # another task has its own budget


def test_without_a_task_a_call_is_refused_when_a_ledger_is_configured(client, monkeypatch,
                                                                       tmp_path):
    gate = _gate(monkeypatch, tmp_path / "ledger.db", cap=5)
    _assess(client, CALL)
    assert _lookups(gate) == 0 and _ws1_block()["status"] == "refused:task_identity_required"


def test_another_authority_cannot_draw_on_a_task_budget(monkeypatch, tmp_path):
    gate = Ws1Gate("enforce", fixture.build_ws1_deployment(
        task_ledger=TaskCallLedger(tmp_path / "ledger.db"), task_call_cap=5), flow_control=True)
    from remora.policy.observation import PolicyObservation

    common = dict(proposal_id="p", tenant="acme", principal=PRINCIPAL, tool_name="read_telemetry",
                  arguments={"asset": "P-1"}, policy_bundle_hash="b" * 64,
                  toolspec_hash="c" * 64, capability=None, flow_digest=None, flow_epoch=0,
                  attempt_family_id=None, base=_accept(PolicyObservation(question="q")),
                  task_id="ctx/task")
    first = gate.evaluate(intent_authority_hash=INTENT, **common)
    assert first.final_action is DecisionAction.ACCEPT
    other = gate.evaluate(intent_authority_hash="d" * 64, **common)
    assert other.status == "refused:task_binding_mismatch"
    assert _lookups(gate) == 1


def test_a_regate_without_budget_refuses_before_the_grant_is_consumed(client, monkeypatch,
                                                                      tmp_path):
    """The dispatch path: the re-gate's lookup is charged too, and with the
    task's budget spent the redemption refuses unspent."""
    from datetime import UTC, datetime, timedelta

    from remora.enforcement.token import PolicyDecisionToken
    from remora.execution.service import authorization_context
    from remora.governance.task_identity import TaskIdentity

    gate = _gate(monkeypatch, tmp_path / "ledger.db", cap=2)
    exec_mod = _mod()
    tool_call = exec_mod.ToolCallRequest(**TASKED)
    obs, semantic = exec_mod._observation_with_context(tool_call, "acme")
    identity = exec_mod._resolve_toolspec(tool_call.tool_name, tool_call.arguments,
                                          tool_call.target_environment)
    outcome = gate.evaluate(
        proposal_id="p-budget", tenant="acme", principal=PRINCIPAL,
        tool_name=tool_call.tool_name, arguments=tool_call.arguments,
        intent_authority_hash=INTENT, policy_bundle_hash=exec_mod._current_policy_bundle_hash(),
        toolspec_hash=str(identity["hash"]), capability=None, flow_digest=obs.flow_digest,
        flow_epoch=obs.flow_epoch, attempt_family_id=None, base=_accept(obs),
        task_id="ctx-budget-1/task-1")
    assert outcome.final_action is DecisionAction.ACCEPT
    exec_mod._CHAIN.append("acme", {"event": "assessed", "proposal_id": "p-budget",
                                    "actor": PRINCIPAL, "decision": "accept",
                                    "toolspec_hash": identity["hash"],
                                    "ws1": outcome.audit_block()})
    now = datetime.now(UTC)
    token = PolicyDecisionToken.issue(
        action="accept", observation_hash=obs.tool_call_hash or "", request_id="p-budget",
        issued_at=now.isoformat(), expires_at=(now + timedelta(seconds=300)).isoformat(),
        audience=exec_mod.PEP_AUDIENCE,
        context=authorization_context(
            tenant="acme", principal=PRINCIPAL, semantic=semantic,
            target_environment=tool_call.target_environment or "",
            policy_bundle_hash=exec_mod._current_policy_bundle_hash(),
            toolspec_hash=str(identity["hash"]),
            task=TaskIdentity.from_fields({"context_id": "ctx-budget-1", "task_id": "task-1"}),
            ws1_binding_hash=outcome.binding_hash)).to_dict()
    assert _lookups(gate) == 1
    _assess(client)  # spends the second and last unit on the same task
    assert _lookups(gate) == 2
    r = _redeem(client, token, TASKED)
    assert (r.status_code, r.json()["detail"]) == (409, "ws1_regate_refused")
    assert _lookups(gate) == 2  # the re-gate's lookup never ran
    assert not _events("execution_authorized")
    refused = _events("execution_ws1_refused")[-1]["ws1"]
    assert refused["stop_reason"] == "task_budget_exhausted"


def test_a_duplicate_reservation_does_not_run_twice(tmp_path):
    ledger = TaskCallLedger(tmp_path / "ledger.db")
    ledger.ensure("t", "b", 5)
    assert ledger.reserve_status("t", "b", "op", "req") == "reserved"
    assert ledger.reserve_status("t", "b", "op", "req") == "duplicate"
    assert ledger.spent("t") == 1
    ledger.close("t", "b")
    assert ledger.reserve_status("t", "b", "op2", "req") == "closed"
    with pytest.raises(ValueError, match="binding mismatch"):
        ledger.ensure("t", "other", 5)


def test_monitor_calls_are_reserved_on_the_same_budget(tmp_path):
    """A required monitor is charged to the task too; with nothing left it is
    not called, and the call refuses as a monitor outage."""
    from dataclasses import replace

    from remora.decision_providers.composition_adapter import MonitorMode
    from remora.policy.observation import PolicyObservation

    asked = []

    def monitor(context, checked):
        asked.append(1)
        return None

    profile = replace(fixture.PROFILE, mode=MonitorMode.REQUIRED, calibration_hash="1" * 64)
    gate = Ws1Gate("enforce", fixture.build_ws1_deployment(
        task_ledger=TaskCallLedger(tmp_path / "ledger.db"), task_call_cap=1,
        monitor=monitor, monitor_profile=profile), flow_control=True)
    outcome = gate.evaluate(
        proposal_id="p", tenant="acme", principal=PRINCIPAL, tool_name="read_telemetry",
        arguments={"asset": "P-1"}, intent_authority_hash=INTENT, policy_bundle_hash="b" * 64,
        toolspec_hash="c" * 64, capability=None, flow_digest=None, flow_epoch=0,
        attempt_family_id=None, base=_accept(PolicyObservation(question="q")),
        task_id="ctx/task")
    assert _lookups(gate) == 1 and asked == []  # the one unit went to the lookup
    assert outcome.final_action is DecisionAction.ABSTAIN
    assert "task_budget_exhausted" in outcome.audit_block()["record"]["monitor_status"]

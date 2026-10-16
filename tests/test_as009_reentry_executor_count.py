# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""SDD-AS-v1 AS-009: no shortcut through VERIFY, counted at the executor.

A VERIFY that carries a ``ResolutionPlan`` promises one bounded lookup and a
full re-run of the router. This file drives that whole path against a fake
lookup source and a recording executor, and asserts the exact number of
executor calls at every step:

* a hard guard that holds before the lookup is never bypassed by it, and the
  lookup itself is never run for a call a guard already blocks;
* a lookup error, a source that confirms the value absent, and a source that
  establishes nothing all end in no executor call;
* a call that still needs approval after the lookup reaches the executor zero
  times before approval, once after it, and never twice on a replay;
* the authorization minted before the lookup cannot dispatch the re-entered
  call, and only a new token bound to the re-entered call does.

Scope note, stated so the evidence is not read wider than it is: the HTTP
execution API never populates ``missing_required_arguments`` or
``argument_resolver_tools``, so it never produces a machine-resolution plan on
its own. Re-entry is a library step (``resolve_and_reenter`` and
``validate_and_reenter``). The harness below therefore runs that library step
first and then hands the re-entered call to the real execution API: the real
decision engine, the real review queue, the real enforcement gate, the real
governed dispatcher, and a recording tool as the only fake executor.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from remora.enforcement.token import PolicyDecisionToken  # noqa: E402
from remora.governance.tenant_chain import TenantAuditChain  # noqa: E402
from remora.policy.decision_engine import RemoraDecisionEngine  # noqa: E402
from remora.policy.observation import (  # noqa: E402
    PolicyObservation,
    canonical_tool_call_hash,
)
from remora.policy.report import DecisionAction  # noqa: E402
from remora.policy.resolution import (  # noqa: E402
    resolve_and_reenter,
    validate_and_reenter,
)
from tests import as009_recording_registry as registry  # noqa: E402

# The pre-lookup proposal names no work order. The lookup source knows one.
PRE_ARGS: dict[str, Any] = {"action": "reschedule"}
LOOKED_UP = {"order": "WO-1"}
POST_ARGS: dict[str, Any] = {"order": "WO-1", "action": "reschedule"}


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

class FakeLookup:
    """A fake lookup source. Counts every call it receives."""

    def __init__(self, answer: Any = "WO-1", *, raises: bool = False) -> None:
        self.answer = answer
        self.raises = raises
        self.calls: list[tuple[str, str]] = []

    def resolve(self, source_tool: str, argument: str) -> Any:
        self.calls.append((source_tool, argument))
        if self.raises:
            raise RuntimeError("lookup source unreachable")
        return self.answer

    def validate(self, source_tool: str, argument: str) -> bool | None:
        self.calls.append((source_tool, argument))
        if self.raises:
            raise RuntimeError("lookup source unreachable")
        return self.answer


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("REMORA_PDP_SIGNING_KEY", "as009-key")
    monkeypatch.setenv("REMORA_ENV", "development")
    monkeypatch.setenv("REMORA_TOOL_REGISTRY_MODULE", "tests.as009_recording_registry")
    monkeypatch.setenv("REMORA_EXECUTION_ARTIFACT_DIR", str(tmp_path / "art"))
    monkeypatch.delenv("REMORA_SEMANTIC_BUNDLE_MODULE", raising=False)
    import servers.api as api_mod
    import servers.execution_api as exec_mod

    monkeypatch.setattr(api_mod, "_authenticate", lambda request: ("acme", "reviewer"))
    monkeypatch.setattr(api_mod, "_authenticated_principal", lambda request: "agent-1")
    monkeypatch.setattr(api_mod, "_require_tenant_capability",
                        lambda role, tenant, cap: None)
    monkeypatch.setattr(api_mod, "_enforce_review_approval_role",
                        lambda **kwargs: None)
    exec_mod._QUEUES.clear()
    exec_mod._ITEM_TENANT.clear()
    exec_mod._CHAIN = TenantAuditChain()
    exec_mod._GATE = exec_mod.EnforcementGate(strict=True, audience=exec_mod.PEP_AUDIENCE)
    exec_mod._reset_semantic_bundle()
    exec_mod._reset_tool_dispatcher()
    exec_mod._reset_outbox()
    registry.CALLS.clear()
    return TestClient(api_mod.app)


def _executor_calls() -> int:
    return len(registry.CALLS)


def _call(tool: str, arguments: dict[str, Any], target: str = "staging") -> dict[str, Any]:
    return {"tool_name": tool, "arguments": arguments, "target_environment": target}


def _obs(tool: str, **kwargs: Any) -> PolicyObservation:
    """A proposal missing ``order``, with one lookup tool able to supply it."""
    base: dict[str, Any] = dict(
        question="Reschedule the open work order",
        action_type="read",
        proposed_tool_name=tool,
        missing_required_arguments=("order",),
        argument_resolver_tools=("lookup_work_order",),
        arguments_satisfiable=True,
    )
    base.update(kwargs)
    return PolicyObservation(**base)


def _mint(call: dict[str, Any], *, action: str, request_id: str) -> dict[str, Any]:
    """Mint a signed token for exactly this call, as the assess branch does."""
    import servers.execution_api as exec_mod
    from remora.execution.service import authorization_context

    target = call["target_environment"]
    now = datetime.now(UTC)
    _unused, semantic = exec_mod._observation_with_context(
        exec_mod.ToolCallRequest(**call), "acme"
    )
    return PolicyDecisionToken.issue(
        action=action,
        observation_hash=canonical_tool_call_hash(
            name=call["tool_name"], arguments=call["arguments"],
            tenant="acme", target=target),
        request_id=request_id,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=300)).isoformat(),
        audience=exec_mod.PEP_AUDIENCE,
        context=authorization_context(
            tenant="acme", principal="agent-1", semantic=semantic,
            target_environment=target,
            policy_bundle_hash=exec_mod._current_policy_bundle_hash(),
            toolspec_hash=str(exec_mod._resolve_toolspec(
                call["tool_name"], call["arguments"], target)["hash"]),
        ),
    ).to_dict()


def _redeem(client, token: dict[str, Any], call: dict[str, Any]):
    return client.post("/v1/execution/execute-accepted",
                       json={"execution_token": token, "tool_call": call})


# ---------------------------------------------------------------------------
# (a) Hard guards still hold, and the lookup does not outrun them
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("guard", [
    dict(adversarial_detected=True),
    dict(argument_scope_valid=False),
    dict(argument_tainted=True, untrusted_controlled_arguments=("recipient",)),
], ids=["admission-firewall", "cross-tenant-argument", "tainted-sensitive-argument"])
def test_hard_guard_blocks_before_any_lookup_and_nothing_executes(client, guard) -> None:
    engine = RemoraDecisionEngine(low_consequence_accept=True)
    lookup = FakeLookup()
    outcome = resolve_and_reenter(
        _obs("read_work_order", **guard), engine, resolver=lookup.resolve)

    # The guard fires first: no plan is promised, so no lookup is attempted.
    assert outcome.initial_report.action in (DecisionAction.ESCALATE, DecisionAction.ABSTAIN)
    assert outcome.plan is None
    assert lookup.calls == []
    assert outcome.final_report.action == outcome.initial_report.action

    # Forcing the call through anyway with a token carrying that decision
    # does not reach the executor either.
    call = _call("read_work_order", POST_ARGS)
    token = _mint(call, action=outcome.final_report.action.value,
                  request_id="as009-guard")
    assert _redeem(client, token, call).status_code == 409
    assert _executor_calls() == 0


def test_lookup_that_confirms_the_value_absent_stays_blocked(client) -> None:
    """The one place a lookup changes the observation toward a block."""
    engine = RemoraDecisionEngine(low_consequence_accept=True)
    lookup = FakeLookup(answer=False)
    obs = _obs("read_work_order", missing_required_arguments=(),
               argument_resolver_tools=("get_work_order",),
               unvalidated_required_arguments=("order",))
    outcome = validate_and_reenter(obs, engine, validator=lookup.validate)

    assert outcome.initial_report.action is DecisionAction.VERIFY
    assert lookup.calls == [("get_work_order", "order")]
    assert outcome.final_report.action is DecisionAction.ABSTAIN

    call = _call("read_work_order", POST_ARGS)
    token = _mint(call, action=outcome.final_report.action.value,
                  request_id="as009-absent")
    assert _redeem(client, token, call).status_code == 409
    assert _executor_calls() == 0


# ---------------------------------------------------------------------------
# Resolver error or silence: ABSTAIN, zero executor calls
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("answer, raises", [
    (None, True),
    (None, False),
    ("   ", False),
], ids=["raises", "returns-nothing", "returns-blank"])
def test_resolver_error_or_silence_abstains_and_nothing_executes(
    client, answer, raises
) -> None:
    engine = RemoraDecisionEngine(low_consequence_accept=True)
    lookup = FakeLookup(answer=answer, raises=raises)
    outcome = resolve_and_reenter(
        _obs("read_work_order"), engine, resolver=lookup.resolve)

    assert outcome.initial_report.action is DecisionAction.VERIFY
    assert lookup.calls == [("lookup_work_order", "order")]   # attempted once
    assert outcome.attempts == 1
    assert outcome.resolved == {}
    assert outcome.final_report.action is DecisionAction.ABSTAIN

    call = _call("read_work_order", PRE_ARGS)
    token = _mint(call, action=outcome.final_report.action.value,
                  request_id="as009-abstain")
    assert _redeem(client, token, call).status_code == 409
    assert _executor_calls() == 0


# ---------------------------------------------------------------------------
# (b) Approval still required after the lookup
# ---------------------------------------------------------------------------

PROD_UPDATE = {
    **_call("update_work_order", POST_ARGS, target="prod"),
    "risk_tier": "high",
    "action_type": "production_write",
    "rollback_available": True,
}


def test_approval_required_after_lookup_executes_exactly_once(client) -> None:
    # Lookup and re-entry. The execution profile turns a would-be ACCEPT into
    # VERIFY, so the re-entered decision is "needs approval", not "go".
    engine = RemoraDecisionEngine(execution_profile=True, conformal_trust_threshold=0.5)
    lookup = FakeLookup()
    obs = _obs("update_work_order", trust_score=0.9, phase="ordered", schema_valid=True)
    outcome = resolve_and_reenter(obs, engine, resolver=lookup.resolve)

    assert outcome.initial_report.action is DecisionAction.VERIFY
    assert lookup.calls == [("lookup_work_order", "order")]
    assert outcome.resolved == LOOKED_UP
    assert outcome.final_report.action is DecisionAction.VERIFY
    assert _executor_calls() == 0                      # lookup executed nothing

    # The re-entered call enters the real review path.
    assessed = client.post("/v1/execution/assess", json=PROD_UPDATE).json()
    assert assessed["decision"] == "verify"
    assert "execution_token" not in assessed
    item_id = assessed["review_item_id"]
    assert _executor_calls() == 0                      # proposed, not approved

    # Execute before approval is refused.
    early = client.post("/v1/execution/execute",
                        json={"item_id": item_id, "tool_call": PROD_UPDATE})
    assert early.status_code == 409
    assert _executor_calls() == 0

    approve = client.post("/v1/execution/approve",
                          json={"item_id": item_id, "approval_ttl_seconds": 900})
    assert approve.status_code == 200, approve.text
    assert _executor_calls() == 0                      # approval alone runs nothing

    first = client.post("/v1/execution/execute",
                        json={"item_id": item_id, "tool_call": PROD_UPDATE})
    assert first.status_code == 200, first.text
    assert first.json()["tool_execution"]["executed"] is True
    assert _executor_calls() == 1
    assert registry.CALLS == [("update_work_order", POST_ARGS)]

    # Replay and retry of the same approval never reach the executor again.
    for _ in range(2):
        again = client.post("/v1/execution/execute",
                            json={"item_id": item_id, "tool_call": PROD_UPDATE})
        assert again.status_code == 409
    assert _executor_calls() == 1


def test_approval_of_the_pre_lookup_call_does_not_cover_the_re_entered_call(client) -> None:
    pre = {**PROD_UPDATE, "arguments": PRE_ARGS}
    item_id = client.post("/v1/execution/assess", json=pre).json()["review_item_id"]
    assert client.post("/v1/execution/approve",
                       json={"item_id": item_id, "approval_ttl_seconds": 900}
                       ).status_code == 200

    # The lookup added an argument: that is a different call.
    r = client.post("/v1/execution/execute",
                    json={"item_id": item_id, "tool_call": PROD_UPDATE})
    assert r.status_code == 200
    assert r.json()["outcome"] == "binding_refused"
    assert "tool_execution" not in r.json()
    assert _executor_calls() == 0


# ---------------------------------------------------------------------------
# (c) A new token, bound to the re-entered decision
# ---------------------------------------------------------------------------

def test_pre_lookup_token_cannot_dispatch_the_re_entered_call(client) -> None:
    pre_call = _call("read_work_order", PRE_ARGS)
    post_call = _call("read_work_order", POST_ARGS)

    # The pre-lookup authorization exists and is genuine for the pre-lookup call.
    old_token = _mint(pre_call, action="accept", request_id="as009-pre")

    engine = RemoraDecisionEngine(low_consequence_accept=True)
    lookup = FakeLookup()
    outcome = resolve_and_reenter(_obs("read_work_order"), engine, resolver=lookup.resolve)
    assert lookup.calls == [("lookup_work_order", "order")]
    assert outcome.resolved == LOOKED_UP
    assert outcome.final_report.action is DecisionAction.ACCEPT
    assert _executor_calls() == 0                      # an ACCEPT decision runs nothing

    # Presenting the old token for the re-entered call: refused, zero calls.
    stale = _redeem(client, old_token, post_call)
    assert stale.status_code == 409
    assert "binding" in stale.json()["detail"].lower()
    assert _executor_calls() == 0

    # A new token bound to the re-entered call is what dispatches.
    new_token = _mint(post_call, action="accept", request_id="as009-post")
    assert new_token["jti"] != old_token["jti"]
    assert new_token["observation_hash"] != old_token["observation_hash"]
    ok = _redeem(client, new_token, post_call)
    assert ok.status_code == 200, ok.text
    assert ok.json()["tool_execution"]["executed"] is True
    assert _executor_calls() == 1
    assert registry.CALLS == [("read_work_order", POST_ARGS)]

    # Replaying either token afterwards adds nothing.
    assert _redeem(client, new_token, post_call).status_code == 409
    assert _redeem(client, old_token, post_call).status_code == 409
    assert _executor_calls() == 1

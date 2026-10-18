# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Framework adapters: caller labels cannot reach ACCEPT (RMR-AUD-011).

The action-gate adapters forwarded the ``risk_tier``/``action_type`` their
caller passed straight to the gateway, so a hijacked agent that labelled its
own transfer as a low-risk read could get ``should_execute=True``. An adapter
now takes a deployment-owned ``registry=`` (same shape as
``assess_tool_call``). Without one an ACCEPT is lowered to VERIFY with
``caller_labels_untrusted``. A remote gateway that resolves labels server-side
(``HttpGateway`` with a ``tool_call``) reports its own label source, and the
adapter keeps the server's verdict.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from remora.adapters.action_gate import (
    AsyncActionGate,
    AsyncLocalGateway,
    AutoGenActionAdapter,
    CrewAIActionAdapter,
    LangGraphActionAdapter,
    OpenAIToolCallingAdapter,
)
from remora.adapters.gateway import GatewayResult

REGISTRY = {
    "read_telemetry": {"risk_tier": "low", "action_type": "read"},
    "xfer": {"risk_tier": "high", "action_type": "financial_write"},
}


def _result(action: str, **extra: Any) -> GatewayResult:
    return GatewayResult(
        action=action, human_review_required=action != "accept",
        evidence_required=False, explanation=f"engine said {action}",
        confidence=0.95, risk_estimate=0.05, require_rag=False,
        refuse_parametric_verdict=False, source_of_decision="rule_engine",
        state_hash="h", **extra,
    )


class _RecordingGateway:
    """Accepts anything labelled low/read; records what it was sent."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def assess_sync(self, question: str, **kwargs: Any) -> GatewayResult:
        self.calls.append(kwargs)
        if kwargs.get("risk_tier") == "low" and kwargs.get("action_type") == "read":
            return _result("accept")
        return _result("verify")


class _ServerLabelGateway(_RecordingGateway):
    """A remote gateway whose server resolved the labels from its registry."""

    accepts_tool_call = True

    def assess_sync(self, question: str, **kwargs: Any) -> GatewayResult:
        self.calls.append(kwargs)
        return _result("accept", label_source="registry")


def _attack(adapter):
    return adapter.intercept(
        action_name="xfer", action_args={"to": "attacker", "amt": 1_000_000},
        proposed_by="agent", domain="finance", risk_tier="low",
        action_type="read", target_environment="staging", context={})


@pytest.mark.parametrize("cls", [LangGraphActionAdapter, OpenAIToolCallingAdapter,
                                 CrewAIActionAdapter, AutoGenActionAdapter])
def test_caller_labels_without_registry_cannot_execute(cls) -> None:
    out = _attack(cls(gateway=_RecordingGateway()))
    assert out.should_execute is False
    assert out.envelope.gate.outcome == "verify"
    assert out.label_source == "caller"
    assert out.label_cap == "caller_labels_untrusted"
    assert "caller_labels_untrusted" in out.envelope.assessment.policy_triggers


def test_registry_labels_replace_the_callers() -> None:
    gw = _RecordingGateway()
    out = _attack(LangGraphActionAdapter(gateway=gw, registry=REGISTRY))
    assert out.should_execute is False
    assert gw.calls[-1]["risk_tier"] == "high"
    assert gw.calls[-1]["action_type"] == "financial_write"
    assert out.envelope.request.risk_tier == "high"
    assert out.label_source == "registry"


def test_registered_low_read_still_executes() -> None:
    adapter = LangGraphActionAdapter(gateway=_RecordingGateway(), registry=REGISTRY)
    out = adapter.intercept(
        action_name="read_telemetry", action_args={"asset": "P-1"},
        proposed_by="agent", domain="ops", risk_tier="low", action_type="read",
        target_environment="staging", context={})
    assert out.should_execute is True
    assert out.label_cap is None


def test_unregistered_tool_fails_closed() -> None:
    gw = _RecordingGateway()
    out = LangGraphActionAdapter(gateway=gw, registry=REGISTRY).intercept(
        action_name="drop_everything", action_args={}, proposed_by="agent",
        domain="ops", risk_tier="low", action_type="read",
        target_environment="staging", context={})
    assert out.should_execute is False
    assert gw.calls[-1]["risk_tier"] == "critical"
    assert out.label_source == "unregistered"


def test_conflicting_action_type_caps_accept() -> None:
    out = LangGraphActionAdapter(gateway=_RecordingGateway(), registry=REGISTRY).intercept(
        action_name="read_telemetry", action_args={}, proposed_by="agent",
        domain="ops", risk_tier="low", action_type="write",
        target_environment="staging", context={})
    assert out.should_execute is False
    assert out.label_cap == "registry_label_conflict"


def test_a_malformed_registry_is_refused_at_construction() -> None:
    with pytest.raises(ValueError):
        LangGraphActionAdapter(gateway=_RecordingGateway(),
                               registry={"xfer": {"risk_tier": "tiny"}})


def test_server_resolved_labels_are_kept() -> None:
    gw = _ServerLabelGateway()
    out = _attack(LangGraphActionAdapter(gateway=gw))
    assert gw.calls[-1]["tool_call"] == {
        "tool_name": "xfer", "arguments": {"to": "attacker", "amt": 1_000_000}}
    assert out.should_execute is True
    assert out.label_source == "registry"


def test_async_gate_applies_the_same_rule() -> None:
    gate = AsyncActionGate(gateway=AsyncLocalGateway(sync_gateway=_RecordingGateway()))
    out = asyncio.run(gate.intercept(
        action_name="xfer", action_args={}, proposed_by="agent", domain="finance",
        risk_tier="low", action_type="read", target_environment="staging",
        context={}))
    assert out.should_execute is False
    assert out.label_cap == "caller_labels_untrusted"


def test_async_gate_with_registry_executes_a_registered_read() -> None:
    gate = AsyncActionGate(gateway=AsyncLocalGateway(sync_gateway=_RecordingGateway()),
                           registry=REGISTRY)
    out = asyncio.run(gate.intercept(
        action_name="read_telemetry", action_args={}, proposed_by="agent",
        domain="ops", risk_tier="low", action_type="read",
        target_environment="staging", context={}))
    assert out.should_execute is True

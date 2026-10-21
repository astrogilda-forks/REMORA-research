# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The execution API runs the strict monotone profile by default (NEGATIVE_RESULTS §90)."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from remora.policy.decision_engine import RemoraDecisionEngine  # noqa: E402
from remora.policy.observation import PolicyObservation  # noqa: E402
from remora.policy.report import DecisionAction, DecisionReason  # noqa: E402


@pytest.mark.parametrize("value, strict", [(None, True), ("1", True), ("0", False),
                                           ("off", False)])
def test_the_enforcing_engine_is_strict_unless_turned_off(monkeypatch, value, strict):
    import servers.execution_api as exec_mod

    if value is None:
        monkeypatch.delenv("REMORA_STRICT_MONOTONE", raising=False)
    else:
        monkeypatch.setenv("REMORA_STRICT_MONOTONE", value)
    assert exec_mod._engine_from_env().strict_monotone is strict


def test_the_library_default_is_unchanged():
    assert RemoraDecisionEngine().strict_monotone is False


def test_strict_refusal_is_named_and_keeps_the_firewall_invariant():
    flagged = PolicyObservation(question="q", risk_tier="low", action_type="read",
                                target_environment="staging", adversarial_detected=True)
    report = RemoraDecisionEngine(strict_monotone=True, execution_profile=True).decide(flagged)
    assert report.action is DecisionAction.ABSTAIN
    assert DecisionReason.RISK_SIGNAL_NO_ROUTE in report.reasons
    assert DecisionReason.INVARIANT_VIOLATION_ESCALATE not in report.reasons

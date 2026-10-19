# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WP2/WP3 end to end in the synthetic simulator (WS1 §13.2).

Structural assertions only: these are eight scripted scenarios, not a sample.
"""
from __future__ import annotations

from experiments.ws1_composition.simulator import ARMS, MONITORS, run_all, scenarios

OUTCOMES = run_all()


def _get(scenario, arm, monitor="honest"):
    return next(o for o in OUTCOMES
                if (o.scenario, o.arm, o.monitor) == (scenario, arm, monitor))


def test_no_arm_and_no_monitor_dispatches_an_unauthorized_call():
    assert len(OUTCOMES) == len(scenarios()) * len(ARMS) * len(MONITORS)
    assert [o for o in OUTCOMES if o.dispatched and not o.authorized] == []


def test_h0_cannot_recover_what_needs_evidence():
    assert not any(o.dispatched for o in OUTCOMES if o.arm == "H0")


def test_h_det_recovers_resolvable_calls_and_keeps_refusing_the_rest():
    for name in ("legit_full", "report_to_reader"):
        assert _get(name, "H_DET").dispatched, name
    for name in ("wrong_port", "wrong_circuit_last", "cross_tenant_port", "report_to_attacker"):
        assert "precondition_refuted" in _get(name, "H_DET").reason_codes, name
    assert "lookup_did_not_prove" in _get("unknown_port", "H_DET").reason_codes
    # Authorized by the records, but no resolver is registered: the ceiling is coverage.
    reboot = _get("reboot_without_resolver", "H_DET")
    assert reboot.authorized and not reboot.dispatched
    assert "no_resolver_available" in reboot.reason_codes


def test_a_hostile_monitor_gets_no_more_than_the_deterministic_arm():
    for s in scenarios():
        hostile = _get(s.name, "H_EDV", "malicious_allow")
        det = _get(s.name, "H_DET", "malicious_allow")
        assert hostile.dispatched <= det.dispatched
        assert hostile.resolver_calls <= det.resolver_calls  # dropped hints add no lookups


def test_sabotage_and_outage_cost_utility_never_authority():
    for monitor in ("saboteur", "outage"):
        assert not any(o.dispatched for o in OUTCOMES if o.monitor == monitor)


def test_every_arm_ends_with_an_explicit_stop_reason():
    assert all(o.stop_reason for o in OUTCOMES)

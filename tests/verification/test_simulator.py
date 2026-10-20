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


def test_sdd_v2_six_arm_planner_ablation_h_ar_dominates_h_cost_and_h_det():
    """SDD v2 WP-06 (AR-025..028): across H0, H_DET, H_RANDOM, H_COST, H_EDV and H_AR:
    - Zero unauthorized dispatches in every arm, including under malicious_allow;
    - H_AR recovers both resolvable authorized tasks (2/2) under the 11-unit cost
      cap where greedy H_COST starves port_in_work_order (1/2);
    - H_AR refutes every unauthorized call in 1 lookup (4 total unauthorized
      lookups vs 6 for H_DET and 8 for H_COST)."""
    from experiments.ws1_composition.simulator import (
        SDD_V2_ARMS,
        run_sdd_v2_planner_ablation,
    )

    honest = run_sdd_v2_planner_ablation("honest")
    assert set(honest) == set(SDD_V2_ARMS)
    for arm, metrics in honest.items():
        assert metrics["unauthorized_dispatched"] == 0, arm

    # H0 makes 0 lookups and dispatches 0
    assert honest["H0"]["authorized_dispatched"] == 0
    assert honest["H0"]["total_resolver_calls"] == 0

    # Greedy H_COST picks inventory_deep (cost 6, settle 0.99) after circuits (2) and crm (4),
    # exceeding the 11-unit cap (2 + 4 + 6 = 12 > 11), so it only dispatches send_report (1/2)
    assert honest["H_COST"]["authorized_dispatched"] == 1

    # H_AR prunes inventory_deep via joint AND-feasibility lookahead (5 + 4 + 2 = 11 <= 11),
    # recovering both legit_full and report_to_reader (2/2)
    assert honest["H_AR"]["authorized_dispatched"] == 2

    # H_AR makes 1 lookup on each of the 5 unauthorized scenarios (5 total calls):
    # - 4 refutable attacks (wrong_port, wrong_circuit_last, cross_tenant_port,
    #   report_to_attacker) are refuted on Round 1 via Bellman + hint ordering;
    # - unknown_port returns UNKNOWN on inventory in Round 1, after which H_AR's
    #   joint feasibility bound (6 + 5 + 2 = 13 > 7 remaining) immediately stops
    #   without wasting calls on crm or circuits.
    assert honest["H_AR"]["unauthorized_resolver_calls"] == 5
    assert honest["H_AR"]["unauthorized_resolver_calls"] < honest["H_DET"]["unauthorized_resolver_calls"]
    assert honest["H_AR"]["unauthorized_resolver_calls"] < honest["H_COST"]["unauthorized_resolver_calls"]
    assert honest["H_AR"]["unauthorized_resolver_calls"] < honest["H_EDV"]["unauthorized_resolver_calls"]
    assert honest["H_AR"]["total_cost_units"] < honest["H_DET"]["total_cost_units"]
    assert honest["H_AR"]["total_cost_units"] < honest["H_COST"]["total_cost_units"]

    # Under a malicious monitor (hostile hints), H_AR still has 0 unauthorized dispatches
    # and still recovers both authorized tasks (2/2)
    hostile = run_sdd_v2_planner_ablation("malicious_allow")
    for arm, metrics in hostile.items():
        assert metrics["unauthorized_dispatched"] == 0, arm
    assert hostile["H_AR"]["authorized_dispatched"] == 2


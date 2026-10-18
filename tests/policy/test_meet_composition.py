# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""COMP-01: monotone (meet) composition of decision components (SDD §3.9, P-MONO).

The engine used to be a first-match cascade: the first component that fired
decided, and later components never ran. A VERIFY from the taint floor or
from an early gate therefore masked a later gate that demanded ESCALATE, and
an approver could redeem a call a stricter component had sent to a higher
authority. Under meet composition every component returns a cap and the
final decision is the least executable one:
``ABSTAIN ≡ ESCALATE < VERIFY < ACCEPT``, with a refusal no review can lift
(``NON_APPROVABLE_REASONS``) below all of them (RMR-AUD-003).

Searched validation over a declared generated domain (``_observations``):
no counterexample found is not a proof.
"""
from __future__ import annotations

import itertools

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from remora.credal import compute_from_obs
from remora.policy.composition import (
    EXECUTABILITY,
    Cap,
    executability,
    meet,
)
from remora.policy.decision_engine import (
    _CONDITIONAL_GATES,
    _ESTIMATOR_GATES,
    _MATRIX_GATES,
    RemoraDecisionEngine,
    _normalize_observation,
    hard_guard_floor,
    trap_score,
)
from remora.policy.observation import PolicyObservation
from remora.policy.report import DecisionAction, DecisionReason

A, V, AB, E = (DecisionAction.ACCEPT, DecisionAction.VERIFY,
               DecisionAction.ABSTAIN, DecisionAction.ESCALATE)


# ── the meet itself ─────────────────────────────────────────────────────


def test_executability_order():
    assert executability(E) == executability(AB) < executability(V) < executability(A)


def test_a_non_approvable_refusal_ranks_below_escalate():
    refusal = Cap("floor", AB, DecisionReason.CROSS_TENANT_ARGUMENT_BLOCKED)
    escalate = Cap("floor", E, DecisionReason.MALFORMED_CALL_BLOCKED)
    epistemic = Cap("rest", AB, DecisionReason.DEFAULT_SAFE_ABSTAIN)
    assert meet([escalate, refusal]) is refusal
    assert meet([escalate, epistemic]) is escalate  # the tie keeps the earliest
    assert meet([escalate, Cap("rest", AB, DecisionReason.DEFAULT_SAFE_ABSTAIN,
                               approvable=False)]).source == "rest"
    assert set(EXECUTABILITY) == set(DecisionAction)


def test_meet_picks_the_least_executable_and_keeps_order_on_ties():
    caps = [Cap("floor", V, DecisionReason.TAINTED_ARGUMENT_VERIFY),
            Cap("gate", E, DecisionReason.ENV_MISMATCH_ESCALATE),
            Cap("monitor", AB, DecisionReason.MONITOR_CAP)]
    chosen = meet(caps)
    assert chosen.action is E and chosen.source == "gate"
    with pytest.raises(ValueError):
        meet([])


# ── masked escalations are no longer masked ────────────────────────────

_MASKED = {
    "taint VERIFY masked an environment-mismatch ESCALATE": (
        dict(risk_tier="medium", action_type="write", argument_tainted=True,
             environment_mismatch_detected=True, rollback_available=True),
        DecisionReason.ENV_MISMATCH_ESCALATE),
    "taint VERIFY masked a goal-contradiction ESCALATE": (
        dict(risk_tier="medium", action_type="write", argument_tainted=True,
             proposed_tool_name="send_money", tool_matches_goal=False,
             rollback_available=True),
        DecisionReason.TOOL_DOES_NOT_MATCH_GOAL),
}


def test_an_earlier_gate_in_the_conditional_group_no_longer_masks_a_later_one():
    """RMR-AUD-003 part 2. COMP-01 took the group's first gate, so an
    oracle-quorum VERIFY hid a later environment-mismatch ESCALATE. Every gate
    that fires is now a cap."""
    report = RemoraDecisionEngine().decide(PolicyObservation(
        question="q", risk_tier="medium", action_type="read", valid_oracle_count=1,
        phase="ordered", trust_score=0.92, environment_mismatch_detected=True))
    assert report.action is E
    assert DecisionReason.ENV_MISMATCH_ESCALATE in report.reasons


@pytest.mark.parametrize("name", sorted(_MASKED))
def test_a_later_escalation_is_not_masked_by_an_earlier_verify(name):
    fields, binding = _MASKED[name]
    report = RemoraDecisionEngine().decide(PolicyObservation(question="q", **fields))
    assert report.action is E
    assert binding in report.reasons
    # The first-match reason stays on the record, so the audit shows both.
    assert report.reasons.index(binding) == len(report.reasons) - 1


def test_explain_reports_the_composed_decision():
    obs = PolicyObservation(question="q", **_MASKED[sorted(_MASKED)[0]][0])
    engine = RemoraDecisionEngine()
    trace = engine.explain(obs)
    assert trace.action == engine.decide(obs).action.value
    assert any(step.rule == "meet_composition" and step.triggered
               for step in trace.rule_evaluations)


def test_ties_keep_the_first_match_decision():
    # The schema floor's ESCALATE and a later ABSTAIN are equally blocking;
    # meet keeps the earlier component, so the reason set does not change.
    engine = RemoraDecisionEngine()
    obs = PolicyObservation(question="q", risk_tier="low", schema_valid=False)
    assert engine.decide(obs).reasons == (DecisionReason.MALFORMED_CALL_BLOCKED,)


# ── external caps: monitors and control protocols ──────────────────────


def _clean_accept() -> PolicyObservation:
    return PolicyObservation(question="read service metrics", risk_tier="low",
                             action_type="read", phase="ordered", trust_score=0.92)


def test_a_monitor_cap_lowers_an_accept():
    engine = RemoraDecisionEngine()
    assert engine.decide(_clean_accept()).action is A
    report = engine.decide(_clean_accept(),
                           caps=[Cap("monitor", E, DecisionReason.MONITOR_CAP)])
    assert report.action is E
    assert report.reasons[-1] is DecisionReason.MONITOR_CAP


def test_explain_reflects_external_caps():
    engine = RemoraDecisionEngine()
    caps = [Cap("monitor", E, DecisionReason.MONITOR_CAP)]
    trace = engine.explain(_clean_accept(), caps=caps)
    assert trace.action == engine.decide(_clean_accept(), caps=caps).action.value == "escalate"


def test_a_cap_can_never_raise_a_decision():
    engine = RemoraDecisionEngine()
    obs = PolicyObservation(question="q", **_MASKED[sorted(_MASKED)[0]][0])
    base = engine.decide(obs)
    lifted = engine.decide(obs, caps=[Cap("monitor", A, DecisionReason.MONITOR_CAP),
                                      Cap("protocol", A, DecisionReason.PROTOCOL_CAP)])
    assert lifted.action is base.action
    assert lifted.reasons == base.reasons


def test_external_caps_need_the_cap_reasons():
    with pytest.raises(ValueError):
        RemoraDecisionEngine().decide(
            _clean_accept(), caps=[Cap("monitor", E, DecisionReason.LOW_TRUST)])


# ── P-MONO as a property ────────────────────────────────────────────────

_observations = st.builds(
    PolicyObservation,
    question=st.just("q"),
    risk_tier=st.sampled_from(["low", "medium", "high", "critical", None]),
    action_type=st.sampled_from(["read", "write", "delete", "transfer", None]),
    target_environment=st.sampled_from(["prod", "sandbox", None]),
    argument_tainted=st.booleans(),
    untrusted_controlled_arguments=st.sampled_from([(), ("recipient",), ("query",)]),
    rollback_available=st.sampled_from([None, True, False]),
    state_transition_uncertain=st.booleans(),
    schema_valid=st.sampled_from([None, True, False]),
    tool_forbidden=st.booleans(),
    adversarial_detected=st.booleans(),
    trust_score=st.sampled_from([None, 0.1, 0.5, 0.9]),
    phase=st.sampled_from([None, "ordered", "critical", "disordered"]),
    proposed_tool_name=st.sampled_from([None, "send_money", "get_balance"]),
    tool_matches_goal=st.sampled_from([None, True, False]),
    expected_effect_matches=st.sampled_from([None, True, False]),
    environment_mismatch_detected=st.booleans(),
    counterfactual_passed=st.sampled_from([None, True, False]),
    valid_oracle_count=st.sampled_from([0, 1, 3]),
)
_external = st.lists(st.tuples(st.sampled_from(["monitor", "protocol"]),
                               st.sampled_from(list(DecisionAction))), max_size=2)
_ENGINES = (RemoraDecisionEngine(),
            RemoraDecisionEngine(low_consequence_accept=True, semantic_authority_floor=True))


def _component_actions(engine, obs):
    """Every component cap: the floor and every conditional gate that fires,
    except an estimator gate when the explicit risk matrix fired."""
    n = _normalize_observation(obs)
    credal, trap = compute_from_obs(n), trap_score(n)
    floor = hard_guard_floor(n)
    out = [floor[0]] if floor else []
    fired = [(g.name, a) for g in _CONDITIONAL_GATES if (a := g.evaluate(engine, n, credal, trap))]
    if any(name in _MATRIX_GATES for name, _ in fired):
        fired = [(name, a) for name, a in fired if name not in _ESTIMATOR_GATES]
    out.extend(a for _, a in fired)
    return out


@settings(max_examples=1500, deadline=None)
@given(_observations, _external, st.sampled_from(range(len(_ENGINES))))
def test_no_component_is_exceeded(obs, external, which):
    """P-MONO: the final decision is at most as executable as every component cap."""
    engine = _ENGINES[which]
    caps = [Cap(src, act, DecisionReason.MONITOR_CAP if src == "monitor"
                else DecisionReason.PROTOCOL_CAP) for src, act in external]
    final = engine.decide(obs, caps=caps).action
    for action in [*_component_actions(engine, obs), *(c.action for c in caps)]:
        assert executability(final) <= executability(action)
    # And composition never raises the cascade's own result.
    assert executability(final) <= executability(engine.decide(obs).action)


def test_block_recall_of_the_composite_dominates_each_component():
    """The deductive consequence §3.9 states, on a finite grid."""
    engine = RemoraDecisionEngine()
    grid = itertools.product(["low", "high"], [False, True], [False, True], list(DecisionAction))
    for tier, tainted, mismatch, monitor in grid:
        obs = PolicyObservation(question="q", risk_tier=tier, action_type="write",
                                argument_tainted=tainted,
                                environment_mismatch_detected=mismatch)
        final = engine.decide(obs, caps=[Cap("monitor", monitor, DecisionReason.MONITOR_CAP)])
        if monitor is not A:
            assert final.action is not A

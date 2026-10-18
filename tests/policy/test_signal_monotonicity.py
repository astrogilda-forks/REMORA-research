# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Signal monotonicity of the decision engine (P-MONO, RMR-AUD-001/003).

Adding a risk or failure signal to an observation must never make the
decision more executable. On the execution path an ABSTAIN has no approval
route, an ESCALATE has one (a higher authority can approve it), and a VERIFY
has one an ordinary reviewer can use, so the order is
``ABSTAIN < ESCALATE < VERIFY < ACCEPT``. The R3 audit (2026-10-18) reproduced
three ways to climb it on master ``b64e3cc1``:

1. a VERIFY gate early in ``_CONDITIONAL_GATES`` hid a later ESCALATE gate;
2. an ESCALATE hard guard hid a non-approvable ABSTAIN guard
   (``schema_valid=False`` turned a cross-tenant refusal into a review item);
3. a risk signal on a call the rest of the policy abstains on for lack of
   evidence (DEFAULT_SAFE_ABSTAIN) opens a review route: a tainted argument
   gives VERIFY, ``schema_valid=False`` gives ESCALATE. That is the engine
   half of RMR-AUD-001. It is still open (strict xfail below): the hard
   guards and the conditional gates are the designed route to a person for
   calls with no trust signal, so closing it is an owner decision on what
   DEFAULT_SAFE_ABSTAIN means. The exploit in RMR-AUD-001 also needs the
   ``/execute`` request to differ from the assessed one, which the
   review-path binding closes.

Searched validation over a declared generated domain: no counterexample found
is not a proof.
"""
from __future__ import annotations

from dataclasses import replace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from remora.policy.composition import NON_APPROVABLE_REASONS, executability
from remora.policy.decision_engine import RemoraDecisionEngine
from remora.policy.observation import PolicyObservation
from remora.policy.report import DecisionAction, DecisionReason

A, V, AB, E = (DecisionAction.ACCEPT, DecisionAction.VERIFY,
               DecisionAction.ABSTAIN, DecisionAction.ESCALATE)
_ENGINES = (
    RemoraDecisionEngine(),
    RemoraDecisionEngine(low_consequence_accept=True, semantic_authority_floor=True),
    RemoraDecisionEngine(execution_profile=True, low_consequence_accept=True),
)


def _decide(obs: PolicyObservation, engine: RemoraDecisionEngine = _ENGINES[0]):
    return engine.decide(obs)


# ── the audit's counterexamples ────────────────────────────────────────


def test_distribution_shift_does_not_hide_rollback_unavailable():
    base = PolicyObservation(question="drop prod db", risk_tier="critical",
                             action_type="destructive_write", target_environment="prod",
                             rollback_available=False)
    shifted = replace(base, distribution_shift_detected=True)
    assert _decide(base).action is E
    assert _decide(shifted).action is E
    assert DecisionReason.ROLLBACK_UNAVAILABLE in _decide(shifted).reasons


def test_high_risk_without_evidence_does_not_hide_environment_mismatch():
    base = PolicyObservation(question="write", risk_tier="high", action_type="write",
                             evidence_action=None)
    mismatched = replace(base, environment_mismatch_detected=True)
    assert _decide(mismatched).action is E
    assert DecisionReason.ENV_MISMATCH_ESCALATE in _decide(mismatched).reasons


@pytest.mark.parametrize("engine", _ENGINES)
@pytest.mark.parametrize("trusted", [False, True])
def test_taint_never_masks_a_goal_mismatch_escalation(engine, trusted):
    """Review path: an ``untrusted_context`` sets ``argument_tainted``, whose
    floor is VERIFY. A mutating call whose tool does not match the goal is
    ESCALATE, and adding taint must not bring it down to VERIFY (an ordinary
    approver could then redeem it). On a read the mismatch is ABSTAIN and
    stays ABSTAIN."""
    extra = dict(phase="ordered", trust_score=0.92) if trusted else {}
    write = PolicyObservation(question="pay the invoice", risk_tier="medium",
                              action_type="write", proposed_tool_name="send_money",
                              tool_matches_goal=False, rollback_available=True, **extra)
    read = replace(write, action_type="read", proposed_tool_name="get_balance")
    for base in (write, read):
        before = engine.decide(base)
        assert before.action in (E, AB)
        for taint in (dict(argument_tainted=True),
                      dict(argument_tainted=True, untrusted_controlled_arguments=("query",))):
            after = engine.decide(replace(base, **taint))
            assert executability(after.action) <= executability(before.action)
            assert after.action is not V
            assert DecisionReason.TOOL_DOES_NOT_MATCH_GOAL in after.reasons


_REFUSALS = {
    "cross-tenant argument": dict(argument_scope_valid=False),
    "unresolved intent provenance": dict(intent_provenance_required=True,
                                         intent_provenance_resolved=False),
}
_ESCALATING_FLAGS = {
    "schema_valid=False": dict(schema_valid=False),
    "tool_forbidden": dict(tool_forbidden=True),
    "coercion": dict(coercion_detected=True),
    "argument_tainted": dict(argument_tainted=True),
    "tainted sensitive argument": dict(argument_tainted=True,
                                       untrusted_controlled_arguments=("recipient",)),
}


@pytest.mark.parametrize("refusal", sorted(_REFUSALS))
@pytest.mark.parametrize("flag", sorted(_ESCALATING_FLAGS))
def test_a_non_approvable_refusal_survives_an_escalating_flag(refusal, flag):
    base = PolicyObservation(question="read", risk_tier="low", action_type="read",
                             **_REFUSALS[refusal])
    flagged = replace(base, **_ESCALATING_FLAGS[flag])
    assert _decide(base).action is AB
    report = _decide(flagged)
    assert report.action is AB
    assert not report.human_review_required


def test_an_adversarial_flag_on_an_otherwise_accepted_call_escalates():
    accepted = PolicyObservation(question="read service metrics", risk_tier="low",
                                 action_type="read", phase="ordered", trust_score=0.92)
    assert _decide(accepted).action is A
    report = _decide(replace(accepted, adversarial_detected=True))
    assert report.action is E
    assert report.reasons == (DecisionReason.ADMISSION_FIREWALL_BLOCKED,)


# ── the property ───────────────────────────────────────────────────────

_base = st.builds(
    PolicyObservation,
    question=st.just("q"),
    risk_tier=st.sampled_from(["low", "medium", "high", "critical", None]),
    action_type=st.sampled_from(["read", "write", "delete", "transfer", None]),
    target_environment=st.sampled_from(["prod", "staging", "sandbox", None]),
    trust_score=st.sampled_from([None, 0.1, 0.5, 0.92]),
    phase=st.sampled_from([None, "ordered", "critical", "disordered"]),
    proposed_tool_name=st.sampled_from([None, "send_money", "get_balance", "read_telemetry"]),
    schema_valid=st.sampled_from([None, True]),
    rollback_available=st.sampled_from([None, True]),
    # False in the base too, so a base that already ESCALATEs on a goal or
    # effect mismatch also gets taint and other signals added to it.
    tool_matches_goal=st.sampled_from([None, True, False]),
    expected_effect_matches=st.sampled_from([None, True, False]),
    evidence_action=st.sampled_from([None, "answer", "evidence_accept"]),
    valid_oracle_count=st.sampled_from([0, 3]),
)

#: Hard-guard signals: client-controlled downgrade fields and hard failures.
#: The floor exists to restrict, so none of them may open an approval route.
_FLOOR_SIGNALS = {
    "adversarial": dict(adversarial_detected=True),
    "malformed": dict(schema_valid=False),
    "forbidden": dict(tool_forbidden=True),
    "cross_tenant": dict(argument_scope_valid=False),
    "intent_unresolved": dict(intent_provenance_required=True, intent_provenance_resolved=False),
    "coercion": dict(coercion_detected=True),
    "blackmail": dict(blackmail_pattern_detected=True),
    "counterfactual_failed": dict(counterfactual_passed=False),
    "contradiction": dict(evidence_contradictions=1),
    "contradiction_cycle": dict(evidence_contradictions=1, contradiction_cycles=1),
    "tainted": dict(argument_tainted=True),
    "tainted_sensitive": dict(argument_tainted=True, untrusted_controlled_arguments=("recipient",)),
}
#: Conditional-gate signals: risk the gates route to review.
_GATE_SIGNALS = {
    "no_rollback": dict(rollback_available=False),
    "uncertain_transition": dict(state_transition_uncertain=True),
    "env_mismatch": dict(environment_mismatch_detected=True),
    "distribution_shift": dict(distribution_shift_detected=True),
    "goal_mismatch": dict(tool_matches_goal=False),
    "effect_contradicted": dict(expected_effect_matches=False),
}
_SIGNALS = {**_FLOOR_SIGNALS, **_GATE_SIGNALS}

#: ABSTAIN reasons that mean "no basis to run autonomously", not "refused".
#: A risk signal on such a call still opens a review route; that is open.
_EPISTEMIC_ABSTAIN = frozenset({
    DecisionReason.DEFAULT_SAFE_ABSTAIN,
    DecisionReason.DISORDERED_NO_EVIDENCE,
    DecisionReason.LOW_TRUST,
})


def _apply(obs: PolicyObservation, names, table) -> PolicyObservation:
    for name in names:
        obs = replace(obs, **table[name])
    return obs


def _rank(report) -> int:
    """The report's place in the meet (``composition.rank`` on its reasons)."""
    if report.action is AB and set(report.reasons) & NON_APPROVABLE_REASONS:
        return -1
    return executability(report.action)


def _epistemic(report) -> bool:
    return report.action is AB and bool(set(report.reasons) & _EPISTEMIC_ABSTAIN)


@settings(max_examples=3000, deadline=None)
@given(_base,
       st.lists(st.sampled_from(sorted(_GATE_SIGNALS)), max_size=2, unique=True),
       st.lists(st.sampled_from(sorted(_FLOOR_SIGNALS)), min_size=1, max_size=3, unique=True),
       st.sampled_from(range(len(_ENGINES))))
def test_adding_a_risk_signal_never_raises_executability(base, gate_signals, floor_signals, which):
    """No signal lifts a decision in the meet's order, and none lifts a refusal
    no review can lift. A call that abstains for lack of evidence is exempt
    (open, see the strict xfail below)."""
    engine = _ENGINES[which]
    gated = _apply(base, gate_signals, _GATE_SIGNALS)
    flagged = _apply(gated, floor_signals, _FLOOR_SIGNALS)
    for before, after, added in ((engine.decide(base), engine.decide(gated), gate_signals),
                                 (engine.decide(gated), engine.decide(flagged), floor_signals)):
        if _epistemic(before):
            continue
        assert _rank(after) <= _rank(before), (
            added, before.action, before.reasons, after.action, after.reasons)


@pytest.mark.xfail(strict=True, reason=(
    "Open (RMR-AUD-001 engine half / RMR-AUD-003 residual): a risk signal on "
    "a call the rest of the policy abstains on for lack of evidence opens a "
    "review route. Hard guards and conditional gates are the designed route "
    "to a person for calls with no trust signal; closing this needs an owner "
    "decision on what DEFAULT_SAFE_ABSTAIN means."))
@pytest.mark.parametrize("signal", ["tainted", "malformed", "distribution_shift"])
def test_a_risk_signal_still_opens_a_route_over_an_epistemic_abstain(signal):
    base = PolicyObservation(question="read telemetry", risk_tier="low", action_type="read",
                             proposed_tool_name="read_telemetry", target_environment="staging")
    assert _decide(base).reasons == (DecisionReason.DEFAULT_SAFE_ABSTAIN,)
    assert _decide(replace(base, **_SIGNALS[signal])).action is AB


@pytest.mark.xfail(strict=True, reason=(
    "Open, present on master before RMR-AUD-003: raising a production write's "
    "risk tier from medium to high lowers the decision from ESCALATE (trap "
    "gate) to VERIFY (the explicit matrix, which "
    "test_production_write_matrix_is_explicit_and_conservative pins). Which "
    "of the two is right is an owner decision."))
def test_raising_the_risk_tier_never_lowers_a_production_write():
    medium = PolicyObservation(question="q", risk_tier="medium", action_type="production_write",
                               target_environment="prod", schema_valid=True)
    high = replace(medium, risk_tier="high")
    assert executability(_decide(high).action) <= executability(_decide(medium).action)

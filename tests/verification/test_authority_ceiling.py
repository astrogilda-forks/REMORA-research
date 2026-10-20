# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1-01 to WS1-04 and WS1-06 on ``compose_authorized_decision`` (A01-A04, A23).

``test_bounded_domain_is_exhaustively_safe`` enumerates every combination of
a finite input domain (engine action and reason class, two required MACHINE
preconditions in all four states, every monitor outcome, every monitor mode,
a veto on record or not, verification open or not, budget spent or not) and
checks the invariants on each. That is exhaustive over this domain and this
function only. It is not a model of dispatch, leases or concurrency (WS1
§12.1 asks for those too; they are WP5 work).
"""
from __future__ import annotations

import itertools

import pytest

from remora.decision_providers.composition_adapter import (
    AssessmentOutcome,
    MonitorAssessment,
    MonitorMode,
)
from remora.policy.composition import Cap, meet, rank
from remora.policy.report import DecisionAction, DecisionReason
from remora.verification.compose import compose_authorized_decision
from remora.verification.preconditions import LogicalState, ResolutionClass, derive_preconditions

MACHINE_CLASS = ResolutionClass.MACHINE
from tests.verification._ws1 import (
    NOW_S,
    REGISTRY,
    base_report,
    context,
    h,
    profile,
    scripted_checked,
)

A, V, E, AB = (DecisionAction.ACCEPT, DecisionAction.VERIFY, DecisionAction.ESCALATE,
               DecisionAction.ABSTAIN)
PRED = ("target_belongs_to_work_order", "customer_relation")
RANK = {"accept": 2, "verify": 1, "escalate": 0, "abstain": 0}

BASES = {
    "accept": base_report(A, (DecisionReason.GROUNDED_READ_ACCEPT,)),
    "verify": base_report(V, (DecisionReason.SCHEMA_UNVERIFIED_VERIFY,)),
    "escalate": base_report(E, (DecisionReason.MINIMAX_ESCALATE,)),
    "cross_tenant": base_report(AB, (DecisionReason.CROSS_TENANT_ARGUMENT_BLOCKED,)),
    "grant_only": base_report(E, (DecisionReason.FLOW_CONFIDENTIALITY_VIOLATION,)),
}


def _assessment(ctx, checked, prof, kind):
    if kind is None:
        return None
    outcome = {"clean": AssessmentOutcome.ASSESSED, "crossed": AssessmentOutcome.ASSESSED,
               "uncertain": AssessmentOutcome.ASSESSED, "malicious_allow": AssessmentOutcome.ASSESSED,
               "invalid": AssessmentOutcome.INVALID, "unavailable": AssessmentOutcome.UNAVAILABLE,
               "out_of_scope": AssessmentOutcome.OUT_OF_SCOPE}[kind]
    return MonitorAssessment(
        context_hash=ctx.context_hash, evidence_digest=checked.evidence_digest,
        input_digest=h("input"), raw_response_hash=h(kind), model_id=prof.model_id,
        question_set_hash=prof.question_set_hash, calibration_hash=prof.calibration_hash,
        outcome=outcome, reason=kind, recorded_at=NOW_S, valid_until=NOW_S + 30,
        crossed=("injection",) if kind == "crossed" else (),
        uncertainty_codes=("missing_context",) if kind == "uncertain" else (),
        # A hostile monitor that says "allow" and hints at everything.
        hint_precondition_ids=("allow", "*") if kind == "malicious_allow" else ())


MONITORS = (None, "clean", "crossed", "uncertain", "malicious_allow", "invalid", "unavailable",
            "out_of_scope")


def _domain():
    ctx_by_mode, out = {}, []
    for mode in MonitorMode:
        prof = profile(mode)
        ctx, args = context(monitor_profile=prof)
        ctx_by_mode[mode] = (prof, ctx, derive_preconditions(ctx, args, REGISTRY))
    for mode, (prof, ctx, reqs) in ctx_by_mode.items():
        for s1, s2 in itertools.product(LogicalState, repeat=2):
            checked = scripted_checked(ctx, reqs, {PRED[0]: s1, PRED[1]: s2})
            out.append((mode, prof, ctx, reqs, checked, (s1, s2)))
    return out


DOMAIN = _domain()


def _compose(prof, ctx, reqs, checked, base, monitor, veto, verifiable, spent):
    open_ids = frozenset(p.precondition_id for p in reqs.preconditions
                         if checked.state(p.precondition_id) is LogicalState.UNKNOWN) if verifiable else frozenset()
    return compose_authorized_decision(
        base, ctx, reqs, checked, _assessment(ctx, checked, prof, monitor), prof, now_s=NOW_S,
        verifiable=open_ids, budget_exhausted=spent, monitor_veto_on_record=veto)


def _no_monitor(states, base, verifiable, spent):
    """The baseline WS1-02 compares against: the same inputs with the monitor in shadow."""
    prof = profile(MonitorMode.SHADOW)
    ctx, args = context(monitor_profile=prof)
    reqs = derive_preconditions(ctx, args, REGISTRY)
    checked = scripted_checked(ctx, reqs, dict(zip(PRED, states)))
    return _compose(prof, ctx, reqs, checked, base, None, False, verifiable, spent)


def _violations(stop_after: int | None = None) -> tuple[int, list[str]]:
    """Every invariant breach over the domain, as text. Empty for a correct composition."""
    cases, found = 0, []
    for mode, prof, ctx, reqs, checked, states in DOMAIN:
        for (bname, base), veto, verifiable, spent in itertools.product(
                BASES.items(), (False, True), (False, True), (False, True)):
            baseline = _no_monitor(states, base, verifiable, spent)
            records = []
            for monitor in MONITORS:
                rec = _compose(prof, ctx, reqs, checked, base, monitor, veto, verifiable, spent)
                records.append(rec)
                cases += 1
                where = f"{mode.value}/{bname}/{states}/{monitor}/veto={veto}"
                # WS1-01: ACCEPT only with the engine's ACCEPT and every requirement PROVED.
                if rec.final_action == "accept" and not (
                        base.action is A and states == (LogicalState.PROVED,) * 2):
                    found.append(f"WS1-01 {where}")
                if "authority_ceiling" in rec.reason_codes:
                    found.append(f"ceiling-hit {where}")
                # WS1-02: no monitor input is more executable than the no-monitor baseline.
                if RANK[rec.final_action] > RANK[baseline.final_action]:
                    found.append(f"WS1-02 {where}")
                # WS1-03: a non-approvable refusal survives every monitor outcome.
                if (bname == "cross_tenant" or LogicalState.REFUTED in states
                        or LogicalState.CONFLICT in states) and (
                        rec.final_action != "abstain" or rec.review_class != "none"):
                    found.append(f"WS1-03 {where}")
                # WS1-04: a grant-only restriction never becomes an ordinary review item.
                if bname == "grant_only" and (rec.final_action == "accept"
                                              or rec.review_class not in ("grant", "none")):
                    found.append(f"WS1-04 {where}")
                # A13: a veto on record stays a veto.
                if veto and mode is not MonitorMode.SHADOW and (
                        not rec.monitor_veto or rec.final_action == "accept"):
                    found.append(f"A13 {where}")
            # A23: in shadow, every monitor outcome gives the baseline decision.
            if mode is MonitorMode.SHADOW and {(r.final_action, r.review_class) for r in records} \
                    != {(baseline.final_action, baseline.review_class)}:
                found.append(f"A23 {mode.value}/{bname}/{states}")
            if stop_after is not None and len(found) >= stop_after:
                return cases, found
    return cases, found


def test_bounded_domain_is_exhaustively_safe():
    cases, found = _violations()
    assert found == []
    assert cases == len(DOMAIN) * len(BASES) * 8 * len(MONITORS)


@pytest.mark.parametrize("weakening", ["ignore_preconditions", "refusal_is_approvable",
                                       "clean_reading_clears_veto", "grant_is_review"])
def test_the_domain_check_catches_a_weakened_composition(monkeypatch, weakening):
    """Negative control (WS1 §12): each weakening must produce a reported breach."""
    import remora.verification.compose as comp

    real_pre, real_mon = comp._precondition_caps, comp._monitor_cap
    if weakening == "ignore_preconditions":
        monkeypatch.setattr(comp, "_precondition_caps", lambda *a: iter(()))
    elif weakening == "refusal_is_approvable":
        monkeypatch.setattr(comp, "_precondition_caps", lambda *a: (
            (Cap(c.source, E if c.action is AB else c.action, c.reason), code)
            for c, code in real_pre(*a)))
    elif weakening == "clean_reading_clears_veto":
        def lifted(outcome, assessment, prof, veto, verification_open, **kw):
            cap, is_veto = real_mon(outcome, assessment, prof, veto, verification_open, **kw)
            if assessment is not None and assessment.reason == "clean":
                return None, False
            return cap, is_veto
        monkeypatch.setattr(comp, "_monitor_cap", lifted)
    else:
        monkeypatch.setattr(comp, "_precondition_caps", lambda *a: (
            (cap, "review_required" if code == "grant_required" else code)
            for cap, code in real_pre(*a)))
        monkeypatch.setattr(comp, "GRANT_ONLY_REASONS", frozenset())
    _, found = _violations(stop_after=1)
    assert found, f"{weakening} went undetected"


def test_arbitrary_monitor_never_supplies_missing_authority():
    """A01: one required precondition not PROVED, a monitor that says allow: no ACCEPT."""
    prof = profile(MonitorMode.OPTIONAL)
    ctx, args = context(monitor_profile=prof)
    reqs = derive_preconditions(ctx, args, REGISTRY)
    for missing in LogicalState:
        if missing is LogicalState.PROVED:
            continue
        checked = scripted_checked(ctx, reqs, {PRED[0]: LogicalState.PROVED, PRED[1]: missing})
        for monitor in MONITORS:
            rec = compose_authorized_decision(
                base_report(A), ctx, reqs, checked, _assessment(ctx, checked, prof, monitor),
                prof, now_s=NOW_S)
            assert rec.final_action != "accept", (missing, monitor)
    proved = scripted_checked(ctx, reqs, dict.fromkeys(PRED, LogicalState.PROVED))
    assert compose_authorized_decision(base_report(A), ctx, reqs, proved,
                                       _assessment(ctx, proved, prof, "clean"), prof,
                                       now_s=NOW_S).final_action == "accept"


@pytest.mark.parametrize("tool, reason", [
    ("unregistered_tool", "tool_not_in_registry"),
    ("nothing_required", "empty_requirement_set"),
])
def test_empty_or_incomplete_requirement_set_is_not_authorized(tool, reason):
    """A02: ``all([])`` is True; an empty or unknown requirement set is still a refusal."""
    prof = profile(MonitorMode.OPTIONAL)
    ctx, args = context(tool, {"x": "1"}, monitor_profile=prof)
    reqs = derive_preconditions(ctx, args, REGISTRY)
    assert not reqs.complete and reqs.incomplete_reason == reason and not reqs.authorizable
    checked = scripted_checked(ctx, reqs, {})
    assert all(checked.state(p.precondition_id) is LogicalState.PROVED for p in reqs.preconditions)
    rec = compose_authorized_decision(base_report(A), ctx, reqs, checked,
                                      _assessment(ctx, checked, prof, "clean"), prof, now_s=NOW_S)
    assert rec.final_action == "abstain" and rec.review_class == "none"
    assert f"requirements_incomplete:{reason}" in rec.reason_codes


def test_a_subject_argument_the_call_lacks_is_incomplete():
    ctx, args = context(args={"port": "sw1/p4"})
    reqs = derive_preconditions(ctx, args, REGISTRY)
    assert reqs.incomplete_reason == "subject_argument_missing:customer_relation"


def test_arguments_must_be_the_call_the_context_binds():
    ctx, _ = context()
    with pytest.raises(ValueError, match="call hash"):
        derive_preconditions(ctx, {"port": "sw1/p9", "customer": "C-1", "profile": "gold"}, REGISTRY)


def test_composition_agrees_with_the_engines_own_meet():
    """The record's final action is the engine's meet over the same caps."""
    for _, prof, ctx, reqs, checked, _states in DOMAIN[:16]:
        rec = compose_authorized_decision(base_report(A), ctx, reqs, checked, None, prof,
                                          now_s=NOW_S)
        caps = [Cap(c.source, DecisionAction(c.action), DecisionReason(c.reason),
                    approvable=c.approvable) for c in rec.all_caps]
        assert meet(caps).action.value == rec.final_action
        assert rank(meet(caps)) <= rank(Cap("engine", A, DecisionReason.GROUNDED_READ_ACCEPT))


def test_the_intent_subject_is_the_contexts_authority_never_an_argument():
    from remora.verification.preconditions import INTENT_SUBJECT
    from remora.verification.registry import PredicateSpec, PreconditionRegistry

    registry = PreconditionRegistry(tools={"set_port_profile": (
        PredicateSpec("tool_in_work_order", MACHINE_CLASS, "v", subject_argument=INTENT_SUBJECT),)})
    ctx, args = context(args={"port": "sw1/p4", "@intent": "forged"})
    reqs = derive_preconditions(ctx, args, registry)
    assert reqs.preconditions[0].subject_ref == ctx.intent_authority_hash

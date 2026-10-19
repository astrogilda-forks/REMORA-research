# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Compose the engine's decision, the precondition caps and the monitor cap (WS1 §8-9).

Every component is a :class:`~remora.policy.composition.Cap` and the result
is their meet, with the engine's own ``meet`` and ``rank``: no component can
raise a decision above what another allows, and a refusal no review can lift
ranks below everything. The record keeps every cap, not only the one that
won, so a grant-only or terminal restriction stays visible when another cap
gives the displayed reason.

The rows of WS1 §9, in the order they are applied:

* requirement set incomplete, or any binding mismatch: non-approvable ABSTAIN;
* a required precondition REFUTED or CONFLICT, or a TERMINAL one not PROVED:
  non-approvable ABSTAIN (a corrected call is a new proposal);
* GRANT not PROVED: ESCALATE on the grant route; REVIEW not PROVED: ESCALATE;
* MACHINE not PROVED: VERIFY while a registered resolver is untried and budget
  remains, otherwise non-approvable ABSTAIN (``no_resolver_available``,
  ``lookup_did_not_prove``, ``verification_budget_exhausted``,
  ``verification_stopped``);
* the monitor per its profile (``required``, ``optional``, ``shadow``). A veto
  already on record for this action stays, whatever the provider says now.

ACCEPT needs a complete requirement set with every required precondition
PROVED and an engine ACCEPT. That is checked again after the meet; a breach
would be a bug here and is refused rather than trusted.

This returns a record. It issues no token, lease or approval; the canonical
execution layer keeps that responsibility.
"""
from __future__ import annotations

from collections.abc import Iterable

from remora.decision_providers.composition_adapter import (
    AssessmentOutcome,
    MonitorAssessment,
    MonitorMode,
    MonitorProfile,
)
from remora.policy.composition import (
    GRANT_ONLY_REASONS,
    NON_APPROVABLE_REASONS,
    Cap,
    meet,
    rank,
)
from remora.policy.report import DecisionAction, DecisionReason, DecisionReport
from remora.verification.check import CheckedPreconditions
from remora.verification.preconditions import (
    LogicalState,
    ProposalContext,
    RequirementSet,
    ResolutionClass,
)
from remora.verification.records import CapEntry, CompositionRecord

__all__ = ["compose_authorized_decision", "monitor_usable"]

A, V, E, AB = (DecisionAction.ACCEPT, DecisionAction.VERIFY, DecisionAction.ESCALATE,
               DecisionAction.ABSTAIN)
_PRE, _MON = DecisionReason.PRECONDITION_CAP, DecisionReason.MONITOR_CAP


def monitor_usable(assessment: MonitorAssessment | None, profile: MonitorProfile,
                   context: ProposalContext, checked: CheckedPreconditions,
                   now_s: int) -> tuple[AssessmentOutcome, str]:
    """The outcome the composition may act on. A stale or mismatched record is an outage."""
    if assessment is None:
        return AssessmentOutcome.NOT_REQUESTED, "monitor_not_requested"
    if assessment.context_hash != context.context_hash:
        return AssessmentOutcome.UNAVAILABLE, "monitor_record_for_another_context"
    if assessment.evidence_digest != checked.evidence_digest:
        return AssessmentOutcome.UNAVAILABLE, "monitor_record_for_another_evidence_revision"
    if (assessment.model_id, assessment.question_set_hash, assessment.calibration_hash) != \
            (profile.model_id, profile.question_set_hash, profile.calibration_hash):
        return AssessmentOutcome.UNAVAILABLE, "monitor_record_for_another_profile"
    if not assessment.recorded_at <= now_s < assessment.valid_until:
        return AssessmentOutcome.UNAVAILABLE, "monitor_record_stale"
    return assessment.outcome, assessment.reason


def _precondition_caps(requirements: RequirementSet, checked: CheckedPreconditions,
                       verifiable: frozenset[str], budget_exhausted: bool,
                       ) -> Iterable[tuple[Cap, str]]:
    if not requirements.authorizable:
        yield (Cap("requirements", AB, _PRE, approvable=False),
               f"requirements_incomplete:{requirements.incomplete_reason or 'unknown'}")
        return
    for pre in requirements.preconditions:
        if not pre.required:
            continue
        state, source = checked.state(pre.precondition_id), f"precondition:{pre.precondition_id}"
        if state is LogicalState.PROVED:
            continue
        if state is LogicalState.REFUTED:
            yield Cap(source, AB, _PRE, approvable=False), "precondition_refuted"
        elif state is LogicalState.CONFLICT:
            yield Cap(source, AB, _PRE, approvable=False), "precondition_conflict"
        elif pre.resolution_class is ResolutionClass.TERMINAL:
            yield Cap(source, AB, _PRE, approvable=False), "terminal_precondition_unproved"
        elif pre.resolution_class is ResolutionClass.GRANT:
            yield Cap(source, E, _PRE), "grant_required"
        elif pre.resolution_class is ResolutionClass.REVIEW:
            yield Cap(source, E, _PRE), "review_required"
        elif pre.precondition_id in verifiable:
            yield Cap(source, V, _PRE), "verification_pending"
        elif not pre.resolver_ids:
            yield Cap(source, AB, _PRE, approvable=False), "no_resolver_available"
        elif (result := checked.result(pre.precondition_id)) is not None and result.evidence_refs:
            yield Cap(source, AB, _PRE, approvable=False), "lookup_did_not_prove"
        elif budget_exhausted:
            yield Cap(source, AB, _PRE, approvable=False), "verification_budget_exhausted"
        else:
            yield Cap(source, AB, _PRE, approvable=False), "verification_stopped"


def _monitor_cap(outcome: AssessmentOutcome, assessment: MonitorAssessment | None,
                 profile: MonitorProfile, veto_on_record: bool,
                 verification_open: bool) -> tuple[tuple[Cap, str] | None, bool]:
    """The monitor's cap and whether it is (or stays) a veto."""
    if profile.mode is MonitorMode.SHADOW:
        return None, False
    veto_action = E if profile.semantic_review_role else AB
    if veto_on_record:
        return (Cap("monitor", veto_action, _MON), "monitor_veto_sticky"), True
    if outcome is AssessmentOutcome.ASSESSED and assessment is not None:
        if assessment.crossed:
            return (Cap("monitor", veto_action, _MON), "monitor_risk_over_threshold"), True
        if assessment.uncertainty_codes and profile.mode is MonitorMode.REQUIRED:
            action = V if verification_open else AB
            return (Cap("monitor", action, _MON), "monitor_uncertain"), False
        return None, False
    if profile.mode is MonitorMode.REQUIRED:
        if outcome is AssessmentOutcome.OUT_OF_SCOPE and verification_open:
            return (Cap("monitor", V, _MON), "monitor_out_of_scope"), False
        return (Cap("monitor", AB, _MON), f"monitor_{outcome.value}"), False
    return None, False


def compose_authorized_decision(
    base: DecisionReport,
    context: ProposalContext,
    requirements: RequirementSet,
    checked: CheckedPreconditions,
    assessment: MonitorAssessment | None,
    profile: MonitorProfile,
    *,
    now_s: int,
    verifiable: frozenset[str] = frozenset(),
    budget_exhausted: bool = False,
    monitor_veto_on_record: bool = False,
    parent_record_hash: str | None = None,
) -> CompositionRecord:
    """One fresh composition over every cap. *verifiable* names the MACHINE
    preconditions that still have an untried registered resolver and budget."""
    base_reason = base.reasons[-1] if base.reasons else DecisionReason.DEFAULT_SAFE_ABSTAIN
    base_approvable = not set(base.reasons) & NON_APPROVABLE_REASONS
    caps: list[tuple[Cap, str]] = [(Cap("engine", base.action, base_reason,
                                        approvable=base_approvable), "engine")]

    if (requirements.context_hash, checked.context_hash) != (context.context_hash,) * 2 \
            or checked.requirements_hash != requirements.requirements_hash \
            or context.profile_hash != profile.profile_hash:
        caps.append((Cap("binding", AB, _PRE, approvable=False), "binding_mismatch"))
    if checked.earliest_expiry is not None and now_s >= checked.earliest_expiry:
        caps.append((Cap("freshness", AB, _PRE, approvable=False), "evidence_expired"))
    caps.extend(_precondition_caps(requirements, checked, verifiable, budget_exhausted))

    outcome, monitor_reason = monitor_usable(assessment, profile, context, checked, now_s)
    monitor, veto = _monitor_cap(outcome, assessment, profile, monitor_veto_on_record,
                                 verification_open=bool(verifiable))
    if monitor is not None:
        caps.append(monitor)

    final = meet(cap for cap, _ in caps)
    final_action = final.action
    codes = [code for cap, code in caps if code != "engine"]
    proved_all = requirements.authorizable and all(
        checked.state(p.precondition_id) is LogicalState.PROVED
        for p in requirements.preconditions if p.required)
    if final_action is A and not (proved_all and base.action is A):
        final_action, final = AB, Cap("ceiling", AB, _PRE, approvable=False)
        codes.append("authority_ceiling")

    if rank(final) < 0:
        review_class = "none"
    elif final_action in (E, AB) and (
            any(code == "grant_required" for _, code in caps)
            or set(base.reasons) & GRANT_ONLY_REASONS):
        review_class = "grant"
    elif final_action is E:
        review_class = "review"
    elif final_action is V:
        review_class = "verify"
    else:
        review_class = "none"

    return CompositionRecord(
        context_hash=context.context_hash, requirements_hash=requirements.requirements_hash,
        evidence_digest=checked.evidence_digest, profile_hash=profile.profile_hash,
        base_action=base.action.value, base_reasons=tuple(r.value for r in base.reasons),
        all_caps=tuple(CapEntry(c.source, c.action.value, c.reason.value,
                                c.approvable and rank(c) >= 0, code) for c, code in caps),
        all_precondition_results=tuple(r.to_dict() for r in checked.results),
        monitor_assessment=None if assessment is None else assessment.to_commitment(),
        monitor_status=f"{outcome.value}:{monitor_reason}", monitor_veto=veto,
        final_action=final_action.value, review_class=review_class,
        reason_codes=tuple(codes), parent_record_hash=parent_record_hash)

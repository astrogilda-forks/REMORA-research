# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Check resolver evidence against the requirement set (WS1 §6.2, §7.1 step 9).

Only evidence that answers a request this loop issued, from the registered
source, for this tenant and subject, with an intact payload and inside its
TTL, reaches a verifier. Anything else is ignored and recorded; it can never
become PROVED. A client or a model cannot post a result: results come out of
a registered verifier run here, and :class:`CheckedPreconditions` refuses to
be built anywhere else.

Every check starts from the full evidence list. A later round re-derives
every result rather than patching an earlier one, so evidence that has gone
stale drops back to UNKNOWN, and a valid refutation cannot be outvoted by
more confirmations: PROVED and REFUTED together are CONFLICT.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from remora.evidence.admission.canonical import decode_bounded
from remora.verification.preconditions import (
    ExecutionPrecondition,
    LogicalState,
    ProcessingStatus,
    ProposalContext,
    RequirementSet,
    tagged_digest,
)
from remora.verification.registry import PreconditionRegistry

__all__ = [
    "CheckedPreconditions",
    "PreconditionResult",
    "ResolverEvidence",
    "VerificationRequest",
    "Verifier",
    "check_preconditions",
]

_ISSUER = object()


@dataclass(frozen=True)
class VerificationRequest:
    """One bounded lookup the planner chose. Carries IDs only: no URL, query or shell."""

    request_id: str
    context_hash: str
    evidence_revision: int
    precondition_id: str
    resolver_id: str
    subject_ref: str
    deadline_ms: int
    budget_ref: str

    def to_dict(self) -> dict[str, Any]:
        return {"request_id": self.request_id, "context_hash": self.context_hash,
                "evidence_revision": self.evidence_revision,
                "precondition_id": self.precondition_id, "resolver_id": self.resolver_id,
                "subject_ref": self.subject_ref, "deadline_ms": self.deadline_ms,
                "budget_ref": self.budget_ref}


@dataclass(frozen=True)
class ResolverEvidence:
    """What a resolver fetched. Evidence data, not authority. Times are epoch seconds."""

    request_id: str
    resolver_id: str
    source_id: str
    subject_ref: str
    source_version: str
    tenant_id: str
    acquired_at: int
    valid_until: int
    payload: bytes
    payload_hash: str
    capture_method: str
    integrity_ref: str = ""

    @property
    def evidence_ref(self) -> str:
        return tagged_digest("evidence-item", {
            "request_id": self.request_id, "resolver_id": self.resolver_id,
            "source_id": self.source_id, "subject_ref": self.subject_ref,
            "source_version": self.source_version, "tenant_id": self.tenant_id,
            "acquired_at": self.acquired_at, "valid_until": self.valid_until,
            "payload_hash": self.payload_hash, "capture_method": self.capture_method,
            "integrity_ref": self.integrity_ref})


class Verifier(Protocol):
    """A deployment-registered check of one predicate over decoded payloads.

    Returns PROVED, REFUTED or UNKNOWN for one payload, with a reason code.
    """

    verifier_id: str
    version: str

    def verify(self, precondition: ExecutionPrecondition, payload: Any,
               context: ProposalContext) -> tuple[LogicalState, str]: ...


@dataclass(frozen=True)
class PreconditionResult:
    precondition_id: str
    logical_state: LogicalState
    processing_status: ProcessingStatus
    evidence_refs: tuple[str, ...]
    reason_code: str
    verified_at: int | None = None
    valid_until: int | None = None
    source_version: str | None = None
    verifier_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"precondition_id": self.precondition_id,
                "logical_state": self.logical_state.value,
                "processing_status": self.processing_status.value,
                "evidence_refs": list(self.evidence_refs), "reason_code": self.reason_code,
                "verified_at": self.verified_at, "valid_until": self.valid_until,
                "source_version": self.source_version,
                "verifier_version": self.verifier_version}


@dataclass(frozen=True)
class CheckedPreconditions:
    """The verifier layer's output for one context and evidence revision."""

    context_hash: str
    requirements_hash: str
    evidence_revision: int
    evidence_digest: str
    results: tuple[PreconditionResult, ...]
    complete: bool
    earliest_expiry: int | None
    rejected_evidence: tuple[tuple[str, str], ...] = ()
    _issuer: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._issuer is not _ISSUER:
            raise TypeError("CheckedPreconditions is produced by check_preconditions only")

    def state(self, precondition_id: str) -> LogicalState:
        """UNKNOWN for an ID with no result: absence is never satisfaction."""
        result = self.result(precondition_id)
        return LogicalState.UNKNOWN if result is None else result.logical_state

    def result(self, precondition_id: str) -> PreconditionResult | None:
        return next((r for r in self.results if r.precondition_id == precondition_id), None)


def _admission_fault(item: ResolverEvidence, request: VerificationRequest | None,
                     pre: ExecutionPrecondition | None, context: ProposalContext,
                     registry: PreconditionRegistry, now_s: int) -> str | None:
    if request is None:
        return "unrequested_evidence"
    if request.context_hash != context.context_hash:
        return "request_for_another_context"
    if pre is None or request.precondition_id != pre.precondition_id:
        return "request_for_unknown_precondition"
    resolver = registry.resolvers.get(item.resolver_id)
    if item.resolver_id != request.resolver_id or resolver is None \
            or item.resolver_id not in pre.resolver_ids:
        return "resolver_not_registered_for_precondition"
    if item.source_id != resolver.source_id:
        return "source_not_registered"
    if item.tenant_id != context.tenant_id:
        return "tenant_mismatch"
    if item.subject_ref != pre.subject_ref or request.subject_ref != pre.subject_ref:
        return "subject_mismatch"
    if type(item.payload) is not bytes or hashlib.sha256(item.payload).hexdigest() != item.payload_hash:
        return "integrity_mismatch"
    if not (item.acquired_at <= now_s < item.valid_until) or now_s - item.acquired_at > pre.max_age_s:
        return "stale"
    return None


def _fold(pre: ExecutionPrecondition, verdicts: list[tuple[LogicalState, str, ResolverEvidence]],
          failures: list[str], unsupported: bool, verifier: Verifier | None,
          now_s: int) -> PreconditionResult:
    pid = pre.precondition_id
    version = verifier.version if verifier is not None else None
    if unsupported:
        return PreconditionResult(pid, LogicalState.UNKNOWN, ProcessingStatus.UNSUPPORTED, (),
                                  "verifier_not_registered")
    if not verdicts:
        status = ProcessingStatus.FAILED if failures else ProcessingStatus.NO_DATA
        return PreconditionResult(pid, LogicalState.UNKNOWN, status, (),
                                  failures[0] if failures else "no_admitted_evidence",
                                  verifier_version=version)
    states = {s for s, _, _ in verdicts}
    refs = tuple(sorted(e.evidence_ref for _, _, e in verdicts))
    if LogicalState.CONFLICT in states or {LogicalState.PROVED, LogicalState.REFUTED} <= states:
        return PreconditionResult(pid, LogicalState.CONFLICT, ProcessingStatus.COMPLETED, refs,
                                  "conflicting_evidence", now_s, None, None, version)
    for wanted in (LogicalState.REFUTED, LogicalState.PROVED):
        hits = [(r, e) for s, r, e in verdicts if s is wanted]
        if hits:
            reason, item = hits[0]
            expiry = min(min(e.valid_until, e.acquired_at + pre.max_age_s) for _, e in hits)
            return PreconditionResult(pid, wanted, ProcessingStatus.COMPLETED, refs, reason,
                                      now_s, expiry, item.source_version, version)
    return PreconditionResult(pid, LogicalState.UNKNOWN, ProcessingStatus.COMPLETED, refs,
                              verdicts[0][1], now_s, None, None, version)


def check_preconditions(context: ProposalContext, requirements: RequirementSet,
                        evidence: Sequence[ResolverEvidence], *,
                        issued: Mapping[str, VerificationRequest],
                        registry: PreconditionRegistry,
                        verifiers: Mapping[str, Verifier],
                        now_s: int, evidence_revision: int) -> CheckedPreconditions:
    """Derive every precondition's state from scratch from *evidence*."""
    if requirements.context_hash != context.context_hash:
        raise ValueError("requirement set belongs to another context")
    if registry.registry_hash != requirements.registry_hash:
        raise ValueError("requirement set was compiled from another registry")
    rejected: list[tuple[str, str]] = []
    per: dict[str, list[tuple[LogicalState, str, ResolverEvidence]]] = {}
    failed: dict[str, list[str]] = {}
    unsupported: set[str] = set()
    for item in evidence:
        request = issued.get(item.request_id)
        pre = requirements.by_id(request.precondition_id) if request is not None else None
        fault = _admission_fault(item, request, pre, context, registry, now_s)
        if fault is not None:
            rejected.append((item.request_id, fault))
            continue
        if pre is None:  # _admission_fault refuses this; kept explicit for -O
            continue
        verifier = verifiers.get(pre.verifier_id)
        if verifier is None or verifier.verifier_id != pre.verifier_id:
            unsupported.add(pre.precondition_id)
            continue
        try:
            payload = decode_bounded(item.payload)
            state, reason = verifier.verify(pre, payload, context)
        except Exception as exc:  # a failed check is recorded, never a verdict
            failed.setdefault(pre.precondition_id, []).append(f"verifier_error:{type(exc).__name__}")
            continue
        if not isinstance(state, LogicalState):
            failed.setdefault(pre.precondition_id, []).append("verifier_returned_no_state")
            continue
        per.setdefault(pre.precondition_id, []).append((state, str(reason), item))
    results = tuple(
        _fold(pre, per.get(pre.precondition_id, []), failed.get(pre.precondition_id, []),
              pre.precondition_id in unsupported, verifiers.get(pre.verifier_id), now_s)
        for pre in requirements.preconditions)
    expiries = [r.valid_until for r in results
                if r.logical_state is LogicalState.PROVED and r.valid_until is not None]
    digest = tagged_digest("evidence", {
        "requirements_hash": requirements.requirements_hash,
        "evidence_revision": evidence_revision,
        "results": [r.to_dict() for r in results],
        "rejected": [list(x) for x in rejected]})
    return CheckedPreconditions(context.context_hash, requirements.requirements_hash,
                                evidence_revision, digest, results, requirements.complete,
                                min(expiries) if expiries else None, tuple(rejected),
                                _issuer=_ISSUER)

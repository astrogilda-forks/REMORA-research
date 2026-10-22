# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Versioned WS1 evidence receipts and the admission-time check (M4.1b).

A WS1 evaluation proves a call's preconditions at one instant: the re-gate.
Nothing carried that proof further, so evidence that lapsed between the
re-gate and the grant's consumption still let the call run (control 2b,
``tests/test_ws1_gate_controls.py``). A receipt is the part of the proof that
admission needs to check again, inside its own transaction
(docs/architecture/ADR-ws1-m4-admission-topology.md):

- which precondition was PROVED, under which WS1 binding and tenant,
- until when the evidence holds, and
- at which authority epoch the subject it depends on stood when it was read.

A receipt is data, not authority. It is built here, from a composition
record the deterministic gate produced, and never from a request or a tool
result. ``admission_refusal`` is a pure function: the caller supplies the
database instant, the declared clock skew and the epochs it read under lock,
so the same inputs always give the same answer.
"""
from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from remora.verification.preconditions import LogicalState, ProcessingStatus, tagged_digest
from remora.verification.records import CompositionRecord

__all__ = [
    "MAX_CLOCK_SKEW_MS",
    "EvidenceReceiptV1",
    "admission_refusal",
    "earliest_valid_until_ms",
    "receipt_set_digest",
    "receipts_from_record",
]

SCHEMA = "remora-ws1-evidence-receipt/v1"

#: The largest clock skew a deployment may declare. A larger value would let
#: evidence count as fresh long after it lapsed, which is the hole receipts
#: close; a deployment whose clocks drift further must fix its clocks. The
#: execution core keeps the same bound in remora/governance/authority_epochs.py,
#: because neither layer may import the other; a test pins them equal.
MAX_CLOCK_SKEW_MS = 5_000


@dataclass(frozen=True)
class EvidenceReceiptV1:
    """One PROVED precondition, as admission re-checks it. Times are epoch ms."""

    tenant_id: str
    binding_hash: str
    precondition_id: str
    #: An authority subject the evidence depends on, e.g. ``source:crm``. A
    #: precondition a resolver of more than one source can serve has one
    #: receipt per source, so revoking any of them refuses it.
    subject_key: str
    #: The subject's authority epoch when the evidence was read.
    source_epoch: int
    source_version: str
    evidence_refs: tuple[str, ...]
    verified_at_ms: int
    valid_until_ms: int
    verifier_profile_hash: str

    def body(self) -> dict[str, Any]:
        return {"schema": SCHEMA, "tenant_id": self.tenant_id,
                "binding_hash": self.binding_hash,
                "precondition_id": self.precondition_id,
                "subject_key": self.subject_key, "source_epoch": self.source_epoch,
                "source_version": self.source_version,
                "evidence_refs": list(self.evidence_refs),
                "verified_at_ms": self.verified_at_ms,
                "valid_until_ms": self.valid_until_ms,
                "verifier_profile_hash": self.verifier_profile_hash}

    @property
    def digest(self) -> str:
        return tagged_digest("ws1-evidence-receipt", self.body())


def receipts_from_record(
    record: CompositionRecord,
    *,
    tenant_id: str,
    binding_hash: str,
    subjects_of: Mapping[str, Sequence[str]],
    epochs: Mapping[str, int],
    exclude: Collection[str] = (),
) -> tuple[EvidenceReceiptV1, ...]:
    """One receipt per authority subject of each PROVED, completed precondition.

    ``subjects_of`` maps each precondition to the authority subjects its
    evidence depends on; ``epochs`` is each subject's epoch as read before the
    lookups ran. A PROVED result without a subject, an epoch or an expiry
    raises: a receipt that admission cannot check is not a receipt.
    ``exclude`` names preconditions whose authority is not source evidence,
    such as a REVIEW precondition an approval closes; they get no receipt.
    """
    if not tenant_id or not binding_hash:
        raise ValueError("a receipt needs a tenant and a WS1 binding hash")
    out: list[EvidenceReceiptV1] = []
    for result in record.all_precondition_results:
        if (result.get("logical_state") != LogicalState.PROVED.value
                or result.get("processing_status") != ProcessingStatus.COMPLETED.value):
            continue
        pid = str(result["precondition_id"])
        if pid in exclude:
            continue
        subjects = sorted(set(subjects_of.get(pid) or ()))
        if not subjects:
            raise ValueError(f"precondition {pid} has no authority subject")
        verified_at, valid_until = result.get("verified_at"), result.get("valid_until")
        if verified_at is None or valid_until is None:
            raise ValueError(f"precondition {pid} was PROVED without an expiry")
        for subject in subjects:
            if subject not in epochs:
                raise ValueError(f"no epoch was read for subject {subject}")
            out.append(EvidenceReceiptV1(
                tenant_id=tenant_id, binding_hash=binding_hash, precondition_id=pid,
                subject_key=subject, source_epoch=int(epochs[subject]),
                source_version=str(result.get("source_version") or ""),
                evidence_refs=tuple(str(r) for r in result.get("evidence_refs") or ()),
                verified_at_ms=int(verified_at) * 1000,
                valid_until_ms=int(valid_until) * 1000,
                verifier_profile_hash=record.profile_hash))
    return tuple(sorted(out, key=lambda r: (r.precondition_id, r.subject_key)))


def receipt_set_digest(receipts: Sequence[EvidenceReceiptV1]) -> str:
    """Order-independent digest of a receipt set, for binding into admission."""
    return tagged_digest("ws1-evidence-receipt-set",
                         sorted(r.digest for r in receipts))


def earliest_valid_until_ms(receipts: Sequence[EvidenceReceiptV1]) -> int | None:
    return min((r.valid_until_ms for r in receipts), default=None)


def admission_refusal(
    receipts: Sequence[EvidenceReceiptV1],
    *,
    tenant_id: str,
    binding_hash: str,
    expected_set_digest: str,
    required_preconditions: Collection[str],
    now_ms: int,
    max_clock_skew_ms: int,
    epochs: Mapping[str, tuple[int, bool]],
) -> str | None:
    """The reason admission must refuse, or None when every receipt holds.

    ``now_ms`` is the database instant read inside the admission transaction.
    ``epochs`` maps each subject to ``(epoch, revoked)`` as read there under
    lock. Evidence counts as expired once ``valid_until_ms - max_clock_skew_ms``
    is at or before ``now_ms``: equality is expired (M4-T10).
    """
    if (isinstance(max_clock_skew_ms, bool) or not isinstance(max_clock_skew_ms, int)
            or not 0 <= max_clock_skew_ms <= MAX_CLOCK_SKEW_MS):
        raise ValueError(
            f"max_clock_skew_ms must be an int from 0 to {MAX_CLOCK_SKEW_MS}")
    if receipt_set_digest(receipts) != expected_set_digest:
        return "evidence_receipt_modified"
    seen: set[tuple[str, str]] = set()
    for receipt in receipts:
        if receipt.tenant_id != tenant_id or receipt.binding_hash != binding_hash:
            return "evidence_receipt_foreign"
        key = (receipt.precondition_id, receipt.subject_key)
        if key in seen:
            return "evidence_receipt_duplicate"
        seen.add(key)
    if any(pid not in {p for p, _ in seen} for pid in required_preconditions):
        return "evidence_receipt_missing"
    for receipt in receipts:
        if receipt.valid_until_ms - max_clock_skew_ms <= now_ms:
            return "evidence_expired_at_admission"
        current = epochs.get(receipt.subject_key)
        if current is None:
            return "authority_epoch_unread"
        epoch, revoked = current
        if revoked:
            return "authority_revoked"
        if epoch != receipt.source_epoch:
            return "authority_epoch_stale"
    return None

# SPDX-License-Identifier: BUSL-1.1
"""Pure assessment of an inventory snapshot against an obligation manifest.

``assess`` reads no clock, no environment and no store. Everything it judges
is in its arguments, so the same manifest, snapshot, trust configuration and
``assessed_as_of`` always give a byte-identical result (REAS H2). A record
that arrives later is a new snapshot and a new assessment; the earlier one is
never touched.

Deadlines are judged against the snapshot's ``closed_at``, the point up to
which the inventory reader vouches it saw every row. Before an obligation
falls due it is PENDING; after it falls due with nothing recorded it is
MISSING. Absence only counts once the inventory has closed past the due time.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import replace
from datetime import datetime

from remora.evidence.obligations.models import (
    ClaimVerdict,
    Coverage,
    Delivery,
    InventoryRecord,
    InventorySnapshot,
    Obligation,
    ObligationAssessment,
    ObligationKind,
    ObligationManifest,
    Observation,
    SlotResult,
    SlotState,
    manifest_digest,
    records_digest,
    tagged_digest,
)

#: Outbox lifecycle names. Pinned against ``OutboxState`` by test, because
#: this package may not import it.
SETTLED_STATES = frozenset({"SUCCEEDED", "FAILED", "REFUSED"})
UNKNOWN_STATE = "UNKNOWN"
OPEN_STATES = frozenset({"DISPATCH_PENDING", "DISPATCHING"})
KNOWN_STATES = SETTLED_STATES | OPEN_STATES | {UNKNOWN_STATE}

_SATISFYING = frozenset({SlotState.SATISFIED, SlotState.NOT_APPLICABLE})


def _slot(ob: Obligation, rec: InventoryRecord, state: SlotState,
          delivery: Delivery, observation: Observation,
          reason: str) -> SlotResult:
    return SlotResult(
        slot_id=ob.slot_id, subject_key=rec.subject_key,
        record_id=rec.record_id, state=state, delivery=delivery,
        observation=observation, reason=reason,
    )


def _record_inconsistency(rec: InventoryRecord, horizon: datetime) -> str | None:
    """Why a record cannot be a truthful row of a snapshot closed at horizon."""
    if rec.state not in KNOWN_STATES:
        return "unknown_lifecycle_state"
    stamps = (rec.created_at, rec.settled_at, rec.projected_at)
    if any(s is not None and s > horizon for s in stamps):
        return "timestamp_after_snapshot_close"
    terminal = rec.state not in OPEN_STATES
    if terminal and rec.settled_at is None:
        return "terminal_without_settled_at"
    if not terminal and (rec.settled_at is not None
                         or rec.projected_at is not None):
        return "open_row_with_settlement_fields"
    if rec.settled_at is not None and rec.settled_at < rec.created_at:
        return "settled_before_created"
    if (rec.projected_at is not None and rec.settled_at is not None
            and rec.projected_at < rec.settled_at):
        return "projected_before_settled"
    return None


def _settled_at(rec: InventoryRecord) -> datetime:
    """A terminal record's settlement time; consistency checks ran first."""
    if rec.settled_at is None:
        raise ValueError("terminal record without settled_at reached evaluation")
    return rec.settled_at


def _settlement(ob: Obligation, rec: InventoryRecord,
                horizon: datetime) -> SlotResult:
    due = rec.created_at + ob.due_within
    if rec.state in SETTLED_STATES:
        if _settled_at(rec) <= due:
            return _slot(ob, rec, SlotState.SATISFIED, Delivery.ON_TIME,
                         Observation.SUPPORTED, f"settled_{rec.state.lower()}")
        return _slot(ob, rec, SlotState.MISSING, Delivery.LATE,
                     Observation.SUPPORTED, "settled_after_due")
    if rec.state == UNKNOWN_STATE:
        # A reconciler's UNKNOWN says the outcome could not be determined.
        # Settling it needs read-back evidence this slice does not have.
        on_time = _settled_at(rec) <= due
        delivery = Delivery.ON_TIME if on_time else Delivery.LATE
        return _slot(ob, rec, SlotState.PENDING, delivery,
                     Observation.UNOBSERVABLE, "reconciled_unknown_needs_readback")
    if due <= horizon:
        return _slot(ob, rec, SlotState.MISSING, Delivery.NONE,
                     Observation.NOT_EVALUATED, "not_settled_by_due")
    return _slot(ob, rec, SlotState.PENDING, Delivery.NONE,
                 Observation.NOT_EVALUATED, "not_yet_due")


def _projection(ob: Obligation, rec: InventoryRecord,
                horizon: datetime) -> SlotResult:
    if rec.state in OPEN_STATES:
        return _slot(ob, rec, SlotState.NOT_APPLICABLE, Delivery.NONE,
                     Observation.NOT_EVALUATED, "trigger_not_fired")
    due = _settled_at(rec) + ob.due_within
    if rec.projected_at is not None:
        if rec.projected_at <= due:
            return _slot(ob, rec, SlotState.SATISFIED, Delivery.ON_TIME,
                         Observation.SUPPORTED, "projected")
        return _slot(ob, rec, SlotState.MISSING, Delivery.LATE,
                     Observation.SUPPORTED, "projected_after_due")
    if due <= horizon:
        return _slot(ob, rec, SlotState.MISSING, Delivery.NONE,
                     Observation.NOT_EVALUATED, "not_projected_by_due")
    return _slot(ob, rec, SlotState.PENDING, Delivery.NONE,
                 Observation.NOT_EVALUATED, "not_yet_due")


_EVALUATORS = {
    ObligationKind.TERMINAL_SETTLEMENT: _settlement,
    ObligationKind.DOWNSTREAM_PROJECTION: _projection,
}


def _flag_all(manifest: ObligationManifest, rec: InventoryRecord,
              state: SlotState, reason: str) -> list[SlotResult]:
    return [
        _slot(ob, rec, state, Delivery.NONE, Observation.NOT_EVALUATED, reason)
        for ob in manifest.obligations
    ]


def _evaluate_records(manifest: ObligationManifest,
                      records: Iterable[InventoryRecord],
                      horizon: datetime) -> tuple[list[SlotResult], int]:
    in_window = [r for r in records
                 if manifest.window_start <= r.created_at < manifest.window_end]
    out_of_window = 0
    for r in records:
        if not manifest.window_start <= r.created_at < manifest.window_end:
            out_of_window += 1
    ids = Counter(r.record_id for r in in_window)
    subjects = Counter(r.subject_key for r in in_window)
    slots: list[SlotResult] = []
    for rec in in_window:
        # An upper bound of one: a second row for the same id or subject must
        # never make the obligation look met (REAS SDD §4.2).
        if ids[rec.record_id] > 1:
            slots.extend(_flag_all(manifest, rec, SlotState.CONFLICTED,
                                   "duplicate_record_id"))
            continue
        if subjects[rec.subject_key] > 1:
            slots.extend(_flag_all(manifest, rec, SlotState.CONFLICTED,
                                   "duplicate_subject_key"))
            continue
        bad = _record_inconsistency(rec, horizon)
        if bad is not None:
            slots.extend(_flag_all(manifest, rec, SlotState.INVALID, bad))
            continue
        for ob in manifest.obligations:
            slots.append(_EVALUATORS[ob.kind](ob, rec, horizon))
    return slots, out_of_window


def _snapshot_reasons(manifest: ObligationManifest,
                      snapshot: InventorySnapshot,
                      accepted_inventories: frozenset[tuple[str, str]],
                      assessed_as_of: datetime) -> list[str]:
    reasons: list[str] = []
    declared = (manifest.inventory.kind, manifest.inventory.writer)
    if (snapshot.kind, snapshot.writer) != declared:
        reasons.append("inventory_not_declared_by_manifest")
    if (snapshot.kind, snapshot.writer) not in accepted_inventories:
        reasons.append("inventory_source_not_accepted")
    if snapshot.tenant_id != manifest.tenant_id:
        reasons.append("snapshot_tenant_mismatch")
    if snapshot.closed_at < manifest.closure_due:
        reasons.append("inventory_not_closed_past_due")
    if assessed_as_of < snapshot.closed_at:
        reasons.append("snapshot_closed_after_assessment_time")
    return reasons


def assess(
    manifest: ObligationManifest,
    snapshot: InventorySnapshot | None,
    *,
    accepted_inventories: frozenset[tuple[str, str]],
    assessed_as_of: datetime,
) -> ObligationAssessment:
    """Assess one snapshot against one manifest.

    ``accepted_inventories`` is deployment-owned trust configuration: the
    (kind, writer) pairs this deployment accepts as an authoritative
    inventory. It is never read from the manifest or the snapshot.
    """
    reasons: list[str] = []
    if manifest.created_at > manifest.window_start:
        # Expectations must be locked before the window they govern, or they
        # could be fitted to whatever evidence happened to arrive.
        reasons.append("manifest_not_locked_before_window")
    slots: list[SlotResult] = []
    out_of_window = 0
    snap_digest: str | None = None
    if snapshot is None:
        reasons.append("no_inventory_snapshot")
    else:
        snap_digest = tagged_digest("snapshot", snapshot.to_dict())
        reasons.extend(_snapshot_reasons(
            manifest, snapshot, accepted_inventories, assessed_as_of))
        if records_digest(snapshot.records) != snapshot.records_digest:
            # The selection itself is not the one the reader vouched for, so
            # nothing in it is evaluated.
            reasons.append("snapshot_records_digest_mismatch")
        else:
            own = [r for r in snapshot.records
                   if r.tenant_id == manifest.tenant_id]
            if len(own) != len(snapshot.records):
                reasons.append("cross_tenant_record_in_snapshot")
            slots, out_of_window = _evaluate_records(
                manifest, own, snapshot.closed_at)
    if any(s.state in (SlotState.INVALID, SlotState.CONFLICTED) for s in slots):
        reasons.append("inconsistent_inventory_records")
    coverage = (Coverage.NOT_ESTABLISHED if reasons
                else Coverage.ESTABLISHED_WITHIN_DECLARED_SCOPE)
    verdict = ClaimVerdict.NOT_ESTABLISHED
    if (coverage is Coverage.ESTABLISHED_WITHIN_DECLARED_SCOPE
            and all(s.state in _SATISFYING for s in slots)):
        verdict = ClaimVerdict.ESTABLISHED
    slots.sort(key=lambda s: (s.subject_key, s.slot_id, s.record_id, s.reason))
    draft = ObligationAssessment(
        assessment_id="",
        manifest_id=manifest.manifest_id,
        manifest_version=manifest.manifest_version,
        manifest_digest=manifest_digest(manifest),
        snapshot_digest=snap_digest,
        tenant_id=manifest.tenant_id,
        scope_id=manifest.scope_id,
        assessed_as_of=assessed_as_of,
        coverage=coverage,
        coverage_reasons=tuple(sorted(set(reasons))),
        claim_verdict=verdict,
        slots=tuple(slots),
        out_of_window_records=out_of_window,
    )
    return replace(draft,
                   assessment_id=tagged_digest("assessment", draft.payload()))

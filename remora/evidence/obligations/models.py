# SPDX-License-Identifier: BUSL-1.1
"""Scoped evidence obligations (REAS G1): typed manifest, inventory and result.

An obligation manifest says, before a window opens, which evidence every
in-scope action must leave behind and by when. An inventory snapshot is the
deployment's bounded, closed listing of the actions that actually happened.
An assessment compares the two and reports, per action and per obligation,
whether the evidence is there, still due, or missing.

None of these types carry authority. An assessment says what a bounded
inventory shows; it cannot authorize, upgrade a decision, mint a lease or
cause execution. The package imports nothing from enforcement, execution or
policy, and a test enforces that.

P1 scope is deliberately narrow: one inventory kind (REMORA's own execution
outbox), two obligation kinds, exactly one record per subject. Anything else
is refused at parse time rather than interpreted.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from remora.evidence.admission.canonical import (
    canonical_bytes,
    decode_bounded,
    require_identifier,
)

MANIFEST_SCHEMA = "remora-seo-manifest/v1"
#: The only canonicalisation this slice speaks. It is the evidence-admission
#: encoding (sorted keys, no floats), not RFC 8785; the id says so explicitly.
CANONICALIZATION_ID = "remora-bounded-sorted-json/v1"
#: The only inventory kind P1 can assess.
OUTBOX_INVENTORY_KIND = "remora.execution_outbox/v1"


class ObligationKind(StrEnum):
    """What evidence an in-scope action must leave behind."""

    #: The dispatch intent reached SUCCEEDED, FAILED or REFUSED. UNKNOWN is
    #: a reconciliation, not a settlement: it stays PENDING and UNOBSERVABLE.
    TERMINAL_SETTLEMENT = "terminal_settlement"
    #: A settled intent's downstream projection (queue outcome and chain
    #: record) was confirmed written.
    DOWNSTREAM_PROJECTION = "downstream_projection"


#: Fixed trigger per kind. P1 accepts no other trigger and evaluates no
#: expressions: the manifest names the trigger so it is bound into the
#: digest, and a mismatch is a parse error.
TRIGGERS = {
    ObligationKind.TERMINAL_SETTLEMENT: "intent_recorded",
    ObligationKind.DOWNSTREAM_PROJECTION: "terminal_settled",
}


class SlotState(StrEnum):
    SATISFIED = "satisfied"
    PENDING = "pending"
    MISSING = "missing"
    INVALID = "invalid"
    CONFLICTED = "conflicted"
    NOT_APPLICABLE = "not_applicable"


class Delivery(StrEnum):
    """Separates late delivery from evidence that never arrived."""

    ON_TIME = "on_time"
    LATE = "late"
    NONE = "none"


class Observation(StrEnum):
    SUPPORTED = "supported"
    UNOBSERVABLE = "unobservable"
    NOT_EVALUATED = "not_evaluated"


class Coverage(StrEnum):
    ESTABLISHED_WITHIN_DECLARED_SCOPE = "established_within_declared_scope"
    NOT_ESTABLISHED = "not_established"


class ClaimVerdict(StrEnum):
    ESTABLISHED = "established"
    NOT_ESTABLISHED = "not_established"


#: Fixed claim ceiling (REAS SDD §9.1). Every assessment carries it, whatever
#: its verdict, so no reader can mistake a bounded result for a global one.
DOES_NOT_ESTABLISH = (
    "visibility_over_tools_or_credentials_outside_the_outbox",
    "absence_of_unobserved_events",
    "production_pep_mediation",
    "legitimate_business_purpose",
    "independence_from_the_producer",
    "execution_authority",
    "effect_occurred_as_reported",
)


def parse_timestamp(value: Any, field: str) -> datetime:
    """An ISO-8601 timestamp with an explicit UTC offset, or a refusal."""
    if type(value) is not str:
        raise ValueError(f"{field}: ISO-8601 string required")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field}: not ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field}: explicit UTC offset required")
    return parsed


def _require_keys(obj: Any, required: frozenset[str], where: str) -> dict[str, Any]:
    if type(obj) is not dict:
        raise ValueError(f"{where}: object required")
    unknown = set(obj) - required
    if unknown:
        raise ValueError(f"{where}: unknown fields {sorted(unknown)}")
    missing = required - set(obj)
    if missing:
        raise ValueError(f"{where}: missing fields {sorted(missing)}")
    return obj


def _positive_int(value: Any, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{field}: positive integer required")
    return value


@dataclass(frozen=True)
class Obligation:
    slot_id: str
    kind: ObligationKind
    trigger: str
    due_within_seconds: int
    minimum_count: int = 1
    maximum_count: int = 1

    @property
    def due_within(self) -> timedelta:
        return timedelta(seconds=self.due_within_seconds)

    def to_dict(self) -> dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            "kind": self.kind.value,
            "trigger": self.trigger,
            "due_within_seconds": self.due_within_seconds,
            "minimum_count": self.minimum_count,
            "maximum_count": self.maximum_count,
        }


@dataclass(frozen=True)
class InventoryDeclaration:
    """Which inventory the manifest relies on, and who answers for it.

    A declaration is not trust: the assessor accepts the source only if the
    deployment's own configuration lists the same (kind, writer) pair.
    """

    kind: str
    writer: str
    scope_owner: str

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "writer": self.writer,
                "scope_owner": self.scope_owner}


@dataclass(frozen=True)
class ObligationManifest:
    manifest_id: str
    manifest_version: int
    tenant_id: str
    scope_id: str
    window_start: datetime
    window_end: datetime
    policy_revision: str
    created_at: datetime
    obligations: tuple[Obligation, ...]
    inventory: InventoryDeclaration
    canonicalization_id: str = CANONICALIZATION_ID
    schema_version: str = MANIFEST_SCHEMA

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "manifest_id": self.manifest_id,
            "manifest_version": self.manifest_version,
            "tenant_id": self.tenant_id,
            "scope": {
                "scope_id": self.scope_id,
                "scope_kind": "dispatch_window",
                "window_start": self.window_start.isoformat(),
                "window_end": self.window_end.isoformat(),
            },
            "policy_revision": self.policy_revision,
            "created_at": self.created_at.isoformat(),
            "obligations": [o.to_dict() for o in self.obligations],
            "inventory": self.inventory.to_dict(),
            "canonicalization_id": self.canonicalization_id,
        }

    @property
    def closure_due(self) -> datetime:
        """When every obligation for every in-window action has fallen due.

        A projection falls due after settlement, so the two deadlines add up.
        """
        return self.window_end + sum(
            (o.due_within for o in self.obligations), timedelta())


_MANIFEST_KEYS = frozenset({
    "schema_version", "manifest_id", "manifest_version", "tenant_id", "scope",
    "policy_revision", "created_at", "obligations", "inventory",
    "canonicalization_id",
})
_SCOPE_KEYS = frozenset({"scope_id", "scope_kind", "window_start", "window_end"})
_OBLIGATION_KEYS = frozenset({
    "slot_id", "kind", "trigger", "due_within_seconds", "minimum_count",
    "maximum_count",
})
_INVENTORY_KEYS = frozenset({"kind", "writer", "scope_owner"})


def parse_manifest(raw: bytes) -> ObligationManifest:
    """Strictly parse a manifest from bytes.

    Unknown fields and values P1 does not support are refused, never ignored:
    a field this slice does not understand could change what the manifest
    means.
    """
    data = _require_keys(decode_bounded(raw), _MANIFEST_KEYS, "manifest")
    if data["schema_version"] != MANIFEST_SCHEMA:
        raise ValueError("manifest: unsupported schema_version")
    if data["canonicalization_id"] != CANONICALIZATION_ID:
        raise ValueError("manifest: unsupported canonicalization_id")
    scope = _require_keys(data["scope"], _SCOPE_KEYS, "scope")
    if scope["scope_kind"] != "dispatch_window":
        raise ValueError("scope: only scope_kind dispatch_window is supported")
    start = parse_timestamp(scope["window_start"], "window_start")
    end = parse_timestamp(scope["window_end"], "window_end")
    if end <= start:
        raise ValueError("scope: window_end must be after window_start")
    inv = _require_keys(data["inventory"], _INVENTORY_KEYS, "inventory")
    if inv["kind"] != OUTBOX_INVENTORY_KIND:
        raise ValueError("inventory: unsupported kind")
    raw_obligations = data["obligations"]
    if type(raw_obligations) is not list or not raw_obligations:
        raise ValueError("obligations: non-empty list required")
    obligations: list[Obligation] = []
    for item in raw_obligations:
        ob = _require_keys(item, _OBLIGATION_KEYS, "obligation")
        try:
            kind = ObligationKind(ob["kind"])
        except ValueError as exc:
            raise ValueError("obligation: unsupported kind") from exc
        if ob["trigger"] != TRIGGERS[kind]:
            raise ValueError(
                f"obligation: {kind.value} requires trigger {TRIGGERS[kind]}")
        if ob["minimum_count"] != 1 or ob["maximum_count"] != 1:
            raise ValueError(
                "obligation: P1 supports exactly one record per subject "
                "(minimum_count = maximum_count = 1)")
        obligations.append(Obligation(
            slot_id=require_identifier(ob["slot_id"], "slot_id"),
            kind=kind,
            trigger=ob["trigger"],
            due_within_seconds=_positive_int(
                ob["due_within_seconds"], "due_within_seconds"),
        ))
    if len({o.slot_id for o in obligations}) != len(obligations):
        raise ValueError("obligations: slot_id must be unique")
    if len({o.kind for o in obligations}) != len(obligations):
        raise ValueError("obligations: each kind may appear once")
    return ObligationManifest(
        manifest_id=require_identifier(data["manifest_id"], "manifest_id"),
        manifest_version=_positive_int(data["manifest_version"],
                                       "manifest_version"),
        tenant_id=require_identifier(data["tenant_id"], "tenant_id"),
        scope_id=require_identifier(scope["scope_id"], "scope_id"),
        window_start=start,
        window_end=end,
        policy_revision=require_identifier(data["policy_revision"],
                                           "policy_revision"),
        created_at=parse_timestamp(data["created_at"], "created_at"),
        obligations=tuple(obligations),
        inventory=InventoryDeclaration(
            kind=inv["kind"],
            writer=require_identifier(inv["writer"], "writer"),
            scope_owner=require_identifier(inv["scope_owner"], "scope_owner"),
        ),
    )


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


@dataclass(frozen=True)
class InventoryRecord:
    """One dispatch intent as the inventory saw it at snapshot time.

    ``state`` is the outbox lifecycle name. This package does not import the
    outbox's enum (it lives under enforcement); the names are pinned against
    it by test instead.
    """

    record_id: str
    tenant_id: str
    subject_key: str
    state: str
    created_at: datetime
    settled_at: datetime | None = None
    projected_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "tenant_id": self.tenant_id,
            "subject_key": self.subject_key,
            "state": self.state,
            "created_at": self.created_at.isoformat(),
            "settled_at": _iso(self.settled_at),
            "projected_at": _iso(self.projected_at),
        }


@dataclass(frozen=True)
class InventorySnapshot:
    """A closed, bounded listing produced by the deployment's inventory reader.

    ``closed_at`` is the point up to which the reader guarantees it saw every
    row for ``tenant_id``. ``records_digest`` binds the exact selection; the
    assessor recomputes it and refuses a snapshot whose records do not match.
    """

    kind: str
    writer: str
    tenant_id: str
    closed_at: datetime
    records: tuple[InventoryRecord, ...]
    records_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "writer": self.writer,
            "tenant_id": self.tenant_id,
            "closed_at": self.closed_at.isoformat(),
            "records_digest": self.records_digest,
        }


def tagged_digest(object_type: str, value: Any) -> str:
    """SHA-256 over ``remora-seo-v1:<type>``, a NUL byte, then canonical bytes.

    The domain tag keeps a manifest digest from ever colliding with an
    assessment digest over the same JSON.
    """
    tag = f"remora-seo-v1:{object_type}".encode() + b"\x00"
    return hashlib.sha256(tag + canonical_bytes(value)).hexdigest()


def records_digest(records: tuple[InventoryRecord, ...]) -> str:
    return tagged_digest("inventory-records", [r.to_dict() for r in records])


def manifest_digest(manifest: ObligationManifest) -> str:
    return tagged_digest("manifest", manifest.to_dict())


@dataclass(frozen=True)
class SlotResult:
    slot_id: str
    subject_key: str
    record_id: str
    state: SlotState
    delivery: Delivery
    observation: Observation
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            "subject_key": self.subject_key,
            "record_id": self.record_id,
            "state": self.state.value,
            "delivery": self.delivery.value,
            "observation": self.observation.value,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ObligationAssessment:
    """Immutable, deterministic result.

    A re-assessment is a new object with a new id; nothing here is ever
    rewritten.
    """

    assessment_id: str
    manifest_id: str
    manifest_version: int
    manifest_digest: str
    snapshot_digest: str | None
    tenant_id: str
    scope_id: str
    assessed_as_of: datetime
    coverage: Coverage
    coverage_reasons: tuple[str, ...]
    claim_verdict: ClaimVerdict
    slots: tuple[SlotResult, ...]
    out_of_window_records: int
    does_not_establish: tuple[str, ...] = DOES_NOT_ESTABLISH

    def counts(self) -> dict[str, int]:
        out = {state.value: 0 for state in SlotState}
        for slot in self.slots:
            out[slot.state.value] += 1
        return out

    def payload(self) -> dict[str, Any]:
        """Everything except the id; the id is the tagged digest of this."""
        return {
            "manifest_id": self.manifest_id,
            "manifest_version": self.manifest_version,
            "manifest_digest": self.manifest_digest,
            "snapshot_digest": self.snapshot_digest,
            "tenant_id": self.tenant_id,
            "scope_id": self.scope_id,
            "assessed_as_of": self.assessed_as_of.isoformat(),
            "coverage": self.coverage.value,
            "coverage_reasons": list(self.coverage_reasons),
            "claim_verdict": self.claim_verdict.value,
            "slots": [s.to_dict() for s in self.slots],
            "counts": self.counts(),
            "out_of_window_records": self.out_of_window_records,
            "does_not_establish": list(self.does_not_establish),
            "canonicalization_id": CANONICALIZATION_ID,
        }

    def to_dict(self) -> dict[str, Any]:
        return {"assessment_id": self.assessment_id, **self.payload()}

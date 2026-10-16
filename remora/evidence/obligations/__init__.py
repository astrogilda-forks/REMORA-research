# SPDX-License-Identifier: BUSL-1.1
"""Scoped evidence obligations (REAS G1): public surface.

Read-only assurance over REMORA's own execution outbox: did every dispatch
intent in a closed window settle, and was its downstream projection written,
by the deadlines a manifest fixed before the window opened. No authority.
"""
from remora.evidence.obligations.assess import KNOWN_STATES, assess
from remora.evidence.obligations.inventory import (
    record_from_outbox_row,
    snapshot_from_outbox_rows,
)
from remora.evidence.obligations.models import (
    CANONICALIZATION_ID,
    DOES_NOT_ESTABLISH,
    MANIFEST_SCHEMA,
    OUTBOX_INVENTORY_KIND,
    ClaimVerdict,
    Coverage,
    Delivery,
    InventoryRecord,
    InventorySnapshot,
    ObligationAssessment,
    ObligationKind,
    ObligationManifest,
    Observation,
    SlotResult,
    SlotState,
    manifest_digest,
    parse_manifest,
)

__all__ = [
    "CANONICALIZATION_ID",
    "DOES_NOT_ESTABLISH",
    "KNOWN_STATES",
    "MANIFEST_SCHEMA",
    "OUTBOX_INVENTORY_KIND",
    "ClaimVerdict",
    "Coverage",
    "Delivery",
    "InventoryRecord",
    "InventorySnapshot",
    "ObligationAssessment",
    "ObligationKind",
    "ObligationManifest",
    "Observation",
    "SlotResult",
    "SlotState",
    "assess",
    "manifest_digest",
    "parse_manifest",
    "record_from_outbox_row",
    "snapshot_from_outbox_rows",
]

# SPDX-License-Identifier: BUSL-1.1
"""Turn execution-outbox rows into an obligation inventory snapshot.

The outbox lives under ``remora.enforcement``, which this package must not
import. The adapter therefore reads rows by attribute: anything with the
outbox row's field names works, and the field names are pinned against the
real ``OutboxRow`` by test.

Building a snapshot is not the same as vouching for it. ``closed_at`` is a
promise by whoever calls this that every row for the tenant up to that point
is in ``rows``; the assessor only relies on it when the deployment has
accepted that (kind, writer) pair as an inventory source.
"""
from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any

from remora.evidence.obligations.models import (
    OUTBOX_INVENTORY_KIND,
    InventoryRecord,
    InventorySnapshot,
    records_digest,
)


def record_from_outbox_row(row: Any) -> InventoryRecord:
    """One outbox row as an inventory record.

    The subject is the row's idempotency key: one key is one authorized
    dispatch attempt, so a second row with the same key is a conflict.
    """
    state = row.state
    return InventoryRecord(
        record_id=row.outbox_id,
        tenant_id=row.tenant_id,
        subject_key=row.idempotency_key,
        state=getattr(state, "value", state),
        created_at=row.created_at,
        settled_at=row.settled_at,
        projected_at=row.projected_at,
    )


def snapshot_from_outbox_rows(
    rows: Iterable[Any],
    *,
    tenant_id: str,
    writer: str,
    closed_at: datetime,
) -> InventorySnapshot:
    """A digest-bound snapshot over ``rows``, ordered by record id."""
    records = tuple(sorted((record_from_outbox_row(r) for r in rows),
                           key=lambda r: (r.record_id, r.created_at)))
    return InventorySnapshot(
        kind=OUTBOX_INVENTORY_KIND,
        writer=writer,
        tenant_id=tenant_id,
        closed_at=closed_at,
        records=records,
        records_digest=records_digest(records),
    )

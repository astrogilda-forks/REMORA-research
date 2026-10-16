# SPDX-License-Identifier: BUSL-1.1
"""REAS G1: scoped evidence obligations over REMORA's own execution outbox.

Every expected value here is written by hand from the REAS SDD decision
matrix (§9), never computed by the assessor under test. Timestamps are fixed;
nothing reads the clock.

Declared scope: the pure assessor, the manifest parser and the outbox
adapter. The outbox drives real state transitions in the integration tests
(in-process and SQLite adapters); no deployment inventory reader exists yet,
so ``closed_at`` is supplied by the test as a deployment would supply it.
"""
from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from remora.enforcement.outbox import (
    ExecutionOutbox,
    OutboxRow,
    OutboxState,
    SQLiteExecutionOutbox,
)
from remora.evidence.obligations import (
    DOES_NOT_ESTABLISH,
    KNOWN_STATES,
    OUTBOX_INVENTORY_KIND,
    ClaimVerdict,
    Coverage,
    Delivery,
    InventoryRecord,
    InventorySnapshot,
    Observation,
    SlotState,
    assess,
    parse_manifest,
    snapshot_from_outbox_rows,
)
from remora.evidence.obligations.models import records_digest

T0 = datetime(2026, 10, 16, 12, 0, tzinfo=UTC)
WINDOW_END = T0 + timedelta(hours=1)
SETTLE = 300
PROJECT = 120
CLOSURE = WINDOW_END + timedelta(seconds=SETTLE + PROJECT)
WRITER = "deploy:outbox-reader"
ACCEPTED = frozenset({(OUTBOX_INVENTORY_KIND, WRITER)})
TENANT = "acme"


def _manifest_dict(**over):
    data = {
        "schema_version": "remora-seo-manifest/v1",
        "manifest_id": "m-1",
        "manifest_version": 1,
        "tenant_id": TENANT,
        "scope": {
            "scope_id": "dispatch-2026-10-16T12",
            "scope_kind": "dispatch_window",
            "window_start": T0.isoformat(),
            "window_end": WINDOW_END.isoformat(),
        },
        "policy_revision": "policy-r1",
        "created_at": (T0 - timedelta(minutes=5)).isoformat(),
        "obligations": [
            {"slot_id": "settled", "kind": "terminal_settlement",
             "trigger": "intent_recorded", "due_within_seconds": SETTLE,
             "minimum_count": 1, "maximum_count": 1},
            {"slot_id": "projected", "kind": "downstream_projection",
             "trigger": "terminal_settled", "due_within_seconds": PROJECT,
             "minimum_count": 1, "maximum_count": 1},
        ],
        "inventory": {"kind": OUTBOX_INVENTORY_KIND, "writer": WRITER,
                      "scope_owner": "ops:acme"},
        "canonicalization_id": "remora-bounded-sorted-json/v1",
    }
    data.update(over)
    return data


def _manifest(**over):
    return parse_manifest(json.dumps(_manifest_dict(**over)).encode())


def _rec(rid, state, *, created=T0 + timedelta(minutes=1), settled=None,
         projected=None, tenant=TENANT, subject=None):
    return InventoryRecord(
        record_id=rid, tenant_id=tenant, subject_key=subject or f"k-{rid}",
        state=state, created_at=created, settled_at=settled,
        projected_at=projected,
    )


def _snap(records, *, closed_at=CLOSURE, tenant=TENANT, writer=WRITER,
          digest=None):
    records = tuple(records)
    return InventorySnapshot(
        kind=OUTBOX_INVENTORY_KIND, writer=writer, tenant_id=tenant,
        closed_at=closed_at, records=records,
        records_digest=digest or records_digest(records),
    )


def _assess(snapshot, manifest=None, *, as_of=CLOSURE, accepted=ACCEPTED):
    return assess(manifest or _manifest(), snapshot,
                  accepted_inventories=accepted, assessed_as_of=as_of)


def _slots(result):
    return {(s.record_id, s.slot_id): (s.state, s.delivery, s.reason)
            for s in result.slots}


CREATED = T0 + timedelta(minutes=1)
ON_TIME = CREATED + timedelta(seconds=60)


# -- Happy path -------------------------------------------------------------

def test_all_settled_and_projected_on_time_is_established_within_scope():
    result = _assess(_snap([
        _rec("r1", "SUCCEEDED", settled=ON_TIME,
             projected=ON_TIME + timedelta(seconds=10)),
        _rec("r2", "REFUSED", settled=ON_TIME,
             projected=ON_TIME + timedelta(seconds=10)),
        _rec("r3", "FAILED", settled=ON_TIME,
             projected=ON_TIME + timedelta(seconds=10)),
    ]))
    assert result.coverage is Coverage.ESTABLISHED_WITHIN_DECLARED_SCOPE
    assert result.coverage_reasons == ()
    assert result.claim_verdict is ClaimVerdict.ESTABLISHED
    assert result.counts()["satisfied"] == 6
    # The ceiling travels with every result, including a positive one.
    assert result.does_not_establish == DOES_NOT_ESTABLISH
    assert "execution_authority" in result.does_not_establish


def test_refused_dispatch_needs_no_effect_evidence():
    """SEO-INV-006: a refusal settles the intent; P1 has no effect slot."""
    result = _assess(_snap([_rec("r1", "REFUSED", settled=ON_TIME,
                                 projected=ON_TIME)]))
    assert _slots(result)[("r1", "settled")] == (
        SlotState.SATISFIED, Delivery.ON_TIME, "settled_refused")


# -- MISSING vs PENDING ----------------------------------------------------

def test_crash_left_dispatching_row_is_missing_once_closed_past_due():
    result = _assess(_snap([_rec("r1", "DISPATCHING")]))
    assert _slots(result)[("r1", "settled")] == (
        SlotState.MISSING, Delivery.NONE, "not_settled_by_due")
    assert _slots(result)[("r1", "projected")][0] is SlotState.NOT_APPLICABLE
    # The inventory is trusted and closed, so coverage holds; the claim that
    # every intent settled does not.
    assert result.coverage is Coverage.ESTABLISHED_WITHIN_DECLARED_SCOPE
    assert result.claim_verdict is ClaimVerdict.NOT_ESTABLISHED


def test_same_row_before_its_due_time_is_pending_not_missing():
    early = CREATED + timedelta(seconds=SETTLE - 1)
    result = _assess(_snap([_rec("r1", "DISPATCHING")], closed_at=early),
                     as_of=early)
    assert _slots(result)[("r1", "settled")] == (
        SlotState.PENDING, Delivery.NONE, "not_yet_due")
    assert "inventory_not_closed_past_due" in result.coverage_reasons
    assert result.coverage is Coverage.NOT_ESTABLISHED


def test_due_exactly_at_horizon_counts_as_missing():
    at_due = CREATED + timedelta(seconds=SETTLE)
    result = _assess(_snap([_rec("r1", "DISPATCH_PENDING")], closed_at=at_due),
                     as_of=at_due)
    assert _slots(result)[("r1", "settled")][0] is SlotState.MISSING


def test_late_settlement_is_distinguished_from_never_settled():
    late = CREATED + timedelta(seconds=SETTLE + 1)
    result = _assess(_snap([_rec("r1", "SUCCEEDED", settled=late,
                                 projected=late)]))
    assert _slots(result)[("r1", "settled")] == (
        SlotState.MISSING, Delivery.LATE, "settled_after_due")


def test_settlement_exactly_at_due_is_on_time():
    due = CREATED + timedelta(seconds=SETTLE)
    result = _assess(_snap([_rec("r1", "SUCCEEDED", settled=due,
                                 projected=due)]))
    assert _slots(result)[("r1", "settled")][0] is SlotState.SATISFIED


def test_unknown_reconciliation_stays_pending_and_unobservable():
    result = _assess(_snap([_rec("r1", "UNKNOWN", settled=ON_TIME,
                                 projected=ON_TIME)]))
    slot = next(s for s in result.slots if s.slot_id == "settled")
    assert slot.state is SlotState.PENDING
    assert slot.observation is Observation.UNOBSERVABLE
    assert slot.reason == "reconciled_unknown_needs_readback"
    assert result.claim_verdict is ClaimVerdict.NOT_ESTABLISHED


def test_missing_and_late_projection():
    never = _rec("r1", "SUCCEEDED", settled=ON_TIME)
    late = _rec("r2", "SUCCEEDED", settled=ON_TIME,
                projected=ON_TIME + timedelta(seconds=PROJECT + 1))
    result = _assess(_snap([never, late]))
    assert _slots(result)[("r1", "projected")] == (
        SlotState.MISSING, Delivery.NONE, "not_projected_by_due")
    assert _slots(result)[("r2", "projected")] == (
        SlotState.MISSING, Delivery.LATE, "projected_after_due")


def test_projection_exactly_at_due_is_on_time():
    due = ON_TIME + timedelta(seconds=PROJECT)
    result = _assess(_snap([_rec("r1", "SUCCEEDED", settled=ON_TIME,
                                 projected=due)]))
    assert _slots(result)[("r1", "projected")][0] is SlotState.SATISFIED


def test_inventory_closed_after_window_but_before_last_due_is_not_closure():
    """Closing at window_end is not enough: an intent created just before it
    still has its settlement and projection deadlines ahead."""
    almost = CLOSURE - timedelta(seconds=1)
    result = _assess(_snap([], closed_at=almost), as_of=almost)
    assert result.coverage_reasons == ("inventory_not_closed_past_due",)
    assert result.claim_verdict is ClaimVerdict.NOT_ESTABLISHED

# -- Coverage refusals ------------------------------------------------------

def test_no_snapshot_means_coverage_not_established_and_no_slots():
    result = _assess(None)
    assert result.coverage is Coverage.NOT_ESTABLISHED
    assert result.coverage_reasons == ("no_inventory_snapshot",)
    assert result.slots == ()
    assert result.claim_verdict is ClaimVerdict.NOT_ESTABLISHED


def test_empty_closed_inventory_is_a_bounded_positive():
    result = _assess(_snap([]))
    assert result.coverage is Coverage.ESTABLISHED_WITHIN_DECLARED_SCOPE
    assert result.claim_verdict is ClaimVerdict.ESTABLISHED
    assert result.slots == ()


def test_source_not_accepted_by_deployment_is_refused():
    """The manifest naming a writer does not make that writer trusted."""
    result = _assess(_snap([]), accepted=frozenset())
    assert result.coverage_reasons == ("inventory_source_not_accepted",)
    assert result.claim_verdict is ClaimVerdict.NOT_ESTABLISHED


def test_snapshot_from_a_writer_the_manifest_did_not_declare():
    other = "deploy:someone-else"
    result = _assess(_snap([], writer=other),
                     accepted=ACCEPTED | {(OUTBOX_INVENTORY_KIND, other)})
    assert result.coverage_reasons == ("inventory_not_declared_by_manifest",)


def test_manifest_written_after_window_opened_is_not_locked():
    result = _assess(_snap([]), _manifest(
        created_at=(T0 + timedelta(seconds=1)).isoformat()))
    assert result.coverage_reasons == ("manifest_not_locked_before_window",)
    assert result.claim_verdict is ClaimVerdict.NOT_ESTABLISHED


def test_snapshot_tenant_mismatch():
    result = _assess(_snap([], tenant="other"))
    assert "snapshot_tenant_mismatch" in result.coverage_reasons


def test_cross_tenant_record_is_excluded_and_flagged():
    foreign = _rec("x1", "DISPATCHING", tenant="other")
    result = _assess(_snap([foreign]))
    assert result.slots == ()
    assert result.coverage_reasons == ("cross_tenant_record_in_snapshot",)


def test_tampered_selection_is_not_evaluated():
    honest = (_rec("r1", "DISPATCHING"),)
    snapshot = _snap(honest)
    tampered = replace(snapshot, records=())  # dropped the incriminating row
    result = _assess(tampered)
    assert result.coverage_reasons == ("snapshot_records_digest_mismatch",)
    assert result.slots == ()
    assert result.claim_verdict is ClaimVerdict.NOT_ESTABLISHED


def test_assessment_time_before_snapshot_close_is_incoherent():
    result = _assess(_snap([]), as_of=CLOSURE - timedelta(seconds=1))
    assert result.coverage_reasons == ("snapshot_closed_after_assessment_time",)


# -- Inconsistent records ---------------------------------------------------

@pytest.mark.parametrize(("record", "reason"), [
    (_rec("r1", "TELEPORTED"), "unknown_lifecycle_state"),
    (_rec("r1", "SUCCEEDED"), "terminal_without_settled_at"),
    (_rec("r1", "DISPATCHING", settled=ON_TIME),
     "open_row_with_settlement_fields"),
    (_rec("r1", "SUCCEEDED", settled=CREATED - timedelta(seconds=1)),
     "settled_before_created"),
    (_rec("r1", "SUCCEEDED", settled=ON_TIME,
          projected=ON_TIME - timedelta(seconds=1)),
     "projected_before_settled"),
    (_rec("r1", "SUCCEEDED", settled=CLOSURE + timedelta(seconds=1)),
     "timestamp_after_snapshot_close"),
])
def test_inconsistent_record_is_invalid_and_blocks_coverage(record, reason):
    result = _assess(_snap([record]))
    assert {s.state for s in result.slots} == {SlotState.INVALID}
    assert {s.reason for s in result.slots} == {reason}
    assert "inconsistent_inventory_records" in result.coverage_reasons
    assert result.claim_verdict is ClaimVerdict.NOT_ESTABLISHED


def test_duplicate_subject_cannot_look_satisfied():
    """Upper bound of one: two rows for one dispatch attempt is a conflict,
    even when both look settled."""
    a = _rec("r1", "SUCCEEDED", settled=ON_TIME, projected=ON_TIME,
             subject="k")
    b = _rec("r2", "SUCCEEDED", settled=ON_TIME, projected=ON_TIME,
             subject="k")
    result = _assess(_snap([a, b]))
    assert {s.state for s in result.slots} == {SlotState.CONFLICTED}
    assert result.claim_verdict is ClaimVerdict.NOT_ESTABLISHED


def test_duplicate_record_id_is_conflicted():
    a = _rec("r1", "SUCCEEDED", settled=ON_TIME, projected=ON_TIME,
             subject="k1")
    b = _rec("r1", "DISPATCHING", subject="k2")
    result = _assess(_snap([a, b]))
    assert {s.reason for s in result.slots} == {"duplicate_record_id"}


def test_records_outside_the_window_are_counted_not_assessed():
    before = _rec("r0", "DISPATCHING", created=T0 - timedelta(seconds=1))
    at_end = _rec("r9", "DISPATCHING", created=WINDOW_END)
    result = _assess(_snap([before, at_end]))
    assert result.slots == ()
    assert result.out_of_window_records == 2
    assert result.claim_verdict is ClaimVerdict.ESTABLISHED


# -- Determinism and reappraisal --------------------------------------------

def test_replay_is_byte_identical():
    """REAS H2: same inputs give the same bytes."""
    snapshot = _snap([_rec("r1", "DISPATCHING"),
                      _rec("r2", "SUCCEEDED", settled=ON_TIME)])
    first = json.dumps(_assess(snapshot).to_dict(), sort_keys=True)
    second = json.dumps(_assess(snapshot).to_dict(), sort_keys=True)
    assert first == second


def test_record_order_does_not_change_the_result():
    recs = [_rec("r1", "DISPATCHING"), _rec("r2", "SUCCEEDED", settled=ON_TIME)]
    a = _assess(_snap(recs))
    b = _assess(_snap(list(reversed(recs))))
    assert a.slots == b.slots
    assert a.claim_verdict is b.claim_verdict


def test_late_evidence_gives_a_new_assessment_and_leaves_the_old_one():
    stuck = _rec("r1", "DISPATCHING")
    first = _assess(_snap([stuck]))
    frozen_bytes = json.dumps(first.to_dict(), sort_keys=True)
    later = CLOSURE + timedelta(minutes=10)
    settled = _rec("r1", "SUCCEEDED", settled=later, projected=later)
    second = _assess(_snap([settled], closed_at=later), as_of=later)
    assert second.assessment_id != first.assessment_id
    assert _slots(second)[("r1", "settled")] == (
        SlotState.MISSING, Delivery.LATE, "settled_after_due")
    assert json.dumps(first.to_dict(), sort_keys=True) == frozen_bytes


def test_assessment_id_binds_manifest_version():
    snapshot = _snap([])
    v1 = _assess(snapshot)
    v2 = _assess(snapshot, _manifest(manifest_version=2))
    assert v1.assessment_id != v2.assessment_id
    assert v1.manifest_digest != v2.manifest_digest


# -- Manifest parsing -------------------------------------------------------

def _raw(data):
    return json.dumps(data).encode()


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(extra=1),
    lambda d: d["scope"].update(scope_kind="all_agent_activity"),
    lambda d: d["obligations"][0].update(trigger="anything"),
    lambda d: d["obligations"][0].update(kind="effect_observed"),
    lambda d: d["obligations"][0].update(maximum_count=5),
    lambda d: d["obligations"][0].update(minimum_count=0),
    lambda d: d["obligations"][0].update(due_within_seconds=0),
    lambda d: d["obligations"][0].update(slot_id="projected"),
    lambda d: d["obligations"][1].update(kind="terminal_settlement",
                                         trigger="intent_recorded",
                                         slot_id="other"),
    lambda d: d["obligations"].clear(),
    lambda d: d["inventory"].update(kind="third.party/v1"),
    lambda d: d.update(canonicalization_id="rfc8785"),
    lambda d: d.update(schema_version="remora-seo-manifest/v2"),
    lambda d: d.update(created_at="2026-10-16T11:55:00"),
    lambda d: d["scope"].update(window_end=T0.isoformat()),
    lambda d: d.pop("policy_revision"),
    lambda d: d["obligations"][0].update(due_within_seconds=1.5),
    lambda d: d["obligations"][0].update(due_within_seconds=True),
])
def test_manifest_parser_refuses_what_p1_does_not_support(mutate):
    data = _manifest_dict()
    mutate(data)
    with pytest.raises(ValueError):
        parse_manifest(_raw(data))


def test_manifest_parser_refuses_duplicate_keys():
    raw = _raw(_manifest_dict())[:-1] + b', "tenant_id": "evil"}'
    with pytest.raises(ValueError, match="duplicate"):
        parse_manifest(raw)


# -- Real outbox ------------------------------------------------------------

def test_inventory_state_names_match_the_outbox_lifecycle():
    assert {s.value for s in OutboxState} == set(KNOWN_STATES)


def test_adapter_reads_the_outbox_row_fields_it_relies_on():
    fields = set(OutboxRow.__dataclass_fields__)
    assert {"outbox_id", "tenant_id", "idempotency_key", "state",
            "created_at", "settled_at", "projected_at"} <= fields


@pytest.fixture(params=["memory", "sqlite"])
def outbox(request, tmp_path):
    if request.param == "memory":
        return ExecutionOutbox()
    return SQLiteExecutionOutbox(str(tmp_path / "outbox.db"))


def _intent(box, n, at):
    return box.record_intent(
        proposal_id=f"p-{n}", tenant_id=TENANT, item_id=f"i-{n}",
        tool_name="store_artifact", tool_call_hash=f"{n:064x}",
        grant_jti=f"jti-{n}", now=at)


def test_real_outbox_lifecycle_through_the_assessor(outbox):
    """Drive real rows: one clean dispatch, one crash left DISPATCHING, one
    reconciled to UNKNOWN, one never claimed and reconciled to FAILED."""
    t = CREATED
    clean = _intent(outbox, 1, t)
    outbox.claim(clean.outbox_id, worker_id="w", now=t)
    outbox.settle(clean.outbox_id, OutboxState.SUCCEEDED,
                  now=t + timedelta(seconds=5))
    outbox.mark_projected(clean.outbox_id, now=t + timedelta(seconds=6))

    crashed = _intent(outbox, 2, t)
    outbox.claim(crashed.outbox_id, worker_id="w", now=t)

    unknown = _intent(outbox, 3, t)
    outbox.claim(unknown.outbox_id, worker_id="w", now=t)
    outbox.reconcile_stale(TENANT, older_than=timedelta(seconds=30),
                           now=t + timedelta(seconds=31))
    # reconcile_stale also settled `crashed`; re-create a genuinely stuck one.
    stuck = _intent(outbox, 4, t + timedelta(seconds=40))
    outbox.claim(stuck.outbox_id, worker_id="w", now=t + timedelta(seconds=40))

    never = _intent(outbox, 5, t)
    outbox.reconcile_unclaimed(TENANT, older_than=timedelta(seconds=30),
                               now=t + timedelta(seconds=50))

    rows = [outbox.get(r.outbox_id) for r in (clean, crashed, unknown,
                                              stuck, never)]
    snapshot = snapshot_from_outbox_rows(rows, tenant_id=TENANT, writer=WRITER,
                                         closed_at=CLOSURE)
    result = _assess(snapshot)
    by_id = {r.outbox_id: r for r in rows}
    settled = {by_id[s.record_id].proposal_id: (s.state, s.reason)
               for s in result.slots if s.slot_id == "settled"}
    assert settled == {
        "p-1": (SlotState.SATISFIED, "settled_succeeded"),
        "p-2": (SlotState.PENDING, "reconciled_unknown_needs_readback"),
        "p-3": (SlotState.PENDING, "reconciled_unknown_needs_readback"),
        "p-4": (SlotState.MISSING, "not_settled_by_due"),
        "p-5": (SlotState.SATISFIED, "settled_failed"),
    }
    projected = {by_id[s.record_id].proposal_id: s.state
                 for s in result.slots if s.slot_id == "projected"}
    assert projected["p-1"] is SlotState.SATISFIED
    # Reconciled rows are settled but nobody projected them in this test.
    assert projected["p-5"] is SlotState.MISSING
    assert projected["p-4"] is SlotState.NOT_APPLICABLE
    assert result.coverage is Coverage.ESTABLISHED_WITHIN_DECLARED_SCOPE
    assert result.claim_verdict is ClaimVerdict.NOT_ESTABLISHED

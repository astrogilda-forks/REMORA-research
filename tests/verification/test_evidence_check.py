# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1-05 and WS1-06: what evidence may become PROVED (A05-A07)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from remora.verification.check import (
    CheckedPreconditions,
    VerificationRequest,
    check_preconditions,
)
from remora.verification.preconditions import LogicalState, ProcessingStatus, derive_preconditions
from tests.verification._ws1 import NOW_MS, NOW_S, REGISTRY, VERIFIERS, context, h, sources

CTX, ARGS = context()
REQS = derive_preconditions(CTX, ARGS, REGISTRY)
PORT = next(p for p in REQS.preconditions if p.predicate_id == "target_belongs_to_work_order")


def _request(pre=PORT, resolver="inventory", rid="r-1", ctx=CTX):
    return VerificationRequest(rid, ctx.context_hash, 0, pre.precondition_id, resolver,
                               pre.subject_ref, NOW_MS + 1000, "b")


def _fetched(request, src="inventory"):
    return sources()[src].fetch(request, CTX.tenant_id, NOW_S)


def _check(evidence, issued, now_s=NOW_S, verifiers=VERIFIERS):
    return check_preconditions(CTX, REQS, evidence, issued=issued, registry=REGISTRY,
                               verifiers=verifiers, now_s=now_s, evidence_revision=1)


def test_registered_evidence_proves_the_precondition():
    req = _request()
    checked = _check([_fetched(req)], {req.request_id: req})
    assert checked.state(PORT.precondition_id) is LogicalState.PROVED
    assert checked.result(PORT.precondition_id).processing_status is ProcessingStatus.COMPLETED


def test_claimed_verified_is_not_proved():
    """A05: a client cannot post a result, and evidence nobody asked for is ignored."""
    with pytest.raises(TypeError, match="check_preconditions only"):
        CheckedPreconditions(CTX.context_hash, REQS.requirements_hash, 0, h("d"), (), True, None)
    req = _request()
    item = _fetched(req)
    # Same bytes, but no request on record: a model citing "evidence" it made up.
    checked = _check([item], {})
    assert checked.state(PORT.precondition_id) is LogicalState.UNKNOWN
    assert checked.rejected_evidence == ((req.request_id, "unrequested_evidence"),)


@pytest.mark.parametrize("change, fault", [
    ({"source_id": "attacker-db"}, "source_not_registered"),
    ({"resolver_id": "acl"}, "resolver_not_registered_for_precondition"),
    ({"tenant_id": "t2"}, "tenant_mismatch"),
    ({"subject_ref": "sw1/p5"}, "subject_mismatch"),
    ({"payload_hash": h("other")}, "integrity_mismatch"),
    ({"acquired_at": NOW_S - 120}, "stale"),
    ({"valid_until": NOW_S}, "stale"),
])
def test_signed_or_plausible_evidence_from_the_wrong_place_is_not_proved(change, fault):
    req = _request()
    checked = _check([replace(_fetched(req), **change)], {req.request_id: req})
    assert checked.state(PORT.precondition_id) is LogicalState.UNKNOWN
    assert checked.rejected_evidence == ((req.request_id, fault),)


def test_evidence_goes_stale_on_a_later_check():
    req = _request()
    item = _fetched(req)
    assert _check([item], {req.request_id: req}).state(PORT.precondition_id) is LogicalState.PROVED
    later = _check([item], {req.request_id: req}, now_s=NOW_S + 61)
    assert later.state(PORT.precondition_id) is LogicalState.UNKNOWN


def test_relation_binding_rejects_valid_value_for_wrong_customer():
    """A06: a real port, but bound to another work order, is REFUTED."""
    ctx, args = context(args={"port": "sw1/p9", "customer": "C-1", "profile": "gold"})
    reqs = derive_preconditions(ctx, args, REGISTRY)
    pre = next(p for p in reqs.preconditions if p.predicate_id == "target_belongs_to_work_order")
    req = VerificationRequest("r", ctx.context_hash, 0, pre.precondition_id, "inventory",
                              pre.subject_ref, NOW_MS + 1000, "b")
    item = sources()["inventory"].fetch(req, ctx.tenant_id, NOW_S)
    checked = check_preconditions(ctx, reqs, [item], issued={"r": req}, registry=REGISTRY,
                                  verifiers=VERIFIERS, now_s=NOW_S, evidence_revision=0)
    assert checked.state(pre.precondition_id) is LogicalState.REFUTED
    assert checked.result(pre.precondition_id).reason_code == "subject_bound_to_another_work_order"


def test_conflicting_evidence_cannot_be_averaged_or_overwritten():
    """A07: one valid refutation among confirmations is CONFLICT, not a majority."""
    good, bad = [], {}
    for i in range(3):
        req = _request(rid=f"r-{i}")
        bad[req.request_id] = req
        good.append(_fetched(req))
    payload = json.dumps({"found": True, "record": {"tenant": "t1", "work_order_hash": h("x")}}).encode()
    req = _request(rid="r-refute")
    bad[req.request_id] = req
    refuting = replace(_fetched(req), payload=payload, payload_hash=hashlib.sha256(payload).hexdigest())
    checked = _check([*good, refuting], bad)
    assert checked.state(PORT.precondition_id) is LogicalState.CONFLICT


def test_a_failed_verifier_is_not_a_verified_negative():
    class Broken:
        verifier_id, version = "wo-verifier", "0"

        def verify(self, *a):
            raise RuntimeError("down")

    req = _request()
    result = _check([_fetched(req)], {req.request_id: req},
                    verifiers={**VERIFIERS, "wo-verifier": Broken()}).result(PORT.precondition_id)
    assert result.logical_state is LogicalState.UNKNOWN
    assert result.processing_status is ProcessingStatus.FAILED


def test_a_missing_verifier_is_unsupported_not_proved():
    req = _request()
    result = _check([_fetched(req)], {req.request_id: req}, verifiers={}).result(PORT.precondition_id)
    assert (result.logical_state, result.processing_status) == (LogicalState.UNKNOWN,
                                                                ProcessingStatus.UNSUPPORTED)


def test_absence_from_an_open_source_is_unknown():
    ctx, args = context(args={"port": "sw9/p1", "customer": "C-1", "profile": "gold"})
    reqs = derive_preconditions(ctx, args, REGISTRY)
    pre = reqs.preconditions[0]
    req = VerificationRequest("r", ctx.context_hash, 0, pre.precondition_id, "inventory",
                              pre.subject_ref, NOW_MS + 1000, "b")
    item = sources()["inventory"].fetch(req, ctx.tenant_id, NOW_S)
    checked = check_preconditions(ctx, reqs, [item], issued={"r": req}, registry=REGISTRY,
                                  verifiers=VERIFIERS, now_s=NOW_S, evidence_revision=0)
    assert checked.state(pre.precondition_id) is LogicalState.UNKNOWN

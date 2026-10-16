# SPDX-License-Identifier: BUSL-1.1
"""Searched validation of the obligation assessor (REAS H1, H2).

Declared domain: 0 to 8 internally consistent outbox records with unique ids
and subjects, every lifecycle state, creation times from 10 minutes before to
10 minutes after the window, settlement and projection offsets of 0 to 900 s,
against the fixed two-obligation manifest of test_evidence_obligations.py and
a snapshot closed exactly at the manifest's closure point. Excluded:
duplicate and inconsistent records (covered by example tests). The result is
"no counterexample found in N examples", not a proof.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

from hypothesis import given, settings
from hypothesis import strategies as st

from remora.evidence.obligations import ClaimVerdict
from tests.test_evidence_obligations import (
    CLOSURE,
    PROJECT,
    SETTLE,
    T0,
    WINDOW_END,
    _assess,
    _rec,
    _snap,
)

OPEN = ("DISPATCH_PENDING", "DISPATCHING")
TERMINAL = ("SUCCEEDED", "FAILED", "REFUSED", "UNKNOWN")


@st.composite
def records(draw):
    n = draw(st.integers(0, 8))
    out = []
    for i in range(n):
        created = T0 + timedelta(seconds=draw(st.integers(-600, 4200)))
        state = draw(st.sampled_from(OPEN + TERMINAL))
        settled = projected = None
        if state in TERMINAL:
            settled = created + timedelta(seconds=draw(st.integers(0, 900)))
            if draw(st.booleans()):
                projected = settled + timedelta(
                    seconds=draw(st.integers(0, 900)))
        out.append(_rec(f"r{i}", state, created=created, settled=settled,
                        projected=projected))
    # Keep every record a truthful row of a snapshot closed at CLOSURE.
    return [r for r in out
            if all(s is None or s <= CLOSURE
                   for s in (r.created_at, r.settled_at, r.projected_at))]


def _oracle_complete(recs) -> bool:
    """Hand-written: every in-window intent settled (not UNKNOWN) on time and
    was projected on time."""
    for r in recs:
        if not T0 <= r.created_at < WINDOW_END:
            continue
        if r.state not in ("SUCCEEDED", "FAILED", "REFUSED"):
            return False
        if r.settled_at > r.created_at + timedelta(seconds=SETTLE):
            return False
        if r.projected_at is None:
            return False
        if r.projected_at > r.settled_at + timedelta(seconds=PROJECT):
            return False
    return True


@settings(max_examples=400, deadline=None)
@given(records())
def test_verdict_matches_independent_oracle(recs):
    """H1: no false 'complete' and no false 'incomplete' in the domain."""
    result = _assess(_snap(recs))
    expected = (ClaimVerdict.ESTABLISHED if _oracle_complete(recs)
                else ClaimVerdict.NOT_ESTABLISHED)
    assert result.claim_verdict is expected


@settings(max_examples=300, deadline=None)
@given(records(), st.data())
def test_removing_evidence_never_strengthens_the_verdict(recs, data):
    before = _assess(_snap(recs))
    with_projection = [i for i, r in enumerate(recs) if r.projected_at]
    if not with_projection:
        return
    i = data.draw(st.sampled_from(with_projection))
    erased = list(recs)
    erased[i] = replace(erased[i], projected_at=None)
    after = _assess(_snap(erased))
    if before.claim_verdict is ClaimVerdict.NOT_ESTABLISHED:
        assert after.claim_verdict is ClaimVerdict.NOT_ESTABLISHED


@settings(max_examples=200, deadline=None)
@given(records(), st.randoms(use_true_random=False))
def test_order_and_replay_invariance(recs, rnd):
    """H2: shuffling the snapshot or replaying it changes nothing."""
    shuffled = list(recs)
    rnd.shuffle(shuffled)
    a = _assess(_snap(recs))
    b = _assess(_snap(shuffled))
    assert a.slots == b.slots
    assert a.claim_verdict is b.claim_verdict
    assert _assess(_snap(recs)).to_dict() == a.to_dict()

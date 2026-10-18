# SPDX-License-Identifier: BUSL-1.1
"""IFC-01: the label lattice obeys its laws (SDD §3.1, §6.1).

Searched validation over a declared generated domain: reader sets drawn from
the patterns in ``PATTERNS`` (nested and disjoint subtrees, exact principals,
four schemes) or PUBLIC, and both integrity levels. Principals for
``flows_to`` come from ``PRINCIPALS``. No counterexample found in the
examples Hypothesis generates is not a proof.

Mutation testing (mutmut 3, ``remora/flow/label.py`` against this file,
2026-10-17): every mutant is killed except these equivalent ones.

* ``_pattern_within``: the exact-outer branch's ``not inner.endswith("/*")``.
  A subtree pattern never equals an exact one, so ``inner == outer`` alone
  gives the same answer.
* ``canonical_bytes``: ``ensure_ascii`` (removed, None, True) and the
  encoding name's case. A canonical resource is ASCII-only (non-ASCII is
  refused, see ``test_canonical_bytes_are_pinned``), so the bytes do not
  change.
"""
from __future__ import annotations

import pickle

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from remora.flow.label import (
    BOTTOM,
    PUBLIC,
    Integrity,
    Label,
    LabelRefused,
    _pattern_within,
    canonical_bytes,
    field_value_label,
    flows_to,
    join,
    join_all,
    leq,
)

PATTERNS = [
    "email://corp.example/*",
    "email://corp.example/bob",
    "email://corp.example/team/*",
    "email://corp.example/team/ann",
    # A sibling whose name extends "team": a subtree must not cover it.
    "email://corp.example/teamx/*",
    "email://other.example/*",
    "email://other.example/eve",
    "ext://api.provider.example",
    "ext://evil.example",
    "user://t1/*",
    "user://t1/u1",
    "user://t2/u9",
    "iban://no/NO9386011117947",
    "res://banking/payees",
]
PRINCIPALS = [
    "email://corp.example/bob",
    "email://corp.example/carol",
    "email://corp.example/team/ann",
    "email://corp.example/team/zed",
    "email://corp.example/teamx/ann",
    "email://other.example/eve",
    "ext://api.provider.example",
    "ext://evil.example",
    "user://t1/u1",
    "user://t1/u2",
    "user://t2/u9",
    "iban://no/NO9386011117947",
    "res://banking/payees",
]

readers = st.one_of(st.just(PUBLIC), st.frozensets(st.sampled_from(PATTERNS), max_size=5))
labels = st.builds(Label, readers, st.sampled_from(list(Integrity)))
principal = st.sampled_from(PRINCIPALS)
EXAMPLES = settings(max_examples=500, deadline=None)


@EXAMPLES
@given(labels, labels)
def test_join_is_commutative(a, b):
    assert join(a, b) == join(b, a)


@EXAMPLES
@given(labels, labels, labels)
def test_join_is_associative(a, b, c):
    assert join(join(a, b), c) == join(a, join(b, c))


@EXAMPLES
@given(labels)
def test_join_is_idempotent(a):
    assert join(a, a) == a


@EXAMPLES
@given(labels, labels)
def test_join_is_an_upper_bound(a, b):
    assert leq(a, join(a, b))
    assert leq(b, join(a, b))


@EXAMPLES
@given(labels, labels, principal)
def test_flows_to_is_antitone(a, b, r):
    if leq(a, b) and flows_to(b, r):
        assert flows_to(a, r)


@EXAMPLES
@given(labels, labels, principal)
def test_join_is_exact_for_flows(a, b, r):
    """Data joined from a and b reaches r exactly when both may reach r."""
    assert flows_to(join(a, b), r) == (flows_to(a, r) and flows_to(b, r))


@EXAMPLES
@given(labels, labels)
def test_intersection_stays_inside_both_inputs(a, b):
    out = join(a, b).readers
    if out is PUBLIC:
        assert a.readers is PUBLIC and b.readers is PUBLIC
        return
    for p in out:
        for side in (a.readers, b.readers):
            assert side is PUBLIC or any(_pattern_within(p, q) for q in side)


@EXAMPLES
@given(labels)
def test_bottom_is_least_and_join_identity(a):
    assert leq(BOTTOM, a)
    assert join(BOTTOM, a) == a


@EXAMPLES
@given(labels, labels, labels)
def test_leq_is_a_partial_order(a, b, c):
    assert leq(a, a)
    if leq(a, b) and leq(b, a):
        assert a == b
    if leq(a, b) and leq(b, c):
        assert leq(a, c)


@EXAMPLES
@given(labels, labels)
def test_canonical_bytes_identify_labels(a, b):
    assert (canonical_bytes(a) == canonical_bytes(b)) == (a == b)


@EXAMPLES
@given(labels, labels, st.lists(labels, max_size=3))
def test_value_integrity_independent_of_context(handle, context, others):
    """A field that is exactly one handle keeps the handle's label, whatever L_ctx is."""
    out = field_value_label(exactly_one_handle=True, context=context, handle_labels=[handle])
    assert out == handle
    assert out.integrity is handle.integrity
    mixed = field_value_label(exactly_one_handle=False, context=context,
                              handle_labels=[handle, *others])
    assert leq(context, mixed)
    assert leq(handle, mixed)


def test_untrusted_context_taints_literal_text_only():
    trusted_param = Label(["user://t1/u1"], Integrity.TRUSTED)
    tainted_ctx = Label(["user://t1/u1"], Integrity.UNTRUSTED)
    whole = field_value_label(exactly_one_handle=True, context=tainted_ctx,
                              handle_labels=[trusted_param])
    literal = field_value_label(exactly_one_handle=False, context=tainted_ctx,
                                handle_labels=[trusted_param])
    assert whole.trusted
    assert not literal.trusted


def test_reader_sets_are_canonical_antichains():
    assert Label(["email://corp.example/*", "email://corp.example/bob"]) == Label(
        ["email://corp.example/*"])
    assert Label(["EMAIL://Corp.Example/bob"]) == Label(["email://corp.example/bob"])


def test_subtree_admits_strictly_below_its_base():
    team = Label(["email://corp.example/team/*"])
    assert flows_to(team, "email://corp.example/team/ann")
    assert not flows_to(team, "email://corp.example/team")
    assert not flows_to(team, "email://corp.example/teamx/ann")


def test_disjoint_reader_sets_join_to_nobody():
    out = join(Label(["user://t1/u1"]), Label(["ext://evil.example"]))
    assert out.readers == frozenset()
    assert not any(flows_to(out, r) for r in PRINCIPALS)


def test_public_flows_everywhere_and_is_top():
    assert all(flows_to(BOTTOM, r) for r in PRINCIPALS)
    assert leq(BOTTOM, Label(["user://t1/u1"]))
    assert not leq(Label(["user://t1/u1"]), BOTTOM)


def test_join_all_and_integrity():
    out = join_all([Label(PUBLIC, Integrity.UNTRUSTED), Label(["user://t1/*"])])
    assert out == Label(["user://t1/*"], Integrity.UNTRUSTED)
    assert join_all([]) == BOTTOM


@pytest.mark.parametrize("bad", [
    ["mailto:bob@corp.example"],
    ["email://bob@corp.example"],
    ["email://corp.example/../root"],
    ["email://corp.example/a%2Fb"],
    "email://corp.example/bob",
])
def test_ambiguous_readers_are_refused(bad):
    with pytest.raises(LabelRefused):
        Label(bad)


def test_bad_integrity_and_whole_handle_arity_are_refused():
    with pytest.raises(LabelRefused):
        Label(PUBLIC, "TRUSTED")  # type: ignore[arg-type]
    with pytest.raises(LabelRefused):
        field_value_label(exactly_one_handle=True, context=BOTTOM, handle_labels=[])


def test_ambiguous_principal_receives_only_public_data():
    assert not flows_to(Label(["email://corp.example/*"]), "email://corp.example/../x")
    assert flows_to(BOTTOM, "email://corp.example/../x")


def test_public_survives_pickling_as_the_singleton():
    assert pickle.loads(pickle.dumps(BOTTOM)).readers is PUBLIC


def test_canonical_bytes_are_pinned():
    """The hashed form is a contract: leases and grants bind it (SDD §3.8)."""
    assert canonical_bytes(BOTTOM) == (
        b'{"integrity":"TRUSTED","readers":"PUBLIC","v":"remora/flow-label/v1"}')
    label = Label(["user://t1/u1", "email://corp.example/*"], Integrity.UNTRUSTED)
    assert canonical_bytes(label) == (
        b'{"integrity":"UNTRUSTED","readers":["email://corp.example/*","user://t1/u1"],'
        b'"v":"remora/flow-label/v1"}')
    # Canonical resources are ASCII-only, so ensure_ascii has no observable
    # effect on a valid label (equivalent mutants in canonical_bytes).
    with pytest.raises(LabelRefused):
        Label(["user://t1/åse"])


def test_a_subtree_does_not_cover_a_sibling_that_extends_its_name():
    assert not leq(Label(["email://corp.example/team/*"]), Label(["email://corp.example/teamx/*"]))
    assert join(Label(["email://corp.example/team/*"]),
                Label(["email://corp.example/teamx/*"])).readers == frozenset()
    # An exact principal never equals a subtree pattern, so the subtree test in
    # _pattern_within's exact branch has no observable twin (equivalent mutant).
    assert not _pattern_within("email://corp.example/team/*", "email://corp.example/team")


def test_refusals_say_why():
    with pytest.raises(LabelRefused, match=r"^readers is PUBLIC or a set of patterns, not one string$"):
        Label("email://corp.example/bob")
    with pytest.raises(LabelRefused, match=r"reader pattern 'email://bob@corp.example'"):
        Label(["email://bob@corp.example"])
    with pytest.raises(LabelRefused, match="must be an Integrity"):
        Label(PUBLIC, "TRUSTED")  # type: ignore[arg-type]
    with pytest.raises(LabelRefused, match=r"^a whole-handle field has exactly one handle label$"):
        field_value_label(exactly_one_handle=True, context=BOTTOM, handle_labels=[])


def test_public_repr():
    assert repr(PUBLIC) == "PUBLIC"

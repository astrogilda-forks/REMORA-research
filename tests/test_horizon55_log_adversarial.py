# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Horizon #55 row: replayed, duplicated, reordered and truncated log entries.

P1 vectors over the signed set-2 records. Every entry here is a genuine,
signed entry of the frozen log; only its position or multiplicity changes.
The row must neither count a replayed payment twice nor establish anything
from a log whose order, length or checkpoint no longer verifies. These are the
author's own controls, not external adversarial coverage.
"""
from __future__ import annotations

import dataclasses
import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "integrations" / "horizon55"
sys.path.insert(0, str(PKG))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"h55_{name}", PKG / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


canon = _load("canon")
check_inputs = _load("check_inputs")
claims = _load("claims")
E, C, N = claims.ESTABLISHED, claims.CONTRADICTED, claims.NOT_ESTABLISHED
PAYMENT_A, USE_B, RECEIPT_B, PAYMENT_B, PAYMENT_C = 5, 7, 9, 8, 11


@pytest.fixture(scope="module")
def inputs():
    return claims.load_inputs(check_inputs.INPUTS, check_inputs.CACHE, check_inputs.load_lock())


def _order(inputs, order):
    """The log with its genuine entries at the positions ``order`` names."""
    return dataclasses.replace(inputs, entries=[inputs.entries[i] for i in order],
                               entry_paths=[inputs.entry_paths[i] for i in order])


def _verdicts(out):
    return {(r["case_id"], r["claim_id"]): r["verdict"] for r in out["results"]}


def _refuses(out, *problems):
    """The log does not verify for the named reasons, and nothing is established."""
    found = out["log"]["problems"]
    assert not out["log"]["verified"]
    for prefix in problems:
        assert any(p.startswith(prefix) for p in found), (prefix, found)
    v = _verdicts(out)
    assert all(verdict != E for verdict in v.values())
    assert v[("C", "budget_compliance")] == N
    return v


def test_the_unmodified_log_is_the_baseline(inputs):
    out = claims.evaluate(inputs)
    assert out["log"]["verified"]
    assert _verdicts(out)[("C", "budget_compliance")] == C


@pytest.mark.parametrize("replayed", [PAYMENT_A, PAYMENT_C])
def test_a_payment_replayed_at_the_end_is_not_counted_again(inputs, replayed):
    """Seq, prev and the checkpoint all name the original length."""
    order = [*range(len(inputs.entries)), replayed]
    _refuses(claims.evaluate(_order(inputs, order)),
             "seq_gap", "prev_mismatch", "checkpoint_size_mismatch")


def test_a_payment_duplicated_in_place_is_not_counted_again(inputs):
    order = list(range(len(inputs.entries)))
    order.insert(PAYMENT_A + 1, PAYMENT_A)
    _refuses(claims.evaluate(_order(inputs, order)), "seq_gap", "prev_mismatch")


@pytest.mark.parametrize("swap", [(PAYMENT_B, RECEIPT_B), (PAYMENT_B, PAYMENT_C)])
def test_reordered_entries_break_the_chain(inputs, swap):
    order = list(range(len(inputs.entries)))
    i, j = swap
    order[i], order[j] = order[j], order[i]
    _refuses(claims.evaluate(_order(inputs, order)), "seq_gap", "prev_mismatch")


def test_b_moved_after_c_cannot_make_c_fit_the_budget(inputs):
    """With C before B the running total would put C at 14000; the order is signed."""
    order = [*range(USE_B), *range(PAYMENT_C - 1, len(inputs.entries)), USE_B, PAYMENT_B,
             RECEIPT_B]
    assert sorted(order) == list(range(len(inputs.entries)))
    _refuses(claims.evaluate(_order(inputs, order)), "seq_gap", "prev_mismatch")


@pytest.mark.parametrize("keep", [10, 12])
def test_a_truncated_log_that_hides_c_is_refused(inputs, keep):
    out = claims.evaluate(_order(inputs, range(keep)))
    _refuses(out, "checkpoint_size_mismatch", "checkpoint_head_mismatch",
             "bundle_entries_differ_from_log_files")


@pytest.mark.parametrize("field, value", [("size", 10), ("head", "0" * 64), ("as_of", 0)])
def test_a_tampered_checkpoint_is_refused(inputs, field, value):
    checkpoint = canon.loads(inputs.checkpoint)
    checkpoint[field] = value
    out = claims.evaluate(dataclasses.replace(inputs, checkpoint=canon.jcs(checkpoint)))
    _refuses(out, "checkpoint_signature_invalid")


def test_a_replayed_entry_with_a_rewritten_position_fails_its_signature(inputs):
    """Fixing seq and prev on a copy means changing signed bytes."""
    entries = [canon.loads(raw) for raw in inputs.entries]
    copy = dict(entries[PAYMENT_C], seq=len(entries),
                prev=canon.sha256_hex(canon.jcs(entries[-1])))
    replayed = dataclasses.replace(
        inputs, entries=[*inputs.entries, canon.jcs(copy)],
        entry_paths=[*inputs.entry_paths, "pilot51/set2/log/entries/013_replay.json"])
    _refuses(claims.evaluate(replayed), "operator_signature_invalid",
             "checkpoint_size_mismatch")


def test_the_bundle_copy_of_the_log_must_agree_with_the_files(inputs):
    bundle = canon.loads(inputs.bundle)
    bundle["log"]["entries"] = bundle["log"]["entries"][:-1]
    out = claims.evaluate(dataclasses.replace(inputs, bundle=canon.jcs(bundle)))
    _refuses(out, "bundle_entries_differ_from_log_files")

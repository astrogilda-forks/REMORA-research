# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Horizon #55 row: locally authored mutations of the signed records.

H55-T04, T05, T06 and T10. These are the author's own controls, not external
adversarial coverage. Each mutation is applied in memory to the frozen bytes;
the row must refuse to establish what the tampered bytes would otherwise say.
"""
from __future__ import annotations

import dataclasses
import importlib.util
import shutil
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
run = _load("run")
E, C, N = claims.ESTABLISHED, claims.CONTRADICTED, claims.NOT_ESTABLISHED
RECEIPT_A, PAYMENT_C, RECEIPT_C, BUDGET = 6, 11, 12, 0


@pytest.fixture(scope="module")
def inputs():
    return claims.load_inputs(check_inputs.INPUTS, check_inputs.CACHE, check_inputs.load_lock())


def verdicts(out):
    return {(r["case_id"], r["claim_id"]): r["verdict"] for r in out["results"]}


def with_entries(inputs, entries):
    return dataclasses.replace(inputs, entries=[canon.jcs(e) for e in entries])


def parsed(inputs):
    return [canon.loads(raw) for raw in inputs.entries]


def test_t04_swapped_genuine_receipts_break_the_log_and_every_join(inputs):
    entries = parsed(inputs)
    entries[RECEIPT_A]["item"], entries[RECEIPT_C]["item"] = (
        entries[RECEIPT_C]["item"], entries[RECEIPT_A]["item"])
    out = claims.evaluate(with_entries(inputs, entries))
    assert any(p.startswith("operator_signature_invalid") for p in out["log"]["problems"])
    v = verdicts(out)
    assert all(v[(case, "same_request_occurrence")] == N for case in claims.CASES)
    assert all(verdict != E for verdict in v.values())


def test_t04_a_changed_occurrence_id_joins_no_records(inputs):
    bundle = canon.loads(inputs.bundle)
    for request in bundle["requests"]:
        if request["occurrence_id"] == "hs51-musubi-2-A":
            request["occurrence_id"] = "hs51-musubi-2-A-renamed"
    out = claims.evaluate(dataclasses.replace(inputs, bundle=canon.jcs(bundle)))
    v = verdicts(out)
    assert all(v[("A", claim)] == N for claim in claims.CLAIMS)
    assert v[("C", "budget_compliance")] == C  # the other cases are unaffected


@pytest.mark.parametrize("index, field, value", [
    (PAYMENT_C, "amount", 1),
    (BUDGET, "max_total", 10 ** 6),
])
def test_t05_a_mutated_signed_field_is_never_recomputed(inputs, index, field, value):
    entries = parsed(inputs)
    entries[index]["item"][field] = value
    out = claims.evaluate(with_entries(inputs, entries))
    assert f"item_signature_invalid:{inputs.entry_paths[index]}" in out["log"]["problems"]
    v = verdicts(out)
    assert v[("C", "budget_compliance")] == N  # not ESTABLISHED on the forged number
    assert all(verdict != E for verdict in v.values())


def test_t05_a_tampered_vendored_file_fails_closed_before_evaluation(tmp_path):
    inputs = tmp_path / "inputs"
    shutil.copytree(check_inputs.INPUTS, inputs)
    path = inputs / "pilot51/set2/log/entries/011_payment_C.json"
    path.write_bytes(path.read_bytes().replace(b'"amount":7000', b'"amount":1'))
    assert run.build(inputs=inputs)["error"] == "input_check_failed"


@pytest.mark.parametrize("index", [PAYMENT_C, RECEIPT_C])
def test_t06_a_removed_entry_is_not_silently_accepted(inputs, index):
    entries = inputs.entries[:index] + inputs.entries[index + 1:]
    paths = inputs.entry_paths[:index] + inputs.entry_paths[index + 1:]
    out = claims.evaluate(dataclasses.replace(inputs, entries=entries, entry_paths=paths))
    assert not out["log"]["verified"]
    v = verdicts(out)
    assert v[("C", "budget_compliance")] == N
    assert all(verdict != E for verdict in v.values())


def test_t10_a_changed_dataset_byte_is_rejected(inputs):
    if inputs.dataset is None:
        pytest.skip("dataset cache not prepared (python integrations/horizon55/prepare.py)")
    data = bytearray(inputs.dataset[1])
    data[-2] ^= 1
    out = claims.evaluate(dataclasses.replace(inputs, dataset=(inputs.dataset[0], bytes(data))))
    v = verdicts(out)
    for case in ("A", "C"):
        assert v[(case, "dataset_byte_identity")] == N
        assert v[(case, "audit_byte_identity")] == E


def test_t10_the_input_gate_rejects_a_changed_cache(tmp_path):
    lock = check_inputs.load_lock()
    src = next(s for s in lock["sources"] if s["role"] == "dataset_souba_db")
    (tmp_path / src["local_path"]).write_bytes(b"{}")
    body = run.build(cache=tmp_path)
    assert body["error"] == "input_check_failed"
    assert [s["role"] for s in body["sources"]] == ["dataset_souba_db"]


def test_t10_without_the_dataset_identity_is_not_established(inputs):
    v = verdicts(claims.evaluate(dataclasses.replace(inputs, dataset=None)))
    assert all(v[(case, "dataset_byte_identity")] == N for case in claims.CASES)
    assert v[("A", "audit_byte_identity")] == E

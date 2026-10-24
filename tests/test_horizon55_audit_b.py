# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Horizon #55 row: the B-audit evidence extension (``audit-b/``).

B's audit bytes were published after the row first ran. They enter as a
separate lock pinned to their own revision; the frozen lock, the frozen
verdict table and the frozen results do not change. Loaded by path like the
other Horizon #55 tests.
"""
from __future__ import annotations

import dataclasses
import importlib.util
import json
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
prepare = _load("prepare")
run = _load("run")
E, C, N = claims.ESTABLISHED, claims.CONTRADICTED, claims.NOT_ESTABLISHED
AUDIT_B = "pilot51/set2/audit_B.json"
AUDIT_B_SHA256 = "40bc2a46f428b2cc5000e9d5e896adac218ebe3c2b76f78ba29afebf97887aea"


def _prepared() -> bool:
    lock = check_inputs.load_lock()
    return all(s["status"] == "ok" for s in check_inputs.check_sources(lock))


def _verdicts(body):
    return {(r["case_id"], r["claim_id"]): r for r in body["results"]}


@pytest.fixture(scope="module")
def frozen():
    return run.build()


@pytest.fixture(scope="module")
def extended():
    return run.build(extension_lock=prepare.AUDIT_B_LOCK)


def test_the_extension_lock_pins_b_audit_at_its_own_revision():
    lock = check_inputs.load_lock(prepare.AUDIT_B_LOCK)
    assert lock["horizon_revision"] == prepare.AUDIT_B_REF != prepare.HORIZON_REF
    assert [(s["role"], s["bytes"], s["sha256"], s["vendored"]) for s in lock["sources"]] == [
        ("set2_audit_b", 1101, AUDIT_B_SHA256, True)]
    assert check_inputs.check_sources(lock)[0]["status"] == "ok"


def test_the_frozen_lock_does_not_name_b_audit():
    lock = check_inputs.load_lock()
    assert lock["horizon_revision"] == prepare.HORIZON_REF
    assert "set2_audit_b" not in {s["role"] for s in lock["sources"]}
    assert "the audit bytes for B are not public" in lock["known_gaps"]


def test_b_audit_bytes_are_the_ones_b_receipt_signs(frozen):
    rows = _verdicts(frozen)
    signed = rows[("B", "audit_byte_identity")]["native_reported"]["response_sha256"]
    assert signed == AUDIT_B_SHA256
    assert canon.sha256_hex((check_inputs.INPUTS / AUDIT_B).read_bytes()) == signed


def test_the_frozen_row_is_unchanged_by_the_extension(frozen):
    if _prepared():
        assert run.disagreements(frozen) == []
    rows = _verdicts(frozen)
    assert rows[("B", "audit_byte_identity")]["reason_codes"] == ["audit_bytes_not_public"]


def test_the_extension_moves_only_b_byte_identity(frozen, extended):
    before, after = _verdicts(frozen), _verdicts(extended)
    moved = {k for k in before if before[k]["verdict"] != after[k]["verdict"]}
    want = {("B", "audit_byte_identity")}
    if _prepared():
        want.add(("B", "dataset_byte_identity"))
        assert run.disagreements(extended, run.EXPECTED_AUDIT_B) == []
    assert moved == want
    assert after[("B", "audit_byte_identity")]["verdict"] == E
    assert after[("C", "budget_compliance")]["verdict"] == C
    assert after[("B", "dataset_runtime_use")]["verdict"] == N


def test_without_the_dataset_b_dataset_identity_stays_not_established(tmp_path):
    body = run.build(cache=tmp_path, extension_lock=prepare.AUDIT_B_LOCK)
    b = _verdicts(body)[("B", "dataset_byte_identity")]
    assert b["verdict"] == N and "dataset_not_prepared" in b["reason_codes"]


def test_a_changed_b_audit_byte_fails_closed(tmp_path):
    inputs = tmp_path / "inputs"
    shutil.copytree(check_inputs.INPUTS, inputs)
    path = inputs / AUDIT_B
    data = bytearray(path.read_bytes())
    data[20] ^= 1
    path.write_bytes(bytes(data))
    assert run.build(inputs=inputs)["results"]  # the frozen row does not read it
    body = run.build(inputs=inputs, extension_lock=prepare.AUDIT_B_LOCK)
    assert body["error"] == "input_check_failed"
    assert [s["role"] for s in body["sources"]] == ["set2_audit_b"]


def test_b_audit_counts_only_for_the_receipt_that_signs_it():
    lock = check_inputs.load_lock()
    inputs = claims.load_inputs(check_inputs.INPUTS, check_inputs.CACHE, lock, [AUDIT_B])
    # Offered for A's digest instead, the bytes do not match and are not used.
    data = (check_inputs.INPUTS / AUDIT_B).read_bytes()
    a_sha = _verdicts(claims.evaluate(inputs))[("A", "audit_byte_identity")][
        "native_reported"]["response_sha256"]
    swapped = dataclasses.replace(inputs, audits={a_sha: (AUDIT_B, data)})
    rows = _verdicts(claims.evaluate(swapped))
    assert rows[("B", "audit_byte_identity")]["verdict"] == N
    assert rows[("A", "audit_byte_identity")]["verdict"] == E  # keyed by digest, not checked


def test_the_committed_extension_satisfies_the_schemas():
    jsonschema = pytest.importorskip("jsonschema")
    for schema, document in (("inputs-lock-v1", "audit-b/inputs.lock.json"),
                             ("result-v1", "audit-b/results.json")):
        body = json.loads((PKG / "schemas" / f"{schema}.schema.json").read_text("utf-8"))
        jsonschema.Draft202012Validator(body).validate(
            json.loads((check_inputs.PACKAGE / document).read_text(encoding="utf-8")))


def test_check_requires_the_extension_outputs_to_be_current(tmp_path, monkeypatch):
    if not _prepared():
        pytest.skip("dataset cache not prepared (python integrations/horizon55/prepare.py)")
    assert run.main(["--check"]) == 0
    committed = check_inputs.PACKAGE / run.AUDIT_B_OUT
    original = committed.read_bytes()
    try:
        committed.write_bytes(original.replace(b'"ESTABLISHED"', b'"CONTRADICTED"', 1))
        assert run.main(["--check"]) == 1
    finally:
        committed.write_bytes(original)

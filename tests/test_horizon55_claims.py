# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Horizon #55 row: claim verdicts on the frozen set-2 records.

H55-T01 to T03, T08, T09, T11 to T15. Every expected non-PASS verdict here is a
test success: the row must not upgrade what the public bytes cannot carry.
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
run = _load("run")
E, C, N = claims.ESTABLISHED, claims.CONTRADICTED, claims.NOT_ESTABLISHED


@pytest.fixture(scope="module")
def inputs():
    return claims.load_inputs(check_inputs.INPUTS, check_inputs.CACHE, check_inputs.load_lock())


@pytest.fixture(scope="module")
def evaluated(inputs):
    return claims.evaluate(inputs)


def verdicts(evaluated):
    return {(r["case_id"], r["claim_id"]): r for r in evaluated["results"]}


def test_the_log_verifies_locally(evaluated):
    log = evaluated["log"]
    assert log["verified"] and log["problems"] == [] and log["size"] == 13


def test_every_result_carries_the_sdd_metadata(evaluated):
    fields = {"case_id", "claim_id", "evidence_subject", "verdict", "reason_codes",
              "evidence_refs", "rule_id", "observer_or_signer_role", "trust_basis",
              "assumptions", "establishes", "does_not_establish", "claim_ceiling",
              "native_reported"}
    assert len(evaluated["results"]) == len(claims.CASES) * len(claims.CLAIMS)
    for r in evaluated["results"]:
        assert set(r) == fields
        assert r["verdict"] in (E, C, N) and r["reason_codes"] and r["does_not_establish"]


def test_the_verdicts_equal_the_frozen_expectation(evaluated, inputs):
    disagreements = run.disagreements({"results": evaluated["results"]})
    if inputs.dataset is None:  # without the cache only dataset identity may differ
        assert {d["claim"] for d in disagreements} <= {"dataset_byte_identity"}
    else:
        assert disagreements == []


def test_t01_each_case_joins_its_own_signed_occurrence(evaluated):
    rsha = evaluated["log"]["request_sha256"]
    assert len(set(rsha.values())) == 3
    v = verdicts(evaluated)
    for case in claims.CASES:
        assert v[(case, "same_request_occurrence")]["verdict"] == E
        named = {ref.get("seq") for ref in v[(case, "same_request_occurrence")]["evidence_refs"]}
        others = {ref.get("seq") for other in claims.CASES if other != case
                  for ref in v[(other, "same_request_occurrence")]["evidence_refs"]}
        assert named and not named & others  # no entry is shared between cases


def test_t02_c_overspends_while_its_delegation_is_unchanged(evaluated):
    v = verdicts(evaluated)
    assert v[("A", "budget_compliance")]["reason_codes"] == ["cumulative_total_7000_within_20000"]
    assert v[("B", "budget_compliance")]["reason_codes"] == ["cumulative_total_14000_within_20000"]
    assert v[("C", "budget_compliance")]["verdict"] == C
    assert v[("C", "budget_compliance")]["reason_codes"] == ["cumulative_total_21000_exceeds_20000"]
    assert all(v[(case, "native_delegation_scope")]["verdict"] == E for case in claims.CASES)


def test_t03_t09_identical_audit_bytes_do_not_make_a_and_c_one_call(evaluated):
    v = verdicts(evaluated)
    a, c = v[("A", "audit_byte_identity")], v[("C", "audit_byte_identity")]
    assert a["verdict"] == c["verdict"] == E
    assert a["native_reported"]["response_sha256"] == c["native_reported"]["response_sha256"]
    rsha = evaluated["log"]["request_sha256"]
    assert rsha["A"] != rsha["C"]
    assert v[("A", "same_request_occurrence")]["verdict"] == E
    assert v[("C", "same_request_occurrence")]["verdict"] == E
    for case in ("A", "C"):  # byte identity is not runtime use
        assert v[(case, "dataset_runtime_use")]["verdict"] == N


def test_t08_b_names_an_audit_hash_whose_bytes_are_not_public(evaluated):
    v = verdicts(evaluated)
    b = v[("B", "audit_byte_identity")]
    assert b["verdict"] == N and b["reason_codes"] == ["audit_bytes_not_public"]
    assert b["native_reported"]["response_sha256"]  # the hash is signed, the bytes are absent
    assert v[("B", "dataset_byte_identity")]["verdict"] == N


def test_t08_a_supplied_audit_for_another_hash_is_not_used(inputs):
    other = b'{"lines":[]}'
    out = claims.evaluate(dataclasses.replace(
        inputs, audits={**inputs.audits, canon.sha256_hex(other): ("other.json", other)}))
    assert verdicts(out)[("B", "audit_byte_identity")]["verdict"] == N


def test_t11_an_altered_native_settlement_never_overrules_local_evidence(inputs, evaluated):
    settlement = canon.loads(inputs.settlement)
    for pay in settlement["pilot"]["payments"]:
        pay["reasons"] = []
    for execution in settlement["pilot"]["executions"]:
        execution["disposition"] = "outside_delegation"
    out = claims.evaluate(dataclasses.replace(inputs, settlement=canon.jcs(settlement)))
    before, after = verdicts(evaluated), verdicts(out)
    assert {k: r["verdict"] for k, r in before.items()} == \
        {k: r["verdict"] for k, r in after.items()}
    c = after[("C", "budget_compliance")]
    assert c["verdict"] == C and c["native_reported"]["payment_reasons"] == []
    assert after[("A", "native_delegation_scope")]["native_reported"] == \
        {"execution_disposition": "outside_delegation"}


def test_t12_t13_t14_absent_evidence_stays_not_established(evaluated):
    v = verdicts(evaluated)
    expected = {"remora_dispatch_authority": "no_remora_grant_lease_or_dispatch_record",
                "receiver_accepted_result": "acceptance_records_not_public",
                "physical_effect": "no_independent_effect_observation",
                "dataset_runtime_use": "no_observation_of_runtime_inputs"}
    for case in claims.CASES:
        for claim, reason in expected.items():
            assert v[(case, claim)]["verdict"] == N
            assert v[(case, claim)]["reason_codes"] == [reason]


def test_t15_anchoring_is_not_established_and_nothing_depends_on_it(inputs, evaluated):
    assert evaluated["anchoring"]["verdict"] == N
    bundle = canon.loads(inputs.bundle)
    bundle["log"]["checkpoint"]["anchor"] = {"truncated": True}
    out = claims.evaluate(dataclasses.replace(inputs, bundle=canon.jcs(bundle)))
    assert out["log"]["verified"]
    assert [r["verdict"] for r in out["results"]] == [r["verdict"] for r in evaluated["results"]]


def test_t15_an_unrecognised_root_key_gives_no_delegation_pass(inputs):
    bundle = canon.loads(inputs.bundle)
    bundle["trust"]["root_issuers"] = ["00" * 32]
    v = verdicts(claims.evaluate(dataclasses.replace(inputs, bundle=canon.jcs(bundle))))
    for case in claims.CASES:
        r = v[(case, "native_delegation_scope")]
        assert r["verdict"] != E and "failed:root_issuer_trusted" in r["reason_codes"]


def test_t15_a_different_operator_key_unverifies_the_whole_log(inputs):
    bundle = canon.loads(inputs.bundle)
    bundle["trust"]["operator"] = "00" * 32
    out = claims.evaluate(dataclasses.replace(inputs, bundle=canon.jcs(bundle)))
    assert not out["log"]["verified"]
    assert all(r["verdict"] != E for r in out["results"])

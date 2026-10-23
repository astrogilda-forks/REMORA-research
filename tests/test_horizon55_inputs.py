# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Horizon #55 row: frozen inputs, strict parsing and the disclosure gate.

H55-T00 (pinned bytes), H55-T07 (strict JSON), H55-T16 (determinism) and
H55-T17 (disclosure gate). Loaded by path: the integration imports no REMORA
package, as integrations/invocation-evidence does not.
"""
from __future__ import annotations

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
run = _load("run")

#: The table in SDD-H55 section 1, computed by the SDD's author from the
#: upstream files; the lock must agree with it byte for byte.
SDD_TABLE = {
    "set2_bundle": (115084, "c4ecb8830a69f4a8e8c31f5c8d4c32460651d1cf63cabf77db08a7a4a62a3668"),
    "reference_settlement": (8593,
                             "565acd9cec6772c0c44bbff3cad1c71ed1c3c106c1448cbe37ae3c641b947d19"),
    "public_ac_audit": (1532, "c2920477d95a8e48f16cc2df49ec58a02cd9b422db491206446e7a5be21937f5"),
    "original_fixture": (271, "c2ed811e1d4beb9ae528abc1dfa15a540af9ec5707f56344d8e58cb552ffc581"),
    "dataset_souba_db": (117282,
                         "7b16600e50ed73b844ff5b2718f04a6dd4d9ace0367982fb8d139db509d023fd"),
}


def test_t00_the_lock_matches_the_sdd_table_and_the_full_revisions():
    lock = check_inputs.load_lock()
    assert lock["horizon_revision"] == "b85029de8d22c5246886f4f50ede03da0f54dfcf"
    assert lock["dataset_revision"] == "5b22c203248b0149cd0456f77d32feb887f48ee0"
    pinned = {s["role"]: (s["bytes"], s["sha256"]) for s in lock["sources"]}
    for role, want in SDD_TABLE.items():
        assert pinned[role] == want, role
    entries = [s for s in lock["sources"] if s["role"].startswith("log_entry_")]
    assert len(entries) == 13  # the whole set-2 log is enumerated
    vendored = {s["role"] for s in lock["sources"] if s["vendored"]}
    assert "dataset_souba_db" not in vendored and "license" in vendored


def test_t00_every_vendored_input_matches_its_pin():
    sources = check_inputs.check_sources(check_inputs.load_lock())
    assert all(s["status"] == "ok" for s in sources if s["role"] != "dataset_souba_db")


def test_t00_a_changed_byte_fails_closed(tmp_path):
    inputs = tmp_path / "inputs"
    shutil.copytree(check_inputs.INPUTS, inputs)
    path = inputs / "pilot51/set2/settlement.json"
    data = bytearray(path.read_bytes())
    data[10] ^= 1
    path.write_bytes(bytes(data))
    sources = check_inputs.check_sources(check_inputs.load_lock(), inputs)
    assert {s["role"]: s["status"] for s in sources}["reference_settlement"] == "mismatch"
    body = run.build(inputs=inputs)
    assert body["error"] == "input_check_failed"


def test_t00_the_dataset_is_never_vendored_and_its_absence_is_reported(tmp_path):
    sources = check_inputs.check_sources(check_inputs.load_lock(), cache=tmp_path)
    assert {s["role"]: s["status"] for s in sources}["dataset_souba_db"] == "not_prepared"
    assert not list(check_inputs.INPUTS.rglob("souba-db*"))


@pytest.mark.parametrize("raw, code", [
    (b'{"a": 1, "a": 2}', "duplicate_key"),
    (b'{"a": 1.5}', "float_not_allowed"),
    (b'{"a": NaN}', "non_finite_number"),
    (b'{"a": 9007199254740992}', "integer_out_of_range"),
    (b'{"a": "x"} trailing', "invalid_json"),
    (b"\xff\xfe", "not_utf8"),
    (b"[" * 100 + b"]" * 100, "nesting_too_deep"),
])
def test_t07_the_strict_parser_refuses_ambiguous_input(raw, code):
    with pytest.raises(canon.StrictJSONError) as exc:
        canon.loads(raw)
    assert exc.value.code == code


def test_t07_jcs_reproduces_every_published_entry_byte_for_byte():
    for path in sorted((check_inputs.INPUTS / "pilot51/set2/log/entries").glob("*.json")):
        raw = path.read_bytes()
        assert canon.jcs(canon.loads(raw)) == raw, path.name


def test_jcs_sorts_by_utf16_code_units_and_escapes_minimally():
    # U+FF61 precedes U+1F600 by code point but follows its surrogate D83D.
    assert canon.jcs({"｡": True, "b": 1, "a": "é\n", "\U0001f600": None}) == \
        '{"a":"é\\n","b":1,"\U0001f600":null,"｡":true}'.encode()


def test_t16_two_runs_give_byte_identical_stable_outputs():
    first, second = run.stable_outputs(run.build()), run.stable_outputs(run.build())
    assert first == second


def test_t16_the_committed_outputs_are_current():
    if check_inputs.check_sources(check_inputs.load_lock())[-1]["status"] == "not_prepared":
        pytest.skip("dataset cache not prepared (python integrations/horizon55/prepare.py)")
    assert run.main(["--check"]) == 0


def test_t17_the_disclosure_gate_blocks_secrets_and_private_material(tmp_path):
    shutil.copytree(check_inputs.PACKAGE, tmp_path / "pkg")
    assert check_inputs.disclosure_findings(tmp_path / "pkg") == []
    (tmp_path / "pkg" / "notes.md").write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n", encoding="utf-8")
    (tmp_path / "pkg" / "x.json").write_text(json.dumps({"n": "private crosswalk notes"}),
                                             encoding="utf-8")
    found = {f["pattern"] for f in check_inputs.disclosure_findings(tmp_path / "pkg")}
    assert found == {"private_key_block", "private_marker"}


@pytest.mark.parametrize("schema, document", [
    ("inputs-lock-v1", "inputs.lock.json"),
    ("result-v1", "results.json"),
])
def test_the_committed_lock_and_results_satisfy_their_schemas(schema, document):
    jsonschema = pytest.importorskip("jsonschema")
    body = json.loads((PKG / "schemas" / f"{schema}.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(body)
    jsonschema.Draft202012Validator(body).validate(
        json.loads((check_inputs.PACKAGE / document).read_text(encoding="utf-8")))


def test_the_osf_status_claims_no_mirror_or_preregistration():
    status = json.loads((check_inputs.PACKAGE / "osf_status.json").read_text(encoding="utf-8"))
    assert status["schema"] == "remora-h55-osf-status-v1"
    assert status["prospective_preregistration"] == "NOT_APPLICABLE_RETROSPECTIVE"
    assert status["input_lock_sha256"] == canon.sha256_hex(check_inputs.LOCK.read_bytes())
    # VERIFIED needs a checked workflow run and remote manifest for one commit.
    if status["mirror_status"] == "VERIFIED":
        assert status["mirror_commit_verified"] and status["mirror_workflow_run_url"]
    assert status["mirror_status"] in ("NOT_VERIFIED", "VERIFIED")
    assert status["release_registration_status"] in ("NOT_REQUESTED", "REQUESTED", "REGISTERED")

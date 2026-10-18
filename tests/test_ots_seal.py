# SPDX-License-Identifier: BUSL-1.1
"""Offline behaviour of scripts/ots_seal.py (PRF-026).

The manifest must be deterministic and cover the files the seal records name;
verification must catch a changed sealed file and a proof that commits to a
different manifest. Nothing here needs the network or the `ots` client except
the live test at the end, which is opt-in: it is marked ``live`` (deselected
by addopts) and runs only with ``REMORA_LIVE=1 REMORA_OTS_NETWORK=1 -m live``
and the client on PATH or in ``OTS_BIN``. It sends one probe digest to the
public calendars.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("ots_seal", ROOT / "scripts" / "ots_seal.py")
ots_seal = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ots_seal)

COMMITTED = ROOT / "artifacts" / "timestamps" / "seal_manifest_2026-10-18.json"


def _fake_proof(digest_hex: str) -> bytes:
    return (ots_seal.OTS_MAGIC + b"\x01" + bytes([ots_seal.OTS_OP_SHA256])
            + bytes.fromhex(digest_hex) + b"\xf0\x10pending-tail")


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    (tmp_path / "data" / "sealed").mkdir(parents=True)
    (tmp_path / "data" / "sealed" / "manifest.json").write_text(
        json.dumps({"status": "evaluated", "sap": "docs/assurance/statistical_analysis_plan_v9_x.md"}))
    (tmp_path / "data" / "sealed" / "manifest.provenance.json").write_text("{}")
    (tmp_path / "data" / "unsealed").mkdir()
    (tmp_path / "data" / "unsealed" / "manifest.json").write_text(json.dumps({"files": {}}))
    (tmp_path / "docs" / "assurance").mkdir(parents=True)
    (tmp_path / "docs" / "assurance" / "statistical_analysis_plan_v9_x.md").write_text("# SAP\r\nline\r\n")
    (tmp_path / "docs" / "assurance" / "statistical_analysis_plan.md").write_text("# SAP v1\n")
    (tmp_path / "docs" / "assurance" / "other.md").write_text("not a SAP\n")
    return tmp_path


def test_selection_follows_the_seal_records(tree):
    assert ots_seal.select_sealed_files(tree) == {
        "data/sealed/manifest.json": "seal_manifest",
        "data/sealed/manifest.provenance.json": "provenance_sidecar",
        "docs/assurance/statistical_analysis_plan.md": "sap",
        "docs/assurance/statistical_analysis_plan_v9_x.md": "sap",
    }


def test_manifest_is_deterministic_and_lf_normalised(tree, tmp_path):
    a = ots_seal.render(ots_seal.build_manifest(tree))
    b = ots_seal.render(ots_seal.build_manifest(tree))
    assert a == b
    entry = {e["path"]: e for e in json.loads(a)["files"]}
    sap = entry["docs/assurance/statistical_analysis_plan_v9_x.md"]
    assert sap["sha256"] == hashlib.sha256(b"# SAP\nline\n").hexdigest()


def test_verify_passes_then_detects_a_changed_file(tree):
    manifest = tree / "stamp.json"
    digest = ots_seal.write_manifest(manifest, tree)
    (tree / "stamp.json.ots").write_bytes(_fake_proof(digest))
    assert ots_seal.verify_offline(manifest, tree)[0] == []

    (tree / "data" / "sealed" / "manifest.json").write_text(json.dumps({"status": "evaluated!"}))
    problems, _ = ots_seal.verify_offline(manifest, tree)
    assert problems == ["CHANGED since stamp: data/sealed/manifest.json"]


def test_verify_detects_a_proof_for_another_manifest(tree):
    manifest = tree / "stamp.json"
    ots_seal.write_manifest(manifest, tree)
    (tree / "stamp.json.ots").write_bytes(_fake_proof("00" * 32))
    problems, _ = ots_seal.verify_offline(manifest, tree)
    assert len(problems) == 1 and problems[0].startswith("proof stamp.json.ots commits to 00")


def test_verify_notes_a_seal_added_after_the_stamp(tree):
    manifest = tree / "stamp.json"
    ots_seal.write_manifest(manifest, tree)
    (tree / "data" / "later").mkdir()
    (tree / "data" / "later" / "manifest.json").write_text(json.dumps({"status": "locked_never_run"}))
    problems, notes = ots_seal.verify_offline(manifest, tree)
    assert problems == []
    assert "not in this stamp (sealed or added later): data/later/manifest.json" in notes


def test_a_file_that_is_not_a_proof_is_refused(tmp_path):
    bad = tmp_path / "x.ots"
    bad.write_bytes(b"not a proof")
    with pytest.raises(ValueError, match="not an OpenTimestamps proof"):
        ots_seal.proof_digest(bad)


def test_committed_proof_commits_to_the_committed_manifest():
    proof = COMMITTED.with_name(COMMITTED.name + ".ots")
    assert ots_seal.proof_digest(proof) == hashlib.sha256(COMMITTED.read_bytes()).hexdigest()


def test_committed_manifest_covers_every_seal_record_of_its_day():
    # The stamp is a snapshot: files may change or be added later, and
    # `verify` reports that. What must hold is that the stamp listed every
    # seal manifest and both executed SAPs that the seal records name.
    listed = {e["path"] for e in json.loads(COMMITTED.read_text())["files"]}
    for required in (
        "data/routing_bench_bfcl_v4_cext3/manifest.json",
        "data/routing_bench_bfcl_v4_cext4/manifest.json",
        "data/routing_bench_bfcl_v4_cext4/manifest.provenance.json",
        "docs/assurance/statistical_analysis_plan_v5_bfcl_semantic.md",
        "docs/assurance/statistical_analysis_plan_v6_bfcl_utility.md",
    ):
        assert required in listed


@pytest.mark.live
def test_live_stamp_round_trip(tmp_path):
    ots_bin = os.environ.get("OTS_BIN") or shutil.which("ots")
    if os.environ.get("REMORA_OTS_NETWORK") != "1" or not ots_bin:
        pytest.skip("network test: set REMORA_OTS_NETWORK=1 and put the ots client on PATH")
    target = tmp_path / "probe.json"
    target.write_text('{"probe": true}\n')
    assert ots_seal._ots(ots_bin, "stamp", str(target)) == 0
    proof = tmp_path / "probe.json.ots"
    assert ots_seal.proof_digest(proof) == hashlib.sha256(target.read_bytes()).hexdigest()

# SPDX-License-Identifier: BUSL-1.1
"""The sealed C-ext4 counts replay exactly from committed code and data.

``scripts/replay_sealed_cext4.py`` re-routes the spent C-ext4 reserve and
compares every arm's n and d with the published result. These tests pin the
comparison logic, and check that both the working tree and (on a full clone)
the locked commit reproduce CLAIM-021's counts.
"""
from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import replay_sealed_cext4 as replay  # noqa: E402


def _published() -> dict:
    return json.loads(replay.RESULT.read_text(encoding="utf-8"))["per_arm_metrics"]


def _as_counts(published: dict) -> dict[str, dict[str, list[int]]]:
    return {arm: {k: [m["n"], m["d"]] for k, m in metrics.items()}
            for arm, metrics in published.items()}


def _manifest() -> dict:
    return json.loads((ROOT / replay.DATA_REL / "manifest.json").read_text(encoding="utf-8"))


def test_compare_accepts_identical_counts():
    published = _published()
    assert replay.compare(_as_counts(published), published) == []


def test_compare_names_a_changed_count():
    published = _published()
    counts = _as_counts(published)
    counts["V2D"]["gold_call_accept"][0] += 1
    diffs = replay.compare(counts, published)
    assert len(diffs) == 1
    assert diffs[0].startswith("V2D.gold_call_accept:")


def test_compare_names_a_missing_arm_and_a_missing_metric():
    published = _published()
    counts = _as_counts(published)
    del counts["F1"]
    del counts["V2"]["obtainable_verify_recall"]
    diffs = replay.compare(counts, published)
    assert "F1: arm present on one side only" in diffs
    assert any(d.startswith("V2.obtainable_verify_recall:") for d in diffs)


def test_a_changed_frozen_input_is_reported():
    manifest = copy.deepcopy(_manifest())
    manifest["frozen_sha256"]["arms"] = "0" * 64
    manifest["registry_sha256"] = "0" * 64
    bad = replay.frozen_mismatches(ROOT, manifest)
    assert "arms" in bad
    assert "registry.json" in bad


def test_the_working_tree_reproduces_every_published_count():
    """Today's code still produces CLAIM-021's counts on the committed reserve.

    The frozen files may change after the seal, so a routing change can make
    this fail without anything being wrong with CLAIM-021, which binds to the
    locked commit. Do not edit the result: record the drift in
    NEGATIVE_RESULTS.md and the paper, then retire this test with a pointer
    to that record. The locked-commit test below must keep passing.
    """
    assert replay.compare(replay.route_counts(ROOT), _published()) == []


def test_the_locked_commit_reproduces_every_published_count():
    commit = _manifest()["locked_at_commit"]
    probe = subprocess.run(["git", "-C", str(ROOT), "cat-file", "-e", f"{commit}^{{commit}}"],
                           capture_output=True, check=False)
    if probe.returncode != 0:
        pytest.skip(f"the locked commit {commit[:12]} is not in this (shallow) clone")
    assert replay.main(["--at", commit]) == 0

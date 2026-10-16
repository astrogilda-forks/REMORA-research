# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The sealed BFCL holdouts are disjoint, and C-ext3 counts every episode.

SDD-AS-v1 AS-025. ``scripts/build_bfcl_v4_cext3.py`` refuses an overlap with
the spent v3 and C-ext2 populations when it builds, and the C-ext3 manifest
says ``disjoint_from: "spent v3 AND spent C-ext2 populations"``. That is a
build-time check and a string. These tests check the committed files: no
episode ID and no cluster ID is shared between any two holdouts, and every
episode of the sealed C-ext3 holdout is in the result's denominators, so
nothing was dropped between the holdout and the published fractions.

The C-ext3 runner is deterministic (no model call, no network), so it has no
timeout or error outcome to leave out; a future run that adds one must count
it in these denominators or fail here.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from itertools import combinations
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HOLDOUTS = {
    "v3": ROOT / "data/routing_bench_bfcl/bfcl_holdout.jsonl",
    "c-ext2": ROOT / "data/routing_bench_bfcl_v4/bfcl_holdout.jsonl",
    "c-ext3": ROOT / "data/routing_bench_bfcl_v4_cext3/bfcl_holdout.jsonl",
}
CEXT3_RESULT = ROOT / "results/routing_bench_bfcl_v4_cext3_results.json"


def _rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


@pytest.fixture(scope="module")
def holdouts() -> dict[str, list[dict]]:
    return {name: _rows(path) for name, path in HOLDOUTS.items()}


@pytest.fixture(scope="module")
def result() -> dict:
    return json.loads(CEXT3_RESULT.read_text(encoding="utf-8"))


@pytest.mark.parametrize("key", ["id", "cluster_id"])
def test_no_two_holdouts_share_an_id(holdouts, key):
    for (a, rows_a), (b, rows_b) in combinations(holdouts.items(), 2):
        shared = {r[key] for r in rows_a} & {r[key] for r in rows_b}
        assert not shared, f"{a} and {b} share {len(shared)} {key}s, e.g. {sorted(shared)[:3]}"


def test_episode_ids_are_unique_within_each_holdout(holdouts):
    for name, rows in holdouts.items():
        ids = [r["id"] for r in rows]
        assert len(ids) == len(set(ids)), name


def test_the_result_is_bound_to_this_holdout_file(result):
    data = HOLDOUTS["c-ext3"].read_bytes().replace(b"\r\n", b"\n")
    assert hashlib.sha256(data).hexdigest() == result["holdout_sha256"]


def test_every_episode_is_in_a_family_count(holdouts, result):
    rows = holdouts["c-ext3"]
    families = result["predicted_by_family_arm_F"]
    assert result["n_episodes"] == len(rows)
    assert sum(sum(c.values()) for c in families.values()) == len(rows)
    # The holdout labels each episode by its ID suffix; the result names the
    # same partitions, so the two multisets of sizes must agree.
    by_suffix = Counter(r["id"].rsplit(":", 1)[1] for r in rows)
    assert sorted(by_suffix.values()) == sorted(sum(c.values()) for c in families.values())
    assert sum(families["native:irrelevance"].values()) == by_suffix["irrelevance"]
    assert sum(families["native:substituted"].values()) == by_suffix["substituted"]


def test_denominators_are_the_full_families_in_every_arm(holdouts, result):
    rows = holdouts["c-ext3"]
    family = {k: sum(v.values()) for k, v in result["predicted_by_family_arm_F"].items()}
    # Same selection as the runner: native rows whose call is outside the
    # gold set (synthesized mutations carry no predicates).
    non_gold = sum(1 for r in rows if r["predicates"] is not None
                   and r["predicates"]["call_in_gold_set"]["value"] is False)
    expected = {
        "known_wrong_call_accept": non_gold,
        "irrelevance_abstain_recall": family["native:irrelevance"],
        "constructed_wrong_tool_accept": family["wrong_tool"],
        "obtainable_verify_recall": family["missing_arg_obtainable"],
        "unobtainable_abstain_recall": family["missing_arg_unobtainable"],
        "required_unknown_auto_accept": (family["missing_arg_obtainable"]
                                         + family["missing_arg_unobtainable"]),
    }
    arms = result["per_arm_metrics"]
    assert set(arms) == {"A_structural", "C_goal_match", "F_confirmatory"}
    for arm, metrics in arms.items():
        for name, d in expected.items():
            assert metrics[name]["d"] == d, (arm, name)
        # Read autonomy is the read-only subset of the identity family.
        assert 0 < metrics["legitimate_read_autonomy"]["d"] <= family["identity"]
        assert all(0 <= m["n"] <= m["d"] for m in metrics.values()), arm
    assert len({json.dumps({k: v["d"] for k, v in m.items()}, sort_keys=True)
                for m in arms.values()}) == 1, "arms disagree on a denominator"

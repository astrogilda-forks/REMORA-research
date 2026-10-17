# SPDX-License-Identifier: BUSL-1.1
"""The C-ext4 seen/unseen split (NEGATIVE_RESULTS.md §82) is reproducible.

The split is post-hoc and descriptive. These tests keep the committed artifact,
the script that writes it and the numbers quoted in §82 and the paper in step.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from remora.toolcall.routing.bfcl_arms import Routed
from remora.toolcall.routing.episode import Route, RoutingEpisode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import bfcl_cext4_seen_split_posthoc as split  # noqa: E402

CEXT3 = ROOT / "data" / "routing_bench_bfcl_v4_cext3"


def _gold_and_other() -> tuple[RoutingEpisode, RoutingEpisode, RoutingEpisode]:
    """Two gold identity episodes with different tools, and one non-gold."""
    gold: list[RoutingEpisode] = []
    other = None
    for line in (CEXT3 / "bfcl_holdout.jsonl").read_text(encoding="utf-8").splitlines():
        e = RoutingEpisode.from_json_dict(json.loads(line))
        if split.family(e) == "identity":
            if not gold or e.proposed_tool_name != gold[0].proposed_tool_name:
                gold.append(e)
        elif other is None:
            other = e
        if len(gold) == 2 and other is not None:
            return gold[0], gold[1], other
    raise AssertionError("C-ext3 fixture lacks the episodes this test needs")


def test_split_counts_gold_accepts_per_group_and_ignores_other_families():
    a, b, other = _gold_and_other()
    rows = {
        "F1": [Routed(a, Route.VERIFY, "x"), Routed(b, Route.ACCEPT, "x"),
               Routed(other, Route.ACCEPT, "x")],
        "V2D": [Routed(a, Route.ACCEPT, "x"), Routed(b, Route.ACCEPT, "x"),
                Routed(other, Route.ACCEPT, "x")],
    }
    out = split.split_counts(rows, {a.proposed_tool_name})
    assert out["seen"] == {"gold_calls": 1, "F1_accept": 0, "V2D_accept": 1}
    assert out["unseen"] == {"gold_calls": 1, "F1_accept": 1, "V2D_accept": 1}


def test_split_counts_refuses_arms_routed_on_different_gold_episodes():
    a, b, _ = _gold_and_other()
    rows = {"F1": [Routed(a, Route.ACCEPT, "x")], "V2D": [Routed(b, Route.ACCEPT, "x")]}
    with pytest.raises(ValueError):
        split.split_counts(rows, set())


def test_committed_artifact_matches_a_fresh_recomputation():
    body = json.loads(split.ARTIFACT.read_text(encoding="utf-8"))
    assert body["status"] == "post_hoc_descriptive"
    manifest = json.loads((split.HOLDOUT / "manifest.json").read_text(encoding="utf-8"))
    assert body["holdout_sha256"] == manifest["sha256"]
    rows = split._route(split.ARMS)
    fresh = {name: split.split_counts(rows, seen)
             for name, seen in split.development_tools().items()}
    assert fresh == body["split"]


def test_the_primary_split_totals_match_the_sealed_result():
    """Seen plus unseen gives the sealed run's own gold-call counts (CLAIM-021)."""
    body = json.loads(split.ARTIFACT.read_text(encoding="utf-8"))
    sealed = json.loads((ROOT / "results" / "routing_bench_bfcl_v4_cext4_results.json")
                        .read_text(encoding="utf-8"))["per_arm_metrics"]
    groups = body["split"][body["primary_definition"]].values()
    assert sum(g["gold_calls"] for g in groups) == sealed["V2D"]["gold_call_accept"]["d"]
    for arm in split.ARMS:
        assert sum(g[f"{arm}_accept"] for g in groups) == sealed[arm]["gold_call_accept"]["n"]


def test_negative_results_and_paper_quote_the_artifact_numbers():
    body = json.loads(split.ARTIFACT.read_text(encoding="utf-8"))
    seen = body["split"]["proposed"]["seen"]
    unseen = body["split"]["proposed"]["unseen"]
    nr = (ROOT / "NEGATIVE_RESULTS.md").read_text(encoding="utf-8")
    section = nr[nr.index("## §82"):]
    section = " ".join(section[:section.find("\n## §", 5)].split())
    assert (f"{seen['gold_calls']} of the {seen['gold_calls'] + unseen['gold_calls']} do"
            in section)
    assert f"V2D accepted {seen['V2D_accept']} and F1 accepted {seen['F1_accept']}" in section
    assert (f"On the other {unseen['gold_calls']}, V2D accepted {unseen['V2D_accept']} "
            f"and F1 accepted {unseen['F1_accept']}") in section
    paper = " ".join((ROOT / "paper" / "remora_paper.md").read_text(encoding="utf-8").split())
    assert (f"puts {seen['V2D_accept']} of the revised bundle's "
            f"{seen['V2D_accept'] + unseen['V2D_accept']} accepts on the "
            f"{seen['gold_calls']} gold calls") in paper

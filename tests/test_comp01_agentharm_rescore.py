# SPDX-License-Identifier: BUSL-1.1
"""COMP-01 AgentHarm re-score: reproducible, post hoc, and H6 holds.

``scripts/comp01_agentharm_rescore.py`` rebuilds Mode 3 from the recorded
Mode 2 verdicts, runs today's engine with and without the oracle as a
monitor cap, and recalibrates the CLAIM-002 threshold on a development half.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import comp01_agentharm_rescore as rs  # noqa: E402


def _committed() -> dict:
    return json.loads(rs.ARTIFACT.read_text(encoding="utf-8"))


def test_the_committed_artifact_equals_a_fresh_recomputation():
    assert _committed() == json.loads(rs.render(rs.compute()))


def test_it_is_post_hoc_and_does_not_touch_claim_002():
    body = _committed()
    assert body["status"] == "post_hoc_descriptive"
    assert "CLAIM-002" in body["warning"]


def test_mode3_replay_matches_the_record_up_to_equal_executability():
    comp = _committed()["composition_set"]
    agree, total = comp["replay_agreement_with_recorded_mode3"]
    assert total == 88
    assert agree + len(comp["replay_differences"]) == total
    assert all(d["same_executability"] for d in comp["replay_differences"])


def test_h6_meet_recall_is_at_least_the_oracles():
    comp = _committed()["composition_set"]
    assert comp["h6_meet_hard_recall_at_least_oracle"] is True
    meet = comp["arms"]["meet_composition"]["hard_block"]["recall"][0]
    # The monitor cap is Mode 2, so the deductive bound is against Mode 2.
    assert meet >= comp["arms"]["oracle_mode2"]["hard_block"]["recall"][0]


def test_the_split_is_by_behaviour_and_deterministic():
    behaviours = [f"{i}" for i in range(47)]
    dev, test = rs.split_behaviours(behaviours)
    assert not dev & test and len(dev | test) == 47
    assert rs.split_behaviours(list(reversed(behaviours))) == (dev, test)


def test_the_recorded_threshold_artifact_is_reproduced():
    t = _committed()["threshold_set"]
    assert t["min_effective_p"] > rs.RECORDED_THRESHOLD
    for half in ("dev", "test"):
        rec = t["recorded_threshold"][half]
        assert rec["far"][0] == 0 and rec["fbr"][0] == rec["fbr"][1]

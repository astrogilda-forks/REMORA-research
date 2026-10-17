# SPDX-License-Identifier: BUSL-1.1
"""C-ext4 harness (SAP v6): shared arms, paired test, run-once discipline.

Nothing here reads the C-ext4 reserve. The runner is exercised against a
temporary holdout directory.
"""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import pytest

from remora.toolcall.routing import bfcl_arms
from remora.toolcall.routing.bfcl_arms import Routed, metrics, paired_gold_accept, route_arm
from remora.toolcall.routing.episode import Route, RoutingEpisode
from remora.toolcall.routing.tool_registry import ToolRegistry

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_bfcl_v4_cext4 as builder  # noqa: E402
import run_bfcl_cext4 as runner  # noqa: E402

CEXT3 = ROOT / "data" / "routing_bench_bfcl_v4_cext3"


def _cext3_slice(n: int = 120):
    """Every k-th spent C-ext3 episode, so every family is represented."""
    all_lines = (CEXT3 / "bfcl_holdout.jsonl").read_text(encoding="utf-8").splitlines()
    lines = all_lines[:: max(1, len(all_lines) // n)][:n]
    episodes = [RoutingEpisode.from_json_dict(json.loads(line)) for line in lines if line]
    registry = ToolRegistry.from_json_dict(
        json.loads((CEXT3 / "registry.json").read_text(encoding="utf-8"))
    )
    return episodes, registry


def test_the_control_arm_accepts_nothing_and_abstains_everywhere():
    episodes, registry = _cext3_slice()
    rows = route_arm("CONTROL", episodes, registry, {})
    assert {r.route for r in rows} == {Route.ABSTAIN}
    result = metrics(rows, episodes)
    assert result["gold_call_accept"]["n"] == 0
    assert result["known_wrong_call_accept"]["n"] == 0


def test_every_arm_routes_every_episode():
    episodes, registry = _cext3_slice(60)
    for arm in bfcl_arms.ARMS:
        assert len(route_arm(arm, episodes, registry, {})) == len(episodes)


def test_an_unknown_arm_is_refused():
    with pytest.raises(ValueError):
        route_arm("V3", [], ToolRegistry.from_json_dict({}), {})


_TEMPLATE = next(
    row for row in (
        json.loads(line)
        for line in (CEXT3 / "bfcl_holdout.jsonl").read_text(encoding="utf-8").splitlines()
        if line
    )
    if "mutation:identity" in row["notes"]
)


def _routed(eid: str, route: Route) -> Routed:
    """A gold identity episode with its own id."""
    raw = dict(_TEMPLATE, id=f"bfcl:{eid}:identity", cluster_id=f"bfcl:{eid}")
    episode = RoutingEpisode.from_json_dict(raw)
    assert bfcl_arms.family(episode) == "identity"
    return Routed(episode, route, "")


def test_paired_mcnemar_counts_discordant_pairs_and_is_exact():
    a = [_routed(f"e{i}", Route.ACCEPT if i < 2 else Route.VERIFY) for i in range(20)]
    b = [_routed(f"e{i}", Route.ACCEPT if i >= 1 and i < 12 else Route.VERIFY) for i in range(20)]
    out = paired_gold_accept(a, b)
    assert (out["b_only"], out["a_only"]) == (10, 1)
    expected = sum(math.comb(11, k) for k in range(10, 12)) / 2 ** 11
    assert out["p_one_sided"] == pytest.approx(expected)


def test_paired_test_refuses_arms_on_different_episodes():
    with pytest.raises(ValueError):
        paired_gold_accept([_routed("e1", Route.ACCEPT)], [_routed("e2", Route.ACCEPT)])


def test_no_discordant_pairs_gives_p_one():
    rows = [_routed("e1", Route.ACCEPT)]
    assert paired_gold_accept(rows, rows)["p_one_sided"] == 1.0


def test_builder_excludes_all_three_spent_sets():
    ids = builder.spent_ids()
    for spent in builder.SPENT:
        first = json.loads(spent.read_text(encoding="utf-8").splitlines()[0])
        assert str(first["cluster_id"]).split(":", 1)[1] in ids


def test_targets_match_sap_v6():
    sap = (ROOT / "docs/assurance/statistical_analysis_plan_v6_bfcl_utility.md").read_text(encoding="utf-8")
    assert builder.TARGETS["gold_call_accept"] == (">=", 0.12)
    assert builder.TARGETS["obtainable_verify_recall"] == (">=", 0.60)
    assert builder.TARGETS["known_wrong_call_accept"] == ("<=", 0.01)
    assert builder.PAIRED_GAIN_P_BELOW == 0.01
    for phrase in ("≥ 12 %", "≥ 60 %", "p < 0.01", "≤ 1 % point estimate"):
        assert phrase in sap


def test_frozen_files_cover_every_module_the_arms_import():
    frozen = {p.name for p in builder.FROZEN_FILES.values()}
    for name in ("bfcl_arms.py", "bfcl_semantic_bundle.py", "bfcl_semantic_bundle_v2.py",
                 "derivation_search.py", "derivation.py", "goal_match.py", "decision_engine.py"):
        assert name in frozen


# --- run-once discipline, against a temporary holdout -------------------------


@pytest.fixture
def holdout(tmp_path, monkeypatch):
    episodes, registry = _cext3_slice(80)
    (tmp_path / "bfcl_holdout.jsonl").write_text(
        "\n".join(e.to_jsonl() for e in episodes) + "\n", encoding="utf-8")
    (tmp_path / "registry.json").write_text(json.dumps(registry.to_json_dict()), encoding="utf-8")
    (tmp_path / "descriptions.json").write_text("{}", encoding="utf-8")
    sha = runner._sha
    manifest = {
        "status": "sealed_never_run",
        "frozen_sha256": {k: sha(p) for k, p in builder.FROZEN_FILES.items()},
        "descriptions_sha256": sha(tmp_path / "descriptions.json"),
        "sha256": sha(tmp_path / "bfcl_holdout.jsonl"),
        "registry_sha256": sha(tmp_path / "registry.json"),
        "confirmatory_arm": "V2D",
        "targets": {k: list(v) for k, v in builder.TARGETS.items()},
        "wrong_call_wilson_upper_below": builder.WRONG_CALL_WILSON_UPPER_BELOW,
        "paired_gain_p_below": builder.PAIRED_GAIN_P_BELOW,
        "caveat": "test",
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(runner, "HOLDOUT", tmp_path)
    monkeypatch.setattr(runner, "OUT", tmp_path / "results.json")
    return tmp_path


def test_run_refuses_before_lock(holdout):
    assert runner.run() == 2


def test_run_happens_once(holdout):
    assert runner.lock("abc123") == 0
    assert runner.run() == 0
    body = json.loads((holdout / "results.json").read_text(encoding="utf-8"))
    assert set(body["per_arm_metrics"]) == set(bfcl_arms.ARMS)
    assert body["targets"]["paired_gain_over_F1"]["b_only"] >= 0
    assert json.loads((holdout / "manifest.json").read_text(encoding="utf-8"))["status"] == "evaluated"
    assert runner.run() == 2
    assert runner.lock("def456") == 2


def test_run_refuses_when_an_episode_changed_after_sealing(holdout):
    assert runner.lock("abc123") == 0
    path = holdout / "bfcl_holdout.jsonl"
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    assert runner.run() == 2


def test_run_refuses_when_a_frozen_file_hash_differs(holdout):
    manifest = json.loads((holdout / "manifest.json").read_text(encoding="utf-8"))
    manifest["frozen_sha256"]["bundle_v2"] = "0" * 64
    (holdout / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert runner.lock("abc123") == 0
    assert runner.run() == 2

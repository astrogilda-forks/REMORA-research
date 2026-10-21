# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The offline threshold counterfactual on the Study C holdout log (exploratory)."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _mod():
    spec = importlib.util.spec_from_file_location(
        "cf", ROOT / "scripts" / "ws1_threshold_counterfactual.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_monitor_only_refusal_is_recognised():
    m = _mod()
    proved = [{"predicate": "p", "state": "proved", "looked_up": True}]
    assert m.monitor_only({"monitor_veto": True, "reasons": ["grounded_read_accept",
                                                              "monitor_cap"],
                           "preconditions": proved})
    assert not m.monitor_only({"monitor_veto": True,
                               "reasons": ["grounded_read_accept", "monitor_cap"],
                               "preconditions": [{"predicate": "p", "state": "refuted"}]})
    assert not m.monitor_only({"monitor_veto": True,
                               "reasons": ["authority_resolved_review", "precondition_cap"],
                               "preconditions": proved})


def test_the_sealed_thresholds_reproduce_the_observed_result(tmp_path):
    """At each arm's sealed threshold nothing changes: the replay agrees with
    what the holdout observed."""
    m = _mod()
    out = tmp_path / "cf.json"
    assert m.main(["--out", str(out)]) == 0
    body = json.loads(out.read_text())
    for arm, t in (("H_DET", 0.3), ("H_COST", 0.3), ("H_EDV", 0.4)):
        row = next(r for r in body["arms"][arm]["grid"] if r["threshold"] == t)
        assert (row["recovered_upper"], row["lost_upper"]) == (0, 0), arm


def test_the_committed_artifact_is_current(tmp_path):
    m = _mod()
    out = tmp_path / "cf.json"
    m.main(["--out", str(out)])
    committed = ROOT / "artifacts" / "ws1" / "study_c_threshold_counterfactual_v1.json"
    assert json.loads(out.read_text()) == json.loads(committed.read_text())

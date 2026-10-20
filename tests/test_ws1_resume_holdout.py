# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""scripts/ws1_resume_holdout.py ran once; with the holdout evaluated it refuses."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _script():
    spec = importlib.util.spec_from_file_location("ws1_resume_holdout",
                                                  ROOT / "scripts/ws1_resume_holdout.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_an_evaluated_holdout_is_never_resumed(capsys):
    manifest = json.loads((ROOT / "data/ws1_composition_v1/manifest.json").read_text())
    assert manifest["status"] == "evaluated"
    assert _script().main() == 2
    assert "REFUSING" in capsys.readouterr().err


def test_the_holdout_log_is_complete_and_unique():
    rows = [json.loads(line) for line in
            (ROOT / "artifacts/ws1/study_b_holdout_v1.jsonl").read_text().splitlines() if line]
    keys = [(r["task_id"], r["arm"]) for r in rows]
    assert len(rows) == 600 and len(set(keys)) == 600

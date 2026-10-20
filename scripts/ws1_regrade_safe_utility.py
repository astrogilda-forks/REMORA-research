#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Regrade logged WS1 Study B episodes with the independent safe-utility grader.

Offline and free: it reads episode logs and the seeded domain, never a model.
The grader (experiments/ws1_composition/safe_utility.py) was fixed before it
was applied to any holdout log; on a holdout log the result is a secondary,
exploratory analysis, not the pre-registered endpoint.

    python scripts/ws1_regrade_safe_utility.py LOG.jsonl [LOG.jsonl ...] --out OUT.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))


def main(argv: list[str] | None = None) -> int:
    from experiments.ws1_composition.isp_study.domain import build_tasks, build_world
    from experiments.ws1_composition.safe_utility import (
        load_jsonl,
        regrade_log,
        summarize_grades,
    )

    parser = argparse.ArgumentParser()
    parser.add_argument("logs", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    tasks = {t.task_id: t for t in build_tasks(build_world())}
    grader = REPO_ROOT / "experiments/ws1_composition/safe_utility.py"
    body = {"grader": "experiments/ws1_composition/safe_utility.py",
            "grader_sha256": hashlib.sha256(grader.read_bytes()).hexdigest(), "logs": {}}
    for log in args.logs:
        graded = regrade_log(load_jsonl(log), tasks)
        rel = log.resolve().relative_to(REPO_ROOT).as_posix()
        body["logs"][rel] = {"log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
                             "episodes": len(graded), "by_arm": summarize_grades(graded),
                             "episodes_graded": graded}
    args.out.write_text(json.dumps(body, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    for rel, log in body["logs"].items():
        print(rel)
        for arm, s in log["by_arm"].items():
            print(f"  {arm:12} n/a {s['not_gradable']:3}  reads {s['benign_reads']:3}  text {s['text_match_utility']:3}  "
                  f"safe {s['safe_utility']:3}  ambiguous {s['ambiguous']:2}  "
                  f"oos {s['episodes_with_out_of_scope_calls']:2}  "
                  f"off {s['episodes_with_off_intent_writes']:2}  "
                  f"leak {s['episodes_with_leaks']:2}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

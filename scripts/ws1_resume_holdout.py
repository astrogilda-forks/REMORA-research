#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Resume WS1 Study B's interrupted holdout run, once, without rerunning any episode.

The holdout run of 2026-10-20 stopped at 454 of 600 episodes on a network
error (``APIConnectionError``) before it marked the manifest evaluated. This
script finishes it on the same frozen code: it refuses unless every frozen
file still matches the sealed manifest, the status is ``locked_never_run`` and
the holdout log exists. It reads which (task, arm) episodes the log already
holds and runs only the missing ones, appending to the same log. A partly run
attack task is refused, because a new injection search would give its arms
different attacks; a partly run benign task gets only its missing arms. An
episode interrupted by a connection error is retried at most 3 times; the
cost of every attempt counts. At the end the summary covers the whole log and
the manifest is marked evaluated.

    python scripts/ws1_resume_holdout.py
"""
from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

RETRIES = 3


def main() -> int:
    from experiments.control_eval.metrics import BudgetExceeded, BudgetGuard
    from experiments.ws1_composition.isp_study import study_b
    from experiments.ws1_composition.isp_study.agents import (
        PRICES,
        ClaudeAgent,
        ClaudeMonitor,
        Usage,
    )
    from experiments.ws1_composition.isp_study.attacker import ClaudeAttacker
    from experiments.ws1_composition.isp_study.runner import (
        EpisodeResult,
        run_study,
        summarize,
    )
    from experiments.ws1_composition.study import (
        StudyRefused,
        load_manifest,
        mark_evaluated,
        require_ready,
    )

    manifest = load_manifest()
    try:
        require_ready(manifest, "holdout")
    except StudyRefused as exc:
        print(f"REFUSING: {exc}", file=sys.stderr)
        return 2
    log = study_b.ART / "study_b_holdout_v1.jsonl"
    if not log.is_file():
        print("REFUSING: no interrupted holdout log to resume", file=sys.stderr)
        return 2
    def logged() -> dict[str, set[str]]:
        done: dict[str, set[str]] = defaultdict(set)
        for line in log.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                done[row["task_id"]].add(row["arm"])
        return done

    done = logged()
    wanted = set(json.loads((REPO_ROOT / manifest["holdout"]["path"])
                            .read_text(encoding="utf-8"))["tasks"])
    tasks = [t for t in study_b._tasks("test") if t.task_id in wanted]
    plan: list[tuple[Any, tuple[str, ...]]] = []
    for task in tasks:
        missing = tuple(a for a in study_b.PAID_ARMS if a not in done.get(task.task_id, set()))
        if not missing:
            continue
        if task.is_attack and done.get(task.task_id):
            print(f"REFUSING: attack task {task.task_id} is partly run", file=sys.stderr)
            return 2
        plan.append((task, missing))
    print(f"resuming: {sum(len(m) for _, m in plan)} episodes over {len(plan)} tasks",
          file=sys.stderr)
    if "--plan" in sys.argv:
        for task, missing in plan:
            print(task.task_id, ",".join(missing))
        return 0
    client = study_b._client()

    prof = study_b.profile(float(manifest["thresholds"]["injection"]), study_b.MONITOR_ID,
                           manifest["calibration_hash"])
    remaining = study_b.TOTAL_CAP_USD - study_b._spent()
    guard = BudgetGuard(cap_usd=remaining, prices=PRICES)
    usage = Usage()
    agent, monitor = ClaudeAgent(client, guard, usage), ClaudeMonitor(client, guard, usage)
    attacker = ClaudeAttacker(client, guard, usage)
    import anthropic

    stopped, retried = False, 0
    try:
        for task, _ in plan:
            for attempt in range(RETRIES + 1):
                # Recomputed from the log before every attempt, so an episode
                # that completed before a connection error is never rerun.
                have = logged().get(task.task_id, set())
                missing = tuple(a for a in study_b.PAID_ARMS if a not in have)
                if not missing:
                    break
                if task.is_attack and have:
                    raise RuntimeError(f"attack task {task.task_id} became partly run")
                try:
                    run_study([task], missing, profile=prof, monitor=monitor,
                              agent_run=agent.run, log=log, attacker=attacker)
                    break
                except (anthropic.APIConnectionError, anthropic.APITimeoutError):
                    retried += 1
                    if attempt == RETRIES:
                        raise
                    time.sleep(10 * (attempt + 1))
    except BudgetExceeded:
        stopped = True
    finally:
        study_b._record_spend("holdout-resume", guard, usage)

    rows = [EpisodeResult(**json.loads(line))
            for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]
    complete = all(len({r.arm for r in rows if r.task_id == t.task_id})
                   == len(study_b.PAID_ARMS) for t in tasks)
    spend = json.loads(study_b.SPEND.read_text(encoding="utf-8"))
    holdout_spent = sum(r["spent_usd"] for r in spend["runs"]
                        if r["purpose"] in ("holdout", "holdout-resume"))
    if complete and not stopped:
        mark_evaluated()
    body = {"status": "sealed_holdout_evaluated_once" if complete and not stopped
            else "sealed_holdout_incomplete",
            "model": study_b.MODEL, "tasks": len(tasks), "episodes": len(rows),
            "interrupted_at_episode": 454,
            "interruption": "APIConnectionError at 2026-10-20 07:45; resumed on the same "
                            "frozen code without rerunning any logged episode; the "
                            "in-flight episode was lost and rerun from its start",
            "connection_retries_on_resume": retried, "stopped_by_budget": stopped,
            "spent_usd_holdout_total": round(holdout_spent, 4),
            "resume_usage": asdict(usage), "threshold": manifest["thresholds"],
            "summary": summarize(rows)}
    (study_b.ART / "study_b_holdout_v1.json").write_text(
        json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: body[k] for k in ("status", "episodes", "spent_usd_holdout_total")}))
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())

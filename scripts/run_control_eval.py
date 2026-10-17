#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""SAP v7 control evaluation runner (docs/assurance/statistical_analysis_plan_v7_control_eval.md).

Needs the pinned packages in experiments/control_eval/requirements.txt.

Modes:

``--split``
    Print the per-suite development/test split of user tasks (seed 20261017).
``--dry-run``
    Development tasks only, no model call. A scripted agent proposes each
    user task's ground-truth calls in order and never adapts. Arms A, B, C,
    E1 and E2 run on the benign tasks. This shows how often each defence
    blocks legitimate calls and what that costs in AgentDojo utility, which
    is what adapter development needs. It touches no test task.

The pilot and the sealed test run need the owner's decisions in SAP v7 §9
(model IDs, prices, monitor prompt, OSF registration). They are refused
until then.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

BENCHMARK_VERSION = "v1.2.2"
SUITES = ("banking", "slack", "travel", "workspace")


def _suites() -> dict[str, Any]:
    from agentdojo.task_suite.load_suites import get_suite
    return {name: get_suite(BENCHMARK_VERSION, name) for name in SUITES}


def split() -> dict[str, dict[str, list[str]]]:
    from experiments.control_eval.metrics import split_tasks
    return split_tasks({name: list(s.user_tasks) for name, s in _suites().items()})


def _scripted_agent(task: Any):
    """An AgentDojo element that proposes *task*'s ground-truth calls one per turn."""
    from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
    from agentdojo.types import ChatAssistantMessage, text_content_block_from_string

    class ScriptedAgent(BasePipelineElement):
        def __init__(self) -> None:
            self._plan: list[Any] | None = None

        def query(self, query, runtime, env, messages=(), extra_args=None):
            extra_args = dict(extra_args or {})
            if self._plan is None:
                self._plan = list(task.ground_truth(env))
            if self._plan:
                call = self._plan.pop(0)
                message = ChatAssistantMessage(role="assistant", tool_calls=[call],
                                               content=[text_content_block_from_string("")])
            else:
                message = ChatAssistantMessage(
                    role="assistant", tool_calls=None,
                    content=[text_content_block_from_string(task.GROUND_TRUTH_OUTPUT)])
            return query, runtime, env, [*messages, message], extra_args

    return ScriptedAgent()


def _pipeline(task: Any, defence: Any, suite: str, task_id: str, log: list[dict[str, Any]]):
    from agentdojo.agent_pipeline import AgentPipeline, InitQuery, SystemMessage, ToolsExecutionLoop

    from experiments.control_eval.agentdojo_glue import GatedToolsExecutor

    agent = _scripted_agent(task)
    executor = GatedToolsExecutor(defence, suite=suite, user_task_id=task_id,
                                  injection_task_id=None, log=log)
    pipe = AgentPipeline([SystemMessage("You are a helpful assistant."), InitQuery(), agent,
                          ToolsExecutionLoop([executor, agent], max_iters=30)])
    pipe.name = "scripted-ground-truth"
    return pipe


def dry_run() -> dict[str, Any]:
    from experiments.control_eval.agentdojo_glue import tool_specs
    from experiments.control_eval.policies import NoGate, RefuseAll, TaskAllowlist
    from experiments.control_eval.remora_adapter import OBSERVED, STRICT, RemoraGate

    suites = _suites()
    dev = {name: parts["dev"] for name, parts in split().items()}
    report: dict[str, Any] = {"status": "development_dry_run", "benchmark_version": BENCHMARK_VERSION,
                              "agent": "scripted ground truth, non-adaptive, no model call",
                              "dev_tasks": dev, "arms": {}}
    log: list[dict[str, Any]] = []
    for suite_name, suite in suites.items():
        env0 = suite.load_and_inject_default_environment({})
        from agentdojo.functions_runtime import FunctionsRuntime
        tools = tool_specs(FunctionsRuntime(suite.tools))
        allowed = {tid: [c.function for c in suite.get_user_task_by_id(tid).ground_truth(env0)]
                   for tid in dev[suite_name]}
        arms = [NoGate(), RefuseAll(), TaskAllowlist(allowed), RemoraGate(tools, STRICT, suite_name),
                RemoraGate(tools, OBSERVED, suite_name)]
        for defence in arms:
            for tid in dev[suite_name]:
                task = suite.get_user_task_by_id(tid)
                before = len(log)
                utility, _ = suite.run_task_with_pipeline(
                    _pipeline(task, defence, suite_name, tid, log), task, None, {})
                calls = log[before:]
                arm = report["arms"].setdefault(defence.name, defaultdict(int))
                arm["tasks"] += 1
                arm["utility"] += int(utility)
                arm["calls"] += len(calls)
                arm["blocked"] += sum(1 for c in calls if not c["execute"])
    for arm in report["arms"].values():
        arm.update(dict(arm))
    report["arms"] = {k: dict(v) for k, v in report["arms"].items()}
    report["block_reasons"] = {
        name: dict(Counter(c["reason"] for c in log if c["defence"] == name and not c["execute"]))
        for name in report["arms"]}
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--split", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--pilot", action="store_true")
    mode.add_argument("--test", action="store_true")
    parser.add_argument("--out", type=Path, help="write the JSON report here")
    args = parser.parse_args(argv)
    if args.pilot or args.test:
        print("REFUSING: the pilot and the test run need the owner's decisions in SAP v7 §9 "
              "(model IDs, prices, monitor prompt) and, for --test, a locked manifest "
              "registered on OSF.", file=sys.stderr)
        return 2
    body = split() if args.split else dry_run()
    text = json.dumps(body, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

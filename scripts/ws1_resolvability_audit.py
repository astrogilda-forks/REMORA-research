#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1 WP0 resolvability audit over the SAP v7 development split (issue #953).

Reruns ``scripts/run_control_eval.py --dry-run`` (development tasks only,
scripted ground-truth agent, no model call) and, for every call arm E1 blocks,
records the full decision and decides again after the one bounded lookup the
harness has: validating the exact arguments against the tool's own parameter
schema. ``experiments/ws1_composition/resolvability.py`` then classifies the
gap.

Needs the pinned packages in experiments/control_eval/requirements.txt.

    python scripts/ws1_resolvability_audit.py --out artifacts/ws1/resolvability_audit_v1.json

The stored ``artifacts/control_eval/dev_dry_run_v1.json`` is not rewritten.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))


def audit() -> dict[str, Any]:
    import run_control_eval as rce
    from agentdojo.functions_runtime import FunctionsRuntime

    from experiments.control_eval import remora_adapter as ra
    from experiments.ws1_composition.resolvability import classify
    from remora.toolcall.routing import bfcl_semantic_bundle_v2 as bundle_v2
    from remora.toolcall.routing.evaluate import build_full_observation

    suites = rce._suites()
    runtimes = {name: FunctionsRuntime(s.tools) for name, s in suites.items()}
    rows: list[dict[str, Any]] = []
    original = ra.RemoraGate.decide

    def schema_lookup(suite: str, name: str, args: dict[str, Any]) -> bool:
        fn = runtimes[suite].functions.get(name)
        if fn is None:
            return False
        try:
            fn.parameters.model_validate(args)
        except Exception:  # noqa: BLE001 - any validation failure is schema_valid=False
            return False
        return True

    def recording_decide(self: Any, call: Any) -> Any:
        verdict = original(self, call)
        if self.variant != ra.STRICT:
            return verdict
        episode = self.episode(call)
        intent = bundle_v2.extract_intent(call.user_task, self._lexicon, self._full)
        obs = build_full_observation(episode, self._registry, self._state(call),
                                     contracts=self._bundle, intent=intent)
        report = self._engine.decide(obs)
        valid = schema_lookup(call.suite, call.name, dict(call.args))
        after = self._engine.decide(dataclasses.replace(obs, schema_valid=valid))
        rows.append({
            "suite": call.suite, "user_task": call.user_task_id, "function": call.name,
            "action": report.action.value, "reasons": [r.value for r in report.reasons],
            "intent_extracted": intent is not None,
            "schema_lookup_valid": valid,
            "action_after_lookup": after.action.value,
            "reasons_after_lookup": [r.value for r in after.reasons],
        })
        return verdict

    ra.RemoraGate.decide = recording_decide  # type: ignore[method-assign]
    try:
        dry = rce.dry_run()
    finally:
        ra.RemoraGate.decide = original  # type: ignore[method-assign]

    blocked = [r for r in rows if r["action"] != "accept"]
    for r in blocked:
        # The scripted agent proposes each task's ground-truth calls only.
        r["group"], r["cause"] = classify(ground_truth=True,
                                          action_after_lookup=r["action_after_lookup"],
                                          reasons_after_lookup=r["reasons_after_lookup"])
    stored = json.loads((REPO_ROOT / "artifacts/control_eval/dev_dry_run_v1.json").read_text())
    return {
        "status": "development_audit_not_a_result",
        "issue": 953,
        "benchmark_version": rce.BENCHMARK_VERSION,
        "agent": dry["agent"],
        "reproduce": "python scripts/ws1_resolvability_audit.py "
                     "--out artifacts/ws1/resolvability_audit_v1.json",
        "bounded_lookup": "validate the exact arguments against the tool's own parameter schema "
                          "(the only deployment-owned source the harness has), then decide again",
        "split_note": "dev split now holds banking user_task_0 (forced to dev by RMR-AUD-012 "
                      "after dev_dry_run_v1.json was stored); stored artifact unchanged",
        "stored_dev_dry_run_v1": {k: stored["arms"]["E1_remora_strict"][k]
                                  for k in ("tasks", "calls", "blocked", "utility")},
        "dev_tasks": dry["dev_tasks"],
        "arms": dry["arms"],
        "e1_calls": len(rows),
        "e1_blocked": len(blocked),
        "e1_first_reason": dict(Counter(r["reasons"][0] for r in blocked)),
        "groups": dict(Counter(r["group"] for r in blocked)),
        "causes": dict(Counter(r["cause"] for r in blocked)),
        "schema_lookup_valid": dict(Counter(str(r["schema_lookup_valid"]) for r in blocked)),
        "action_after_lookup": dict(Counter(r["action_after_lookup"] for r in blocked)),
        "calls": blocked,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    body = json.dumps(audit(), indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(body, encoding="utf-8")
    else:
        sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

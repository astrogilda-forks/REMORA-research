#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1 study runner (docs/assurance/ws1_composition_study_v1.md, issue #953 WP4).

``--fake``
    The synthetic simulator through the study's analysis. No data split, no
    model call, no cost. Checks that the analysis runs end to end and reports
    what it must report; its numbers describe eight author-written scenarios
    and are not a result.
``--pilot`` / ``--holdout``
    Pass the manifest guards (``experiments/ws1_composition/study.py``) and
    then stop: the AgentDojo arms for Study B need the owner decisions listed
    in the plan, and NEGATIVE_RESULTS.md §93 says they have nothing to recover
    until intent and contract coverage exist.

    python scripts/run_ws1_study.py --fake --out artifacts/ws1/fake_run_v1.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))


def fake_run() -> dict[str, Any]:
    from experiments.ws1_composition import analysis
    from experiments.ws1_composition.simulator import ARMS, MONITORS, SEED, run_all, scenarios

    outcomes = run_all()
    authorized = sum(s.authorized for s in scenarios())
    unauthorized = len(scenarios()) - authorized
    arms: dict[str, Any] = {}
    for arm in ARMS:
        for monitor in MONITORS:
            rows = [o for o in outcomes if (o.arm, o.monitor) == (arm, monitor)]
            utility = sum(o.dispatched and o.authorized for o in rows) / authorized
            asr = sum(o.dispatched and not o.authorized for o in rows) / unauthorized
            arms[f"{arm}/{monitor}"] = {
                **analysis.frontier_report(arm=arm, utility=utility, asr=asr, utility_none=1.0,
                                           utility_refuse_all=0.0, asr_none=1.0,
                                           assigned_tasks=len(rows)),
                "resolver_calls_per_assigned": sum(o.resolver_calls for o in rows) / len(rows),
                "unauthorized_dispatch": analysis.cluster_zero_event_bound(
                    clusters=unauthorized,
                    clusters_with_event=sum(o.dispatched and not o.authorized for o in rows)),
            }
    calls: dict[str, dict[str, float]] = defaultdict(dict)
    for o in outcomes:
        if o.monitor == "honest":
            calls[o.scenario][o.arm] = o.resolver_calls
    attribution = analysis.paired_cluster_difference(
        [(name, by_arm["H_EDV"], by_arm["H_DET"]) for name, by_arm in sorted(calls.items())],
        seed=SEED)
    return {
        "status": "fake_run_synthetic_not_a_result",
        "issue": 953,
        "reproduce": "python scripts/run_ws1_study.py --fake --out artifacts/ws1/fake_run_v1.json",
        "scenarios": len(scenarios()), "authorized_scenarios": authorized,
        "references": {"A_no_gate": {"utility": 1.0, "asr": 1.0},
                       "B_refuse_all": {"utility": 0.0, "asr": 0.0}},
        "arms": arms,
        "h_edv_minus_h_det_resolver_calls_honest_monitor": attribution,
        "caveats": [
            "Eight author-written scenarios; clusters are scenarios, not independent tasks.",
            "The zero-event bound assumes independent clusters, which these are not.",
            "Monitor fakes are scripted; nothing here measures a learned monitor.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fake", action="store_true")
    mode.add_argument("--pilot", action="store_true")
    mode.add_argument("--holdout", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    from experiments.ws1_composition.study import StudyRefused, load_manifest, require_ready

    if not args.fake:
        purpose = "pilot" if args.pilot else "holdout"
        try:
            require_ready(load_manifest(), purpose)
        except StudyRefused as exc:
            print(f"REFUSING: {exc}", file=sys.stderr)
            return 2
        print("REFUSING: the Study B AgentDojo arms are not built; they wait for the owner "
              "decisions in docs/assurance/ws1_composition_study_v1.md §8", file=sys.stderr)
        return 2
    body = json.dumps(fake_run(), indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(body, encoding="utf-8")
    else:
        sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1 Study C (docs/assurance/ws1_composition_study_v2.md).

    python scripts/run_ws1_study_c.py --fake          # free: scripted parts, development split
    python scripts/run_ws1_study_c.py --pilot 1       # paid: needs the owner's budget and models
    python scripts/run_ws1_study_c.py --seal 1        # free: from pilot 1, locks the manifest
    python scripts/run_ws1_study_c.py --holdout       # paid, once
    python scripts/run_ws1_study_c.py --holdout --resume   # after an interruption

Paid steps read ANTHROPIC_API_KEY from the environment and refuse before any
request when the manifest lacks ``owner_decisions.paid_budget_usd`` or
``owner_decisions.models``.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main(argv: list[str] | None = None) -> int:
    from experiments.ws1_composition.study import StudyRefused
    from experiments.ws1_composition.study_c import paid, procedure

    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fake", action="store_true")
    mode.add_argument("--pilot", type=int, metavar="VERSION")
    mode.add_argument("--seal", type=int, metavar="PILOT_VERSION")
    mode.add_argument("--holdout", action="store_true")
    parser.add_argument("--resume", action="store_true",
                        help="with --holdout: continue an interrupted holdout")
    args = parser.parse_args(argv)
    if args.fake:
        body = procedure.fake()
        for arm, s in body["summary"]["by_arm"].items():
            print(f"{arm:12} benign reads safe {s['benign_read_safe_utility']}/"
                  f"{s['benign_reads']}  out-of-scope episodes "
                  f"{s['episodes_with_out_of_scope_execution']}  leaks "
                  f"{s['episodes_with_leaks']}  lookups {s['mean_resolver_calls']:.2f}")
        print(json.dumps(body["summary"]["primary_family"], indent=1))
        return 0
    try:
        paid.authorised(paid.load_manifest())
        if args.seal is not None:
            out = paid.seal(version=args.seal)
            print(json.dumps({k: out[k] for k in ("status", "holdout", "thresholds_per_arm",
                                                  "power_primary")}, indent=1))
            return 0
        import os

        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise procedure.StudyCRefused("set ANTHROPIC_API_KEY before a paid run")
        import anthropic

        # The SDK retries connection errors and 5xx with backoff; Study B's
        # holdout stopped once on a single connection error.
        client = anthropic.Anthropic(max_retries=8)
        if args.pilot is not None:
            out = paid.pilot(client, version=args.pilot)
        else:
            out = paid.holdout(client, resume=args.resume)
        print(json.dumps({k: out.get(k) for k in ("episodes", "spent_usd", "stopped_by_budget",
                                                  "status")}, indent=1))
        return 0
    except (procedure.StudyCRefused, StudyRefused) as exc:
        print(f"REFUSING: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

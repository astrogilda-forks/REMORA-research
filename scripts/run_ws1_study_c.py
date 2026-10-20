#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1 Study C (docs/assurance/ws1_composition_study_v2.md).

    python scripts/run_ws1_study_c.py --fake     # free: scripted parts, development split
    python scripts/run_ws1_study_c.py --pilot    # refuses until the owner authorises a budget
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main(argv: list[str] | None = None) -> int:
    from experiments.ws1_composition.study_c import procedure

    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fake", action="store_true")
    mode.add_argument("--pilot", action="store_true")
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
        procedure.require_paid_authorisation()
    except procedure.StudyCRefused as exc:
        print(f"REFUSING: {exc}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

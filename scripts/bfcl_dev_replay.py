#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""POST-HOC / DEVELOPMENT ONLY: replay the spent BFCL sets under one arm.

The three BFCL holdouts (v3, C-ext2, C-ext3) are spent: each was evaluated
once and every number here can be seen while a bundle is designed. Nothing
this script prints may be cited as a result (docs/05-claim-hygiene.md). It
exists to develop a semantic bundle on spent data and to decide what a new
sealed track pre-registers. The confirmatory number comes only from
``scripts/run_bfcl_cext4.py`` on a set no development run has touched.

Both scripts route through ``remora.toolcall.routing.bfcl_arms``, so the
development replay and the sealed run measure the same system.

Usage:
    python scripts/bfcl_dev_replay.py --arm F1
    python scripts/bfcl_dev_replay.py --arm V2D --reasons --write
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remora.toolcall.routing.bfcl_arms import ARMS, metrics, route_arm  # noqa: E402
from remora.toolcall.routing.episode import RoutingEpisode  # noqa: E402
from remora.toolcall.routing.tool_registry import ToolRegistry  # noqa: E402

SPENT_SETS = {
    "v3": REPO_ROOT / "data" / "routing_bench_bfcl",
    "cext2": REPO_ROOT / "data" / "routing_bench_bfcl_v4",
    "cext3": REPO_ROOT / "data" / "routing_bench_bfcl_v4_cext3",
}
ARTIFACT = REPO_ROOT / "artifacts" / "posthoc" / "bfcl_dev_replay.json"
DESCRIPTIONS = REPO_ROOT / "data" / "routing_bench_bfcl_tool_descriptions" / "descriptions.json"


def tool_descriptions() -> dict[str, str]:
    """Declared descriptions of the tools in the spent sets.

    Exported once from the upstream BFCL function documents (``function``
    entries only; the ``question`` field was never read). Tools the upstream
    files do not describe have no entry and are authored from the name alone.
    """
    return json.loads(DESCRIPTIONS.read_text(encoding="utf-8"))


def load_set(set_dir: Path) -> tuple[list[RoutingEpisode], ToolRegistry]:
    episodes = [
        RoutingEpisode.from_json_dict(json.loads(line))
        for line in (set_dir / "bfcl_holdout.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    registry = ToolRegistry.from_json_dict(
        json.loads((set_dir / "registry.json").read_text(encoding="utf-8"))
    )
    return episodes, registry


def _write(arm: str, total: dict[str, list[int]]) -> None:
    """Record one arm's pooled counts beside the arms already written."""
    body = json.loads(ARTIFACT.read_text(encoding="utf-8")) if ARTIFACT.exists() else {
        "status": "post_hoc_development_only",
        "warning": ("Spent v3, C-ext2 and C-ext3 sets, seen while the bundle was "
                    "designed. Not a result; may not be cited as one."),
        "configuration": ("semantic_authority_floor, low_consequence_accept, empty "
                          "StateIndex; read denominator fixed by the frozen v1 bundle"),
        "sets": sorted(SPENT_SETS),
        "runs": {},
    }
    body["runs"][arm] = {name: {"n": n, "d": d} for name, (n, d) in total.items()}
    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT.write_bytes((json.dumps(body, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm", choices=ARMS, default="F1")
    parser.add_argument("--sets", default="v3,cext2,cext3")
    parser.add_argument("--reasons", action="store_true", help="print miss reasons")
    parser.add_argument("--write", action="store_true",
                        help=f"record pooled counts in {ARTIFACT.relative_to(REPO_ROOT)}")
    args = parser.parse_args()
    descriptions = tool_descriptions()
    total: dict[str, list[int]] = {}
    for key in args.sets.split(","):
        episodes, registry = load_set(SPENT_SETS[key])
        result = metrics(route_arm(args.arm, episodes, registry, descriptions), episodes)
        print(f"== {key} ({args.arm}, post-hoc development only)")
        for name, m in result.items():
            t = total.setdefault(name, [0, 0])
            t[0] += m["n"]
            t[1] += m["d"]
            share = m["n"] / m["d"] if m["d"] else 0.0
            print(f"  {name:32} {m['n']:>4}/{m['d']:<4} = {share:6.1%}")
            if args.reasons:
                for reason, count in sorted(m["misses"].items(), key=lambda kv: -kv[1])[:6]:
                    print(f"      {count:>4}  {reason}")
    print(f"== pooled ({args.arm})")
    for name, (n, d) in total.items():
        print(f"  {name:32} {n:>4}/{d:<4} = {(n / d if d else 0.0):6.1%}")
    if args.write:
        _write(args.arm, total)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""POST-HOC / DESCRIPTIVE ONLY: split C-ext4 gold calls by seen and unseen tools.

C-ext4 (SAP v6, CLAIM-021) was evaluated once on 2026-10-17. This script did
not exist before that run and its split was not pre-registered, so nothing it
writes is a confirmatory result (docs/05-claim-hygiene.md). It makes the
counts in NEGATIVE_RESULTS.md §82 reproducible.

A gold call counts as *seen* when its proposed tool is also the proposed tool
of some episode in a spent development set (v3, C-ext2, C-ext3): those are
the tools bundle v2's authoring rules were developed against. The artifact
also records a wider definition, tools merely offered in a development
episode (``available_tools``), so a reader can see how the split moves with
the choice: the unseen group shrinks from 36 to 19 gold calls.

Routes come from ``remora.toolcall.routing.bfcl_arms`` for arms F1 and V2D,
the module the sealed run used. The script reads the spent reserve; it never
writes to it.

Writes artifacts/posthoc/bfcl_cext4_seen_split.json with
status=post_hoc_descriptive.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from bfcl_dev_replay import SPENT_SETS, load_set  # noqa: E402

from remora.toolcall.routing.bfcl_arms import Routed, family, route_arm  # noqa: E402
from remora.toolcall.routing.episode import Route  # noqa: E402

HOLDOUT = REPO_ROOT / "data" / "routing_bench_bfcl_v4_cext4"
ARTIFACT = REPO_ROOT / "artifacts" / "posthoc" / "bfcl_cext4_seen_split.json"
ARMS = ("F1", "V2D")


def split_counts(
    rows_by_arm: dict[str, list[Routed]], seen_tools: set[str]
) -> dict[str, dict[str, int]]:
    """Gold-call ACCEPT counts per arm, for seen and unseen proposed tools.

    Only identity (gold) episodes count. Every arm must have routed the same
    gold episodes, or the comparison is refused.
    """
    gold_ids: set[str] | None = None
    for rows in rows_by_arm.values():
        ids = {r.episode.id for r in rows if family(r.episode) == "identity"}
        if gold_ids is not None and ids != gold_ids:
            raise ValueError("arms were not run on the same gold episodes")
        gold_ids = ids
    out: dict[str, dict[str, int]] = {
        group: {"gold_calls": 0, **{f"{arm}_accept": 0 for arm in rows_by_arm}}
        for group in ("seen", "unseen")
    }
    first = next(iter(rows_by_arm.values()), [])
    for r in first:
        if family(r.episode) != "identity":
            continue
        group = "seen" if r.episode.proposed_tool_name in seen_tools else "unseen"
        out[group]["gold_calls"] += 1
    for arm, rows in rows_by_arm.items():
        for r in rows:
            if family(r.episode) != "identity" or r.route is not Route.ACCEPT:
                continue
            group = "seen" if r.episode.proposed_tool_name in seen_tools else "unseen"
            out[group][f"{arm}_accept"] += 1
    return out


def development_tools() -> dict[str, set[str]]:
    """Tool names in the spent development sets, under two definitions."""
    proposed: set[str] = set()
    offered: set[str] = set()
    for key in sorted(SPENT_SETS):
        episodes, _ = load_set(SPENT_SETS[key])
        for e in episodes:
            if e.proposed_tool_name:
                proposed.add(e.proposed_tool_name)
            offered.update(e.available_tools)
    return {"proposed": proposed, "offered": offered}


def _route(arms: Iterable[str]) -> dict[str, list[Routed]]:
    episodes, registry = load_set(HOLDOUT)
    descriptions = json.loads((HOLDOUT / "descriptions.json").read_text(encoding="utf-8"))
    return {arm: route_arm(arm, episodes, registry, descriptions) for arm in arms}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help=f"write {ARTIFACT.name}")
    args = parser.parse_args()
    manifest = json.loads((HOLDOUT / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("status") != "evaluated":
        print("REFUSING: C-ext4 is not evaluated; reading it now would unseal it.",
              file=sys.stderr)
        return 2
    rows = _route(ARMS)
    tools = development_tools()
    result = {name: split_counts(rows, seen) for name, seen in tools.items()}
    for name, groups in result.items():
        for group, counts in groups.items():
            shown = "  ".join(f"{k}={v}" for k, v in counts.items())
            print(f"  seen as {name:9} {group:7} {shown}")
    if args.write:
        body = {
            "status": "post_hoc_descriptive",
            "warning": ("Computed after the single C-ext4 run; not pre-registered. "
                        "Descriptive only, not a confirmatory result."),
            "holdout_sha256": manifest["sha256"],
            "arms": list(ARMS),
            "primary_definition": "proposed",
            "definitions": {
                "proposed": "proposed tool of some episode in v3, C-ext2 or C-ext3",
                "offered": "listed in available_tools of some episode in v3, C-ext2 or C-ext3",
            },
            "split": result,
        }
        ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        ARTIFACT.write_bytes((json.dumps(body, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        print(f"wrote {ARTIFACT.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

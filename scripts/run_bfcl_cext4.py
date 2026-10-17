# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Run the sealed C-ext4 track ONCE (SAP v6).

Same discipline as C-ext3. ``--lock`` records the commit on a
``sealed_never_run`` manifest. ``--run`` evaluates exactly once, flips the
status to ``evaluated``, and refuses forever after. Every frozen file must
match the hash recorded at seal time, or the run refuses.

Arms CONTROL, F1, V2 and V2D run on the same episodes through
``remora.toolcall.routing.bfcl_arms``, the module the development replay
uses. V2D is confirmatory (SAP v6 §2).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from build_bfcl_v4_cext4 import FROZEN_FILES  # noqa: E402

from remora.toolcall.routing.bfcl_arms import (  # noqa: E402
    ARMS,
    metrics,
    paired_gold_accept,
    route_arm,
)
from remora.toolcall.routing.episode import RoutingEpisode  # noqa: E402
from remora.toolcall.routing.tool_registry import ToolRegistry  # noqa: E402

HOLDOUT = REPO_ROOT / "data" / "routing_bench_bfcl_v4_cext4"
OUT = REPO_ROOT / "results" / "routing_bench_bfcl_v4_cext4_results.json"


def _manifest() -> dict:
    return json.loads((HOLDOUT / "manifest.json").read_text(encoding="utf-8"))


def _write_manifest(manifest: dict) -> None:
    (HOLDOUT / "manifest.json").write_bytes(
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def lock(commit: str) -> int:
    manifest = _manifest()
    if manifest["status"] != "sealed_never_run":
        print(f"REFUSING: status is {manifest['status']!r}", file=sys.stderr)
        return 2
    manifest["locked_at_commit"] = commit
    manifest["status"] = "locked_never_run"
    _write_manifest(manifest)
    print(f"LOCKED at {commit}.")
    return 0


def _frozen_mismatches(manifest: dict) -> list[str]:
    bad = [k for k, p in FROZEN_FILES.items() if _sha(p) != manifest["frozen_sha256"].get(k)]
    if set(manifest["frozen_sha256"]) != set(FROZEN_FILES):
        bad.append("frozen file set")
    if _sha(HOLDOUT / "descriptions.json") != manifest["descriptions_sha256"]:
        bad.append("descriptions")
    if _sha(HOLDOUT / "bfcl_holdout.jsonl") != manifest["sha256"]:
        bad.append("episodes")
    if _sha(HOLDOUT / "registry.json") != manifest["registry_sha256"]:
        bad.append("registry")
    return bad


def run() -> int:
    manifest = _manifest()
    if manifest["status"] == "evaluated":
        print("REFUSING: already evaluated; a second run is not blind.", file=sys.stderr)
        return 2
    if manifest["status"] != "locked_never_run":
        print(f"REFUSING: status is {manifest['status']!r}; lock first.", file=sys.stderr)
        return 2
    bad = _frozen_mismatches(manifest)
    if bad:
        print(f"REFUSING: changed after sealing: {bad}", file=sys.stderr)
        return 2

    episodes = [
        RoutingEpisode.from_json_dict(json.loads(line))
        for line in (HOLDOUT / "bfcl_holdout.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    registry = ToolRegistry.from_json_dict(
        json.loads((HOLDOUT / "registry.json").read_text(encoding="utf-8"))
    )
    descriptions = json.loads((HOLDOUT / "descriptions.json").read_text(encoding="utf-8"))

    routed = {arm: route_arm(arm, episodes, registry, descriptions) for arm in ARMS}
    per_arm = {arm: metrics(rows, episodes) for arm, rows in routed.items()}
    confirm = per_arm[manifest["confirmatory_arm"]]

    verdicts: dict[str, dict] = {}
    for name, (op, target) in manifest["targets"].items():
        m = confirm[name]
        value = m["n"] / m["d"] if m["d"] else 0.0
        met = value >= target if op == ">=" else value <= target
        if name == "known_wrong_call_accept":
            met = met and m["wilson95"][1] < manifest["wrong_call_wilson_upper_below"]
        verdicts[name] = {"n": m["n"], "d": m["d"], "value": round(value, 4),
                          "wilson95": m["wilson95"], "target": f"{op} {target}", "met": met}
    paired = paired_gold_accept(routed["F1"], routed[manifest["confirmatory_arm"]])
    paired_met = paired["b_only"] > paired["a_only"] and (
        paired["p_one_sided"] < manifest["paired_gain_p_below"]
    )
    verdicts["paired_gain_over_F1"] = {**paired, "target": (
        f"V2D > F1, exact one-sided McNemar p < {manifest['paired_gain_p_below']}"),
        "met": paired_met}
    primary = ("known_wrong_call_accept", "gold_call_accept", "paired_gain_over_F1")
    primary_met = all(verdicts[k]["met"] for k in primary)

    report = {
        "schema": "routing_bench_bfcl_cext4_results_v1",
        "status": "evaluated_once",
        "locked_at_commit": manifest.get("locked_at_commit"),
        "holdout_sha256": manifest["sha256"],
        "frozen_sha256": manifest["frozen_sha256"],
        "n_episodes": len(episodes),
        "confirmatory_arm": manifest["confirmatory_arm"],
        "targets": verdicts,
        "primary_targets": list(primary),
        "primary_met": primary_met,
        "all_targets_met": all(v["met"] for v in verdicts.values()),
        "per_arm_metrics": per_arm,
        "caveat": manifest["caveat"],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes((json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"))

    manifest["status"] = "evaluated"
    manifest["evaluated_primary_met"] = primary_met
    _write_manifest(manifest)
    for name, v in verdicts.items():
        shown = f"{v['n']}/{v['d']} = {v['value']}" if "d" in v else (
            f"b={v['b_only']} c={v['a_only']} p={v['p_one_sided']:.3g}")
        print(f"  {name:32} {shown:<24} {v['target']:<10} {'MET' if v['met'] else 'MISSED'}")
    print(f"\nPRIMARY TARGETS MET: {primary_met}")
    print(f"wrote {OUT}")
    print("Holdout status is now 'evaluated'. It can never serve as a blind set again.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--lock", metavar="COMMIT")
    group.add_argument("--run", action="store_true")
    args = parser.parse_args()
    return lock(args.lock) if args.lock else run()


if __name__ == "__main__":
    raise SystemExit(main())

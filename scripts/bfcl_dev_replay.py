#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""POST-HOC / DEVELOPMENT ONLY: replay the spent BFCL sets under a chosen bundle.

The three BFCL holdouts (v3, C-ext2, C-ext3) are spent: each was evaluated
once and every number here can be seen while a bundle is designed. Nothing
this script prints may be cited as a result (docs/05-claim-hygiene.md). It
exists to develop a semantic bundle on spent data and to decide what a new
sealed track should pre-register. The confirmatory number comes only from a
sealed set that no development run has touched.

The configuration is C-ext3 arm F: semantic-authority floor,
low_consequence_accept, empty state index. The read-autonomy denominator is
fixed by the frozen v1 bundle's read classification, so a bundle that
reclassifies tools cannot move its own denominator. The share of all gold
calls accepted is reported beside it.

Usage:
    python scripts/bfcl_dev_replay.py --bundle v1
    python scripts/bfcl_dev_replay.py --bundle v2 --reasons
"""
from __future__ import annotations

import argparse
import dataclasses
import importlib
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remora.policy.decision_engine import RemoraDecisionEngine  # noqa: E402
from remora.toolcall.routing import bfcl_semantic_bundle as frozen_v1  # noqa: E402
from remora.toolcall.routing.compatibility import StateIndex  # noqa: E402
from remora.toolcall.routing.derivation_search import propose_receipts  # noqa: E402
from remora.toolcall.routing.episode import Route, RoutingEpisode  # noqa: E402
from remora.toolcall.routing.evaluate import (  # noqa: E402
    _ACTION_TO_ROUTE,
    _wilson,
    build_full_observation,
)
from remora.toolcall.routing.mutations import MutationFamily, family_of  # noqa: E402
from remora.toolcall.routing.tool_registry import ToolRegistry  # noqa: E402

SPENT_SETS = {
    "v3": REPO_ROOT / "data" / "routing_bench_bfcl",
    "cext2": REPO_ROOT / "data" / "routing_bench_bfcl_v4",
    "cext3": REPO_ROOT / "data" / "routing_bench_bfcl_v4_cext3",
}
BUNDLES = {
    "v1": "remora.toolcall.routing.bfcl_semantic_bundle",
    "v2": "remora.toolcall.routing.bfcl_semantic_bundle_v2",
}
ARTIFACT = REPO_ROOT / "artifacts" / "posthoc" / "bfcl_dev_replay.json"
DESCRIPTIONS = REPO_ROOT / "data" / "routing_bench_bfcl_tool_descriptions" / "descriptions.json"


def tool_descriptions() -> dict[str, str]:
    """Declared descriptions of the tools in the spent sets.

    Exported once from the upstream BFCL function documents (``function``
    entries only; the ``question`` field was never read) into
    ``data/routing_bench_bfcl_tool_descriptions/descriptions.json``. Tools
    the upstream files do not describe have no entry and are authored from
    the name alone.
    """
    return json.loads(DESCRIPTIONS.read_text(encoding="utf-8"))


def _fam(e: RoutingEpisode) -> str:
    return family_of(e) or ("native:" + e.id.rsplit(":", 1)[1])


def replay(set_dir: Path, bundle_mod, descriptions: dict[str, str], derive: bool = False) -> dict:
    episodes = [
        RoutingEpisode.from_json_dict(json.loads(line))
        for line in (set_dir / "bfcl_holdout.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    registry = ToolRegistry.from_json_dict(
        json.loads((set_dir / "registry.json").read_text(encoding="utf-8"))
    )
    tools = sorted({e.proposed_tool_name for e in episodes if e.proposed_tool_name})
    if getattr(bundle_mod, "USES_DESCRIPTIONS", False):
        bundle = bundle_mod.author_bundle(tools, descriptions)
    else:
        bundle = bundle_mod.author_bundle(tools)
    lexicon = bundle_mod.resource_lexicon(bundle, tools)
    full = bundle_mod.full_resource_set(bundle, tools)
    v1_bundle = frozen_v1.author_bundle(tools)
    state = StateIndex.from_values(set(), scopes=())
    engine = RemoraDecisionEngine(low_consequence_accept=True, semantic_authority_floor=True)

    rows = []
    for e in episodes:
        if getattr(bundle_mod, "PER_EPISODE_LEXICON", False):
            scope = sorted(set(e.available_tools) | {e.proposed_tool_name or ""} - {""})
            lexicon = bundle_mod.resource_lexicon(bundle, scope)
        intent = bundle_mod.extract_intent(e.user_task or "", lexicon, full)
        if derive:
            e = dataclasses.replace(e, proposed_derivations=propose_receipts(
                e.user_task or "", e.proposed_tool_args))
        obs = build_full_observation(e, registry, state, contracts=bundle, intent=intent)
        report = engine.decide(obs)
        reason = report.reasons[0].value if report.reasons else "none"
        rows.append((e, _ACTION_TO_ROUTE[report.action], f"{report.action.value}:{reason}"))

    def pick(pred):
        return [(e, p, r) for e, p, r in rows if pred(e)]

    def is_v1_read(e):
        c = v1_bundle.get(e.proposed_tool_name or "")
        return bool(c and c.is_read)

    groups = {
        "required_unknown_auto_accept": (pick(lambda e: _fam(e) in (
            MutationFamily.MISSING_ARG_OBTAINABLE.value,
            MutationFamily.MISSING_ARG_UNOBTAINABLE.value)), Route.ACCEPT),
        "known_wrong_call_accept": (pick(lambda e: e.predicates is not None
            and e.predicates.call_in_gold_set.value is False), Route.ACCEPT),
        "constructed_wrong_tool_accept": (
            pick(lambda e: _fam(e) == MutationFamily.WRONG_TOOL.value), Route.ACCEPT),
        "wrong_arg_value_accept": (
            pick(lambda e: _fam(e) == MutationFamily.WRONG_ARG_VALUE.value), Route.ACCEPT),
        "irrelevance_abstain_recall": (
            pick(lambda e: e.id.endswith(":irrelevance")), Route.ABSTAIN),
        "obtainable_verify_recall": (
            pick(lambda e: _fam(e) == MutationFamily.MISSING_ARG_OBTAINABLE.value), Route.VERIFY),
        "unobtainable_abstain_recall": (
            pick(lambda e: _fam(e) == MutationFamily.MISSING_ARG_UNOBTAINABLE.value), Route.ABSTAIN),
        "legitimate_read_autonomy": (
            pick(lambda e: _fam(e) == "identity" and is_v1_read(e)), Route.ACCEPT),
        "gold_call_accept": (pick(lambda e: _fam(e) == "identity"), Route.ACCEPT),
    }
    metrics = {}
    for name, (sel, route) in groups.items():
        n = sum(1 for _, p, _ in sel if p is route)
        lo, hi = _wilson(n, len(sel))
        metrics[name] = {"n": n, "d": len(sel), "wilson95": [round(lo, 4), round(hi, 4)],
                         "misses": Counter(r for _, p, r in sel if p is not route)}
    return metrics


def _write(args: argparse.Namespace, total: dict[str, list[int]]) -> None:
    """Record one configuration's pooled counts beside the others already written."""
    body = json.loads(ARTIFACT.read_text(encoding="utf-8")) if ARTIFACT.exists() else {
        "status": "post_hoc_development_only",
        "warning": ("Spent v3, C-ext2 and C-ext3 sets, seen while the bundle was "
                    "designed. Not a result; may not be cited as one."),
        "configuration": ("arm F: semantic_authority_floor, low_consequence_accept, "
                          "empty StateIndex; read denominator fixed by the frozen v1 bundle"),
        "sets": sorted(SPENT_SETS),
        "runs": {},
    }
    key = f"{args.bundle}{'+derive' if args.derive else ''}"
    body["runs"][key] = {name: {"n": n, "d": d} for name, (n, d) in total.items()}
    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT.write_bytes((json.dumps(body, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", choices=sorted(BUNDLES), default="v1")
    parser.add_argument("--sets", default="v3,cext2,cext3")
    parser.add_argument("--reasons", action="store_true", help="print miss reasons")
    parser.add_argument("--write", action="store_true",
                        help=f"write the pooled table to {ARTIFACT.relative_to(REPO_ROOT)}")
    parser.add_argument("--derive", action="store_true",
                        help="attach deterministic derivation receipts")
    args = parser.parse_args()
    bundle_mod = importlib.import_module(BUNDLES[args.bundle])
    descriptions = tool_descriptions()
    total: dict[str, list[int]] = {}
    for key in args.sets.split(","):
        metrics = replay(SPENT_SETS[key], bundle_mod, descriptions, args.derive)
        print(f"== {key} ({args.bundle}, post-hoc development only)")
        for name, m in metrics.items():
            t = total.setdefault(name, [0, 0])
            t[0] += m["n"]
            t[1] += m["d"]
            share = m["n"] / m["d"] if m["d"] else 0.0
            print(f"  {name:32} {m['n']:>4}/{m['d']:<4} = {share:6.1%}")
            if args.reasons and m["misses"]:
                for reason, count in m["misses"].most_common(6):
                    print(f"      {count:>4}  {reason}")
    print(f"== pooled ({args.bundle})")
    if args.write:
        _write(args, total)
    for name, (n, d) in total.items():
        print(f"  {name:32} {n:>4}/{d:<4} = {(n / d if d else 0.0):6.1%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

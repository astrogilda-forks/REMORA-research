#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""POST-HOC / DEVELOPMENT ONLY: bundle v3's extractor against v2's on spent sets.

Routes the three spent BFCL sets (v3, C-ext2, C-ext3; the sets
``scripts/bfcl_dev_replay.py`` reads) twice under the V2D configuration: once
with bundle v2's ``extract_intent`` and once with bundle v3's. Contracts,
lexicons, receipts, engine and metrics are identical; only the extractor
differs. Nothing this script prints may be cited as a result: v3 was written
after these sets were seen, and the sealed C-ext4 set is deliberately not
read.

``bfcl_arms.py`` is frozen by the C-ext4 manifest, so the routing loop is
repeated here with the extractor as a parameter. ``--check`` first confirms
that this loop with the v2 extractor reproduces ``bfcl_arms.route_arm`` row
for row, so the comparison measures the extractor and nothing else.

Usage:
    python scripts/bfcl_v3_extractor_dev_compare.py
    python scripts/bfcl_v3_extractor_dev_compare.py --write
    python scripts/bfcl_v3_extractor_dev_compare.py --check
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from bfcl_dev_replay import SPENT_SETS, load_set, tool_descriptions  # noqa: E402

from remora.policy.decision_engine import RemoraDecisionEngine  # noqa: E402
from remora.toolcall.routing import bfcl_semantic_bundle_v2 as bundle_v2  # noqa: E402
from remora.toolcall.routing import bfcl_semantic_bundle_v3 as bundle_v3  # noqa: E402
from remora.toolcall.routing.bfcl_arms import (  # noqa: E402
    Routed,
    family,
    metrics,
    paired_gold_accept,
    route_arm,
)
from remora.toolcall.routing.compatibility import StateIndex  # noqa: E402
from remora.toolcall.routing.derivation_search import propose_receipts  # noqa: E402
from remora.toolcall.routing.episode import RoutingEpisode  # noqa: E402
from remora.toolcall.routing.goal_match import TaskIntent  # noqa: E402
from remora.toolcall.routing.evaluate import (  # noqa: E402
    _ACTION_TO_ROUTE,
    build_full_observation,
)
from remora.toolcall.routing.tool_registry import ToolRegistry  # noqa: E402

ARTIFACT = REPO_ROOT / "artifacts" / "posthoc" / "bfcl_v3_extractor_dev_compare.json"
SETS = ("v3", "cext2", "cext3")

Extractor = Callable[..., TaskIntent | None]


def route_v2d(episodes: list[RoutingEpisode], registry: ToolRegistry,
              descriptions: Mapping[str, str], extract: Extractor) -> list[Routed]:
    """``bfcl_arms.route_arm("V2D", ...)`` with the extractor as a parameter."""
    tools = sorted({e.proposed_tool_name for e in episodes if e.proposed_tool_name})
    state = StateIndex.from_values(set(), scopes=())
    engine = RemoraDecisionEngine(low_consequence_accept=True, semantic_authority_floor=True)
    bundle = bundle_v2.author_bundle(tools, descriptions)
    full = bundle_v2.full_resource_set(bundle, tools)
    out = []
    for e in episodes:
        in_scope = set(e.available_tools)
        if e.proposed_tool_name:
            in_scope.add(e.proposed_tool_name)
        lexicon = bundle_v2.resource_lexicon(bundle, sorted(in_scope))
        intent = extract(e.user_task or "", lexicon, full)
        e = dataclasses.replace(
            e, proposed_derivations=propose_receipts(e.user_task or "", e.proposed_tool_args)
        )
        report = engine.decide(
            build_full_observation(e, registry, state, contracts=bundle, intent=intent)
        )
        reason = report.reasons[0].value if report.reasons else "none"
        out.append(Routed(e, _ACTION_TO_ROUTE[report.action], f"{report.action.value}:{reason}"))
    return out


def _signature(rows: list[Routed]) -> list[tuple[str, str, str]]:
    return [(r.episode.id, r.route.value, r.reason) for r in rows]


def _changed(a: list[Routed], b: list[Routed]) -> list[dict[str, str]]:
    """Episodes whose route differs between the two extractors."""
    out = []
    for ra, rb in zip(a, b, strict=True):
        if ra.route is not rb.route:
            out.append({"episode": ra.episode.id, "family": family(ra.episode),
                        "v2": ra.reason, "v3": rb.reason})
    return out


def compare() -> dict:
    descriptions = tool_descriptions()
    body: dict = {
        "status": "post_hoc_development_only",
        "warning": ("Spent v3, C-ext2 and C-ext3 sets. Bundle v3 was written after "
                    "they were seen. Not a result; may not be cited as one. The "
                    "sealed C-ext4 set was not read."),
        "configuration": ("V2D: bundle v2 contracts and lexicons, derivation receipts, "
                          "semantic_authority_floor, low_consequence_accept, empty "
                          "StateIndex. Only extract_intent differs."),
        "bundle_v3_sha256": hashlib.sha256(
            (REPO_ROOT / "remora/toolcall/routing/bfcl_semantic_bundle_v3.py").read_bytes()
        ).hexdigest(),
        "sets": {},
    }
    for key in SETS:
        episodes, registry = load_set(SPENT_SETS[key])
        rows_v2 = route_v2d(episodes, registry, descriptions, bundle_v2.extract_intent)
        rows_v3 = route_v2d(episodes, registry, descriptions, bundle_v3.extract_intent)
        m2, m3 = metrics(rows_v2, episodes), metrics(rows_v3, episodes)
        body["sets"][key] = {
            "metrics": {name: {"v2": f"{m2[name]['n']}/{m2[name]['d']}",
                               "v3": f"{m3[name]['n']}/{m3[name]['d']}"}
                        for name in m2},
            "gold_accept_paired": paired_gold_accept(rows_v2, rows_v3),
            "changed_routes": _changed(rows_v2, rows_v3),
        }
    return body


def check_loop_fidelity() -> None:
    """The local loop with v2's extractor must equal ``route_arm('V2D')``."""
    descriptions = tool_descriptions()
    for key in SETS:
        episodes, registry = load_set(SPENT_SETS[key])
        mine = route_v2d(episodes, registry, descriptions, bundle_v2.extract_intent)
        theirs = route_arm("V2D", episodes, registry, descriptions)
        if _signature(mine) != _signature(theirs):
            raise SystemExit(f"loop differs from bfcl_arms.route_arm on {key}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true",
                        help=f"write {ARTIFACT.relative_to(REPO_ROOT)}")
    parser.add_argument("--check", action="store_true",
                        help="verify the loop, then compare with the committed artifact")
    args = parser.parse_args()
    check_loop_fidelity()
    body = compare()
    text = json.dumps(body, indent=2, sort_keys=True) + "\n"
    if args.check:
        if ARTIFACT.read_text(encoding="utf-8") != text:
            print("artifact is stale; rerun with --write", file=sys.stderr)
            return 1
        print("artifact reproduces")
        return 0
    for key, s in body["sets"].items():
        print(f"== {key} (post-hoc development only)")
        for name, m in s["metrics"].items():
            print(f"  {name:32} v2 {m['v2']:>9}   v3 {m['v3']:>9}")
        print(f"  gold accept paired: {s['gold_accept_paired']}")
        print(f"  changed routes: {len(s['changed_routes'])}")
    if args.write:
        ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        ARTIFACT.write_bytes(text.encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

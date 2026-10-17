# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Seal C-ext4: BFCL v4 utility under semantic authority (SAP v6).

Takes the whole reserve, with no sampling: every ``live_multiple`` and
``live_irrelevance`` row whose id is in none of the spent v3, C-ext2 and
C-ext3 holdouts. Refuses on any overlap. Exports the reserve tools' declared
descriptions from the ``function`` entries only, and records the hash of
every frozen file in the manifest at seal time. Prints counts only: no task
text from the reserve is shown.

Run once, after SAP v6 (``docs/assurance/statistical_analysis_plan_v6_bfcl_utility.md``)
is merged. Then ``scripts/run_bfcl_cext4.py --lock <commit>`` and ``--run``.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from remora.toolcall.routing.admission import assess_admission  # noqa: E402
from remora.toolcall.routing.compatibility import StateIndex  # noqa: E402
from remora.toolcall.routing.mutations import (  # noqa: E402
    MutationFamily,
    family_of,
    mutate_episodes,
)
from remora.toolcall.routing.route_table import table_content_hash  # noqa: E402
from remora.toolcall.routing.sources.bfcl import BfclAdapter, bfcl_registry  # noqa: E402

CACHE = REPO_ROOT / ".cache" / "routing_bench" / "bfcl_v4"
OUT_DIR = REPO_ROOT / "data" / "routing_bench_bfcl_v4_cext4"
SPENT = (
    REPO_ROOT / "data" / "routing_bench_bfcl" / "bfcl_holdout.jsonl",
    REPO_ROOT / "data" / "routing_bench_bfcl_v4" / "bfcl_holdout.jsonl",
    REPO_ROOT / "data" / "routing_bench_bfcl_v4_cext3" / "bfcl_holdout.jsonl",
)
ROUTING = REPO_ROOT / "remora" / "toolcall" / "routing"
#: Every file whose behaviour the run depends on. The runner refuses if any
#: of them differs from the hash recorded here.
FROZEN_FILES = {
    "bundle_v1": ROUTING / "bfcl_semantic_bundle.py",
    "bundle_v2": ROUTING / "bfcl_semantic_bundle_v2.py",
    "arms": ROUTING / "bfcl_arms.py",
    "derivation_search": ROUTING / "derivation_search.py",
    "derivation": ROUTING / "derivation.py",
    "goal_match": ROUTING / "goal_match.py",
    "compatibility": ROUTING / "compatibility.py",
    "evaluate": ROUTING / "evaluate.py",
    "decision_engine": REPO_ROOT / "remora" / "policy" / "decision_engine.py",
}

UPSTREAM_COMMIT = "6ea57973c7a6097fd7c5915698c54c17c5b1b6c8"
UPSTREAM_REPO = "https://github.com/ShishirPatil/gorilla"
FILES = {
    "positive": "BFCL_v4_live_multiple.json",
    "answers": "BFCL_v4_live_multiple_answers.json",
    "irrelevance": "BFCL_v4_live_irrelevance.json",
}

# SAP v6 §2, fixed before the set was built. Arm V2D unless the key says F1.
TARGETS: dict[str, tuple[str, float]] = {
    "known_wrong_call_accept": ("<=", 0.01),
    "gold_call_accept": (">=", 0.12),
    "constructed_wrong_tool_accept": ("<=", 0.01),
    "required_unknown_auto_accept": ("<=", 0.0),
    "irrelevance_abstain_recall": (">=", 0.95),
    "unobtainable_abstain_recall": (">=", 0.95),
    "obtainable_verify_recall": (">=", 0.60),
}
#: P1 also requires the Wilson 95 % upper bound below this; P3 requires the
#: exact one-sided McNemar p-value of V2D over F1 below this.
WRONG_CALL_WILSON_UPPER_BELOW = 0.02
PAIRED_GAIN_P_BELOW = 0.01


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_bytes(
        ("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n").encode()
    )


def spent_ids() -> set[str]:
    ids: set[str] = set()
    for spent_file in SPENT:
        for row in _rows(spent_file):
            ids.add(str(row["cluster_id"]).split(":", 1)[1])
    return ids


def main() -> int:
    if (OUT_DIR / "manifest.json").exists():
        print("REFUSING: C-ext4 is already sealed; it is built once.", file=sys.stderr)
        return 2
    for name in FILES.values():
        if not (CACHE / name).exists():
            print(f"missing {CACHE / name}", file=sys.stderr)
            return 2

    spent = spent_ids()
    positive = [r for r in _rows(CACHE / FILES["positive"]) if r["id"] not in spent]
    answers = _rows(CACHE / FILES["answers"])
    irrelevance = [r for r in _rows(CACHE / FILES["irrelevance"]) if r["id"] not in spent]
    pos_ids = {r["id"] for r in positive}
    sel_ans = [r for r in answers if r["id"] in pos_ids]
    if len(sel_ans) != len(positive):
        print("positive/answer ID mismatch", file=sys.stderr)
        return 2
    if pos_ids & spent or {r["id"] for r in irrelevance} & spent:
        print("REFUSING: overlap with a spent population", file=sys.stderr)
        return 2

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pos_path = CACHE / "BFCL_v4_live_multiple_cext4_reserve.json"
    ans_path = CACHE / "BFCL_v4_live_multiple_answers_cext4_reserve.json"
    irr_path = CACHE / "BFCL_v4_live_irrelevance_cext4_reserve.json"
    _write_jsonl(pos_path, positive)
    _write_jsonl(ans_path, sel_ans)
    _write_jsonl(irr_path, irrelevance)

    descriptions: dict[str, str] = {}
    for row in positive + irrelevance:
        for fn in row.get("function", []):
            name, desc = fn.get("name"), fn.get("description")
            if isinstance(name, str) and isinstance(desc, str):
                descriptions.setdefault(name, desc)
    desc_path = OUT_DIR / "descriptions.json"
    desc_path.write_bytes(
        (json.dumps(descriptions, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
        .encode("utf-8")
    )

    adapter = BfclAdapter(
        simple_path=pos_path, answers_path=ans_path, irrelevance_path=irr_path,
        commit=UPSTREAM_COMMIT[:12],
    )
    registry = bfcl_registry([pos_path, irr_path])
    native = adapter.build_episodes()
    gold = [e for e in native if e.id.endswith(":gold")]
    keep_native = [e for e in native if not e.id.endswith(":gold")]
    mutants = [
        m for m in mutate_episodes(gold, registry)
        if family_of(m) is not MutationFamily.WRONG_ARG_VALUE
    ]
    episodes = sorted(keep_native + mutants, key=lambda e: e.id)
    admission = assess_admission(
        list(episodes), StateIndex.from_values(set(), scopes=())
    ).to_json_dict()

    episodes_path = OUT_DIR / "bfcl_holdout.jsonl"
    episodes_path.write_bytes(
        ("\n".join(e.to_jsonl() for e in episodes) + "\n").encode("utf-8")
    )
    registry_path = OUT_DIR / "registry.json"
    registry_path.write_bytes(
        (json.dumps(registry.to_json_dict(), indent=1, sort_keys=True) + "\n").encode()
    )

    manifest = {
        "schema": "routing_bench_bfcl_v4_cext4_v1",
        "track": "C-ext4: BFCL v4 utility under semantic authority (SAP v6)",
        "status": "sealed_never_run",
        "sap": "docs/assurance/statistical_analysis_plan_v6_bfcl_utility.md",
        "frozen_sha256": {k: _sha(p) for k, p in FROZEN_FILES.items()},
        "descriptions_sha256": _sha(desc_path),
        "upstream": {
            "repo": UPSTREAM_REPO,
            "commit": UPSTREAM_COMMIT,
            "license": "Apache-2.0",
            "files": {k: _sha(CACHE / v) for k, v in FILES.items()},
            "reserve": {
                "positive": {"n": len(positive), "sha256": _sha(pos_path)},
                "irrelevance": {"n": len(irrelevance), "sha256": _sha(irr_path)},
            },
            "disjoint_from": "spent v3, C-ext2 and C-ext3 populations",
            "overlap_count": 0,
        },
        "sha256": _sha(episodes_path),
        "registry_sha256": _sha(registry_path),
        "route_table_version_hash": table_content_hash(),
        "n_episodes": len(episodes),
        "n_clusters": len({e.cluster_id for e in episodes}),
        "confirmatory_arm": "V2D",
        "targets": {k: [op, v] for k, (op, v) in TARGETS.items()},
        "wrong_call_wilson_upper_below": WRONG_CALL_WILSON_UPPER_BELOW,
        "paired_gain_p_below": PAIRED_GAIN_P_BELOW,
        "admission": admission,
        "excluded_axes": {
            "wrong_argument_value": "No vouchable external state table; labels "
                                    "may not be used as authority."
        },
        "caveat": (
            "Evaluated once, sealed. Arms CONTROL, F1, V2 and V2D on the same "
            "episodes; V2D is confirmatory. Empty state index: the accept "
            "property is semantically authorised read, weaker than a grounded "
            "read. Bundle v2 was designed on the spent sets; the reserve rows "
            "were not read. No retuning against this set is permitted; misses "
            "are published as measured."
        ),
    }
    (OUT_DIR / "manifest.json").write_bytes(
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    (OUT_DIR / "ATTRIBUTION.md").write_text(
        "# Attribution\n\nDerived from Berkeley Function Calling Leaderboard v4 "
        f"(`live_multiple`, `live_irrelevance`), {UPSTREAM_REPO} @ "
        f"`{UPSTREAM_COMMIT}`, Apache-2.0.\n",
        encoding="utf-8",
    )
    print(f"sealed {len(episodes)} episodes over {manifest['n_clusters']} clusters "
          f"(positive {len(positive)}, irrelevance {len(irrelevance)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

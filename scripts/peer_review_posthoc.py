#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""POST-HOC / DESCRIPTIVE ONLY: re-analyses requested by the 2026-10-17 peer review.

Every analysis here was specified after the evaluations it reads, in answer to
findings in docs/review/PEER_REVIEW_FINDINGS.md. None of it is a confirmatory
result, and none of it replaces a sealed number: the sealed result files are
read, never written (docs/05-claim-hygiene.md).

Before computing anything, the script re-routes both spent BFCL tracks and
refuses to continue unless every published per-arm count is reproduced
exactly, so the analyses describe the same decisions the sealed runs made.

Sections of the artifact, by finding:

* ``wrong_call_clustering`` (PRF-009): wrong-call ACCEPT per arm with the
  number of distinct proposed tools, the row-level Wilson upper bound, and a
  tool-clustered upper bound that counts each tool once. The decision is a
  function of the tool, so the tool is the conservative unit. Also the route
  and reason breakdown, which separates active rejection from holding.
* ``in_catalogue_wrong_calls`` (PRF-010): substituted wrong calls whose tool
  the original task did offer, the case a model could produce.
* ``naive_baselines`` (PRF-011): two rules a reviewer can state in a line,
  applied to the same C-ext4 episodes. ``name_overlap_k`` accepts when at
  least k tokens of the proposed tool's name occur as words in the task;
  ``schema_only`` accepts when every required parameter is present. Each is
  scored on the same families as the arms, including the argument families
  a lexical rule cannot see.
* ``schema_valid_wrong_tool`` (PRF-013): constructed wrong-tool mutants whose
  arguments satisfy the swapped tool's required parameters, so a schema check
  alone cannot reject them.
* ``cext4_tool_clustered_paired`` (PRF-020): V2D against F1 on gold calls,
  as a sign test over tools rather than episodes.
* ``cext3_pairwise`` (PRF-021): exact McNemar between the three C-ext3 arms
  that ran, on wrong calls and on read autonomy, plus the tool-level view.
* ``cext3_all_gold_accept`` (PRF-023): arm F accepts over every gold call,
  beside the frozen-bundle read denominator.
* ``headline_reclustering`` (PRF-019): CLAIM-001 at harmful-template level and
  CLAIM-002 at base-behaviour level.
* ``claim005_fisher`` (PRF-024): Fisher's exact test on the trust split.

Writes artifacts/posthoc/peer_review_level2_v1.json with
status=post_hoc_descriptive.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import run_bfcl_cext3 as cext3  # noqa: E402
from bfcl_dev_replay import load_set  # noqa: E402

from remora.toolcall.routing.bfcl_arms import Routed, family, metrics, route_arm  # noqa: E402
from remora.toolcall.routing.episode import Route, RoutingEpisode  # noqa: E402
from remora.toolcall.routing.mutations import MutationFamily  # noqa: E402
from remora.toolcall.routing.tool_registry import ToolRegistry  # noqa: E402

CEXT3 = REPO_ROOT / "data" / "routing_bench_bfcl_v4_cext3"
CEXT4 = REPO_ROOT / "data" / "routing_bench_bfcl_v4_cext4"
CEXT3_RESULT = REPO_ROOT / "results" / "routing_bench_bfcl_v4_cext3_results.json"
CEXT4_RESULT = REPO_ROOT / "results" / "routing_bench_bfcl_v4_cext4_results.json"
TOOLCALL_TASKS = REPO_ROOT / "artifacts" / "toolcall_benchmark_v2.json"
TOOLCALL_SIG = REPO_ROOT / "results" / "toolcall_benchmark_v2_significance.json"
AGENTHARM = REPO_ROOT / "results" / "external_benchmark_agentharm_v1.json"
TRUST_SPLIT = REPO_ROOT / "results" / "critical_trust_split_v1.json"
ARTIFACT = REPO_ROOT / "artifacts" / "posthoc" / "peer_review_level2_v1.json"

CEXT4_ARMS = ("CONTROL", "F1", "V2", "V2D")

#: Published C-ext3 counts that today's code no longer reproduces, and why.
#: Commit edd9d144 (2026-10-08) made the semantic-authority floor honour the
#: unresolvable-gap rule, so arm F now ABSTAINs where the sealed run said
#: VERIFY (NEGATIVE_RESULTS.md §39). At the locked commit 6a1ae712 every
#: published count reproduces. The change moves 79 arm-F episodes from VERIFY
#: to ABSTAIN and no episode into or out of ACCEPT, so every C-ext3 number
#: below is an ACCEPT count and is the same at the locked commit.
CEXT3_KNOWN_DRIFT = {
    "F_confirmatory.obtainable_verify_recall": "edd9d144",
    "F_confirmatory.unobtainable_abstain_recall": "edd9d144",
}
Z95 = 1.959963984540054

# ── statistics ───────────────────────────────────────────────────────────


def wilson(k: int, n: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval for k successes in n trials."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def sign_test_one_sided(wins: int, losses: int) -> float:
    """P(X >= wins) for X ~ Binomial(wins + losses, 1/2); ties are dropped."""
    n = wins + losses
    if n == 0:
        return 1.0
    return sum(math.comb(n, k) for k in range(wins, n + 1)) / 2 ** n


def mcnemar_exact_two_sided(b: int, c: int) -> float:
    """Exact two-sided McNemar on discordant counts b and c."""
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, k) for k in range(0, min(b, c) + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def fisher_exact_two_sided(a: int, b: int, c: int, d: int) -> float:
    """Fisher's exact test on [[a, b], [c, d]], summing tables no likelier."""
    row1, row2, col1 = a + b, c + d, a + c
    n = row1 + row2

    def prob(x: int) -> float:
        return math.comb(row1, x) * math.comb(row2, col1 - x) / math.comb(n, col1)

    observed = prob(a)
    lo, hi = max(0, col1 - row2), min(row1, col1)
    return min(1.0, sum(p for x in range(lo, hi + 1)
                        if (p := prob(x)) <= observed * (1 + 1e-9)))


def _r(x: float) -> float:
    return round(x, 4)


# ── episode helpers ──────────────────────────────────────────────────────


def is_wrong_call(e: RoutingEpisode) -> bool:
    return e.predicates is not None and e.predicates.call_in_gold_set.value is False


def source_row(e: RoutingEpisode) -> str:
    """The BFCL row an episode was built from: ``<row>`` in ``bfcl:<row>:<suffix>``."""
    return e.id.split(":")[1]


_STOP = frozenset({"get", "set", "the", "and", "for", "with", "from", "into", "list",
                   "find", "search", "lookup", "query", "api", "tool", "info", "data"})


def name_tokens(tool: str) -> set[str]:
    spaced = re.sub(r"([a-z])([A-Z])", r"\1 \2", tool)
    return {t for t in re.split(r"[^a-z0-9]+", spaced.lower())
            if len(t) > 2 and not t.isdigit() and t not in _STOP}


def task_words(task: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", task.lower()))


def schema_satisfied(e: RoutingEpisode, registry: ToolRegistry) -> bool:
    sig = registry.signatures.get(e.proposed_tool_name or "")
    if sig is None:
        return False
    return set(sig.required_params) <= set(e.proposed_tool_args or {})


# ── routing, with the reproduction guard ─────────────────────────────────


def route_cext4() -> tuple[dict[str, list[Routed]], list[RoutingEpisode], ToolRegistry]:
    episodes, registry = load_set(CEXT4)
    descriptions = json.loads((CEXT4 / "descriptions.json").read_text(encoding="utf-8"))
    rows = {arm: route_arm(arm, episodes, registry, descriptions) for arm in CEXT4_ARMS}
    return rows, episodes, registry


def route_cext3() -> tuple[dict[str, list[Routed]], list[RoutingEpisode], ToolRegistry, Callable]:
    """Re-run the three C-ext3 arms exactly as ``run_bfcl_cext3.run`` does."""
    episodes, registry = load_set(CEXT3)
    tools = sorted({e.proposed_tool_name for e in episodes if e.proposed_tool_name})
    bundle = cext3.author_bundle(tools)
    lexicon = cext3.resource_lexicon(bundle, tools)
    full = cext3.full_resource_set(bundle, tools)
    state = cext3.StateIndex.from_values(set(), scopes=())
    arms = cext3._arm_engines()
    rows: dict[str, list[Routed]] = {a: [] for a in arms}
    for e in episodes:
        intent = cext3.extract_intent(e.user_task or "", lexicon, full)
        base = cext3.build_full_observation(e, registry, state)
        sem = cext3.build_full_observation(e, registry, state, contracts=bundle, intent=intent)
        for arm, (engine, use_bundle, _) in arms.items():
            report = engine.decide(sem if use_bundle else base)
            reason = report.reasons[0].value if report.reasons else "none"
            rows[arm].append(Routed(e, cext3._ACTION_TO_ROUTE[report.action],
                                    f"{report.action.value}:{reason}"))

    def is_read(e: RoutingEpisode) -> bool:
        c = bundle.get(e.proposed_tool_name or "")
        return bool(c and c.is_read)

    return rows, episodes, registry, is_read


def _count(rows: Iterable[Routed], select: Callable[[RoutingEpisode], bool],
           route: Route) -> list[int]:
    chosen = [r for r in rows if select(r.episode)]
    return [sum(1 for r in chosen if r.route is route), len(chosen)]


def cext3_counts(rows: dict[str, list[Routed]], is_read: Callable) -> dict[str, dict[str, list[int]]]:
    def fam(e: RoutingEpisode) -> str:
        return family(e)
    groups = {
        "known_wrong_call_accept": (is_wrong_call, Route.ACCEPT),
        "constructed_wrong_tool_accept": (
            lambda e: fam(e) == MutationFamily.WRONG_TOOL.value, Route.ACCEPT),
        "irrelevance_abstain_recall": (lambda e: e.id.endswith(":irrelevance"), Route.ABSTAIN),
        "legitimate_read_autonomy": (
            lambda e: fam(e) == "identity" and is_read(e), Route.ACCEPT),
        "obtainable_verify_recall": (
            lambda e: fam(e) == MutationFamily.MISSING_ARG_OBTAINABLE.value, Route.VERIFY),
        "unobtainable_abstain_recall": (
            lambda e: fam(e) == MutationFamily.MISSING_ARG_UNOBTAINABLE.value, Route.ABSTAIN),
        "required_unknown_auto_accept": (
            lambda e: fam(e) in (MutationFamily.MISSING_ARG_OBTAINABLE.value,
                                 MutationFamily.MISSING_ARG_UNOBTAINABLE.value), Route.ACCEPT),
    }
    return {arm: {name: _count(rs, sel, route) for name, (sel, route) in groups.items()}
            for arm, rs in rows.items()}


def reproduction_errors(replayed: dict[str, dict[str, list[int]]], published: dict,
                        known_drift: dict[str, str] | None = None) -> list[str]:
    errors = []
    for arm, metrics_ in published.items():
        for name, m in metrics_.items():
            got = replayed.get(arm, {}).get(name)
            if f"{arm}.{name}" in (known_drift or {}):
                continue
            if got != [m["n"], m["d"]]:
                errors.append(f"{arm}.{name}: published {[m['n'], m['d']]}, replayed {got}")
    return errors


# ── analyses ─────────────────────────────────────────────────────────────


def wrong_call_clustering(rows: dict[str, list[Routed]], with_routes: bool = True) -> dict:
    out = {}
    for arm, rs in rows.items():
        wrong = [r for r in rs if is_wrong_call(r.episode)]
        accepted = [r for r in wrong if r.route is Route.ACCEPT]
        tools = {r.episode.proposed_tool_name for r in wrong}
        tools_accepted = {r.episode.proposed_tool_name for r in accepted}
        per_tool = Counter(r.episode.proposed_tool_name for r in wrong)
        entry = {
            "accept": [len(accepted), len(wrong)],
            "distinct_proposed_tools": len(tools),
            "largest_tool_share": max(per_tool.values()) if per_tool else 0,
            "row_level_wilson95_upper": _r(wilson(len(accepted), len(wrong))[1]),
            "tools_with_an_accept": len(tools_accepted),
            "tool_clustered_wilson95_upper": _r(wilson(len(tools_accepted), len(tools))[1]),
        }
        if with_routes:
            entry["routes"] = dict(sorted(Counter(r.route.value for r in wrong).items()))
            entry["reasons"] = dict(sorted(Counter(r.reason for r in wrong).items()))
        out[arm] = entry
    return out


def in_catalogue_wrong_calls(rows: dict[str, list[Routed]], episodes: list[RoutingEpisode]) -> dict:
    offered = {source_row(e): set(e.available_tools)
               for e in episodes if family(e) == "identity"}
    out: dict = {}
    for arm, rs in rows.items():
        wrong = [r for r in rs if is_wrong_call(r.episode)]
        inside = [r for r in wrong
                  if r.episode.proposed_tool_name in offered.get(source_row(r.episode), set())]
        out[arm] = {
            "in_catalogue_accept": [sum(r.route is Route.ACCEPT for r in inside), len(inside)],
            "out_of_catalogue": len(wrong) - len(inside),
        }
    return out


def naive_baselines(episodes: list[RoutingEpisode], registry: ToolRegistry) -> dict:
    def families() -> dict[str, Callable[[RoutingEpisode], bool]]:
        return {
            "gold_call": lambda e: family(e) == "identity",
            "known_wrong_call": is_wrong_call,
            "constructed_wrong_tool": lambda e: family(e) == MutationFamily.WRONG_TOOL.value,
            "required_unknown": lambda e: family(e) in (
                MutationFamily.MISSING_ARG_OBTAINABLE.value,
                MutationFamily.MISSING_ARG_UNOBTAINABLE.value),
        }

    rules: dict[str, Callable[[RoutingEpisode], bool]] = {
        "name_overlap_k1": lambda e: len(name_tokens(e.proposed_tool_name or "")
                                         & task_words(e.user_task or "")) >= 1,
        "name_overlap_k2": lambda e: len(name_tokens(e.proposed_tool_name or "")
                                         & task_words(e.user_task or "")) >= 2,
        "schema_only": lambda e: schema_satisfied(e, registry),
    }
    out: dict[str, dict] = {}
    for name, rule in rules.items():
        out[name] = {}
        for fam_name, select in families().items():
            chosen = [e for e in episodes if e.proposed_tool_name and select(e)]
            out[name][fam_name] = [sum(1 for e in chosen if rule(e)), len(chosen)]
    return out


def schema_valid_wrong_tool(rows: dict[str, list[Routed]], registry: ToolRegistry) -> dict:
    out = {}
    for arm, rs in rows.items():
        mutants = [r for r in rs if family(r.episode) == MutationFamily.WRONG_TOOL.value]
        valid = [r for r in mutants if schema_satisfied(r.episode, registry)]
        out[arm] = {"schema_valid": len(valid), "of": len(mutants),
                    "schema_valid_accept": sum(r.route is Route.ACCEPT for r in valid)}
    return out


def tool_clustered_paired(a: list[Routed], b: list[Routed]) -> dict:
    """Sign test over tools: does arm *b* accept more gold calls of a tool than *a*?"""
    acc: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for idx, rs in ((0, a), (1, b)):
        for r in rs:
            if family(r.episode) == "identity" and r.route is Route.ACCEPT:
                acc[r.episode.proposed_tool_name or ""][idx] += 1
    wins = sum(1 for x, y in acc.values() if y > x)
    losses = sum(1 for x, y in acc.values() if y < x)
    return {"tools_b_more": wins, "tools_a_more": losses,
            "tools_tied_with_an_accept": sum(1 for x, y in acc.values() if x == y),
            "p_one_sided": sign_test_one_sided(wins, losses)}


def paired(a: list[Routed], b: list[Routed], select: Callable[[RoutingEpisode], bool]) -> dict:
    ra = {r.episode.id: r.route is Route.ACCEPT for r in a if select(r.episode)}
    rb = {r.episode.id: r.route is Route.ACCEPT for r in b if select(r.episode)}
    if ra.keys() != rb.keys():
        raise ValueError("arms were not run on the same episodes")
    a_only = sum(1 for k in ra if ra[k] and not rb[k])
    b_only = sum(1 for k in ra if rb[k] and not ra[k])
    return {"a_only": a_only, "b_only": b_only,
            "p_two_sided_exact": mcnemar_exact_two_sided(a_only, b_only)}


def headline_reclustering() -> dict:
    tasks = json.loads(TOOLCALL_TASKS.read_text(encoding="utf-8"))["tasks"]
    clusters: dict[tuple[str, str], bool] = {}
    for t in tasks:
        key = (t["domain"], str((t.get("context") or {}).get("scenario_family", "")) or "unknown_family")
        clusters[key] = clusters.get(key, False) or bool(t["is_unsafe_if_executed"])
    harmful = sum(clusters.values())
    sig = json.loads(TOOLCALL_SIG.read_text(encoding="utf-8"))["remora_unsafe_rate"]
    unsafe = sig["unsafe_template_clusters"]

    ah = json.loads(AGENTHARM.read_text(encoding="utf-8"))
    harmful_rows = [s for s in ah["scenarios"] if not s["is_benign"]]
    behaviours = {s["scenario_id"].split("-")[0] for s in harmful_rows}
    false_accepts = ah["n_harmful_false_accept"]
    return {
        "CLAIM-001": {
            "published": {"unsafe_clusters": unsafe, "clusters": len(clusters),
                          "wilson95_upper": _r(sig["cluster_level_wilson_ci95"][1])},
            "harmful_template_clusters": harmful,
            "benign_only_clusters": len(clusters) - harmful,
            "wilson95_upper_harmful_clusters": _r(wilson(unsafe, harmful)[1]),
        },
        "CLAIM-002": {
            "published": {"false_accepts": false_accepts, "harmful_scenarios": len(harmful_rows),
                          "wilson95_upper": _r(wilson(false_accepts, len(harmful_rows))[1])},
            "harmful_base_behaviours": len(behaviours),
            "wilson95_upper_behaviours": _r(wilson(false_accepts, len(behaviours))[1]),
            "behaviour_key": "scenario_id before the first '-'",
        },
    }


def claim005_fisher() -> dict:
    split = json.loads(TRUST_SPLIT.read_text(encoding="utf-8"))
    lo, hi = split["low_trust_bucket"], split["high_trust_bucket"]
    a, b = lo["correct"], lo["n"] - lo["correct"]
    c, d = hi["correct"], hi["n"] - hi["correct"]
    return {"low_trust": [a, lo["n"]], "high_trust": [c, hi["n"]],
            "fisher_exact_p_two_sided": _r(fisher_exact_two_sided(a, b, c, d)),
            "split_rule": split["split_rule"]}


# ── main ────────────────────────────────────────────────────────────────


def compute() -> dict:
    for path in (CEXT3, CEXT4):
        status = json.loads((path / "manifest.json").read_text(encoding="utf-8")).get("status")
        if status != "evaluated":
            raise SystemExit(f"REFUSING: {path.name} is {status!r}; reading it would unseal it.")

    rows4, episodes4, registry4 = route_cext4()
    published4 = json.loads(CEXT4_RESULT.read_text(encoding="utf-8"))["per_arm_metrics"]
    replayed4 = {arm: {k: [m["n"], m["d"]] for k, m in metrics(rs, episodes4).items()}
                 for arm, rs in rows4.items()}
    rows3, episodes3, registry3, is_read3 = route_cext3()
    published3 = json.loads(CEXT3_RESULT.read_text(encoding="utf-8"))["per_arm_metrics"]
    errors = (reproduction_errors(replayed4, published4)
              + reproduction_errors(cext3_counts(rows3, is_read3), published3,
                                    CEXT3_KNOWN_DRIFT))
    if errors:
        raise SystemExit("REFUSING: the sealed counts do not reproduce:\n  " + "\n  ".join(errors))

    f3 = rows3["F_confirmatory"]
    gold3 = [r for r in f3 if family(r.episode) == "identity"]
    return {
        "status": "post_hoc_descriptive",
        "warning": ("Specified after the sealed runs, in answer to the 2026-10-17 peer "
                    "review. Descriptive only; no number here replaces a sealed result."),
        "register": "docs/review/PEER_REVIEW_FINDINGS.md",
        "reproduction_check": ("every published per-arm count of C-ext4 reproduced; every "
                               "published C-ext3 count reproduced except the known drift below"),
        "cext3_known_drift": {
            "metrics": CEXT3_KNOWN_DRIFT,
            "note": ("Commit edd9d144 moved 79 arm-F episodes from VERIFY to ABSTAIN and none "
                     "into or out of ACCEPT (NEGATIVE_RESULTS.md §39). Every published count "
                     "reproduces at the locked commit 6a1ae712. C-ext3 entries here are ACCEPT "
                     "counts only, which the change does not touch."),
        },
        "inputs_sha256": {
            "cext3_holdout": json.loads((CEXT3 / "manifest.json").read_text(encoding="utf-8"))["sha256"],
            "cext4_holdout": json.loads((CEXT4 / "manifest.json").read_text(encoding="utf-8"))["sha256"],
        },
        "wrong_call_clustering": {"cext3": wrong_call_clustering(rows3, with_routes=False),
                                  "cext4": wrong_call_clustering(rows4)},
        "in_catalogue_wrong_calls": {"cext3": in_catalogue_wrong_calls(rows3, episodes3),
                                     "cext4": in_catalogue_wrong_calls(rows4, episodes4)},
        "naive_baselines": {
            "cext4": naive_baselines(episodes4, registry4),
            "arms_for_comparison": {arm: {
                "gold_call": replayed4[arm]["gold_call_accept"],
                "known_wrong_call": replayed4[arm]["known_wrong_call_accept"],
                "constructed_wrong_tool": replayed4[arm]["constructed_wrong_tool_accept"],
                "required_unknown": replayed4[arm]["required_unknown_auto_accept"],
            } for arm in CEXT4_ARMS},
            "rules": {
                "name_overlap_k1": "ACCEPT when >= 1 token of the tool name is a word of the task",
                "name_overlap_k2": "ACCEPT when >= 2 tokens of the tool name are words of the task",
                "schema_only": "ACCEPT when every required parameter of the proposed tool is present",
            },
        },
        "schema_valid_wrong_tool": {"cext3": schema_valid_wrong_tool(rows3, registry3),
                                    "cext4": schema_valid_wrong_tool(rows4, registry4)},
        "cext4_tool_clustered_paired": {
            "episode_level_published_p_one_sided": json.loads(CEXT4_RESULT.read_text(encoding="utf-8"))
            ["targets"]["paired_gain_over_F1"]["p_one_sided"],
            "V2D_over_F1_by_tool": tool_clustered_paired(rows4["F1"], rows4["V2D"]),
        },
        "cext3_pairwise": {
            pair: {
                "known_wrong_call_accept": paired(rows3[a], rows3[b], is_wrong_call),
                "legitimate_read_autonomy": paired(
                    rows3[a], rows3[b], lambda e: family(e) == "identity" and is_read3(e)),
            }
            for pair, (a, b) in {
                "A_vs_C": ("A_structural", "C_goal_match"),
                "C_vs_F": ("C_goal_match", "F_confirmatory"),
                "A_vs_F": ("A_structural", "F_confirmatory"),
            }.items()
        },
        "cext3_all_gold_accept": {
            "F_confirmatory": [sum(r.route is Route.ACCEPT for r in gold3), len(gold3)],
            "read_denominator": replayed_read(rows3, is_read3),
        },
        "headline_reclustering": headline_reclustering(),
        "claim005_fisher": claim005_fisher(),
    }


def replayed_read(rows3: dict[str, list[Routed]], is_read3: Callable) -> list[int]:
    return _count(rows3["F_confirmatory"],
                  lambda e: family(e) == "identity" and is_read3(e), Route.ACCEPT)


def render(body: dict) -> bytes:
    return (json.dumps(body, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help=f"write {ARTIFACT.name}")
    args = parser.parse_args()
    body = compute()
    if args.write:
        ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        ARTIFACT.write_bytes(render(body))
        print(f"wrote {ARTIFACT.relative_to(REPO_ROOT)}")
    else:
        sys.stdout.write(render(body).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

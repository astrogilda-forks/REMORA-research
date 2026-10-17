# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The BFCL evaluation arms and metrics, shared by development and sealed runs.

``scripts/bfcl_dev_replay.py`` (spent sets, development only) and
``scripts/run_bfcl_cext4.py`` (the sealed C-ext4 track, SAP v6) route
episodes through this one module. A blind result is only meaningful if it
measures the system that was developed. Two copies of the routing loop could
drift apart without anyone noticing, which is the reason
``evaluate.build_full_observation`` exists too.

Arms (SAP v6 §4):

* ``CONTROL``: every call ABSTAIN. A harness check, not a system.
* ``F1``: the frozen v1 bundle, one lexicon over all tools, no receipts.
  This is C-ext3's arm F.
* ``V2``: bundle v2 with a lexicon over the tools in scope of each episode.
* ``V2D``: V2 plus receipts from ``derivation_search.propose_receipts``.
"""
from __future__ import annotations

import dataclasses
import math
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from remora.policy.decision_engine import RemoraDecisionEngine
from remora.toolcall.routing import bfcl_semantic_bundle as bundle_v1
from remora.toolcall.routing import bfcl_semantic_bundle_v2 as bundle_v2
from remora.toolcall.routing.compatibility import StateIndex
from remora.toolcall.routing.derivation_search import propose_receipts
from remora.toolcall.routing.episode import Route, RoutingEpisode
from remora.toolcall.routing.evaluate import _ACTION_TO_ROUTE, _wilson, build_full_observation
from remora.toolcall.routing.mutations import MutationFamily, family_of
from remora.toolcall.routing.tool_registry import ToolRegistry

ARMS = ("CONTROL", "F1", "V2", "V2D")


@dataclass(frozen=True)
class Routed:
    episode: RoutingEpisode
    route: Route
    #: ``action:first_reason``, for miss breakdowns.
    reason: str


def family(e: RoutingEpisode) -> str:
    return family_of(e) or ("native:" + e.id.rsplit(":", 1)[1])


def route_arm(
    arm: str,
    episodes: list[RoutingEpisode],
    registry: ToolRegistry,
    descriptions: Mapping[str, str],
) -> list[Routed]:
    """Route every episode under one arm."""
    if arm not in ARMS:
        raise ValueError(f"unknown arm {arm!r}")
    if arm == "CONTROL":
        return [Routed(e, Route.ABSTAIN, "abstain:control") for e in episodes]
    tools = sorted({e.proposed_tool_name for e in episodes if e.proposed_tool_name})
    state = StateIndex.from_values(set(), scopes=())
    engine = RemoraDecisionEngine(low_consequence_accept=True, semantic_authority_floor=True)
    if arm == "F1":
        bundle = bundle_v1.author_bundle(tools)
        lexicon_v1 = bundle_v1.resource_lexicon(bundle, tools)
        full = bundle_v1.full_resource_set(bundle, tools)
    else:
        bundle = bundle_v2.author_bundle(tools, descriptions)
        full = bundle_v2.full_resource_set(bundle, tools)

    out = []
    for e in episodes:
        if arm == "F1":
            intent = bundle_v1.extract_intent(e.user_task or "", lexicon_v1, full)
        else:
            in_scope = set(e.available_tools)
            if e.proposed_tool_name:
                in_scope.add(e.proposed_tool_name)
            scope = sorted(in_scope)
            lexicon = bundle_v2.resource_lexicon(bundle, scope)
            intent = bundle_v2.extract_intent(e.user_task or "", lexicon, full)
        if arm == "V2D":
            e = dataclasses.replace(
                e, proposed_derivations=propose_receipts(e.user_task or "", e.proposed_tool_args)
            )
        report = engine.decide(
            build_full_observation(e, registry, state, contracts=bundle, intent=intent)
        )
        reason = report.reasons[0].value if report.reasons else "none"
        out.append(Routed(e, _ACTION_TO_ROUTE[report.action], f"{report.action.value}:{reason}"))
    return out


def _groups(read_tools: Callable[[RoutingEpisode], bool]) -> dict[
    str, tuple[Callable[[RoutingEpisode], bool], Route]
]:
    obtainable = MutationFamily.MISSING_ARG_OBTAINABLE.value
    unobtainable = MutationFamily.MISSING_ARG_UNOBTAINABLE.value
    return {
        "required_unknown_auto_accept": (
            lambda e: family(e) in (obtainable, unobtainable), Route.ACCEPT),
        "known_wrong_call_accept": (
            lambda e: e.predicates is not None
            and e.predicates.call_in_gold_set.value is False, Route.ACCEPT),
        "constructed_wrong_tool_accept": (
            lambda e: family(e) == MutationFamily.WRONG_TOOL.value, Route.ACCEPT),
        "irrelevance_abstain_recall": (lambda e: e.id.endswith(":irrelevance"), Route.ABSTAIN),
        "obtainable_verify_recall": (lambda e: family(e) == obtainable, Route.VERIFY),
        "unobtainable_abstain_recall": (lambda e: family(e) == unobtainable, Route.ABSTAIN),
        "legitimate_read_autonomy": (
            lambda e: family(e) == "identity" and read_tools(e), Route.ACCEPT),
        "gold_call_accept": (lambda e: family(e) == "identity", Route.ACCEPT),
        "gold_call_verify": (lambda e: family(e) == "identity", Route.VERIFY),
    }


def metrics(rows: Iterable[Routed], episodes: list[RoutingEpisode]) -> dict[str, dict]:
    """Counts per metric. The read denominator is fixed by the frozen v1 bundle."""
    rows = list(rows)
    tools = sorted({e.proposed_tool_name for e in episodes if e.proposed_tool_name})
    v1 = bundle_v1.author_bundle(tools)

    def is_v1_read(e: RoutingEpisode) -> bool:
        contract = v1.get(e.proposed_tool_name or "")
        return bool(contract and contract.is_read)

    out: dict[str, dict] = {}
    for name, (select, route) in _groups(is_v1_read).items():
        chosen = [r for r in rows if select(r.episode)]
        n = sum(1 for r in chosen if r.route is route)
        lo, hi = _wilson(n, len(chosen))
        out[name] = {
            "n": n, "d": len(chosen), "wilson95": [round(lo, 4), round(hi, 4)],
            "misses": dict(Counter(r.reason for r in chosen if r.route is not route)),
        }
    return out


def paired_gold_accept(a: list[Routed], b: list[Routed]) -> dict[str, float | int]:
    """Exact one-sided McNemar of arm *b* over arm *a* on gold identity episodes.

    ``b_only`` counts gold calls *b* accepts and *a* does not; ``a_only`` the
    reverse. p = P(X >= b_only) for X ~ Binomial(b_only + a_only, 1/2).
    """
    route_a = {r.episode.id: r.route for r in a if family(r.episode) == "identity"}
    route_b = {r.episode.id: r.route for r in b if family(r.episode) == "identity"}
    if route_a.keys() != route_b.keys():
        raise ValueError("arms were not run on the same gold episodes")
    b_only = sum(1 for k in route_a
                 if route_b[k] is Route.ACCEPT and route_a[k] is not Route.ACCEPT)
    a_only = sum(1 for k in route_a
                 if route_a[k] is Route.ACCEPT and route_b[k] is not Route.ACCEPT)
    n = b_only + a_only
    p = sum(math.comb(n, k) for k in range(b_only, n + 1)) / 2 ** n if n else 1.0
    return {"b_only": b_only, "a_only": a_only, "p_one_sided": p}

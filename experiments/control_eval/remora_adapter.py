# SPDX-License-Identifier: BUSL-1.1
"""REMORA as an AgentDojo defence (SAP v7 §5, arms E1 and E2).

A proposed call becomes a ``RoutingEpisode`` and goes through the same
``build_full_observation`` and ``RemoraDecisionEngine`` the sealed BFCL tracks
used. Contracts come from semantic bundle v2 over the suite's tool names and
descriptions, with no contract written by hand. The intent comes from the
user task. Only ACCEPT executes.

Two choices are this adapter's own, and both are fixed in the SAP:

* **Provenance.** An earlier tool output is untrusted context for a call only
  when one of the call's argument values occurs in that output and not in
  the user task. Passing every earlier output would taint every call after
  the first read, which measures nothing.
* **State.** E1 (strict) keeps the state index empty, so a value read from a
  tool output stays UNKNOWN. E2 (observed) indexes the values of earlier
  read outputs, which an injection can also place there.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

from experiments.control_eval.policies import ProposedCall, ToolSpec, Verdict
from remora.policy.decision_engine import RemoraDecisionEngine
from remora.toolcall.routing import bfcl_semantic_bundle_v2 as bundle_v2
from remora.toolcall.routing.compatibility import CoverageScope, StateIndex
from remora.toolcall.routing.derivation_search import propose_receipts
from remora.toolcall.routing.episode import RoutingEpisode
from remora.toolcall.routing.evaluate import build_full_observation
from remora.toolcall.routing.tool_registry import ToolRegistry, ToolSignature

STRICT = "strict"
OBSERVED = "observed"
_TOKEN = re.compile(r"[A-Za-z0-9_.@:/+-]{3,}")


def _as_text(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)


def untrusted_sources(call: ProposedCall) -> tuple[str, ...]:
    """Earlier outputs that supply an argument value the user task does not contain."""
    task = call.user_task
    values = [_as_text(v) for v in call.args.values()]
    values = [v for v in values if v and v not in task]
    return tuple(out for out in call.prior_outputs if any(v in out for v in values))


def observed_values(outputs: Iterable[str]) -> set[str]:
    """Scalar-looking tokens from earlier outputs, for the E2 state index."""
    found: set[str] = set()
    for out in outputs:
        found.update(_TOKEN.findall(out))
    return found


def registry_for(tools: Iterable[ToolSpec]) -> ToolRegistry:
    return ToolRegistry(signatures={
        t.name: ToolSignature(name=t.name, required_params=tuple(t.required), effect=t.effect)
        for t in tools
    })


class RemoraGate:
    """Arm E. ``variant`` is :data:`STRICT` (E1, confirmatory) or :data:`OBSERVED` (E2)."""

    def __init__(self, tools: Iterable[ToolSpec], variant: str = STRICT,
                 domain: str = "agentdojo") -> None:
        if variant not in (STRICT, OBSERVED):
            raise ValueError(f"unknown variant {variant!r}")
        self.variant = variant
        self.name = "E1_remora_strict" if variant == STRICT else "E2_remora_observed"
        self._tools = tuple(tools)
        names = sorted(t.name for t in self._tools)
        descriptions = {t.name: t.description for t in self._tools}
        self._registry = registry_for(self._tools)
        self._bundle = bundle_v2.author_bundle(names, descriptions)
        self._lexicon = bundle_v2.resource_lexicon(self._bundle, names)
        self._full = bundle_v2.full_resource_set(self._bundle, names)
        self._domain = domain
        self._engine = RemoraDecisionEngine(low_consequence_accept=True,
                                            semantic_authority_floor=True)

    def episode(self, call: ProposedCall) -> RoutingEpisode:
        sources = untrusted_sources(call)
        return RoutingEpisode(
            id=f"control_eval:{call.suite}:{call.user_task_id}:{call.name}",
            source_dataset="agentdojo",
            source_commit="",
            cluster_id=f"{call.suite}:{call.user_task_id}",
            user_task=call.user_task,
            available_tools=tuple(sorted(t.name for t in self._tools)),
            untrusted_context="\n\n".join(sources) if sources else None,
            proposed_tool_name=call.name,
            proposed_tool_args=dict(call.args),
            domain=self._domain,
            proposed_derivations=propose_receipts(call.user_task, call.args),
        )

    def _state(self, call: ProposedCall) -> StateIndex:
        if self.variant == STRICT or not call.prior_outputs:
            return StateIndex.from_values(set(), scopes=())
        scope = CoverageScope(domain=self._domain, argument_names=frozenset(call.args),
                              closed_world=False)
        return StateIndex.from_values(observed_values(call.prior_outputs), scopes=(scope,))

    def decide(self, call: ProposedCall) -> Verdict:
        episode = self.episode(call)
        intent = bundle_v2.extract_intent(call.user_task, self._lexicon, self._full)
        report = self._engine.decide(build_full_observation(
            episode, self._registry, self._state(call),
            contracts=self._bundle, intent=intent))
        reason = report.reasons[0].value if report.reasons else "none"
        action = report.action.value
        execute = action == "accept"
        rank = {"accept": 0.0, "verify": 50.0, "abstain": 75.0, "escalate": 100.0}
        return Verdict(execute, rank.get(action, 100.0), reason,
                       {"action": action, "tainted": episode.untrusted_context is not None})


# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Exhaustive check of typed uncertainty and grounding from proofs (#953).

``model.py`` calls the composition with the untyped uncertainty rule only.
This module covers what the gate now passes on top. Both functions are the
implementation, called over every combination in a finite domain:

* :func:`remora.verification.compose.compose_authorized_decision` with
  ``uncertainty_settled``. Domain: three MACHINE preconditions in PROVED,
  UNKNOWN or REFUTED; every subset of the four uncertainty codes; four
  settled sets; four engine actions; a required or optional monitor.
* :func:`remora.verification.execution_gate.grounding_facts`. Domain: three
  predicates with subjects ``a``, ``b`` and the intent authority, in PROVED,
  UNKNOWN or REFUTED; arguments ``{a}``, ``{a, b}`` or ``{a, b, note}``; and
  every grounding map that gives each predicate none, one or two signals.

Invariants:

* ``TypedNarrowing``: the typed rule is never more executable than the
  untyped one;
* ``OpenCodeBlocksAccept``: with a required monitor, a code the evidence does
  not settle never ends in ACCEPT;
* ``SettledAsUntyped``: when the evidence settles every code, the typed rule
  decides as the untyped one;
* ``GroundingNeedsProof``: a signal is only ever True, and only when every
  precondition that declares it is PROVED;
* ``ArgumentSignalsNeedEveryArgument``: an argument signal needs every
  argument to be a PROVED subject.

Two negative controls show the invariants are not vacuous.
``settle_everything`` passes every code as settled whatever the evidence
says, and must break ``OpenCodeBlocksAccept``. ``ground_everything`` grants
every declared signal whatever the evidence says, and must break both
grounding invariants. A result here is about these two functions within
these bounds.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from formal.ws1_composition.model import NOW, _h, _profile, _registry, _Scripted  # noqa: E402
from remora.decision_providers.composition_adapter import (  # noqa: E402
    UNCERTAINTY_CODES,
    AssessmentOutcome,
    MonitorAssessment,
    MonitorMode,
)
from remora.policy.composition import executability  # noqa: E402
from remora.policy.observation import PolicyObservation, canonical_tool_call_hash  # noqa: E402
from remora.policy.report import DecisionAction, DecisionReason, DecisionReport  # noqa: E402
from remora.verification.check import (  # noqa: E402
    ResolverEvidence,
    VerificationRequest,
    check_preconditions,
)
from remora.verification.compose import compose_authorized_decision  # noqa: E402
from remora.verification.execution_gate import (  # noqa: E402
    _ARGUMENT_FIELDS,
    GROUNDING_FIELDS,
    grounding_facts,
)
from remora.verification.preconditions import (  # noqa: E402
    INTENT_SUBJECT,
    LogicalState,
    ProposalContext,
    ResolutionClass,
    derive_preconditions,
)
from remora.verification.registry import (  # noqa: E402
    PredicateSpec,
    PreconditionRegistry,
    ResolverSpec,
)

P, U, R = LogicalState.PROVED, LogicalState.UNKNOWN, LogicalState.REFUTED
CODES = tuple(sorted(UNCERTAINTY_CODES))
SETTLED = (frozenset(), frozenset({"missing_context", "ambiguous_intent"}),
           frozenset({"ambiguous_target", "unverified_value"}), frozenset(CODES))
BASES = (DecisionAction.ACCEPT, DecisionAction.VERIFY, DecisionAction.ESCALATE,
         DecisionAction.ABSTAIN)
M = ResolutionClass.MACHINE


def _checked(registry: PreconditionRegistry, states: tuple[LogicalState, ...],
             args: dict[str, Any], tool: str, intent: str = "") -> tuple[Any, Any, Any]:
    ctx = ProposalContext(
        proposal_id="p", tenant_id="t", principal_id="a", tool_name=tool,
        call_hash=canonical_tool_call_hash(name=tool, arguments=args, tenant="t"),
        intent_authority_hash=intent or _h("i"), policy_bundle_hash=_h("pol"),
        toolspec_hash=_h("ts"), profile_hash=_profile(MonitorMode.REQUIRED, 0).profile_hash,
        capability_hash=_h("c"), flow_digest=_h("f"), flow_epoch=0, context_version=1)
    reqs = derive_preconditions(ctx, args, registry)
    issued, evidence = {}, []
    for pre, state in zip(reqs.preconditions, states, strict=True):
        if state is U:
            continue
        rid = f"{pre.predicate_id}:0"
        issued[rid] = VerificationRequest(rid, ctx.context_hash, 0, pre.precondition_id,
                                          pre.resolver_ids[0], pre.subject_ref, 0, "b")
        payload = json.dumps({"s": state.value}).encode()
        evidence.append(ResolverEvidence(rid, pre.resolver_ids[0], "src", pre.subject_ref, "v",
                                         "t", NOW - 1, NOW + 30, payload,
                                         hashlib.sha256(payload).hexdigest(), "model"))
    checked = check_preconditions(ctx, reqs, evidence, issued=issued, registry=registry,
                                  verifiers={"scripted": _Scripted()}, now_s=NOW,
                                  evidence_revision=0)
    return ctx, reqs, checked


@lru_cache(maxsize=None)
def _setup(states: tuple[LogicalState, ...]) -> tuple[Any, Any, Any]:
    return _checked(_registry((M, M, M)), states, {"x": "subject"}, "t")


def _final(states: tuple[LogicalState, ...], codes: frozenset[str], mode: MonitorMode,
           base: DecisionAction, settled: frozenset[str] | None) -> DecisionAction:
    ctx, reqs, checked = _setup(states)
    profile = _profile(mode, 0)
    assessment = MonitorAssessment(
        context_hash=ctx.context_hash, evidence_digest=checked.evidence_digest,
        input_digest=_h("in"), raw_response_hash=_h("r"), model_id=profile.model_id,
        question_set_hash=profile.question_set_hash, calibration_hash=profile.calibration_hash,
        outcome=AssessmentOutcome.ASSESSED, reason="model", recorded_at=NOW,
        valid_until=NOW + 30, crossed=(), uncertainty_codes=tuple(sorted(codes)))
    report = DecisionReport(action=base, reasons=(DecisionReason.GROUNDED_READ_ACCEPT,),
                            risk_estimate=None, confidence=None, coverage_policy="model",
                            evidence_required=False, human_review_required=False,
                            audit_root=None, explanation="",
                            raw_observation=PolicyObservation(question="model"))
    record = compose_authorized_decision(report, ctx, reqs, checked, assessment, profile,
                                         now_s=NOW, uncertainty_settled=settled)
    return DecisionAction(record.final_action)


def check_typed(*, settle_everything: bool = False) -> dict[str, Any]:
    violated: dict[str, int] = {}
    cases = 0

    def fail(name: str) -> None:
        violated[name] = violated.get(name, 0) + 1

    for states in itertools.product((P, U, R), repeat=3):
        for n in range(len(CODES) + 1):
            for codes in map(frozenset, itertools.combinations(CODES, n)):
                for settled, mode, base in itertools.product(
                        SETTLED, (MonitorMode.REQUIRED, MonitorMode.OPTIONAL), BASES):
                    cases += 1
                    passed = frozenset(CODES) if settle_everything else settled
                    typed = _final(states, codes, mode, base, passed)
                    untyped = _final(states, codes, mode, base, None)
                    if executability(typed) > executability(untyped):
                        fail("TypedNarrowing")
                    if mode is MonitorMode.REQUIRED and codes - settled \
                            and typed is DecisionAction.ACCEPT:
                        fail("OpenCodeBlocksAccept")
                    if codes <= settled and not settle_everything and typed is not untyped:
                        fail("SettledAsUntyped")
    return {"cases": cases, "violated": dict(sorted(violated.items()))}


def _grounding_registry() -> PreconditionRegistry:
    specs = (PredicateSpec("pa", M, "scripted", ("r",), "a"),
             PredicateSpec("pb", M, "scripted", ("r",), "b"),
             PredicateSpec("pi", M, "scripted", ("r",), INTENT_SUBJECT))
    return PreconditionRegistry(tools={"g": specs}, resolvers={
        "r": ResolverSpec("r", "src", frozenset({"pa", "pb", "pi"}), "cap:r")})


def _ground_everything(grounding: Any, specs: Any, reqs: Any, checked: Any,
                       arguments: Any) -> dict[str, bool]:
    """The negative control: every declared signal, proved or not."""
    return {name: True for signals in grounding.values() for name in signals}


def check_grounding(facts_of: Any = grounding_facts) -> dict[str, Any]:
    registry = _grounding_registry()
    specs = registry.tools["g"]
    choices = ((), ("tool_matches_goal",), ("argument_values_grounded",),
               ("expected_effect_matches", "argument_values_supported"))
    violated: dict[str, int] = {}
    cases = 0
    for argset in ({"a": "1"}, {"a": "1", "b": "2"}, {"a": "1", "b": "2", "note": "x"}):
        present = [s for s in specs if s.subject_argument in argset
                   or s.subject_argument == INTENT_SUBJECT]
        reg = PreconditionRegistry(tools={"g": tuple(present)}, resolvers=registry.resolvers)
        for states in itertools.product((P, U, R), repeat=len(present)):
            _ctx, reqs, checked = _checked(reg, states, argset, "g", _h("wo"))
            proved = {s.predicate_id for s, st in zip(present, states, strict=True)
                      if st is P}
            for picks in itertools.product(choices, repeat=len(present)):
                cases += 1
                grounding = {s.predicate_id: c for s, c in zip(present, picks, strict=True)
                             if c}
                facts = facts_of(grounding, tuple(present), reqs, checked, argset)
                for name, value in facts.items():
                    declaring = {p for p, c in grounding.items() if name in c}
                    if value is not True or name not in GROUNDING_FIELDS \
                            or not declaring or not declaring <= proved:
                        violated["GroundingNeedsProof"] = violated.get(
                            "GroundingNeedsProof", 0) + 1
                    subjects = {s.subject_argument for s in present
                                if s.predicate_id in proved} - {INTENT_SUBJECT}
                    if name in _ARGUMENT_FIELDS and not set(argset) <= subjects:
                        violated["ArgumentSignalsNeedEveryArgument"] = violated.get(
                            "ArgumentSignalsNeedEveryArgument", 0) + 1
    return {"cases": cases, "violated": dict(sorted(violated.items()))}


def main() -> int:
    out = {"typed": check_typed(), "settle_everything": check_typed(settle_everything=True),
           "grounding": check_grounding(), "ground_everything": check_grounding(_ground_everything)}
    print(json.dumps(out, indent=1))
    return 0 if not out["typed"]["violated"] and not out["grounding"]["violated"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

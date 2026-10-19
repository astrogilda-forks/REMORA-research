# SPDX-License-Identifier: BUSL-1.1
"""One defence decision per proposed call, for every Study B arm (§4).

The WS1 arms share everything but the planner order:

1. the server builds the context from the episode (the work order the request
   names is the intent authority);
2. the WS1 loop runs in the arm's mode: H0 makes no lookup, H_DET, H_EDV and
   H_RANDOM make the same registered lookups under the same budget;
3. the monitor is asked once on the final evidence revision (all WS1 arms),
   and in H_EDV also once per round for hints, charged to the same budget;
4. a fresh engine decision runs on an observation whose grounding fields come
   only from PROVED preconditions: unknown stays None;
5. the composition meets engine, precondition and monitor caps. Only ACCEPT
   executes; a write is never autonomous in REMORA, so it can at most reach
   review (recorded as ``routed_to_review``).

``A`` executes every call and ``B`` none; they are the references J needs.
"""
from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from experiments.ws1_composition.isp_study.authority import (
    CAPABILITIES,
    REGISTRY,
    VERIFIERS,
    resolvers_for,
)
from experiments.ws1_composition.isp_study.domain import (
    EFFECT,
    TENANT,
    TOOL_SPECS,
    Task,
    World,
    digest,
    schema_valid,
)
from remora.decision_providers.composition_adapter import (
    MONITOR_RESPONSE_SCHEMA,
    MonitorProfile,
    assess_monitor_response,
)
from remora.policy.decision_engine import RemoraDecisionEngine
from remora.policy.observation import PolicyObservation, canonical_tool_call_hash
from remora.verification.check import CheckedPreconditions
from remora.verification.compose import compose_authorized_decision
from remora.verification.planner import PlannerMode, VerificationBudget, run_verification
from remora.verification.preconditions import LogicalState, ProposalContext, derive_preconditions

ARMS = ("A_no_gate", "B_refuse_all", "H0", "H_DET", "H_EDV", "H_RANDOM")
WS1_ARMS = {"H0": PlannerMode.H0, "H_DET": PlannerMode.H_DET, "H_EDV": PlannerMode.H_EDV,
            "H_RANDOM": PlannerMode.H_RANDOM}
#: Study B v1 profile: one lookup per round, so the order of lookups can matter.
STUDY_BUDGET = VerificationBudget(max_rounds=3, max_resolver_calls=3, max_monitor_calls=3,
                                  requests_per_round=1)
QUESTIONS = ("injection", "target_mismatch")
_ENGINE = RemoraDecisionEngine(grounded_read_accept=True)


class MonitorModel(Protocol):
    """A learned monitor. Sees the request, the untrusted tool output so far,
    the proposed call and the open preconditions' predicates; returns scores,
    uncertainty codes and predicate IDs to check first."""

    model_id: str

    def score(self, *, request: str, untrusted: Sequence[str], call_name: str,
              call_args: Mapping[str, Any], open_predicates: Sequence[str]) -> dict[str, Any]: ...


@dataclass
class CallRecord:
    arm: str
    name: str
    args: dict[str, Any]
    executed: bool
    final_action: str
    routed_to_review: bool
    reasons: list[str]
    precondition_states: dict[str, str]
    resolver_calls: int
    monitor_status: str
    monitor_veto: bool
    stop_reason: str
    latency_ms: float
    #: The final assessment's scores, kept for threshold selection on development data.
    monitor_scores: dict[str, float] = field(default_factory=dict)
    #: The fresh engine decision before the WS1 meet, for the F/G replay.
    engine_action: str = ""
    engine_reasons: list[str] = field(default_factory=list)


@dataclass
class EpisodeDefence:
    """The defence for one arm in one episode: holds the world it checks."""

    arm: str
    task: Task
    world: World
    profile: MonitorProfile
    monitor: MonitorModel | None
    clock_ms: Callable[[], int] = field(default=lambda: time.time_ns() // 1_000_000)
    seed: int = 20261019
    untrusted: list[str] = field(default_factory=list)
    records: list[CallRecord] = field(default_factory=list)
    monitor_calls: int = 0
    veto_recorded: set[str] = field(default_factory=set)

    def observe_output(self, name: str, output: str) -> None:
        """Ticket text is untrusted free text; the other tools read systems of record."""
        if name == "read_ticket":
            self.untrusted.append(output)

    def _context(self, name: str, args: dict[str, Any]) -> ProposalContext:
        spec = next(t for t in TOOL_SPECS if t["name"] == name)
        return ProposalContext(
            proposal_id=f"{self.task.task_id}:{self.arm}:{len(self.records)}",
            tenant_id=TENANT, principal_id="agent", tool_name=name,
            call_hash=canonical_tool_call_hash(name=name, arguments=args, tenant=TENANT),
            intent_authority_hash=self.world.work_order_hash(self.task.work_order),
            policy_bundle_hash=digest("study-b-policy-v1"), toolspec_hash=digest(spec),
            profile_hash=self.profile.profile_hash, capability_hash=digest(sorted(CAPABILITIES)),
            flow_digest=digest("flow-absent"), flow_epoch=0, context_version=1)

    def _ask(self, ctx: ProposalContext, reqs: Any, checked: CheckedPreconditions,
             name: str, args: dict[str, Any]) -> tuple[bytes | None, str | None]:
        if self.monitor is None:
            return None, "no_monitor"
        open_ids = {p.predicate_id: p.precondition_id for p in reqs.preconditions
                    if checked.state(p.precondition_id) is LogicalState.UNKNOWN}
        try:
            out = self.monitor.score(request=self.task.request, untrusted=tuple(self.untrusted),
                                     call_name=name, call_args=args,
                                     open_predicates=sorted(open_ids))
        except Exception as exc:  # an outage, never a low-risk reading
            return None, f"provider_error:{type(exc).__name__}"
        self.monitor_calls += 1
        body = {"schema": MONITOR_RESPONSE_SCHEMA, "model_id": self.profile.model_id,
                "question_set_hash": self.profile.question_set_hash,
                "calibration_hash": self.profile.calibration_hash,
                "language": self.profile.language, "context_hash": ctx.context_hash,
                "evidence_digest": checked.evidence_digest,
                "answers": [{"question_id": q, "score": out["scores"][q]}
                            for q in QUESTIONS if q in out.get("scores", {})],
                "uncertainty_codes": list(out.get("uncertainty_codes", [])),
                "hint_precondition_ids": [open_ids[p] for p in out.get("hints", [])
                                          if p in open_ids],
                "out_of_scope": bool(out.get("out_of_scope", False))}
        return json.dumps(body).encode(), None

    def decide(self, name: str, args: dict[str, Any]) -> bool:
        start = time.perf_counter()
        if self.arm == "A_no_gate":
            self._record(name, args, True, "accept", [], {}, 0, "none", False, "no_gate", start)
            return True
        if self.arm == "B_refuse_all" or not schema_valid(name, args):
            reason = "refuse_all" if self.arm == "B_refuse_all" else "schema_invalid"
            self._record(name, args, False, "abstain", [reason], {}, 0, "none", False, reason,
                         start)
            return False
        ctx = self._context(name, args)
        reqs = derive_preconditions(ctx, args, REGISTRY)
        resolvers = resolvers_for(self.world)

        def hints(checked: CheckedPreconditions) -> Sequence[str]:
            raw, err = self._ask(ctx, reqs, checked, name, args)
            a = assess_monitor_response(raw, profile=self.profile, context_hash=ctx.context_hash,
                                        evidence_digest=checked.evidence_digest,
                                        input_digest=checked.evidence_digest,
                                        now_s=self.clock_ms() // 1000, error=err)
            return a.hint_precondition_ids

        run = run_verification(ctx, reqs, registry=REGISTRY, verifiers=VERIFIERS,
                               resolvers=resolvers, held_capabilities=CAPABILITIES,
                               mode=WS1_ARMS[self.arm], budget=STUDY_BUDGET,
                               clock_ms=self.clock_ms, hints_for=hints, seed=self.seed)
        checked = run.checked
        raw, err = self._ask(ctx, reqs, checked, name, args)
        assessment = assess_monitor_response(
            raw, profile=self.profile, context_hash=ctx.context_hash,
            evidence_digest=checked.evidence_digest, input_digest=checked.evidence_digest,
            now_s=self.clock_ms() // 1000, error=err) if err != "no_monitor" else None
        states = {p.predicate_id: checked.state(p.precondition_id) for p in reqs.preconditions}
        proved = reqs.authorizable and all(s is LogicalState.PROVED for s in states.values())
        tool_ok = states.get("tool_in_work_order") is LogicalState.PROVED
        args_ok = all(s is LogicalState.PROVED for k, s in states.items()
                      if k != "tool_in_work_order")
        read = EFFECT[name] == "read"
        obs = PolicyObservation(
            question=self.task.request, risk_tier="low" if read else "medium",
            action_type="read" if read else "write", target_environment="staging",
            schema_valid=True, intent_authority_present=True, intent_resolution_status="resolved",
            tool_matches_goal=True if tool_ok else None,
            expected_effect_matches=True if tool_ok else None,
            argument_values_grounded=True if args_ok and proved else None,
            argument_values_supported=True if args_ok and proved else None)
        base = _ENGINE.decide(obs)
        key = json.dumps([name, args], sort_keys=True)
        record = compose_authorized_decision(
            base, ctx, reqs, checked, assessment, self.profile,
            now_s=self.clock_ms() // 1000, budget_exhausted=run.budget_exhausted,
            monitor_veto_on_record=key in self.veto_recorded)
        if record.monitor_veto:
            self.veto_recorded.add(key)
        self._scores = dict(assessment.scores) if assessment is not None else {}
        self._engine = (base.action.value, [r.value for r in base.reasons])
        executed = record.final_action == "accept"
        routed = record.final_action in ("escalate", "verify") and all(
            c.source == "engine" for c in record.all_caps)
        self._record(name, args, executed, record.final_action, list(record.reason_codes),
                     {k: v.value for k, v in states.items()},
                     sum(r.calls for r in resolvers.values()), record.monitor_status,
                     record.monitor_veto, run.stop_reason, start, routed)
        return executed

    def _record(self, name: str, args: dict[str, Any], executed: bool, final: str,
                reasons: list[str], states: dict[str, str], resolver_calls: int,
                monitor_status: str, veto: bool, stop: str, start: float,
                routed: bool = False) -> None:
        self.records.append(CallRecord(self.arm, name, dict(args), executed, final, routed,
                                       reasons, states, resolver_calls, monitor_status, veto,
                                       stop, (time.perf_counter() - start) * 1000,
                                       getattr(self, "_scores", {}),
                                       *getattr(self, "_engine", ("", []))))
        self._scores, self._engine = {}, ("", [])

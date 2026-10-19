# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1 at the canonical execution path (WS1 SDD §7.1, §13.2 WP5, §13.3).

The execution core (CORE) never imports this module. It sees a
``Ws1GatePort`` (``remora/execution/ports.py``); ``servers/execution_api.py``
builds the gate from the deployment's configuration and passes it in.

Modes, chosen by the deployment and never by a request:

* ``off`` (default): no gate is built; every decision is as before.
* ``shadow``: the gate runs and its record is audited; the decision, the
  token and the review item are exactly what they would be without it.
* ``enforce``: the WS1 composition caps the decision, its binding enters the
  ACCEPT token's authorization context, and every dispatch path runs the
  gate again with fresh lookups before anything is consumed. Refused at
  construction unless flow control is on and the deployment names evidence
  for every prerequisite work package (``ENFORCE_DEPENDENCIES``).

v1 is deliberately narrower than the design's decision table. No route yet
binds a review or a grant to the WS1 precondition it would close, so any WS1
cap under ``enforce`` makes the call ABSTAIN rather than open a review item
nothing could ever execute. WS1 therefore never opens a review route, and an
approval can lift only the engine's own ESCALATE or VERIFY: at execution the
gate must reach ACCEPT on its own.

The monitor sees the :class:`ProposalContext` and the checked precondition
states: hashes, IDs and states, never argument values or tool output. A
resolver sends the precondition's subject to its registered source only.
"""
from __future__ import annotations

import dataclasses
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from remora.decision_providers.composition_adapter import (
    MonitorProfile,
    assess_monitor_response,
)
from remora.policy.observation import canonical_tool_call_hash
from remora.policy.report import DecisionAction, DecisionReason, DecisionReport
from remora.verification.check import CheckedPreconditions, Verifier
from remora.verification.compose import compose_authorized_decision
from remora.verification.planner import (
    FamilyLedger,
    PlannerMode,
    VerificationBudget,
    run_verification,
)
from remora.verification.preconditions import (
    ProposalContext,
    derive_preconditions,
    tagged_digest,
)
from remora.verification.records import CompositionRecord
from remora.verification.registry import PreconditionRegistry
from remora.verification.resolvers import Resolver

__all__ = ["ENFORCE_DEPENDENCIES", "WS1_MODES", "Ws1Deployment", "Ws1Gate", "Ws1Outcome"]

WS1_MODES = ("off", "shadow", "enforce")
#: Work packages WS1 SDD §13.2 names before H-EDV reads sensitive data in
#: production: source provenance, result labelling, egress, read capabilities
#: and dispatch control. ``enforce`` needs evidence named for each.
ENFORCE_DEPENDENCIES = ("IFC-04b", "IFC-06", "IFC-11", "IFC-12", "IFC-13")
#: The deployment-declared absence of flow state, bound like any digest.
FLOW_ABSENT = tagged_digest("flow-absent", {"flow_control": "off"})
_RUNTIME_MODES = (PlannerMode.H0, PlannerMode.H_DET, PlannerMode.H_EDV)
_HEX = frozenset("0123456789abcdef")


def _as_digest(name: str, value: str) -> str:
    """A bound value as a 64-hex digest: itself when it is one (``sha256:``
    prefix dropped), otherwise a tagged digest of the exact string. The same
    value gives the same digest at assessment and at every re-gate."""
    bare = value.removeprefix("sha256:")
    if len(bare) == 64 and set(bare) <= _HEX:
        return bare
    return tagged_digest("bound-value", {"field": name, "value": value})


@dataclass(frozen=True)
class Ws1Deployment:
    """Everything the gate runs with. Built by the deployment, not the request."""

    registry: PreconditionRegistry
    verifiers: Mapping[str, Verifier]
    resolvers: Mapping[str, Resolver]
    monitor_profile: MonitorProfile
    resolve_capabilities: Callable[[str, str], frozenset[str]]
    clock_ms: Callable[[], int]
    monitor: Callable[[ProposalContext, CheckedPreconditions], bytes | None] | None = None
    planner_mode: PlannerMode = PlannerMode.H_DET
    budget: VerificationBudget = field(default_factory=VerificationBudget)
    family_ledger: FamilyLedger | None = None
    enforce_dependencies: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.planner_mode not in _RUNTIME_MODES:
            raise ValueError(f"planner mode {self.planner_mode.value!r} is a research control, "
                             "not a runtime mode")

    @property
    def binding_terms(self) -> dict[str, Any]:
        return {"profile_hash": self.monitor_profile.profile_hash,
                "registry_hash": self.registry.registry_hash,
                "planner_mode": self.planner_mode.value,
                "budget": {k: v for k, v in dataclasses.asdict(self.budget).items()
                           if k.startswith(("max_", "requests_", "wall_", "resolver_"))}}


@dataclass(frozen=True)
class Ws1Outcome:
    mode: str
    final_action: DecisionAction
    status: str
    binding_hash: str = ""
    record: CompositionRecord | None = None
    stop_reason: str = ""

    @property
    def clean(self) -> bool:
        """No WS1 cap: every required precondition PROVED, no monitor cap."""
        return self.record is not None and all(c.source == "engine" for c in self.record.all_caps)

    @property
    def monitor_veto(self) -> bool:
        return self.record is not None and self.record.monitor_veto

    def audit_block(self) -> dict[str, Any]:
        block: dict[str, Any] = {"mode": self.mode, "status": self.status,
                                 "final_action": self.final_action.value,
                                 "binding_hash": self.binding_hash,
                                 "stop_reason": self.stop_reason,
                                 "monitor_veto": self.monitor_veto}
        if self.record is not None:
            block["record"] = {**self.record.body(), "record_hash": self.record.record_hash}
        return block

    def apply(self, report: DecisionReport) -> DecisionReport:
        """The decision under this mode. Shadow returns *report* unchanged;
        enforce returns it, or ABSTAIN when WS1 put any cap on it."""
        if self.mode != "enforce" or (self.clean and self.status == "evaluated"):
            return report
        monitor_only = self.record is not None and all(
            c.source in ("engine", "monitor") for c in self.record.all_caps)
        reason = DecisionReason.MONITOR_CAP if monitor_only else DecisionReason.PRECONDITION_CAP
        return dataclasses.replace(report, action=DecisionAction.ABSTAIN,
                                   reasons=(*report.reasons, reason),
                                   human_review_required=False)


class Ws1Gate:
    """Builds the context, runs the bounded loop and composes; never raises."""

    def __init__(self, mode: str, deployment: Ws1Deployment, *, flow_control: bool) -> None:
        if mode not in WS1_MODES or mode == "off":
            raise ValueError(f"WS1 mode must be 'shadow' or 'enforce' to build a gate, not {mode!r}")
        if mode == "enforce":
            if not flow_control:
                raise ValueError("WS1 enforce needs REMORA_FLOW_CONTROL=1")
            missing = [d for d in ENFORCE_DEPENDENCIES
                       if not str(deployment.enforce_dependencies.get(d, "")).strip()]
            if missing:
                raise ValueError(f"WS1 enforce needs evidence for {missing} (WS1 SDD §13.2 WP5)")
        self.mode = mode
        self.deployment = deployment

    def _capability_hash(self, capability: Mapping[str, Any] | None) -> str:
        if capability is None:
            return tagged_digest("capability-none", {})
        return tagged_digest("capability", {
            "allowed": bool(capability.get("allowed")),
            "policy_version": str(capability.get("policy_version") or ""),
            "task_type": str(capability.get("task_type") or ""),
            "allowed_tools": sorted(str(t) for t in capability.get("allowed_tools") or ())})

    def evaluate(self, *, proposal_id: str, tenant: str, principal: str, tool_name: str,
                 arguments: Mapping[str, Any], intent_authority_hash: str,
                 policy_bundle_hash: str, toolspec_hash: str,
                 capability: Mapping[str, Any] | None, flow_digest: str | None,
                 flow_epoch: int | None, attempt_family_id: str | None,
                 base: DecisionReport, veto_on_record: bool = False) -> Ws1Outcome:
        try:
            return self._evaluate(proposal_id, tenant, principal, tool_name, arguments,
                                  intent_authority_hash, policy_bundle_hash, toolspec_hash,
                                  capability, flow_digest, flow_epoch, attempt_family_id,
                                  base, veto_on_record)
        except Exception as exc:  # a gate fault refuses; its text never reaches the record
            return Ws1Outcome(self.mode, DecisionAction.ABSTAIN, f"error:{type(exc).__name__}")

    def _evaluate(self, proposal_id: str, tenant: str, principal: str, tool_name: str,
                  arguments: Mapping[str, Any], intent_authority_hash: str,
                  policy_bundle_hash: str, toolspec_hash: str,
                  capability: Mapping[str, Any] | None, flow_digest: str | None,
                  flow_epoch: int | None, attempt_family_id: str | None,
                  base: DecisionReport, veto_on_record: bool) -> Ws1Outcome:
        d = self.deployment
        for name, value in (("intent_authority", intent_authority_hash),
                            ("policy_bundle", policy_bundle_hash), ("toolspec", toolspec_hash)):
            if not value:
                return Ws1Outcome(self.mode, DecisionAction.ABSTAIN, f"refused:{name}_unbound")
        args = dict(arguments)
        context = ProposalContext(
            proposal_id=proposal_id, tenant_id=tenant, principal_id=principal,
            tool_name=tool_name,
            call_hash=canonical_tool_call_hash(name=tool_name, arguments=args, tenant=tenant),
            intent_authority_hash=_as_digest("intent_authority_hash", intent_authority_hash),
            policy_bundle_hash=_as_digest("policy_bundle_hash", policy_bundle_hash),
            toolspec_hash=_as_digest("toolspec_hash", toolspec_hash),
            profile_hash=d.monitor_profile.profile_hash,
            capability_hash=self._capability_hash(capability),
            flow_digest=_as_digest("flow_digest", flow_digest) if flow_digest else FLOW_ABSENT,
            flow_epoch=int(flow_epoch or 0), context_version=1)
        if d.family_ledger is not None and attempt_family_id \
                and not d.family_ledger.admit(attempt_family_id, context):
            return Ws1Outcome(self.mode, DecisionAction.ABSTAIN,
                              "refused:attempt_family_budget_exhausted")
        requirements = derive_preconditions(context, args, d.registry)
        monitor_calls = 0

        def ask(checked: CheckedPreconditions) -> tuple[bytes | None, str | None]:
            nonlocal monitor_calls
            if d.monitor is None:
                return None, "no_monitor"
            if monitor_calls >= d.budget.max_monitor_calls:
                return None, "monitor_budget_exhausted"
            monitor_calls += 1
            try:
                return d.monitor(context, checked), None
            except Exception as exc:  # an outage, never a low-risk reading
                return None, f"provider_error:{type(exc).__name__}"

        def assess(checked: CheckedPreconditions) -> Any:
            raw, error = ask(checked)
            if raw is None and error == "no_monitor":
                return None
            return assess_monitor_response(
                raw, profile=d.monitor_profile, context_hash=context.context_hash,
                evidence_digest=checked.evidence_digest, input_digest=checked.evidence_digest,
                now_s=d.clock_ms() // 1000, error=error)

        def hints(checked: CheckedPreconditions) -> tuple[str, ...]:
            a = assess(checked)
            return a.hint_precondition_ids if a is not None else ()

        run = run_verification(
            context, requirements, registry=d.registry, verifiers=d.verifiers,
            resolvers=d.resolvers, held_capabilities=d.resolve_capabilities(tenant, principal),
            mode=d.planner_mode, budget=d.budget, clock_ms=d.clock_ms,
            hints_for=hints if d.planner_mode is PlannerMode.H_EDV else None)
        record = compose_authorized_decision(
            base, context, requirements, run.checked, assess(run.checked), d.monitor_profile,
            now_s=d.clock_ms() // 1000, budget_exhausted=run.budget_exhausted,
            monitor_veto_on_record=veto_on_record)
        outcome = Ws1Outcome(self.mode, DecisionAction(record.final_action), "evaluated",
                             record=record, stop_reason=run.stop_reason)
        if outcome.clean:
            binding = tagged_digest("execution-binding", {
                "context_hash": context.context_hash,
                "requirements_hash": requirements.requirements_hash, **d.binding_terms})
            outcome = dataclasses.replace(outcome, binding_hash=binding)
        return outcome

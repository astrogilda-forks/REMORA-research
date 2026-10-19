# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Explicit-state model of WS1 composition, issuance and dispatch (WS1 SDD §12.1).

Breadth-first over every reachable state of a small transition system. Three
required preconditions in four logical states, a resolution class each, a
required or optional monitor with arbitrary output, a grant-only engine
restriction, evidence revisions, profile binding, one single-use grant and
two concurrent execute attempts.

Two transitions call the implementation rather than a copy of it:

* ``decide`` and ``regate`` call
  :func:`remora.verification.compose.compose_authorized_decision` over a real
  :class:`~remora.verification.check.CheckedPreconditions` (built by
  :func:`remora.verification.check.check_preconditions`), as
  ``Ws1Gate.evaluate`` and ``remora.execution.service.ws1_regate`` do;
* ``issue`` and ``begin`` compare :meth:`AuthorizationContext.hash` with the
  WS1 binding in it, as ``redeem_accept_token`` does.

Token consumption is modelled, not called: ``consume`` is one atomic step, as
the gate's single-use ledger is (CAP-003), and it follows the re-gate as a
separate step, as in the code. The world can therefore move between the two;
``Residual_ProvedAtDispatchInstant`` records that window in every
configuration where the world moves. The design's claim is the invariant
``FreshAtRegate``: proved at the last re-gate before consumption. The world moves on its own between
steps: evidence is revoked or refuted, the profile changes. Configurations
switch one rule off at a time; each must break exactly the invariant that
rule protects (``expected.json``). That is what shows the invariants are not
vacuous. A result here is about this abstraction and the two functions it
calls, within these bounds. It is not a proof about the rest of the code.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import sys
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from remora.decision_providers.composition_adapter import (  # noqa: E402
    AssessmentOutcome,
    MonitorAssessment,
    MonitorMode,
    MonitorProfile,
)
from remora.enforcement.token import AuthorizationContext  # noqa: E402
from remora.policy.observation import PolicyObservation, canonical_tool_call_hash  # noqa: E402
from remora.policy.report import DecisionAction, DecisionReason, DecisionReport  # noqa: E402
from remora.verification.check import (  # noqa: E402
    ResolverEvidence,
    VerificationRequest,
    check_preconditions,
)
from remora.verification.compose import compose_authorized_decision  # noqa: E402
from remora.verification.preconditions import (  # noqa: E402
    LogicalState,
    ProposalContext,
    ResolutionClass,
    derive_preconditions,
)
from remora.verification.registry import PredicateSpec, PreconditionRegistry, ResolverSpec  # noqa: E402

P, R, U, C = LogicalState.PROVED, LogicalState.REFUTED, LogicalState.UNKNOWN, LogicalState.CONFLICT
M, RV, G, T = (ResolutionClass.MACHINE, ResolutionClass.REVIEW, ResolutionClass.GRANT,
               ResolutionClass.TERMINAL)
MONITOR_OUTPUTS = ("none", "clean", "veto", "uncertain", "invalid", "outage")
NOW = 1_800_000_000


def _h(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


# ── the implementation calls ────────────────────────────────────────────


def _registry(classes: tuple[ResolutionClass, ...]) -> PreconditionRegistry:
    specs = tuple(PredicateSpec(f"p{i}", cls, "scripted", ("r",) if cls is M else (),
                                subject_argument="x",
                                review_role="reviewer" if cls is RV else None)
                  for i, cls in enumerate(classes))
    return PreconditionRegistry(tools={"t": specs}, resolvers={
        "r": ResolverSpec("r", "src", frozenset(f"p{i}" for i, c in enumerate(classes)
                                                if c is M), "cap:r")})


def _profile(mode: MonitorMode, version: int) -> MonitorProfile:
    return MonitorProfile(profile_id=f"model-{version}", mode=mode, model_id="model-1.0.0",
                          question_set_hash=_h("q"), thresholds={"q": 0.5}, language="en",
                          calibration_hash=_h("cal"))


class _Scripted:
    verifier_id, version = "scripted", "0"

    def verify(self, pre: Any, payload: Any, ctx: Any) -> tuple[LogicalState, str]:
        return LogicalState(payload["s"]), "scripted"


@lru_cache(maxsize=None)
def _compose(classes: tuple[ResolutionClass, ...], states: tuple[LogicalState, ...],
             mode: MonitorMode, profile_version: int, monitor: str, veto_on_record: bool,
             base: DecisionAction, grant_only: bool) -> tuple[str, str, bool, str]:
    """(final_action, review_class, monitor_veto, binding) from the real composition."""
    profile = _profile(mode, profile_version)
    registry = _registry(classes)
    args = {"x": "subject"}
    ctx = ProposalContext(
        proposal_id="p", tenant_id="t", principal_id="a", tool_name="t",
        call_hash=canonical_tool_call_hash(name="t", arguments=args, tenant="t"),
        intent_authority_hash=_h("i"), policy_bundle_hash=_h("pol"), toolspec_hash=_h("ts"),
        profile_hash=profile.profile_hash, capability_hash=_h("c"), flow_digest=_h("f"),
        flow_epoch=0, context_version=1)
    reqs = derive_preconditions(ctx, args, registry)
    issued, evidence = {}, []
    for pre, state in zip(reqs.preconditions, states):
        if state is U or not pre.resolver_ids:
            continue
        for k, s in enumerate((P, R) if state is C else (state,)):
            rid = f"{pre.predicate_id}:{k}"
            req = VerificationRequest(rid, ctx.context_hash, 0, pre.precondition_id, "r",
                                      pre.subject_ref, 0, "b")
            payload = json.dumps({"s": s.value}).encode()
            issued[rid] = req
            evidence.append(ResolverEvidence(rid, "r", "src", pre.subject_ref, "v", "t", NOW - 1,
                                             NOW + 30, payload,
                                             hashlib.sha256(payload).hexdigest(), "model"))
    checked = check_preconditions(ctx, reqs, evidence, issued=issued, registry=registry,
                                  verifiers={"scripted": _Scripted()}, now_s=NOW,
                                  evidence_revision=0)
    assessment = None
    if monitor != "none":
        outcome = {"clean": AssessmentOutcome.ASSESSED, "veto": AssessmentOutcome.ASSESSED,
                   "uncertain": AssessmentOutcome.ASSESSED, "invalid": AssessmentOutcome.INVALID,
                   "outage": AssessmentOutcome.UNAVAILABLE}[monitor]
        assessment = MonitorAssessment(
            context_hash=ctx.context_hash, evidence_digest=checked.evidence_digest,
            input_digest=_h("in"), raw_response_hash=_h(monitor), model_id=profile.model_id,
            question_set_hash=profile.question_set_hash,
            calibration_hash=profile.calibration_hash, outcome=outcome, reason=monitor,
            recorded_at=NOW, valid_until=NOW + 30,
            crossed=("q",) if monitor == "veto" else (),
            uncertainty_codes=("missing_context",) if monitor == "uncertain" else ())
    reasons = (DecisionReason.FLOW_CONFIDENTIALITY_VIOLATION,) if grant_only else \
        (DecisionReason.GROUNDED_READ_ACCEPT,)
    report = DecisionReport(action=base, reasons=reasons, risk_estimate=None, confidence=None,
                            coverage_policy="model", evidence_required=False,
                            human_review_required=False, audit_root=None, explanation="",
                            raw_observation=PolicyObservation(question="model"))
    record = compose_authorized_decision(report, ctx, reqs, checked, assessment, profile,
                                         now_s=NOW, monitor_veto_on_record=veto_on_record)
    clean = all(c.source == "engine" for c in record.all_caps)
    binding = _h(f"{ctx.context_hash}:{reqs.requirements_hash}") if clean else ""
    return record.final_action, record.review_class, record.monitor_veto, binding


def _context_hash(binding: str) -> str:
    return AuthorizationContext(tenant="t", principal="a", ws1_binding_hash=binding).hash()


# ── the transition system ──────────────────────────────────────────────


@dataclass(frozen=True)
class Config:
    name: str
    classes: tuple[ResolutionClass, ...]
    lookups: int = 3
    regate: bool = True            # re-run WS1 with fresh evidence at dispatch
    atomic_consume: bool = True    # the grant is spent in one step
    bind_profile: bool = True      # the WS1 binding enters the token context
    monitor_can_prove: bool = False  # weakening: a clean reading settles the preconditions
    world_moves: bool = True


@dataclass(frozen=True)
class State:
    states: tuple[LogicalState, ...]
    mode: MonitorMode
    monitor: str
    veto_recorded: bool
    profile: int                   # deployment profile in force now
    lookups_left: int
    decided: bool = False
    token: str = "none"            # none | issued | consumed
    token_context: str = ""
    token_states: tuple[LogicalState, ...] = ()
    #: Per attempt: idle | checked | done, and whether every precondition was
    #: PROVED under the bound profile when its re-gate ran.
    attempts: tuple[tuple[str, bool], tuple[str, bool]] = (("idle", False), ("idle", False))
    dispatched: int = 0
    #: Per dispatch: (fresh at its re-gate, fresh at the consuming step).
    dispatch_ok: tuple[tuple[bool, bool], ...] = ()
    base: DecisionAction = DecisionAction.ACCEPT
    grant_only: bool = False
    world_steps: int = 1


def _decision(cfg: Config, s: State, states: tuple[LogicalState, ...] | None = None,
              base: DecisionAction | None = None) -> tuple[str, str, bool, str]:
    states = states or s.states
    if cfg.monitor_can_prove and s.monitor == "clean":
        states = tuple(P for _ in states)
    return _compose(cfg.classes, states, s.mode, s.profile, s.monitor,
                    s.veto_recorded, base or s.base, s.grant_only)


def initial(cfg: Config) -> Iterator[State]:
    for mode in (MonitorMode.REQUIRED, MonitorMode.OPTIONAL):
        for base in (DecisionAction.ACCEPT, DecisionAction.ESCALATE):
            for grant_only in (False, True):
                if grant_only and base is not DecisionAction.ESCALATE:
                    continue
                yield State(states=tuple(U for _ in cfg.classes), mode=mode, monitor="none",
                            veto_recorded=False, profile=0, lookups_left=cfg.lookups,
                            base=base, grant_only=grant_only)


def successors(cfg: Config, s: State) -> Iterator[tuple[str, State]]:
    if not s.decided:
        # Lookups settle a MACHINE precondition any way the world allows.
        if s.lookups_left:
            for i, cls in enumerate(s.states):
                if cfg.classes[i] is M and cls is U:
                    for new in (P, R, C, U):
                        states = s.states[:i] + (new,) + s.states[i + 1:]
                        yield f"lookup p{i}={new.value}", dataclasses.replace(
                            s, states=states, lookups_left=s.lookups_left - 1)
        for out in MONITOR_OUTPUTS:
            if out != s.monitor:
                yield f"monitor {out}", dataclasses.replace(
                    s, monitor=out, veto_recorded=s.veto_recorded or out == "veto")
        final, _rc, _veto, binding = _decision(cfg, s)
        nxt = dataclasses.replace(s, decided=True)
        if final == "accept":
            ctx = _context_hash(binding if cfg.bind_profile else "")
            nxt = dataclasses.replace(nxt, token="issued", token_context=ctx,
                                      token_states=s.states)
        yield f"decide {final}", nxt
        return
    if cfg.world_moves and s.world_steps:
        for i, st in enumerate(s.states):
            if st is P:
                for new in (U, R):
                    states = s.states[:i] + (new,) + s.states[i + 1:]
                    yield f"world p{i}->{new.value}", dataclasses.replace(
                        s, states=states, world_steps=s.world_steps - 1)
        yield "world profile change", dataclasses.replace(s, profile=s.profile + 1,
                                                           world_steps=s.world_steps - 1)
    for a in (0, 1):
        phase, fresh_at_check = s.attempts[a]
        if phase == "idle" and s.token != "none":
            # Redemption, before consumption: the WS1 re-gate with fresh
            # lookups (when on) and the context comparison.
            if cfg.regate:
                final, _rc, _veto, binding = _decision(cfg, s, base=DecisionAction.ACCEPT)
                ok = final == "accept"
            else:
                binding, ok = _decision(cfg, s, states=s.token_states,
                                        base=DecisionAction.ACCEPT)[3], True
            presented = _context_hash(binding if cfg.bind_profile else "")
            if ok and presented == s.token_context:
                fresh = all(x is P for x in s.states) and s.profile == 0
                yield f"check {a}", dataclasses.replace(
                    s, attempts=_set(s.attempts, a, ("checked", fresh)))
            else:
                yield f"refused {a}", dataclasses.replace(
                    s, attempts=_set(s.attempts, a, ("done", False)))
        elif phase == "checked":
            # The gate's single-use ledger: one atomic step (CAP-003).
            if cfg.atomic_consume and s.token != "issued":
                yield f"refused {a} replay", dataclasses.replace(
                    s, attempts=_set(s.attempts, a, ("done", False)))
                continue
            now_fresh = all(x is P for x in s.states) and s.profile == 0
            yield f"consume {a}", dataclasses.replace(
                s, token="consumed", attempts=_set(s.attempts, a, ("done", False)),
                dispatched=s.dispatched + 1,
                dispatch_ok=(*s.dispatch_ok, (fresh_at_check, now_fresh)))


Attempt = tuple[str, bool]


def _set(t: tuple[Attempt, Attempt], i: int, v: Attempt) -> tuple[Attempt, Attempt]:
    return (v, t[1]) if i == 0 else (t[0], v)


def violations(cfg: Config, s: State) -> list[str]:
    out = []
    if s.dispatched > 1:
        out.append("SingleUse")
    if not all(at_check for at_check, _ in s.dispatch_ok):
        out.append("FreshAtRegate")             # WS1-01 / WS1-09: proved at the last re-gate
    if not all(now for _, now in s.dispatch_ok):
        # Not an invariant of the design: the world can move between the
        # re-gate and the consuming step. Reported so the window stays visible;
        # evidence TTLs bound it, nothing here closes it.
        out.append("Residual_ProvedAtDispatchInstant")
    if s.decided and s.token != "none":
        if not all(x is P for x in s.token_states):
            out.append("AuthorityCeiling")      # WS1-01 / WS1-06 at issuance
        if s.grant_only:
            out.append("GrantSeparation")       # WS1-04
    if s.decided:
        final, review_class, _v, _b = _decision(cfg, s)
        floor = {"accept": 2, "verify": 1, "escalate": 0, "abstain": 0}
        no_monitor = _compose(cfg.classes, s.states, MonitorMode.SHADOW, s.profile, "none",
                              False, s.base, s.grant_only)[0]
        if floor[final] > floor[no_monitor]:
            out.append("MonitorNonExpansion")   # WS1-02
        terminal = any(x in (R, C) for x in s.states) or any(
            cls is T and x is not P for cls, x in zip(cfg.classes, s.states))
        if terminal and (final != "abstain" or review_class != "none"):
            out.append("RefusalPersistence")    # WS1-03
    return out


def check(cfg: Config, max_states: int = 200_000) -> dict[str, Any]:
    seen: dict[State, tuple[State | None, str]] = {}
    queue: deque[State] = deque()
    for s in initial(cfg):
        seen[s] = (None, "init")
        queue.append(s)
    found: dict[str, list[str]] = {}
    while queue:
        s = queue.popleft()
        for name in violations(cfg, s):
            if name not in found:
                found[name] = _trace(seen, s)
        for label, nxt in successors(cfg, s):
            if nxt not in seen:
                if len(seen) >= max_states:
                    raise RuntimeError(f"{cfg.name}: state bound {max_states} reached")
                seen[nxt] = (s, label)
                queue.append(nxt)
    return {"config": cfg.name, "states": len(seen), "violated": sorted(found),
            "counterexamples": found}


def _trace(seen: dict[State, tuple[State | None, str]], s: State) -> list[str]:
    steps = []
    cur: State | None = s
    while cur is not None:
        parent, label = seen[cur]
        steps.append(label)
        cur = parent
    return list(reversed(steps))


ALL_MACHINE = (M, M, M)
MIXED = (M, RV, T)
CONFIGS = (
    Config("all_machine", ALL_MACHINE),
    Config("machine_review_terminal", MIXED),
    Config("grant_class", (M, G, M)),
    Config("no_regate", ALL_MACHINE, regate=False),
    Config("nonatomic_consume", ALL_MACHINE, atomic_consume=False),
    Config("no_profile_binding", ALL_MACHINE, bind_profile=False),
    Config("monitor_can_prove", ALL_MACHINE, monitor_can_prove=True),
)


def main() -> int:
    expected = json.loads((Path(__file__).parent / "expected.json").read_text(encoding="utf-8"))
    bad = 0
    for cfg in CONFIGS:
        result = check(cfg)
        want = expected[cfg.name]
        status = "ok" if result["violated"] == want else "MISMATCH"
        bad += status != "ok"
        print(f"{status:8} {cfg.name:26} states={result['states']:6} violated={result['violated']}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())

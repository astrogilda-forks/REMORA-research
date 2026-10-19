# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Verification planning and the bounded loop (WS1 §7).

The planner chooses which registered lookups to run, in which order, inside a
fixed budget. It never chooses what counts as evidence, which verifier
decides, or which rights a call has. Three orderings are the WS1 study's
independent variable and nothing else differs between them:

* ``H_DET``: requirement order, then resolver ID;
* ``H_EDV``: the monitor's hinted precondition IDs first, then ``H_DET``
  order. A hint that is not an open MACHINE precondition of this
  requirement set is dropped and recorded; it cannot add a source, a URL, a
  tenant or a predicate (A08, A15);
* ``H_RANDOM``: a seeded shuffle, as a control for plain lookup gain.

The loop stops on the first of: every required MACHINE precondition settled,
a REFUTED or CONFLICT required precondition, no candidate left, no progress
in a round, the round or call budget, or the wall deadline. Each request is
deduplicated on (context, precondition, resolver). Times come from an
injected clock; nothing here reads one.
"""
from __future__ import annotations

import random
import sqlite3
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from enum import StrEnum
from fractions import Fraction
from pathlib import Path

from remora.verification.check import (
    CheckedPreconditions,
    ResolverEvidence,
    ReviewAttestation,
    VerificationRequest,
    Verifier,
    check_preconditions,
)
from remora.verification.preconditions import (
    LogicalState,
    ProposalContext,
    RequirementSet,
    ResolutionClass,
    tagged_digest,
)
from remora.verification.registry import PreconditionRegistry
from remora.verification.resolvers import Resolver, ResolverRefused, run_request

__all__ = ["FamilyLedger", "LookupEstimate", "PlannerMode", "TaskCallLedger",
           "VerificationBudget", "VerificationRun", "choose_next_by_cost",
           "open_candidates", "plan_verification", "run_verification"]


class PlannerMode(StrEnum):
    H0 = "h0"              # no new lookups
    H_DET = "h_det"
    H_COST = "h_cost"      # deterministic cost-per-settlement baseline (SDD v2 AR-025)
    H_EDV = "h_edv"
    H_RANDOM = "h_random"


@dataclass(frozen=True)
class LookupEstimate:
    """Server-owned development estimate for a (precondition_id, resolver_id) pair (AR-025)."""

    cost_units: int
    settle_ppm: int

    def __post_init__(self) -> None:
        if type(self.cost_units) is not int or self.cost_units <= 0:
            raise ValueError("cost_units must be a positive integer")
        if type(self.settle_ppm) is not int or not 1 <= self.settle_ppm <= 1_000_000:
            raise ValueError("settle_ppm must be an integer in [1, 1000000]")


@dataclass(frozen=True)
class VerificationBudget:
    """Server-side limits for one proposal (WS1 §7.2 v1 values)."""

    max_rounds: int = 2
    max_resolver_calls: int = 3
    max_monitor_calls: int = 3
    requests_per_round: int = 2
    wall_deadline_ms: int = 5_000
    resolver_timeout_ms: int = 1_000
    spent_calls: int = 0
    spent_monitor_calls: int = 0
    rounds: int = 0
    dedup_keys: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        for name in ("max_rounds", "max_resolver_calls", "max_monitor_calls",
                     "requests_per_round", "wall_deadline_ms", "resolver_timeout_ms"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")

        for counter, limit in (("spent_calls", "max_resolver_calls"),
                               ("spent_monitor_calls", "max_monitor_calls"),
                               ("rounds", "max_rounds")):
            value = getattr(self, counter)
            if type(value) is not int or not 0 <= value <= getattr(self, limit):
                raise ValueError(f"{counter} must be an integer in [0, {limit}]")

    @property
    def calls_left(self) -> int:
        return max(0, self.max_resolver_calls - self.spent_calls)

    @property
    def exhausted(self) -> bool:
        return self.calls_left == 0 or self.rounds >= self.max_rounds


@dataclass
class FamilyLedger:
    """Server-owned attempt-family limit (WS1 §7.2): at most *max_proposals*
    distinct calls per family. The same call under a new proposal ID is the
    same attempt, not a new one, so a client cannot reset the count (A16)."""

    max_proposals: int = 3
    _seen: dict[str, list[str]] = field(default_factory=dict)

    def admit(self, attempt_family_id: str, context: ProposalContext) -> bool:
        key = tagged_digest("family-member", {"call_hash": context.call_hash,
                                              "intent_authority_hash": context.intent_authority_hash,
                                              "principal_id": context.principal_id,
                                              "tenant_id": context.tenant_id})
        members = self._seen.setdefault(attempt_family_id, [])
        if key in members:
            return True
        if len(members) >= self.max_proposals:
            return False
        members.append(key)
        return True


def _bounded_id(value: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError("invalid bounded identifier")


class TaskCallLedger:
    """Single-host SQLite ledger for durable, task-wide call reservation (SDD v2 WP-03 / AR-013..016).

    Enforces atomic reserve-before-call on ``(task_id, operation_id)`` with a
    bound request hash and a non-resettable task cap. Guarantees at-most-once
    local reservation, not distributed exactly-once external effects.
    """

    def __init__(self, path: str | Path) -> None:
        from remora.persistence.sqlite_path import refuse_memory_db

        self.path = str(path)
        refuse_memory_db(self.path, what="WS1 task call reservation ledger")
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS task_budget (
                    task_id TEXT PRIMARY KEY, binding TEXT NOT NULL,
                    cap INTEGER NOT NULL CHECK(cap >= 0),
                    spent INTEGER NOT NULL DEFAULT 0 CHECK(spent >= 0),
                    closed INTEGER NOT NULL DEFAULT 0 CHECK(closed IN (0,1)),
                    CHECK(spent <= cap)
                );
                CREATE TABLE IF NOT EXISTS reservation (
                    task_id TEXT NOT NULL REFERENCES task_budget(task_id),
                    operation_id TEXT NOT NULL, request_hash TEXT NOT NULL,
                    units INTEGER NOT NULL CHECK(units > 0),
                    PRIMARY KEY(task_id, operation_id)
                );
            """)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=5.0)
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            with conn:
                yield conn
        finally:
            conn.close()

    def create(self, task_id: str, binding: str, cap: int) -> None:
        _bounded_id(task_id)
        _bounded_id(binding)
        if type(cap) is not int or not 0 <= cap <= 1_000_000:
            raise ValueError("invalid cap")
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO task_budget(task_id,binding,cap) VALUES(?,?,?)",
                (task_id, binding, cap),
            )

    def reserve(
        self,
        task_id: str,
        binding: str,
        operation_id: str,
        request_hash: str,
        units: int = 1,
    ) -> bool:
        for value in (task_id, binding, operation_id, request_hash):
            _bounded_id(value)
        if type(units) is not int or not 1 <= units <= 1_000_000:
            raise ValueError("invalid units")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            task = conn.execute(
                "SELECT binding FROM task_budget WHERE task_id=?", (task_id,)
            ).fetchone()
            if task is None or task[0] != binding:
                raise ValueError("unknown task or binding mismatch")
            prior = conn.execute(
                "SELECT request_hash,units FROM reservation WHERE task_id=? AND operation_id=?",
                (task_id, operation_id),
            ).fetchone()
            if prior is not None:
                if prior != (request_hash, units):
                    raise ValueError("idempotency key reused for a different request")
                return False
            changed = conn.execute(
                "UPDATE task_budget SET spent=spent+? "
                "WHERE task_id=? AND closed=0 AND spent+?<=cap",
                (units, task_id, units),
            ).rowcount
            if changed != 1:
                return False
            conn.execute(
                "INSERT INTO reservation VALUES(?,?,?,?)",
                (task_id, operation_id, request_hash, units),
            )
            return True

    def close(self, task_id: str, binding: str) -> None:
        with self._connect() as conn:
            changed = conn.execute(
                "UPDATE task_budget SET closed=1 WHERE task_id=? AND binding=?",
                (task_id, binding),
            ).rowcount
            if changed != 1:
                raise ValueError("unknown task or binding mismatch")

    def spent(self, task_id: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT spent FROM task_budget WHERE task_id=?", (task_id,)
            ).fetchone()
            if row is None:
                raise ValueError("unknown task")
            return int(row[0])


def _dedup_key(context_hash: str, precondition_id: str, resolver_id: str) -> str:
    return tagged_digest("dedup", {"context_hash": context_hash,
                                   "precondition_id": precondition_id,
                                   "resolver_id": resolver_id})


def open_candidates(requirements: RequirementSet, checked: CheckedPreconditions,
                    budget: VerificationBudget) -> list[tuple[str, str]]:
    """(precondition_id, resolver_id) pairs still worth a lookup, in H_DET order."""
    out: list[tuple[str, str]] = []
    for pre in requirements.preconditions:
        if not pre.required or pre.resolution_class is not ResolutionClass.MACHINE:
            continue
        if checked.state(pre.precondition_id) is not LogicalState.UNKNOWN:
            continue
        for rid in sorted(pre.resolver_ids):
            if _dedup_key(requirements.context_hash, pre.precondition_id, rid) not in budget.dedup_keys:
                out.append((pre.precondition_id, rid))
    return out


def choose_next_by_cost(
    requirements: RequirementSet,
    checked: CheckedPreconditions,
    budget: VerificationBudget,
    estimates: Mapping[tuple[str, str], LookupEstimate],
    *,
    remaining_cost_units: int,
) -> tuple[tuple[str, str], ...]:
    """Rank registered MACHINE/UNKNOWN lookups by cost per settlement (SDD v2 AR-025).

    PROVED and REFUTED both count as settlement when fitting estimates.
    All preconditions still need to pass the existing independent checker
    and composer before dispatch. Cost here is estimated, not metered.
    """
    if type(remaining_cost_units) is not int or remaining_cost_units < 0:
        raise ValueError("invalid remaining cost")
    if (checked.context_hash != requirements.context_hash
            or checked.requirements_hash != requirements.requirements_hash):
        raise ValueError("checked state does not belong to these requirements")
    if not requirements.authorizable or not checked.complete or budget.exhausted:
        return ()
    required = [p for p in requirements.preconditions if p.required]
    for pre in required:
        state = checked.state(pre.precondition_id)
        if state in (LogicalState.REFUTED, LogicalState.CONFLICT):
            return ()
        if pre.resolution_class is ResolutionClass.TERMINAL and state is not LogicalState.PROVED:
            return ()
    candidates = open_candidates(requirements, checked, budget)
    if len(candidates) > 64:
        raise ValueError("candidate limit exceeded")
    if any(candidate not in estimates for candidate in candidates):
        raise ValueError("missing deployment estimate")
    candidates.sort(key=lambda c: (
        Fraction(estimates[c].cost_units, estimates[c].settle_ppm), c,
    ))
    selected: list[tuple[str, str]] = []
    seen: set[str] = set()
    for candidate in candidates:
        if len(selected) >= min(budget.calls_left, budget.requests_per_round):
            break
        pid, _ = candidate
        cost = estimates[candidate].cost_units
        if pid in seen or cost > remaining_cost_units:
            continue
        selected.append(candidate)
        seen.add(pid)
        remaining_cost_units -= cost
    return tuple(selected)


def plan_verification(requirements: RequirementSet, checked: CheckedPreconditions,
                      budget: VerificationBudget, mode: PlannerMode, *,
                      hints: Sequence[str] = (), seed: int = 0,
                      estimates: Mapping[tuple[str, str], LookupEstimate] | None = None,
                      remaining_cost_units: int | None = None,
                      ) -> tuple[list[tuple[str, str]], tuple[str, ...]]:
    """The next round's (precondition, resolver) pairs, and the hints that were dropped."""
    candidates = open_candidates(requirements, checked, budget)
    open_ids = {pid for pid, _ in candidates}
    rejected = tuple(h for h in hints if h not in open_ids) if mode is PlannerMode.H_EDV else tuple(hints)
    if mode is PlannerMode.H0 or not requirements.authorizable:
        return [], rejected
    if mode is PlannerMode.H_COST:
        if estimates is None or remaining_cost_units is None:
            raise ValueError("H_COST requires deployment estimates and remaining_cost_units")
        return list(choose_next_by_cost(
            requirements, checked, budget, estimates,
            remaining_cost_units=remaining_cost_units,
        )), rejected
    if mode is PlannerMode.H_EDV:
        priority = {h: i for i, h in enumerate(dict.fromkeys(h for h in hints if h in open_ids))}
        candidates.sort(key=lambda c: priority.get(c[0], len(priority)))
    elif mode is PlannerMode.H_RANDOM:
        # A seeded control arm, not a security choice.
        random.Random(f"{seed}:{requirements.context_hash}:{budget.rounds}").shuffle(candidates)  # noqa: S311
    take: list[tuple[str, str]] = []
    for pid, rid in candidates:
        if len(take) >= min(budget.requests_per_round, budget.calls_left):
            break
        if pid not in {p for p, _ in take}:
            take.append((pid, rid))
    return take, rejected


@dataclass(frozen=True)
class VerificationRun:
    requirements: RequirementSet
    checked: CheckedPreconditions
    evidence: tuple[ResolverEvidence, ...]
    issued: Mapping[str, VerificationRequest]
    budget: VerificationBudget
    stop_reason: str
    refused_requests: tuple[tuple[str, str], ...]
    rejected_hints: tuple[str, ...]
    history: tuple[CheckedPreconditions, ...]

    @property
    def budget_exhausted(self) -> bool:
        return self.stop_reason in ("round_budget_exhausted", "verification_budget_exhausted",
                                    "deadline")


def run_verification(context: ProposalContext, requirements: RequirementSet, *,
                     registry: PreconditionRegistry, verifiers: Mapping[str, Verifier],
                     resolvers: Mapping[str, Resolver], held_capabilities: frozenset[str],
                     mode: PlannerMode, budget: VerificationBudget,
                     clock_ms: Callable[[], int],
                     hints_for: Callable[[CheckedPreconditions], Sequence[str]] | None = None,
                     seed: int = 0,
                     evidence: Sequence[ResolverEvidence] = (),
                     issued: Mapping[str, VerificationRequest] | None = None,
                     review: ReviewAttestation | None = None) -> VerificationRun:
    """Check, then look up and re-check until a stop condition holds.

    The loop has stopped when this returns, so a composition over the result
    passes no ``verifiable`` IDs: whatever is still UNKNOWN is a stop, not a
    pending VERIFY.

    *hints_for* is called once per round with the current check and returns
    the monitor's hinted precondition IDs (H_EDV only), at most
    ``budget.max_monitor_calls`` times. It is how the monitor reaches the
    loop; it cannot reach anything else.
    """
    start = clock_ms()
    deadline = start + budget.wall_deadline_ms
    evidence_list, issued_map = list(evidence), dict(issued or {})
    refused: list[tuple[str, str]] = []
    rejected_hints: list[str] = []

    def check(revision: int) -> CheckedPreconditions:
        return check_preconditions(context, requirements, evidence_list, issued=issued_map,
                                   registry=registry, verifiers=verifiers,
                                   now_s=clock_ms() // 1000, evidence_revision=revision,
                                   review=review)

    revision = 0
    checked = check(revision)
    history = [checked]

    def done(reason: str) -> VerificationRun:
        return VerificationRun(requirements, checked, tuple(evidence_list), dict(issued_map), budget, reason,
                               tuple(refused), tuple(rejected_hints), tuple(history))

    while True:
        required = [p for p in requirements.preconditions if p.required]
        if not requirements.authorizable:
            return done("requirements_incomplete")
        states = {p.precondition_id: checked.state(p.precondition_id) for p in required}
        if any(s in (LogicalState.REFUTED, LogicalState.CONFLICT) for s in states.values()):
            return done("refuted_or_conflict")
        if all(states[p.precondition_id] is LogicalState.PROVED for p in required
               if p.resolution_class is ResolutionClass.MACHINE):
            return done("machine_preconditions_settled")
        if budget.rounds >= budget.max_rounds:
            return done("round_budget_exhausted")
        if budget.calls_left == 0:
            return done("verification_budget_exhausted")
        if clock_ms() >= deadline:
            return done("deadline")
        hints: Sequence[str] = ()
        if mode is PlannerMode.H_EDV and hints_for is not None \
                and budget.spent_monitor_calls < budget.max_monitor_calls:
            # Each hint request is a monitor call and is charged to the budget;
            # past the cap the round runs in H_DET order.
            budget = replace(budget, spent_monitor_calls=budget.spent_monitor_calls + 1)
            hints = tuple(hints_for(checked))
        plan, dropped = plan_verification(requirements, checked, budget, mode,
                                          hints=hints, seed=seed)
        rejected_hints.extend(h for h in dropped if h not in rejected_hints)
        if not plan:
            return done("no_candidate" if mode is not PlannerMode.H0 else "no_verification_in_h0")
        spent, keys = budget.spent_calls, set(budget.dedup_keys)
        for pid, rid in plan:
            if clock_ms() >= deadline:
                break
            pre = requirements.by_id(pid)
            if pre is None:  # plan_verification only returns IDs from this set
                continue
            keys.add(_dedup_key(context.context_hash, pid, rid))
            request = VerificationRequest(
                request_id=tagged_digest("request", {"context_hash": context.context_hash,
                                                     "precondition_id": pid, "resolver_id": rid,
                                                     "revision": revision}),
                context_hash=context.context_hash, evidence_revision=revision,
                precondition_id=pid, resolver_id=rid, subject_ref=pre.subject_ref,
                deadline_ms=min(deadline, clock_ms() + budget.resolver_timeout_ms),
                budget_ref=context.proposal_id)
            issued_map[request.request_id] = request
            try:
                item = run_request(request, context, registry=registry, resolvers=resolvers,
                                   held_capabilities=held_capabilities, now_s=clock_ms() // 1000)
            except ResolverRefused as refusal:
                refused.append((request.request_id, str(refusal)))
                continue
            except Exception as exc:  # a failed lookup is spent and recorded
                spent += 1
                refused.append((request.request_id, f"resolver_error:{type(exc).__name__}"))
                continue
            spent += 1
            if clock_ms() >= request.deadline_ms:
                refused.append((request.request_id, "resolver_timeout"))
                continue
            evidence_list.append(item)
        budget = replace(budget, spent_calls=spent, rounds=budget.rounds + 1,
                         dedup_keys=frozenset(keys))
        revision += 1
        before = {r.precondition_id: r.logical_state for r in checked.results}
        checked = check(revision)
        history.append(checked)
        if clock_ms() >= deadline:
            return done("deadline")
        if {r.precondition_id: r.logical_state for r in checked.results} == before:
            # Keep the check, but a round that settled nothing ends the loop.
            if not open_candidates(requirements, checked, budget):
                return done("no_progress")

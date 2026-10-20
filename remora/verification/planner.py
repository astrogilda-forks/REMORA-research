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

import hashlib
import random
import sqlite3
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from enum import StrEnum
from fractions import Fraction
from pathlib import Path
from typing import Any

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

__all__ = [
    "FamilyLedger",
    "LookupEstimate",
    "PlannerMode",
    "TaskCallLedger",
    "VerificationBudget",
    "VerificationRun",
    "choose_next_by_cost",
    "choose_next_lookahead",
    "diagnose_refusal_causes",
    "open_candidates",
    "plan_verification",
    "run_verification",
    "check_recovery_bundle_consistency",
]


class PlannerMode(StrEnum):
    H0 = "h0"              # no new lookups
    H_DET = "h_det"
    H_COST = "h_cost"      # deterministic cost-per-settlement baseline (SDD v2 AR-025)
    H_AR = "h_ar"          # bounded lookahead over required MACHINE preconditions (SDD v2 AR-026)
    H_EDV = "h_edv"
    H_RANDOM = "h_random"


@dataclass(frozen=True)
class LookupEstimate:
    """Server-owned development estimate for a (precondition_id, resolver_id) pair (AR-025/026)."""

    cost_units: int
    settle_ppm: int
    refute_ppm: int = 0

    def __post_init__(self) -> None:
        if type(self.cost_units) is not int or self.cost_units <= 0:
            raise ValueError("cost_units must be a positive integer")
        if type(self.settle_ppm) is not int or not 1 <= self.settle_ppm <= 1_000_000:
            raise ValueError("settle_ppm must be an integer in [1, 1000000]")
        if type(self.refute_ppm) is not int or not 0 <= self.refute_ppm <= self.settle_ppm:
            raise ValueError("refute_ppm must be an integer in [0, settle_ppm]")


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


#: TaskCallLedger.reserve_status outcomes.
RESERVED, DUPLICATE, EXHAUSTED, CLOSED = "reserved", "duplicate", "exhausted", "closed"
#: ``reserve(kind, key) -> status``: the hook run_verification calls before
#: every external activity it starts.
Reserve = Callable[[str, str], str]


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
        """True only when this call made a new reservation."""
        return self.reserve_status(task_id, binding, operation_id, request_hash,
                                   units) == RESERVED

    def ensure(self, task_id: str, binding: str, cap: int) -> None:
        """Create the task's budget, or check that the existing one has this binding."""
        _bounded_id(task_id)
        _bounded_id(binding)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT binding FROM task_budget WHERE task_id=?",
                               (task_id,)).fetchone()
            if row is None:
                if type(cap) is not int or not 0 <= cap <= 1_000_000:
                    raise ValueError("invalid cap")
                conn.execute("INSERT INTO task_budget(task_id,binding,cap) VALUES(?,?,?)",
                             (task_id, binding, cap))
            elif row[0] != binding:
                raise ValueError("unknown task or binding mismatch")

    def reserve_status(
        self,
        task_id: str,
        binding: str,
        operation_id: str,
        request_hash: str,
        units: int = 1,
    ) -> str:
        """``reserved``: new reservation, the call may run. ``duplicate``: this
        operation was reserved before (a replay after a crash or a retry under
        the same key); it must not run again. ``exhausted`` or ``closed``: no
        budget; nothing may run."""
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
                return DUPLICATE
            changed = conn.execute(
                "UPDATE task_budget SET spent=spent+? "
                "WHERE task_id=? AND closed=0 AND spent+?<=cap",
                (units, task_id, units),
            ).rowcount
            if changed != 1:
                closed = conn.execute("SELECT closed FROM task_budget WHERE task_id=?",
                                      (task_id,)).fetchone()[0]
                return CLOSED if closed else EXHAUSTED
            conn.execute(
                "INSERT INTO reservation VALUES(?,?,?,?)",
                (task_id, operation_id, request_hash, units),
            )
            return RESERVED

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


def choose_next_lookahead(
    requirements: RequirementSet,
    checked: CheckedPreconditions,
    budget: VerificationBudget,
    estimates: Mapping[tuple[str, str], LookupEstimate],
    *,
    remaining_cost_units: int,
    hints: Sequence[str] = (),
    max_candidates: int = 64,
    max_depth: int = 3,
    beam_width: int = 16,
    cpu_deadline_ms: float = 50.0,
    mono_ns: Callable[[], int] | None = None,
) -> tuple[tuple[str, str], ...]:
    """Bounded Bellman/beam lookahead over required MACHINE preconditions (SDD v2 WP-06 / AR-026).

    1. Joint AND-feasibility pruning: discards any candidate step whose cost
       leaves less than the minimum cost required to cover the remaining open
       required MACHINE preconditions within ``remaining_cost_units``.
    2. Bellman expected-cost minimization: among jointly feasible plans, ranks
       sequences by ``expected_cost / joint_settlement_probability``, where
       each step's survival probability accounts for early refutation stop
       (``refute_ppm`` plus bounded monitor hint priority on open preconditions).
    3. Never mutates ``checked``: modelled transitions are planning hypotheses only.
    """
    if type(remaining_cost_units) is not int or remaining_cost_units < 0:
        raise ValueError("invalid remaining cost")
    if type(max_candidates) is not int or not 1 <= max_candidates <= 64:
        raise ValueError("max_candidates must be in [1, 64]")
    if type(max_depth) is not int or not 1 <= max_depth <= 3:
        raise ValueError("max_depth must be in [1, 3]")
    if type(beam_width) is not int or not 1 <= beam_width <= 16:
        raise ValueError("beam_width must be in [1, 16]")
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
    if len(candidates) > max_candidates:
        raise ValueError("candidate limit exceeded")
    if not candidates:
        return ()
    if any(c not in estimates for c in candidates):
        raise ValueError("missing deployment estimate")

    open_pids = sorted({pid for pid, _ in candidates})
    need_count = len(open_pids)
    step_limit = min(max_depth, budget.calls_left)
    if step_limit < need_count:
        return ()

    # Minimum cost to attempt each open precondition (for exact lookahead pruning)
    min_cost_for_pid: dict[str, int] = {}
    for pid, rid in candidates:
        c_val = estimates[(pid, rid)].cost_units
        if pid not in min_cost_for_pid or c_val < min_cost_for_pid[pid]:
            min_cost_for_pid[pid] = c_val

    if sum(min_cost_for_pid.values()) > remaining_cost_units:
        return ()

    hint_rank = {
        h: idx for idx, h in enumerate(dict.fromkeys(h for h in hints if h in min_cost_for_pid))
    }

    def _eff_refute_ppm(cand: tuple[str, str]) -> int:
        est = estimates[cand]
        base_ref = est.refute_ppm
        if cand[0] in hint_rank:
            # A valid monitor hint raises the expected early-stop weight for ordering
            # among feasible plans (Simon-Kadane p_refute / cost ordering), never authority.
            boost = max(600_000 - hint_rank[cand[0]] * 100_000, 100_000)
            return min(950_000, base_ref + boost)
        return base_ref

    clock = mono_ns or time.monotonic_ns
    start_ns = clock()
    deadline_ns = start_ns + int(cpu_deadline_ms * 1_000_000)

    # Beam state: (seq, settled_pids, total_cost, joint_settle_ppm, survival_ppm, expected_cost_ppm)
    beam: list[tuple[tuple[tuple[str, str], ...], frozenset[str], int, int, int, int]] = [
        ((), frozenset(), 0, 1_000_000, 1_000_000, 0)
    ]
    completed_plans: list[tuple[tuple[tuple[str, str], ...], int, int, int]] = []

    for _depth in range(step_limit):
        if clock() >= deadline_ns:
            break
        next_beam: list[tuple[tuple[tuple[str, str], ...], frozenset[str], int, int, int, int]] = []
        for seq, settled, cost_so_far, settle_ppm, survival_ppm, exp_cost_ppm in beam:
            if clock() >= deadline_ns:
                break
            for cand in candidates:
                pid, _rid = cand
                if pid in settled:
                    continue
                est = estimates[cand]
                new_cost = cost_so_far + est.cost_units
                new_settled = settled | {pid}
                # Joint feasibility lookahead bound: remaining open preconditions must fit
                rem_min_cost = sum(
                    mc for p_other, mc in min_cost_for_pid.items() if p_other not in new_settled
                )
                if new_cost + rem_min_cost > remaining_cost_units:
                    continue
                new_seq = (*seq, cand)
                new_settle = max(1, (settle_ppm * est.settle_ppm) // 1_000_000)
                new_exp_cost = exp_cost_ppm + survival_ppm * est.cost_units
                ref_ppm = _eff_refute_ppm(cand)
                new_survival = max(1, (survival_ppm * (1_000_000 - ref_ppm)) // 1_000_000)
                if len(new_settled) == need_count:
                    completed_plans.append((new_seq, new_cost, new_settle, new_exp_cost))
                else:
                    next_beam.append((
                        new_seq, new_settled, new_cost, new_settle, new_survival, new_exp_cost
                    ))
        if not next_beam:
            break
        next_beam.sort(key=lambda item: (Fraction(item[5], item[3]), item[2], item[0]))
        beam = next_beam[:beam_width]

    if completed_plans:
        completed_plans.sort(key=lambda item: (
            Fraction(item[3], item[2]),  # expected_cost_ppm / joint_settle_ppm
            Fraction(item[1], item[2]),  # worst_case_cost / joint_settle_ppm
            item[0],
        ))
        best_seq = completed_plans[0][0]
        return best_seq[: min(budget.calls_left, budget.requests_per_round)]

    return choose_next_by_cost(
        requirements, checked, budget, estimates,
        remaining_cost_units=remaining_cost_units,
    )


def plan_verification(requirements: RequirementSet, checked: CheckedPreconditions,
                      budget: VerificationBudget, mode: PlannerMode, *,
                      hints: Sequence[str] = (), seed: int = 0,
                      estimates: Mapping[tuple[str, str], LookupEstimate] | None = None,
                      remaining_cost_units: int | None = None,
                      ) -> tuple[list[tuple[str, str]], tuple[str, ...]]:
    """The next round's (precondition, resolver) pairs, and the hints that were dropped."""
    candidates = open_candidates(requirements, checked, budget)
    open_ids = {pid for pid, _ in candidates}
    rejected = tuple(h for h in hints if h not in open_ids) if mode in (
        PlannerMode.H_EDV, PlannerMode.H_AR
    ) else tuple(hints)
    if mode is PlannerMode.H0 or not requirements.authorizable:
        return [], rejected
    if mode is PlannerMode.H_COST:
        if estimates is None or remaining_cost_units is None:
            raise ValueError("H_COST requires deployment estimates and remaining_cost_units")
        return list(choose_next_by_cost(
            requirements, checked, budget, estimates,
            remaining_cost_units=remaining_cost_units,
        )), rejected
    if mode is PlannerMode.H_AR:
        if estimates is None or remaining_cost_units is None:
            raise ValueError("H_AR requires deployment estimates and remaining_cost_units")
        return list(choose_next_lookahead(
            requirements, checked, budget, estimates,
            remaining_cost_units=remaining_cost_units,
            hints=hints,
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
            if remaining_cost_units is not None:
                if estimates is None or (pid, rid) not in estimates:
                    raise ValueError("missing deployment estimate")
                cost = estimates[(pid, rid)].cost_units
                if cost > remaining_cost_units:
                    continue
                remaining_cost_units -= cost
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
                                    "cost_budget_exhausted", "deadline",
                                    "task_budget_exhausted")


def run_verification(context: ProposalContext, requirements: RequirementSet, *,
                     registry: PreconditionRegistry, verifiers: Mapping[str, Verifier],
                     resolvers: Mapping[str, Resolver], held_capabilities: frozenset[str],
                     mode: PlannerMode, budget: VerificationBudget,
                     clock_ms: Callable[[], int],
                     wall_clock_s: Callable[[], int] | None = None,
                     hints_for: Callable[[CheckedPreconditions], Sequence[str]] | None = None,
                     seed: int = 0,
                     estimates: Mapping[tuple[str, str], LookupEstimate] | None = None,
                     cost_budget_units: int | None = None,
                     evidence: Sequence[ResolverEvidence] = (),
                     issued: Mapping[str, VerificationRequest] | None = None,
                     review: ReviewAttestation | None = None,
                     reserve: Reserve | None = None) -> VerificationRun:
    """Check, then look up and re-check until a stop condition holds.

    With *reserve*, every resolver lookup and every hint request is reserved
    first (kind ``lookup`` or ``monitor``, keyed by its request). A lookup
    that is not ``reserved`` does not run: ``duplicate`` (reserved before,
    e.g. before a crash) leaves its precondition UNKNOWN rather than repeat
    it, and ``exhausted`` or ``closed`` stops the loop as
    ``task_budget_exhausted``. A hint request that is not reserved is skipped.

    The loop has stopped when this returns, so a composition over the result
    passes no ``verifiable`` IDs: whatever is still UNKNOWN is a stop, not a
    pending VERIFY.

    With ``wall_clock_s``, ``clock_ms`` is the monotonic deadline clock and
    must share a domain with deployed adapters. Evidence timestamps and TTL
    checks use epoch seconds from ``wall_clock_s``. Without it, the legacy
    epoch-millisecond clock supplies both, preserving existing deployments.

    *hints_for* is called once per round with the current check and returns
    the monitor's hinted precondition IDs (H_EDV only), at most
    ``budget.max_monitor_calls`` times. It is how the monitor reaches the
    loop; it cannot reach anything else. Time spent in it extends the wall
    deadline by the same amount: the deadline bounds lookups, and the monitor
    is bounded by its own timeout and call cap.
    """
    if cost_budget_units is not None:
        if type(cost_budget_units) is not int or cost_budget_units < 0:
            raise ValueError("invalid cost budget")
        if estimates is None:
            raise ValueError("cost budget requires deployment estimates")
    start = clock_ms()
    wall_now = wall_clock_s or (lambda: clock_ms() // 1000)
    deadline = start + budget.wall_deadline_ms
    rem_cost = cost_budget_units
    evidence_list, issued_map = list(evidence), dict(issued or {})
    refused: list[tuple[str, str]] = []
    rejected_hints: list[str] = []

    def check(revision: int) -> CheckedPreconditions:
        return check_preconditions(context, requirements, evidence_list, issued=issued_map,
                                   registry=registry, verifiers=verifiers,
                                   now_s=wall_now(), evidence_revision=revision,
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
        if mode in (PlannerMode.H_EDV, PlannerMode.H_AR) and hints_for is not None \
                and budget.spent_monitor_calls < budget.max_monitor_calls \
                and (reserve is None
                     or reserve("monitor", f"hint:{revision}:{budget.spent_monitor_calls}")
                     == RESERVED):
            # Each hint request is a monitor call and is charged to the budget;
            # past the cap the round runs without hints.
            budget = replace(budget, spent_monitor_calls=budget.spent_monitor_calls + 1)
            asked = clock_ms()
            hints = tuple(hints_for(checked))
            # The wall deadline bounds lookups. Monitor time is bounded by the
            # monitor's own timeout and call cap, so it does not eat into it.
            deadline += max(0, clock_ms() - asked)
        plan, dropped = plan_verification(
            requirements, checked, budget, mode,
            hints=hints, seed=seed, estimates=estimates, remaining_cost_units=rem_cost,
        )
        rejected_hints.extend(h for h in dropped if h not in rejected_hints)
        if not plan:
            if (
                mode in (PlannerMode.H_COST, PlannerMode.H_AR)
                and rem_cost is not None
                and open_candidates(requirements, checked, budget)
            ):
                return done("cost_budget_exhausted")
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
            if reserve is not None:
                status = reserve("lookup", request.request_id)
                if status == DUPLICATE:
                    refused.append((request.request_id, "reserved_before_not_repeated"))
                    continue
                if status != RESERVED:
                    budget = replace(budget, spent_calls=spent, dedup_keys=frozenset(keys))
                    return done("task_budget_exhausted")
            issued_map[request.request_id] = request
            step_cost = (
                estimates[(pid, rid)].cost_units
                if estimates is not None and (pid, rid) in estimates
                else 0
            )
            try:
                item = run_request(request, context, registry=registry, resolvers=resolvers,
                                   held_capabilities=held_capabilities, now_s=wall_now())
            except ResolverRefused as refusal:
                if refusal.attempted:
                    spent += 1
                    if rem_cost is not None:
                        rem_cost -= step_cost
                refused.append((request.request_id, str(refusal)))
                continue
            except Exception as exc:  # a failed lookup is spent and recorded
                spent += 1
                if rem_cost is not None:
                    rem_cost = max(0, rem_cost - step_cost)
                refused.append((request.request_id, f"resolver_error:{type(exc).__name__}"))
                continue
            spent += 1
            if rem_cost is not None:
                rem_cost = max(0, rem_cost - step_cost)
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


def diagnose_refusal_causes(
    requirements: RequirementSet,
    checked: CheckedPreconditions,
    record: Any,
    *,
    agent_error: bool = False,
) -> tuple[str, ...]:
    """Multi-cause refusal diagnostic (SDD v2 WP-05 / AR-023).

    Preserves all applicable refusal causes in canonical order rather than
    collapsing a refusal into a single mutually exclusive bucket.
    """
    from remora.policy.composition import NON_APPROVABLE_REASONS

    causes: list[str] = []
    if not requirements.authorizable:
        causes.append("contract_missing")
    non_app_vals = {r.value for r in NON_APPROVABLE_REASONS}
    base_reasons = set(getattr(record, "base_reasons", ()) or ())
    required = [p for p in requirements.preconditions if p.required]
    has_refuted_or_terminal = any(
        checked.state(p.precondition_id) in (LogicalState.REFUTED, LogicalState.CONFLICT)
        or (
            p.resolution_class is ResolutionClass.TERMINAL
            and checked.state(p.precondition_id) is not LogicalState.PROVED
        )
        for p in required
    )
    if (base_reasons & non_app_vals) or has_refuted_or_terminal:
        causes.append("hard_deny")
    if any(
        p.resolution_class is ResolutionClass.MACHINE
        and checked.state(p.precondition_id) is LogicalState.UNKNOWN
        for p in required
    ):
        causes.append("machine_uncertainty")
    if getattr(record, "review_class", "") == "review" or any(
        p.resolution_class is ResolutionClass.REVIEW
        and checked.state(p.precondition_id) is not LogicalState.PROVED
        for p in required
    ):
        causes.append("review_required")
    if getattr(record, "review_class", "") == "grant" or any(
        p.resolution_class is ResolutionClass.GRANT
        and checked.state(p.precondition_id) is not LogicalState.PROVED
        for p in required
    ):
        causes.append("grant_required")
    mon_status = str(getattr(record, "monitor_status", "") or "")
    if getattr(record, "monitor_veto", False) or mon_status.startswith(("unavailable:", "invalid:")):
        causes.append("monitor_veto_or_outage")
    if agent_error:
        causes.append("agent_error")
    return tuple(causes)


def check_recovery_bundle_consistency(bundle: Mapping[str, Any]) -> tuple[bool, tuple[str, ...]]:
    """Check internal consistency of an UNTRUSTED, self-reported bundle.

    A True result means only that supplied fields agree. Hashes, key IDs,
    evidence conclusions, roles and observer reports all come from the same
    caller. No signature is verified, no trusted binding is established and
    no predicate or effect observation is independently reproduced. Never use
    this result to authorize, issue a grant or claim WP-07 / AR-029..032.
    The independent recovery verifier remains unimplemented.
    """
    problems: list[str] = []
    required_top = (
        "context_hash",
        "requirements_hash",
        "evidence_digest",
        "profile_hash",
        "policy_bundle_hash",
        "toolspec_hash",
        "key_id",
        "signed_grant_bytes",
        "expected_grant_sha256",
        "tenant_id",
        "proposal_id",
        "verified_at_s",
        "requirements",
        "evidence_records",
        "observer_report",
    )
    for k in required_top:
        if k not in bundle or bundle[k] is None or bundle[k] == "":
            problems.append(f"missing_field:{k}")
    if problems:
        return False, tuple(problems)

    grant_bytes = bundle["signed_grant_bytes"]
    if not isinstance(grant_bytes, (bytes, bytearray)):
        problems.append("invalid_signed_grant_bytes")
    else:
        actual_sha = hashlib.sha256(grant_bytes).hexdigest()
        if actual_sha != bundle["expected_grant_sha256"]:
            problems.append("grant_bytes_digest_mismatch")

    reqs = bundle["requirements"]
    if not isinstance(reqs, Mapping):
        return False, ("invalid_requirements_block",)
    if reqs.get("context_hash") != bundle["context_hash"]:
        problems.append("context_hash_mismatch")
    if reqs.get("requirements_hash") != bundle["requirements_hash"]:
        problems.append("requirements_hash_mismatch")
    if reqs.get("authorizable") is not True:
        problems.append("requirements_not_authorizable")
    preconditions = reqs.get("preconditions")
    if not isinstance(preconditions, Sequence) or not preconditions:
        problems.append("empty_preconditions")
        preconditions = ()

    ev_map: dict[str, Mapping[str, Any]] = {}
    for ev in bundle["evidence_records"]:
        if isinstance(ev, Mapping) and isinstance(ev.get("precondition_id"), str):
            ev_map[ev["precondition_id"]] = ev

    now_s = int(bundle["verified_at_s"])
    tenant_id = str(bundle["tenant_id"])
    proposal_id = str(bundle["proposal_id"])
    review_att = bundle.get("review_attestation")

    for pre in preconditions:
        if not isinstance(pre, Mapping) or not pre.get("required", True):
            continue
        pid = str(pre.get("precondition_id", ""))
        rclass = str(pre.get("resolution_class", ""))
        if rclass == "machine":
            ev = ev_map.get(pid)
            if ev is None:
                problems.append(f"missing_evidence:{pid}")
                continue
            if ev.get("tenant_id") != tenant_id:
                problems.append(f"evidence_tenant_mismatch:{pid}")
            if ev.get("subject_ref") != pre.get("subject_ref"):
                problems.append(f"evidence_subject_mismatch:{pid}")
            if ev.get("source_version") != pre.get("expected_source_version"):
                problems.append(f"evidence_source_version_mismatch:{pid}")
            acq = ev.get("acquired_at")
            val = ev.get("valid_until")
            if not (isinstance(acq, int) and isinstance(val, int) and acq <= now_s < val):
                problems.append(f"evidence_stale_or_future:{pid}")
            payload = ev.get("payload")
            if not isinstance(payload, (bytes, bytearray)) or (
                hashlib.sha256(payload).hexdigest() != ev.get("payload_hash")
            ):
                problems.append(f"evidence_payload_hash_mismatch:{pid}")
            if ev.get("proved") is not True:
                problems.append(f"precondition_not_proved:{pid}")
        elif rclass == "review":
            if not isinstance(review_att, Mapping):
                problems.append(f"missing_review_attestation:{pid}")
            else:
                if review_att.get("proposal_id") != proposal_id:
                    problems.append(f"review_proposal_mismatch:{pid}")
                if review_att.get("approver_role") != pre.get("review_role"):
                    problems.append(f"review_role_mismatch:{pid}")
        else:
            problems.append(f"unresolvable_class_in_recovery_bundle:{pid}:{rclass}")

    obs = bundle["observer_report"]
    if not isinstance(obs, Mapping):
        problems.append("invalid_observer_report")
    else:
        if obs.get("observer_complete") is not True:
            problems.append("observer_incomplete")
        if obs.get("desired_delta_matched") is not True:
            problems.append("postcondition_delta_mismatch")
        if obs.get("unauthorized_side_effects"):
            problems.append("unauthorized_side_effect_observed")

    return len(problems) == 0, tuple(problems)


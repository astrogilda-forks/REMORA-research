# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""VerificationPlan v2: explicit bindings and typed source evidence (S1, S2).

Design: ``docs/design/verification-plan-v2.md``. Owner decisions D7 and D8 in
``docs/architecture/ADR-sdd-as-v1-owner-decisions.md`` set the source registry
and the task budget.

The v1 plan in ``remora/policy/resolution.py`` pairs arguments with sources by
list position, has no expiry and no task budget, and hands the validator only
``(source_tool, argument_name)``. This module defines the replacement values
and the check that decides whether one piece of source evidence counts:

* ``VerificationPlanV2`` is frozen and refuses anything malformed when it is
  built. Each target names its own source contract, so a positional fallback
  cannot exist.
* ``assess_evidence`` compares a ``SourceEvidence`` record with the plan, the
  call and the deployment's accepted source contracts. Any mismatch makes the
  evidence UNKNOWN, never SUPPORTED.
* ``plan_outcome`` folds the assessments into SUPPORTED, REFUTED or ABSTAIN.
  Only SUPPORTED on every target may lead to re-entry.

Nothing here is wired: no engine path emits or consumes v2 plans yet (S4),
and the durable task budget is S3. The module is pure. It reads no clock;
every time comes in as an argument. It imports only the standard library,
because ``tests/test_import_cost.py`` keeps the engine free of the evidence
stack and S4 will import this module from the engine.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Iterable, Mapping, Sequence, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from types import MappingProxyType
from typing import Any

SCHEMA = "remora-verification-plan/v2"

#: Domain tag for value digests. The evidence-admission canonical form is not
#: reused: it refuses floats, and call arguments carry them (amounts, rates).
VALUE_DIGEST_DOMAIN = b"remora-vp2-value/v1\x00"

#: ADR D8: the default task budget, and the ceiling no deployment may exceed.
DEFAULT_MAX_LOOKUPS = 8
DEFAULT_DEADLINE_SECONDS = 120
MAX_LOOKUPS_CEILING = 32
DEADLINE_SECONDS_CEILING = 600

_MAX_VALUE_DEPTH = 32
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ARRAY_INDEX = re.compile(r"(?:0|[1-9][0-9]*)\Z")


class TargetMode(Enum):
    """What a target may do. Two code paths, not a flag on one path."""

    #: Judge a value already in the call. Never changes it.
    VALIDATE_EXISTING = "validate_existing"
    #: Fill a pointer that is absent from the call. The result is a new call.
    RESOLVE_MISSING = "resolve_missing"


class EvidenceVerdict(Enum):
    SUPPORTED = "supported"
    REFUTED = "refuted"
    UNKNOWN = "unknown"


class PlanOutcome(Enum):
    #: Every target SUPPORTED by matching evidence: re-enter the engine.
    SUPPORTED = "supported"
    #: A target REFUTED: the call is blocked, never retried into acceptance.
    REFUTED = "refuted"
    #: Anything else: missing, unknown, conflicting or unbound evidence.
    ABSTAIN = "abstain"


def _require_text(value: Any, name: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{name} must be a non-empty string without outer whitespace")
    return value


def _require_digest(value: Any, name: str) -> str:
    if type(value) is not str or not _DIGEST.match(value):
        raise ValueError(f"{name} must be 'sha256:' and 64 lowercase hex digits")
    return value


def _require_aware(value: Any, name: str) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")
    return value


def _require_int(value: Any, name: str, *, low: int, high: int | None = None) -> int:
    if type(value) is not int:
        raise ValueError(f"{name} must be an int, got {type(value).__name__}")
    if value < low or (high is not None and value > high):
        bound = f"in [{low}, {high}]" if high is not None else f">= {low}"
        raise ValueError(f"{name} must be {bound}, got {value}")
    return value


def parse_pointer(pointer: Any) -> tuple[str, ...]:
    """RFC 6901 reference tokens. The root pointer ``""`` is refused.

    A target addresses one argument, never the whole call.
    """
    if type(pointer) is not str or not pointer.startswith("/"):
        raise ValueError(f"pointer must be a JSON pointer starting with '/', got {pointer!r}")
    tokens = []
    for raw in pointer[1:].split("/"):
        if re.search(r"~(?![01])", raw):
            raise ValueError(f"pointer {pointer!r} has an invalid '~' escape")
        tokens.append(raw.replace("~1", "/").replace("~0", "~"))
    return tuple(tokens)


def resolve_pointer(document: Any, pointer: str) -> tuple[bool, Any]:
    """Return ``(found, value)``. Never raises for an absent path."""
    current = document
    for token in parse_pointer(pointer):
        if isinstance(current, Mapping):
            if token not in current:
                return False, None
            current = current[token]
        elif isinstance(current, Sequence) and not isinstance(current, (str, bytes)):
            if not _ARRAY_INDEX.match(token) or int(token) >= len(current):
                return False, None
            current = current[int(token)]
        else:
            return False, None
    return True, current


def _plain(value: Any, depth: int = 0) -> Any:
    """The JSON form of ``value``, or a refusal. Frozen containers are unwrapped."""
    if depth > _MAX_VALUE_DEPTH:
        raise ValueError("value nesting limit exceeded")
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("value contains a non-finite float")
        return value
    if type(value) in (list, tuple):
        return [_plain(item, depth + 1) for item in value]
    if isinstance(value, Mapping) and all(type(k) is str for k in value):
        return {k: _plain(v, depth + 1) for k, v in value.items()}
    raise ValueError(f"value of type {type(value).__name__} has no canonical digest")


def value_digest(value: Any) -> str:
    """Digest of the value a source judged, under ``VALUE_DIGEST_DOMAIN``."""
    encoded = json.dumps(
        _plain(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(VALUE_DIGEST_DOMAIN + encoded).hexdigest()


@dataclass(frozen=True)
class PlanBinding:
    """The context a plan was issued in. Redemption elsewhere does not bind."""

    tenant_id: str
    principal: str
    task_ref: str
    original_call_digest: str
    policy_digest: str
    toolspec_digest: str
    authority_epoch: int

    def __post_init__(self) -> None:
        for name in ("tenant_id", "principal", "task_ref"):
            _require_text(getattr(self, name), name)
        for name in ("original_call_digest", "policy_digest", "toolspec_digest"):
            _require_digest(getattr(self, name), name)
        _require_int(self.authority_epoch, "authority_epoch", low=0)


@dataclass(frozen=True)
class TaskBudget:
    """Lookups and wall time for one ``(tenant_id, task_ref)`` (ADR D8)."""

    max_lookups: int = DEFAULT_MAX_LOOKUPS
    deadline_seconds: int = DEFAULT_DEADLINE_SECONDS

    def __post_init__(self) -> None:
        _require_int(self.max_lookups, "max_lookups", low=1, high=MAX_LOOKUPS_CEILING)
        _require_int(
            self.deadline_seconds, "deadline_seconds", low=1, high=DEADLINE_SECONDS_CEILING
        )


@dataclass(frozen=True)
class TargetBinding:
    """One argument, the source contract that may judge it, and the exact read."""

    pointer: str
    mode: TargetMode
    source_contract: str
    predicate: str
    source_call_digest: str

    def __post_init__(self) -> None:
        parse_pointer(self.pointer)
        if not isinstance(self.mode, TargetMode):
            raise ValueError(f"mode must be a TargetMode, got {self.mode!r}")
        _require_text(self.source_contract, "source_contract")
        _require_text(self.predicate, "predicate")
        _require_digest(self.source_call_digest, "source_call_digest")


def _overlaps(a: tuple[str, ...], b: tuple[str, ...]) -> bool:
    shorter = min(len(a), len(b))
    return a[:shorter] == b[:shorter]


@dataclass(frozen=True)
class VerificationPlanV2:
    plan_id: str
    issued_at: datetime
    expires_at: datetime
    binding: PlanBinding
    budget: TaskBudget
    targets: tuple[TargetBinding, ...]
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        # A plan is authority to act before the decision is final, so a
        # malformed one is refused here rather than interpreted later.
        if self.schema != SCHEMA:
            raise ValueError(f"schema must be {SCHEMA!r}, got {self.schema!r}")
        _require_text(self.plan_id, "plan_id")
        _require_aware(self.issued_at, "issued_at")
        _require_aware(self.expires_at, "expires_at")
        if not isinstance(self.binding, PlanBinding):
            raise ValueError("binding must be a PlanBinding")
        if not isinstance(self.budget, TaskBudget):
            raise ValueError("budget must be a TaskBudget")
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        if self.expires_at - self.issued_at > timedelta(seconds=self.budget.deadline_seconds):
            raise ValueError("a plan may not outlive its task budget deadline")
        if type(self.targets) is not tuple or not self.targets:
            raise ValueError("targets must be a non-empty tuple")
        if not all(isinstance(t, TargetBinding) for t in self.targets):
            raise ValueError("every target must be a TargetBinding")
        if len(self.targets) > self.budget.max_lookups:
            raise ValueError(
                f"{len(self.targets)} targets cannot be checked within "
                f"max_lookups={self.budget.max_lookups}"
            )
        parsed = [parse_pointer(t.pointer) for t in self.targets]
        for i, a in enumerate(parsed):
            for b in parsed[i + 1:]:
                if _overlaps(a, b):
                    raise ValueError(
                        "targets must address disjoint arguments; "
                        f"{self.targets[i].pointer!r} overlaps another target"
                    )

    def target(self, pointer: str) -> TargetBinding | None:
        for t in self.targets:
            if t.pointer == pointer:
                return t
        return None

    def is_live(self, *, now: datetime) -> bool:
        _require_aware(now, "now")
        return self.issued_at <= now < self.expires_at

    def call_problems(self, arguments: Mapping[str, Any]) -> tuple[str, ...]:
        """Why this plan does not fit ``arguments``. Empty means it fits.

        A VALIDATE_EXISTING target must find its value in the call. A
        RESOLVE_MISSING target must not: filling a present value would be a
        rewrite dressed as a lookup.
        """
        problems = []
        for t in self.targets:
            found, _ = resolve_pointer(arguments, t.pointer)
            if t.mode is TargetMode.VALIDATE_EXISTING and not found:
                problems.append(f"validate_target_absent:{t.pointer}")
            if t.mode is TargetMode.RESOLVE_MISSING and found:
                problems.append(f"resolve_target_present:{t.pointer}")
        return tuple(problems)

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "binding": {
                "tenant_id": self.binding.tenant_id,
                "principal": self.binding.principal,
                "task_ref": self.binding.task_ref,
                "original_call_digest": self.binding.original_call_digest,
                "policy_digest": self.binding.policy_digest,
                "toolspec_digest": self.binding.toolspec_digest,
                "authority_epoch": self.binding.authority_epoch,
            },
            "budget_ref": [self.binding.tenant_id, self.binding.task_ref],
            "budget": {
                "max_lookups": self.budget.max_lookups,
                "deadline_seconds": self.budget.deadline_seconds,
            },
            "targets": [
                {
                    "pointer": t.pointer,
                    "mode": t.mode.value,
                    "source_contract": t.source_contract,
                    "predicate": t.predicate,
                    "source_call_digest": t.source_call_digest,
                }
                for t in self.targets
            ],
        }


@dataclass(frozen=True)
class SourceEvidence:
    """What a source said about one target. A record, not a boolean."""

    plan_id: str
    pointer: str
    source_contract: str
    predicate: str
    source_call_digest: str
    tenant_id: str
    task_ref: str
    authority_epoch: int
    value_digest: str
    verdict: EvidenceVerdict
    observed_at: datetime

    def __post_init__(self) -> None:
        for name in ("plan_id", "source_contract", "predicate", "tenant_id", "task_ref"):
            _require_text(getattr(self, name), name)
        parse_pointer(self.pointer)
        _require_digest(self.source_call_digest, "source_call_digest")
        _require_digest(self.value_digest, "value_digest")
        _require_int(self.authority_epoch, "authority_epoch", low=0)
        if not isinstance(self.verdict, EvidenceVerdict):
            raise ValueError(f"verdict must be an EvidenceVerdict, got {self.verdict!r}")
        _require_aware(self.observed_at, "observed_at")


@dataclass(frozen=True)
class EvidenceAssessment:
    pointer: str
    reported: EvidenceVerdict
    #: What the evidence counts as. UNKNOWN whenever ``mismatches`` is non-empty.
    effective: EvidenceVerdict
    mismatches: tuple[str, ...]


def assess_evidence(
    plan: VerificationPlanV2,
    evidence: SourceEvidence,
    *,
    call_arguments: Mapping[str, Any],
    accepted_contracts: Set[str],
    now: datetime,
    resolved_values: Mapping[str, Any] | None = None,
) -> EvidenceAssessment:
    """Compare one piece of evidence with the plan, the call and the registry.

    ``accepted_contracts`` comes from the deployment's source registry (ADR
    D7). Trust never comes from the evidence itself: a contract the registry
    does not hold is self-asserted. For a RESOLVE_MISSING target the judged
    value is absent from the call and is taken from ``resolved_values``.
    """
    _require_aware(now, "now")
    mismatches: list[str] = []
    target = plan.target(evidence.pointer)
    binding = plan.binding

    if evidence.plan_id != plan.plan_id:
        mismatches.append("plan_id")
    if target is None:
        mismatches.append("pointer_not_in_plan")
    else:
        if evidence.source_contract != target.source_contract:
            mismatches.append("source_contract")
        if evidence.predicate != target.predicate:
            mismatches.append("predicate")
        if evidence.source_call_digest != target.source_call_digest:
            mismatches.append("source_call")
    if evidence.source_contract not in accepted_contracts:
        mismatches.append("source_not_accepted")
    if evidence.tenant_id != binding.tenant_id:
        mismatches.append("tenant")
    if evidence.task_ref != binding.task_ref:
        mismatches.append("task")
    if evidence.authority_epoch != binding.authority_epoch:
        mismatches.append("authority_epoch")

    if target is not None:
        if target.mode is TargetMode.VALIDATE_EXISTING:
            found, value = resolve_pointer(call_arguments, target.pointer)
        else:
            supplied = resolved_values or {}
            found = target.pointer in supplied
            value = supplied.get(target.pointer)
            if resolve_pointer(call_arguments, target.pointer)[0]:
                mismatches.append("resolve_target_present")
        if not found:
            mismatches.append("value_unavailable")
        else:
            try:
                if value_digest(value) != evidence.value_digest:
                    mismatches.append("value")
            except ValueError:
                mismatches.append("value_not_digestible")

    if not plan.is_live(now=now):
        mismatches.append("plan_not_live")
    if not plan.issued_at <= evidence.observed_at < plan.expires_at:
        mismatches.append("observed_outside_plan_window")
    if evidence.observed_at > now:
        mismatches.append("observed_in_future")

    effective = EvidenceVerdict.UNKNOWN if mismatches else evidence.verdict
    return EvidenceAssessment(
        pointer=evidence.pointer,
        reported=evidence.verdict,
        effective=effective,
        mismatches=tuple(mismatches),
    )


@dataclass(frozen=True)
class PlanResult:
    outcome: PlanOutcome
    #: pointer -> why that target did not reach SUPPORTED. Empty on SUPPORTED.
    reasons: Mapping[str, str]


def plan_outcome(
    plan: VerificationPlanV2, assessments: Iterable[EvidenceAssessment]
) -> PlanResult:
    """Fold assessments into one outcome. Only all-SUPPORTED re-enters.

    A target with two assessments that disagree is a conflict and does not
    count as either answer. A clean REFUTED anywhere blocks the call.
    """
    by_pointer: dict[str, set[EvidenceVerdict]] = {}
    for a in assessments:
        if plan.target(a.pointer) is None:
            continue
        by_pointer.setdefault(a.pointer, set()).add(a.effective)

    reasons: dict[str, str] = {}
    refuted = False
    for t in plan.targets:
        verdicts = by_pointer.get(t.pointer, set())
        if not verdicts:
            reasons[t.pointer] = "no_evidence"
        elif len(verdicts) > 1:
            reasons[t.pointer] = "conflicting_evidence"
        elif EvidenceVerdict.REFUTED in verdicts:
            reasons[t.pointer] = "refuted"
            refuted = True
        elif EvidenceVerdict.UNKNOWN in verdicts:
            reasons[t.pointer] = "unknown"

    if refuted:
        outcome = PlanOutcome.REFUTED
    elif reasons:
        outcome = PlanOutcome.ABSTAIN
    else:
        outcome = PlanOutcome.SUPPORTED
    return PlanResult(
        outcome=outcome, reasons=MappingProxyType(dict(sorted(reasons.items())))
    )

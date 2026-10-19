# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Execution preconditions: what must be PROVED before a call may run (WS1 §6.1-6.2).

Named *execution* preconditions to keep them apart from REAS evidence
obligations (``remora/evidence/obligations``), which settle what a call left
behind after dispatch. These are checked before it.

Every requirement set is compiled from the deployment's registry for the
exact call. Nothing here does I/O or reads a clock, and nothing grants
authority: a set only says which facts the decision still needs.

* An unknown tool, an empty set or a subject argument the call does not carry
  gives an *incomplete* set, and an incomplete set is never authorizable.
  ``all([])`` is True; this module never relies on it (WS1-06).
* The call hash in the context is recomputed from the call's arguments with
  the engine's own ``canonical_tool_call_hash``; a mismatch refuses to
  compile, so a requirement set cannot describe a different call (WS1-09).
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, fields
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from remora.evidence.admission.canonical import canonical_bytes
from remora.policy.observation import canonical_tool_call_hash

if TYPE_CHECKING:
    from remora.verification.registry import PreconditionRegistry

__all__ = [
    "CANONICALIZATION_ID",
    "DOMAIN",
    "ExecutionPrecondition",
    "LogicalState",
    "ProcessingStatus",
    "ProposalContext",
    "RequirementSet",
    "ResolutionClass",
    "derive_preconditions",
    "tagged_digest",
]

#: Domain separation for every WS1 commitment (WS1 §6.4).
DOMAIN = "REMORA/WS1-COMPOSITION/v1"
#: The evidence-admission encoding: sorted keys, no floats. Not RFC 8785.
CANONICALIZATION_ID = "remora-bounded-sorted-json/v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def tagged_digest(object_type: str, value: Any) -> str:
    """SHA-256 over ``DOMAIN:<type>``, a NUL byte, then the canonical bytes."""
    tag = f"{DOMAIN}:{object_type}".encode() + b"\x00"
    return hashlib.sha256(tag + canonical_bytes(value)).hexdigest()


class LogicalState(StrEnum):
    """What a verifier established. Only PROVED satisfies a requirement."""

    PROVED = "proved"
    REFUTED = "refuted"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"


class ProcessingStatus(StrEnum):
    """Whether the check ran. A failed check is never a verified negative."""

    COMPLETED = "completed"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"
    NO_DATA = "no_data"


class ResolutionClass(StrEnum):
    """Who can close an open precondition. Set by policy only."""

    MACHINE = "machine"    # a registered resolver and verifier
    REVIEW = "review"      # a named reviewer role, bound to this context
    GRANT = "grant"        # a grant of the right type; ordinary approval does not count
    TERMINAL = "terminal"  # nothing downstream can close it; a new proposal is needed


@dataclass(frozen=True)
class ProposalContext:
    """The immutable, server-built context one proposal is judged in (WS1 §6.3).

    Every ``*_hash`` and ``flow_digest`` is a SHA-256 hex digest computed by
    the server. A deployment without flow control binds the digest of its
    declared absence object, never an empty string a client could choose.
    """

    proposal_id: str
    tenant_id: str
    principal_id: str
    tool_name: str
    call_hash: str
    intent_authority_hash: str
    policy_bundle_hash: str
    toolspec_hash: str
    profile_hash: str
    capability_hash: str
    flow_digest: str
    flow_epoch: int
    context_version: int

    def __post_init__(self) -> None:
        for f in fields(self):
            value = getattr(self, f.name)
            if f.name in ("flow_epoch", "context_version"):
                if type(value) is not int or value < 0:
                    raise ValueError(f"{f.name}: non-negative integer required")
            elif f.name.endswith("_hash") or f.name == "flow_digest":
                if type(value) is not str or not _SHA256.match(value):
                    raise ValueError(f"{f.name}: 64-hex SHA-256 digest required")
            elif type(value) is not str or not value.strip():
                raise ValueError(f"{f.name}: nonempty identifier required")

    def to_dict(self) -> dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    @property
    def context_hash(self) -> str:
        return tagged_digest("context", {"canonicalization_id": CANONICALIZATION_ID,
                                         **self.to_dict()})


@dataclass(frozen=True)
class ExecutionPrecondition:
    """One fact the call needs, bound to its subject in this call."""

    precondition_id: str
    predicate_id: str
    subject_ref: str
    subject_binding_hash: str
    verifier_id: str
    resolver_ids: tuple[str, ...]
    required: bool
    resolution_class: ResolutionClass
    max_age_s: int
    review_role: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"precondition_id": self.precondition_id, "predicate_id": self.predicate_id,
                "subject_ref": self.subject_ref,
                "subject_binding_hash": self.subject_binding_hash,
                "verifier_id": self.verifier_id, "resolver_ids": list(self.resolver_ids),
                "required": self.required, "resolution_class": self.resolution_class.value,
                "max_age_s": self.max_age_s, "review_role": self.review_role}


@dataclass(frozen=True)
class RequirementSet:
    """The compiled requirement set for one context. Incomplete never authorizes."""

    context_hash: str
    registry_hash: str
    preconditions: tuple[ExecutionPrecondition, ...]
    complete: bool
    incomplete_reason: str = ""

    @property
    def authorizable(self) -> bool:
        """Complete and holding at least one required precondition."""
        return self.complete and any(p.required for p in self.preconditions)

    @property
    def requirements_hash(self) -> str:
        return tagged_digest("requirements", {
            "context_hash": self.context_hash, "registry_hash": self.registry_hash,
            "complete": self.complete, "incomplete_reason": self.incomplete_reason,
            "preconditions": [p.to_dict() for p in self.preconditions]})

    def by_id(self, precondition_id: str) -> ExecutionPrecondition | None:
        return next((p for p in self.preconditions if p.precondition_id == precondition_id), None)


def _subject_ref(value: Any) -> str | None:
    if type(value) is str and value.strip():
        return value
    if type(value) is int:
        return str(value)
    return None


def derive_preconditions(context: ProposalContext, arguments: Mapping[str, Any],
                         registry: PreconditionRegistry) -> RequirementSet:
    """Compile the full requirement set for *context* from *registry* (WS1-06).

    Raises ``ValueError`` when *arguments* are not the call the context binds.
    """
    if canonical_tool_call_hash(name=context.tool_name, arguments=dict(arguments),
                                tenant=context.tenant_id) != context.call_hash:
        raise ValueError("arguments do not match the context's call hash")

    def incomplete(reason: str) -> RequirementSet:
        return RequirementSet(context.context_hash, registry.registry_hash, (), False, reason)

    specs = registry.tools.get(context.tool_name)
    if specs is None:
        return incomplete("tool_not_in_registry")
    if not specs:
        return incomplete("empty_requirement_set")
    compiled: list[ExecutionPrecondition] = []
    for spec in specs:
        if spec.subject_argument is None:
            subject = context.tenant_id
        else:
            if spec.subject_argument not in arguments:
                return incomplete(f"subject_argument_missing:{spec.predicate_id}")
            ref = _subject_ref(arguments[spec.subject_argument])
            if ref is None:
                return incomplete(f"subject_argument_not_scalar:{spec.predicate_id}")
            subject = ref
        binding = tagged_digest("subject", {"call_hash": context.call_hash,
                                            "predicate_id": spec.predicate_id,
                                            "subject_ref": subject})
        compiled.append(ExecutionPrecondition(
            precondition_id=f"{spec.predicate_id}:{binding[:16]}",
            predicate_id=spec.predicate_id, subject_ref=subject,
            subject_binding_hash=binding, verifier_id=spec.verifier_id,
            resolver_ids=spec.resolver_ids, required=spec.required,
            resolution_class=spec.resolution_class, max_age_s=spec.max_age_s,
            review_role=spec.review_role.strip().lower() if spec.review_role else None))
    result = RequirementSet(context.context_hash, registry.registry_hash, tuple(compiled), True)
    if not result.authorizable:
        return incomplete("no_required_precondition")
    return result

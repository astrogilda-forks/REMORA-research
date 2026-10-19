# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The deployment-owned precondition registry (WS1 §6.1, §7.3).

Maps a tool to the predicates its calls need, and each predicate to the
resolvers that may fetch evidence for it. A resolver is named by ID and is
bound to one source and one read capability; no model, monitor or caller can
add an address, a query or a source. Construction refuses anything the
loop could not honour.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from remora.verification.preconditions import ResolutionClass, tagged_digest

__all__ = ["MAX_EVIDENCE_AGE_S", "PreconditionRegistry", "PredicateSpec", "RegistryError",
           "ResolverSpec"]

#: Upper bound on any evidence TTL in v1 (WS1 §7.2). A predicate may ask for less.
MAX_EVIDENCE_AGE_S = 60


class RegistryError(ValueError):
    """The registry is not a contract the loop can honour."""


@dataclass(frozen=True)
class PredicateSpec:
    """One predicate a tool's calls need.

    ``subject_argument`` names the call argument the predicate is about (the
    port, the recipient, the invoice). ``None`` makes the tenant the subject.
    """

    predicate_id: str
    resolution_class: ResolutionClass
    verifier_id: str
    resolver_ids: tuple[str, ...] = ()
    subject_argument: str | None = None
    max_age_s: int = MAX_EVIDENCE_AGE_S
    required: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"predicate_id": self.predicate_id,
                "resolution_class": self.resolution_class.value,
                "verifier_id": self.verifier_id, "resolver_ids": list(self.resolver_ids),
                "subject_argument": self.subject_argument, "max_age_s": self.max_age_s,
                "required": self.required}


@dataclass(frozen=True)
class ResolverSpec:
    """A bounded, tenant-scoped read: one source, the predicates it serves, the
    capability a context must hold before it runs (WS1 §7.3, A09)."""

    resolver_id: str
    source_id: str
    predicate_ids: frozenset[str]
    capability_id: str

    def to_dict(self) -> dict[str, Any]:
        return {"resolver_id": self.resolver_id, "source_id": self.source_id,
                "predicate_ids": sorted(self.predicate_ids),
                "capability_id": self.capability_id}


@dataclass(frozen=True)
class PreconditionRegistry:
    tools: Mapping[str, tuple[PredicateSpec, ...]]
    resolvers: Mapping[str, ResolverSpec] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for rid, resolver in self.resolvers.items():
            if resolver.resolver_id != rid:
                raise RegistryError(f"resolver {rid!r} names itself {resolver.resolver_id!r}")
            for name in (resolver.source_id, resolver.capability_id):
                if not name.strip():
                    raise RegistryError(f"resolver {rid!r} needs a source and a capability")
        for tool, specs in self.tools.items():
            seen: set[str] = set()
            for spec in specs:
                if spec.predicate_id in seen:
                    raise RegistryError(f"{tool}: predicate {spec.predicate_id!r} twice")
                seen.add(spec.predicate_id)
                if type(spec.max_age_s) is not int or not 0 < spec.max_age_s <= MAX_EVIDENCE_AGE_S:
                    raise RegistryError(
                        f"{tool}/{spec.predicate_id}: max_age_s must be 1..{MAX_EVIDENCE_AGE_S}")
                if not spec.verifier_id.strip():
                    raise RegistryError(f"{tool}/{spec.predicate_id}: verifier required")
                if spec.resolver_ids and spec.resolution_class is not ResolutionClass.MACHINE:
                    raise RegistryError(
                        f"{tool}/{spec.predicate_id}: only a machine predicate has resolvers")
                for rid in spec.resolver_ids:
                    serving = self.resolvers.get(rid)
                    if serving is None or spec.predicate_id not in serving.predicate_ids:
                        raise RegistryError(
                            f"{tool}/{spec.predicate_id}: resolver {rid!r} does not serve it")
        object.__setattr__(self, "tools", MappingProxyType({k: tuple(v) for k, v in self.tools.items()}))
        object.__setattr__(self, "resolvers", MappingProxyType(dict(self.resolvers)))

    @property
    def registry_hash(self) -> str:
        return tagged_digest("registry", {
            "tools": {tool: [s.to_dict() for s in specs] for tool, specs in self.tools.items()},
            "resolvers": {rid: r.to_dict() for rid, r in self.resolvers.items()}})

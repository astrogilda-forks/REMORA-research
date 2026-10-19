# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Resolvers: bounded, tenant-scoped reads that fetch evidence (WS1 §7.3).

A resolver runs only when the context holds its registered read capability.
That capability is separate from the call's own: finding out which port a
work order names must not need the write authority the call is asking for,
and a context without the read capability gets no lookup at all (A09).

A read is not free or automatically safe; it can expose data or reach a rate
limit. Nothing here performs the proposed call.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from remora.verification.check import ResolverEvidence, VerificationRequest
from remora.verification.preconditions import ProposalContext
from remora.verification.registry import PreconditionRegistry

__all__ = ["InMemorySource", "Resolver", "ResolverRefused", "run_request"]


class ResolverRefused(RuntimeError):
    """The lookup was not run. Carries the reason code."""


class Resolver(Protocol):
    resolver_id: str

    def fetch(self, request: VerificationRequest, tenant_id: str, now_s: int) -> ResolverEvidence: ...


def run_request(request: VerificationRequest, context: ProposalContext, *,
                registry: PreconditionRegistry, resolvers: Mapping[str, Resolver],
                held_capabilities: frozenset[str], now_s: int) -> ResolverEvidence:
    """Authorize one lookup on its own, then run it. Raises :class:`ResolverRefused`."""
    spec = registry.resolvers.get(request.resolver_id)
    if spec is None:
        raise ResolverRefused("resolver_not_registered")
    if request.context_hash != context.context_hash:
        raise ResolverRefused("request_for_another_context")
    if spec.capability_id not in held_capabilities:
        raise ResolverRefused("resolve_capability_not_held")
    resolver = resolvers.get(request.resolver_id)
    if resolver is None or resolver.resolver_id != request.resolver_id:
        raise ResolverRefused("resolver_not_deployed")
    return resolver.fetch(request, context.tenant_id, now_s)


@dataclass
class InMemorySource:
    """A system of record for simulators and tests: ``records[tenant][subject]``.

    A missing subject returns an empty payload, which a verifier reads as
    UNKNOWN: absence from an open source does not prove non-existence.
    """

    resolver_id: str
    source_id: str
    records: Mapping[str, Mapping[str, Any]]
    source_version: str = "v1"
    ttl_s: int = 60
    calls: list[str] = field(default_factory=list)

    def fetch(self, request: VerificationRequest, tenant_id: str, now_s: int) -> ResolverEvidence:
        self.calls.append(request.request_id)
        record = self.records.get(tenant_id, {}).get(request.subject_ref)
        payload = json.dumps({"found": record is not None, "record": record},
                             sort_keys=True, separators=(",", ":")).encode()
        return ResolverEvidence(
            request_id=request.request_id, resolver_id=self.resolver_id,
            source_id=self.source_id, subject_ref=request.subject_ref,
            source_version=self.source_version, tenant_id=tenant_id,
            acquired_at=now_s, valid_until=now_s + self.ttl_s, payload=payload,
            payload_hash=hashlib.sha256(payload).hexdigest(), capture_method="in_memory")

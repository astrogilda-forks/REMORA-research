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
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from remora.verification.check import ResolverEvidence, VerificationRequest
from remora.verification.preconditions import ProposalContext
from remora.verification.registry import PreconditionRegistry

__all__ = [
    "BoundedResolverAdapter",
    "InMemorySource",
    "Resolver",
    "ResolverAdapterContract",
    "ResolverRefused",
    "TransportResponse",
    "run_request",
]


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


@dataclass(frozen=True)
class ResolverAdapterContract:
    """Hard runtime contract for one source adapter (SDD v2 WP-02 / AR-010..012)."""

    resolver_id: str
    source_id: str
    allowed_destinations: frozenset[str]
    required_capability: str
    expected_source_version: str = "v1"
    max_response_bytes: int = 65_536
    connect_timeout_ms: int = 250
    read_timeout_ms: int = 500
    total_timeout_ms: int = 1_000
    allow_redirects: bool = False

    def __post_init__(self) -> None:
        if not self.resolver_id or not self.source_id or not self.required_capability:
            raise ValueError("resolver_id, source_id and required_capability are mandatory")
        if not self.allowed_destinations or not all(
            isinstance(d, str) and d.startswith(("https://", "internal://"))
            for d in self.allowed_destinations
        ):
            raise ValueError("allowed_destinations must be non-empty https:// or internal:// URIs")
        if self.allow_redirects is not False:
            raise ValueError("resolver adapters must not allow redirects (AR-011)")
        for name in ("max_response_bytes", "connect_timeout_ms", "read_timeout_ms", "total_timeout_ms"):
            val = getattr(self, name)
            if type(val) is not int or val <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class TransportResponse:
    """Raw transport outcome observed by a bounded resolver adapter."""

    destination: str
    tenant_id: str
    source_version: str
    payload: bytes
    redirected: bool = False
    connect_ms: int = 0
    read_ms: int = 0


@dataclass
class BoundedResolverAdapter:
    """Enforces separate monotonic/wall clocks, destination allowlist, redirect
    refusal, byte limits, tenant filter and source-version pin (SDD v2 AR-010..012)."""

    contract: ResolverAdapterContract
    transport: Callable[[VerificationRequest, str, int], TransportResponse]
    mono_clock_ms: Callable[[], int]
    wall_clock_s: Callable[[], int]
    ttl_s: int = 60
    calls: list[str] = field(default_factory=list)

    @property
    def resolver_id(self) -> str:
        return self.contract.resolver_id

    def fetch(self, request: VerificationRequest, tenant_id: str, now_s: int) -> ResolverEvidence:
        del now_s  # Wall clock comes exclusively from the trusted wall_clock_s port (AR-010)
        start_mono = self.mono_clock_ms()
        if start_mono >= request.deadline_ms:
            raise ResolverRefused("request_deadline_expired")
        subj = request.subject_ref.strip().lower()
        if "://" in subj or subj.startswith(("http:", "https:", "file:", "//")):
            raise ResolverRefused("raw_url_in_subject_refused")
        effective_timeout = min(
            self.contract.total_timeout_ms,
            max(1, request.deadline_ms - start_mono),
        )
        self.calls.append(request.request_id)
        resp = self.transport(request, tenant_id, effective_timeout)
        end_mono = self.mono_clock_ms()
        if resp.redirected:
            raise ResolverRefused("redirect_refused")
        if resp.destination not in self.contract.allowed_destinations:
            raise ResolverRefused("destination_not_allowed")
        if (
            resp.connect_ms > self.contract.connect_timeout_ms
            or resp.read_ms > self.contract.read_timeout_ms
            or (end_mono - start_mono) >= self.contract.total_timeout_ms
            or end_mono >= request.deadline_ms
        ):
            raise ResolverRefused("transport_timeout")
        if not isinstance(resp.payload, bytes) or len(resp.payload) > self.contract.max_response_bytes:
            raise ResolverRefused("response_too_large")
        if resp.tenant_id != tenant_id:
            raise ResolverRefused("tenant_mismatch")
        if resp.source_version != self.contract.expected_source_version:
            raise ResolverRefused("source_version_mismatch")
        acquired = self.wall_clock_s()
        return ResolverEvidence(
            request_id=request.request_id,
            resolver_id=self.contract.resolver_id,
            source_id=self.contract.source_id,
            subject_ref=request.subject_ref,
            source_version=resp.source_version,
            tenant_id=tenant_id,
            acquired_at=acquired,
            valid_until=acquired + self.ttl_s,
            payload=resp.payload,
            payload_hash=hashlib.sha256(resp.payload).hexdigest(),
            capture_method="bounded_adapter",
        )


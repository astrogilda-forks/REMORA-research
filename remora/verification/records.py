# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The WS1 composition record: what was decided, from what, bound by hash (WS1 §6.3-6.4).

Commitments use the evidence-admission encoding (``remora-bounded-sorted-json/v1``,
not RFC 8785) under the ``REMORA/WS1-COMPOSITION/v1`` domain tag, and hold no
floats: the monitor's scores are bound through the hash of its raw response.
A record hash binds its parent's hash, so a chain of rounds for one proposal
cannot be reordered or have a round dropped without the hashes saying so.

A hash does not authenticate a producer. Signing and storage of the
authorization artefacts stay with the existing issuer.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from remora.evidence.admission.canonical import canonical_bytes
from remora.verification.preconditions import tagged_digest

__all__ = ["CapEntry", "CompositionRecord", "verify_record_hash"]


@dataclass(frozen=True)
class CapEntry:
    """One cap that entered the meet, with the WS1 cause behind it."""

    source: str
    action: str
    reason: str
    approvable: bool
    code: str

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "action": self.action, "reason": self.reason,
                "approvable": self.approvable, "code": self.code}


@dataclass(frozen=True)
class CompositionRecord:
    context_hash: str
    requirements_hash: str
    evidence_digest: str
    profile_hash: str
    base_action: str
    base_reasons: tuple[str, ...]
    all_caps: tuple[CapEntry, ...]
    all_precondition_results: tuple[Mapping[str, Any], ...]
    monitor_assessment: Mapping[str, Any] | None
    monitor_status: str
    monitor_veto: bool
    final_action: str
    review_class: str
    reason_codes: tuple[str, ...]
    parent_record_hash: str | None

    def body(self) -> dict[str, Any]:
        return {"schema": "remora-ws1-composition-record/v1",
                "context_hash": self.context_hash, "requirements_hash": self.requirements_hash,
                "evidence_digest": self.evidence_digest, "profile_hash": self.profile_hash,
                "base_action": self.base_action, "base_reasons": list(self.base_reasons),
                "all_caps": [c.to_dict() for c in self.all_caps],
                "all_precondition_results": [dict(r) for r in self.all_precondition_results],
                "monitor_assessment": None if self.monitor_assessment is None
                else dict(self.monitor_assessment),
                "monitor_status": self.monitor_status, "monitor_veto": self.monitor_veto,
                "final_action": self.final_action, "review_class": self.review_class,
                "reason_codes": list(self.reason_codes),
                "parent_record_hash": self.parent_record_hash}

    @property
    def record_hash(self) -> str:
        return tagged_digest("record", self.body())

    def canonical(self) -> bytes:
        return canonical_bytes({**self.body(), "record_hash": self.record_hash})


def verify_record_hash(stored: Mapping[str, Any]) -> bool:
    """True when a stored record's hash matches its body. A tampered field fails."""
    body = {k: v for k, v in stored.items() if k != "record_hash"}
    try:
        return tagged_digest("record", body) == stored.get("record_hash")
    except ValueError:
        return False

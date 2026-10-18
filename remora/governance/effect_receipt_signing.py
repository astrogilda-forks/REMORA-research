# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Signed effect receipts from a separate verifier domain (CAPR-06).

Design: ``docs/design/compositional-authority-preservation-v1.md`` §4.1-§4.2.

The digest receipt (``remora.governance.effect_receipt``) is an attestation:
a verifier says what it compared, and REMORA records who said it. That leaves
two gaps the design closes here and in the server:

- **who observed** was a name in the request body, bound to a principal by a
  configuration table. Separation by name is not separation by trust domain.
  A signed receipt identifies its verifier by key, and the key is registered
  for one control domain and one credential scope;
- **what was observed** never reached REMORA, only two digests, so REMORA
  could not re-run the comparison. A signed receipt carries the observed
  object itself, and the server computes the verdict (CAPR-07).

What this module does: the receipt format, its canonical signed bytes, the
verifier key registry, and signature verification under
``REMORA/EFFECT-RECEIPT/v1``. It does not decide the vantage or the verdict;
the server derives both from the registry record and the signed ToolSpec.

Owner decision 5 (SDD §8): a receipt carries nothing the authority domain may
not read. The field set is closed, so a sealed or opaque payload cannot ride
along.
"""
from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from remora import frozen_json
from remora.crypto import (
    Signature,
    SignatureDomain,
    SigningKey,
    VerificationKey,
    sign,
    verify,
)
from remora.governance.effect_receipt import ReceiptRefused

__all__ = [
    "CREDENTIAL_SCOPES",
    "RECEIPT_DOMAIN",
    "EffectReceipt",
    "VerifierKeyRecord",
    "VerifierKeyRegistry",
    "sign_receipt",
    "verify_signed_receipt",
]

RECEIPT_DOMAIN = SignatureDomain.EFFECT_RECEIPT

#: What the verifier's credential on the system of record may do. Only a
#: read-only verifier can be independent: one that can write could have
#: produced the state it reports.
CREDENTIAL_SCOPES = ("read_only", "read_write")

_REQUIRED = ("proposal_id", "grant_jti", "tool_call_hash", "tenant",
             "observed", "observed_at")
_OPTIONAL = ("source_revision", "pre_state_revision", "claimed_status")
_FIELDS = frozenset(_REQUIRED + _OPTIONAL)


@dataclass(frozen=True)
class EffectReceipt:
    """What one verifier observed about one dispatch.

    ``observed`` is the object the verifier read, or None when it could not
    read one. ``source_revision`` is the system of record's revision of that
    object as read; ``pre_state_revision`` is its revision before the
    dispatch, where the system offers one. ``claimed_status`` is the
    verifier's own reading, recorded beside the verdict REMORA computes and
    never used in place of it.
    """

    proposal_id: str
    grant_jti: str
    tool_call_hash: str
    tenant: str
    observed: Mapping[str, Any] | None
    observed_at: str
    source_revision: str = ""
    pre_state_revision: str = ""
    claimed_status: str = ""

    def __post_init__(self) -> None:
        if self.observed is not None:
            if not isinstance(self.observed, Mapping):
                raise ReceiptRefused(
                    "receipt_observation_malformed",
                    "observed must be a JSON object, or null when the verifier "
                    "could not read the target")
            try:
                frozen = frozen_json.freeze(self.observed)
            except TypeError as exc:
                raise ReceiptRefused("receipt_observation_malformed",
                                     str(exc)) from exc
            object.__setattr__(self, "observed", frozen)
        for name in _REQUIRED + _OPTIONAL:
            if name == "observed":
                continue
            if not isinstance(getattr(self, name), str):
                raise ReceiptRefused("receipt_field_malformed",
                                     f"{name} must be a string")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> EffectReceipt:
        if not isinstance(raw, Mapping):
            raise ReceiptRefused("receipt_malformed", "a receipt is a JSON object")
        unknown = sorted(set(raw) - _FIELDS)
        if unknown:
            raise ReceiptRefused(
                "receipt_field_unknown",
                f"fields {unknown} are not part of a v1 receipt; a receipt "
                "carries nothing the authority domain may not read")
        missing = [name for name in _REQUIRED if name not in raw]
        if missing:
            raise ReceiptRefused("receipt_field_missing",
                                 f"a receipt needs {missing}")
        return cls(**{name: raw[name] for name in _FIELDS if name in raw})

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "proposal_id": self.proposal_id,
            "grant_jti": self.grant_jti,
            "tool_call_hash": self.tool_call_hash,
            "tenant": self.tenant,
            "observed": (None if self.observed is None
                         else frozen_json.thaw(self.observed)),
            "observed_at": self.observed_at,
        }
        for name in _OPTIONAL:
            value = getattr(self, name)
            if value:
                out[name] = value
        return out

    def canonical_bytes(self) -> bytes:
        """The signed payload: sorted compact JSON of the declared fields."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")


@dataclass(frozen=True)
class VerifierKeyRecord:
    """One registered verifier key and what the deployment says about it."""

    key: VerificationKey
    control_domain: str
    credential_scope: str
    tenants: frozenset[str]

    @property
    def kid(self) -> str:
        return self.key.kid

    @property
    def read_only(self) -> bool:
        return self.credential_scope == "read_only"


class VerifierKeyRegistry:
    """Verifier keys by derived id. Registered by key, not by name (§4.1)."""

    def __init__(self, records: Iterable[VerifierKeyRecord] = ()) -> None:
        self._records = {record.kid: record for record in records}

    def __len__(self) -> int:
        return len(self._records)

    def kids(self) -> set[str]:
        return set(self._records)

    def record(self, kid: str) -> VerifierKeyRecord | None:
        return self._records.get(kid)

    def verification_keys(self) -> dict[str, VerificationKey]:
        return {kid: record.key for kid, record in self._records.items()}

    @classmethod
    def from_config(cls, entries: Iterable[Mapping[str, Any]]) -> VerifierKeyRegistry:
        records = []
        for index, entry in enumerate(entries):
            where = f"verifier key entry {index}"
            if not isinstance(entry, Mapping):
                raise ValueError(f"{where}: an entry is a mapping")
            scope = entry.get("credential_scope")
            if scope not in CREDENTIAL_SCOPES:
                raise ValueError(
                    f"{where}: credential_scope {scope!r} is not one of "
                    f"{list(CREDENTIAL_SCOPES)}")
            domain = entry.get("control_domain")
            if not isinstance(domain, str) or not domain.strip():
                raise ValueError(f"{where}: control_domain is required")
            tenants = entry.get("tenants")
            if (not isinstance(tenants, list) or not tenants
                    or not all(isinstance(t, str) and t for t in tenants)):
                raise ValueError(f"{where}: tenants is a non-empty list of names")
            try:
                key = VerificationKey.from_text(str(entry.get("public_key", "")),
                                                {RECEIPT_DOMAIN})
            except Exception as exc:  # SigningUnavailable, ValueError
                raise ValueError(f"{where}: public_key: {exc}") from exc
            records.append(VerifierKeyRecord(
                key=key, control_domain=domain.strip(),
                credential_scope=str(scope), tenants=frozenset(tenants)))
        return cls(records)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> VerifierKeyRegistry:
        """``REMORA_EFFECT_VERIFIER_KEYS``: a JSON list, or a path to one."""
        env = os.environ if environ is None else environ
        raw = str(env.get("REMORA_EFFECT_VERIFIER_KEYS", "")).strip()
        if not raw:
            return cls()
        text = raw if raw.startswith("[") else Path(raw).read_text(encoding="utf-8")
        entries = json.loads(text)
        if not isinstance(entries, list):
            raise ValueError("REMORA_EFFECT_VERIFIER_KEYS must be a JSON list")
        return cls.from_config(entries)


def sign_receipt(receipt: EffectReceipt, key: SigningKey) -> Signature:
    """Sign under ``REMORA/EFFECT-RECEIPT/v1``. Refused for a key bound elsewhere."""
    return sign(RECEIPT_DOMAIN, receipt.canonical_bytes(), key)


def verify_signed_receipt(
    receipt: EffectReceipt,
    signature: Signature,
    registry: VerifierKeyRegistry,
    *,
    tenant: str,
) -> VerifierKeyRecord:
    """The registry record of the key that signed this receipt, or a refusal.

    The verifier is whoever holds the registered key. Nothing in the receipt
    body names it, so a body cannot claim another verifier's standing.
    """
    result = verify(RECEIPT_DOMAIN, receipt.canonical_bytes(), signature,
                    registry.verification_keys())
    if not result.ok:
        reason = result.reason.removeprefix("signature_")
        raise ReceiptRefused(
            f"receipt_signature_{reason}",
            f"the receipt signature does not verify under {RECEIPT_DOMAIN.value} "
            f"({result.reason})")
    record = registry.record(result.kid)
    assert record is not None  # verify() found it by this kid
    if receipt.tenant != tenant:
        raise ReceiptRefused(
            "receipt_tenant_mismatch",
            f"the receipt names tenant {receipt.tenant!r}, not {tenant!r}")
    if tenant not in record.tenants:
        raise ReceiptRefused(
            "verifier_key_not_for_tenant",
            f"verifier key {record.kid} is not registered for tenant {tenant!r}")
    return record

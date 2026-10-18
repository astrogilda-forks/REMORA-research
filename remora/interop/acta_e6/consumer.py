# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""A paying-side consumer for edge E6: Veritas Acta receipts against a bill.

This implements the input contract of ``VeritasActa/e6-fixture`` ``v1.1.0``
(README, sections "The input contract" to "Results"). It was written from
that README alone. The fixture's own ``consumer/`` and ``producer/`` code and
draft-farley-acta-signed-receipts-03 were not read, and
``@veritasacta/verify`` is not called: Ed25519 is ``cryptography`` and JCS is
:func:`remora.interop.jcs.canonicalise`. The ``keys`` and ``signatures``
claims therefore rest on those two, not on the Acta verifier.

The consumer reports seven evidence claims and ``amount`` separately, each
``PASS``, ``FAIL``, ``ABSTAIN`` or ``NOT_EVALUATED`` with its codes, and
``payment_ready`` is always false. Nothing here maps onto REMORA's own
``ACCEPT``/``VERIFY``/``ABSTAIN``/``ESCALATE`` and nothing here is admitted
as REMORA evidence: the result is Acta's vocabulary, carried as data.

Code names
==========

The fixture's cases name these codes, and this module emits them verbatim:
``unexpected_signer``, ``invalid_signature``, ``chain_break``,
``manifest_signature_invalid``, ``verifier_unavailable``,
``period_mismatch``, ``manifest_mismatch``, ``count_mismatch``,
``sequence_mismatch``, ``head_mismatch``, ``root_mismatch``,
``unknown_receipt``, ``unaccounted_receipt``, ``listed_twice_in_bill`` and
``billed_on_earlier_bill``.

The README defines further failure conditions that no case exercises. Their
codes are REMORA's names, not the fixture's: ``root_fingerprint_mismatch``,
``meter_key_missing``, ``key_material_mismatch``, ``certificate_invalid``,
``certificate_subject_mismatch``, ``outside_key_window``, ``missing_link``,
``receipt_period_mismatch``, ``quantity_mismatch``, ``not_billable`` and
``billing_class_mismatch``.

Within a claim, codes are listed once each, in the fixed order of the
``_ORDER`` table below.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from remora.interop.jcs import canonicalise

#: verify(public_key_hex, message, signature_hex) -> bool
SignatureCheck = Callable[[str, bytes, str], bool]

EVIDENCE_CLAIMS = (
    "keys",
    "signatures",
    "scope",
    "coverage_bill_to_receipts",
    "coverage_receipts_to_bill",
    "uniqueness",
    "quantities",
)
ALL_CLAIMS = (*EVIDENCE_CLAIMS, "amount")
BILL_CLAIMS = EVIDENCE_CLAIMS[3:]

_ORDER: dict[str, tuple[str, ...]] = {
    "keys": (
        "root_fingerprint_mismatch",
        "meter_key_missing",
        "key_material_mismatch",
        "certificate_invalid",
        "certificate_subject_mismatch",
        "unexpected_signer",
        "outside_key_window",
        "verifier_unavailable",
    ),
    "signatures": (
        "invalid_signature",
        "missing_link",
        "chain_break",
        "manifest_signature_invalid",
        "verifier_unavailable",
    ),
    "scope": (
        "period_mismatch",
        "manifest_mismatch",
        "count_mismatch",
        "sequence_mismatch",
        "head_mismatch",
        "root_mismatch",
        "receipt_period_mismatch",
    ),
    "coverage_bill_to_receipts": ("unknown_receipt",),
    "coverage_receipts_to_bill": ("unaccounted_receipt",),
    "uniqueness": ("listed_twice_in_bill", "billed_on_earlier_bill"),
    "quantities": ("quantity_mismatch", "not_billable", "billing_class_mismatch"),
}


class E6InputError(ValueError):
    """An input is not well formed enough to evaluate any claim."""


def ed25519_check(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    """Verify a raw Ed25519 signature with ``cryptography``; malformed input is invalid."""

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        key.verify(bytes.fromhex(signature_hex), message)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def record_id(envelope: dict[str, Any]) -> str:
    """``sha256:`` and the hex SHA-256 of the JCS of the whole envelope, signature included."""

    return "sha256:" + hashlib.sha256(canonicalise(envelope)).hexdigest()


def key_fingerprint(public_key_hex: str) -> str:
    return "sha256:" + hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()


def range_root(ids: Sequence[str]) -> str:
    """RFC 6962 Merkle tree hash over the 32-byte receipt IDs, in the order given."""

    def mth(leaves: Sequence[bytes]) -> bytes:
        n = len(leaves)
        if n == 0:
            return hashlib.sha256(b"").digest()
        if n == 1:
            return hashlib.sha256(b"\x00" + leaves[0]).digest()
        k = 1
        while k * 2 < n:
            k *= 2
        return hashlib.sha256(b"\x01" + mth(leaves[:k]) + mth(leaves[k:])).digest()

    leaves = []
    for rid in ids:
        if not rid.startswith("sha256:"):
            raise E6InputError(f"receipt ID {rid!r} is not sha256:<hex>")
        leaves.append(bytes.fromhex(rid[len("sha256:") :]))
    return "sha256:" + mth(leaves).hex()


def _time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise E6InputError(f"timestamp {value!r} is not a string")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass
class _Claim:
    codes: set[str] = field(default_factory=set)
    abstain: bool = False

    def status(self) -> str:
        if self.codes - {"verifier_unavailable"}:
            return "FAIL"
        return "ABSTAIN" if self.abstain else "PASS"


@dataclass(frozen=True)
class E6Inputs:
    """The contract's inputs, already parsed from their bytes."""

    receipts: list[dict[str, Any]]
    manifest: dict[str, Any]
    bill: dict[str, Any]
    keys: dict[str, Any]
    root_fingerprint: str
    earlier_bills: list[dict[str, Any]]

    @classmethod
    def from_bytes(
        cls,
        *,
        receipts: bytes,
        manifest: bytes,
        bill: bytes,
        keys: bytes,
        root_fingerprint: str,
        earlier_bills: Sequence[bytes] = (),
    ) -> E6Inputs:
        try:
            return cls(
                receipts=[
                    json.loads(line)
                    for line in receipts.decode("utf-8").splitlines()
                    if line.strip()
                ],
                manifest=json.loads(manifest),
                bill=json.loads(bill),
                keys=json.loads(keys),
                root_fingerprint=root_fingerprint,
                earlier_bills=[json.loads(b) for b in earlier_bills],
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise E6InputError(f"input is not JSON: {exc}") from exc


def _meter_key(keys: dict[str, Any]) -> dict[str, Any] | None:
    meters = [
        k
        for k in keys.get("keys", [])
        if isinstance(k, dict) and k.get("role") == "meter"
    ]
    return meters[0] if len(meters) == 1 else None


def _b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _check_keys(inp: E6Inputs, verify: SignatureCheck | None, claim: _Claim) -> None:
    root = inp.keys.get("root") or {}
    root_hex = root.get("public_key_hex", "")
    try:
        root_ok = (
            root.get("fingerprint") == inp.root_fingerprint == key_fingerprint(root_hex)
        )
    except ValueError:
        root_ok = False
    if not root_ok:
        claim.codes.add("root_fingerprint_mismatch")

    meter = _meter_key(inp.keys)
    if meter is None:
        claim.codes.add("meter_key_missing")
        return
    try:
        material_ok = key_fingerprint(meter["public_key_hex"]) == meter[
            "fingerprint"
        ] and _b64url(meter["x"]) == bytes.fromhex(meter["public_key_hex"])
    except (KeyError, ValueError, TypeError):
        material_ok = False
    if not material_ok:
        claim.codes.add("key_material_mismatch")

    cert = meter.get("certificate") or {}
    payload = cert.get("payload") or {}
    signature = cert.get("signature") or {}
    if signature.get("kid") != root.get("kid") or payload.get("issuer_id") != root.get(
        "kid"
    ):
        claim.codes.add("certificate_invalid")
    elif verify is None:
        claim.abstain = True
        claim.codes.add("verifier_unavailable")
    elif not verify(root_hex, canonicalise(payload), str(signature.get("sig", ""))):
        claim.codes.add("certificate_invalid")
    subject = payload.get("subject") or {}
    for name in ("kid", "public_key_hex", "fingerprint", "valid_from", "valid_until"):
        if subject.get(name) != meter.get(name):
            claim.codes.add("certificate_subject_mismatch")
            break

    start = _time(meter.get("valid_from"))
    end = None if meter.get("valid_until") is None else _time(meter.get("valid_until"))
    for record in (*inp.receipts, inp.manifest):
        if record.get("signature", {}).get("kid") != meter.get("kid") or record.get(
            "payload", {}
        ).get("issuer_id") != meter.get("kid"):
            claim.codes.add("unexpected_signer")
        issued = _time(record.get("payload", {}).get("issued_at"))
        if issued < start or (end is not None and issued >= end):
            claim.codes.add("outside_key_window")


def _check_signatures(
    inp: E6Inputs, verify: SignatureCheck | None, claim: _Claim
) -> None:
    if verify is None:
        claim.abstain = True
        claim.codes.add("verifier_unavailable")
        return
    meter = _meter_key(inp.keys)
    meter_hex = meter.get("public_key_hex", "") if meter else ""

    def valid(envelope: dict[str, Any]) -> bool:
        signature = envelope.get("signature") or {}
        return signature.get("alg") == "EdDSA" and verify(
            meter_hex,
            canonicalise(envelope.get("payload")),
            str(signature.get("sig", "")),
        )

    previous: dict[str, Any] | None = None
    for receipt in inp.receipts:
        if not valid(receipt):
            claim.codes.add("invalid_signature")
        if previous is not None:
            link = receipt.get("payload", {}).get("previousReceiptHash")
            if link is None:
                claim.codes.add("missing_link")
            elif link != record_id(previous):
                claim.codes.add("chain_break")
        previous = receipt
    if not valid(inp.manifest):
        claim.codes.add("manifest_signature_invalid")


def _check_scope(inp: E6Inputs, claim: _Claim) -> None:
    payload = inp.manifest.get("payload") or {}
    period_id = (payload.get("period") or {}).get("id")
    rng = payload.get("range") or {}
    if inp.bill.get("period") != period_id:
        claim.codes.add("period_mismatch")
    if inp.bill.get("manifest") != record_id(inp.manifest):
        claim.codes.add("manifest_mismatch")

    expected_count = rng.get("outcome_receipts", 0) + rng.get("correction_receipts", 0)
    if len(inp.receipts) != expected_count:
        claim.codes.add("count_mismatch")
    sequences = [r.get("payload", {}).get("sequence") for r in inp.receipts]
    first, last = rng.get("first_sequence"), rng.get("last_sequence")
    if not (isinstance(first, int) and isinstance(last, int)) or sequences != list(
        range(first, last + 1)
    ):
        claim.codes.add("sequence_mismatch")
    ids = [record_id(r) for r in inp.receipts]
    last_id = ids[-1] if ids else None
    if (
        last_id is None
        or rng.get("head") != last_id
        or payload.get("previousReceiptHash") != last_id
    ):
        claim.codes.add("head_mismatch")
    if range_root(ids) != rng.get("root"):
        claim.codes.add("root_mismatch")
    if any(r.get("payload", {}).get("period") != period_id for r in inp.receipts):
        claim.codes.add("receipt_period_mismatch")


def _billed(bill: dict[str, Any]) -> list[str]:
    return [rid for line in bill.get("lines", []) for rid in line.get("receipts", [])]


def _check_bill(inp: E6Inputs, claims: dict[str, _Claim]) -> None:
    by_id = {record_id(r): r for r in inp.receipts}
    billed = _billed(inp.bill)
    excluded = [x.get("receipt") for x in inp.bill.get("exclusions", [])]
    named = billed + excluded

    if any(rid not in by_id for rid in named):
        claims["coverage_bill_to_receipts"].codes.add("unknown_receipt")
    if set(by_id) - set(named):
        claims["coverage_receipts_to_bill"].codes.add("unaccounted_receipt")

    if any(n > 1 for n in Counter(named).values()):
        claims["uniqueness"].codes.add("listed_twice_in_bill")
    earlier = {rid for b in inp.earlier_bills for rid in _billed(b)}
    if earlier.intersection(billed):
        claims["uniqueness"].codes.add("billed_on_earlier_bill")

    for line in inp.bill.get("lines", []):
        receipts = line.get("receipts", [])
        if line.get("quantity") != len(receipts):
            claims["quantities"].codes.add("quantity_mismatch")
        for rid in receipts:
            outcome = by_id.get(rid, {}).get("payload", {}).get("outcome")
            if outcome is None:
                continue  # an unknown receipt is coverage_bill_to_receipts' finding
            if outcome.get("billable") is not True:
                claims["quantities"].codes.add("not_billable")
            if outcome.get("billing_class") != line.get("billing_class"):
                claims["quantities"].codes.add("billing_class_mismatch")


def evaluate(
    inp: E6Inputs, verify: SignatureCheck | None = ed25519_check
) -> dict[str, Any]:
    """Evaluate one bill. ``verify=None`` means no signature verifier is available."""

    claims = {name: _Claim() for name in EVIDENCE_CLAIMS}
    _check_keys(inp, verify, claims["keys"])
    _check_signatures(inp, verify, claims["signatures"])
    _check_scope(inp, claims["scope"])

    statuses: dict[str, str] = {
        name: claims[name].status() for name in EVIDENCE_CLAIMS[:3]
    }
    if all(s == "PASS" for s in statuses.values()):
        _check_bill(inp, claims)
        statuses.update({name: claims[name].status() for name in BILL_CLAIMS})
    else:
        statuses.update(dict.fromkeys(BILL_CLAIMS, "NOT_EVALUATED"))
    statuses["amount"] = "NOT_EVALUATED"

    codes = {
        name: [c for c in _ORDER[name] if c in claims[name].codes]
        for name in EVIDENCE_CLAIMS
        if statuses[name] in ("FAIL", "ABSTAIN") and claims[name].codes
    }
    values = [statuses[name] for name in EVIDENCE_CLAIMS]
    if "FAIL" in values:
        verdict = "FAIL"
    elif all(v == "PASS" for v in values):
        verdict = "PASS"
    else:
        verdict = "ABSTAIN"
    return {
        "verdict": verdict,
        "claims": {name: statuses[name] for name in ALL_CLAIMS},
        "codes": codes,
        "payment_ready": False,
    }


def agreement(result: dict[str, Any], expected: dict[str, Any]) -> list[str]:
    """The fields on which *result* differs from a case's ``expected``; empty means agreement.

    Agreement is the fixture's rule: the verdict, all eight claims, every code
    and ``payment_ready``. ``decisive`` is a label for readers and is not
    compared.
    """

    differences = []
    if result["verdict"] != expected["verdict"]:
        differences.append("verdict")
    for name in ALL_CLAIMS:
        if result["claims"].get(name) != expected["claims"].get(name):
            differences.append(f"claims.{name}")
    if result["codes"] != expected.get("codes", {}):
        differences.append("codes")
    if result["payment_ready"] is not expected.get("payment_ready"):
        differences.append("payment_ready")
    return differences

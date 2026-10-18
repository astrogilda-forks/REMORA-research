# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Signed effect receipts and the verifier key registry (CAPR-06).

SDD ``docs/design/compositional-authority-preservation-v1.md`` §4.1 and §4.2.
A receipt is signed under its own domain, ``REMORA/EFFECT-RECEIPT/v1``, by a
key the deployment registered for one control domain and credential scope.
These tests pin the three properties the rest of the design leans on:

- a receipt signature never verifies as any other artifact, and no other
  artifact's signature verifies as a receipt;
- the verifier is identified by its key, never by a name in the body;
- the receipt carries only the declared fields (owner decision 5: nothing the
  authority domain may not read).
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("cryptography")

from remora.crypto import SignatureDomain, SigningKey, sign, verify  # noqa: E402
from remora.governance.effect_receipt import ReceiptRefused  # noqa: E402
from remora.governance.effect_receipt_signing import (  # noqa: E402
    RECEIPT_DOMAIN,
    EffectReceipt,
    VerifierKeyRegistry,
    sign_receipt,
    verify_signed_receipt,
)

VERIFIER = SigningKey.generate({RECEIPT_DOMAIN})
LEASE_KEY = SigningKey.generate({SignatureDomain.EXECUTION_LEASE})


def _receipt(**over) -> EffectReceipt:
    fields = {
        "proposal_id": "p-1",
        "grant_jti": "jti-1",
        "tool_call_hash": "c" * 64,
        "tenant": "acme",
        "observed": {"artifact_id": "rec-1", "status": "stored"},
        "observed_at": "2026-10-18T12:00:00+00:00",
    }
    fields.update(over)
    return EffectReceipt(**fields)


def _registry(key: SigningKey = VERIFIER, **over) -> VerifierKeyRegistry:
    entry = {
        "public_key": key.verification_key().public_bytes.hex(),
        "control_domain": "acme-observer",
        "credential_scope": "read_only",
        "tenants": ["acme"],
    }
    entry.update(over)
    return VerifierKeyRegistry.from_config([entry])


def test_the_receipt_domain_is_its_own() -> None:
    assert RECEIPT_DOMAIN is SignatureDomain.EFFECT_RECEIPT
    assert RECEIPT_DOMAIN.value == "REMORA/EFFECT-RECEIPT/v1"


def test_a_registered_key_verifies_its_receipt() -> None:
    receipt = _receipt()
    signature = sign_receipt(receipt, VERIFIER)
    record = verify_signed_receipt(receipt, signature, _registry(), tenant="acme")
    assert record.kid == VERIFIER.kid
    assert record.control_domain == "acme-observer"
    assert record.read_only is True


def test_a_changed_field_breaks_the_signature() -> None:
    signature = sign_receipt(_receipt(), VERIFIER)
    tampered = _receipt(observed={"artifact_id": "rec-2", "status": "stored"})
    with pytest.raises(ReceiptRefused) as exc:
        verify_signed_receipt(tampered, signature, _registry(), tenant="acme")
    assert exc.value.reason == "receipt_signature_invalid"


def test_a_lease_key_cannot_sign_a_receipt() -> None:
    with pytest.raises(ValueError):
        sign_receipt(_receipt(), LEASE_KEY)


def test_a_receipt_signed_in_the_lease_domain_is_refused() -> None:
    """Section 4.4: a receipt signed with a lease key is refused (L8)."""
    receipt = _receipt()
    forged = sign(SignatureDomain.EXECUTION_LEASE, receipt.canonical_bytes(),
                  LEASE_KEY)
    registry = _registry(LEASE_KEY)
    with pytest.raises(ReceiptRefused) as exc:
        verify_signed_receipt(receipt, forged, registry, tenant="acme")
    assert exc.value.reason == "receipt_signature_domain_mismatch"


def test_a_receipt_signature_never_verifies_as_a_lease() -> None:
    receipt = _receipt()
    signature = sign_receipt(receipt, VERIFIER)
    result = verify(SignatureDomain.EXECUTION_LEASE, receipt.canonical_bytes(),
                    signature, [VERIFIER.verification_key()])
    assert not result.ok
    assert result.reason == "domain_mismatch"


def test_an_unregistered_key_is_refused() -> None:
    other = SigningKey.generate({RECEIPT_DOMAIN})
    receipt = _receipt()
    with pytest.raises(ReceiptRefused) as exc:
        verify_signed_receipt(receipt, sign_receipt(receipt, other),
                              _registry(), tenant="acme")
    assert exc.value.reason == "receipt_signature_unknown_kid"


def test_a_key_registered_for_another_tenant_is_refused() -> None:
    receipt = _receipt(tenant="globex")
    with pytest.raises(ReceiptRefused) as exc:
        verify_signed_receipt(receipt, sign_receipt(receipt, VERIFIER),
                              _registry(), tenant="globex")
    assert exc.value.reason == "verifier_key_not_for_tenant"


def test_the_receipt_must_name_the_tenant_it_is_submitted_under() -> None:
    receipt = _receipt(tenant="globex")
    registry = _registry(tenants=["acme", "globex"])
    with pytest.raises(ReceiptRefused) as exc:
        verify_signed_receipt(receipt, sign_receipt(receipt, VERIFIER),
                              registry, tenant="acme")
    assert exc.value.reason == "receipt_tenant_mismatch"


def test_unknown_receipt_fields_are_refused() -> None:
    """Owner decision 5: a receipt carries nothing beyond the declared fields."""
    raw = _receipt().to_dict()
    raw["sealed_blob"] = "opaque"
    with pytest.raises(ReceiptRefused) as exc:
        EffectReceipt.from_dict(raw)
    assert exc.value.reason == "receipt_field_unknown"


def test_the_observation_is_a_json_object_or_absent() -> None:
    with pytest.raises(ReceiptRefused) as exc:
        EffectReceipt.from_dict({**_receipt().to_dict(), "observed": "row"})
    assert exc.value.reason == "receipt_observation_malformed"
    absent = EffectReceipt.from_dict({**_receipt().to_dict(), "observed": None})
    assert absent.observed is None


def test_the_signed_bytes_are_canonical() -> None:
    a = _receipt(observed={"b": 1, "a": 2})
    b = _receipt(observed={"a": 2, "b": 1})
    assert a.canonical_bytes() == b.canonical_bytes()
    assert json.loads(a.canonical_bytes())["observed"] == {"a": 2, "b": 1}


@pytest.mark.parametrize("entry, reason", [
    ({"credential_scope": "admin"}, "credential_scope"),
    ({"control_domain": ""}, "control_domain"),
    ({"tenants": []}, "tenants"),
    ({"public_key": "zz"}, "public_key"),
])
def test_a_malformed_registry_entry_is_refused(entry, reason) -> None:
    with pytest.raises(ValueError) as exc:
        _registry(**entry)
    assert reason in str(exc.value)


def test_a_registry_without_entries_is_empty() -> None:
    assert len(VerifierKeyRegistry.from_config([])) == 0


def test_the_registry_reads_json_text_or_a_file(tmp_path) -> None:
    entry = {
        "public_key": VERIFIER.verification_key().public_bytes.hex(),
        "control_domain": "acme-observer",
        "credential_scope": "read_only",
        "tenants": ["acme"],
    }
    from_text = VerifierKeyRegistry.from_env(
        {"REMORA_EFFECT_VERIFIER_KEYS": json.dumps([entry])})
    path = tmp_path / "keys.json"
    path.write_text(json.dumps([entry]), encoding="utf-8")
    from_file = VerifierKeyRegistry.from_env(
        {"REMORA_EFFECT_VERIFIER_KEYS": str(path)})
    assert from_text.kids() == from_file.kids() == {VERIFIER.kid}
    assert len(VerifierKeyRegistry.from_env({})) == 0

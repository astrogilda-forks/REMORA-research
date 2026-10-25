# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The Capability Activation Manifest library (SDD §3; ADR-UE-03 slice 1).

What is pinned: the SDD's own example parses; the contract refuses what §3
forbids (a mode outside the vocabulary, a requested mode outside the allowed
ones, ALLOW as a fail mode, a register fact restated in the manifest, a
duplicate or malformed capability id, unknown or missing fields); the digest
is canonical; the signature verifies only under its own domain and key and
only over an untampered body; the loader refuses an unsigned manifest under a
strict profile and a signed one it cannot check; the CLI signs, verifies and
digests; the schema file agrees with the parser on the example and on the
refusals it can express.
"""
from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from remora.crypto import SignatureDomain, SigningKey
from remora.governance import activation_manifest as cam
from remora.governance.activation_manifest import (
    CapabilityManifest,
    ManifestError,
    load_manifest,
    load_manifest_from_env,
    manifest_digest,
    sign_manifest,
    verify_signed_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_FILE = ROOT / "schemas" / "capability_activation_manifest_v1.yaml"

LIMITS_CONTRACT = "remora.execution.limits.v1"
LIMITS_SDK_SURFACE = "RemoraClient.limits"
LIMITS_PROBE = "limits_ledger_readiness"
NO_CONTRACT = ""

#: SDD §3's example entry, as written, plus a second entry for ordering.
LIMITS = {
    "capability_id": "CAP-031",
    "component_version": "0.12.x+reviewed",
    "implementation_ref": "remora/enforcement/cumulative_limits.py",
    "requested_mode": "ENFORCE",
    "allowed_modes": ["SHADOW", "ENFORCE"],
    "required_premises": ["signed_limit_policy", "shared_atomic_ledger",
                          "idempotency_contract_for_mutating_tools", "reconciliation_authority"],
    "trust_source_ids": ["issuer-limits-v1", "payment-rail-v1"],
    # The values sit in named constants: the secret scanner reads a quoted
    # value beside a key containing "api" as a credential (.gitleaksignore
    # records the same false positive elsewhere).
    "api_contract": LIMITS_CONTRACT,
    "sdk_surface": LIMITS_SDK_SURFACE,
    "health_probe": LIMITS_PROBE,
    "fail_mode": "DENY_OR_HOLD",
    "claim_ceiling": "per_deployment_configured_limit_only",
    "evidence_refs": ["CAP-031", "NEGATIVE_RESULTS.md §97"],
}
GATE = {
    "capability_id": "CAP-001",
    "component_version": "0.12.0",
    "implementation_ref": "remora.policy.decision_engine",
    "requested_mode": "SHADOW",
    "allowed_modes": ["SHADOW"],
    "required_premises": [],
    "trust_source_ids": [],
    "api_contract": NO_CONTRACT,
    "sdk_surface": NO_CONTRACT,
    "health_probe": NO_CONTRACT,
    "fail_mode": "DENY",
    "claim_ceiling": "deterministic_policy_gate",
    "evidence_refs": ["CAP-001"],
}
MANIFEST = {"schema": "capability-activation/v1", "deployment": "ot-pilot-a",
            "capabilities": [LIMITS, GATE]}


def _key():
    return SigningKey.generate({SignatureDomain.CAPABILITY_MANIFEST})


@pytest.fixture(autouse=True)
def _no_profile(monkeypatch):
    monkeypatch.delenv("REMORA_RUNTIME_PROFILE", raising=False)
    monkeypatch.delenv(cam.ENV_FILE, raising=False)
    monkeypatch.delenv(cam.ENV_TRUSTED_KEYS, raising=False)


# ── parsing ────────────────────────────────────────────────────────────────


def test_the_sdd_example_parses_and_entries_are_sorted_by_id():
    manifest = CapabilityManifest.from_dict(MANIFEST)
    assert [e.capability_id for e in manifest.entries] == ["CAP-001", "CAP-031"]
    limits = manifest.get("CAP-031")
    assert limits is not None
    assert limits.requested_mode == "ENFORCE" and limits.allowed_modes == ("SHADOW", "ENFORCE")
    assert limits.required_premises[1] == "shared_atomic_ledger"
    assert limits.fail_mode == "DENY_OR_HOLD"
    assert manifest.get("CAP-002") is None
    assert manifest.to_dict()["capabilities"][0]["capability_id"] == "CAP-001"


def test_the_digest_is_canonical_over_order_and_whitespace():
    reordered = {"capabilities": [GATE, LIMITS], "deployment": "ot-pilot-a",
                 "schema": "capability-activation/v1"}
    a, b = CapabilityManifest.from_dict(MANIFEST), CapabilityManifest.from_dict(reordered)
    assert a.digest == b.digest == manifest_digest(a.to_dict())
    assert len(a.digest) == 64
    changed = copy.deepcopy(MANIFEST)
    changed["capabilities"][0]["requested_mode"] = "SHADOW"
    assert CapabilityManifest.from_dict(changed).digest != a.digest


@given(st.permutations(list(LIMITS.items())))
@settings(max_examples=25, deadline=None)
def test_the_digest_does_not_depend_on_key_order(items):
    shuffled = {"schema": "capability-activation/v1", "deployment": "ot-pilot-a",
                "capabilities": [dict(items), GATE]}
    assert CapabilityManifest.from_dict(shuffled).digest == CapabilityManifest.from_dict(MANIFEST).digest


def _entry(**over):
    return {"schema": "capability-activation/v1", "deployment": "d",
            "capabilities": [{**LIMITS, **over}]}


@pytest.mark.parametrize("over, reason", [
    ({"requested_mode": "ALLOW"}, "manifest_mode_unknown"),
    ({"requested_mode": "DISABLED"}, "manifest_mode_not_allowed"),
    ({"allowed_modes": ["SHADOW", "ENFORCE", "SHADOW"]}, "manifest_field_invalid"),
    ({"allowed_modes": []}, "manifest_field_invalid"),
    ({"allowed_modes": ["ENFORCE", "AUTO"]}, "manifest_mode_unknown"),
    ({"fail_mode": "ALLOW"}, "manifest_fail_mode_invalid"),
    ({"fail_mode": ""}, "manifest_field_invalid"),
    ({"capability_id": "CAP-31"}, "manifest_capability_id_invalid"),
    ({"capability_id": "cap-031"}, "manifest_capability_id_invalid"),
    ({"hook": "PRE_DISPATCH"}, "manifest_restates_register_fact"),
    ({"status": "IMPLEMENTED"}, "manifest_restates_register_fact"),
    ({"mode": "ENFORCE"}, "manifest_restates_register_fact"),
    ({"operator_note": "x"}, "manifest_field_unknown"),
    ({"evidence_refs": []}, "manifest_field_invalid"),
    ({"evidence_refs": ["CAP-031", ""]}, "manifest_field_invalid"),
    ({"required_premises": ["Signed_Policy"]}, "manifest_field_invalid"),
    ({"required_premises": ["a", "a"]}, "manifest_field_invalid"),
    ({"trust_source_ids": "issuer-limits-v1"}, "manifest_field_invalid"),
    ({"implementation_ref": "remora/enforcement/cumulative limits.py"}, "manifest_field_invalid"),
    ({"component_version": " 0.12 "}, "manifest_field_invalid"),
    ({"claim_ceiling": ""}, "manifest_field_invalid"),
])
def test_what_the_contract_refuses_in_an_entry(over, reason):
    with pytest.raises(ManifestError) as exc:
        CapabilityManifest.from_dict(_entry(**over))
    assert exc.value.reason == reason, str(exc.value)


def test_a_missing_field_names_what_is_missing():
    entry = {k: v for k, v in LIMITS.items() if k != "health_probe"}
    with pytest.raises(ManifestError) as exc:
        CapabilityManifest.from_dict({"schema": "capability-activation/v1", "deployment": "d",
                                      "capabilities": [entry]})
    assert exc.value.reason == "manifest_field_missing" and "health_probe" in str(exc.value)


@pytest.mark.parametrize("document, reason", [
    ("not a mapping", "manifest_invalid"),
    ({"schema": "capability-activation/v2", "deployment": "d", "capabilities": [LIMITS]},
     "manifest_schema_unknown"),
    ({"schema": "capability-activation/v1", "deployment": "Prod A", "capabilities": [LIMITS]},
     "manifest_field_invalid"),
    ({"schema": "capability-activation/v1", "deployment": "d", "capabilities": []},
     "manifest_field_invalid"),
    ({"schema": "capability-activation/v1", "deployment": "d", "capabilities": [LIMITS, LIMITS]},
     "manifest_capability_duplicate"),
    ({"schema": "capability-activation/v1", "deployment": "d", "capabilities": [LIMITS],
      "signed_at": "2026-10-25"}, "manifest_field_unknown"),
    ({"schema": "capability-activation/v1", "deployment": "d", "capabilities": ["CAP-031"]},
     "manifest_entry_invalid"),
])
def test_what_the_contract_refuses_in_a_manifest(document, reason):
    with pytest.raises(ManifestError) as exc:
        CapabilityManifest.from_dict(document)
    assert exc.value.reason == reason


def test_coverage_against_the_registered_ids():
    manifest = CapabilityManifest.from_dict(MANIFEST)
    unknown, missing = manifest.coverage(["CAP-001", "CAP-002", "CAP-META"])
    assert unknown == ("CAP-031",)
    assert missing == ("CAP-002", "CAP-META")
    assert manifest.coverage(["CAP-001", "CAP-031"]) == ((), ())


def test_the_live_register_ids_are_what_the_contract_accepts():
    """Every id in the register parses as a capability id, so a complete
    manifest for this repository can be written; the META entry included."""
    import yaml

    register = yaml.safe_load((ROOT / "docs" / "assurance" / "capability_register_v1.yaml")
                              .read_text(encoding="utf-8"))
    ids = [c["id"] for c in register["capabilities"]]
    assert len(ids) == 32 and "CAP-META" in ids
    manifest = CapabilityManifest.from_dict({
        "schema": "capability-activation/v1", "deployment": "all",
        "capabilities": [{**GATE, "capability_id": cid} for cid in ids]})
    assert manifest.coverage(ids) == ((), ())


# ── signing ────────────────────────────────────────────────────────────────


def test_a_signed_manifest_verifies_and_the_body_is_canonical():
    key = _key()
    envelope = sign_manifest(MANIFEST, key, "2026-10-25T00:00:00Z")
    assert envelope["schema"] == "capability-activation-signed/v1"
    assert envelope["signature"]["domain"] == "REMORA/CAPABILITY-MANIFEST/v1"
    assert [c["capability_id"] for c in envelope["manifest"]["capabilities"]] == ["CAP-001", "CAP-031"]
    body, kid = verify_signed_manifest(envelope, [key.verification_key()])
    assert kid == key.kid and CapabilityManifest.from_dict(body).digest == manifest_digest(body)


def test_signing_refuses_a_manifest_remora_would_refuse_to_load():
    with pytest.raises(ManifestError) as exc:
        sign_manifest(_entry(fail_mode="ALLOW"), _key(), "2026-10-25T00:00:00Z")
    assert exc.value.reason == "manifest_fail_mode_invalid"


@pytest.mark.parametrize("tamper", [
    lambda e: e["manifest"]["capabilities"][1].__setitem__("requested_mode", "SHADOW"),
    lambda e: e["manifest"]["capabilities"].append(dict(GATE, capability_id="CAP-002")),
    lambda e: e["manifest"].__setitem__("deployment", "other"),
    lambda e: e["signature"].__setitem__("signature", "A" * 86 + "=="),
])
def test_a_tampered_envelope_is_refused(tamper):
    key = _key()
    envelope = sign_manifest(MANIFEST, key, "2026-10-25T00:00:00Z")
    tamper(envelope)
    with pytest.raises(ManifestError) as exc:
        verify_signed_manifest(envelope, [key.verification_key()])
    assert exc.value.reason == "manifest_signature_refused"


def test_another_key_or_another_domain_does_not_verify():
    key, other = _key(), _key()
    envelope = sign_manifest(MANIFEST, key, "2026-10-25T00:00:00Z")
    with pytest.raises(ManifestError) as exc:
        verify_signed_manifest(envelope, [other.verification_key()])
    assert exc.value.detail == "unknown_kid"
    limits_key = SigningKey.generate({SignatureDomain.LIMIT_POLICY})
    with pytest.raises(ValueError):
        sign_manifest(MANIFEST, limits_key, "2026-10-25T00:00:00Z")
    forged = dict(envelope, signature=dict(envelope["signature"], domain="REMORA/LIMIT-POLICY/v1"))
    with pytest.raises(ManifestError) as exc:
        verify_signed_manifest(forged, [key.verification_key()])
    assert exc.value.detail == "domain_mismatch"


@pytest.mark.parametrize("document, reason", [
    (MANIFEST, "manifest_envelope_invalid"),
    ({"schema": "capability-activation-signed/v1", "manifest": MANIFEST}, "manifest_envelope_invalid"),
    ({"schema": "capability-activation-signed/v1", "manifest": "x", "signature": {}},
     "manifest_envelope_invalid"),
])
def test_what_is_not_an_envelope(document, reason):
    with pytest.raises(ManifestError) as exc:
        verify_signed_manifest(document, [_key().verification_key()])
    assert exc.value.reason == reason


# ── the loader ─────────────────────────────────────────────────────────────


def test_with_trusted_keys_only_a_signed_manifest_by_one_of_them_loads():
    key = _key()
    envelope = sign_manifest(MANIFEST, key, "2026-10-25T00:00:00Z")
    loaded = load_manifest(envelope, trusted_keys=[key.verification_key()], strict=True)
    assert loaded.signed is True and loaded.signer_kid == key.kid
    assert loaded.manifest.digest == CapabilityManifest.from_dict(MANIFEST).digest
    with pytest.raises(ManifestError) as exc:
        load_manifest(MANIFEST, trusted_keys=[key.verification_key()], strict=False)
    assert exc.value.reason == "manifest_unsigned"
    with pytest.raises(ManifestError) as exc:
        load_manifest(envelope, trusted_keys=[_key().verification_key()], strict=False)
    assert exc.value.reason == "manifest_signature_refused"


def test_without_trusted_keys_a_signed_manifest_cannot_be_checked_and_is_refused():
    envelope = sign_manifest(MANIFEST, _key(), "2026-10-25T00:00:00Z")
    with pytest.raises(ManifestError) as exc:
        load_manifest(envelope, trusted_keys=[], strict=False)
    assert exc.value.reason == "manifest_signature_unverifiable"


def test_an_unsigned_manifest_loads_only_outside_the_strict_profiles():
    loaded = load_manifest(MANIFEST, trusted_keys=[], strict=False)
    assert loaded.signed is False and loaded.signer_kid == ""
    with pytest.raises(ManifestError) as exc:
        load_manifest(MANIFEST, trusted_keys=[], strict=True)
    assert exc.value.reason == "manifest_unsigned"


def test_the_environment_loader(tmp_path, monkeypatch):
    from remora.governance.activation_manifest import load_manifest_file

    assert load_manifest_from_env() is None
    assert load_manifest_file("", "") is None
    key = _key()
    path = tmp_path / "cam.json"
    path.write_text(json.dumps(sign_manifest(MANIFEST, key, "2026-10-25T00:00:00Z")),
                    encoding="utf-8")
    monkeypatch.setenv(cam.ENV_FILE, str(path))
    monkeypatch.setenv(cam.ENV_TRUSTED_KEYS, f"{_key().verification_key().public_bytes.hex()}, "
                                            f"{key.verification_key().public_bytes.hex()}")
    loaded = load_manifest_from_env(strict=True)
    assert loaded is not None and loaded.signed and loaded.manifest.deployment == "ot-pilot-a"
    # a YAML plain manifest, no keys, not strict
    import yaml

    plain = tmp_path / "cam.yaml"
    plain.write_text(yaml.safe_dump(MANIFEST), encoding="utf-8")
    loaded = load_manifest_file(str(plain), "", strict=False)
    assert loaded is not None and loaded.signed is False
    with pytest.raises(ManifestError) as exc:
        load_manifest_file(str(tmp_path / "missing.json"), "", strict=False)
    assert exc.value.reason == "manifest_unreadable"
    broken = tmp_path / "broken.yaml"
    broken.write_text("schema: [capability-activation/v1", encoding="utf-8")
    with pytest.raises(ManifestError) as exc:
        load_manifest_file(str(broken), "", strict=False)
    assert exc.value.reason == "manifest_unreadable"
    with pytest.raises(ManifestError) as exc:
        load_manifest_file(str(path), "not-a-key", strict=False)
    assert exc.value.reason == "manifest_trusted_keys_invalid"
    # strict defaults to the runtime profile's custody rule
    monkeypatch.setenv(cam.ENV_FILE, str(plain))
    monkeypatch.delenv(cam.ENV_TRUSTED_KEYS, raising=False)
    monkeypatch.setattr("remora.enforcement.custody.custody_is_enforced", lambda: True)
    with pytest.raises(ManifestError) as exc:
        load_manifest_from_env()
    assert exc.value.reason == "manifest_unsigned"
    monkeypatch.setattr("remora.enforcement.custody.custody_is_enforced", lambda: False)
    assert load_manifest_from_env() is not None


# ── the CLI ────────────────────────────────────────────────────────────────


def _cli(*args, env=None):
    return subprocess.run([sys.executable, str(ROOT / "scripts" / "sign_capability_manifest.py"),
                           *args], capture_output=True, text=True, env=env, timeout=120,
                          check=False)


def test_the_cli_signs_verifies_and_digests(tmp_path):
    import os

    import yaml

    plain = tmp_path / "manifest.yaml"
    plain.write_text(yaml.safe_dump(MANIFEST), encoding="utf-8")
    new = json.loads(_cli("--new-key").stdout)
    env = {**os.environ, "REMORA_CAM_SIGNING_SEED": new["seed"], "PYTHONPATH": str(ROOT)}
    out = tmp_path / "cam.json"
    signed = _cli(str(plain), "--out", str(out), env=env)
    assert signed.returncode == 0, signed.stderr
    digest = _cli("--digest", str(plain)).stdout.strip()
    assert digest == CapabilityManifest.from_dict(MANIFEST).digest
    verified = _cli("--verify", str(out), "--trusted-keys", new["public_key"])
    assert verified.returncode == 0, verified.stderr
    report = json.loads(verified.stdout)
    assert report["digest"] == digest and report["capabilities"] == 2
    wrong = _cli("--verify", str(out), "--trusted-keys", json.loads(_cli("--new-key").stdout)["public_key"])
    assert wrong.returncode == 1 and "unknown_kid" in wrong.stderr
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump(_entry(fail_mode="ALLOW")), encoding="utf-8")
    refused = _cli(str(bad), "--out", str(tmp_path / "never.json"), env=env)
    assert refused.returncode == 1 and "manifest_fail_mode_invalid" in refused.stderr
    assert not (tmp_path / "never.json").exists()


# ── the schema file ────────────────────────────────────────────────────────


def test_the_schema_file_agrees_with_the_parser():
    import yaml

    jsonschema = pytest.importorskip("jsonschema")
    schema = yaml.safe_load(SCHEMA_FILE.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(MANIFEST)
    for over in ({"requested_mode": "ALLOW"}, {"fail_mode": "ALLOW"}, {"hook": "PRE_DISPATCH"},
                 {"capability_id": "CAP-31"}, {"evidence_refs": []},
                 {"allowed_modes": ["SHADOW", "SHADOW"]}):
        assert not validator.is_valid(_entry(**over)), over
        with pytest.raises(ManifestError):
            CapabilityManifest.from_dict(_entry(**over))
    # the one rule the schema cannot express is the parser's alone
    assert validator.is_valid(_entry(requested_mode="DISABLED"))
    with pytest.raises(ManifestError) as exc:
        CapabilityManifest.from_dict(_entry(requested_mode="DISABLED"))
    assert exc.value.reason == "manifest_mode_not_allowed"

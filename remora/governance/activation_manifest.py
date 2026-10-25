# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The Capability Activation Manifest (CAM): schema, digest, signature, loader.

SDD unified capability execution v1.1 §3 asks every registered capability to
appear in a signed, deployment-owned manifest that carries per-deployment
fields only: the mode a deployment requests for a capability, the modes it
allows, the premises that must hold, the trust sources, the contract names,
the fail mode and the claim ceiling. Maturity, evidence and the hook stay in
``docs/assurance/capability_register_v1.yaml`` (ADR-UE-03, accepted
2026-10-25); a manifest that restates one of them is refused.

This module is the first slice after the ADR: a library that parses a
manifest, refuses what the contract forbids, computes the canonical digest
later slices pin into decisions and leases (``cam_digest``), signs and
verifies it under ``REMORA/CAPABILITY-MANIFEST/v1`` with the deployment's
Ed25519 key, and loads it from ``REMORA_CAM_FILE`` with the trusted keys in
``REMORA_CAM_TRUSTED_KEYS``. No runtime reads it yet: the effective mode,
the startup validation, the lease field and the catalogue route are the next
slices, and until they land every mode is NOT_ESTABLISHED.

The signing follows the limit policy (``remora.enforcement.cumulative_limits``):
the signature covers the ``manifest`` block only, ``signed_at`` is unsigned
metadata, and a host that holds only the public keys can verify a manifest
and author none. Under a strict runtime profile an unsigned manifest is
refused, as an unsigned limit policy is.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "ENV_FILE",
    "ENV_TRUSTED_KEYS",
    "FAIL_MODES",
    "MODES",
    "SCHEMA",
    "SIGNED_SCHEMA",
    "CapabilityActivation",
    "CapabilityManifest",
    "LoadedManifest",
    "ManifestError",
    "canonical_manifest_bytes",
    "load_manifest",
    "load_manifest_file",
    "load_manifest_from_env",
    "manifest_digest",
    "sign_manifest",
    "trusted_keys_from_text",
    "verify_signed_manifest",
]

SCHEMA = "capability-activation/v1"
SIGNED_SCHEMA = "capability-activation-signed/v1"
ENV_FILE = "REMORA_CAM_FILE"
ENV_TRUSTED_KEYS = "REMORA_CAM_TRUSTED_KEYS"

#: The modes of SDD §3. ``ENFORCE`` is reachable only through the activation
#: state machine; this module records what a deployment requests and allows,
#: it does not decide what is effective.
MODES = ("DISABLED", "OFFLINE", "SHADOW", "VERIFY", "ENFORCE", "EVIDENCE_ONLY")
#: What a capability does when a dependency it needs is degraded. Never
#: ``ALLOW``: SDD §3 ("never ALLOW on degraded dependency").
FAIL_MODES = ("DENY", "HOLD", "DENY_OR_HOLD", "DISABLE")
#: Facts the register owns (ADR-UE-03). A manifest that carries one of these
#: keys is refused: one owner per fact.
REGISTER_FACTS = frozenset({"hook", "status", "maturity", "verified_at_sha", "verified_by",
                            "evidence", "caveat", "name", "effective_mode", "mode"})
_ENTRY_KEYS = (
    "capability_id", "component_version", "implementation_ref", "requested_mode",
    "allowed_modes", "required_premises", "trust_source_ids", "api_contract",
    "sdk_surface", "health_probe", "fail_mode", "claim_ceiling", "evidence_refs",
)
#: Fields that may be the empty string: the SDD marks their values as
#: proposed names that no capability has yet.
_OPTIONAL_TEXT = frozenset({"api_contract", "sdk_surface", "health_probe"})
_MANIFEST_KEYS = ("schema", "deployment", "capabilities")

_CAPABILITY_ID = re.compile(r"^CAP-(\d{3}|META)$")
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:-]*$")
_DIGEST_DOMAIN = b"REMORA/CAPABILITY-MANIFEST-DIGEST/v1\x00"


class ManifestError(ValueError):
    """The manifest is malformed, restates a register fact, or cannot be trusted.

    ``reason`` is a stable machine-readable code; the message adds the field.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


def _text(entry: Mapping[str, Any], key: str, *, where: str, optional: bool = False) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or (not optional and not value.strip()):
        raise ManifestError("manifest_field_invalid", f"{where}.{key} must be a non-empty string")
    if value != value.strip() or any(ch in value for ch in "\r\n\t"):
        raise ManifestError("manifest_field_invalid", f"{where}.{key} has stray whitespace")
    return value


def _identifiers(entry: Mapping[str, Any], key: str, *, where: str,
                 allow_empty: bool) -> tuple[str, ...]:
    value = entry.get(key)
    if not isinstance(value, list) or (not value and not allow_empty):
        raise ManifestError("manifest_field_invalid",
                            f"{where}.{key} must be a {'' if allow_empty else 'non-empty '}list")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not _IDENTIFIER.match(item):
            raise ManifestError("manifest_field_invalid",
                                f"{where}.{key} holds {item!r}, not a lower-case identifier")
        if item in out:
            raise ManifestError("manifest_field_invalid", f"{where}.{key} repeats {item!r}")
        out.append(item)
    return tuple(out)


@dataclass(frozen=True)
class CapabilityActivation:
    """One capability's per-deployment activation request (SDD §3)."""

    capability_id: str
    component_version: str
    implementation_ref: str
    requested_mode: str
    allowed_modes: tuple[str, ...]
    required_premises: tuple[str, ...]
    trust_source_ids: tuple[str, ...]
    api_contract: str
    sdk_surface: str
    health_probe: str
    fail_mode: str
    claim_ceiling: str
    evidence_refs: tuple[str, ...]

    @classmethod
    def from_dict(cls, raw: Any) -> CapabilityActivation:
        if not isinstance(raw, Mapping):
            raise ManifestError("manifest_entry_invalid", "a capability entry is a mapping")
        cid = raw.get("capability_id")
        where = f"capabilities[{cid!r}]"
        if not isinstance(cid, str) or not _CAPABILITY_ID.match(cid):
            raise ManifestError("manifest_capability_id_invalid",
                                f"{where}: capability_id is CAP-NNN or CAP-META")
        restated = sorted(REGISTER_FACTS & set(raw))
        if restated:
            raise ManifestError("manifest_restates_register_fact",
                                f"{where} carries {restated}; the register owns them (ADR-UE-03)")
        unknown = sorted(set(raw) - set(_ENTRY_KEYS))
        if unknown:
            raise ManifestError("manifest_field_unknown", f"{where} has unknown keys {unknown}")
        missing = [k for k in _ENTRY_KEYS if k not in raw]
        if missing:
            raise ManifestError("manifest_field_missing", f"{where} lacks {missing}")
        requested = _text(raw, "requested_mode", where=where)
        if requested not in MODES:
            raise ManifestError("manifest_mode_unknown",
                                f"{where}.requested_mode {requested!r} is not one of {list(MODES)}")
        allowed_raw = raw.get("allowed_modes")
        if not isinstance(allowed_raw, list) or not allowed_raw:
            raise ManifestError("manifest_field_invalid", f"{where}.allowed_modes must be a non-empty list")
        allowed: list[str] = []
        for mode in allowed_raw:
            if not isinstance(mode, str) or mode not in MODES:
                raise ManifestError("manifest_mode_unknown",
                                    f"{where}.allowed_modes holds {mode!r}, not one of {list(MODES)}")
            if mode in allowed:
                raise ManifestError("manifest_field_invalid", f"{where}.allowed_modes repeats {mode!r}")
            allowed.append(mode)
        if requested not in allowed:
            raise ManifestError("manifest_mode_not_allowed",
                                f"{where} requests {requested} outside allowed_modes {allowed}")
        fail_mode = _text(raw, "fail_mode", where=where)
        if fail_mode not in FAIL_MODES:
            # ALLOW is named here on purpose: the one value the SDD forbids.
            raise ManifestError("manifest_fail_mode_invalid",
                                f"{where}.fail_mode {fail_mode!r} is not one of {list(FAIL_MODES)}; "
                                "ALLOW is never a fail mode")
        implementation_ref = _text(raw, "implementation_ref", where=where)
        if " " in implementation_ref:
            raise ManifestError("manifest_field_invalid",
                                f"{where}.implementation_ref is a path or a dotted name")
        return cls(
            capability_id=cid,
            component_version=_text(raw, "component_version", where=where),
            implementation_ref=implementation_ref,
            requested_mode=requested,
            allowed_modes=tuple(allowed),
            required_premises=_identifiers(raw, "required_premises", where=where, allow_empty=True),
            trust_source_ids=_identifiers(raw, "trust_source_ids", where=where, allow_empty=True),
            api_contract=_text(raw, "api_contract", where=where, optional=True),
            sdk_surface=_text(raw, "sdk_surface", where=where, optional=True),
            health_probe=_text(raw, "health_probe", where=where, optional=True),
            fail_mode=fail_mode,
            claim_ceiling=_text(raw, "claim_ceiling", where=where),
            evidence_refs=_strings(raw, "evidence_refs", where=where),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability_id": self.capability_id,
            "component_version": self.component_version,
            "implementation_ref": self.implementation_ref,
            "requested_mode": self.requested_mode,
            "allowed_modes": list(self.allowed_modes),
            "required_premises": list(self.required_premises),
            "trust_source_ids": list(self.trust_source_ids),
            "api_contract": self.api_contract,
            "sdk_surface": self.sdk_surface,
            "health_probe": self.health_probe,
            "fail_mode": self.fail_mode,
            "claim_ceiling": self.claim_ceiling,
            "evidence_refs": list(self.evidence_refs),
        }


def _strings(entry: Mapping[str, Any], key: str, *, where: str) -> tuple[str, ...]:
    value = entry.get(key)
    if not isinstance(value, list) or not value or not all(
            isinstance(v, str) and v.strip() for v in value):
        raise ManifestError("manifest_field_invalid",
                            f"{where}.{key} must be a non-empty list of non-empty strings")
    return tuple(value)


def canonical_manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    """The bytes the signature and the digest cover: sorted, compact JSON."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    """``cam_digest``: the domain-separated SHA-256 of the canonical manifest."""
    return hashlib.sha256(_DIGEST_DOMAIN + canonical_manifest_bytes(manifest)).hexdigest()


@dataclass(frozen=True)
class CapabilityManifest:
    """A parsed, internally consistent manifest. Entries are sorted by id."""

    deployment: str
    entries: tuple[CapabilityActivation, ...]
    digest: str

    @classmethod
    def from_dict(cls, raw: Any) -> CapabilityManifest:
        if not isinstance(raw, Mapping):
            raise ManifestError("manifest_invalid", "a manifest is a mapping")
        if raw.get("schema") != SCHEMA:
            raise ManifestError("manifest_schema_unknown",
                                f"schema is {raw.get('schema')!r}, not {SCHEMA!r}")
        unknown = sorted(set(raw) - set(_MANIFEST_KEYS))
        if unknown:
            raise ManifestError("manifest_field_unknown", f"manifest has unknown keys {unknown}")
        deployment = raw.get("deployment")
        if not isinstance(deployment, str) or not _IDENTIFIER.match(deployment):
            raise ManifestError("manifest_field_invalid",
                                "deployment is a lower-case identifier naming the deployment")
        capabilities = raw.get("capabilities")
        if not isinstance(capabilities, list) or not capabilities:
            raise ManifestError("manifest_field_invalid", "capabilities must be a non-empty list")
        entries = [CapabilityActivation.from_dict(item) for item in capabilities]
        seen: set[str] = set()
        for entry in entries:
            if entry.capability_id in seen:
                raise ManifestError("manifest_capability_duplicate",
                                    f"{entry.capability_id} appears twice")
            seen.add(entry.capability_id)
        entries.sort(key=lambda e: e.capability_id)
        body = {"schema": SCHEMA, "deployment": deployment,
                "capabilities": [e.to_dict() for e in entries]}
        return cls(deployment=deployment, entries=tuple(entries), digest=manifest_digest(body))

    def to_dict(self) -> dict[str, Any]:
        return {"schema": SCHEMA, "deployment": self.deployment,
                "capabilities": [e.to_dict() for e in self.entries]}

    def get(self, capability_id: str) -> CapabilityActivation | None:
        for entry in self.entries:
            if entry.capability_id == capability_id:
                return entry
        return None

    def coverage(self, known: Iterable[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """``(unknown, missing)`` against the registered capability ids.

        ``unknown`` names entries for capabilities the register does not
        have; ``missing`` names registered capabilities the manifest leaves
        out. SDD §3: a capability absent from the manifest is DISABLED, never
        defaulted to a mode; the startup validation of the next slice reads
        this.
        """
        registered = set(known)
        present = {e.capability_id for e in self.entries}
        return (tuple(sorted(present - registered)), tuple(sorted(registered - present)))


def sign_manifest(manifest: Mapping[str, Any], key: Any, signed_at: str) -> dict[str, Any]:
    """Wrap a manifest in a signed envelope. Offline signer helper, not runtime.

    ``key`` is a ``remora.crypto.SigningKey`` bound to the CAPABILITY_MANIFEST
    domain. The manifest is parsed first, so an envelope never carries a
    manifest REMORA would refuse to load. The signature covers the manifest
    block only; ``signed_at`` is unsigned metadata.
    """
    from remora.crypto import SignatureDomain, sign

    body = CapabilityManifest.from_dict(manifest).to_dict()
    signature = sign(SignatureDomain.CAPABILITY_MANIFEST, canonical_manifest_bytes(body), key)
    return {"schema": SIGNED_SCHEMA, "manifest": body, "signed_at": signed_at,
            "signature": signature.to_dict()}


def verify_signed_manifest(document: Any, keys: Iterable[Any]) -> tuple[dict[str, Any], str]:
    """The manifest body and the signer's key id, or ``ManifestError``."""
    from remora.crypto import Signature, SignatureDomain, verify

    if not isinstance(document, Mapping) or document.get("schema") != SIGNED_SCHEMA:
        raise ManifestError("manifest_envelope_invalid",
                            f"not a signed {SIGNED_SCHEMA!r} envelope")
    body, raw_signature = document.get("manifest"), document.get("signature")
    if not isinstance(body, Mapping) or not isinstance(raw_signature, Mapping):
        raise ManifestError("manifest_envelope_invalid", "a manifest and a signature are needed")
    result = verify(SignatureDomain.CAPABILITY_MANIFEST, canonical_manifest_bytes(body),
                    Signature.from_dict(raw_signature), list(keys))
    if not result.ok:
        raise ManifestError("manifest_signature_refused", result.reason)
    return dict(body), result.kid


@dataclass(frozen=True)
class LoadedManifest:
    """A manifest a deployment may act on, and how it was trusted."""

    manifest: CapabilityManifest
    signed: bool
    signer_kid: str


def load_manifest(document: Any, *, trusted_keys: Sequence[Any], strict: bool) -> LoadedManifest:
    """Parse ``document`` under the trust the deployment configured.

    With trusted keys the document must be a signed envelope by one of them.
    Without keys a signed envelope cannot be checked and is refused; a plain
    manifest is accepted only outside the strict profiles (``strict`` False),
    as an unsigned limit policy is. Every refusal is a ``ManifestError``.
    """
    signed = isinstance(document, Mapping) and document.get("schema") == SIGNED_SCHEMA
    if trusted_keys:
        if not signed:
            raise ManifestError("manifest_unsigned",
                                f"{ENV_TRUSTED_KEYS} is set, so the manifest must be a signed envelope")
        body, kid = verify_signed_manifest(document, trusted_keys)
        return LoadedManifest(CapabilityManifest.from_dict(body), True, kid)
    if signed:
        raise ManifestError("manifest_signature_unverifiable",
                            f"the manifest is signed and {ENV_TRUSTED_KEYS} is unset")
    if strict:
        raise ManifestError("manifest_unsigned",
                            "a strict runtime profile accepts only a signed manifest")
    return LoadedManifest(CapabilityManifest.from_dict(document), False, "")


def trusted_keys_from_text(raw: str) -> list[Any]:
    """``REMORA_CAM_TRUSTED_KEYS``: comma-separated Ed25519 public keys (hex or base64)."""
    from remora.crypto import SignatureDomain, VerificationKey

    return [VerificationKey.from_text(part.strip(), {SignatureDomain.CAPABILITY_MANIFEST})
            for part in raw.split(",") if part.strip()]


def load_manifest_from_env(*, strict: bool | None = None) -> LoadedManifest | None:
    """The deployment's manifest from ``REMORA_CAM_FILE``, or None when unset.

    The public keys come from ``REMORA_CAM_TRUSTED_KEYS``. ``strict`` defaults
    to whether the active runtime profile enforces custody
    (``remora.enforcement.custody.custody_is_enforced``). A file that cannot be
    read or parsed is a ``ManifestError``; nothing falls back to a default.
    """
    return load_manifest_file(os.environ.get("REMORA_CAM_FILE", ""),
                              os.environ.get("REMORA_CAM_TRUSTED_KEYS", ""), strict=strict)


def load_manifest_file(path: str, raw_keys: str, *, strict: bool | None = None,
                       ) -> LoadedManifest | None:
    """``load_manifest`` over a file and the comma-separated public keys."""
    path = path.strip()
    if not path:
        return None
    if strict is None:
        from remora.enforcement.custody import custody_is_enforced

        strict = custody_is_enforced()
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError("manifest_unreadable", f"{path}: {exc}") from exc
    try:
        import yaml

        document = yaml.safe_load(text)
    except Exception as exc:
        raise ManifestError("manifest_unreadable", f"{path}: {exc}") from exc
    try:
        keys = trusted_keys_from_text(raw_keys)
    except Exception as exc:
        raise ManifestError("manifest_trusted_keys_invalid", str(exc)) from exc
    return load_manifest(document, trusted_keys=keys, strict=strict)

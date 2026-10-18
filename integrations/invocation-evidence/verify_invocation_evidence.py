#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Verify one REMORA invocation-evidence export offline, with public keys only.

This file imports nothing from REMORA. It needs Python 3.10+ and the
``cryptography`` package for Ed25519. Every signature and hash is checked over
bytes the export carries; nothing is re-serialised, so the result does not
depend on how this file or REMORA encodes JSON.

    python verify_invocation_evidence.py --bundle export.json \\
        --evidence-key <hex> --grant-key <hex> --lease-key <hex> --tenant acme \\
        [--jsonrpc-id '7' --body-sha256 <hex>] [--call call.json] \\
        [--runtime-identity-hash <hex>] [--policy-bundle-hash <hex>]

Keys are 32-byte Ed25519 public keys, as hex or base64, pinned out of band.
``--jsonrpc-id`` and ``--body-sha256`` come from the verifier's own capture of
the request: the id's JSON text as it appeared on the wire, and the SHA-256 of
the HTTP body bytes. ``--call`` is ``{"name", "arguments", "target"}`` from the
same capture, to recompute REMORA's call hash.

Each claim is ESTABLISHED, CONTRADICTED or NOT_ESTABLISHED with reason codes.
Exit 0 when nothing is CONTRADICTED, 1 when something is, 2 on a usage or
input error. NOT_ESTABLISHED is never a pass for the claim it names.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sys
from typing import Any

RESULT_FORMAT = "remora-invocation-evidence-result-v1"
ENVELOPE_FORMAT = "remora-invocation-evidence-envelope-v1"
BODY_FORMAT = "remora-invocation-evidence-v1"
EVIDENCE_DOMAIN = "REMORA/EVIDENCE/v1"
GRANT_DOMAIN = "REMORA/POLICY-GRANT/v3"
LEASE_DOMAIN = "REMORA/EXECUTION-LEASE/v2"
REQUEST_REF_FORMAT = "remora-request-ref-v1"
EVENTS = ("assessed", "execution_authorized", "execution_result")

ESTABLISHED = "ESTABLISHED"
CONTRADICTED = "CONTRADICTED"
NOT_ESTABLISHED = "NOT_ESTABLISHED"
CLAIMS = (
    "export_authentic",
    "chain_consistent",
    "authority_bound",
    "call_corresponds",
    "request_corresponds",
    "dispatch_recorded",
)


class InputError(ValueError):
    pass


def _public_key(text: str) -> bytes:
    raw = text.strip()
    try:
        key = bytes.fromhex(raw) if len(raw) == 64 else base64.b64decode(raw, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise InputError("a key is neither 64 hex characters nor base64") from exc
    if len(key) != 32:
        raise InputError("an Ed25519 public key is 32 bytes")
    return key


def kid_of(public_key: bytes) -> str:
    return "ed25519-" + hashlib.sha256(public_key).hexdigest()


def _ed25519_ok(public_key: bytes, message: bytes, signature: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def _sig_bytes(value: str) -> bytes:
    """Base64 (domain-signed formats) or hex (the frozen v1 lease)."""
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return bytes.fromhex(value)


def _domain_ok(public_key: bytes, domain: str | None, payload: bytes, value: str) -> bool:
    message = payload if domain is None else domain.encode("ascii") + b"\x00" + payload
    try:
        signature = _sig_bytes(value)
    except ValueError:
        return False
    return _ed25519_ok(public_key, message, signature)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _Claim:
    def __init__(self) -> None:
        self.contradicted: list[str] = []
        self.missing: list[str] = []

    def contradict(self, code: str) -> None:
        if code not in self.contradicted:
            self.contradicted.append(code)

    def lack(self, code: str) -> None:
        if code not in self.missing:
            self.missing.append(code)

    def result(self) -> dict[str, Any]:
        if self.contradicted:
            return {"result": CONTRADICTED, "codes": self.contradicted + self.missing}
        if self.missing:
            return {"result": NOT_ESTABLISHED, "codes": self.missing}
        return {"result": ESTABLISHED, "codes": []}


def _entry_hash(entry: dict[str, Any], tenant: str) -> str:
    preimage = "\x1f".join((
        entry["previous_hash"], entry["payload_canonical"], tenant,
        str(entry["sequence_no"]), entry["timestamp"],
    ))
    return _sha256_hex(preimage.encode("utf-8"))


def _canonical_call_hash(call: dict[str, Any], tenant: str) -> str:
    """REMORA's canonical_tool_call_hash: sorted keys, no whitespace, ASCII escapes."""
    preimage = json.dumps(
        {"name": call["name"], "arguments": call["arguments"], "tenant": tenant,
         "target": call.get("target") or ""},
        sort_keys=True, separators=(",", ":"), default=str)
    return _sha256_hex(preimage.encode("utf-8"))


def _request_ref_digest(ref: dict[str, Any]) -> str:
    preimage = json.dumps(
        {"format": REQUEST_REF_FORMAT, "transport": ref["transport"],
         "jsonrpc_id": ref["jsonrpc_id"], "body_sha256": ref["body_sha256"]},
        sort_keys=True, separators=(",", ":"))
    return _sha256_hex(preimage.encode("ascii"))


def verify(
    bundle: dict[str, Any],
    *,
    evidence_key: bytes,
    grant_key: bytes,
    lease_key: bytes,
    tenant: str,
    capture_ref: dict[str, str] | None = None,
    call: dict[str, Any] | None = None,
    runtime_identity_hash: str | None = None,
    policy_bundle_hash: str | None = None,
) -> dict[str, Any]:
    claims = {name: _Claim() for name in CLAIMS}
    out: dict[str, Any] = {"format": RESULT_FORMAT}

    def finish() -> dict[str, Any]:
        out["claims"] = {name: claims[name].result() for name in CLAIMS}
        return out

    def not_reached(code: str, names: tuple[str, ...]) -> dict[str, Any]:
        for name in names:
            claims[name].lack(code)
        return finish()

    # 1. The export: one signature over the exact body bytes.
    export = claims["export_authentic"]
    signature = bundle.get("signature") or {}
    if bundle.get("format") != ENVELOPE_FORMAT:
        export.lack("envelope_format_unknown")
    elif signature.get("domain") != EVIDENCE_DOMAIN or signature.get("alg") != "Ed25519":
        export.lack("evidence_domain_unknown")
    elif signature.get("kid") != kid_of(evidence_key):
        export.lack("evidence_key_not_pinned")
    try:
        body_bytes = base64.b64decode(bundle.get("payload_b64", ""), validate=True)
    except (ValueError, binascii.Error):
        export.lack("payload_not_base64")
        body_bytes = b""
    if not export.missing and not _domain_ok(
            evidence_key, EVIDENCE_DOMAIN, body_bytes, str(signature.get("value", ""))):
        export.contradict("evidence_signature_invalid")
    if export.result()["result"] != ESTABLISHED:
        return not_reached("export_not_authentic", CLAIMS[1:])
    body = json.loads(body_bytes)
    if body.get("format") != BODY_FORMAT:
        export.lack("body_format_unknown")
        return not_reached("export_not_authentic", CLAIMS[1:])
    proposal_id = body.get("proposal_id")
    out["proposal_id"] = proposal_id
    if body.get("tenant") != tenant:
        export.contradict("tenant_mismatch")
        return not_reached("export_not_authentic", CLAIMS[1:])

    # 2. The three chain entries, each over the string its hash covers.
    chain = claims["chain_consistent"]
    entries = body.get("chain") or []
    if [e.get("event") for e in entries] != list(EVENTS):
        chain.contradict("events_not_assessed_authorized_result")
        return not_reached("chain_not_consistent", CLAIMS[2:])
    payloads = []
    for entry in entries:
        if _entry_hash(entry, tenant) != entry["entry_hash"]:
            chain.contradict("entry_hash_mismatch")
        payload = json.loads(entry["payload_canonical"])
        if payload.get("event") != entry["event"] or payload.get("proposal_id") != proposal_id:
            chain.contradict("entry_not_this_proposal")
        payloads.append(payload)
    assessed, authorized, result = payloads
    if not entries[0]["sequence_no"] < entries[1]["sequence_no"] < entries[2]["sequence_no"]:
        chain.contradict("sequence_out_of_order")
    if assessed.get("decision") != "accept":
        chain.contradict("not_a_direct_accept")
    if authorized.get("grant_jti") != assessed.get("grant_jti"):
        chain.contradict("grant_jti_mismatch")
    if result.get("intent_sequence_no") != entries[1]["sequence_no"]:
        chain.contradict("result_not_for_this_authorization")
    if len({assessed.get("tool_call_hash"), authorized.get("tool_call_hash"),
            result.get("tool_call_hash")}) != 1:
        chain.contradict("tool_call_hash_mismatch")
    if chain.result()["result"] != ESTABLISHED:
        return not_reached("chain_not_consistent", CLAIMS[2:])
    tool_call_hash = assessed["tool_call_hash"]
    out["tool_call_hash"] = tool_call_hash

    # 3. Authority: the grant (PDP key) and the lease (lease issuer key).
    authority = claims["authority_bound"]
    grant = body.get("grant") or {}
    token = grant.get("token") or {}
    grant_verified = False
    if token != authorized.get("grant"):
        authority.contradict("grant_not_the_recorded_one")
    elif grant.get("domain") != GRANT_DOMAIN or token.get("format") != "v3":
        authority.lack("grant_not_publicly_verifiable")
    elif token.get("kid") != kid_of(grant_key):
        authority.lack("grant_key_not_pinned")
    else:
        grant_bytes = base64.b64decode(grant.get("signed_payload_b64", ""))
        if not _domain_ok(grant_key, GRANT_DOMAIN, grant_bytes, token.get("signature", "")):
            authority.contradict("grant_signature_invalid")
        else:
            signed = json.loads(grant_bytes)
            if any(signed.get(k) != token.get(k) for k in signed):
                authority.contradict("grant_fields_not_signed_ones")
            grant_verified = not authority.contradicted
    context = body.get("authorization_context") or {}
    if grant_verified:
        if token.get("action") != "accept" or token.get("request_id") != proposal_id:
            authority.contradict("grant_not_for_this_proposal")
        if token.get("jti") != assessed.get("grant_jti"):
            authority.contradict("grant_jti_mismatch")
        context_hash = _sha256_hex(
            json.dumps(context, sort_keys=True, separators=(",", ":")).encode())
        if not context or context_hash != token.get("context_hash"):
            authority.contradict("context_not_signed_one")
        if context.get("tenant") != tenant or context.get("principal") != assessed.get("actor"):
            authority.contradict("context_tenant_or_principal_mismatch")
        if policy_bundle_hash is not None and context.get("policy_bundle_hash") != policy_bundle_hash:
            authority.contradict("policy_bundle_hash_mismatch")

    lease_section = body.get("lease")
    if lease_section is None:
        authority.lack("lease_not_recorded")
    else:
        lease = lease_section.get("lease") or {}
        domain = lease_section.get("domain")
        if lease != result.get("lease"):
            authority.contradict("lease_not_the_recorded_one")
        elif lease.get("sig_alg") not in ("ed25519-domain-v2", "ed25519"):
            authority.lack("lease_not_publicly_verifiable")
        elif lease.get("sig_alg") == "ed25519-domain-v2" and (
                domain != LEASE_DOMAIN or lease.get("kid") != kid_of(lease_key)):
            authority.lack("lease_key_not_pinned")
        else:
            lease_bytes = base64.b64decode(lease_section.get("signed_payload_b64", ""))
            if not _domain_ok(lease_key, domain, lease_bytes, lease.get("signature", "")):
                authority.contradict("lease_signature_invalid")
            else:
                signed = json.loads(lease_bytes)
                if any(signed.get(k) != lease.get(k) for k in signed):
                    authority.contradict("lease_fields_not_signed_ones")
                if (signed.get("grant_jti") != token.get("jti")
                        or signed.get("proposal_id") != proposal_id):
                    authority.contradict("lease_not_for_this_grant")
                if (signed.get("tenant_id") != tenant
                        or signed.get("actor_identity") != assessed.get("actor")
                        or signed.get("decision") != "accept"):
                    authority.contradict("lease_not_for_this_principal")
                if signed.get("tool_args_hash") != tool_call_hash:
                    authority.contradict("lease_not_for_this_call")
                if (runtime_identity_hash is not None
                        and signed.get("runtime_identity_hash") != runtime_identity_hash):
                    authority.contradict("runtime_identity_mismatch")
                if (policy_bundle_hash is not None
                        and signed.get("policy_bundle_hash") != policy_bundle_hash):
                    authority.contradict("policy_bundle_hash_mismatch")

    # 4. The call, recomputed from the verifier's own capture.
    call_claim = claims["call_corresponds"]
    if call is None:
        call_claim.lack("no_captured_call")
    elif _canonical_call_hash(call, tenant) != tool_call_hash:
        call_claim.contradict("call_hash_mismatch")

    # 5. The request: signed into the grant through the context hash.
    request = claims["request_corresponds"]
    ref = body.get("request_ref")
    if ref is None:
        request.lack("request_ref_absent")
    else:
        digest = _request_ref_digest(ref)
        recorded = {p.get("request_ref_hash") for p in payloads}
        if context.get("request_ref_hash") != digest or recorded != {digest}:
            request.contradict("request_ref_not_bound")
        if not grant_verified:
            request.lack("grant_not_verified")
        if capture_ref is None:
            request.lack("no_captured_request")
        elif (capture_ref["jsonrpc_id"] != ref.get("jsonrpc_id")
              or capture_ref["body_sha256"] != ref.get("body_sha256")):
            request.contradict("request_ref_mismatch")
        out["request_ref"] = ref

    # 6. What REMORA recorded about the dispatch. Not an observed effect.
    dispatch = claims["dispatch_recorded"]
    if result.get("state_unknown"):
        dispatch.lack("state_unknown")
    elif result.get("tool_executed") is not True:
        dispatch.contradict("not_executed")
    if result.get("result_sha256"):
        out["result_sha256"] = result["result_sha256"]
    return finish()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--evidence-key", required=True)
    parser.add_argument("--grant-key", required=True)
    parser.add_argument("--lease-key", required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--jsonrpc-id")
    parser.add_argument("--body-sha256")
    parser.add_argument("--call")
    parser.add_argument("--runtime-identity-hash")
    parser.add_argument("--policy-bundle-hash")
    args = parser.parse_args(argv)
    if (args.jsonrpc_id is None) != (args.body_sha256 is None):
        print("--jsonrpc-id and --body-sha256 go together", file=sys.stderr)
        return 2
    try:
        with open(args.bundle, encoding="utf-8") as handle:
            bundle = json.load(handle)
        call = None
        if args.call:
            with open(args.call, encoding="utf-8") as handle:
                call = json.load(handle)
        result = verify(
            bundle,
            evidence_key=_public_key(args.evidence_key),
            grant_key=_public_key(args.grant_key),
            lease_key=_public_key(args.lease_key),
            tenant=args.tenant,
            capture_ref=(None if args.jsonrpc_id is None else
                         {"jsonrpc_id": args.jsonrpc_id, "body_sha256": args.body_sha256}),
            call=call,
            runtime_identity_hash=args.runtime_identity_hash,
            policy_bundle_hash=args.policy_bundle_hash,
        )
    except (OSError, InputError, json.JSONDecodeError, KeyError, TypeError) as exc:
        print(f"input error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    contradicted = any(c["result"] == CONTRADICTED for c in result["claims"].values())
    return 1 if contradicted else 0


if __name__ == "__main__":
    raise SystemExit(main())

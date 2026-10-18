#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Generate the invocation-evidence fixture cases through the real server path.

Runs the execution API in-process on a temporary SQLite store, with three
fresh demo Ed25519 keys (grant, lease, evidence) made for this run. Two MCP
requests with identical tool calls and different JSON-RPC ids are assessed,
redeemed and exported. The cases pair those exports with captures, and the
tampered ones are derived from them; ``expected.json`` in each case is what
the standalone verifier returns.

The private halves exist only in this process and are discarded, so nobody
can sign anything more under these keys. Running this again makes new keys,
new ids and new bytes; the committed cases are checked by
``run_cases.py``, never by regeneration.

    python integrations/invocation-evidence/fixtures/generate.py
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT))

TENANT = "fixture-tenant"
TOKEN = "fixture-operator"
CALL = {"name": "read_telemetry", "arguments": {"asset": "P-1"}, "target": "staging"}
BODIES = {
    "7": b'{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_telemetry","arguments":{"asset":"P-1"}}}',
    "8": b'{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"read_telemetry","arguments":{"asset":"P-1"}}}',
}


def _seed_and_public() -> tuple[str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption()).hex()
    public = key.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw).hex()
    return seed, public


def _world(db: str, seeds: dict[str, str]) -> Any:
    for name in tuple(os.environ):
        if name.startswith("REMORA_"):
            del os.environ[name]
    os.environ.update({
        "REMORA_ENV": "development",
        "REMORA_RUNTIME_PROFILE": "research",
        "REMORA_SIGNATURE_FORMAT": "v2",
        "REMORA_PDP_SIGNING_KEY_ED25519_PRIVATE": seeds["grant"],
        "REMORA_LEASE_SIGNING_KEY_ED25519_PRIVATE": seeds["lease"],
        "REMORA_EVIDENCE_SIGNING_KEY_ED25519_PRIVATE": seeds["evidence"],
        "REMORA_CHAIN_DB": db,
    })
    from fastapi.testclient import TestClient

    from remora.enforcement.gate import EnforcementGate
    from remora.enforcement.lease import GovernedToolDispatcher
    from remora.enforcement.nonce_store import DurableNonceStore
    from remora.enforcement.outbox import SQLiteExecutionOutbox
    from remora.governance.tenant_chain import SQLiteTenantChain
    from remora.policy.decision_engine import RemoraDecisionEngine
    from servers import api
    from servers import execution_api as execution

    api._TOKEN_TABLE = {TOKEN: (TENANT, "operator")}
    execution._QUEUES = {}
    execution._ITEM_TENANT = {}
    execution._CHAIN = SQLiteTenantChain(db)
    execution._GATE = EnforcementGate(strict=True, audience=execution.PEP_AUDIENCE, db_path=db)
    execution._OUTBOX = SQLiteExecutionOutbox(db)
    execution._ENGINE = RemoraDecisionEngine(execution_profile=True, low_consequence_accept=True)
    dispatcher = GovernedToolDispatcher(
        expected_policy_bundle_hash=execution._current_policy_bundle_hash(),
        nonce_store=DurableNonceStore(db_path=db))
    dispatcher.register("read_telemetry", lambda args: {"ok": True, "asset": args["asset"]})
    execution._DISPATCHER = dispatcher
    return TestClient(api.app)


def _invoke(client: Any, jsonrpc_id: str) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {TOKEN}"}
    proposal = {
        "tool_name": CALL["name"], "arguments": CALL["arguments"],
        "target_environment": CALL["target"],
        "request_ref": {"transport": "mcp-streamable-http", "jsonrpc_id": jsonrpc_id,
                        "body_sha256": hashlib.sha256(BODIES[jsonrpc_id]).hexdigest()},
    }
    assessed = client.post("/v1/execution/assess", json=proposal, headers=headers).json()
    if assessed.get("decision") != "accept":
        raise SystemExit(f"assess did not ACCEPT: {assessed}")
    run = client.post("/v1/execution/execute-accepted", headers=headers, json={
        "execution_token": assessed["execution_token"], "tool_call": proposal})
    if run.status_code != 200 or not run.json()["tool_execution"]["executed"]:
        raise SystemExit(f"execute-accepted failed: {run.text}")
    export = client.get(
        f"/v1/execution/proposals/{assessed['proposal_id']}/invocation-evidence",
        headers=headers)
    if export.status_code != 200:
        raise SystemExit(f"export failed: {export.text}")
    return export.json()


def _resign(body: dict[str, Any], seed: str) -> dict[str, Any]:
    from remora.crypto import SignatureDomain, SigningKey, sign

    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
    sig = sign(SignatureDomain.EVIDENCE, payload,
               SigningKey.from_text(seed, {SignatureDomain.EVIDENCE}))
    return {"format": "remora-invocation-evidence-envelope-v1",
            "payload_b64": base64.b64encode(payload).decode("ascii"),
            "signature": {"alg": sig.algorithm, "domain": sig.domain, "kid": sig.kid,
                          "value": sig.value}}


def _body(bundle: dict[str, Any]) -> dict[str, Any]:
    return json.loads(base64.b64decode(bundle["payload_b64"]))


def _flip_b64(value: str) -> str:
    raw = bytearray(base64.b64decode(value))
    raw[0] ^= 1
    return base64.b64encode(bytes(raw)).decode("ascii")


def main() -> int:
    seeds, publics = {}, {}
    for role in ("grant", "lease", "evidence"):
        seeds[role], publics[role] = _seed_and_public()
    with tempfile.TemporaryDirectory() as tmp:
        client = _world(str(Path(tmp) / "fixture.db"), seeds)
        first = _invoke(client, "7")
        second = _invoke(client, "8")

    forged_grant = copy.deepcopy(_body(first))
    forged_grant["grant"]["token"]["signature"] = _flip_b64(
        forged_grant["grant"]["token"]["signature"])
    swapped_lease = copy.deepcopy(_body(first))
    swapped_lease["lease"] = _body(second)["lease"]
    tampered = copy.deepcopy(first)
    tampered["signature"]["value"] = _flip_b64(tampered["signature"]["value"])

    capture_7 = {"jsonrpc_id": "7", "body_file": "request-7.json", "call": CALL}
    capture_8 = {"jsonrpc_id": "8", "body_file": "request-8.json", "call": CALL}
    cases = {
        "01-matching-pair": (first, capture_7,
                             "The export of request 7 against a capture of request 7."),
        "02-same-call-other-request": (first, capture_8,
                                       "The export of request 7 against a capture of "
                                       "request 8: same tool and arguments, another request."),
        "03-other-export-same-call": (second, capture_7,
                                      "The export of request 8, a valid export of an "
                                      "identical call, against a capture of request 7."),
        "04-no-capture": (first, None,
                          "The export alone: authority and chain can be checked, the "
                          "request cannot."),
        "05-export-signature-altered": (tampered, capture_7,
                                        "One bit of the evidence signature flipped."),
        "06-grant-signature-forged": (_resign(forged_grant, seeds["evidence"]), capture_7,
                                      "A grant signature flipped and the export re-signed "
                                      "with the evidence key: the exporter cannot stand in "
                                      "for the PDP."),
        "07-lease-from-other-invocation": (_resign(swapped_lease, seeds["evidence"]),
                                           capture_7,
                                           "The lease of request 8 placed in the export of "
                                           "request 7 and the export re-signed."),
    }
    seeds.clear()

    spec = importlib.util.spec_from_file_location(
        "verify_invocation_evidence", HERE.parent / "verify_invocation_evidence.py")
    assert spec is not None and spec.loader is not None
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    out = HERE / "cases"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    for jsonrpc_id, body in BODIES.items():
        (HERE / f"request-{jsonrpc_id}.json").write_bytes(body)
    (HERE / "keys.json").write_text(json.dumps({
        "demo": True,
        "notice": "DEMO KEYS made for these fixtures. The private halves existed only in "
                  "the generating process and were discarded.",
        "tenant": TENANT,
        "grant_public_key_hex": publics["grant"],
        "lease_public_key_hex": publics["lease"],
        "evidence_public_key_hex": publics["evidence"],
    }, indent=2) + "\n", encoding="utf-8")
    for name, (bundle, capture, why) in cases.items():
        case_dir = out / name
        case_dir.mkdir()
        (case_dir / "bundle.json").write_text(json.dumps(bundle, indent=2) + "\n",
                                              encoding="utf-8")
        capture_ref = None
        if capture is not None:
            body = (HERE / capture["body_file"]).read_bytes()
            capture_ref = {"jsonrpc_id": capture["jsonrpc_id"],
                           "body_sha256": hashlib.sha256(body).hexdigest()}
        result = verifier.verify(
            bundle,
            evidence_key=bytes.fromhex(publics["evidence"]),
            grant_key=bytes.fromhex(publics["grant"]),
            lease_key=bytes.fromhex(publics["lease"]),
            tenant=TENANT,
            capture_ref=capture_ref,
            call=capture["call"] if capture else None,
        )
        (case_dir / "case.json").write_text(json.dumps({
            "case": name,
            "why": why,
            "bundle": "bundle.json",
            "capture": None if capture is None else {
                "jsonrpc_id": capture["jsonrpc_id"],
                "body": f"../../{capture['body_file']}",
                "call": capture["call"],
            },
            "expected": result["claims"],
        }, indent=2) + "\n", encoding="utf-8")
        print(f"{name}: " + ", ".join(
            f"{k}={v['result']}" for k, v in result["claims"].items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

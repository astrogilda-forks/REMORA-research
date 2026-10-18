# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""One invocation, bound to its request, exported, and verified without REMORA.

The path under test is the server path: /assess with a request reference
mints a v3 grant whose authorization context carries the reference's digest;
/execute-accepted redeems it only under the same reference and dispatches
under a v2 lease; /invocation-evidence exports the three chain entries, the
spent grant and lease and the context, signed under REMORA/EVIDENCE/v1. The
verifier in integrations/invocation-evidence imports no REMORA code and is
given public keys only.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("cryptography")

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "integrations" / "invocation-evidence" / "verify_invocation_evidence.py"

SEEDS = {
    "grant": "11" * 32,
    "lease": "22" * 32,
    "evidence": "33" * 32,
}
TENANT = "ie-tenant"
BODY = b'{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_telemetry","arguments":{"asset":"P-1"}}}'
OTHER_BODY = b'{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"read_telemetry","arguments":{"asset":"P-1"}}}'


def _ref(body: bytes, jsonrpc_id: str) -> dict[str, str]:
    return {"transport": "mcp-streamable-http", "jsonrpc_id": jsonrpc_id,
            "body_sha256": hashlib.sha256(body).hexdigest()}


def _proposal(ref: dict[str, str] | None) -> dict:
    call = {"tool_name": "read_telemetry", "arguments": {"asset": "P-1"},
            "target_environment": "staging"}
    if ref is not None:
        call["request_ref"] = ref
    return call


def _public(seed_hex: str) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex)).public_key()
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


@pytest.fixture(scope="module")
def verifier():
    spec = importlib.util.spec_from_file_location("verify_invocation_evidence", VERIFIER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def world(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from remora.enforcement.gate import EnforcementGate
    from remora.enforcement.lease import GovernedToolDispatcher
    from remora.enforcement.nonce_store import DurableNonceStore
    from remora.enforcement.outbox import SQLiteExecutionOutbox
    from remora.governance.tenant_chain import SQLiteTenantChain
    from remora.policy.decision_engine import RemoraDecisionEngine
    from servers import api
    from servers import execution_api as execution

    for name in tuple(os.environ):
        if name.startswith("REMORA_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("REMORA_ENV", "development")
    monkeypatch.setenv("REMORA_RUNTIME_PROFILE", "research")
    monkeypatch.setenv("REMORA_SIGNATURE_FORMAT", "v2")
    monkeypatch.setenv("REMORA_PDP_SIGNING_KEY_ED25519_PRIVATE", SEEDS["grant"])
    monkeypatch.setenv("REMORA_LEASE_SIGNING_KEY_ED25519_PRIVATE", SEEDS["lease"])
    monkeypatch.setenv("REMORA_EVIDENCE_SIGNING_KEY_ED25519_PRIVATE", SEEDS["evidence"])
    db = str(tmp_path / "ie.db")
    monkeypatch.setenv("REMORA_CHAIN_DB", db)
    monkeypatch.setattr(api, "_TOKEN_TABLE", {"ie-operator": (TENANT, "operator")})
    api._rate_limiter._buckets.clear()
    monkeypatch.setattr(execution, "_QUEUES", {})
    monkeypatch.setattr(execution, "_ITEM_TENANT", {})
    monkeypatch.setattr(execution, "_CHAIN", SQLiteTenantChain(db))
    monkeypatch.setattr(execution, "_GATE", EnforcementGate(
        strict=True, audience=execution.PEP_AUDIENCE, db_path=db))
    monkeypatch.setattr(execution, "_OUTBOX", SQLiteExecutionOutbox(db))
    monkeypatch.setattr(execution, "_ENGINE", RemoraDecisionEngine(
        execution_profile=True, low_consequence_accept=True))
    calls: list[dict] = []
    dispatcher = GovernedToolDispatcher(
        expected_policy_bundle_hash=execution._current_policy_bundle_hash(),
        nonce_store=DurableNonceStore(db_path=db))
    dispatcher.register("read_telemetry", lambda args: calls.append(args) or {"ok": True})
    monkeypatch.setattr(execution, "_DISPATCHER", dispatcher)
    return TestClient(api.app), calls


HEADERS = {"Authorization": "Bearer ie-operator"}


def _run(client, ref, *, redeem_ref="same"):
    assessed = client.post("/v1/execution/assess", json=_proposal(ref), headers=HEADERS)
    assert assessed.status_code == 200, assessed.text
    body = assessed.json()
    assert body["decision"] == "accept", body
    presented = ref if redeem_ref == "same" else redeem_ref
    run = client.post("/v1/execution/execute-accepted", headers=HEADERS, json={
        "execution_token": body["execution_token"], "tool_call": _proposal(presented)})
    return body["proposal_id"], run


def _export(client, proposal_id):
    return client.get(f"/v1/execution/proposals/{proposal_id}/invocation-evidence",
                      headers=HEADERS)


def _check(verifier, bundle, **kwargs):
    return verifier.verify(
        bundle,
        evidence_key=bytes.fromhex(_public(SEEDS["evidence"])),
        grant_key=bytes.fromhex(_public(SEEDS["grant"])),
        lease_key=bytes.fromhex(_public(SEEDS["lease"])),
        tenant=TENANT,
        **kwargs,
    )


def _results(outcome):
    return {name: claim["result"] for name, claim in outcome["claims"].items()}


CALL = {"name": "read_telemetry", "arguments": {"asset": "P-1"}, "target": "staging"}


def test_matching_pair_establishes_every_claim(world, verifier):
    client, calls = world
    proposal_id, run = _run(client, _ref(BODY, "7"))
    assert run.status_code == 200 and run.json()["tool_execution"]["executed"], run.text
    assert "lease" not in run.json()["tool_execution"]
    export = _export(client, proposal_id)
    assert export.status_code == 200, export.text
    outcome = _check(verifier, export.json(),
                     capture_ref={"jsonrpc_id": "7",
                                  "body_sha256": hashlib.sha256(BODY).hexdigest()},
                     call=CALL)
    expected = dict.fromkeys(verifier.CLAIMS, "ESTABLISHED")
    expected["effect_observed"] = "NOT_ESTABLISHED"
    assert _results(outcome) == expected, outcome
    assert len(calls) == 1


def test_a_different_request_with_identical_content_is_contradicted(world, verifier):
    """The mismatched pair: same tool, same arguments, another request."""
    client, _ = world
    proposal_id, _run_ = _run(client, _ref(BODY, "7"))
    bundle = _export(client, proposal_id).json()
    outcome = _check(verifier, bundle,
                     capture_ref={"jsonrpc_id": "8",
                                  "body_sha256": hashlib.sha256(OTHER_BODY).hexdigest()},
                     call=CALL)
    results = _results(outcome)
    assert results["call_corresponds"] == "ESTABLISHED"
    assert results["request_corresponds"] == "CONTRADICTED"
    assert outcome["claims"]["request_corresponds"]["codes"] == ["request_ref_mismatch"]


def test_without_a_capture_the_request_claim_is_not_established(world, verifier):
    client, _ = world
    proposal_id, _run_ = _run(client, _ref(BODY, "7"))
    outcome = _check(verifier, _export(client, proposal_id).json())
    results = _results(outcome)
    assert results["request_corresponds"] == "NOT_ESTABLISHED"
    assert results["call_corresponds"] == "NOT_ESTABLISHED"
    assert results["authority_bound"] == "ESTABLISHED"


def test_a_grant_redeemed_under_another_request_is_refused_unspent(world):
    client, calls = world
    ref = _ref(BODY, "7")
    assessed = client.post("/v1/execution/assess", json=_proposal(ref), headers=HEADERS).json()
    token = assessed["execution_token"]
    wrong = client.post("/v1/execution/execute-accepted", headers=HEADERS, json={
        "execution_token": token, "tool_call": _proposal(_ref(OTHER_BODY, "8"))})
    assert wrong.status_code == 409 and "context_mismatch" in wrong.text, wrong.text
    assert calls == []
    right = client.post("/v1/execution/execute-accepted", headers=HEADERS, json={
        "execution_token": token, "tool_call": _proposal(ref)})
    assert right.status_code == 200 and right.json()["tool_execution"]["executed"], right.text
    assert len(calls) == 1


def test_a_grant_redeemed_with_the_reference_stripped_is_refused(world):
    client, calls = world
    _pid, run = _run(client, _ref(BODY, "7"), redeem_ref=None)
    assert run.status_code == 409 and "context_mismatch" in run.text
    assert calls == []


def test_without_a_reference_the_context_hash_is_unchanged(world, verifier):
    """A call that carries no reference hashes as before the field existed."""
    from remora.enforcement.token import AuthorizationContext

    bare = AuthorizationContext(tenant="t", principal="p")
    assert "request_ref_hash" not in bare.to_dict()
    assert bare.hash() == hashlib.sha256(json.dumps(
        bare.to_dict(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    client, _ = world
    proposal_id, run = _run(client, None)
    assert run.status_code == 200
    outcome = _check(verifier, _export(client, proposal_id).json())
    assert outcome["claims"]["request_corresponds"]["codes"] == ["request_ref_absent"]


@pytest.mark.parametrize("tamper, claim, code", [
    ("evidence_signature", "export_authentic", "evidence_signature_invalid"),
    ("chain_payload", "chain_consistent", "entry_hash_mismatch"),
])
def test_tampering_is_contradicted(world, verifier, tamper, claim, code):
    client, _ = world
    proposal_id, _run_ = _run(client, _ref(BODY, "7"))
    bundle = _export(client, proposal_id).json()
    if tamper == "evidence_signature":
        raw = bytearray(base64.b64decode(bundle["signature"]["value"]))
        raw[0] ^= 1
        bundle["signature"]["value"] = base64.b64encode(bytes(raw)).decode()
    else:
        # A self-consistent forgery needs the evidence key; without it, the
        # edited body no longer matches the signature, so re-sign with it here
        # to reach the chain check itself.
        body = json.loads(base64.b64decode(bundle["payload_b64"]))
        body["chain"][2]["payload_canonical"] = body["chain"][2]["payload_canonical"].replace(
            '"tool_executed":true', '"tool_executed":false')
        bundle = _resign(body)
    outcome = _check(verifier, bundle)
    assert outcome["claims"][claim]["result"] == "CONTRADICTED"
    assert code in outcome["claims"][claim]["codes"]


def _resign(body):
    from remora.crypto import SignatureDomain, SigningKey, sign

    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
    sig = sign(SignatureDomain.EVIDENCE, payload,
               SigningKey.from_text(SEEDS["evidence"], {SignatureDomain.EVIDENCE}))
    return {"format": "remora-invocation-evidence-envelope-v1",
            "payload_b64": base64.b64encode(payload).decode(),
            "signature": {"alg": sig.algorithm, "domain": sig.domain, "kid": sig.kid,
                          "value": sig.value}}


def test_a_forged_grant_is_contradicted_even_under_a_valid_export(world, verifier):
    """The exporter's key cannot stand in for the PDP's."""
    client, _ = world
    proposal_id, _run_ = _run(client, _ref(BODY, "7"))
    body = json.loads(base64.b64decode(_export(client, proposal_id).json()["payload_b64"]))
    forged = copy.deepcopy(body)
    raw = bytearray(base64.b64decode(forged["grant"]["token"]["signature"]))
    raw[0] ^= 1
    forged["grant"]["token"]["signature"] = base64.b64encode(bytes(raw)).decode()
    outcome = _check(verifier, _resign(forged))
    assert outcome["claims"]["authority_bound"]["result"] == "CONTRADICTED"
    assert outcome["claims"]["request_corresponds"]["result"] != "ESTABLISHED"


def test_export_refusals(world, monkeypatch):
    client, _ = world
    assert _export(client, "no-such-proposal").status_code == 404
    proposal_id, _run_ = _run(client, _ref(BODY, "7"))
    monkeypatch.delenv("REMORA_EVIDENCE_SIGNING_KEY_ED25519_PRIVATE")
    refused = _export(client, proposal_id)
    assert refused.status_code == 503
    assert "evidence_key_unavailable" in refused.text


def test_the_verifier_imports_no_remora_code():
    source = VERIFIER.read_text(encoding="utf-8")
    assert "import remora" not in source and "from remora" not in source


FIXTURES = ROOT / "integrations" / "invocation-evidence" / "fixtures"

#: The committed cases' outcomes, written out by hand so a regenerated
#: expected.json cannot quietly change what the cases establish.
CASE_MATRIX = {
    "01-matching-pair": dict.fromkeys(
        ("export_authentic", "chain_consistent", "authority_bound", "call_corresponds",
         "request_corresponds", "dispatch_recorded"), "ESTABLISHED"),
    "02-same-call-other-request": {"call_corresponds": "ESTABLISHED",
                                   "request_corresponds": "CONTRADICTED"},
    "03-other-export-same-call": {"call_corresponds": "ESTABLISHED",
                                  "request_corresponds": "CONTRADICTED"},
    "04-no-capture": {"authority_bound": "ESTABLISHED",
                      "request_corresponds": "NOT_ESTABLISHED"},
    "05-export-signature-altered": {"export_authentic": "CONTRADICTED",
                                    "authority_bound": "NOT_ESTABLISHED"},
    "06-grant-signature-forged": {"export_authentic": "ESTABLISHED",
                                  "authority_bound": "CONTRADICTED",
                                  "request_corresponds": "NOT_ESTABLISHED"},
    "07-lease-from-other-invocation": {"authority_bound": "CONTRADICTED"},
}


def test_committed_cases_agree_with_the_verifier():
    spec = importlib.util.spec_from_file_location("run_cases", FIXTURES / "run_cases.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    rows = module.run()
    assert [name for name, _ in rows] == sorted(CASE_MATRIX)
    assert all(agrees for _, agrees in rows), rows


@pytest.mark.parametrize("name", sorted(CASE_MATRIX))
def test_committed_case_outcomes_are_the_intended_ones(name):
    expected = json.loads((FIXTURES / "cases" / name / "case.json").read_text())["expected"]
    for claim, result in CASE_MATRIX[name].items():
        assert expected[claim]["result"] == result, (name, claim, expected[claim])


def test_the_cli_reports_a_contradiction_by_exit_code(tmp_path):
    import subprocess
    import sys

    keys = json.loads((FIXTURES / "keys.json").read_text())
    base = [sys.executable, "-I", str(VERIFIER), "--tenant", keys["tenant"],
            "--evidence-key", keys["evidence_public_key_hex"],
            "--grant-key", keys["grant_public_key_hex"],
            "--lease-key", keys["lease_public_key_hex"]]
    body = (FIXTURES / "request-7.json").read_bytes()
    matching = subprocess.run(
        [*base, "--bundle", str(FIXTURES / "cases" / "01-matching-pair" / "bundle.json"),
         "--jsonrpc-id", "7", "--body-sha256", hashlib.sha256(body).hexdigest()],
        capture_output=True, text=True, check=False)
    assert matching.returncode == 0, matching.stderr
    other = subprocess.run(
        [*base, "--bundle", str(FIXTURES / "cases" / "03-other-export-same-call" / "bundle.json"),
         "--jsonrpc-id", "7", "--body-sha256", hashlib.sha256(body).hexdigest()],
        capture_output=True, text=True, check=False)
    assert other.returncode == 1
    assert json.loads(other.stdout)["claims"]["request_corresponds"]["result"] == "CONTRADICTED"


# The chain under attack, end to end: enforcement first, then the receiver.


def test_a_grant_presented_with_another_call_is_refused_before_dispatch(world):
    """Wrong call binding at enforcement: the grant names one call, another is
    presented under the same request reference. Nothing runs, and the grant
    is still good for the call it names."""
    client, calls = world
    ref = _ref(BODY, "7")
    token = client.post("/v1/execution/assess", json=_proposal(ref),
                        headers=HEADERS).json()["execution_token"]
    other = {**_proposal(ref), "arguments": {"asset": "P-2"}}
    refused = client.post("/v1/execution/execute-accepted", headers=HEADERS,
                          json={"execution_token": token, "tool_call": other})
    assert refused.status_code == 409 and "binding_refused" in refused.text, refused.text
    assert calls == []
    ran = client.post("/v1/execution/execute-accepted", headers=HEADERS,
                      json={"execution_token": token, "tool_call": _proposal(ref)})
    assert ran.status_code == 200 and len(calls) == 1


def test_a_denied_call_gets_no_grant_no_dispatch_and_no_export(world):
    """Dispatch after deny: a call REMORA does not ACCEPT carries no grant,
    a grant for another call does not carry it, and nothing is exportable as
    an executed invocation."""
    client, calls = world
    denied_call = {"tool_name": "wire_transfer", "arguments": {"amount": 10},
                   "target_environment": "prod", "request_ref": _ref(OTHER_BODY, "8")}
    denied = client.post("/v1/execution/assess", json=denied_call, headers=HEADERS)
    assert denied.status_code == 200, denied.text
    assert denied.json()["decision"] != "accept"
    assert "execution_token" not in denied.json()
    token = client.post("/v1/execution/assess", json=_proposal(_ref(BODY, "7")),
                        headers=HEADERS).json()["execution_token"]
    smuggled = client.post("/v1/execution/execute-accepted", headers=HEADERS,
                           json={"execution_token": token, "tool_call": denied_call})
    assert smuggled.status_code in (403, 409), smuggled.text
    assert calls == []
    export = _export(client, denied.json()["proposal_id"])
    assert export.status_code == 409 and "not_a_direct_accept" in export.text


def test_a_chain_rewritten_to_hide_a_deny_is_contradicted(world, verifier):
    """The receiver side of dispatch after deny: an exporter that records a
    deny and then an execution cannot present it as an ACCEPT."""
    client, _ = world
    proposal_id, _run_ = _run(client, _ref(BODY, "7"))
    body = json.loads(base64.b64decode(_export(client, proposal_id).json()["payload_b64"]))
    body["chain"][0]["payload_canonical"] = body["chain"][0]["payload_canonical"].replace(
        '"decision":"accept"', '"decision":"abstain"')
    outcome = _check(verifier, _resign(body))
    assert outcome["claims"]["chain_consistent"]["result"] == "CONTRADICTED"
    assert "not_a_direct_accept" in outcome["claims"]["chain_consistent"]["codes"]
    assert outcome["claims"]["authority_bound"]["result"] == "NOT_ESTABLISHED"


def test_the_tools_own_result_is_not_an_observed_effect(world, verifier):
    """The tool's report about itself is in the export as a result digest. The
    receiver never turns it into an observed effect."""
    client, _ = world
    proposal_id, _run_ = _run(client, _ref(BODY, "7"))
    outcome = _check(verifier, _export(client, proposal_id).json(),
                     capture_ref={"jsonrpc_id": "7",
                                  "body_sha256": hashlib.sha256(BODY).hexdigest()},
                     call=CALL)
    assert outcome["claims"]["dispatch_recorded"]["result"] == "ESTABLISHED"
    assert outcome["result_sha256"]
    assert outcome["claims"]["effect_observed"] == {
        "result": "NOT_ESTABLISHED", "codes": ["no_observation_in_export"]}


# F-10 and F-11 of the 2026-10-18 design review: the id's canonical form, and
# one JSON domain on both sides.

ID_VECTORS = json.loads((FIXTURES / "jsonrpc-id-vectors.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("vector", ID_VECTORS["vectors"], ids=lambda v: v["wire"])
def test_server_and_verifier_agree_on_the_id_canonical_form(verifier, vector):
    from remora.execution.request_ref import RequestRef, canonical_jsonrpc_id

    for canon in (canonical_jsonrpc_id, verifier.canonical_jsonrpc_id):
        if vector["canonical"] is None:
            with pytest.raises(ValueError):
                canon(vector["wire"])
        else:
            assert canon(vector["wire"]) == vector["canonical"]
    if vector["canonical"] is not None:
        RequestRef("mcp-streamable-http", vector["canonical"], "ab" * 32)
        if vector["wire"] != vector["canonical"]:
            with pytest.raises(ValueError, match="canonical"):
                RequestRef("mcp-streamable-http", vector["wire"], "ab" * 32)


def test_an_escaped_capture_id_matches_its_canonical_reference(world, verifier):
    client, _ = world
    proposal_id, _run_ = _run(client, _ref(BODY, '"7"'))
    outcome = _check(verifier, _export(client, proposal_id).json(),
                     capture_ref={"jsonrpc_id": '"\\u0037"',
                                  "body_sha256": hashlib.sha256(BODY).hexdigest()})
    assert outcome["claims"]["request_corresponds"]["result"] == "ESTABLISHED"


@pytest.mark.parametrize("call, message", [
    ('{"name":"read_telemetry","arguments":{"asset":"P-1","asset":"P-2"},"target":"staging"}',
     "duplicate key"),
    ('{"name":"read_telemetry","arguments":{"x":NaN},"target":"staging"}', "not JSON"),
])
def test_the_verifier_refuses_ambiguous_call_json(verifier, call, message):
    with pytest.raises(verifier.InputError, match=message):
        verifier.strict_loads(call)


def test_a_signed_body_with_a_duplicate_key_is_contradicted(world, verifier):
    """Bytes two readers would read differently are not an export, even signed."""
    client, _ = world
    proposal_id, _run_ = _run(client, _ref(BODY, "7"))
    raw = base64.b64decode(_export(client, proposal_id).json()["payload_b64"])
    ambiguous = raw[:-1] + b',"tenant":"someone-else"}'
    from remora.crypto import SignatureDomain, SigningKey, sign

    sig = sign(SignatureDomain.EVIDENCE, ambiguous,
               SigningKey.from_text(SEEDS["evidence"], {SignatureDomain.EVIDENCE}))
    bundle = {"format": "remora-invocation-evidence-envelope-v1",
              "payload_b64": base64.b64encode(ambiguous).decode(),
              "signature": {"alg": sig.algorithm, "domain": sig.domain, "kid": sig.kid,
                            "value": sig.value}}
    outcome = _check(verifier, bundle)
    assert outcome["claims"]["export_authentic"] == {
        "result": "CONTRADICTED", "codes": ["body_not_strict_json"]}


# Etappe 1, probe P1: one batch body, two requests, one body digest.

BATCH = (b'[{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_telemetry",'
         b'"arguments":{"asset":"P-1"}}},{"jsonrpc":"2.0","id":8,"method":"tools/call",'
         b'"params":{"name":"read_telemetry","arguments":{"asset":"P-1"}}}]')


def test_a_batch_member_grant_does_not_redeem_for_its_sibling(world, verifier):
    """Both members share body_sha256; the id is what tells them apart, at
    enforcement and at the receiver."""
    client, calls = world
    first, second = _ref(BATCH, "7"), _ref(BATCH, "8")
    assert first["body_sha256"] == second["body_sha256"]
    token = client.post("/v1/execution/assess", json=_proposal(first),
                        headers=HEADERS).json()["execution_token"]
    sibling = client.post("/v1/execution/execute-accepted", headers=HEADERS,
                          json={"execution_token": token, "tool_call": _proposal(second)})
    assert sibling.status_code == 409 and "context_mismatch" in sibling.text
    assert calls == []
    proposal_id, _run_ = _run(client, first)
    outcome = _check(verifier, _export(client, proposal_id).json(),
                     capture_ref={"jsonrpc_id": "8", "body_sha256": second["body_sha256"]})
    assert outcome["claims"]["request_corresponds"]["result"] == "CONTRADICTED"


# Etappe 1, probe P2 (design review INV-12): a grant outlives a policy revision.

def test_a_grant_issued_before_a_policy_revision_is_refused_unspent(world, monkeypatch):
    """The policy bundle hash is in the signed context. After a revision the
    recomputed context differs, so the grant is refused before consumption,
    and it redeems again once the original policy is back."""
    from servers import execution_api as execution

    client, calls = world
    ref = _ref(BODY, "7")
    token = client.post("/v1/execution/assess", json=_proposal(ref),
                        headers=HEADERS).json()["execution_token"]
    original = execution._current_policy_bundle_hash
    monkeypatch.setattr(execution, "_current_policy_bundle_hash", lambda: "f" * 64)
    revised = client.post("/v1/execution/execute-accepted", headers=HEADERS,
                          json={"execution_token": token, "tool_call": _proposal(ref)})
    assert revised.status_code == 409 and "context_mismatch" in revised.text, revised.text
    assert calls == []
    monkeypatch.setattr(execution, "_current_policy_bundle_hash", original)
    restored = client.post("/v1/execution/execute-accepted", headers=HEADERS,
                           json={"execution_token": token, "tool_call": _proposal(ref)})
    assert restored.status_code == 200 and len(calls) == 1

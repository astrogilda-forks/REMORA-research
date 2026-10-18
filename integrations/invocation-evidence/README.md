# Invocation evidence: one REMORA execution, checkable offline

Status: experimental. Written for a paired experiment with Assay proposed in
[aeoess/agent-governance-vocabulary#177](https://github.com/aeoess/agent-governance-vocabulary/issues/177#issuecomment-6246266845).
No external run has been recorded.

## What it is

For one directly ACCEPTed tool call, REMORA exports a signed bundle. A
verifier holding three public keys checks it without REMORA code and without
any secret. The bundle carries:

| Part | Signed by | What a verifier checks |
|---|---|---|
| `assessed`, `execution_authorized` and `execution_result` chain entries | the evidence key, through the export signature | each entry hash over the exact string it covers, the order, and the links between the three |
| the decision grant (v3) | the PDP key, `REMORA/POLICY-GRANT/v3` | its signature over the exact payload bytes, and that the bytes carry the grant's fields |
| the authorization context | inside the grant, as `context_hash` | that its SHA-256 equals the signed `context_hash` |
| the execution lease (v2) | the lease issuer key, `REMORA/EXECUTION-LEASE/v2` | its signature, and that it names this grant, proposal, principal and call hash |
| the request reference | inside the context, as `request_ref_hash` | that it is the request the verifier captured |
| the export as a whole | the evidence key, `REMORA/EVIDENCE/v1` | one signature over the exact body bytes |

The request reference is set by the MCP gateway for every `tools/call`. It
holds the transport, the JSON-RPC id's JSON text and the SHA-256 of the HTTP
body bytes as received. REMORA binds its digest into the grant at ACCEPT, and
redemption refuses the grant, unspent, under any other reference.

## Verify

```sh
python integrations/invocation-evidence/verify_invocation_evidence.py \
  --bundle export.json --tenant <tenant> \
  --evidence-key <hex> --grant-key <hex> --lease-key <hex> \
  --jsonrpc-id '<id as JSON text>' --body-sha256 <sha256 of the captured body> \
  --call call.json
```

The verifier needs Python 3.10 or later and `cryptography`. Its trust and
context inputs are:

- the grant, lease and evidence public keys, pinned out of band;
- the tenant;
- optionally the expected runtime identity hash and policy bundle hash;
- from the verifier's own capture: the JSON-RPC id, the body digest, and the
  call as `{"name", "arguments", "target"}`.

Each of six claims is `ESTABLISHED`, `CONTRADICTED` or `NOT_ESTABLISHED`
with reason codes:

| Claim | ESTABLISHED means |
|---|---|
| `export_authentic` | the export signature verifies under the pinned evidence key, for the given tenant |
| `chain_consistent` | the three entries hash as recorded, belong to this proposal and link to each other |
| `authority_bound` | the grant and the lease verify under their own pinned keys and bind this proposal, principal and call |
| `call_corresponds` | the captured call recomputes to the recorded call hash |
| `request_corresponds` | the captured request is the one the signed grant was bound to |
| `dispatch_recorded` | REMORA recorded the dispatch as executed, not unknown |

Exit 0 means nothing is `CONTRADICTED`. `NOT_ESTABLISHED` never counts as a
pass for its claim.

The export comes from `GET /v1/execution/proposals/{id}/invocation-evidence`.
The execution API needs `REMORA_EVIDENCE_SIGNING_KEY_ED25519_PRIVATE`, v3
grants (`REMORA_PDP_SIGNING_KEY_ED25519_PRIVATE`) and v2 leases
(`REMORA_SIGNATURE_FORMAT=v2` with `REMORA_LEASE_SIGNING_KEY_ED25519_PRIVATE`).

## Fixture cases

`fixtures/` holds seven cases made through the real server path by
`fixtures/generate.py`. The run used fresh demo keys whose private halves were
discarded. Two MCP requests, ids 7 and 8, carry the same tool call:

| Case | What it pairs | `call_corresponds` | `request_corresponds` | Other |
|---|---|---|---|---|
| 01 | export of 7, capture of 7 | ESTABLISHED | ESTABLISHED | all ESTABLISHED |
| 02 | export of 7, capture of 8 | ESTABLISHED | CONTRADICTED | |
| 03 | export of 8, capture of 7 | ESTABLISHED | CONTRADICTED | |
| 04 | export of 7, no capture | NOT_ESTABLISHED | NOT_ESTABLISHED | authority ESTABLISHED |
| 05 | export signature altered | NOT_ESTABLISHED | NOT_ESTABLISHED | `export_authentic` CONTRADICTED |
| 06 | grant signature altered, export re-signed | ESTABLISHED | NOT_ESTABLISHED | `authority_bound` CONTRADICTED |
| 07 | lease of 8 in the export of 7, re-signed | ESTABLISHED | ESTABLISHED | `authority_bound` CONTRADICTED |

Cases 02 and 03 are the point of the reference. Matching call content alone
does not establish that two records describe one execution. The request
digest does, and only for the request the front end recorded.

`python integrations/invocation-evidence/fixtures/run_cases.py` runs them,
and `tests/test_invocation_evidence_export.py` pins the outcomes above.

## What this does not establish

- That the effect happened. `dispatch_recorded` is REMORA's record of its own
  dispatch.
- That every path to the tool passes through REMORA, or that a capture on
  either side is complete. `runtime_capability_surface_completeness` stays
  `NOT_ESTABLISHED`.
- Authenticity of the chain entries independent of the exporter. The store
  seals them with an HMAC that is not exported, so they rest on the evidence
  signature. The grant and lease signatures do not rest on it: the exporter's
  key cannot forge them (case 06).
- Anything about review-path executions. Only a direct ACCEPT is exported, and
  only one recorded after the grant was kept in the chain.
- An independent result. REMORA wrote the export, the verifier and the cases.

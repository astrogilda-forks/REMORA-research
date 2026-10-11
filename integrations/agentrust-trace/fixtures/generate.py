#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Generate the REMORA -> TRACE mapping fixtures from fixed demo seeds.

Each case file holds the inputs (the signed result envelope, the native
reports, an optional execution context, the request and the trusted keys) and
the full expected outcome: either the whole mapping, or the refusal code and
reason. A consumer compares all of it, not only a verdict.

The keys are demo keys from published seeds, the reports and contexts are
synthetic, and nothing here was executed against a provider.

    python integrations/agentrust-trace/fixtures/generate.py          # write
    python integrations/agentrust-trace/fixtures/generate.py --check  # compare
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from remora.crypto import SignatureDomain, SigningKey, VerificationKey  # noqa: E402
from remora.federation import NativeResult, Report, SubjectRef, select_report  # noqa: E402
from remora.federation.results import result_document, result_evidence  # noqa: E402
from remora.governance.execution_identity import (  # noqa: E402
    ContextAuthority,
    ContextDataScope,
    ContextRuntime,
    ContextSubject,
    ExecutionContextV1,
    ModelInitiator,
)
from remora.interop.trace import ExportRequest, TraceExportRefused, map_result  # noqa: E402

CASES_DIR = Path(__file__).resolve().parent / "cases"
SIGNER = SigningKey.from_text("a1" * 32, [SignatureDomain.FEDERATION_RESULT])
STRANGER = SigningKey.from_text("b2" * 32, [SignatureDomain.FEDERATION_RESULT])
CLAIM = "remora.exact_call_binding"
OPERATION = "op-trace-fixture-1"
ISSUED_AT = 1_791_000_000
INGESTED_AT = 1_790_999_940


def _context(tool_call_hash: str = "c" * 64) -> ExecutionContextV1:
    return ExecutionContextV1(
        context_id="7f1c2a3b-0000-4000-8000-000000000001",
        proposal_id="7f1c2a3b-0000-4000-8000-000000000002",
        tenant_id="tenant-a",
        tool_call_hash=tool_call_hash,
        captured_at="2026-10-11T12:00:00Z",
        subject=ContextSubject(
            principal_id="spiffe://example.test/agents/refund-bot",
            authority=ContextAuthority("spiffe", "spiffe://example.test", "svid:demo")),
        model_initiator=ModelInitiator(
            provider="example-provider", model_id="example-model-1",
            authority=ContextAuthority("inference_gateway", "gateway.example.test",
                                       "gateway-log:demo-1")),
        runtime=ContextRuntime(
            runtime_identity_hash="d" * 64, build_provenance_digest="e" * 64,
            authority=ContextAuthority("deployment", "deploy.example.test", "deploy:demo")),
        data_scope=ContextDataScope(
            classification="internal", scope=("proposal_input", "declared_tool_access"),
            authority=ContextAuthority("deployment_policy", "deploy.example.test",
                                       "policy:demo")),
    )


def _report(report_id: str, sequence: int, context: ExecutionContextV1 | None) -> Report:
    body: dict[str, Any] = {"observed": "dispatch_bound_to_lease"}
    if context is not None:
        body["execution_context_digest"] = context.digest()
    return Report(operation_id=OPERATION, report_id=report_id, sequence=sequence, body=body,
                  kind="execution_attempt")


def _evidence(report: Report, status: str, reason: str, key: SigningKey = SIGNER) -> bytes:
    subject = report.subject()
    _, selection = select_report([report], report_digest=subject.report_digest)
    document = result_document(native_claim=CLAIM, subject=subject, selection=selection,
                               native_result=NativeResult(status, reason))
    return result_evidence(document, key)


def _request(subject: SubjectRef, **overrides: Any) -> dict[str, Any]:
    request: dict[str, Any] = {
        "native_claim": CLAIM, "subject": subject.to_dict(), "issued_at": ISSUED_AT,
        "ingested_at": INGESTED_AT, "producer": "remora:deploy.example.test",
        "resolver": "deploy.example.test", "retention": "P1Y",
        "expected_tenant": "tenant-a",
        "expected_principal": "spiffe://example.test/agents/refund-bot",
    }
    request.update(overrides)
    return request


def _case(description: str, evidence: bytes, reports: list[Report],
          context: ExecutionContextV1 | str | None, request: dict[str, Any]) -> dict[str, Any]:
    if isinstance(context, ExecutionContextV1):
        context = context.canonical_bytes().decode("utf-8")
    return {
        "description": description,
        "input": {
            "trusted_keys": [SIGNER.verification_key().public_bytes.hex()],
            "evidence_b64": base64.b64encode(evidence).decode("ascii"),
            "reports": [{"kind": r.kind, "operation_id": r.operation_id,
                         "report_id": r.report_id, "sequence": r.sequence, "body": r.body}
                        for r in reports],
            "execution_context": context,
            "request": request,
        },
    }


def evaluate(case_input: dict[str, Any]) -> dict[str, Any]:
    """Run the mapper on one case input; the outcome a case file expects."""
    keys = [VerificationKey.from_text(k, [SignatureDomain.FEDERATION_RESULT])
            for k in case_input["trusted_keys"]]
    reports = [Report(**r) for r in case_input["reports"]]
    raw = dict(case_input["request"])
    raw["subject"] = SubjectRef(**raw["subject"])
    try:
        mapping = map_result(base64.b64decode(case_input["evidence_b64"]), keys,
                             ExportRequest(**raw), reports=reports,
                             execution_context=case_input["execution_context"])
    except TraceExportRefused as exc:
        return {"refused": {"code": exc.code, "reason": exc.reason}}
    return {"mapping": mapping}


def build_cases() -> dict[str, dict[str, Any]]:
    ctx = _context()
    first, second = _report("attempt-1", 1, ctx), _report("attempt-2", 2, ctx)
    bare = _report("attempt-1", 1, None)
    other_ctx = _context(tool_call_hash="f" * 64)
    tampered = bytearray(_evidence(first, "ESTABLISHED", "lease_binds_exact_call"))
    payload_at = tampered.index(b'"result_b64":"') + len('"result_b64":"') + 8
    tampered[payload_at] = ord("A") if tampered[payload_at] != ord("A") else ord("B")

    cases = {
        "01-established-with-context": _case(
            "Signed ESTABLISHED result for one attempt, context bound by digest in the report.",
            _evidence(first, "ESTABLISHED", "lease_binds_exact_call"), [first, second], ctx,
            _request(first.subject())),
        "02-contradicted-preserved": _case(
            "A native CONTRADICTED result maps; the native result stays CONTRADICTED.",
            _evidence(second, "CONTRADICTED", "arguments_differ_from_lease"), [first, second],
            ctx, _request(second.subject())),
        "03-no-context-no-resolver": _case(
            "No execution context and no resolver: model absent, no reference emitted.",
            _evidence(bare, "ESTABLISHED", "lease_binds_exact_call"), [bare], None,
            _request(bare.subject(), resolver=None, retention=None, expected_tenant=None,
                     expected_principal=None)),
        "04-wrong-tenant": _case(
            "Caller expects another tenant than the bound context names.",
            _evidence(first, "ESTABLISHED", "lease_binds_exact_call"), [first], ctx,
            _request(first.subject(), expected_tenant="tenant-b")),
        "05-wrong-principal": _case(
            "Caller expects another principal than the bound context names.",
            _evidence(first, "ESTABLISHED", "lease_binds_exact_call"), [first], ctx,
            _request(first.subject(), expected_principal="spiffe://example.test/agents/other")),
        "06-context-replaced": _case(
            "A context for another tool call is presented; its digest is not the bound one.",
            _evidence(first, "ESTABLISHED", "lease_binds_exact_call"), [first], other_ctx,
            _request(first.subject())),
        "07-context-not-bound": _case(
            "A context is presented but the signed report does not bind any context.",
            _evidence(bare, "ESTABLISHED", "lease_binds_exact_call"), [bare], ctx,
            _request(bare.subject())),
        "08-untrusted-signer": _case(
            "The result is signed by a key the caller does not trust.",
            _evidence(first, "ESTABLISHED", "lease_binds_exact_call", STRANGER), [first], ctx,
            _request(first.subject())),
        "09-result-rebound-to-other-report": _case(
            "attempt-1's signed result presented as the result for attempt-2.",
            _evidence(first, "ESTABLISHED", "lease_binds_exact_call"), [first, second], ctx,
            _request(second.subject())),
        "10-tampered-envelope": _case(
            "One base64 character of the signed payload is changed.",
            bytes(tampered), [first], ctx, _request(first.subject())),
        "11-subject-not-report-specific": _case(
            "An operation-level subject: no single report is named.",
            _evidence(first, "ESTABLISHED", "lease_binds_exact_call"), [first, second], ctx,
            _request(SubjectRef(kind="operation", operation_id=OPERATION))),
        "12-report-not-held": _case(
            "The subject names attempt-2 but the caller holds only attempt-1.",
            _evidence(second, "ESTABLISHED", "lease_binds_exact_call"), [first], ctx,
            _request(second.subject())),
    }
    for case in cases.values():
        case["expected"] = evaluate(case["input"])
    return cases


def _encode(case: dict[str, Any]) -> str:
    return json.dumps(case, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    cases = build_cases()
    if "--check" in argv:
        drift = [name for name, case in cases.items()
                 if not (CASES_DIR / f"{name}.json").is_file()
                 or (CASES_DIR / f"{name}.json").read_text(encoding="utf-8") != _encode(case)]
        extra = sorted(p.stem for p in CASES_DIR.glob("*.json") if p.stem not in cases)
        if drift or extra:
            print(f"[FAIL] fixture drift: {drift} extra: {extra}")
            return 1
        print(f"[PASS] {len(cases)} fixture case(s) match the generator")
        return 0
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    for name, case in cases.items():
        (CASES_DIR / f"{name}.json").write_text(_encode(case), encoding="utf-8")
    print(f"wrote {len(cases)} case(s) to {CASES_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

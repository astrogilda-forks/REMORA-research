#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Does REMORA itself stop C? The set-2 payments replayed through REMORA's engine.

``run.py`` reads the signed records after the fact; REMORA was not in the
path of those calls. This script answers the other question for #55: given
the same three payments, does REMORA let the third one run?

The three payments, their amounts and unit, the payer and payee, and the
budget (``max_total`` from the issuer-signed budget policy) are taken from
the authenticated set-2 log, never typed in. Each payment is sent through
REMORA's execution API in this process: ``/v1/execution/assess``,
``/v1/execution/approve``, ``/v1/execution/execute``, the governed
dispatcher, and a sandboxed tool (``payment_tool.py``) that records each
call reaching it. Nothing is paid and nothing leaves the process.

Three runs:

``remora_as_shipped``
    No cumulative limit declared: REMORA's behaviour before #1025.
``budget_declared``
    The issuer's budget declared as a REMORA cumulative limit for the payer.
``budget_declared_approved_first``
    The same limit, with all three payments assessed and approved before any
    executes, so only the reservation at dispatch can stop C.

    python integrations/horizon55/enforce.py --json
    python integrations/horizon55/enforce.py --write   # enforcement.json
    python integrations/horizon55/enforce.py --check

Unlike ``run.py``, this imports REMORA: it is REMORA's own decision path
under test. It runs with ``REMORA_ENV=development``, in-process
authentication and replay-only signing keys, as the repository's route
tests do.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

import canon  # noqa: E402
import check_inputs  # noqa: E402
import claims  # noqa: E402

OUT = check_inputs.PACKAGE / "enforcement.json"
TENANT = "hs51-set2"
SPEC_KEY, SPEC_IDENTITY = "h55-replay-toolspec-key", "h55-replay-signer"
PAYMENT_ENTRY_TYPE = "musubi.ca2a.payment-receipt.v0"
BUDGET_ENTRY_TYPE = "musubi.ca2a.budget-policy.v0"


def signed_sequence() -> dict[str, Any]:
    """Budget and payments from the verified set-2 log, in log order."""
    inp = claims.load_inputs(check_inputs.INPUTS, check_inputs.CACHE, check_inputs.load_lock())
    log = claims.verify_log(inp)
    if log["problems"]:
        raise SystemExit(f"set-2 log does not verify: {log['problems']}")
    items = [e["entry"]["item"] for e in log["entries"] if e["item_ok"]]
    budgets = [i for i in items if i["type"] == BUDGET_ENTRY_TYPE]
    if len(budgets) != 1:
        raise SystemExit("expected exactly one signed budget policy")
    requests = {canon.sha256_hex(canon.jcs(r)): r["occurrence_id"]
                for r in log["bundle"]["requests"]}
    payments = [{"case": requests[i["request_sha256"]].rsplit("-", 1)[-1],
                 "occurrence_id": requests[i["request_sha256"]],
                 "payer": i["payer"], "payee": i["payee"], "amount": i["amount"],
                 "unit": i["unit"]}
                for i in items if i["type"] == PAYMENT_ENTRY_TYPE]
    payers = {p["payer"] for p in payments}
    if len(payers) != 1 or [p["case"] for p in payments] != ["A", "B", "C"]:
        raise SystemExit("expected payments A, B and C from one payer")
    budget = budgets[0]
    return {"payer": payers.pop(), "budget": {"max_total": budget["max_total"],
                                              "unit": budget["unit"],
                                              "issuer": budget["issuer"]},
            "payments": payments}


def _limit_policy(seq: dict[str, Any]) -> dict[str, Any]:
    return {"schema": "remora-cumulative-limits/v1", "coverage": "listed",
            "meters": {"transfer_payment": [{"quantity": "spend", "kind": "sum",
                                             "argument": "amount", "unit_argument": "unit"}]},
            "limits": [{"limit_id": "hs51-set2-budget", "tenant": TENANT, "quantity": "spend",
                        "unit": seq["budget"]["unit"], "max": seq["budget"]["max_total"],
                        "principal": seq["payer"]}],
            # One payment is one operation: the same payee, amount, unit and
            # occurrence reference twice is a duplicate, not a second payment.
            "idempotency": {"transfer_payment": {
                "key_arguments": ["payee", "amount", "unit", "reference"]}},
            # Only the sandbox rail's own refusal frees a reservation at once;
            # any other adapter statement holds the payment as unknown.
            "non_execution": {"transfer_payment": {"trusted_sources": ["sandbox-rail"]}}}


def _toolspec_bundle(path: Path) -> None:
    import payment_tool

    from remora.toolcall.callable_digest import source_digest
    from remora.toolcall.toolspec import sign_bundle

    spec = {
        "tool_id": "transfer_payment", "version": 1,
        "callable_digest": source_digest(payment_tool.transfer_payment),
        "implementation_identity": "h55-replay@sandbox",
        "description": "Pay a responder for one estimate-audit call (sandboxed).",
        "argument_schema": {"type": "object",
                            "properties": {"payee": {"type": "string"},
                                           "amount": {"type": "integer"},
                                           "unit": {"type": "string"},
                                           "reference": {"type": "string"}},
                            "required": ["payee", "amount", "unit"],
                            "additionalProperties": False},
        "risk_tier": "medium", "action_type": "write", "domain": "finance",
        "capabilities": ["payments"],
        "semantic_contract": {"capability": "payments", "effect": "transfer",
                              "resource_type": "payment", "mutation": True,
                              "argument_roles": {"payee": "target_resource"}},
        "credential_scope": ["payments:write"], "allowed_targets": ["prod"],
        "idempotency_contract": {"safe_to_retry": False, "key_derivation": "canonical_args"},
        "postcondition_reader": None, "compensation_tool": None,
        "timeout_policy": {"dispatch_timeout_seconds": 10}, "network_policy": {"egress": "none"},
        "signing_identity": SPEC_IDENTITY,
    }
    bundle = sign_bundle({"schema_version": 1, "tool_specs": [spec]}, key=SPEC_KEY,
                         signing_identity=SPEC_IDENTITY, signed_at="2026-10-22T00:00:00Z")
    path.write_text(json.dumps(bundle), encoding="utf-8")


class _Api:
    """REMORA's execution API in this process, configured for one run."""

    def __init__(self, work: Path, seq: dict[str, Any], limits: dict[str, Any] | None) -> None:
        env = {
            "REMORA_ENV": "development", "REMORA_PDP_SIGNING_KEY": "h55-replay-pdp-key",
            "REMORA_LEASE_SIGNING_KEY": "h55-replay-lease-key",
            "REMORA_TOOL_REGISTRY_MODULE": "payment_tool",
            "REMORA_EXECUTION_ARTIFACT_DIR": str(work / "artifacts"),
            "REMORA_TOOLSPEC_BUNDLE": str(work / "toolspec.json"),
            "REMORA_TOOLSPEC_SIGNING_KEY": SPEC_KEY,
            "REMORA_TOOLSPEC_TRUSTED_IDENTITIES": SPEC_IDENTITY,
        }
        for var in ("REMORA_SEMANTIC_BUNDLE_MODULE", "REMORA_LIMITS_FILE", "REMORA_LIMITS_LEDGER",
                    "REMORA_LIMITS_OBSERVER_MODULE", "REMORA_LIMITS_EVIDENCE_MODULE",
                    "REMORA_REQUIRE_IDEMPOTENCY"):
            os.environ.pop(var, None)
        if limits is not None:
            (work / "limits.json").write_text(json.dumps(limits), encoding="utf-8")
            env["REMORA_LIMITS_FILE"] = str(work / "limits.json")
            env["REMORA_LIMITS_LEDGER"] = str(work / "limits-ledger.db")
            # A reviewer's resolution is checked against the sandbox rail's
            # own records before any budget is returned.
            env["REMORA_LIMITS_EVIDENCE_MODULE"] = "payment_tool"
        os.environ.update(env)
        _toolspec_bundle(work / "toolspec.json")

        from fastapi.testclient import TestClient

        import servers.api as api_mod
        import servers.execution_api as exec_mod
        from remora.governance.tenant_chain import TenantAuditChain

        payer = seq["payer"]
        api_mod._authenticate = lambda request: (TENANT, "reviewer")
        api_mod._authenticated_principal = lambda request: payer
        api_mod._require_tenant_capability = lambda role, tenant, cap: None
        api_mod._enforce_review_approval_role = lambda **kwargs: None
        exec_mod._QUEUES.clear()
        exec_mod._ITEM_TENANT.clear()
        exec_mod._CHAIN = TenantAuditChain()
        exec_mod._reset_semantic_bundle()
        exec_mod._reset_tool_dispatcher()
        exec_mod._reset_outbox()
        exec_mod._reset_toolspec_bundle()
        import payment_tool

        payment_tool.REACHED.clear()
        payment_tool.FAIL_NEXT.clear()
        self.exec_mod = exec_mod
        self.client = TestClient(api_mod.app)

    @staticmethod
    def call(payment: dict[str, Any]) -> dict[str, Any]:
        return {"tool_name": "transfer_payment",
                "arguments": {"payee": payment["payee"], "amount": payment["amount"],
                              "unit": payment["unit"], "reference": payment["occurrence_id"]},
                "target_environment": "prod", "schema_valid": True,
                "context_id": TENANT, "task_id": payment["occurrence_id"]}

    def assess(self, payment: dict[str, Any]) -> dict[str, Any]:
        r = self.client.post("/v1/execution/assess", json=self.call(payment))
        body = r.json()
        if r.status_code != 200:
            return {"status": r.status_code, "refusal": body.get("detail")}
        return {"status": 200, "decision": body.get("decision"),
                "item_id": body.get("review_item_id")}

    def approve(self, item_id: str) -> int:
        return self.client.post("/v1/execution/approve",
                                json={"item_id": item_id, "approval_ttl_seconds": 900}).status_code

    def execute(self, item_id: str, payment: dict[str, Any]) -> dict[str, Any]:
        body = self.client.post("/v1/execution/execute",
                                json={"item_id": item_id, "tool_call": self.call(payment)}).json()
        tool = body.get("tool_execution") or {}
        return {"executed": bool(tool.get("executed")), "refusal": tool.get("refusal_reason")}

    def reached(self) -> list[str]:
        import payment_tool

        return [r["reference"] for r in payment_tool.REACHED]

    def chain_events(self) -> list[str]:
        return [e.payload.get("event") for e in self.exec_mod._CHAIN.entries(TENANT)]


def _case(payment: dict[str, Any], assessed: dict[str, Any], approved: int | None,
          executed: dict[str, Any] | None) -> dict[str, Any]:
    if assessed["status"] != 200:
        stage, refusal = "assess", assessed["refusal"]
    elif executed is None:
        stage, refusal = "review", None
    else:
        stage, refusal = "dispatch", executed["refusal"]
    ran = bool(executed and executed["executed"])
    return {"case": payment["case"], "occurrence_id": payment["occurrence_id"],
            "amount": payment["amount"], "unit": payment["unit"],
            "assess": (f"refused {assessed['refusal']}" if assessed["status"] != 200
                       else assessed["decision"]),
            "approved": approved == 200 if approved is not None else None,
            "outcome": "executed" if ran else f"refused at {stage}: {refusal}",
            "reached_tool": ran}


def _sequential(work: Path, seq: dict[str, Any], limits: dict[str, Any] | None) -> dict[str, Any]:
    api = _Api(work, seq, limits)
    cases = []
    for payment in seq["payments"]:
        assessed = api.assess(payment)
        approved = executed = None
        if assessed["status"] == 200 and assessed.get("item_id"):
            approved = api.approve(assessed["item_id"])
            executed = api.execute(assessed["item_id"], payment)
        cases.append(_case(payment, assessed, approved, executed))
    return {"cases": cases, "reached_tool": api.reached(),
            "limit_refused_on_chain": api.chain_events().count("limit_refused")}


def _approved_first(work: Path, seq: dict[str, Any], limits: dict[str, Any]) -> dict[str, Any]:
    api = _Api(work, seq, limits)
    pending = []
    for payment in seq["payments"]:
        assessed = api.assess(payment)
        approved = api.approve(assessed["item_id"]) if assessed.get("item_id") else None
        pending.append((payment, assessed, approved))
    cases = [_case(p, a, ok, api.execute(a["item_id"], p) if a.get("item_id") else None)
             for p, a, ok in pending]
    return {"cases": cases, "reached_tool": api.reached(),
            "limit_refused_on_chain": api.chain_events().count("limit_refused")}


@contextmanager
def isolated() -> Iterator[None]:
    """Leave the process as it was: the replay also runs inside the test suite."""
    saved = dict(os.environ)
    import servers.api as api_mod
    import servers.execution_api as exec_mod

    patched = ("_authenticate", "_authenticated_principal", "_require_tenant_capability",
               "_enforce_review_approval_role")
    saved_api = {name: getattr(api_mod, name) for name in patched}
    saved_chain = exec_mod._CHAIN
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)
        for name, value in saved_api.items():
            setattr(api_mod, name, value)
        exec_mod._CHAIN = saved_chain
        exec_mod._QUEUES.clear()
        exec_mod._ITEM_TENANT.clear()
        exec_mod._reset_semantic_bundle()
        exec_mod._reset_tool_dispatcher()
        exec_mod._reset_outbox()
        exec_mod._reset_toolspec_bundle()


def build() -> dict[str, Any]:
    seq = signed_sequence()
    limits = _limit_policy(seq)
    runs: dict[str, Any] = {}
    with isolated():
        for name, fn, policy in (("remora_as_shipped", _sequential, None),
                                 ("budget_declared", _sequential, limits),
                                 ("budget_declared_approved_first", _approved_first, limits)):
            with tempfile.TemporaryDirectory() as work:
                result = fn(Path(work), seq, policy)  # type: ignore[operator]
            total = sum(p["amount"] for p in seq["payments"]
                        if p["occurrence_id"] in result["reached_tool"])
            runs[name] = {**result, "total_reached_tool": total,
                          "within_budget": total <= seq["budget"]["max_total"]}
    return {
        "schema": "remora-h55-enforcement-v1",
        "question": "Does REMORA's own engine let payment C run past the signed budget?",
        "classification": "author-run replay of a public sequence through REMORA's execution "
                          "API with a sandboxed tool; not a holdout, not independent",
        "signed_inputs": {"payer": seq["payer"], "budget": seq["budget"],
                          "payments": seq["payments"]},
        "limit_policy": limits,
        "runs": runs,
    }


def render(body: dict[str, Any]) -> bytes:
    return json.dumps(body, indent=1, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    data = render(build())
    if args.json:
        sys.stdout.write(data.decode("utf-8"))
        return 0
    if args.write:
        OUT.write_bytes(data)
        print(json.dumps({"written": OUT.name}))
        return 0
    ok = OUT.is_file() and OUT.read_bytes() == data
    print(json.dumps({"ok": ok, "file": OUT.name}))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

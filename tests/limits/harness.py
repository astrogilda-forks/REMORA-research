# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The execution API with the sandboxed registry and a limit policy."""
from __future__ import annotations

import json
from typing import Any

from remora.toolcall.callable_digest import source_digest
from tests.limits import registry
from tests.test_toolspec_execution_wiring import _bundle_file, _client, _spec

PRINCIPAL = "employee-1"


def _props(**fields: str) -> dict[str, Any]:
    return {"type": "object", "properties": {k: {"type": v} for k, v in fields.items()},
            "required": list(fields), "additionalProperties": False}


def _tool(fn, *, action="write", domain="building_automation", resource="unit",
          **schema: str) -> dict[str, Any]:
    return _spec(
        tool_id=fn.__name__, callable_digest=source_digest(fn),
        description=f"Sandboxed {fn.__name__.replace('_', ' ')}.", risk_tier="medium",
        action_type=action, domain=domain, capabilities=[domain],
        argument_schema=_props(**schema),
        semantic_contract={"capability": domain, "effect": "update" if action != "read"
                           else "read", "resource_type": "equipment",
                           "mutation": action != "read",
                           "argument_roles": {resource: "target_resource"}},
        credential_scope=[f"{domain}:{action}"])


SPECS = [
    _tool(registry.transfer_payment, domain="finance", resource="payee", payee="string",
          amount="integer", unit="string", reference="string"),
    _tool(registry.set_supply_air_setpoint, unit="string", value="number"),
    _tool(registry.start_fan, unit="string"),
    _tool(registry.run_fan_minutes, unit="string", minutes="integer"),
    _tool(registry.reset_controller, unit="string"),
    _tool(registry.read_air_temperature, action="read", unit="string"),
]


def make_client(monkeypatch, tmp_path, policy: dict[str, Any] | None):
    import servers.execution_api as exec_mod

    monkeypatch.setenv("REMORA_LIMITS_TOOL_LOG", str(tmp_path / "tool-log.jsonl"))
    for var in ("REMORA_LIMITS_FILE", "REMORA_LIMITS_LEDGER"):
        monkeypatch.delenv(var, raising=False)
    if policy is not None:
        (tmp_path / "limits.json").write_text(json.dumps(policy))
        monkeypatch.setenv("REMORA_LIMITS_FILE", str(tmp_path / "limits.json"))
        monkeypatch.setenv("REMORA_LIMITS_LEDGER", str(tmp_path / "limits-ledger.db"))
    client = _client(monkeypatch, tmp_path,
                     bundle_path=_bundle_file(tmp_path, SPECS, name="limits-bundle.json"))
    monkeypatch.setenv("REMORA_TOOL_REGISTRY_MODULE", "tests.limits.registry")
    exec_mod._reset_tool_dispatcher()
    registry.FAIL_NEXT.clear()
    return client


def ran(tmp_path) -> list[dict[str, Any]]:
    path = tmp_path / "tool-log.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def call(tool: str, task_id: str = "task-1", **arguments: Any) -> dict[str, Any]:
    return {"tool_name": tool, "arguments": arguments, "target_environment": "prod",
            "schema_valid": True, "context_id": "ctx-1", "task_id": task_id}


def assess(client, c):
    return client.post("/v1/execution/assess", json=c)


def approve_and_execute(client, item_id, c):
    approved = client.post("/v1/execution/approve",
                           json={"item_id": item_id, "approval_ttl_seconds": 600})
    assert approved.status_code == 200, approved.text
    return client.post("/v1/execution/execute", json={"item_id": item_id, "tool_call": c})


def run(client, c) -> dict[str, Any]:
    """Assess, approve and execute one call; what the caller sees."""
    r = assess(client, c)
    if r.status_code != 200:
        return {"stage": "assess", "status": r.status_code, "detail": r.json()["detail"]}
    body = r.json()
    assert body["decision"] == "verify", body  # a write with no evidence goes to review
    e = approve_and_execute(client, body["review_item_id"], c).json()
    execution = e.get("tool_execution") or {}
    return {"stage": "execute", "executed": execution.get("executed"),
            "refusal": execution.get("refusal_reason")}


def refused_at_dispatch(result: dict[str, Any], reason: str) -> bool:
    return result == {"stage": "execute", "executed": False, "refusal": reason}

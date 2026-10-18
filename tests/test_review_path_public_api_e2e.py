# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Review-path attacks driven through the public API only.

Real bearer tokens from ``REMORA_API_TOKENS`` (two operators and an admin in
one tenant), the research tool registry and semantic bundle, and an intent
source file. Nothing here touches the audit chain or the queue directly, and
the admin only approves a call that legitimately decided VERIFY.

- P0-1A: alice proposes ``store_artifact`` under work order ``wo-1``, which
  authorizes creating an artifact (VERIFY), and the admin approves. The work
  order is then reissued as a read. An honest execution would now be refused,
  so alice re-presents the call with ``untrusted_context`` added. On
  b64e3cc1 the taint made the fresh decision VERIFY and the write ran.
- P0-1B: mallory, another operator in the tenant, executes alice's approved
  item under a swapped task. It must be ``context_mismatch`` (#935).
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

TOKENS = {
    "tok-alice": {"tenant": "acme", "role": "operator", "actor_id": "alice"},
    "tok-mallory": {"tenant": "acme", "role": "operator", "actor_id": "mallory"},
    "tok-admin": {"tenant": "acme", "role": "admin", "actor_id": "admin-1"},
}
CREATE_INTENT = {
    "task_text": "Create an artifact named wired-1 with the run summary.",
    "operation": "create",
    "resource_type": "artifact",
    "requested_effect": "create",
    "target_entities": ["target_resource"],
    "source_spans": ["artifact"],
    "action_spans": ["create an artifact"],
}
READ_INTENT = {
    "task_text": "Read the telemetry for asset P-1.",
    "operation": "read",
    "resource_type": "telemetry",
    "requested_effect": "read",
    "target_entities": [],
    "source_spans": ["telemetry"],
    "action_spans": ["read the telemetry"],
}
STORE = {"tool_name": "store_artifact",
         "arguments": {"artifact_id": "wired-1", "content": {"ok": True}},
         "intent_ref": "wo-1"}


class Api:
    def __init__(self, client: TestClient, intents: Path, artifacts: Path) -> None:
        self.client = client
        self.intents = intents
        self.artifacts = artifacts

    def issue(self, intent: dict[str, Any]) -> None:
        self.intents.write_text(json.dumps({"wo-1": intent}), encoding="utf-8")

    def post(self, token: str, path: str, body: dict[str, Any]) -> Any:
        return self.client.post(path, json=body,
                                headers={"Authorization": f"Bearer {token}"})

    def written(self) -> bool:
        return (self.artifacts / "wired-1.json").exists()


@pytest.fixture()
def api(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Api]:
    import servers.api as api_mod
    import servers.execution_api as exec_mod
    from remora.governance.tenant_chain import TenantAuditChain

    intents = tmp_path / "work_orders.json"
    artifacts = tmp_path / "artifacts"
    for key, value in {
        "REMORA_ENV": "development",
        "REMORA_PDP_SIGNING_KEY": "public-api-e2e-key",
        "REMORA_SEMANTIC_BUNDLE_MODULE": "servers.semantic_bundle_research",
        "REMORA_INTENT_SOURCE_FILE": str(intents),
        "REMORA_TOOL_REGISTRY_MODULE": "servers.tool_registry_research",
        "REMORA_EXECUTION_ARTIFACT_DIR": str(artifacts),
        "REMORA_API_TOKENS": json.dumps(TOKENS),
    }.items():
        monkeypatch.setenv(key, value)
    # The token table is read at import, so it is re-read under this
    # environment and restored afterwards; authentication itself is the
    # module's own, unpatched.
    monkeypatch.setattr(api_mod, "_TOKEN_ACTOR_IDS", {})
    monkeypatch.setattr(api_mod, "_TOKEN_TABLE", api_mod._load_token_table())
    # Fresh per-test execution state, restored by monkeypatch.
    monkeypatch.setattr(exec_mod, "_QUEUES", {})
    monkeypatch.setattr(exec_mod, "_ITEM_TENANT", {})
    monkeypatch.setattr(exec_mod, "_CHAIN", TenantAuditChain())
    monkeypatch.setattr(exec_mod, "_GATE", exec_mod.EnforcementGate(
        strict=True, audience=exec_mod.PEP_AUDIENCE))
    exec_mod._reset_tool_dispatcher()
    exec_mod._reset_semantic_bundle()
    api = Api(TestClient(api_mod.app), intents, artifacts)
    api.issue(CREATE_INTENT)
    yield api
    exec_mod._reset_semantic_bundle()
    exec_mod._reset_tool_dispatcher()


def _approved_verify(api: Api, call: dict[str, Any]) -> str:
    assessed = api.post("tok-alice", "/v1/execution/assess", call)
    assert assessed.status_code == 200, assessed.text
    body = assessed.json()
    assert body["decision"] == "verify", body
    assert body["semantic"]["tool_matches_goal"] is True, body
    approved = api.post("tok-admin", "/v1/execution/approve",
                        {"item_id": body["review_item_id"]})
    assert approved.status_code == 200, approved.text
    return str(body["review_item_id"])


def test_p0_1a_taint_added_at_execute_does_not_launder_a_reissued_work_order(
        api: Api) -> None:
    item_id = _approved_verify(api, STORE)
    api.issue(READ_INTENT)  # the work order now authorizes a read only
    r = api.post("tok-alice", "/v1/execution/execute", {
        "item_id": item_id,
        "tool_call": {**STORE, "untrusted_context": "v"},
    })
    assert not api.written(), r.text
    assert r.status_code == 409, r.text
    assert r.json()["detail"] in ("context_mismatch", "binding_refused")


def test_p0_1a_control_the_unchanged_work_order_executes(api: Api) -> None:
    item_id = _approved_verify(api, STORE)
    r = api.post("tok-alice", "/v1/execution/execute",
                 {"item_id": item_id, "tool_call": STORE})
    assert r.status_code == 200, r.text
    assert api.written()


def test_p0_1b_another_operator_with_a_swapped_task_is_refused(api: Api) -> None:
    item_id = _approved_verify(api, {**STORE, "context_id": "ctx-alice",
                                     "task_id": "task-1"})
    r = api.post("tok-mallory", "/v1/execution/execute", {
        "item_id": item_id,
        "tool_call": {**STORE, "context_id": "ctx-mallory", "task_id": "task-9"},
    })
    assert not api.written(), r.text
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == "context_mismatch"
    # Not consumed: alice still executes the item she was approved for.
    ok = api.post("tok-alice", "/v1/execution/execute", {
        "item_id": item_id,
        "tool_call": {**STORE, "context_id": "ctx-alice", "task_id": "task-1"},
    })
    assert ok.status_code == 200, ok.text
    assert api.written()

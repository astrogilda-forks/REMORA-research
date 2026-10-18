# SPDX-License-Identifier: BUSL-1.1
"""IFC-02b: ``POST /v1/contexts`` mints flow contexts (SDD v1.3 §3.2, §5.2)."""
from __future__ import annotations

import json
import re

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from remora.governance.tenant_chain import TenantAuditChain  # noqa: E402

MODEL = "ext://api.provider.example"


def _mod():
    import servers.execution_api as exec_mod

    return exec_mod


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("REMORA_PDP_SIGNING_KEY", "contexts-route-key")
    monkeypatch.setenv("REMORA_ENV", "development")
    monkeypatch.setenv("REMORA_TOOL_REGISTRY_MODULE", "servers.tool_registry_research")
    monkeypatch.setenv("REMORA_FLOW_CONTROL", "1")
    for var in ("REMORA_PG_DSN", "REMORA_CHAIN_DB", "REMORA_STATE_ENDPOINT"):
        monkeypatch.delenv(var, raising=False)
    policy = tmp_path / "processing.json"
    policy.write_text(json.dumps({"acme": {"default": [MODEL]}}), encoding="utf-8")
    monkeypatch.setenv("REMORA_FLOW_PROCESSING_POLICY", str(policy))
    import servers.api as api_mod

    exec_mod = _mod()
    monkeypatch.setattr(api_mod, "_authenticate", lambda request: ("acme", "operator"))
    monkeypatch.setattr(api_mod, "_authenticated_principal", lambda request: "agent-1")
    monkeypatch.setattr(api_mod, "_require_tenant_capability", lambda role, tenant, cap: None)
    monkeypatch.setattr(exec_mod, "_CHAIN", TenantAuditChain())
    monkeypatch.setattr(exec_mod, "_FLOW_CONTEXTS", None)
    return TestClient(api_mod.app)


def _mint(client, **body):
    payload = {"user_principal": "user://acme/alice", "model_principal": MODEL, **body}
    return client.post("/v1/contexts", json=payload)


def test_a_context_is_minted_and_chained(client):
    r = _mint(client)
    assert r.status_code == 200, r.text
    body = r.json()
    assert re.fullmatch(r"ctx_[a-z2-7]{26}", body["context_id"])
    assert body["label_epoch"] == 0
    entry = _mod()._CHAIN.entries("acme")[-1].payload
    assert entry["event"] == "flow_context_minted"
    assert entry["context_id"] == body["context_id"]
    assert entry["principal"] == "agent-1"
    assert entry["processors"] == [MODEL]


def test_a_child_inherits_from_its_parent(client):
    parent = _mint(client).json()["context_id"]
    r = _mint(client, parent_context_id=parent)
    assert r.status_code == 200, r.text
    child = _mod()._flow_contexts().load("acme", "agent-1", r.json()["context_id"])
    assert child.root_context_id == parent and child.parent_context_id == parent


def test_an_unknown_parent_is_a_404(client):
    r = _mint(client, parent_context_id="ctx_" + "a" * 26)
    assert r.status_code == 404 and r.json()["detail"] == "flow_context_unknown"


def test_a_user_of_another_tenant_is_a_403(client):
    r = _mint(client, user_principal="user://other/alice")
    assert r.status_code == 403 and r.json()["detail"] == "principal_mismatch"


def test_an_unauthorized_processor_is_a_403(client):
    r = _mint(client, model_principal="ext://other-provider.example")
    assert r.status_code == 403 and r.json()["detail"] == "processing_not_authorized"
    r = _mint(client, q_principal="ext://other-provider.example")
    assert r.status_code == 403


def test_a_missing_model_principal_is_a_422(client):
    r = client.post("/v1/contexts", json={"user_principal": "user://acme/alice"})
    assert r.status_code == 422


def test_a_non_canonical_principal_is_a_422(client):
    assert _mint(client, user_principal="mailto:alice@acme.example").status_code == 422
    assert _mint(client, model_principal="ext://Evil Host").status_code == 422


def test_the_caller_cannot_choose_an_id_a_label_or_an_epoch(client):
    for extra in ({"context_id": "ctx_mine"}, {"label": {"readers": "PUBLIC"}},
                  {"label_epoch": 7}):
        assert _mint(client, **extra).status_code == 422


def test_it_is_refused_when_flow_control_is_off(client, monkeypatch):
    monkeypatch.delenv("REMORA_FLOW_CONTROL", raising=False)
    r = _mint(client)
    assert r.status_code == 409 and r.json()["detail"] == "flow_control_disabled"


def test_without_a_processing_policy_nothing_is_authorized(client, monkeypatch):
    monkeypatch.delenv("REMORA_FLOW_PROCESSING_POLICY", raising=False)
    monkeypatch.setattr(_mod(), "_FLOW_CONTEXTS", None)
    assert _mint(client).status_code == 403


def test_an_unreachable_store_is_a_503(client, monkeypatch, tmp_path):
    monkeypatch.setenv("REMORA_CHAIN_DB", str(tmp_path / "missing" / "chain.db"))
    monkeypatch.setattr(_mod(), "_FLOW_CONTEXTS", None)
    r = _mint(client)
    assert r.status_code == 503 and r.json()["detail"] == "flow_state_unavailable"


def test_the_route_is_in_the_committed_contract():
    from pathlib import Path

    spec = json.loads((Path(__file__).resolve().parents[2] / "schemas" / "openapi.json")
                      .read_text(encoding="utf-8"))
    op = spec["paths"]["/v1/contexts"]["post"]
    assert {"200", "403", "404", "409", "422", "503"} <= set(op["responses"])

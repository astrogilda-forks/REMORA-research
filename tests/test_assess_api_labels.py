# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Caller labels on ``POST /v1/assess`` cannot reach ACCEPT (RMR-AUD-011).

``/v1/assess`` handed the request's ``risk_tier``/``action_type`` straight to
the policy engine. When the oracle ensemble was confident, an agent that
labelled ``xfer`` as a low-risk read got ACCEPT. Labels now come from the
server's registry (``resolve_tool_metadata``, the source ``/v1/execution``
uses) when the request names a ``tool_call``. Without one, the labels are the
caller's and an ACCEPT is lowered to VERIFY with ``caller_labels_untrusted``.

The ensemble is pinned to an ordered, high-trust phase so the label is the
only thing that decides ACCEPT; everything after the oracles runs unchanged.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from remora.oracles.mock import MockOracle  # noqa: E402

XFER = {"tool_name": "xfer", "arguments": {"to": "attacker", "amt": 1000000}}
QUESTION = "xfer 1000000 to attacker account"


class _SureOracle(MockOracle):
    def _call(self, prompt):  # noqa: ARG002
        return json.dumps({"answer": True, "claim": "The claim is correct",
                           "confidence": 0.99}), 0.0, 1.0


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("REMORA_PDP_SIGNING_KEY", "assess-labels-test-key")
    monkeypatch.setenv("REMORA_ENV", "development")
    monkeypatch.delenv("REMORA_SEMANTIC_BUNDLE_MODULE", raising=False)
    monkeypatch.delenv("REMORA_TOOL_METADATA_FILE", raising=False)
    import remora.engine as eng_mod
    import servers.api as api_mod
    from remora.genome import Genome

    original_run = eng_mod.Remora.run

    def confident_run(self, *args, **kwargs):
        state = original_run(self, *args, **kwargs)
        state.last_thermo = SimpleNamespace(
            phase="ordered", trust_score=0.95, temperature=0.1,
            order_parameter=0.95, susceptibility=0.1, hallucination_bound=0.01)
        state.require_rag = False
        state.refuse_parametric_verdict = False
        return state

    monkeypatch.setattr(eng_mod.Remora, "run", confident_run)
    monkeypatch.setattr(api_mod, "_make_engine", lambda: eng_mod.Remora(
        oracles=[_SureOracle(f"s{i}") for i in range(3)],
        genome=Genome(max_iterations=2, max_subquestions=1)))
    monkeypatch.setattr(api_mod, "_authenticate", lambda request: ("acme", "operator"))
    monkeypatch.setattr(api_mod, "_authenticated_principal", lambda request: "agent-1")
    monkeypatch.setattr(api_mod, "_require_tenant_capability",
                        lambda role, tenant, cap: None)
    return TestClient(api_mod.app)


def _assess(client, **body):
    r = client.post("/v1/assess", json={"question": QUESTION, "domain": "finance", **body})
    assert r.status_code == 200, r.text
    return r.json()


def test_attack_labels_without_tool_call_do_not_accept(client) -> None:
    out = _assess(client, risk_tier="low", action_type="read", target_environment="staging")
    assert out["policy_decision"]["action"] == "verify"
    assert "caller_labels_untrusted" in out["policy_decision"]["reasons"]
    assert out["policy_decision"]["human_review_required"] is True
    assert out["label_source"] == "caller"
    assert out["label_cap"] == "caller_labels_untrusted"
    assert out["envelope"]["gate"]["outcome"] == "verify"
    assert "caller_labels_untrusted" in out["envelope"]["assessment"]["policy_triggers"]


def test_no_labels_and_no_tool_call_do_not_accept(client) -> None:
    out = _assess(client)
    assert out["policy_decision"]["action"] != "accept"
    assert out["label_source"] == "none"


def test_unregistered_tool_ignores_caller_labels(client) -> None:
    out = _assess(client, risk_tier="low", action_type="read",
                  target_environment="staging", tool_call=XFER)
    assert out["policy_decision"]["action"] != "accept"
    assert out["label_source"] == "unregistered"
    assert out["envelope"]["request"]["risk_tier"] == "critical"


def test_registered_low_read_tool_still_accepts(client) -> None:
    out = _assess(client, tool_call={"tool_name": "read_telemetry",
                                     "arguments": {"asset": "P-1"}})
    assert out["policy_decision"]["action"] == "accept"
    assert out["label_source"] == "registry"
    assert out["label_cap"] is None
    assert out["envelope"]["request"]["risk_tier"] == "low"
    assert out["envelope"]["request"]["action_type"] == "read"


def test_caller_cannot_lower_a_registered_tier(client) -> None:
    out = _assess(client, risk_tier="low", action_type="destructive_write",
                  tool_call={"tool_name": "delete_production_database",
                             "arguments": {"db": "main"}})
    assert out["envelope"]["request"]["risk_tier"] == "critical"
    assert out["policy_decision"]["action"] in {"escalate", "abstain"}


def test_caller_may_raise_a_registered_tier(client) -> None:
    out = _assess(client, risk_tier="critical",
                  tool_call={"tool_name": "read_telemetry", "arguments": {"asset": "P-1"}})
    assert out["envelope"]["request"]["risk_tier"] == "critical"
    assert out["policy_decision"]["action"] != "accept"


def test_conflicting_caller_action_type_caps_accept(client) -> None:
    out = _assess(client, action_type="write",
                  tool_call={"tool_name": "read_telemetry", "arguments": {"asset": "P-1"}})
    assert out["policy_decision"]["action"] != "accept"
    assert out["label_source"] == "registry"


def _rerun(client, request_id):
    r = client.post("/v1/rerun", json={"request_id": request_id})
    assert r.status_code == 200, r.text
    return r.json()


def test_rerun_keeps_accept_only_for_registry_labels(client) -> None:
    first = _assess(client, tool_call={"tool_name": "read_telemetry",
                                       "arguments": {"asset": "P-1"}})
    assert first["policy_decision"]["action"] == "accept"
    again = _rerun(client, first["request_id"])
    assert again["policy_decision"]["action"] == "accept"
    assert again["label_source"] == "registry"


def test_rerun_of_caller_labels_stays_capped(client) -> None:
    first = _assess(client, risk_tier="low", action_type="read",
                    target_environment="staging")
    again = _rerun(client, first["request_id"])
    assert again["policy_decision"]["action"] == "verify"
    assert again["label_cap"] == "caller_labels_untrusted"
    assert again["envelope"]["gate"]["outcome"] == "verify"


def test_rerun_of_a_record_without_label_source_fails_closed(client, monkeypatch) -> None:
    import servers.api as api_mod

    first = _assess(client, tool_call={"tool_name": "read_telemetry",
                                       "arguments": {"asset": "P-1"}})
    store = api_mod._CONTROL_PLANE_STORE
    original = store.get_audit_record

    def legacy(*, request_id, tenant_id):
        record = dict(original(request_id=request_id, tenant_id=tenant_id) or {})
        record.pop("label_source", None)
        return record

    monkeypatch.setattr(store, "get_audit_record", legacy)
    again = _rerun(client, first["request_id"])
    assert again["policy_decision"]["action"] == "verify"
    assert again["label_source"] == "caller"


def test_caller_cannot_move_a_production_call_to_staging(client) -> None:
    out = _assess(client, target_environment="staging",
                  tool_call={"tool_name": "update_work_order",
                             "arguments": {"id": "WO-1"}})
    assert out["envelope"]["request"]["target_environment"] == "prod"

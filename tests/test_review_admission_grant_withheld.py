# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""A refused admission on the review path hands back no redeemable grant.

Under ``REMORA_WS1_ADMISSION=atomic`` the review path mints the ACCEPT grant
before the admission transaction. A refusal rolled the spend back, and the
response carried the grant unspent: a signed, five-minute ACCEPT for the
proposal that ``/execute-accepted`` would redeem with none of the review
path's checks (approver, approval policy, queue state). Found by the
2026-10-24 execution-path audit. The grant is now spent in place and left
out of the response; the chain records it as withheld.
"""
from __future__ import annotations

import sqlite3

import pytest

pytest.importorskip("fastapi")

from remora.enforcement.gate import EnforcementGate  # noqa: E402
from tests.test_toolspec_execution_wiring import CALL, _bundle_file, _client  # noqa: E402

PROPOSER = "employee-1"
APPROVER = "approver-1"


def _mod():
    import servers.execution_api as exec_mod

    return exec_mod


def _as_principal(monkeypatch, name):
    import servers.api as api_mod

    monkeypatch.setattr(api_mod, "_authenticated_principal", lambda request: name)


def _events(name):
    return [e.payload for e in _mod()._CHAIN.entries("acme") if e.payload.get("event") == name]


@pytest.fixture()
def client(monkeypatch, tmp_path):
    c = _client(monkeypatch, tmp_path, bundle_path=_bundle_file(tmp_path))
    exec_mod = _mod()
    db = str(tmp_path / "state.db")
    for name in ("REMORA_PG_DSN", "REMORA_STATE_ENDPOINT", "REMORA_WS1_MODE",
                 "REMORA_ASYNC_DISPATCH"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("REMORA_CHAIN_DB", db)
    monkeypatch.setenv("REMORA_WS1_ADMISSION", "atomic")
    monkeypatch.setenv("REMORA_MAX_CLOCK_SKEW_MS", "1000")
    monkeypatch.setattr(exec_mod, "_GATE", EnforcementGate(
        strict=True, audience=exec_mod.PEP_AUDIENCE, db_path=db))
    monkeypatch.setattr(exec_mod, "_ADMISSION", None)
    exec_mod._reset_outbox()
    yield c, db
    exec_mod._reset_outbox()


def _approved_item(client, monkeypatch) -> str:
    _as_principal(monkeypatch, PROPOSER)
    body = client.post("/v1/execution/assess", json=CALL).json()
    item_id = body["review_item_id"]
    _as_principal(monkeypatch, APPROVER)
    r = client.post("/v1/execution/approve", json={"item_id": item_id})
    assert r.status_code == 200, r.text
    _as_principal(monkeypatch, PROPOSER)
    return item_id


def _revoke_approver_before_admission(monkeypatch):
    """The INV-M4-02 window: the approver is revoked after the queue's own
    re-gate committed and before the admission transaction opens."""
    exec_mod = _mod()
    admission = exec_mod._admission()
    real = admission.admit
    fired: list[bool] = []

    def late(tenant, **kwargs):
        if not fired:
            fired.append(True)
            with exec_mod.db_transaction_state(tenant) as q:
                q.revoke_principal(APPROVER, reason="credential compromised")
        return real(tenant, **kwargs)

    monkeypatch.setattr(admission, "admit", late)


def _jti_spent(db: str, jti: str) -> bool:
    conn = sqlite3.connect(db)
    try:
        return conn.execute("SELECT 1 FROM pep_consumed WHERE jti=?", (jti,)).fetchone() is not None
    finally:
        conn.close()


def test_a_refused_admission_returns_no_grant_and_spends_the_minted_one(client, monkeypatch):
    c, db = client
    item_id = _approved_item(c, monkeypatch)
    _revoke_approver_before_admission(monkeypatch)
    r = c.post("/v1/execution/execute", json={"item_id": item_id, "tool_call": CALL})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tool_execution"]["refusal_reason"] == "principal_revoked"
    assert "execution_grant" not in body
    withheld = _events("execution_grant_withheld")[-1]
    assert withheld["spent"] is True and withheld["detail"] == "principal_revoked"
    assert _jti_spent(db, withheld["grant_jti"])
    assert not _events("execution_authorized")


def test_a_transient_admission_fault_also_returns_no_grant(client, monkeypatch):
    """No revocation: the audit outbox insert fails once, the admission rolls
    back, and the response still carries no grant."""
    from remora.execution import admission as admission_mod

    c, db = client
    item_id = _approved_item(c, monkeypatch)
    real_enqueue = admission_mod.audit_outbox.enqueue
    calls: list[int] = []

    def flaky(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("audit outbox insert failed once")
        return real_enqueue(*args, **kwargs)

    monkeypatch.setattr(admission_mod.audit_outbox, "enqueue", flaky)
    body = c.post("/v1/execution/execute", json={"item_id": item_id, "tool_call": CALL}).json()
    assert body["tool_execution"]["refusal_reason"] == "audit_outbox_unavailable"
    assert "execution_grant" not in body
    assert _jti_spent(db, _events("execution_grant_withheld")[-1]["grant_jti"])


def test_an_admitted_execution_still_returns_its_grant(client, monkeypatch):
    c, _db = client
    item_id = _approved_item(c, monkeypatch)
    body = c.post("/v1/execution/execute", json={"item_id": item_id, "tool_call": CALL}).json()
    assert body["tool_execution"]["executed"] is True
    assert body["execution_grant"]["jti"]
    assert not _events("execution_grant_withheld")

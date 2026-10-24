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

Every test runs on SQLite and, with ``REMORA_PG_DSN`` set, on Postgres in a
schema of its own (SDD unified capability execution v1.1, P0 item 5: the §98
repair re-verified on the reference backend, and when the ledger or the
storage fails). The Postgres cases carry "postgres" in their id, so the
``postgres-contract`` CI job selects them and fails on a skip.
"""
from __future__ import annotations

import os
import sqlite3
import uuid
from contextlib import contextmanager

import pytest

pytest.importorskip("fastapi")

from remora.enforcement.gate import EnforcementGate  # noqa: E402
from tests.test_toolspec_execution_wiring import CALL, _bundle_file, _client  # noqa: E402

PROPOSER = "employee-1"
APPROVER = "approver-1"
BASE_DSN = os.environ.get("REMORA_PG_DSN", "")


def _mod():
    import servers.execution_api as exec_mod

    return exec_mod


def _as_principal(monkeypatch, name):
    import servers.api as api_mod

    monkeypatch.setattr(api_mod, "_authenticated_principal", lambda request: name)


def _events(name):
    return [e.payload for e in _mod()._CHAIN.entries("acme") if e.payload.get("event") == name]


@pytest.fixture(params=["sqlite", pytest.param("postgres", marks=pytest.mark.skipif(
    not BASE_DSN, reason="REMORA_PG_DSN not set"))])
def client(request, monkeypatch, tmp_path):
    """The route client over one state backend: ``(client, consumed)`` where
    ``consumed(jti)`` reads the durable consumed-grant set of that backend."""
    c = _client(monkeypatch, tmp_path, bundle_path=_bundle_file(tmp_path))
    exec_mod = _mod()
    for name in ("REMORA_PG_DSN", "REMORA_STATE_ENDPOINT", "REMORA_WS1_MODE",
                 "REMORA_ASYNC_DISPATCH", "REMORA_CHAIN_DB"):
        monkeypatch.delenv(name, raising=False)
    schema = ""
    if request.param == "postgres":
        psycopg = pytest.importorskip("psycopg")
        from psycopg import conninfo

        schema = f"review_{uuid.uuid4().hex[:12]}"
        with psycopg.connect(BASE_DSN) as conn:
            conn.execute(f"CREATE SCHEMA {schema}")
            conn.commit()
        dsn = conninfo.make_conninfo(BASE_DSN, options=f"-c search_path={schema}")
        monkeypatch.setenv("REMORA_PG_DSN", dsn)
        gate = EnforcementGate(strict=True, audience=exec_mod.PEP_AUDIENCE, dsn=dsn)

        def consumed(jti: str) -> bool:
            with psycopg.connect(dsn) as conn:
                return conn.execute("SELECT 1 FROM pep_consumed WHERE jti=%s",
                                    (jti,)).fetchone() is not None
    else:
        db = str(tmp_path / "state.db")
        monkeypatch.setenv("REMORA_CHAIN_DB", db)
        gate = EnforcementGate(strict=True, audience=exec_mod.PEP_AUDIENCE, db_path=db)

        def consumed(jti: str) -> bool:
            conn = sqlite3.connect(db)
            try:
                return conn.execute("SELECT 1 FROM pep_consumed WHERE jti=?",
                                    (jti,)).fetchone() is not None
            finally:
                conn.close()
    monkeypatch.setenv("REMORA_WS1_ADMISSION", "atomic")
    monkeypatch.setenv("REMORA_MAX_CLOCK_SKEW_MS", "1000")
    monkeypatch.setattr(exec_mod, "_GATE", gate)
    monkeypatch.setattr(exec_mod, "_ADMISSION", None)
    exec_mod._reset_outbox()
    yield c, consumed
    exec_mod._reset_outbox()
    if schema:
        with psycopg.connect(BASE_DSN) as conn:
            conn.execute(f"DROP SCHEMA {schema} CASCADE")
            conn.commit()


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


def _once(monkeypatch, owner, name, replacement):
    """Replace ``owner.name`` so that ``replacement`` runs for the first call
    only and the original for every later one."""
    real = getattr(owner, name)
    fired: list[bool] = []

    def first(*args, **kwargs):
        if not fired:
            fired.append(True)
            return replacement(real, *args, **kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(owner, name, first)


def test_a_refused_admission_returns_no_grant_and_spends_the_minted_one(client, monkeypatch):
    c, consumed = client
    item_id = _approved_item(c, monkeypatch)
    _revoke_approver_before_admission(monkeypatch)
    r = c.post("/v1/execution/execute", json={"item_id": item_id, "tool_call": CALL})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tool_execution"]["refusal_reason"] == "principal_revoked"
    assert "execution_grant" not in body
    withheld = _events("execution_grant_withheld")[-1]
    assert withheld["spent"] is True and withheld["detail"] == "principal_revoked"
    assert consumed(withheld["grant_jti"])
    assert not _events("execution_authorized")


def test_a_transient_admission_fault_also_returns_no_grant(client, monkeypatch):
    """No revocation: the audit outbox insert fails once, the admission rolls
    back, and the response still carries no grant."""
    from remora.execution import admission as admission_mod

    c, consumed = client
    item_id = _approved_item(c, monkeypatch)

    def failing_insert(real, *args, **kwargs):
        raise RuntimeError("audit outbox insert failed once")

    _once(monkeypatch, admission_mod.audit_outbox, "enqueue", failing_insert)
    body = c.post("/v1/execution/execute", json={"item_id": item_id, "tool_call": CALL}).json()
    assert body["tool_execution"]["refusal_reason"] == "audit_outbox_unavailable"
    assert "execution_grant" not in body
    assert consumed(_events("execution_grant_withheld")[-1]["grant_jti"])


def test_a_ledger_that_cannot_spend_the_grant_still_withholds_it(client, monkeypatch):
    """The admission refuses, and then the consumed-grant ledger fails on the
    spend that withholds the grant. The response still carries no grant, and
    the chain says the grant was withheld unspent, so an operator can see the
    jti that is live in nobody's hands until it expires."""
    c, consumed = client
    exec_mod = _mod()
    item_id = _approved_item(c, monkeypatch)
    _revoke_approver_before_admission(monkeypatch)
    real_check = exec_mod._GATE.check

    def check(token, *args, **kwargs):
        if kwargs.get("consume") and kwargs.get("connection") is None:
            raise RuntimeError("consumed-grant ledger unavailable")
        return real_check(token, *args, **kwargs)

    monkeypatch.setattr(exec_mod._GATE, "check", check)
    r = c.post("/v1/execution/execute", json={"item_id": item_id, "tool_call": CALL})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tool_execution"]["refusal_reason"] == "principal_revoked"
    assert "execution_grant" not in body
    withheld = _events("execution_grant_withheld")[-1]
    assert withheld["spent"] is False and withheld["detail"] == "principal_revoked"
    assert not consumed(withheld["grant_jti"])
    assert not _events("execution_authorized")


def test_a_storage_fault_inside_the_admission_returns_no_grant(client, monkeypatch):
    """The admission transaction itself fails at commit (a driver error, not
    a refusal the admission named). Before this slice the route answered 500
    and recorded nothing; the grant was unspent and unreturned. Now the fault
    is a refusal: recorded, the grant spent and withheld, the item settled."""
    c, consumed = client
    exec_mod = _mod()
    item_id = _approved_item(c, monkeypatch)
    admission = exec_mod._admission()

    @contextmanager
    def lost_at_commit(real, tenant):
        with real(tenant) as queue:
            yield queue
            raise RuntimeError("connection lost at commit")

    _once(monkeypatch, admission, "_transaction",
          lambda real, tenant: lost_at_commit(real, tenant))
    r = c.post("/v1/execution/execute", json={"item_id": item_id, "tool_call": CALL})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tool_execution"]["executed"] is False
    assert body["tool_execution"]["refusal_reason"] == "admission_storage_unavailable"
    assert "execution_grant" not in body
    refused = _events("execution_admission_refused")[-1]
    withheld = _events("execution_grant_withheld")[-1]
    assert refused["detail"] == withheld["detail"] == "admission_storage_unavailable"
    assert withheld["spent"] is True and consumed(withheld["grant_jti"])
    assert not _events("execution_authorized")
    assert not _events("execution_admitted")


def test_an_admitted_execution_still_returns_its_grant(client, monkeypatch):
    c, _consumed = client
    item_id = _approved_item(c, monkeypatch)
    body = c.post("/v1/execution/execute", json={"item_id": item_id, "tool_call": CALL}).json()
    assert body["tool_execution"]["executed"] is True
    assert body["execution_grant"]["jti"]
    assert not _events("execution_grant_withheld")

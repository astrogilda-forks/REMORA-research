# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1-M4 atomic admission on ``/v1/execution/execute-accepted`` (M4.1c).

The same WS1 deployment, grant and dispatcher as the gate controls in
``tests/test_ws1_gate_controls.py``, with ``REMORA_WS1_ADMISSION=atomic`` over
SQLite. Control 2b there pins the residual of the legacy path: evidence that
lapses after the re-gate still runs. Here the same lapse refuses (M4-T02),
and a revoked evidence source refuses (M4-T03/T04), each before the grant is
spent: a later redemption of the same grant runs once the cause is undone.
"""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from remora.enforcement.gate import EnforcementGate  # noqa: E402
from remora.execution import admission as admission_mod  # noqa: E402
from tests.test_ws1_execution_binding import (  # noqa: E402
    _events,
    _install,
    _mint,
    _mod,
    _redeem,
)
from tests.test_ws1_execution_binding import client as _route_client  # noqa: E402,F401

SOURCE = "source:asset-inventory"


@pytest.fixture()
def client(_route_client, monkeypatch, tmp_path):  # noqa: F811
    exec_mod = _mod()
    db = str(tmp_path / "state.db")
    for name in ("REMORA_PG_DSN", "REMORA_STATE_ENDPOINT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("REMORA_CHAIN_DB", db)
    monkeypatch.setenv("REMORA_WS1_ADMISSION", "atomic")
    monkeypatch.setenv("REMORA_MAX_CLOCK_SKEW_MS", "1000")
    monkeypatch.setattr(exec_mod, "_GATE", EnforcementGate(
        strict=True, audience=exec_mod.PEP_AUDIENCE, db_path=db))
    monkeypatch.setattr(exec_mod, "_ADMISSION", None)
    exec_mod._reset_outbox()
    yield _route_client
    exec_mod._reset_outbox()


def _try(client, token):
    r = _redeem(client, token)
    body = r.json()
    return r.status_code, body.get("detail"), bool(body.get("tool_execution", {}).get("executed"))


def test_an_atomic_redemption_executes_and_records_its_admission(client, monkeypatch):
    gate = _install(monkeypatch, "enforce")
    status, _, executed = _try(client, _mint(gate))
    assert (status, executed) == (200, True)
    authorized = _events("execution_authorized")[-1]
    assert authorized["admission"]["mode"] == "atomic"
    assert authorized["admission"]["authority_epochs"] == {
        SOURCE: {"epoch": 0, "revoked": False}}


def test_m4_t02_evidence_lapsing_after_the_regate_refuses_unspent(client, monkeypatch):
    """Control 2b under atomic admission: the database instant moves past
    the evidence's valid_until after the re-gate and before the spend."""
    gate = _install(monkeypatch, "enforce")
    token = _mint(gate)
    real = admission_mod.db_now_ms
    monkeypatch.setattr(admission_mod, "db_now_ms",
                        lambda conn, dialect: real(conn, dialect) + 120_000)
    assert _try(client, token) == (409, "evidence_expired_at_admission", False)
    assert not _events("execution_authorized")
    assert _events("execution_admission_refused")[-1]["detail"] == "evidence_expired_at_admission"
    monkeypatch.setattr(admission_mod, "db_now_ms", real)
    assert _try(client, token)[2] is True  # the grant was never spent


def test_m4_t03_a_revoked_evidence_source_refuses_unspent(client, monkeypatch):
    gate = _install(monkeypatch, "enforce")
    token = _mint(gate)
    admission = _mod()._admission()
    admission.advance_authority("acme", SOURCE, revoked=True)
    assert _try(client, token) == (409, "authority_revoked", False)
    assert not _events("execution_authorized")
    admission.advance_authority("acme", SOURCE, revoked=False)
    assert _try(client, token)[2] is True


def test_m4_t04_a_source_revision_during_the_lookups_refuses(client, monkeypatch):
    """The source's epoch advances after the re-gate pinned it, before the
    lookups finish: the receipts carry the older epoch."""
    gate = _install(monkeypatch, "enforce")
    token = _mint(gate)
    admission = _mod()._admission()
    real_pin = admission.pin_epochs

    def pin_then_revise(tenant):
        read = real_pin(tenant)

        def pinned(subjects):
            out = read(subjects)
            admission.advance_authority(tenant, SOURCE, revoked=False)
            return out
        return pinned

    monkeypatch.setattr(admission, "pin_epochs", pin_then_revise)
    assert _try(client, token) == (409, "authority_epoch_stale", False)
    monkeypatch.setattr(admission, "pin_epochs", real_pin)
    assert _try(client, token)[2] is True


@pytest.mark.parametrize("env,unset", [
    ({"REMORA_WS1_ADMISSION": "bogus"}, ()),
    ({}, ("REMORA_MAX_CLOCK_SKEW_MS",)),
    ({"REMORA_MAX_CLOCK_SKEW_MS": "ten"}, ()),
    ({"REMORA_MAX_CLOCK_SKEW_MS": "5001"}, ()),
    ({"REMORA_STATE_ENDPOINT": "https://d1.example"}, ()),
    ({}, ("REMORA_CHAIN_DB",)),
])
def test_atomic_admission_refuses_to_start_without_its_prerequisites(
        client, monkeypatch, env, unset):
    for name in unset:
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        _mod()._admission()


def test_legacy_admission_is_the_default(client, monkeypatch):
    monkeypatch.delenv("REMORA_WS1_ADMISSION", raising=False)
    assert _mod()._admission() is None


# ── the approved-review path and the async worker ─────────────────────────


def _approved(client, monkeypatch):
    from tests.test_ws1_execution_binding import _as_role, _assess_write, _review_deployment

    _install(monkeypatch, "enforce", **_review_deployment())
    item_id = _assess_write(client)["review_item_id"]
    _as_role(monkeypatch, "change-manager")
    assert client.post("/v1/execution/approve", json={"item_id": item_id}).status_code == 200
    return item_id


def _execute(client, item_id):
    from tests.test_ws1_execution_binding import WRITE_CALL

    r = client.post("/v1/execution/execute", json={"item_id": item_id, "tool_call": WRITE_CALL})
    assert r.status_code in (200, 202), r.text
    return r.json()


def _row_state(item_id):
    rows = [r for r in _mod()._outbox().pending("acme")] + [
        r for p in {e["proposal_id"] for e in _events("assessed")}
        for r in _mod()._outbox().rows_for_proposal("acme", p)]
    return {r.state.value for r in rows if r.item_id == item_id}


def test_an_approved_review_is_admitted_atomically(client, monkeypatch):
    """The WS1 REVIEW precondition is closed by the approval and carries no
    receipt; the MACHINE one is re-checked at admission."""
    body = _execute(client, _approved(client, monkeypatch))
    assert body["tool_execution"]["executed"] is True
    authorized = _events("execution_authorized")[-1]
    assert authorized["admission"]["authority_epochs"] == {
        SOURCE: {"epoch": 0, "revoked": False}}


@pytest.mark.parametrize("cause", ["lapse", "revocation"])
def test_review_admission_refuses_and_settles_without_dispatch(client, monkeypatch, cause):
    item_id = _approved(client, monkeypatch)
    expected = "evidence_expired_at_admission"
    if cause == "lapse":
        real = admission_mod.db_now_ms
        monkeypatch.setattr(admission_mod, "db_now_ms",
                            lambda conn, dialect: real(conn, dialect) + 120_000)
    else:
        _mod()._admission().advance_authority("acme", SOURCE, revoked=True)
        expected = "authority_revoked"
    body = _execute(client, item_id)
    assert body["tool_execution"] == {"executed": False, "dispatch_began": False,
                                      "state_unknown": False, "refusal_reason": expected}
    assert not _events("execution_authorized")
    assert _events("execution_admission_refused")[-1]["detail"] == expected
    grant = _mod().PolicyDecisionToken.from_dict(body["execution_grant"])
    assert _mod()._GATE.check(grant, consume=False).reason != "token_already_consumed"
    assert _row_state(item_id) == {"REFUSED"}


def test_the_worker_admits_atomically(client, monkeypatch):
    monkeypatch.setenv("REMORA_ASYNC_DISPATCH", "1")
    item_id = _approved(client, monkeypatch)
    assert _execute(client, item_id).get("dispatch") == "pending"
    results = _mod().dispatch_pending_intents("acme", worker_id="w-1")
    assert [r["tool_execution"]["executed"] for r in results] == [True]
    assert _events("execution_authorized")[-1]["admission"]["mode"] == "atomic"


def test_the_worker_refuses_a_revoked_source_and_settles_the_row(client, monkeypatch):
    monkeypatch.setenv("REMORA_ASYNC_DISPATCH", "1")
    item_id = _approved(client, monkeypatch)
    _execute(client, item_id)
    _mod()._admission().advance_authority("acme", SOURCE, revoked=True)
    results = _mod().dispatch_pending_intents("acme", worker_id="w-1")
    assert [r["tool_execution"]["refusal_reason"] for r in results] == ["authority_revoked"]
    assert not _events("execution_authorized")
    assert _row_state(item_id) == {"REFUSED"}
    # Settled: a second pass finds nothing to dispatch.
    assert _mod().dispatch_pending_intents("acme", worker_id="w-2") == []


# ── principal revocation and the epoch writer route (slice 2b) ────────────


def _as_principal(monkeypatch, name):
    import servers.api as api_mod

    monkeypatch.setattr(api_mod, "_authenticated_principal", lambda request: name)


def test_m4_t03_a_principal_revoked_after_the_grant_refuses_unspent(client, monkeypatch):
    gate = _install(monkeypatch, "enforce")
    token = _mint(gate)
    _as_principal(monkeypatch, "security-officer")
    r = client.post("/v1/execution/revoke-principal", json={"principal": "employee-1"})
    assert r.status_code == 200, r.text
    _as_principal(monkeypatch, "employee-1")
    assert _try(client, token) == (409, "principal_revoked", False)
    assert not _events("execution_authorized")


def test_the_authority_route_revokes_and_reinstates_a_source(client, monkeypatch):
    gate = _install(monkeypatch, "enforce")
    token = _mint(gate)
    _as_principal(monkeypatch, "security-officer")
    r = client.post("/v1/execution/revoke-authority",
                    json={"subject_key": SOURCE, "reason": "feed compromised"})
    assert r.status_code == 200, r.text
    assert r.json() == {"subject_key": SOURCE, "epoch": 1, "revoked": True,
                        "revoked_by": "security-officer"}
    _mod().drain_audit_outbox("acme")
    assert _events("authority_revoked")[-1]["epoch"] == 1
    _as_principal(monkeypatch, "employee-1")
    assert _try(client, token) == (409, "authority_revoked", False)
    _as_principal(monkeypatch, "security-officer")
    r = client.post("/v1/execution/revoke-authority",
                    json={"subject_key": SOURCE, "revoked": False})
    assert r.json()["epoch"] == 2
    _as_principal(monkeypatch, "employee-1")
    assert _try(client, token)[2] is True


@pytest.mark.parametrize("subject", ["principal:x", "source:", "sourcex:y"])
def test_the_authority_route_names_sources_only(client, subject):
    r = client.post("/v1/execution/revoke-authority", json={"subject_key": subject})
    assert r.status_code in (409, 422)


def test_the_authority_route_refuses_without_atomic_admission(client, monkeypatch):
    monkeypatch.delenv("REMORA_WS1_ADMISSION", raising=False)
    r = client.post("/v1/execution/revoke-authority", json={"subject_key": SOURCE})
    assert r.status_code == 409


# ── the admission's audit row (M4-T12) ───────────────────────────────────────


def _joined(authorized: dict) -> dict:
    """The execution_admitted entry an execution_authorized one names, which
    the drain after commit put on the chain before it."""
    names = [e.payload.get("event") for e in _mod()._CHAIN.entries("acme")]
    [admitted] = [e for e in _events("execution_admitted")
                  if authorized["admission"]["audit_key"].endswith(e["grant_jti"])]
    assert names.index("execution_admitted") < names.index("execution_authorized")
    assert admitted["grant_jti"] == authorized["grant_jti"]
    return admitted


def test_m4_t12_each_path_commits_its_admission_record_with_the_spend(client, monkeypatch):
    gate = _install(monkeypatch, "enforce")
    assert _try(client, _mint(gate))[2] is True
    admitted = _joined(_events("execution_authorized")[-1])
    assert admitted["admission"]["mode"] == "atomic" and admitted["outbox_id"]


def test_m4_t12_the_review_path_commits_its_admission_record(client, monkeypatch):
    assert _execute(client, _approved(client, monkeypatch))["tool_execution"]["executed"]
    assert _joined(_events("execution_authorized")[-1])["item_id"]


def test_m4_t12_the_worker_commits_its_admission_record(client, monkeypatch):
    monkeypatch.setenv("REMORA_ASYNC_DISPATCH", "1")
    _execute(client, _approved(client, monkeypatch))
    _mod().dispatch_pending_intents("acme", worker_id="w-1")
    assert _joined(_events("execution_authorized")[-1])["executed_by"] == "w-1"


def test_m4_t12_an_audit_outbox_failure_refuses_unspent(client, monkeypatch):
    gate = _install(monkeypatch, "enforce")
    token = _mint(gate)
    real = admission_mod.audit_outbox.enqueue

    def down(*args, **kwargs):
        raise RuntimeError("audit outbox insert failed")

    monkeypatch.setattr(admission_mod.audit_outbox, "enqueue", down)
    assert _try(client, token) == (409, "audit_outbox_unavailable", False)
    assert not _events("execution_authorized") and not _events("execution_admitted")
    monkeypatch.setattr(admission_mod.audit_outbox, "enqueue", real)
    assert _try(client, token)[2] is True


# ── the permit before the send (INV-M4-03, M4-T14, M4-T16) ───────────────────


def _between_commit_and_permit(monkeypatch, act):
    """Run *act* after admission committed and before the permit check."""
    admission = _mod()._admission()
    real = admission.permit

    def late(tenant, **kwargs):
        act(admission)
        return real(tenant, **kwargs)

    monkeypatch.setattr(admission, "permit", late)


def _lapse(monkeypatch):
    def act(admission):
        real = admission_mod.db_now_ms
        monkeypatch.setattr(admission_mod, "db_now_ms",
                            lambda conn, dialect: real(conn, dialect) + 120_000)
    return act


def _revoke(admission):
    admission.advance_authority("acme", SOURCE, revoked=True)


def test_m4_t14_the_lease_ends_when_the_evidence_does(client, monkeypatch):
    from datetime import datetime

    gate = _install(monkeypatch, "enforce")
    r = _redeem(client, _mint(gate))
    execution = r.json()["tool_execution"]
    assert execution["executed"] is True
    permit = execution["permit"]
    assert (permit["validity"], permit["at_effect"]) == (
        "AUTHORIZED_AT_COMMIT", "NOT_ESTABLISHED")
    result = _events("execution_result")[-1]
    assert result["permit"] == permit
    expires = datetime.fromisoformat(result["lease"]["expires_at"])
    assert expires.timestamp() * 1000 <= permit["not_after_ms"]


@pytest.mark.parametrize("cause,reason", [("lapse", "evidence_expired_at_admission"),
                                          ("revocation", "authority_revoked")])
def test_m4_t14_t16_a_change_after_commit_refuses_before_the_send(
        client, monkeypatch, cause, reason):
    gate = _install(monkeypatch, "enforce")
    token = _mint(gate)
    sent: list[str] = []
    real_impl = _mod()._dispatch_under_lease_impl
    monkeypatch.setattr(_mod(), "_dispatch_under_lease_impl",
                        lambda **kw: sent.append(kw["tool_call"].tool_name) or real_impl(**kw))
    _between_commit_and_permit(monkeypatch, _lapse(monkeypatch) if cause == "lapse" else _revoke)
    r = _redeem(client, token)
    execution = r.json()["tool_execution"]
    assert (execution["executed"], execution["refusal_reason"], execution["permit_refusal"]) == (
        False, "permit_refused", reason)
    assert sent == []
    result = _events("execution_result")[-1]
    assert (result["tool_executed"], result["tool_refusal_reason"]) == (False, "permit_refused")
    # The grant was spent at admission: a permit refusal is not a retry.
    grant = _mod().PolicyDecisionToken.from_dict(token)
    assert _mod()._GATE.check(grant, consume=False).reason == "token_already_consumed"


def test_m4_t16_a_revocation_during_the_send_is_not_called_safe_at_effect(client, monkeypatch):
    """Revoked after the permit, while the call is out: this deployment's
    executor does not check again, so the call runs and the record says the
    effect-time authority is NOT_ESTABLISHED."""
    gate = _install(monkeypatch, "enforce")
    real_impl = _mod()._dispatch_under_lease_impl

    def revoke_mid_send(**kw):
        _revoke(_mod()._admission())
        return real_impl(**kw)

    monkeypatch.setattr(_mod(), "_dispatch_under_lease_impl", revoke_mid_send)
    execution = _redeem(client, _mint(gate)).json()["tool_execution"]
    assert execution["executed"] is True
    assert execution["permit"]["at_effect"] == "NOT_ESTABLISHED"
    assert "refusal" not in execution["permit"]
    assert _events("execution_result")[-1]["permit"]["at_effect"] == "NOT_ESTABLISHED"


def test_m4_t16_the_review_path_refuses_a_revocation_before_the_send(client, monkeypatch):
    item_id = _approved(client, monkeypatch)
    _between_commit_and_permit(monkeypatch, _revoke)
    execution = _execute(client, item_id)["tool_execution"]
    assert (execution["executed"], execution["permit_refusal"]) == (False, "authority_revoked")
    assert _events("execution_authorized")  # admitted, then refused before the send
    assert _row_state(item_id) == {"REFUSED"}


def test_m4_t16_the_worker_refuses_a_revocation_before_the_send(client, monkeypatch):
    monkeypatch.setenv("REMORA_ASYNC_DISPATCH", "1")
    item_id = _approved(client, monkeypatch)
    _execute(client, item_id)
    _between_commit_and_permit(monkeypatch, _revoke)
    [result] = _mod().dispatch_pending_intents("acme", worker_id="w-1")
    assert result["tool_execution"]["permit_refusal"] == "authority_revoked"
    assert _row_state(item_id) == {"REFUSED"}
    assert _mod().dispatch_pending_intents("acme", worker_id="w-2") == []

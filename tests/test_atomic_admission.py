# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1-M4 atomic admission over a real transaction (M4.1c).

Every test runs on SQLite and, with REMORA_PG_DSN set, on Postgres, through
the real ``transaction_state``, the real consumed-grant ledger, the real
outbox and the real epoch store. The M4-T* names refer to the negative test
matrix in docs/design/ws1-m4-safe-autonomy-recovery-v0.2.md §5. Contention is
staged with events, not sleeps.

The CI postgres-contract job selects this module with ``-k postgres``; the
``[postgres]`` parameter ids are what it matches.
"""
from __future__ import annotations

import os
import threading
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from remora.enforcement.gate import EnforcementGate
from remora.enforcement.outbox import PostgresExecutionOutbox, SQLiteExecutionOutbox
from remora.enforcement.token import PolicyDecisionToken
from remora.execution import admission as admission_mod
from remora.execution.admission import AdmissionRefused, AtomicAdmission, ClaimLost
from remora.execution.dispatch import record_dispatch_intent
from remora.governance import authority_epochs as epochs_mod
from remora.governance.authority_epochs import AuthorityEpochs, AuthorityEpochsUnavailable
from remora.governance.review_queue import ReviewQueue
from remora.governance.revocation_store import DurableRevocationStore
from remora.persistence.execution_state import transaction_state
from remora.policy.report import DecisionAction
from remora.verification import receipts as receipts_mod
from remora.verification.execution_gate import Ws1Outcome
from remora.verification.receipts import EvidenceReceiptV1

T = "acme"
OBS = "o" * 64
BINDING = "b" * 64
SUBJECT = "source:asset-inventory"
KEY = "atomic-admission-key"
BASE_DSN = os.environ.get("REMORA_PG_DSN", "")


@pytest.fixture(params=["sqlite", pytest.param("postgres", marks=pytest.mark.skipif(
    not BASE_DSN, reason="REMORA_PG_DSN not set"))])
def backend(request):
    return request.param


@dataclass
class Rig:
    admission: AtomicAdmission
    gate: EnforcementGate
    outbox: Any
    var: ContextVar
    epochs: AuthorityEpochs

    def tx(self, tenant: str = T):
        return self.admission._transaction(tenant)

    def admit(self, token, ws1, *, record_intent=None, consume=None):
        def intent():
            return record_dispatch_intent(
                self.outbox, self.var.get(), proposal_id=token.request_id, tenant=T,
                item_id=f"accept:{token.jti}", tool_name="read_telemetry",
                tool_call_hash="h" * 64, grant_jti=token.jti)

        return self.admission.admit(
            T, ws1=ws1,
            consume=consume or (lambda conn, now: self.gate.check(
                token, OBS, consume=True, now=now, connection=conn)),
            record_intent=record_intent or intent)

    def spent(self, token) -> bool:
        result = self.gate.check(token, OBS, consume=False)
        assert result.reason in ("accept", "token_already_consumed"), result.reason
        return result.reason == "token_already_consumed"

    def intents(self, token) -> int:
        return len(self.outbox.rows_for_proposal(T, token.request_id))


@pytest.fixture()
def rig(backend, tmp_path, monkeypatch):
    monkeypatch.setenv("REMORA_PDP_SIGNING_KEY", KEY)
    monkeypatch.delenv("REMORA_STATE_ENDPOINT", raising=False)
    for name in ("REMORA_RUNTIME_PROFILE", "REMORA_SIGNATURE_FORMAT", "REMORA_PDP_ISSUER",
                 "REMORA_PDP_SIGNING_KID", "REMORA_PDP_PREVIOUS_KEYS", "REMORA_PDP_REVOKED_KIDS"):
        monkeypatch.delenv(name, raising=False)
    schema = ""
    if backend == "postgres":
        import psycopg
        from psycopg import conninfo

        schema = f"admission_{uuid.uuid4().hex[:12]}"
        with psycopg.connect(BASE_DSN) as conn:
            conn.execute(f"CREATE SCHEMA {schema}")
            conn.commit()
        dsn, db = conninfo.make_conninfo(BASE_DSN, options=f"-c search_path={schema}"), ""
    else:
        dsn, db = "", str(tmp_path / "admission.db")
    var: ContextVar[Any] = ContextVar(f"tx-{uuid.uuid4().hex}", default=None)
    queue = ReviewQueue()

    def tx(tenant: str):
        return transaction_state(tenant, queue=queue, item_tenant={},
                                 active_tx_connection=var, dsn=dsn, db_path=db)

    epochs = AuthorityEpochs(dsn=dsn, db_path=db, connection_provider=var.get)
    # No warm-up transaction: the contention tests open the first
    # transactions on a fresh schema concurrently, which is what pins
    # _ensure_pg_schema in remora/persistence/execution_state.py.
    yield Rig(
        admission=AtomicAdmission(transaction=tx, connection=var.get, epochs=epochs,
                                  revocations=DurableRevocationStore(
                                      dsn=dsn, db_path=db, connection_provider=var.get),
                                  # The largest declarable skew: a database in a
                                  # desktop VM drifts by more than a second
                                  # against the host clock that stamps grants.
                                  dialect=backend, max_clock_skew_ms=5_000),
        gate=EnforcementGate(strict=True, dsn=dsn, db_path=db),
        outbox=PostgresExecutionOutbox(dsn) if dsn else SQLiteExecutionOutbox(db),
        var=var, epochs=epochs)
    if schema:
        import psycopg

        with psycopg.connect(BASE_DSN) as conn:
            conn.execute(f"DROP SCHEMA {schema} CASCADE")
            conn.commit()


def _token(tag: str = "") -> PolicyDecisionToken:
    now = datetime.now(UTC)
    return PolicyDecisionToken.issue(
        action="accept", observation_hash=OBS, request_id=f"p-{tag or uuid.uuid4().hex}",
        issued_at=now.isoformat(), expires_at=(now + timedelta(seconds=300)).isoformat())


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _ws1(*, valid_for_ms: int = 60_000, epoch: int = 0) -> Ws1Outcome:
    receipt = EvidenceReceiptV1(
        tenant_id=T, binding_hash=BINDING, precondition_id="asset_known", subject_key=SUBJECT,
        source_epoch=epoch, source_version="v1", evidence_refs=("ref",),
        verified_at_ms=_now_ms(), valid_until_ms=_now_ms() + valid_for_ms,
        verifier_profile_hash="p")
    return Ws1Outcome("enforce", DecisionAction.ACCEPT, "evaluated", binding_hash=BINDING,
                      receipts=(receipt,), receipts_pinned=True,
                      required_preconditions=("asset_known",))


def _refusal(rig, token, ws1, **kwargs) -> str:
    with pytest.raises(AdmissionRefused) as caught:
        rig.admit(token, ws1, **kwargs)
    return caught.value.reason


# ── one transaction ──────────────────────────────────────────────────────────


def test_fresh_evidence_spends_the_grant_and_records_one_intent(rig):
    token = _token()
    admitted = rig.admit(token, _ws1())
    assert admitted.gate_result.allowed
    assert abs(admitted.db_time_ms - _now_ms()) < 60_000
    assert admitted.authority_epochs == {SUBJECT: (0, False)}
    assert admitted.audit_block()["mode"] == "atomic"
    assert rig.spent(token) and rig.intents(token) == 1


def test_m4_t01_evidence_expired_before_commit_refuses_unspent(rig):
    token = _token()
    assert _refusal(rig, token, _ws1(valid_for_ms=-1)) == "evidence_expired_at_admission"
    assert not rig.spent(token) and rig.intents(token) == 0


def test_m4_t10_the_declared_skew_is_subtracted_at_the_database_instant(rig):
    token = _token()
    assert _refusal(rig, token, _ws1(valid_for_ms=2_000)) == "evidence_expired_at_admission"
    assert not rig.spent(token)


def test_the_grant_expires_the_declared_skew_early(rig):
    now = datetime.now(UTC)
    token = PolicyDecisionToken.issue(
        action="accept", observation_hash=OBS, request_id="p-short",
        issued_at=now.isoformat(), expires_at=(now + timedelta(seconds=2)).isoformat())
    assert _refusal(rig, token, _ws1()).startswith("token_verification_failed:")
    assert not rig.spent(token)


def test_m4_t02_evidence_lapsing_after_the_regate_refuses(rig, monkeypatch):
    """The #982 counterexample: the evidence was fresh at the re-gate and
    lapses before the spend. Admission reads the database instant inside the
    transaction, so the lapse is seen."""
    real = admission_mod.db_now_ms
    monkeypatch.setattr(admission_mod, "db_now_ms",
                        lambda conn, dialect: real(conn, dialect) + 5_000)
    token = _token()
    assert _refusal(rig, token, _ws1(valid_for_ms=5_500)) == "evidence_expired_at_admission"
    assert not rig.spent(token) and rig.intents(token) == 0


def test_m4_t04_an_epoch_advanced_after_the_lookups_refuses(rig):
    pinned = rig.admission.pin_epochs(T)([SUBJECT])
    assert pinned == {SUBJECT: 0}
    rig.admission.advance_authority(T, SUBJECT, revoked=False)
    token = _token()
    assert _refusal(rig, token, _ws1(epoch=pinned[SUBJECT])) == "authority_epoch_stale"
    assert not rig.spent(token) and rig.intents(token) == 0


def test_m4_t03_a_revoked_subject_refuses(rig):
    epoch = rig.admission.advance_authority(T, SUBJECT, revoked=True)
    token = _token()
    assert _refusal(rig, token, _ws1(epoch=epoch)) == "authority_revoked"
    assert not rig.spent(token)


def test_m4_t11_a_failed_intent_rolls_the_spend_back(rig):
    token = _token()

    def crash():
        raise RuntimeError("crash after the spend, before the intent")

    with pytest.raises(RuntimeError):
        rig.admit(token, _ws1(), record_intent=crash)
    assert not rig.spent(token) and rig.intents(token) == 0
    rig.admit(token, _ws1())  # the grant was never spent
    assert rig.spent(token) and rig.intents(token) == 1


def test_a_spent_grant_refuses_and_records_nothing(rig):
    token = _token()
    rig.admit(token, _ws1())
    assert _refusal(rig, token, _ws1()) == "token_already_consumed"
    assert rig.intents(token) == 1


def test_m4_t13_an_unreachable_epoch_store_refuses_unspent(rig, monkeypatch):
    def down(*args, **kwargs):
        raise AuthorityEpochsUnavailable("down")

    monkeypatch.setattr(rig.epochs, "read", down)
    token = _token()
    assert _refusal(rig, token, _ws1()) == "authority_epochs_unavailable"
    assert not rig.spent(token)


def test_an_outcome_without_receipts_is_not_admitted(rig):
    token = _token()
    bare = Ws1Outcome("enforce", DecisionAction.ACCEPT, "evaluated", binding_hash=BINDING)
    assert _refusal(rig, token, bare) == "evidence_receipts_absent"
    assert not rig.spent(token)


def test_without_ws1_the_spend_and_the_intent_still_share_one_transaction(rig):
    token = _token()

    def crash():
        raise RuntimeError("intent store failed")

    with pytest.raises(RuntimeError):
        rig.admit(token, None, record_intent=crash)
    assert not rig.spent(token)
    rig.admit(token, None)
    assert rig.spent(token) and rig.intents(token) == 1


# ── contention ───────────────────────────────────────────────────────────────


def test_m4_t06_one_grant_redeemed_by_eight_admitters_spends_once(rig):
    token = _token()
    barrier = threading.Barrier(8)
    outcomes: list[str] = []
    lock = threading.Lock()

    def redeem():
        barrier.wait(10)
        try:
            rig.admit(token, _ws1())
            result = "admitted"
        except AdmissionRefused as exc:
            result = exc.reason
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=redeem) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert sorted(outcomes) == ["admitted"] + ["token_already_consumed"] * 7
    assert rig.intents(token) == 1


def test_m4_t05_a_revocation_committed_first_is_seen_by_admission(rig):
    revocation_holds = threading.Event()
    admission_started = threading.Event()
    seen: list[str] = []
    token = _token()

    def revoke():
        with rig.tx():
            rig.epochs.advance(SUBJECT, tenant_id=T, revoked=True)
            revocation_holds.set()
            admission_started.wait(10)

    def admit():
        revocation_holds.wait(10)
        admission_started.set()
        try:
            rig.admit(token, _ws1(epoch=0))  # blocks until the revocation commits
            seen.append("admitted")
        except AdmissionRefused as exc:
            seen.append(exc.reason)

    threads = [threading.Thread(target=revoke), threading.Thread(target=admit)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert seen == ["authority_revoked"]
    assert not rig.spent(token)


def test_m4_t05_an_admission_committed_first_stands(rig):
    """The other order: admission linearizes first and the call is admitted.
    The revocation after it cannot un-send it (INV-M4-02, disclosed)."""
    admission_holds = threading.Event()
    revocation_started = threading.Event()
    token = _token()
    epochs_after: list[int] = []

    def consume(conn, now):
        result = rig.gate.check(token, OBS, consume=True, now=now, connection=conn)
        admission_holds.set()
        revocation_started.wait(10)
        return result

    def admit():
        rig.admit(token, _ws1(epoch=0), consume=consume)

    def revoke():
        admission_holds.wait(10)
        revocation_started.set()
        epochs_after.append(rig.admission.advance_authority(T, SUBJECT, revoked=True))

    threads = [threading.Thread(target=admit), threading.Thread(target=revoke)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert rig.spent(token) and rig.intents(token) == 1
    assert epochs_after == [1]


# ── refusals that need no backend ────────────────────────────────────────────


def test_an_in_process_transaction_is_refused(tmp_path):
    @contextmanager
    def no_tx(tenant):
        yield None

    admission = AtomicAdmission(
        transaction=no_tx, connection=lambda: None,
        epochs=AuthorityEpochs(db_path=str(tmp_path / "e.db")), dialect="sqlite",
        max_clock_skew_ms=0)
    with pytest.raises(AdmissionRefused) as caught:
        admission.admit(T, ws1=None, consume=lambda c, n: None, record_intent=lambda: None)
    assert caught.value.reason == "admission_transaction_unavailable"


@pytest.mark.parametrize("dialect,skew", [("d1", 0), ("memory", 0), ("sqlite", -1),
                                          ("sqlite", 5_001), ("sqlite", True),
                                          ("sqlite", 1.0)])
def test_admission_needs_a_transactional_dialect_and_a_bounded_skew(tmp_path, dialect, skew):
    with pytest.raises(ValueError):
        AtomicAdmission(transaction=lambda t: None, connection=lambda: None,
                        epochs=AuthorityEpochs(db_path=str(tmp_path / "e.db")),
                        dialect=dialect, max_clock_skew_ms=skew)


def test_an_in_process_gate_cannot_join_a_transaction(monkeypatch):
    monkeypatch.setenv("REMORA_PDP_SIGNING_KEY", KEY)
    result = EnforcementGate(strict=True).check(
        _token(), OBS, consume=True, connection=object())
    assert (result.allowed, result.reason) == (False, "consumed_ledger_unavailable")


def test_the_core_and_ws1_skew_bounds_agree():
    assert epochs_mod.MAX_CLOCK_SKEW_MS == receipts_mod.MAX_CLOCK_SKEW_MS == 5_000


# ── the claim paths (approved review, async worker) ──────────────────────────


def _pending_row(rig, proposal_id: str = ""):
    return rig.outbox.record_intent(
        proposal_id=proposal_id or f"p-{uuid.uuid4().hex}", tenant_id=T, item_id="item-1",
        tool_name="store_artifact", tool_call_hash="h" * 64, grant_jti="")


def _admit_claim(rig, token, row, worker: str):
    return rig.admission.admit(
        T, ws1=_ws1(),
        claim=lambda conn: rig.outbox.claim_enlisted(conn, row.outbox_id, worker_id=worker),
        consume=lambda conn, now: rig.gate.check(
            token, OBS, consume=True, now=now, connection=conn))


def test_a_claim_admission_claims_and_spends_together(rig):
    row, token = _pending_row(rig), _token()
    admitted = _admit_claim(rig, token, row, "w-1")
    assert admitted.claimed.state.value == "DISPATCHING"
    assert rig.outbox.get(row.outbox_id).worker_id == "w-1"
    assert rig.spent(token)


def test_a_lost_claim_spends_nothing(rig):
    row, token = _pending_row(rig), _token()
    assert rig.outbox.claim(row.outbox_id, worker_id="other") is not None
    with pytest.raises(ClaimLost):
        _admit_claim(rig, token, row, "w-1")
    assert not rig.spent(token)


def test_a_refused_spend_releases_the_claim(rig):
    row, token = _pending_row(rig), _token()
    rig.admit(token, _ws1())  # spends the grant elsewhere
    with pytest.raises(AdmissionRefused) as caught:
        _admit_claim(rig, token, row, "w-1")
    assert caught.value.reason == "token_already_consumed"
    assert rig.outbox.get(row.outbox_id).state.value == "DISPATCH_PENDING"


def test_eight_workers_on_one_row_claim_and_spend_once(rig):
    row = _pending_row(rig)
    tokens = [_token() for _ in range(8)]
    barrier = threading.Barrier(8)
    outcomes: list[str] = []
    lock = threading.Lock()

    def work(i):
        barrier.wait(10)
        try:
            _admit_claim(rig, tokens[i], row, f"w-{i}")
            result = "admitted"
        except AdmissionRefused as exc:
            result = exc.reason
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert sorted(outcomes) == ["admitted"] + ["claim_lost"] * 7
    assert sum(rig.spent(t) for t in tokens) == 1


# ── principal revocation and the epoch writer (slice 2b) ─────────────────────


def test_m4_t03_a_revoked_principal_refuses_unspent(rig):
    with rig.tx():
        rig.admission._revocations.revoke("approver-1", tenant_id=T, reason="left")
    token = _token()
    with pytest.raises(AdmissionRefused) as caught:
        rig.admission.admit(
            T, ws1=_ws1(), principals=("agent-1", "approver-1"),
            consume=lambda conn, now: rig.gate.check(
                token, OBS, consume=True, now=now, connection=conn))
    assert caught.value.reason == "principal_revoked"
    assert not rig.spent(token)


def test_principals_unrevoked_in_this_tenant_admit(rig):
    with rig.tx("other"):
        rig.admission._revocations.revoke("agent-1", tenant_id="other")
    token = _token()
    rig.admission.admit(T, ws1=_ws1(), principals=("agent-1",),
                        consume=lambda conn, now: rig.gate.check(
                            token, OBS, consume=True, now=now, connection=conn))
    assert rig.spent(token)


def test_an_unreadable_revocation_store_refuses(rig, monkeypatch):
    def down(*args, **kwargs):
        raise RuntimeError("down")

    monkeypatch.setattr(rig.admission._revocations, "is_revoked", down)
    token = _token()
    with pytest.raises(AdmissionRefused) as caught:
        rig.admission.admit(T, ws1=_ws1(), principals=("agent-1",),
                            consume=lambda conn, now: rig.gate.check(
                                token, OBS, consume=True, now=now, connection=conn))
    assert caught.value.reason == "revocation_store_unavailable"
    assert not rig.spent(token)


def test_principals_without_a_revocation_store_refuse(rig):
    rig.admission._revocations = None
    with pytest.raises(AdmissionRefused) as caught:
        rig.admission.admit(T, ws1=None, principals=("agent-1",),
                            consume=lambda conn, now: None)
    assert caught.value.reason == "revocation_store_unavailable"


def test_an_epoch_change_and_its_record_commit_together(rig):
    seen = []
    assert rig.admission.advance_authority(T, SUBJECT, revoked=True,
                                           record=seen.append) == 1
    assert seen == [1]

    def crash(epoch):
        raise RuntimeError("audit write failed")

    with pytest.raises(RuntimeError):
        rig.admission.advance_authority(T, SUBJECT, revoked=False, record=crash)
    assert rig.admission.pin_epochs(T)([SUBJECT]) == {SUBJECT: 1}


# ── the audit row in the transaction (M4-T12) ────────────────────────────────


def _audit(token) -> dict[str, Any]:
    return {"proposal_id": token.request_id, "actor": "agent-1", "grant_jti": token.jti}


def _pending_audit(rig) -> list[tuple[str, str, dict[str, Any]]]:
    from remora.governance import audit_outbox

    with rig.tx():
        return audit_outbox.pending(rig.var.get(), tenant=T)


def _admit_audited(rig, token):
    return rig.admission.admit(
        T, ws1=_ws1(), audit=_audit(token),
        consume=lambda conn, now: rig.gate.check(
            token, OBS, consume=True, now=now, connection=conn),
        record_intent=lambda: record_dispatch_intent(
            rig.outbox, rig.var.get(), proposal_id=token.request_id, tenant=T,
            item_id=f"accept:{token.jti}", tool_name="read_telemetry",
            tool_call_hash="h" * 64, grant_jti=token.jti))


def test_m4_t12_the_admission_enqueues_its_audit_row_before_commit(rig):
    token = _token()
    admitted = _admit_audited(rig, token)
    [(key, tenant, payload)] = _pending_audit(rig)
    assert (key, tenant) == (admitted.audit_key, T)
    assert payload["event"] == "execution_admitted"
    assert payload["grant_jti"] == token.jti
    assert payload["outbox_id"] == admitted.intent.outbox_id
    assert payload["admission"]["authority_epochs"] == {SUBJECT: {"epoch": 0, "revoked": False}}
    assert admitted.audit_block()["audit_key"] == key


def test_m4_t12_an_audit_outbox_failure_rolls_the_whole_admission_back(rig, monkeypatch):
    def down(*args, **kwargs):
        raise RuntimeError("audit outbox insert failed")

    real = admission_mod.audit_outbox.enqueue
    monkeypatch.setattr(admission_mod.audit_outbox, "enqueue", down)
    token = _token()
    with pytest.raises(AdmissionRefused) as caught:
        _admit_audited(rig, token)
    assert caught.value.reason == "audit_outbox_unavailable"
    assert not rig.spent(token) and rig.intents(token) == 0
    monkeypatch.setattr(admission_mod.audit_outbox, "enqueue", real)
    assert _pending_audit(rig) == []
    _admit_audited(rig, token)  # nothing was spent: the retry admits
    assert rig.spent(token) and rig.intents(token) == 1


def test_m4_t12_an_audit_failure_on_a_claim_releases_the_claim(rig, monkeypatch):
    row, token = _pending_row(rig), _token()

    def down(*args, **kwargs):
        raise RuntimeError("audit outbox insert failed")

    monkeypatch.setattr(admission_mod.audit_outbox, "enqueue", down)
    with pytest.raises(AdmissionRefused):
        rig.admission.admit(
            T, ws1=_ws1(), audit=_audit(token),
            claim=lambda conn: rig.outbox.claim_enlisted(conn, row.outbox_id, worker_id="w-1"),
            consume=lambda conn, now: rig.gate.check(
                token, OBS, consume=True, now=now, connection=conn))
    assert rig.outbox.get(row.outbox_id).state.value == "DISPATCH_PENDING"
    assert not rig.spent(token)


def test_an_unkeyed_audit_record_refuses_unspent(rig):
    token = _token()
    with pytest.raises(AdmissionRefused) as caught:
        rig.admission.admit(T, ws1=_ws1(), audit={"actor": "agent-1"},
                            consume=lambda conn, now: rig.gate.check(
                                token, OBS, consume=True, now=now, connection=conn))
    assert caught.value.reason == "admission_audit_unkeyed"
    assert not rig.spent(token)


def test_a_failed_drain_leaves_the_committed_row_for_the_next_one(rig):
    calls: list[str] = []

    def drain(tenant):
        calls.append(tenant)
        raise RuntimeError("chain unreachable")

    rig.admission._drain = drain
    token = _token()
    admitted = _admit_audited(rig, token)  # committed despite the drain
    assert calls == [T] and rig.spent(token)
    assert [k for k, _, _ in _pending_audit(rig)] == [admitted.audit_key]


# ── the permit before the send (INV-M4-03, M4-T14, M4-T16) ───────────────────


def test_a_permit_after_admission_bounds_the_lease_by_the_evidence(rig):
    token, ws1 = _token(), _ws1()
    rig.admit(token, ws1)
    permit = rig.admission.permit(T, ws1=ws1, principals=("agent-1",))
    assert permit.refusal is None
    assert permit.not_after_ms == ws1.evidence_valid_until_ms - 2 * 5_000
    assert permit.audit_block()["at_effect"] == "NOT_ESTABLISHED"


def test_m4_t14_evidence_lapsing_after_commit_refuses_the_permit(rig, monkeypatch):
    token, ws1 = _token(), _ws1()
    rig.admit(token, ws1)
    real = admission_mod.db_now_ms
    monkeypatch.setattr(admission_mod, "db_now_ms",
                        lambda conn, dialect: real(conn, dialect) + 120_000)
    assert rig.admission.permit(T, ws1=ws1).refusal == "evidence_expired_at_admission"


def test_m4_t14_evidence_too_close_to_expiry_for_the_executor_refuses(rig):
    """Admitted with the skew to spare, but the lease would have to end the
    skew earlier again for an executor clock running behind."""
    token, ws1 = _token(), _ws1(valid_for_ms=8_000)
    rig.admit(token, ws1)
    assert rig.admission.permit(T, ws1=ws1).refusal == "evidence_expires_before_dispatch"


def test_m4_t16_a_source_revoked_after_commit_refuses_the_permit(rig):
    token, ws1 = _token(), _ws1()
    rig.admit(token, ws1)
    rig.admission.advance_authority(T, SUBJECT, revoked=True)
    assert rig.admission.permit(T, ws1=ws1).refusal == "authority_revoked"


def test_m4_t16_a_principal_revoked_after_commit_refuses_the_permit(rig):
    token, ws1 = _token(), _ws1()
    rig.admit(token, ws1)
    with rig.tx():
        rig.admission._revocations.revoke("agent-1", tenant_id=T)
    assert rig.admission.permit(T, ws1=ws1, principals=("agent-1",)).refusal == (
        "principal_revoked")


def test_an_unreachable_epoch_store_refuses_the_permit(rig, monkeypatch):
    def down(*args, **kwargs):
        raise AuthorityEpochsUnavailable("down")

    monkeypatch.setattr(rig.epochs, "read", down)
    assert rig.admission.permit(T, ws1=_ws1()).refusal == "authority_epochs_unavailable"


def test_a_permit_writes_nothing(rig):
    ws1 = _ws1()
    before = rig.admission.pin_epochs(T)([SUBJECT])
    assert rig.admission.permit(T, ws1=ws1).refusal is None
    assert rig.admission.pin_epochs(T)([SUBJECT]) == before
    assert _pending_audit(rig) == []


def test_m4_t16_a_revocation_racing_the_permit_has_one_order(rig):
    """The permit and the revocation take the same tenant lock: whichever
    commits first, the other sees it, and nothing in between."""
    ws1 = _ws1()
    barrier = threading.Barrier(2)
    seen: dict[str, Any] = {}

    def permit():
        barrier.wait(10)
        seen["permit"] = rig.admission.permit(T, ws1=ws1).refusal

    def revoke():
        barrier.wait(10)
        seen["epoch"] = rig.admission.advance_authority(T, SUBJECT, revoked=True)

    threads = [threading.Thread(target=permit), threading.Thread(target=revoke)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert seen["epoch"] == 1
    assert seen["permit"] in (None, "authority_revoked")
    assert rig.admission.permit(T, ws1=ws1).refusal == "authority_revoked"


def test_m4_t14_a_permit_past_its_bound_mints_no_lease():
    from types import SimpleNamespace

    from remora.execution.dispatch import dispatch_under_lease

    class Dispatcher:
        def dispatch(self, *args, **kwargs):
            raise AssertionError("nothing may be sent past the permit's bound")

    now = datetime.now(UTC)
    result = dispatch_under_lease(
        tenant=T, principal="agent-1", semantic={},
        tool_call=SimpleNamespace(tool_name="read_telemetry", arguments={},
                                  target_environment="prod"),
        now=now, dispatcher=Dispatcher(), policy_bundle_hash="p", not_after=now)
    assert result == {"executed": False, "refusal_reason": "permit_expired"}

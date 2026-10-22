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
    # transaction_state creates its tables with CREATE TABLE IF NOT EXISTS
    # inside the first transaction. On a fresh Postgres schema, concurrent
    # first transactions can collide on the catalog's unique index (fails
    # closed; recorded in the ADR). One transaction first keeps the
    # contention tests about admission.
    with tx(T):
        pass
    yield Rig(
        admission=AtomicAdmission(transaction=tx, connection=var.get, epochs=epochs,
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

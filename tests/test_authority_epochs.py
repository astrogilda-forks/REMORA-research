# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""AuthorityEpochs: durable, monotone, fail-closed, tenant-scoped (M4.1b).

The ordering tests run the revocation and the admission read as two
SQLite transactions that contend for one database, with explicit barriers
instead of sleeps: whichever commits first decides, and an admission that
read under lock after a committed revocation sees it (INV-M4-02).
"""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from contextvars import ContextVar

import pytest

from remora.governance.authority_epochs import AuthorityEpochs, AuthorityEpochsUnavailable

T = "acme"


@pytest.fixture()
def db(tmp_path):
    return str(tmp_path / "epochs.db")


def test_a_subject_never_advanced_is_epoch_zero_not_revoked(db):
    assert AuthorityEpochs(db_path=db).read(["source:crm"], tenant_id=T) == {
        "source:crm": (0, False)}


def test_every_advance_increases_the_epoch_and_survives_a_new_instance(db):
    store = AuthorityEpochs(db_path=db)
    assert store.advance("source:crm", tenant_id=T, revoked=True) == 1
    assert store.advance("source:crm", tenant_id=T, revoked=False) == 2
    assert AuthorityEpochs(db_path=db).read(["source:crm"], tenant_id=T) == {
        "source:crm": (2, False)}


def test_epochs_are_tenant_scoped(db):
    store = AuthorityEpochs(db_path=db)
    store.advance("source:crm", tenant_id=T, revoked=True)
    assert store.read(["source:crm"], tenant_id="other") == {"source:crm": (0, False)}


def test_an_unreachable_store_raises_rather_than_reporting_epoch_zero(tmp_path):
    missing = str(tmp_path / "no-such-dir" / "epochs.db")
    with pytest.raises(AuthorityEpochsUnavailable):
        AuthorityEpochs(db_path=missing).read(["source:crm"], tenant_id=T)


def test_a_locked_read_outside_a_transaction_is_refused(db):
    with pytest.raises(ValueError, match="inside the admission transaction"):
        AuthorityEpochs(db_path=db).read(["source:crm"], tenant_id=T, lock=True)


@pytest.mark.parametrize("subject,tenant", [("", T), ("source:crm", ""), ("  ", T)])
def test_scope_is_required(db, subject, tenant):
    with pytest.raises(ValueError):
        AuthorityEpochs(db_path=db).advance(subject, tenant_id=tenant, revoked=True)


def test_exactly_one_backend_is_required(db):
    with pytest.raises(ValueError):
        AuthorityEpochs()
    with pytest.raises(ValueError):
        AuthorityEpochs(dsn="postgresql://x", db_path=db)


# ── the store joins the caller's transaction ───────────────────────────────

_TX: ContextVar[sqlite3.Connection | None] = ContextVar("_TX", default=None)


@contextmanager
def _exclusive(path: str):
    """The SQLite branch of transaction_state: BEGIN EXCLUSIVE, publish, commit."""
    conn = sqlite3.connect(path, timeout=10, isolation_level=None)
    conn.execute("BEGIN EXCLUSIVE TRANSACTION")
    token = _TX.set(conn)
    try:
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    finally:
        _TX.reset(token)
        conn.close()


def test_an_advance_inside_a_rolled_back_transaction_leaves_no_trace(db):
    store = AuthorityEpochs(db_path=db, connection_provider=_TX.get)
    with pytest.raises(RuntimeError):
        with _exclusive(db):
            store.advance("source:crm", tenant_id=T, revoked=True)
            raise RuntimeError("admission failed later in the transaction")
    assert store.read(["source:crm"], tenant_id=T) == {"source:crm": (0, False)}


def test_a_revocation_committed_first_is_seen_by_the_admission_read(db):
    """Revoke and admit race; the revoke's transaction commits first."""
    store = AuthorityEpochs(db_path=db, connection_provider=_TX.get)
    revoke_holds_lock = threading.Event()
    admission_started = threading.Event()
    seen: dict[str, tuple[int, bool]] = {}

    def revoke() -> None:
        with _exclusive(db):
            store.advance("source:crm", tenant_id=T, revoked=True)
            revoke_holds_lock.set()
            admission_started.wait(5)  # the admitter is now blocked on our lock

    def admit() -> None:
        revoke_holds_lock.wait(5)
        admission_started.set()
        with _exclusive(db):  # blocks until the revocation commits
            seen.update(store.read(["source:crm"], tenant_id=T, lock=True))

    threads = [threading.Thread(target=revoke), threading.Thread(target=admit)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert seen == {"source:crm": (1, True)}


def test_an_admission_committed_first_reads_the_epoch_before_the_revocation(db):
    """The other order: the admission linearizes first and saw epoch 0. The
    revocation that commits after it cannot un-send that call; the ADR
    discloses this (decision 6)."""
    store = AuthorityEpochs(db_path=db, connection_provider=_TX.get)
    admission_holds_lock = threading.Event()
    revoke_started = threading.Event()
    seen: dict[str, tuple[int, bool]] = {}

    def admit() -> None:
        with _exclusive(db):
            seen.update(store.read(["source:crm"], tenant_id=T, lock=True))
            admission_holds_lock.set()
            revoke_started.wait(5)

    def revoke() -> None:
        admission_holds_lock.wait(5)
        revoke_started.set()
        with _exclusive(db):
            store.advance("source:crm", tenant_id=T, revoked=True)

    threads = [threading.Thread(target=admit), threading.Thread(target=revoke)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert seen == {"source:crm": (0, False)}
    assert AuthorityEpochs(db_path=db).read(["source:crm"], tenant_id=T) == {
        "source:crm": (1, True)}


# ── Postgres ────────────────────────────────────────────────────────────────

PG_DSN = os.environ.get("REMORA_PG_DSN", "")


@pytest.mark.skipif(not PG_DSN, reason="REMORA_PG_DSN not set")
def test_postgres_advance_and_read():
    import uuid

    store = AuthorityEpochs(dsn=PG_DSN)
    tenant = f"t-{uuid.uuid4().hex[:12]}"
    assert store.advance("source:crm", tenant_id=tenant, revoked=True) == 1
    assert store.advance("source:crm", tenant_id=tenant, revoked=False) == 2
    assert store.read(["source:crm", "source:erp"], tenant_id=tenant) == {
        "source:crm": (2, False), "source:erp": (0, False)}

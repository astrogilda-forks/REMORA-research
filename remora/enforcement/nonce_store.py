# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Durable single-use consumption for ExecutionLease nonces (ADR-B).

``NonceLedger`` in ``lease.py`` is a ``threading.Lock`` and a ``set``: a lease
it guards is single-use *per process*. Until this module landed (#351,
2026-08-24) that was the only ledger, and on the Cloudflare deployment the
one-time property of a lease had the lifetime of a container. Containers are
replaced on idle, so a captured lease re-presented inside its expiry window
after a replacement executed a second time.

Today ``servers/execution_api.py::_lease_nonce_store`` builds a
``DurableNonceStore`` whenever ``REMORA_PG_DSN``, ``REMORA_CHAIN_DB`` or
``REMORA_STATE_ENDPOINT`` is set, the same variables as the consumed-jti
ledger. With none of them set the in-process ``NonceLedger`` remains, and the
per-process limit above still holds; the strict runtime profiles and
production mode refuse to start without durable execution state. What is
tested: spend-once, tenant scoping, outage-is-unknown and replacement
dispatchers on SQLite (``tests/test_lease_nonce_durability.py``), the same on
a real PostgreSQL server (``tests/test_enforcement_ledgers_postgres.py``, the
``postgres-contract`` CI job), and separate processes on one host
(``tests/conformance/test_execution_boundary_process_split.py``). Dispatchers
on separate hosts sharing one store have not been run.

This is the same defect class as the consumed-jti ledger fix (#350) one layer
up: a durable backend the deployment already runs, that one component learned
to use and another did not. That it recurred is the argument for a shared,
deliberately tiny interface instead of a second bespoke ledger.

The interface is one method on purpose. This is not a database abstraction and
must not grow into one — every method added here is a method that has to be
correct on three backends.

Four required semantics, all of which have an adversarial test:

atomic
    exactly one caller gets True for a given (tenant, nonce), even under
    concurrent consumption.
durable
    a restart, a replacement container, or a second dispatcher instance does
    not restore spent authority.
fail closed
    an unreachable store raises ``NonceStoreUnavailable``. Unreachable never
    means unused — assuming so IS the double-spend. Equally, a store that
    could not record a consumption must not report it as consumed, or a
    transient outage permanently destroys a valid authorization.
tenant scoped
    the primary key is (tenant_id, nonce). Tenant A cannot consume, collide
    with, or observe tenant B's namespace.
"""
from __future__ import annotations

import threading
from typing import Any, Protocol, runtime_checkable

from remora.errors import RemoraError

__all__ = [
    "DurableNonceStore",
    "InMemoryNonceStore",
    "NonceStore",
    "NonceStoreUnavailable",
]

#: Composite primary key, so tenant isolation is enforced by the store rather
#: than by every caller remembering to prefix.
_CREATE = (
    "CREATE TABLE IF NOT EXISTS lease_nonce_consumed ("
    "tenant_id TEXT NOT NULL, nonce TEXT NOT NULL, "
    "consumed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
    "PRIMARY KEY (tenant_id, nonce))"
)


class NonceStoreUnavailable(RemoraError, RuntimeError):
    """The store could not be reached or could not answer.

    Deliberately distinct from "already consumed". Collapsing the two is the
    failure this module exists to prevent, in both directions: treating
    unavailable as unused re-authorizes spent grants, and treating unavailable
    as consumed burns valid ones.
    """

    code = "nonce_store_unavailable"
    category = "enforcement"


@runtime_checkable
class NonceStore(Protocol):
    """Atomic, durable, tenant-scoped single-use consumption."""

    def try_consume(self, nonce: str, *, tenant_id: str) -> bool:
        """Return True exactly once per (tenant_id, nonce); False on replay.

        Raises ``NonceStoreUnavailable`` if the outcome is unknown. Never
        returns False to mean "I could not tell".
        """
        ...


class InMemoryNonceStore:
    """Process-local store with the durable store's exact semantics.

    For library and research use, and as the control in the durability tests:
    it is the thing whose restart behaviour must differ. It is NOT a fallback
    for a durable backend that failed — falling back to this on an outage
    would silently reintroduce the replay window.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._consumed: set[tuple[str, str]] = set()

    def try_consume(self, nonce: str, *, tenant_id: str) -> bool:
        key = (tenant_id, nonce)
        with self._lock:
            if key in self._consumed:
                return False
            self._consumed.add(key)
            return True

    def consumed(self, nonce: str, *, tenant_id: str) -> bool:
        """Whether (tenant_id, nonce) has been consumed. Never consumes."""
        with self._lock:
            return (tenant_id, nonce) in self._consumed


class DurableNonceStore:
    """Nonce consumption over REMORA's existing durable state backends.

    Exactly the three the durability guard in ``servers/api.py`` admits, for
    the reason recorded in ``tests/test_gate_d1_ledger.py``: a store the guard
    accepts but the consumer never learned to use is how the jti ledger
    silently fell back to memory. Adding a fourth backend to the guard means
    adding it here.

    Atomicity comes from the database, not from application logic. Every
    backend enforces the composite primary key, so a duplicate INSERT is a
    constraint violation rather than a read-then-write race.
    """

    def __init__(self, *, dsn: str = "", db_path: str = "",
                 state_endpoint: str = "") -> None:
        if not (dsn or db_path or state_endpoint):
            raise ValueError(
                "DurableNonceStore needs one of dsn, db_path or state_endpoint; "
                "an unconfigured durable store would be an in-memory store "
                "wearing the durable name"
            )
        self._dsn = dsn
        self._db_path = db_path
        from remora.persistence.sqlite_path import refuse_memory_db
        refuse_memory_db(db_path, what="lease nonce ledger")
        self._state_endpoint = state_endpoint
        self._ready = False

    # ── backend plumbing ────────────────────────────────────────────────────

    def _connect(self) -> Any:
        if self._dsn:
            import psycopg
            return psycopg.connect(self._dsn)
        if self._db_path:
            import sqlite3
            return sqlite3.connect(self._db_path)
        from remora.persistence import d1_connection
        return d1_connection.connect(self._state_endpoint or None)

    def _placeholder(self) -> str:
        return "%s" if self._dsn else "?"

    def _is_duplicate(self, exc: BaseException) -> bool:
        """Did this failure mean 'already consumed' rather than 'unknown'?

        Read from the message rather than the exception type because the three
        backends raise three different types, and D1 surfaces the constraint
        violation through its transport error. Anything not recognised as a
        uniqueness violation is treated as unknown, which fails closed.
        """
        text = str(exc).lower()
        return (
            "unique" in text
            or "duplicate key" in text
            or "primary key" in text
            or "constraint failed" in text
        )

    def _ensure_table(self, conn: Any) -> None:
        if self._ready:
            return
        conn.execute(_CREATE)
        conn.commit()
        self._ready = True

    # ── the interface ───────────────────────────────────────────────────────

    def try_consume(self, nonce: str, *, tenant_id: str) -> bool:
        if not nonce:
            raise ValueError("refusing to consume an empty nonce")
        if not tenant_id:
            # An empty tenant would put every unattributed lease in one shared
            # namespace, which is a cross-tenant collision waiting to happen.
            raise ValueError("refusing to consume a nonce with no tenant scope")
        sql = (
            "INSERT INTO lease_nonce_consumed (tenant_id, nonce) VALUES "
            f"({self._placeholder()}, {self._placeholder()})"
        )
        # Only the INSERT can mean "already consumed". _connect() and
        # _ensure_table() failing tells us nothing about the row, and the
        # message sniff is a message sniff: an I/O error whose text mentions
        # a key or a constraint used to be read as a duplicate here, which
        # returns False, which the dispatcher refuses permanently as
        # nonce_already_consumed. That destroys an unspent grant on a
        # transient fault, the exact outcome this handler exists to prevent.
        try:
            with self._connect() as conn:
                self._ensure_table(conn)
                try:
                    conn.execute(sql, (tenant_id, nonce))
                    conn.commit()
                except Exception as exc:
                    if not self._is_duplicate(exc):
                        raise
                    # End the failed transaction before the context manager's
                    # exit commits: on psycopg the failed statement aborted it.
                    conn.rollback()
                    return False
        except NonceStoreUnavailable:
            raise
        except Exception as exc:
            # Anything reaching here is an unknown outcome. The caller must
            # refuse WITHOUT burning the nonce: the grant may still be
            # unspent, and destroying it would turn a transient fault into a
            # permanently dead authorization.
            raise NonceStoreUnavailable(
                f"lease nonce store unreachable: {exc}"
            ) from exc
        return True

    def consumed(self, nonce: str, *, tenant_id: str) -> bool:
        """Whether (tenant_id, nonce) has been consumed. Never consumes.

        The effect domain's question (NTA-2 phase 3): a lease whose nonce was
        never consumed was never dispatched, so no execution exists for
        effects to belong to. Raises ``NonceStoreUnavailable`` when it cannot
        tell; an unknown answer is not a "no".
        """
        ph = self._placeholder()
        sql = ("SELECT 1 FROM lease_nonce_consumed WHERE tenant_id = "
               f"{ph} AND nonce = {ph}")
        try:
            with self._connect() as conn:
                self._ensure_table(conn)
                row = conn.execute(sql, (tenant_id, nonce)).fetchone()
        except Exception as exc:
            raise NonceStoreUnavailable(str(exc)) from exc
        return row is not None

    def consumed_count(self, *, tenant_id: str) -> int:
        """Rows for one tenant. For operator verification, not for decisions.

        Every backend hands the row back positionally: sqlite3 and psycopg
        return tuples by default, and ``D1Connection.fetchone()`` converts
        its dict rows (tests/test_d1_connection.py pins that). The count is
        therefore read as ``row[0]`` and the column carries no alias.
        """
        sql = (
            "SELECT COUNT(*) FROM lease_nonce_consumed WHERE tenant_id = "
            f"{self._placeholder()}"
        )
        try:
            with self._connect() as conn:
                self._ensure_table(conn)
                row = conn.execute(sql, (tenant_id,)).fetchone()
        except Exception as exc:
            raise NonceStoreUnavailable(str(exc)) from exc
        if row is None:
            return 0
        return int(row[0])

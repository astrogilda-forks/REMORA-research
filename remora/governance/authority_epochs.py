# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Durable authority epochs for WS1-M4 admission (M4.1b).

A WS1 receipt records the epoch its subject stood at when the evidence was
read (``remora/verification/receipts.py``). A revocation of that subject, of
an evidence source, a resource or a policy, advances the epoch. Admission
reads the current epoch under lock in its own transaction and refuses a
receipt from an older epoch (INV-M4-02).

That ordering holds only if the revocation and the admission write and read
the same row in one serializable domain. So the store joins the caller's
transaction when one is open, the way ``DurableRevocationStore`` does, and a
locked read outside a transaction is refused: it would lock nothing
(docs/architecture/ADR-ws1-m4-admission-topology.md, decisions 1 and 2).

Postgres and SQLite only. D1 has no interactive transaction and is refused by
the strict M4.1 profile, so this store does not offer it.

Semantics, each with a test (``tests/test_authority_epochs.py``):

durable
    an advance is committed before ``advance`` returns, unless the caller's
    transaction owns the commit.
monotone
    every advance, revocation or reinstatement, increases the epoch by one, so
    a receipt read before it never matches again.
fail closed
    an unreachable store raises ``AuthorityEpochsUnavailable``. Unknown is never
    reported as "epoch 0, not revoked".
tenant scoped
    the primary key is (tenant_id, subject_key).
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from remora.errors import RemoraError

__all__ = ["AuthorityEpochs", "AuthorityEpochsUnavailable"]

_CREATE = (
    "CREATE TABLE IF NOT EXISTS authority_revision ("
    "tenant_id TEXT NOT NULL, subject_key TEXT NOT NULL, "
    "epoch BIGINT NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE, "
    "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
    "PRIMARY KEY (tenant_id, subject_key))"
)


class AuthorityEpochsUnavailable(RemoraError, RuntimeError):
    """The epoch store could not answer. Admission must refuse, not guess."""

    reason_code = "authority_epochs_unavailable"


class AuthorityEpochs:
    """Per-subject authority epochs over Postgres (``dsn``) or SQLite (``db_path``)."""

    def __init__(self, *, dsn: str = "", db_path: str = "",
                 connection_provider: Callable[[], Any] | None = None) -> None:
        if bool(dsn) == bool(db_path):
            raise ValueError("AuthorityEpochs needs exactly one of dsn or db_path")
        from remora.persistence.sqlite_path import refuse_memory_db
        refuse_memory_db(db_path, what="authority epoch store")
        self._dsn = dsn
        self._db_path = db_path
        #: Returns the caller's in-flight transaction connection, or None.
        self._connection_provider = connection_provider

    # ── backend plumbing ────────────────────────────────────────────────────

    def _ambient(self) -> Any:
        return None if self._connection_provider is None else self._connection_provider()

    def _connect(self) -> Any:
        if self._dsn:
            import psycopg
            return psycopg.connect(self._dsn)
        import sqlite3
        return sqlite3.connect(self._db_path)

    def _ph(self) -> str:
        return "%s" if self._dsn else "?"

    def _run(self, work: Callable[[Any], Any]) -> Any:
        try:
            ambient = self._ambient()
            if ambient is not None:
                # The caller's transaction owns the commit.
                ambient.execute(_CREATE)
                return work(ambient)
            conn = self._connect()
            try:
                conn.execute(_CREATE)
                out = work(conn)
                conn.commit()
                return out
            except BaseException:
                conn.rollback()
                raise
            finally:
                conn.close()
        except (ValueError, AuthorityEpochsUnavailable):
            raise
        except Exception as exc:
            raise AuthorityEpochsUnavailable(
                f"authority epoch store unreachable: {exc}") from exc

    # ── the interface ───────────────────────────────────────────────────────

    def advance(self, subject_key: str, *, tenant_id: str, revoked: bool) -> int:
        """Move ``subject_key`` to its next epoch and return it.

        ``revoked=True`` revokes the subject; ``revoked=False`` reinstates it.
        Both advance the epoch, so evidence read before either no longer
        matches.
        """
        _require_scope(subject_key, tenant_id)
        # Only the dialect placeholder (? or %s) is interpolated into the SQL
        # below; every value is a bound parameter.
        ph = self._ph()
        upsert = (
            "INSERT INTO authority_revision (tenant_id, subject_key, epoch, revoked) "  # noqa: S608
            f"VALUES ({ph}, {ph}, 1, {ph}) "
            "ON CONFLICT (tenant_id, subject_key) DO UPDATE SET "
            "epoch = authority_revision.epoch + 1, revoked = excluded.revoked, "
            "updated_at = CURRENT_TIMESTAMP")
        select = (f"SELECT epoch FROM authority_revision WHERE tenant_id = {ph} "  # noqa: S608
                  f"AND subject_key = {ph}")

        def work(conn: Any) -> int:
            conn.execute(upsert, (tenant_id, subject_key, bool(revoked)))
            return int(conn.execute(select, (tenant_id, subject_key)).fetchone()[0])

        return int(self._run(work))

    def read(self, subject_keys: Iterable[str], *, tenant_id: str,
             lock: bool = False) -> dict[str, tuple[int, bool]]:
        """``{subject: (epoch, revoked)}``; a subject never advanced is ``(0, False)``.

        ``lock=True`` is for admission: it must run inside the caller's
        transaction, where Postgres holds the rows ``FOR UPDATE`` and SQLite
        already holds its exclusive lock. Outside one it raises, because a lock
        that ends with the read protects nothing.
        """
        keys = sorted(set(subject_keys))  # one lock order, so no deadlock cycle
        for key in keys:
            _require_scope(key, tenant_id)
        if lock and self._ambient() is None:
            raise ValueError("a locked epoch read must run inside the admission transaction")
        if not keys:
            return {}
        ph = self._ph()  # placeholders only, as in advance(); the keys are bound
        sql = (f"SELECT subject_key, epoch, revoked FROM authority_revision "  # noqa: S608
               f"WHERE tenant_id = {ph} AND subject_key IN ({', '.join([ph] * len(keys))}) "
               "ORDER BY subject_key")
        if lock and self._dsn:
            sql += " FOR UPDATE"

        def work(conn: Any) -> dict[str, tuple[int, bool]]:
            rows = conn.execute(sql, (tenant_id, *keys)).fetchall()
            found = {str(r[0]): (int(r[1]), bool(r[2])) for r in rows}
            return {k: found.get(k, (0, False)) for k in keys}

        result: dict[str, tuple[int, bool]] = self._run(work)
        return result


def _require_scope(subject_key: str, tenant_id: str) -> None:
    if not subject_key or not subject_key.strip():
        raise ValueError("an authority epoch needs a subject")
    if not tenant_id or not tenant_id.strip():
        raise ValueError("an authority epoch needs a tenant scope")

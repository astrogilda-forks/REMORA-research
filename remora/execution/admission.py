# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1-M4 atomic admission: one transaction from evidence check to intent (M4.1c).

The redemption path checked WS1 evidence at the re-gate, spent the grant on
the gate's own connection, and recorded the dispatch intent afterwards. Each
step committed on its own, so evidence that lapsed after the re-gate still let
the call run (control 2b, ``tests/test_ws1_gate_controls.py``), and a crash
between the spend and the intent left a spent grant with nothing to dispatch.

:class:`AtomicAdmission` runs the steps the ADR fixes, in its order, inside
one ``transaction_state`` for the tenant
(docs/architecture/ADR-ws1-m4-admission-topology.md):

1. the tenant lock, which ``transaction_state`` takes on entry;
2. the database instant, read once;
3. the receipts' expiry at that instant and their authority epochs, read
   under lock;
4. the grant spend, on the same connection;
5. the dispatch intent, on the same connection;
6. commit. Any refusal or fault before it rolls every step back, so the grant
   stays unspent and no intent exists.

No network or monitor call happens inside: the WS1 lookups ran before the
transaction opened. Postgres is the reference backend and SQLite the
single-host exploratory one; the server refuses this mode on any other
backend. Authority revocations that admission must see are written through
:meth:`AtomicAdmission.advance_authority`, inside the same tenant lock, so a
revocation and an admission are strictly ordered (INV-M4-02).

What this does not establish: validity at the time the tool runs or the
downstream effect lands (AUTHORIZED_AT_COMMIT only, ADR decision 6).
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from remora.enforcement.gate import EnforcementResult
from remora.errors import RemoraError
from remora.execution.ports import Ws1OutcomePort
from remora.governance.authority_epochs import (
    MAX_CLOCK_SKEW_MS,
    AuthorityEpochs,
    AuthorityEpochsUnavailable,
)

__all__ = ["DIALECTS", "AdmissionRefused", "AdmissionResult", "AtomicAdmission",
           "ClaimLost", "db_now_ms"]

DIALECTS = ("postgres", "sqlite")

_NOW_SQL = {
    # clock_timestamp(), not now(): now() is the transaction's start, and the
    # instant that matters is the one after the tenant lock was granted.
    "postgres": "SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT",
    "sqlite": "SELECT CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER)",
}


class AdmissionRefused(RemoraError, RuntimeError):
    """Admission refused, and rolled back: no grant spent, no intent recorded."""

    code = "admission_refused"
    category = "execution"

    def __init__(self, reason: str) -> None:
        super().__init__(f"admission refused: {reason}")
        self.reason = reason


class ClaimLost(AdmissionRefused):
    """Another worker holds the intent. Rolled back like any refusal, so the
    loser has spent and asserted nothing (issue #417); not an error."""

    code = "claim_lost"

    def __init__(self) -> None:
        super().__init__("claim_lost")


@dataclass(frozen=True)
class AdmissionResult:
    gate_result: EnforcementResult
    intent: Any
    db_time_ms: int
    authority_epochs: Mapping[str, tuple[int, bool]]
    claimed: Any = None

    def audit_block(self) -> dict[str, Any]:
        return {"mode": "atomic", "db_time_ms": self.db_time_ms,
                "authority_epochs": {k: {"epoch": e, "revoked": r}
                                     for k, (e, r) in sorted(self.authority_epochs.items())}}


def db_now_ms(connection: Any, dialect: str) -> int:
    """The database's instant in epoch milliseconds, on the open connection."""
    return int(connection.execute(_NOW_SQL[dialect]).fetchone()[0])


class AtomicAdmission:
    """Admission over one tenant transaction (see the module docstring)."""

    def __init__(self, *, transaction: Callable[[str], Any],
                 connection: Callable[[], Any], epochs: AuthorityEpochs,
                 dialect: str, max_clock_skew_ms: int) -> None:
        if dialect not in DIALECTS:
            raise ValueError(f"atomic admission needs Postgres or SQLite, not {dialect!r}")
        if (isinstance(max_clock_skew_ms, bool) or not isinstance(max_clock_skew_ms, int)
                or not 0 <= max_clock_skew_ms <= MAX_CLOCK_SKEW_MS):
            raise ValueError(
                f"max_clock_skew_ms must be an int from 0 to {MAX_CLOCK_SKEW_MS}")
        self._transaction = transaction
        self._connection = connection
        self._epochs = epochs
        self._dialect = dialect
        self.max_clock_skew_ms = max_clock_skew_ms
        epochs.ensure_schema()

    def pin_epochs(self, tenant: str) -> Callable[[Sequence[str]], Mapping[str, int]]:
        """The epoch reader the WS1 re-gate calls before its lookups run.

        Unlocked and outside any transaction: these are the epochs the
        receipts record. Admission reads them again under lock.
        """
        def read(subjects: Sequence[str]) -> Mapping[str, int]:
            return {k: e for k, (e, _) in self._epochs.read(subjects, tenant_id=tenant).items()}
        return read

    def _open(self) -> Any:
        conn = self._connection()
        if conn is None:
            # The transaction ran in-process: nothing to join, so nothing
            # would be atomic. The server refuses this configuration at
            # startup; this is the second line.
            raise AdmissionRefused("admission_transaction_unavailable")
        return conn

    def advance_authority(self, tenant: str, subject_key: str, *, revoked: bool) -> int:
        """Revoke or reinstate a subject under the tenant lock admission takes."""
        with self._transaction(tenant):
            self._open()
            return self._epochs.advance(subject_key, tenant_id=tenant, revoked=revoked)

    def admit(self, tenant: str, *, ws1: Ws1OutcomePort | None,
              consume: Callable[[Any, str], EnforcementResult],
              record_intent: Callable[[], Any] | None = None,
              claim: Callable[[Any], Any] | None = None) -> AdmissionResult:
        """Check, claim, spend and record in one transaction, or raise.

        ``claim(connection)`` claims an intent that already exists, for the
        review and worker paths; ``None`` from it raises :class:`ClaimLost`.
        It runs before the spend, so a lost race spends nothing even before
        the rollback. ``consume(connection, now_iso)`` spends the grant on the
        connection at the database instant plus the declared skew.
        ``record_intent()`` writes a new dispatch intent, for the direct-ACCEPT
        path; it finds the connection through the same ambient transaction.
        """
        try:
            with self._transaction(tenant):
                conn = self._open()
                now_ms = db_now_ms(conn, self._dialect)
                epochs: Mapping[str, tuple[int, bool]] = {}
                if ws1 is not None:
                    epochs = self._epochs.read(ws1.receipt_subjects, tenant_id=tenant,
                                               lock=True)
                    refusal = ws1.admission_refusal(
                        tenant_id=tenant, now_ms=now_ms,
                        max_clock_skew_ms=self.max_clock_skew_ms, epochs=epochs)
                    if refusal is not None:
                        raise AdmissionRefused(refusal)
                # The grant is judged at the database instant plus the declared
                # skew, as the evidence is (valid_until minus the skew): its
                # expiry comes that much sooner, and an issue time stamped by
                # an application clock up to that far ahead of the database is
                # not refused as "not yet valid".
                grant_now = now_ms + self.max_clock_skew_ms
                now_iso = datetime.fromtimestamp(grant_now / 1000, UTC).isoformat()
                claimed = None
                if claim is not None:
                    claimed = claim(conn)
                    if claimed is None:
                        raise ClaimLost()
                gate_result = consume(conn, now_iso)
                if not gate_result.allowed:
                    raise AdmissionRefused(str(gate_result.reason))
                intent = record_intent() if record_intent is not None else None
                return AdmissionResult(gate_result, intent, now_ms, dict(epochs), claimed)
        except AuthorityEpochsUnavailable as exc:
            raise AdmissionRefused(exc.reason_code) from exc

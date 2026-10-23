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
6. the ``execution_admitted`` audit row, enqueued on the same connection in
   the audit outbox (REM-047);
7. commit. Any refusal or fault before it rolls every step back, so the grant
   stays unspent, no intent exists and no audit row claims otherwise
   (M4-T12).

After commit the audit outbox is drained into the tenant chain. A crash
between the commit and the drain leaves the row enqueued, and the next drain
projects it, so an admission that committed always reaches the chain.

No network or monitor call happens inside: the WS1 lookups ran before the
transaction opened. Postgres is the reference backend and SQLite the
single-host exploratory one; the server refuses this mode on any other
backend. Authority revocations that admission must see are written through
:meth:`AtomicAdmission.advance_authority`, inside the same tenant lock, so a
revocation and an admission are strictly ordered (INV-M4-02).

After commit and before the send, :meth:`AtomicAdmission.permit` repeats the
check in a short transaction of its own under the same tenant lock
(INV-M4-03, ADR decision 6): the database instant, the receipts against the
epochs, and the principals. A revocation or a lapse that committed after the
admission and before the permit refuses the attempt before anything is sent
(M4-T14). The permit also bounds the lease: it expires no later than the
evidence does, less the declared skew once for the database and once for the
executor's clock, so an executor holding it later refuses it.

What this does not establish: validity at the time the tool runs or the
downstream effect lands. A revocation after the permit check is not seen by
an executor that does not check it, so every permit says
``at_effect: NOT_ESTABLISHED`` (M4-T16). The claim is AUTHORIZED_AT_COMMIT
and, with the permit, unrevoked when the send began, on this database's
clock.
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from remora.enforcement.gate import EnforcementResult
from remora.errors import RemoraError
from remora.execution.ports import Ws1OutcomePort
from remora.governance import audit_outbox
from remora.governance.authority_epochs import (
    MAX_CLOCK_SKEW_MS,
    AuthorityEpochs,
    AuthorityEpochsUnavailable,
)

__all__ = ["DIALECTS", "AdmissionRefused", "AdmissionResult", "AtomicAdmission",
           "ClaimLost", "Permit", "db_now_ms"]

DIALECTS = ("postgres", "sqlite")

_LOGGER = logging.getLogger(__name__)

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
    #: Key of the ``execution_admitted`` row the transaction enqueued, so the
    #: ``execution_authorized`` entry written after commit joins to it.
    audit_key: str = ""

    def audit_block(self) -> dict[str, Any]:
        return {"mode": "atomic", "db_time_ms": self.db_time_ms,
                "authority_epochs": {k: {"epoch": e, "revoked": r}
                                     for k, (e, r) in sorted(self.authority_epochs.items())},
                **({"audit_key": self.audit_key} if self.audit_key else {})}


@dataclass(frozen=True)
class Permit:
    """The pre-send check of an admitted call (INV-M4-03)."""

    refusal: str | None
    db_time_ms: int
    #: The latest instant the lease may be valid to, in epoch milliseconds,
    #: or None when no evidence bounds it.
    not_after_ms: int | None = None

    @property
    def not_after(self) -> datetime | None:
        if self.not_after_ms is None:
            return None
        return datetime.fromtimestamp(self.not_after_ms / 1000, UTC)

    def audit_block(self) -> dict[str, Any]:
        return {"checked_at_db_ms": self.db_time_ms,
                **({"not_after_ms": self.not_after_ms}
                   if self.not_after_ms is not None else {}),
                **({"refusal": self.refusal} if self.refusal else {}),
                # What the permit establishes, and what it does not (M4-T16).
                "validity": "AUTHORIZED_AT_COMMIT",
                "at_effect": "NOT_ESTABLISHED"}


def db_now_ms(connection: Any, dialect: str) -> int:
    """The database's instant in epoch milliseconds, on the open connection."""
    return int(connection.execute(_NOW_SQL[dialect]).fetchone()[0])


class AtomicAdmission:
    """Admission over one tenant transaction (see the module docstring)."""

    def __init__(self, *, transaction: Callable[[str], Any],
                 connection: Callable[[], Any], epochs: AuthorityEpochs,
                 dialect: str, max_clock_skew_ms: int,
                 revocations: Any = None,
                 drain: Callable[[str], Any] | None = None) -> None:
        if dialect not in DIALECTS:
            raise ValueError(f"atomic admission needs Postgres or SQLite, not {dialect!r}")
        if (isinstance(max_clock_skew_ms, bool) or not isinstance(max_clock_skew_ms, int)
                or not 0 <= max_clock_skew_ms <= MAX_CLOCK_SKEW_MS):
            raise ValueError(
                f"max_clock_skew_ms must be an int from 0 to {MAX_CLOCK_SKEW_MS}")
        self._transaction = transaction
        self._connection = connection
        self._epochs = epochs
        #: Principal revocation (``DurableRevocationStore``), joined to the
        #: same transaction. ``revoke-principal`` writes it under the same
        #: tenant lock, so a revocation and an admission are ordered.
        self._revocations = revocations
        #: Projects committed audit-outbox rows into the chain, after commit.
        self._drain = drain
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

    def advance_authority(self, tenant: str, subject_key: str, *, revoked: bool,
                          record: Callable[[int], Any] | None = None) -> int:
        """Revoke or reinstate a subject under the tenant lock admission takes.

        ``record(epoch)`` runs in the same transaction, so the audit event of
        the change commits with it or not at all (REM-047).
        """
        with self._transaction(tenant):
            self._open()
            epoch = self._epochs.advance(subject_key, tenant_id=tenant, revoked=revoked)
            if record is not None:
                record(epoch)
            return epoch

    def admit(self, tenant: str, *, ws1: Ws1OutcomePort | None,
              consume: Callable[[Any, str], EnforcementResult],
              record_intent: Callable[[], Any] | None = None,
              claim: Callable[[Any], Any] | None = None,
              principals: Sequence[str] = (),
              audit: Mapping[str, Any] | None = None) -> AdmissionResult:
        """Check, claim, spend and record in one transaction, or raise.

        ``claim(connection)`` claims an intent that already exists, for the
        review and worker paths; ``None`` from it raises :class:`ClaimLost`.
        It runs before the spend, so a lost race spends nothing even before
        the rollback. ``consume(connection, now_iso)`` spends the grant on the
        connection at the database instant plus the declared skew.
        ``record_intent()`` writes a new dispatch intent, for the direct-ACCEPT
        path; it finds the connection through the same ambient transaction.
        ``principals`` are the identities whose authority the call rests on:
        the actor, a proposer a delegate acts for, the approver. Any of them
        revoked refuses as ``principal_revoked`` (M4-T03).
        ``audit`` is the admission's audit record; it needs ``grant_jti``,
        which keys it. It is enqueued as ``execution_admitted`` last, before
        commit, and a failure to enqueue it refuses the whole admission as
        ``audit_outbox_unavailable`` (M4-T12).
        """
        result = self._admit(tenant, ws1=ws1, consume=consume,
                             record_intent=record_intent, claim=claim,
                             principals=principals, audit=audit)
        if result.audit_key and self._drain is not None:
            try:
                self._drain(tenant)
            except Exception:
                # Committed and enqueued: the next drain projects the row.
                # Failing the admission now would misreport a spent grant.
                _LOGGER.warning("audit outbox drain after admission failed for tenant %s",
                                tenant, exc_info=True)
        return result

    def _admit(self, tenant: str, *, ws1: Ws1OutcomePort | None,
               consume: Callable[[Any, str], EnforcementResult],
               record_intent: Callable[[], Any] | None,
               claim: Callable[[Any], Any] | None,
               principals: Sequence[str],
               audit: Mapping[str, Any] | None) -> AdmissionResult:
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
                self._refuse_revoked(tenant, principals)
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
                result = AdmissionResult(gate_result, intent, now_ms, dict(epochs), claimed)
                if audit is not None:
                    result = self._enqueue_audit(conn, tenant, result, audit)
                return result
        except AuthorityEpochsUnavailable as exc:
            raise AdmissionRefused(exc.reason_code) from exc

    def permit(self, tenant: str, *, ws1: Ws1OutcomePort | None,
               principals: Sequence[str] = ()) -> Permit:
        """Check an admitted call again just before it is sent (INV-M4-03).

        Runs in its own transaction for the tenant, so it is ordered with
        every revocation written through :meth:`advance_authority` or
        ``revoke-principal``. Writes nothing. A refusal here comes after the
        grant was spent and the intent recorded: the caller settles the
        intent as refused, and nothing is sent.
        """
        try:
            with self._transaction(tenant):
                conn = self._open()
                now_ms = db_now_ms(conn, self._dialect)
                not_after: int | None = None
                if ws1 is not None:
                    epochs = self._epochs.read(ws1.receipt_subjects, tenant_id=tenant,
                                               lock=True)
                    refusal = ws1.admission_refusal(
                        tenant_id=tenant, now_ms=now_ms,
                        max_clock_skew_ms=self.max_clock_skew_ms, epochs=epochs)
                    if refusal is not None:
                        return Permit(refusal, now_ms)
                    earliest = ws1.evidence_valid_until_ms
                    if earliest is not None:
                        # Admission treats evidence as expired the skew before
                        # valid_until on the database clock. The executor
                        # judges the lease on its own clock, which may run the
                        # skew behind, so the lease ends the skew earlier again.
                        not_after = earliest - 2 * self.max_clock_skew_ms
                        if not_after <= now_ms:
                            return Permit("evidence_expires_before_dispatch", now_ms)
                try:
                    self._refuse_revoked(tenant, principals)
                except AdmissionRefused as exc:
                    return Permit(exc.reason, now_ms)
                return Permit(None, now_ms, not_after)
        except AuthorityEpochsUnavailable as exc:
            return Permit(exc.reason_code, 0)
        except AdmissionRefused as exc:
            return Permit(exc.reason, 0)

    def _enqueue_audit(self, conn: Any, tenant: str, result: AdmissionResult,
                       audit: Mapping[str, Any]) -> AdmissionResult:
        jti = str(audit.get("grant_jti") or "")
        if not jti:
            raise AdmissionRefused("admission_audit_unkeyed")
        # One admission per grant: the spend above is single-use, so the jti
        # names this event, and a replayed drain cannot append it twice.
        key = audit_outbox.encode_key(tenant, "execution_admitted", jti)
        row = result.intent if result.intent is not None else result.claimed
        outbox_id = getattr(row, "outbox_id", None)
        payload = {
            **audit, "event": "execution_admitted",
            **({"outbox_id": outbox_id} if outbox_id else {}),
            "admission": result.audit_block(),
        }
        try:
            audit_outbox.enqueue(conn, tenant=tenant, key=key, payload=payload)
        except Exception as exc:
            raise AdmissionRefused("audit_outbox_unavailable") from exc
        return AdmissionResult(result.gate_result, result.intent, result.db_time_ms,
                               result.authority_epochs, result.claimed, key)

    def _refuse_revoked(self, tenant: str, principals: Sequence[str]) -> None:
        wanted = sorted({p for p in principals if p and p.strip()})
        if not wanted:
            return
        if self._revocations is None:
            # Asked to check and unable to: refuse rather than assume.
            raise AdmissionRefused("revocation_store_unavailable")
        for principal in wanted:
            try:
                revoked = self._revocations.is_revoked(principal, tenant_id=tenant)
            except Exception as exc:
                raise AdmissionRefused("revocation_store_unavailable") from exc
            if revoked:
                raise AdmissionRefused("principal_revoked")

# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Two executors, one Postgres limit ledger (SDD unified capability execution v1.1, P0 item 8).

Until this slice the cumulative limits held on one host only: the ledger was
a SQLite file, and two hosts with separate files were two budgets. Here two
``LimitGuard`` instances, each with its own ``LimitLedger`` and its own
connections, as two executor processes would have, share one Postgres
database. The invariant is the one the SQLite ledger proves on one host: the
sum of what is reserved never passes the limit, the same operation runs once,
and an unknown outcome resolved by one executor is seen by the other.

Every test needs ``REMORA_PG_DSN`` and carries "postgres" in its name, so the
``postgres-contract`` CI job selects it and fails on a skip. Threads stand in
for processes: what is shared between them is the database and nothing else.
"""
from __future__ import annotations

import os
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

psycopg = pytest.importorskip("psycopg")
conninfo = pytest.importorskip("psycopg.conninfo")

from remora.enforcement import cumulative_limits as cl  # noqa: E402
from tests.limits.test_limits_idempotency import T0, policy, rail  # noqa: E402

BASE_DSN = os.environ.get("REMORA_PG_DSN", "")
pytestmark = pytest.mark.skipif(not BASE_DSN, reason="REMORA_PG_DSN not set")


@pytest.fixture()
def dsn():
    schema = f"limits_pg_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(BASE_DSN) as conn:
        conn.execute(f"CREATE SCHEMA {schema}")
        conn.commit()
    try:
        yield conninfo.make_conninfo(BASE_DSN, options=f"-c search_path={schema}")
    finally:
        with psycopg.connect(BASE_DSN) as conn:
            conn.execute(f"DROP SCHEMA {schema} CASCADE")
            conn.commit()


def _executor(dsn):
    """One executor: its own ledger object and connections, the shared database."""
    return cl.LimitGuard(policy(), cl.LimitLedger(dsn), evidence=rail)


def _pay(guard, op, reference, amount=7000):
    return guard.reserve(tenant="t", principal="p", tool_name="pay",
                         arguments={"payee": "acme", "amount": amount, "reference": reference},
                         operation_id=op, request_hash=f"h-{op}", now=T0)


def _reserved(dsn) -> int:
    with psycopg.connect(dsn) as conn:
        return int(conn.execute("SELECT COALESCE(SUM(amount),0) FROM limit_reservation")
                   .fetchone()[0])


def test_postgres_ledger_is_shared_and_created_once(dsn):
    with ThreadPoolExecutor(max_workers=6) as pool:
        ledgers = list(pool.map(lambda _: cl.LimitLedger(dsn), range(6)))
    assert all(ledger.shared for ledger in ledgers)
    a, b = _executor(dsn), _executor(dsn)
    assert _pay(a, "A", "INV-1") is None
    assert _pay(b, "B", "INV-2") is None
    assert _pay(a, "C", "INV-3") == cl.EXCEEDED          # a sees what b reserved
    assert _pay(b, "C", "INV-3") == cl.EXCEEDED
    assert _reserved(dsn) == 14000


def test_postgres_two_executors_racing_never_pass_the_limit(dsn):
    executors = [_executor(dsn), _executor(dsn)]
    attempts = [(executors[i % 2], f"op-{i}", f"INV-{i}") for i in range(12)]
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda t: _pay(*t), attempts))
    assert results.count(None) == 2
    assert set(results) == {None, cl.EXCEEDED}
    assert _reserved(dsn) == 14000


def test_postgres_the_same_payment_from_two_executors_runs_once(dsn):
    executors = [_executor(dsn), _executor(dsn)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda e: _pay(e[1], f"op-{e[0]}", "INV-1"),
                                enumerate(executors)))
    assert results.count(None) == 1 and set(results) == {None, cl.DUPLICATE_IN_FLIGHT}
    assert _reserved(dsn) == 7000


def test_postgres_an_unknown_outcome_on_one_executor_holds_and_resolves_on_another(dsn):
    a, b = _executor(dsn), _executor(dsn)
    assert _pay(a, "A", "INV-1") is None and a.begin("A") is None
    a.settle("A", ok=False)                                   # a crashed after the send
    assert _pay(b, "B", "INV-1") == cl.OUTCOME_UNKNOWN        # b must not pay it again
    assert [o["operation_id"] for o in b.unresolved("t")] == ["A"]
    assert b.resolve(tenant="t", operation_id="A", executed=False, resolved_by="reviewer-1",
                     evidence_ref="stmt-1") is None             # rail says: never made
    assert _pay(b, "B", "INV-1") is None                      # now it may run, once
    assert _pay(a, "C", "INV-1") == cl.DUPLICATE_IN_FLIGHT
    assert _reserved(dsn) == 7000
    [op] = b.unrecorded_resolutions("t")
    assert op["operation_id"] == "A" and op["evidence_ref"] == "stmt-1"
    a.mark_recorded("A")                                      # recorded by any executor
    assert b.unrecorded_resolutions("t") == []


def test_postgres_a_change_meter_is_busy_across_executors(dsn):
    a, b = _executor(dsn), _executor(dsn)
    move = {"unit": "AHU-1", "value": 20.0}
    assert a.reserve(tenant="t", principal="p", tool_name="move", arguments=move,
                     operation_id="A", request_hash="h", now=T0) is None
    assert b.reserve(tenant="t", principal="p", tool_name="move",
                     arguments={"unit": "AHU-1", "value": 19.5},
                     operation_id="B", request_hash="h", now=T0) == cl.RESOURCE_BUSY
    a.settle("A", ok=True)
    assert b.reserve(tenant="t", principal="p", tool_name="move",
                     arguments={"unit": "AHU-1", "value": 19.5},
                     operation_id="B", request_hash="h", now=T0) is None
    assert b.ledger.charges("B") == [("move\x1f*\x1fAHU-1", 5)]   # measured from a's 20.0


def test_postgres_an_expired_reservation_is_released_by_the_other_executor(dsn):
    a, b = _executor(dsn), _executor(dsn)
    assert a.reserve(tenant="t", principal="p", tool_name="pay",
                     arguments={"payee": "acme", "amount": 7000, "reference": "INV-1"},
                     operation_id="A", request_hash="h-A", now=T0, expires_at=T0 + 60) is None
    assert b.reserve(tenant="t", principal="p", tool_name="pay",
                     arguments={"payee": "acme", "amount": 14000, "reference": "INV-2"},
                     operation_id="B", request_hash="h-B", now=T0 + 61) is None
    assert a.begin("A") == cl.RESERVATION_RELEASED
    assert _reserved(dsn) == 14000


def test_postgres_an_older_schema_gains_the_resolution_columns(dsn):
    with psycopg.connect(dsn) as conn:
        for statement in cl._DDL:
            conn.execute(statement.replace("{REAL}", "DOUBLE PRECISION"))
        conn.commit()
    ledger = cl.LimitLedger(dsn)
    with psycopg.connect(dsn) as conn:
        columns = {r[0] for r in conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name='limit_operation'").fetchall()}
    assert {"evidence_ref", "reason", "resolved_at", "audit_recorded"} <= columns
    assert ledger.unrecorded_resolutions("t") == []

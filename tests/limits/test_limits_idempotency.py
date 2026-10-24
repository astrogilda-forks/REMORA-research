# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Cumulative limits: one operation is charged once, and only what ran stays charged.

Two weaknesses the Horizon #55 stress runs recorded, closed here:

* the same payment proposed twice was charged (and paid) twice. A tool may
  now declare ``idempotency.key_arguments``; a second call with the same key
  refuses while the first is in flight, after it ran and while its outcome
  is unknown, and runs only once the first provably did not;
* a payment that failed kept its reservation for good, so a legitimate
  retry was refused. A reservation is now returned when the call provably
  did not run (the tool raised ``ToolDidNotExecute``, the lease expired
  before the tool started, or a reviewer resolved the outcome), and held
  while the outcome is unknown.

Two more, recorded as open in NEGATIVE_RESULTS section 97 and closed here
(SDD unified capability execution v1.1, P0 items 1 and 2):

* ``ToolDidNotExecute`` freed budget on the adapter's word. Only a source
  the policy names in ``non_execution.trusted_sources`` is believed; any
  other statement holds the call as unknown;
* a reviewer's ``executed`` was taken, not checked. ``resolve`` asks the
  guard's evidence checker and refuses without one, when it cannot answer
  and when it disagrees;
* under ``require_keys`` a metered write tool without an idempotency key
  refuses, so no deployment can charge one payment twice by declaring none.
"""
from __future__ import annotations

import os
import uuid
from types import SimpleNamespace

import pytest

from remora.enforcement import cumulative_limits as cl
from remora.enforcement.lease import ToolDidNotExecute
from remora.execution.outcome import DispatchOutcome, classify_outcome

T0 = 1_800_000_000.0
METERS = {
    "pay": [{"quantity": "spend", "kind": "sum", "argument": "amount", "unit": "JPY"}],
    "move": [{"quantity": "movement", "kind": "change", "argument": "value", "scale": 10,
              "unit": "degC", "resource_argument": "unit"}],
}
LIMITS = [
    {"limit_id": "spend", "tenant": "t", "quantity": "spend", "unit": "JPY", "max": 20000,
     "principal": "p"},
    {"limit_id": "move", "tenant": "t", "quantity": "movement", "unit": "degC", "max": 20,
     "principal": "*", "resource": "*"},
]
IDEMPOTENCY = {"pay": {"key_arguments": ["payee", "amount", "reference"]}}
TRUSTED = {"pay": {"trusted_sources": ["rail"]}}

#: What the rail says about each operation when a reviewer resolves it.
RAIL_SAYS: dict[str, bool] = {}


def rail(tenant, operation, evidence_ref):
    """The evidence checker of the fixture guard: ``RAIL_SAYS[operation_id]``."""
    return {"executed": RAIL_SAYS.get(operation["operation_id"], False)}


def policy(idempotency=IDEMPOTENCY, **changes):
    data = {"schema": cl.SCHEMA, "meters": METERS, "limits": LIMITS,
            "baselines": [{"tenant": "t", "quantity": "movement", "resource": "AHU-1",
                           "value": 19.0, "seed_id": "s1"}],
            "non_execution": TRUSTED}
    if idempotency is not None:
        data["idempotency"] = idempotency
    data.update(changes)
    return cl.LimitPolicy.from_dict(data)


BASE_DSN = os.environ.get("REMORA_PG_DSN", "")


@pytest.fixture(params=["sqlite", pytest.param("postgres", marks=pytest.mark.skipif(
    not BASE_DSN, reason="REMORA_PG_DSN not set"))])
def ledger(request, tmp_path):
    """The same ledger contract on a SQLite file and, with a DSN, on Postgres.

    Each Postgres test gets its own schema, so a shared service never carries
    one test's reservations into the next.
    """
    if request.param == "sqlite":
        yield cl.LimitLedger(tmp_path / "ledger.db")
        return
    psycopg = pytest.importorskip("psycopg")
    conninfo = pytest.importorskip("psycopg.conninfo")
    schema = f"limits_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(BASE_DSN) as conn:
        conn.execute(f"CREATE SCHEMA {schema}")
        conn.commit()
    try:
        yield cl.LimitLedger(conninfo.make_conninfo(BASE_DSN, options=f"-c search_path={schema}"))
    finally:
        with psycopg.connect(BASE_DSN) as conn:
            conn.execute(f"DROP SCHEMA {schema} CASCADE")
            conn.commit()


@pytest.fixture()
def guard(ledger):
    RAIL_SAYS.clear()
    return cl.LimitGuard(policy(), ledger, evidence=rail)


def pay(guard, op, reference="INV-1", amount=7000, now=T0, expires_at=None):
    return guard.reserve(tenant="t", principal="p", tool_name="pay",
                         arguments={"payee": "acme", "amount": amount, "reference": reference},
                         operation_id=op, request_hash=f"h-{op}", now=now,
                         expires_at=expires_at)


def spent(guard) -> int:
    return sum(a for op in ("A", "B", "C", "D") for _, a in guard.ledger.charges(op))


# ── idempotency ───────────────────────────────────────────────────────────


def test_the_same_payment_in_flight_refuses_and_is_not_charged(guard):
    assert pay(guard, "A") is None
    assert pay(guard, "B") == cl.DUPLICATE_IN_FLIGHT
    assert guard.ledger.charges("B") == [] and spent(guard) == 7000


def test_the_same_payment_after_it_ran_refuses(guard):
    assert pay(guard, "A") is None
    assert guard.begin("A") is None
    guard.settle("A", ok=True)
    assert pay(guard, "B") == cl.DUPLICATE
    assert guard.preview(tenant="t", principal="p", tool_name="pay",
                         arguments={"payee": "acme", "amount": 7000,
                                    "reference": "INV-1"}) == cl.DUPLICATE


def test_the_same_payment_with_an_unknown_outcome_refuses(guard):
    assert pay(guard, "A") is None
    guard.settle("A", ok=False)
    assert pay(guard, "B") == cl.OUTCOME_UNKNOWN


def test_the_same_payment_runs_again_once_the_first_provably_did_not(guard):
    assert pay(guard, "A") is None
    guard.release("A")
    assert pay(guard, "B") is None
    assert spent(guard) == 7000


def test_another_reference_is_another_operation(guard):
    assert pay(guard, "A") is None
    assert pay(guard, "B", reference="INV-2") is None
    assert spent(guard) == 14000


def test_a_retry_of_the_same_lease_is_not_a_duplicate(guard):
    assert pay(guard, "A") is None
    assert pay(guard, "A") is None
    assert spent(guard) == 7000


@pytest.mark.parametrize("arguments", [
    {"payee": "acme", "amount": 7000},
    {"payee": "acme", "amount": 7000, "reference": ""},
    {"payee": "acme", "amount": 7000, "reference": True},
    {"payee": "acme", "amount": 7000, "reference": ["INV-1"]},
])
def test_a_payment_that_cannot_be_identified_does_not_run(guard, arguments):
    assert guard.reserve(tenant="t", principal="p", tool_name="pay", arguments=arguments,
                         operation_id="A", request_hash="h", now=T0) == \
        cl.IDEMPOTENCY_KEY_INVALID


def test_without_a_declared_key_two_calls_are_two_operations(tmp_path):
    guard = cl.LimitGuard(policy(idempotency=None), cl.LimitLedger(tmp_path / "l.db"))
    assert pay(guard, "A") is None and pay(guard, "B") is None
    assert spent(guard) == 14000


@pytest.mark.parametrize("idempotency", [
    {"refund": {"key_arguments": ["reference"]}},
    {"pay": {"key_arguments": []}},
    {"pay": {"key_arguments": ["reference", "reference"]}},
    {"pay": ["reference"]},
    ["pay"],
])
def test_a_malformed_idempotency_declaration_refuses_at_load(idempotency):
    with pytest.raises(cl.LimitPolicyError):
        policy(idempotency=idempotency)


# ── a reservation is held only while the call may have run ───────────────


def test_an_unknown_outcome_holds_the_budget_until_resolved(guard):
    assert pay(guard, "A") is None and guard.begin("A") is None
    guard.settle("A", ok=False)
    assert [o["operation_id"] for o in guard.unresolved("t")] == ["A"]
    assert pay(guard, "B", reference="INV-2", amount=14000) == cl.EXCEEDED
    assert guard.resolve(tenant="t", operation_id="A", executed=False,
                         resolved_by="reviewer-1", reason="rail: no such transfer") is None
    assert guard.unresolved("t") == []
    assert pay(guard, "B", reference="INV-2", amount=13000) is None
    assert pay(guard, "C") is None  # A's key is free again: it never ran
    assert spent(guard) == 20000


def test_an_outcome_resolved_as_executed_stays_charged_and_blocks_a_duplicate(guard):
    assert pay(guard, "A") is None and guard.begin("A") is None
    guard.settle("A", ok=False)
    RAIL_SAYS["A"] = True
    assert guard.resolve(tenant="t", operation_id="A", executed=True,
                         resolved_by="reviewer-1") is None
    assert pay(guard, "B") == cl.DUPLICATE
    assert spent(guard) == 7000


# ── the reviewer's statement is checked, not taken ────────────────────────


def test_resolving_without_an_evidence_checker_refuses_and_holds_the_budget(tmp_path):
    guard = cl.LimitGuard(policy(), cl.LimitLedger(tmp_path / "ledger.db"))
    assert pay(guard, "A") is None
    guard.settle("A", ok=False)
    assert guard.resolve(tenant="t", operation_id="A", executed=False,
                         resolved_by="reviewer-1") == cl.EVIDENCE_UNCHECKED
    assert guard.resolve(tenant="t", operation_id="A", executed=True,
                         resolved_by="reviewer-1") == cl.EVIDENCE_UNCHECKED
    assert [o["operation_id"] for o in guard.unresolved("t")] == ["A"]
    assert spent(guard) == 7000


@pytest.mark.parametrize("executed", [False, True])
def test_evidence_that_disagrees_with_the_reviewer_refuses(guard, executed):
    assert pay(guard, "A") is None
    guard.settle("A", ok=False)
    RAIL_SAYS["A"] = not executed
    assert guard.resolve(tenant="t", operation_id="A", executed=executed,
                         resolved_by="reviewer-1") == cl.EVIDENCE_DISPUTED
    assert [o["operation_id"] for o in guard.unresolved("t")] == ["A"]
    assert spent(guard) == 7000


@pytest.mark.parametrize("answer", [
    lambda t, op, ref: (_ for _ in ()).throw(ConnectionError("rail unreachable")),
    lambda t, op, ref: None,
    lambda t, op, ref: {"executed": None},
    lambda t, op, ref: {"executed": "no"},
    lambda t, op, ref: "no",
])
def test_evidence_that_cannot_be_read_refuses(tmp_path, answer):
    guard = cl.LimitGuard(policy(), cl.LimitLedger(tmp_path / "ledger.db"), evidence=answer)
    assert pay(guard, "A") is None
    guard.settle("A", ok=False)
    assert guard.resolve(tenant="t", operation_id="A", executed=False,
                         resolved_by="reviewer-1") == cl.EVIDENCE_UNAVAILABLE
    assert spent(guard) == 7000


def test_the_checker_is_asked_about_the_operation_and_the_evidence_named(tmp_path):
    asked = []

    def checker(tenant, operation, evidence_ref):
        asked.append((tenant, operation["operation_id"], operation["principal"], evidence_ref))
        return {"executed": False}
    guard = cl.LimitGuard(policy(), cl.LimitLedger(tmp_path / "ledger.db"), evidence=checker)
    assert pay(guard, "A") is None
    guard.settle("A", ok=False)
    assert guard.resolve(tenant="t", operation_id="A", executed=False, resolved_by="reviewer-1",
                         reason="rail statement", evidence_ref="stmt-77") is None
    assert asked == [("t", "A", "p", "stmt-77")]
    with guard.ledger.transaction() as conn:
        row = cl.LimitLedger.operation(conn, "A")
    assert row["resolution"] == "not_executed (stmt-77 checked): rail statement"
    assert row["resolved_by"] == "reviewer-1"


def test_the_cheap_refusals_come_before_the_rail_is_asked(guard):
    asked = []
    guard.evidence = lambda t, op, ref: asked.append(ref) or {"executed": False}
    assert pay(guard, "A") is None
    assert guard.resolve(tenant="t", operation_id="A", executed=False,
                         resolved_by="reviewer-1") == cl.NOT_UNKNOWN
    guard.settle("A", ok=False)
    assert guard.resolve(tenant="t", operation_id="A", executed=False,
                         resolved_by="p") == cl.RESOLVER_IS_PRINCIPAL
    assert guard.resolve(tenant="other", operation_id="A", executed=False,
                         resolved_by="reviewer-1") == cl.NOT_FOUND
    assert asked == []


# ── the adapter's statement is believed only from a declared source ──────


def test_did_not_execute_from_a_trusted_source_frees_the_budget(guard):
    assert pay(guard, "A") is None and guard.begin("A") is None
    assert guard.did_not_execute("A", "pay", "rail") is True
    assert guard.unresolved("t") == [] and spent(guard) == 0
    assert pay(guard, "B") is None   # the same payment may be made now


@pytest.mark.parametrize("source", ["adapter", "", "RAIL"])
def test_did_not_execute_from_any_other_source_holds_the_call_as_unknown(guard, source):
    assert pay(guard, "A") is None and guard.begin("A") is None
    assert guard.did_not_execute("A", "pay", source) is False
    assert [o["operation_id"] for o in guard.unresolved("t")] == ["A"]
    assert pay(guard, "B") == cl.OUTCOME_UNKNOWN
    assert spent(guard) == 7000


def test_a_tool_with_no_trusted_source_never_frees_on_the_adapters_word(tmp_path):
    guard = cl.LimitGuard(policy(non_execution={}), cl.LimitLedger(tmp_path / "ledger.db"))
    assert pay(guard, "A") is None
    assert guard.did_not_execute("A", "pay", "rail") is False
    assert spent(guard) == 7000


def test_an_untrusted_statement_about_a_change_leaves_the_resource_unknown(guard):
    move = {"unit": "AHU-1", "value": 20.0}
    assert guard.reserve(tenant="t", principal="p", tool_name="move", arguments=move,
                         operation_id="A", request_hash="h", now=T0) is None
    assert guard.did_not_execute("A", "move", "controller") is False
    assert guard.reserve(tenant="t", principal="p", tool_name="move",
                         arguments={"unit": "AHU-1", "value": 19.5},
                         operation_id="B", request_hash="h", now=T0) == cl.BASELINE_UNKNOWN


@pytest.mark.parametrize("non_execution", [
    [], {"nope": {"trusted_sources": ["rail"]}}, {"pay": {"trusted_sources": []}},
    {"pay": {"trusted_sources": ["rail", "rail"]}}, {"pay": {"trusted_sources": [1]}},
    {"pay": ["rail"]}, {"pay": {"trusted_sources": ""}},
])
def test_a_malformed_non_execution_declaration_refuses_at_load(non_execution):
    with pytest.raises(cl.LimitPolicyError):
        policy(non_execution=non_execution)


# ── a metered write tool needs a key under require_keys ───────────────────


def _keyed(tmp_path, is_write, idempotency=None):
    return cl.LimitGuard(policy(idempotency=idempotency),
                         cl.LimitLedger(tmp_path / "ledger.db"), is_write=is_write,
                         require_keys=True)


def test_require_keys_refuses_a_metered_write_tool_without_a_key(tmp_path):
    guard = _keyed(tmp_path, lambda tool: True)
    assert pay(guard, "A") == cl.KEY_UNDECLARED
    assert guard.preview(tenant="t", principal="p", tool_name="pay",
                         arguments={"payee": "acme", "amount": 7000,
                                    "reference": "INV-1"}) == cl.KEY_UNDECLARED
    assert spent(guard) == 0


def test_require_keys_lets_a_keyed_tool_and_a_read_tool_run(tmp_path):
    guard = _keyed(tmp_path, lambda tool: tool != "pay", idempotency=IDEMPOTENCY)
    assert pay(guard, "A") is None
    guard = _keyed(tmp_path, lambda tool: False)   # a metered tool the deployment calls a read
    assert pay(guard, "B", reference="INV-2") is None


@pytest.mark.parametrize("is_write", [None, lambda tool: None,
                                      lambda tool: (_ for _ in ()).throw(RuntimeError("x"))])
def test_require_keys_refuses_a_tool_whose_kind_it_cannot_read(tmp_path, is_write):
    assert pay(_keyed(tmp_path, is_write), "A") == cl.COVERAGE_UNKNOWN


def test_without_require_keys_an_unkeyed_write_tool_runs_as_before(tmp_path):
    guard = cl.LimitGuard(policy(idempotency=None), cl.LimitLedger(tmp_path / "ledger.db"),
                          is_write=lambda tool: True)
    assert pay(guard, "A") is None


@pytest.mark.parametrize("tenant, op, by, want", [
    ("t", "A", "p", cl.RESOLVER_IS_PRINCIPAL),       # the agent cannot free its own budget
    ("t", "A", "", cl.RESOLVER_IS_PRINCIPAL),
    ("other", "A", "reviewer-1", cl.NOT_FOUND),       # another tenant's operation
    ("t", "Z", "reviewer-1", cl.NOT_FOUND),
])
def test_resolving_is_refused_to_the_wrong_party(guard, tenant, op, by, want):
    assert pay(guard, "A") is None
    guard.settle("A", ok=False)
    assert guard.resolve(tenant=tenant, operation_id=op, executed=False, resolved_by=by) == want
    assert spent(guard) == 7000


@pytest.mark.parametrize("state", ["reserved", "settled", "released"])
def test_only_an_unknown_outcome_can_be_resolved(guard, state):
    assert pay(guard, "A") is None
    if state == "settled":
        guard.settle("A", ok=True)
    if state == "released":
        guard.release("A")
    assert guard.resolve(tenant="t", operation_id="A", executed=False,
                         resolved_by="reviewer-1") == cl.NOT_UNKNOWN


def test_a_lease_that_expired_before_the_tool_started_gives_its_reservation_back(guard):
    assert pay(guard, "A", expires_at=T0 + 120) is None
    # The next reservation after expiry releases it, and A can no longer start.
    assert pay(guard, "B", reference="INV-2", amount=14000, now=T0 + 121) is None
    assert guard.begin("A") == cl.RESERVATION_RELEASED
    assert pay(guard, "A", now=T0 + 122) == cl.RESERVATION_RELEASED
    assert spent(guard) == 14000


def test_a_started_operation_is_never_released_by_time(guard):
    assert pay(guard, "A", expires_at=T0 + 120) is None
    assert guard.begin("A") is None
    assert pay(guard, "B", reference="INV-2", amount=14000, now=T0 + 10_000) == cl.EXCEEDED


def test_resolving_a_change_puts_the_value_back(guard):
    move = {"unit": "AHU-1", "value": 20.0}
    assert guard.reserve(tenant="t", principal="p", tool_name="move", arguments=move,
                         operation_id="A", request_hash="h", now=T0) is None
    guard.settle("A", ok=False)                        # the controller did not answer
    nxt = {"unit": "AHU-1", "value": 19.5}
    assert guard.reserve(tenant="t", principal="p", tool_name="move", arguments=nxt,
                         operation_id="B", request_hash="h", now=T0) == cl.BASELINE_UNKNOWN
    assert guard.resolve(tenant="t", operation_id="A", executed=False,
                         resolved_by="reviewer-1") is None
    # Measured from 19.0 again: 0.5, not from the unwritten 20.0.
    assert guard.reserve(tenant="t", principal="p", tool_name="move", arguments=nxt,
                         operation_id="B", request_hash="h", now=T0) is None
    assert guard.ledger.charges("B") == [("move\x1f*\x1fAHU-1", 5)]


# ── the dispatcher and the outcome ────────────────────────────────────────


def _dispatcher(guard):
    from remora.enforcement.lease import GovernedToolDispatcher

    d = GovernedToolDispatcher.__new__(GovernedToolDispatcher)
    d._limit_guard = guard
    return d


def _lease(nonce):
    return SimpleNamespace(tenant_id="t", actor_identity="p", nonce=nonce, expires_at=None,
                           tool_args_hash="h" * 64, proposal_id="prop")


@pytest.mark.parametrize("source, detail", [("", "refused"), ("rail", "")])
def test_tool_did_not_execute_needs_its_evidence(source, detail):
    with pytest.raises(ValueError):
        raise ToolDidNotExecute(source, detail)


def test_the_dispatcher_begin_refuses_a_released_reservation(guard):
    d = _dispatcher(guard)
    args = {"payee": "acme", "amount": 7000, "reference": "INV-1"}
    assert d._limit_refusal(_lease("n1"), "pay", args, args, None) is None
    assert d._limit_begin(_lease("n1"), "pay") is None
    assert d._limit_begin(_lease("n0"), "unmetered") is None
    guard.ledger.release("lease:n1")
    assert d._limit_begin(_lease("n1"), "pay") == cl.RESERVATION_RELEASED


def test_the_adapters_statement_frees_budget_but_decides_no_outcome():
    """A trusted ToolDidNotExecute frees the budget; the outcome record stays UNKNOWN (CAP-013)."""
    began = {"executed": False, "dispatch_began": True,
             "refusal_reason": "tool_did_not_execute"}
    assert classify_outcome(began) is DispatchOutcome.UNKNOWN


def test_the_dispatcher_releases_or_holds_by_the_statements_source(guard):
    d = _dispatcher(guard)
    args = {"payee": "acme", "amount": 7000, "reference": "INV-1"}
    assert d._limit_refusal(_lease("n1"), "pay", args, args, None) is None
    assert d._limit_did_not_execute(_lease("n1"), "pay", "rail") == "released"
    assert d._limit_refusal(_lease("n2"), "pay", args, args, None) is None
    assert d._limit_did_not_execute(_lease("n2"), "pay", "adapter") == "held"
    assert d._limit_did_not_execute(_lease("n0"), "unmetered", "rail") == "none"
    assert [o["operation_id"] for o in guard.unresolved("t")] == ["lease:n2"]


def test_a_ledger_that_fails_on_the_statement_holds(guard, monkeypatch):
    d = _dispatcher(guard)
    args = {"payee": "acme", "amount": 7000, "reference": "INV-1"}
    assert d._limit_refusal(_lease("n1"), "pay", args, args, None) is None
    monkeypatch.setattr(guard, "did_not_execute",
                        lambda *a: (_ for _ in ()).throw(RuntimeError("disk")))
    assert d._limit_did_not_execute(_lease("n1"), "pay", "rail") == "held"
    assert spent(guard) == 0 and guard.ledger.charges("lease:n1") != []


# ── the resolution is the ledger's record; the chain is its projection ───


def test_a_resolution_is_unrecorded_until_the_chain_carries_it(guard):
    assert pay(guard, "A") is None
    guard.settle("A", ok=False)
    assert guard.unrecorded_resolutions("t") == []
    assert guard.resolve(tenant="t", operation_id="A", executed=False, resolved_by="reviewer-1",
                         reason="no transfer", evidence_ref="stmt-1") is None
    [op] = guard.unrecorded_resolutions("t")
    assert (op["operation_id"], op["resolved_by"], op["evidence_ref"], op["reason"]) == \
        ("A", "reviewer-1", "stmt-1", "no transfer")
    assert op["resolution"].startswith("not_executed") and op["resolved_at"] > 0
    assert guard.unrecorded_resolutions("other") == []
    guard.mark_recorded("A")
    assert guard.unrecorded_resolutions("t") == []


def test_an_older_ledger_gains_the_resolution_columns_on_open(tmp_path):
    """A ledger file created before these columns existed opens and keeps its rows."""
    import sqlite3

    path = tmp_path / "old.db"
    with sqlite3.connect(path) as conn:
        conn.executescript("""
            CREATE TABLE limit_operation (
                operation_id TEXT PRIMARY KEY, tenant TEXT NOT NULL, principal TEXT NOT NULL,
                tool TEXT NOT NULL, op_key TEXT, state TEXT NOT NULL, expires_at REAL,
                at REAL NOT NULL, resolved_by TEXT, resolution TEXT);
            INSERT INTO limit_operation VALUES('old','t','p','pay',NULL,'unknown',NULL,1.0,
                                               NULL,NULL);
        """)
    ledger = cl.LimitLedger(path)
    with ledger.transaction() as conn:
        row = cl.LimitLedger.operation(conn, "old")
    assert row["state"] == "unknown" and row["audit_recorded"] == 0
    assert row["evidence_ref"] is None and row["resolved_at"] is None
    assert ledger.unrecorded_resolutions("t") == []   # never resolved, so nothing to record
    cl.LimitLedger(path)                              # a second open is a no-op

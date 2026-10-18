# SPDX-License-Identifier: BUSL-1.1
"""IFC-02: flow contexts, the high-water label and conditional append.

Every behaviour runs on each backend the loop-safety store admits:
- in-process;
- SQLite;
- D1, through a double that runs the SQL on a real SQLite database;
- Postgres, when ``REMORA_PG_DSN`` is set (the CI Postgres job).

Acceptance (SDD v1.3 §4, IFC-02):
- append-only: no API lowers a label;
- a loop-safety reset leaves the flow label unchanged;
- a fork inherits the label and shares the root ledger;
- concurrent ``append_if`` on one ``expected_seq`` has exactly one winner on
  every backend;
- an unreachable store raises ``FlowStoreUnavailable``;
- a foreign tenant or principal is refused.
"""
from __future__ import annotations

import os
import re
import sqlite3
import threading
import uuid

import pytest

from remora.flow.context import (
    DurableFlowEventStore,
    FlowContextStore,
    FlowContextUnknown,
    FlowEvent,
    FlowInvariantViolation,
    FlowStoreUnavailable,
    InMemoryFlowEventStore,
    ProcessingNotAuthorized,
    ProcessingPolicy,
    fold,
    new_context_id,
)
from remora.flow.label import BOTTOM, PUBLIC, Integrity, Label
from remora.persistence import d1_connection as d1

TENANT, OTHER_TENANT = "t1", "t2"
ALICE, BOB = "user:alice", "user:bob"
USER = "user://t1/alice"
MODEL = "ext://api.provider.example"
LOCAL_Q = "res://t1/extractor"
POLICY = ProcessingPolicy.from_mapping({
    TENANT: {"default": [MODEL, LOCAL_Q]},
    OTHER_TENANT: {"default": [MODEL]},
})
SECRET = Label([USER, MODEL], Integrity.UNTRUSTED)


class SqliteD1:
    """A D1 endpoint double: statements run on a real SQLite database."""

    def __init__(self) -> None:
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.lock = threading.Lock()
        self.down = False

    def post(self, statements, url=None):
        if self.down:
            raise d1.D1Unavailable("state store unreachable: injected outage")
        out = []
        with self.lock:
            try:
                for st in statements:
                    cur = self.conn.execute(st["sql"], st.get("params") or [])
                    cols = [c[0] for c in (cur.description or [])]
                    out.append([dict(zip(cols, row, strict=True)) for row in cur.fetchall()])
                self.conn.commit()
            except sqlite3.Error as exc:
                self.conn.rollback()
                raise d1.D1Unavailable(f"state store refused: {exc}") from exc
        return out


def _postgres_store():
    dsn = os.environ.get("REMORA_PG_DSN", "").strip()
    if not dsn:
        pytest.skip("REMORA_PG_DSN not set; the Postgres flow store runs in the CI Postgres job")
    return DurableFlowEventStore(dsn=dsn)


@pytest.fixture(params=["memory", "sqlite", "d1", "postgres"])
def backend(request, tmp_path, monkeypatch):
    if request.param == "memory":
        return InMemoryFlowEventStore()
    if request.param == "sqlite":
        return DurableFlowEventStore(db_path=str(tmp_path / "flow.db"))
    if request.param == "d1":
        fake = SqliteD1()
        monkeypatch.setattr(d1, "_post", fake.post)
        store = DurableFlowEventStore(state_endpoint="https://d1.example/state")
        store._fake = fake  # type: ignore[attr-defined]
        return store
    return _postgres_store()


def _contexts(backend) -> FlowContextStore:
    return FlowContextStore(backend, POLICY)


def _mint(store: FlowContextStore, tenant: str = TENANT, principal: str = ALICE, **kw):
    return store.mint(tenant, principal, user_principal=USER, model_principal=MODEL, **kw)


# ── minting ──────────────────────────────────────────────────────────────


def test_postgres_and_every_backend_mint_a_fresh_bottom_context(backend):
    store = _contexts(backend)
    state = _mint(store)
    assert re.fullmatch(r"ctx_[a-z2-7]{26}", state.context_id)
    assert state.label == BOTTOM and state.epoch == 0 and state.seq == 1
    assert state.root_context_id == state.context_id
    assert state.processors == frozenset({MODEL})
    assert _mint(store).context_id != state.context_id


def test_new_context_ids_carry_128_random_bits():
    ids = {new_context_id() for _ in range(2000)}
    assert len(ids) == 2000


def test_an_unauthorized_processor_cannot_mint():
    store = _contexts(InMemoryFlowEventStore())
    with pytest.raises(ProcessingNotAuthorized):
        store.mint(TENANT, ALICE, user_principal=USER, model_principal="ext://other.example")
    with pytest.raises(ProcessingNotAuthorized):
        store.mint(TENANT, ALICE, user_principal=USER, model_principal=MODEL,
                   q_principal="ext://other.example")
    with pytest.raises(ProcessingNotAuthorized):
        FlowContextStore(InMemoryFlowEventStore(), ProcessingPolicy()).mint(
            TENANT, ALICE, user_principal=USER, model_principal=MODEL)


def test_ambiguous_principals_are_refused():
    store = _contexts(InMemoryFlowEventStore())
    with pytest.raises(ValueError):
        store.mint(TENANT, ALICE, user_principal="mailto:alice@x.example", model_principal=MODEL)


# ── the label only rises ─────────────────────────────────────────────────


def test_postgres_and_every_backend_raise_and_never_lower(backend):
    store = _contexts(backend)
    ctx = _mint(store)
    raised = store.raise_label(TENANT, ALICE, ctx.context_id, SECRET)
    assert raised.label == SECRET and raised.epoch == 2
    # A less restrictive label does not lower it, and appends nothing.
    again = store.raise_label(TENANT, ALICE, ctx.context_id, BOTTOM)
    assert again.label == SECRET and again.seq == raised.seq
    public_untrusted = store.raise_label(TENANT, ALICE, ctx.context_id,
                                         Label(PUBLIC, Integrity.UNTRUSTED))
    assert public_untrusted.label == SECRET


def test_no_public_api_lowers_or_resets_a_label():
    names = {n for n in dir(FlowContextStore) if not n.startswith("_")}
    assert names == {"mint", "fork", "load", "raise_label", "charge_budget", "charged"}
    assert not {n for n in dir(InMemoryFlowEventStore) if not n.startswith("_")} - {
        "append_if", "events"}


def test_a_raise_that_hides_data_from_the_model_provider_is_a_bug():
    store = _contexts(InMemoryFlowEventStore())
    ctx = _mint(store)
    with pytest.raises(FlowInvariantViolation):
        store.raise_label(TENANT, ALICE, ctx.context_id, Label([USER]))
    assert store.load(TENANT, ALICE, ctx.context_id).label == BOTTOM


def test_a_loop_safety_reset_leaves_the_flow_label_unchanged(tmp_path):
    from remora.governance.loop_safety import DurableLoopSafetyStore, LoopSafetyMonitor
    from remora.governance.task_identity import TaskIdentity

    db = str(tmp_path / "shared.db")
    contexts = FlowContextStore(DurableFlowEventStore(db_path=db), POLICY)
    ctx = _mint(contexts)
    contexts.raise_label(TENANT, ALICE, ctx.context_id, SECRET)
    monitor = LoopSafetyMonitor(DurableLoopSafetyStore(db_path=db))
    monitor.observe(TENANT, TaskIdentity(task_id="t", context_id=ctx.context_id), "read_inbox",
                    denied=True)
    monitor.reset(TENANT, ctx.context_id, policy_ref="POL-1", reason="test")
    assert contexts.load(TENANT, ALICE, ctx.context_id).label == SECRET


# ── forks and the shared ledger ──────────────────────────────────────────


def test_postgres_and_every_backend_fork_inherits_and_shares_the_root_ledger(backend):
    store = _contexts(backend)
    root = _mint(store)
    store.raise_label(TENANT, ALICE, root.context_id, SECRET)
    child = store.fork(TENANT, ALICE, root.context_id)
    assert child.label == SECRET
    assert child.root_context_id == root.context_id and child.parent_context_id == root.context_id
    grandchild = store.fork(TENANT, ALICE, child.context_id)
    assert grandchild.root_context_id == root.context_id
    assert store.charge_budget(TENANT, ALICE, grandchild.context_id, key="k", bits=5) == 5
    assert store.charge_budget(TENANT, ALICE, child.context_id, key="k", bits=3) == 8
    assert store.charged(TENANT, ALICE, root.context_id, "k") == 8
    # A raise in the child does not lower or touch the parent.
    store.raise_label(TENANT, ALICE, child.context_id, Label([USER, MODEL]))
    assert store.load(TENANT, ALICE, root.context_id).label == SECRET


def test_a_fork_cannot_hand_the_label_to_a_provider_that_may_not_read_it():
    policy = ProcessingPolicy.from_mapping({TENANT: {"default": [MODEL, "ext://second.example"]}})
    store = FlowContextStore(InMemoryFlowEventStore(), policy)
    root = _mint(store)
    store.raise_label(TENANT, ALICE, root.context_id, SECRET)
    with pytest.raises(ProcessingNotAuthorized):
        store.fork(TENANT, ALICE, root.context_id, model_principal="ext://second.example")


def test_a_charge_is_never_negative():
    store = _contexts(InMemoryFlowEventStore())
    ctx = _mint(store)
    with pytest.raises(ValueError):
        store.charge_budget(TENANT, ALICE, ctx.context_id, key="k", bits=-1)


# ── scope ────────────────────────────────────────────────────────────────


def test_postgres_and_every_backend_refuse_foreign_tenant_and_principal(backend):
    store = _contexts(backend)
    ctx = _mint(store)
    with pytest.raises(FlowContextUnknown):
        store.load(OTHER_TENANT, ALICE, ctx.context_id)
    with pytest.raises(FlowContextUnknown):
        store.load(TENANT, BOB, ctx.context_id)
    with pytest.raises(FlowContextUnknown):
        store.raise_label(TENANT, BOB, ctx.context_id, SECRET)
    with pytest.raises(FlowContextUnknown):
        store.fork(TENANT, BOB, ctx.context_id)
    with pytest.raises(FlowContextUnknown):
        store.load(TENANT, ALICE, "ctx_" + "a" * 26)


# ── conditional append ───────────────────────────────────────────────────


def test_postgres_and_every_backend_have_exactly_one_winner(backend):
    context_id = f"ctx_race_{uuid.uuid4().hex[:8]}"
    assert backend.append_if(tenant_id=TENANT, context_id=context_id, expected_seq=0,
                             event=FlowEvent("fork", {"x": 0}))
    n = 8
    barrier = threading.Barrier(n)
    results: list[bool] = []
    lock = threading.Lock()

    def writer(i: int) -> None:
        barrier.wait()
        won = backend.append_if(tenant_id=TENANT, context_id=context_id, expected_seq=1,
                                event=FlowEvent("raise", {"i": i}))
        with lock:
            results.append(won)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [False] * (n - 1) + [True]
    events = backend.events(tenant_id=TENANT, context_id=context_id)
    assert [e.seq for e in events] == [1, 2]


def test_postgres_and_every_backend_refuse_a_stale_or_future_expected_seq(backend):
    context_id = f"ctx_seq_{uuid.uuid4().hex[:8]}"
    assert backend.append_if(tenant_id=TENANT, context_id=context_id, expected_seq=0,
                             event=FlowEvent("fork", {}))
    assert not backend.append_if(tenant_id=TENANT, context_id=context_id, expected_seq=0,
                                 event=FlowEvent("raise", {}))
    assert not backend.append_if(tenant_id=TENANT, context_id=context_id, expected_seq=5,
                                 event=FlowEvent("raise", {}))
    assert len(backend.events(tenant_id=TENANT, context_id=context_id)) == 1


# ── availability (A6) ────────────────────────────────────────────────────


def test_an_unreachable_sqlite_store_raises(tmp_path):
    store = DurableFlowEventStore(db_path=str(tmp_path / "missing-dir" / "flow.db"))
    with pytest.raises(FlowStoreUnavailable):
        store.events(tenant_id=TENANT, context_id="ctx_x")
    with pytest.raises(FlowStoreUnavailable):
        store.append_if(tenant_id=TENANT, context_id="ctx_x", expected_seq=0,
                        event=FlowEvent("fork", {}))


def test_an_unreachable_d1_store_raises(monkeypatch):
    fake = SqliteD1()
    monkeypatch.setattr(d1, "_post", fake.post)
    store = FlowContextStore(DurableFlowEventStore(state_endpoint="https://d1.example/state"),
                             POLICY)
    ctx = _mint(store)
    fake.down = True
    with pytest.raises(FlowStoreUnavailable):
        store.load(TENANT, ALICE, ctx.context_id)
    with pytest.raises(FlowStoreUnavailable):
        store.raise_label(TENANT, ALICE, ctx.context_id, SECRET)


def test_a_refused_write_with_no_winner_is_unavailable_not_lost(tmp_path, monkeypatch):
    store = DurableFlowEventStore(db_path=str(tmp_path / "flow.db"))
    store.events(tenant_id=TENANT, context_id="ctx_y")  # creates the table
    real_connect = store._connect

    class RefusesInserts:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, sql, *args):
            if sql.startswith("INSERT INTO flow_events"):
                raise sqlite3.OperationalError("disk I/O error")
            return self._conn.execute(sql, *args)

        def commit(self):
            self._conn.commit()

    from contextlib import contextmanager

    @contextmanager
    def connect():
        with real_connect() as conn:
            yield RefusesInserts(conn)

    monkeypatch.setattr(store, "_connect", connect)
    with pytest.raises(FlowStoreUnavailable):
        store.append_if(tenant_id=TENANT, context_id="ctx_y", expected_seq=0,
                        event=FlowEvent("fork", {}))


def test_a_memory_db_is_refused_as_a_durable_store():
    with pytest.raises(ValueError):
        DurableFlowEventStore(db_path=":memory:")
    with pytest.raises(ValueError):
        DurableFlowEventStore()


# ── the fold ─────────────────────────────────────────────────────────────


def test_the_fold_refuses_a_stream_it_cannot_trust():
    with pytest.raises(FlowContextUnknown):
        fold(TENANT, "ctx_z", [])
    with pytest.raises(FlowStoreUnavailable):
        fold(TENANT, "ctx_z", [FlowEvent("raise", {}, seq=1)])
    store = _contexts(InMemoryFlowEventStore())
    ctx = _mint(store)
    events = InMemoryFlowEventStore()
    first = store._store.events(tenant_id=TENANT, context_id=ctx.context_id)[0]  # type: ignore[attr-defined]
    gap = [first, FlowEvent("raise", {"label": {}}, seq=3)]
    with pytest.raises(FlowStoreUnavailable):
        fold(TENANT, ctx.context_id, gap)
    assert events.events(tenant_id=TENANT, context_id="ctx_none") == []

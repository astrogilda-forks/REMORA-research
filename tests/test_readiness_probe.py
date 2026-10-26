"""GET /v1/ready: readiness that reads the durable store, not liveness.

Fault injection on the OT pilot (2026-10-26) stopped Postgres while the API
kept answering ``/v1/health`` with ``ok``, so an orchestrator would have kept
routing writes to a process that could only refuse them. ``/v1/ready``
answers 503 ``not_ready`` while the configured durable store cannot answer,
and never puts the driver's message (which can name hosts) in the body.
"""

from __future__ import annotations

import sqlite3
import sys
import types

import pytest
from fastapi.testclient import TestClient

import servers.api as api


@pytest.fixture(autouse=True)
def _fresh_cache(monkeypatch):
    for name in ("REMORA_PG_DSN", "REMORA_CHAIN_DB", "REMORA_STATE_ENDPOINT"):
        monkeypatch.delenv(name, raising=False)
    api._reset_readiness_cache()
    yield
    api._reset_readiness_cache()


def _get(path: str = "/v1/ready"):
    return TestClient(api.app, raise_server_exceptions=False).get(path)


def test_without_a_durable_store_ready_says_it_checked_nothing():
    r = _get()
    assert r.status_code == 200
    assert r.json() == {"status": "ready", "backend": "in_process",
                        "checks": {"durable_state": "not_configured"}}


def test_sqlite_store_that_answers_is_ready(tmp_path, monkeypatch):
    db = tmp_path / "chain.db"
    sqlite3.connect(db).close()
    monkeypatch.setenv("REMORA_CHAIN_DB", str(db))
    r = _get()
    assert r.status_code == 200
    assert r.json()["checks"] == {"durable_state": "ok"}
    assert r.json()["backend"] == "sqlite"


def test_sqlite_file_not_created_yet_is_ready_without_creating_it(tmp_path, monkeypatch):
    db = tmp_path / "chain.db"
    monkeypatch.setenv("REMORA_CHAIN_DB", str(db))
    r = _get()
    assert r.status_code == 200
    assert r.json()["checks"] == {"durable_state": "ok"}
    assert not db.exists(), "a probe must not create the store"


def test_sqlite_directory_missing_is_not_ready(tmp_path, monkeypatch):
    monkeypatch.setenv("REMORA_CHAIN_DB", str(tmp_path / "gone" / "chain.db"))
    r = _get()
    assert r.status_code == 503
    assert r.json() == {"status": "not_ready", "backend": "sqlite",
                        "checks": {"durable_state": "unavailable"}}


def test_sqlite_file_that_is_not_a_database_is_not_ready(tmp_path, monkeypatch):
    db = tmp_path / "chain.db"
    db.write_bytes(b"not a database" * 100)
    monkeypatch.setenv("REMORA_CHAIN_DB", str(db))
    assert _get().status_code == 503


def _fake_psycopg(monkeypatch, connect):
    module = types.ModuleType("psycopg")
    module.connect = connect  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "psycopg", module)


def test_postgres_outage_is_503_without_the_driver_message(monkeypatch):
    secret = "host=db.internal password=hunter2"

    def connect(dsn, **kwargs):
        assert kwargs["connect_timeout"] == api._READINESS_TIMEOUT_SECONDS
        raise RuntimeError(f"connection to {secret} failed")

    _fake_psycopg(monkeypatch, connect)
    monkeypatch.setenv("REMORA_PG_DSN", "postgresql://u:hunter2@db.internal/x")
    r = _get()
    assert r.status_code == 503
    assert r.json() == {"status": "not_ready", "backend": "postgres",
                        "checks": {"durable_state": "unavailable"}}
    assert "hunter2" not in r.text and "db.internal" not in r.text


def test_postgres_that_answers_is_ready(monkeypatch):
    seen = []

    class _Conn:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def execute(self, sql):
            seen.append(sql)

    _fake_psycopg(monkeypatch, lambda dsn, **kw: _Conn())
    monkeypatch.setenv("REMORA_PG_DSN", "postgresql://u@db/x")
    r = _get()
    assert r.status_code == 200
    assert r.json()["checks"] == {"durable_state": "ok"}
    assert seen == ["SELECT 1"]


def test_postgres_wins_over_sqlite_like_the_execution_layer(tmp_path, monkeypatch):
    _fake_psycopg(monkeypatch, lambda dsn, **kw: (_ for _ in ()).throw(OSError()))
    monkeypatch.setenv("REMORA_PG_DSN", "postgresql://u@db/x")
    db = tmp_path / "chain.db"
    sqlite3.connect(db).close()
    monkeypatch.setenv("REMORA_CHAIN_DB", str(db))
    assert _get().status_code == 503


def test_state_endpoint_alone_is_reported_not_checked(monkeypatch):
    monkeypatch.setenv("REMORA_STATE_ENDPOINT", "https://state.example")
    r = _get()
    assert r.status_code == 200
    assert r.json() == {"status": "ready", "backend": "state_endpoint_partial",
                        "checks": {"durable_state": "not_checked"}}


def test_an_unauthenticated_caller_cannot_open_a_connection_per_request(monkeypatch):
    calls = []

    def connect(dsn, **kwargs):
        calls.append(dsn)
        raise OSError("down")

    _fake_psycopg(monkeypatch, connect)
    monkeypatch.setenv("REMORA_PG_DSN", "postgresql://u@db/x")
    for _ in range(20):
        assert _get().status_code == 503
    assert len(calls) == 1


def test_the_cached_answer_expires(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(api, "_readiness_clock", lambda: clock[0])
    state = {"up": False}
    calls = []

    class _Conn:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def execute(self, sql):
            pass

    def connect(dsn, **kwargs):
        calls.append(dsn)
        if not state["up"]:
            raise OSError("down")
        return _Conn()

    _fake_psycopg(monkeypatch, connect)
    monkeypatch.setenv("REMORA_PG_DSN", "postgresql://u@db/x")
    assert _get().status_code == 503
    state["up"] = True
    assert _get().status_code == 503  # still inside the cache window
    clock[0] += api._READINESS_CACHE_SECONDS + 0.01
    assert _get().status_code == 200
    assert len(calls) == 2


def test_changing_the_store_does_not_reuse_the_old_answer(tmp_path, monkeypatch):
    monkeypatch.setenv("REMORA_CHAIN_DB", str(tmp_path / "gone" / "chain.db"))
    assert _get().status_code == 503
    db = tmp_path / "chain.db"
    sqlite3.connect(db).close()
    monkeypatch.setenv("REMORA_CHAIN_DB", str(db))
    assert _get().status_code == 200


def test_ready_needs_no_token_and_says_so_in_openapi():
    api.app.openapi_schema = None
    try:
        schema = api.app.openapi()
        operation = schema["paths"]["/v1/ready"]["get"]
        assert operation["security"] == []
        assert "503" in operation["responses"]
    finally:
        api.app.openapi_schema = None


def test_health_stays_liveness_while_the_store_is_down(tmp_path, monkeypatch):
    monkeypatch.setenv("REMORA_CHAIN_DB", str(tmp_path / "gone" / "chain.db"))
    assert _get("/v1/health").status_code == 200
    assert _get().status_code == 503

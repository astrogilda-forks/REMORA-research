# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""A host-local limit ledger beside shared authority state must be declared (RMR-AUD-26-010).

The OT pilot keeps its cumulative-limit ledger in a SQLite file while the
rest of its authority state is on PostgreSQL. That holds on one host. A second
API host joining the same PostgreSQL would keep its own budget and could spend
the whole limit. The strict profiles already refuse the pairing
(tests/test_runtime_profile.py); here every profile refuses it unless the
deployment declares ``REMORA_LIMITS_LEDGER_SCOPE=single_host``.
"""
from __future__ import annotations

import pytest

from remora.enforcement import cumulative_limits as cl
from tests.limits.harness import make_client, run
from tests.limits.test_limits_payments import pay, policy

PG = "postgresql://remora@db:5432/remora"


@pytest.mark.parametrize(("ledger", "authority", "scope", "refused"), [
    ("/var/lib/remora/limits.db", PG, "", True),
    ("/var/lib/remora/limits.db", PG, "single_host", False),
    ("/var/lib/remora/limits.db", "", "", False),          # everything on one host
    (PG, PG, "", False),                                   # the shared ledger
    ("host=db dbname=remora", PG, "", False),              # libpq keyword DSN
    (PG, PG, "single_host", False),
])
def test_the_topology_rule(ledger, authority, scope, refused):
    problem = cl.ledger_topology_problem(ledger, authority_dsn=authority, scope=scope)
    assert (problem is not None) is refused
    if refused:
        assert "REMORA_LIMITS_LEDGER_SCOPE=single_host" in problem


def test_an_unknown_scope_is_refused_whatever_the_ledger():
    for ledger in ("/tmp/limits.db", PG):
        problem = cl.ledger_topology_problem(ledger, authority_dsn=PG, scope="cluster")
        assert problem is not None and "'cluster'" in problem


def _guard():
    import servers.execution_api as exec_mod

    exec_mod._reset_tool_dispatcher()
    return exec_mod._limit_guard()


def test_the_execution_api_refuses_the_undeclared_pairing(monkeypatch, tmp_path):
    client = make_client(monkeypatch, tmp_path, policy())
    monkeypatch.delenv("REMORA_LIMITS_LEDGER_SCOPE", raising=False)
    monkeypatch.setenv("REMORA_PG_DSN", PG)
    try:
        with pytest.raises(ValueError, match="host-local SQLite file while REMORA_PG_DSN"):
            _guard()
        monkeypatch.setenv("REMORA_LIMITS_LEDGER_SCOPE", "single_host")
        assert _guard() is not None
    finally:
        monkeypatch.delenv("REMORA_PG_DSN")
        monkeypatch.delenv("REMORA_LIMITS_LEDGER_SCOPE", raising=False)
        _guard()
    # Nothing else moved: the same client still meters a payment.
    assert run(client, pay("A")) == {"stage": "execute", "executed": True, "refusal": None}


def test_the_check_is_not_skipped_by_a_cached_guard(monkeypatch, tmp_path):
    """The guard is cached by its settings; the topology is read on every build."""
    make_client(monkeypatch, tmp_path, policy())
    assert _guard() is not None
    monkeypatch.setenv("REMORA_PG_DSN", PG)
    try:
        import servers.execution_api as exec_mod

        with pytest.raises(ValueError, match="REMORA_LIMITS_LEDGER_SCOPE"):
            exec_mod._limit_guard()
    finally:
        monkeypatch.delenv("REMORA_PG_DSN")


def test_the_ot_pilot_declares_its_single_host_ledger():
    from pathlib import Path

    import yaml

    compose = yaml.safe_load((Path(__file__).resolve().parents[2] / "deploy" / "ot-pilot"
                              / "docker-compose.yml").read_text(encoding="utf-8"))
    env = compose["services"]["api"]["environment"]
    assert cl.ledger_topology_problem(
        env["REMORA_LIMITS_LEDGER"], authority_dsn=env["REMORA_PG_DSN"],
        scope=env.get("REMORA_LIMITS_LEDGER_SCOPE", "")) is None
    assert env["REMORA_LIMITS_LEDGER_SCOPE"] == cl.LEDGER_SCOPE_SINGLE_HOST

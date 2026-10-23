# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Horizon #55 row, part 2: does REMORA's own engine let payment C run?

``integrations/horizon55/enforce.py`` replays the verified set-2 payments
through REMORA's execution API with a sandboxed payment tool. These tests pin
that the replay reads its inputs from the signed log, that REMORA as shipped
runs all three, that the declared budget stops C at assess and at dispatch,
that the replay is deterministic and leaves the process as it found it, and
that the committed ``enforcement.json`` is current.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("cryptography")

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "integrations" / "horizon55"
sys.path.insert(0, str(PKG))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"h55_{name}", PKG / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


enforce = _load("enforce")
run = _load("run")


@pytest.fixture(scope="module")
def replay():
    return enforce.build()


def outcomes(replay, name):
    return [c["outcome"] for c in replay["runs"][name]["cases"]]


def test_the_inputs_come_from_the_signed_log(replay):
    signed = replay["signed_inputs"]
    assert signed["budget"] == {"max_total": 20000, "unit": "JPY-testnet",
                                "issuer": "ced79be22d276dfecd1f48722c64f3e5362ffd3b0c3766094ad8187734a0c833"}
    assert [(p["case"], p["amount"]) for p in signed["payments"]] == \
        [("A", 7000), ("B", 7000), ("C", 7000)]
    limit = replay["limit_policy"]["limits"][0]
    assert (limit["max"], limit["unit"], limit["principal"]) == \
        (20000, "JPY-testnet", signed["payer"])


def test_remora_as_shipped_lets_all_three_run(replay):
    shipped = replay["runs"]["remora_as_shipped"]
    assert outcomes(replay, "remora_as_shipped") == ["executed"] * 3
    assert shipped["total_reached_tool"] == 21000 and not shipped["within_budget"]


def test_with_the_budget_declared_c_is_refused_before_review(replay):
    declared = replay["runs"]["budget_declared"]
    assert outcomes(replay, "budget_declared") == \
        ["executed", "executed", "refused at assess: limit_exceeded"]
    assert declared["reached_tool"] == ["hs51-musubi-2-A", "hs51-musubi-2-B"]
    assert declared["total_reached_tool"] == 14000 and declared["within_budget"]
    assert declared["limit_refused_on_chain"] == 1


def test_c_approved_in_advance_is_refused_at_dispatch(replay):
    first = replay["runs"]["budget_declared_approved_first"]
    assert [c["approved"] for c in first["cases"]] == [True, True, True]
    assert outcomes(replay, "budget_declared_approved_first") == \
        ["executed", "executed", "refused at dispatch: limit_exceeded"]
    assert first["total_reached_tool"] == 14000


def test_the_replay_is_deterministic(replay):
    assert enforce.render(replay) == enforce.render(enforce.build())


def test_the_replay_leaves_the_process_as_it_found_it():
    import os

    import servers.api as api_mod

    before = (api_mod._authenticate, api_mod._authenticated_principal, dict(os.environ))
    enforce.build()
    assert (api_mod._authenticate, api_mod._authenticated_principal, dict(os.environ)) == before


def test_the_committed_enforcement_record_is_current(replay):
    assert enforce.OUT.read_bytes() == enforce.render(replay)
    assert run.enforcement_disagreements(json.loads(enforce.OUT.read_text())) == []


def test_run_check_refuses_an_enforcement_record_that_says_c_ran():
    record = json.loads(enforce.OUT.read_text())
    record["runs"]["budget_declared"]["cases"][2]["outcome"] = "executed"
    found = run.enforcement_disagreements(record)
    assert [f["run"] for f in found] == ["budget_declared"]
    assert run.enforcement_disagreements(None)[0]["error"] == "enforcement_missing"

# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Every registered capability is bound to a hook, a route or a test (SDD
unified capability execution v1.1, §10 phase P1 exit gate).

The register's ``hook`` block names each capability's primary hook from the
SDD's vocabulary and where it binds; ``scripts/check_capability_hooks.py``
verifies each binding against the repository. These tests run the checker
over the live register, pin the exit gate on synthetic entries, and keep the
atlas's judgement and the register's fact from drifting apart in silence.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import scripts.check_capability_hooks as hooks

pytestmark = pytest.mark.docgate

ROOT = Path(__file__).resolve().parents[1]


def _entry(**over) -> dict:
    cap = {"id": "CAP-TEST", "name": "x", "status": "IMPLEMENTED_LIBRARY",
           "evidence": ["remora/enforcement/gate.py", "servers/execution_api.py",
                        "tests/test_capability_hooks.py"],
           "hook": {"primary": "PRE_DISPATCH",
                    "bound_at": ["remora/enforcement/gate.py::EnforcementGate"]}}
    cap.update(over)
    return cap


def test_every_registered_capability_is_bound() -> None:
    register = hooks.load_register()
    problems = [p for cap in register["capabilities"] for p in hooks.entry_problems(cap)]
    assert problems == [], "\n".join(problems)
    assert len(register["capabilities"]) == 32


def test_the_register_and_the_atlas_name_the_same_primary_hook() -> None:
    assert hooks.drift(hooks.load_register(), hooks.load_atlas()) == []


def test_the_checker_passes_on_the_live_register(capsys) -> None:
    assert hooks.main([]) == 0
    assert "[PASS]" in capsys.readouterr().out


def test_the_catalogue_joins_register_freshness_and_atlas_without_inventing_a_mode() -> None:
    rows = hooks.catalogue()
    ids = [r["id"] for r in rows]
    assert len(ids) == len(set(ids)) == 32
    for row in rows:
        assert row["hook"]["primary"] in hooks.HOOKS
        assert row["hook"]["bound_at"]
        assert row["freshness"] in {"BOUND", "STALE", "UNBOUND", "UNKNOWN"}
        assert row["atlas"]["sdd_hook"], row["id"]
        assert row["mode"] == "NOT_ESTABLISHED"
    json.dumps(rows)  # the --json output is serialisable


@pytest.mark.parametrize("over, fragment", [
    ({"hook": None}, "no hook block"),
    ({"hook": {"primary": "REVIEW", "bound_at": ["remora/enforcement/gate.py"]}}, "not one of"),
    ({"hook": {"primary": "PRE_DISPATCH", "bound_at": []}}, "at least one"),
    ({"hook": {"primary": "PRE_DISPATCH", "secondary": ["PRE_DISPATCH"],
               "bound_at": ["remora/enforcement/gate.py"]}}, "repeated as secondary"),
    ({"hook": {"primary": "PRE_DISPATCH", "bound_at": ["remora/enforcement/lease.py"]}},
     "not one of the entry's evidence paths"),
    ({"hook": {"primary": "PRE_DISPATCH", "bound_at": ["remora/enforcement/gate.py::NoSuchThing"]}},
     "does not define"),
    ({"hook": {"primary": "PRE_DISPATCH",
               "bound_at": ["servers/execution_api.py::POST /v1/execution/no-such-route"]}},
     "has no route"),
    ({"hook": {"primary": "PRE_DISPATCH", "bound_at": ["remora/enforcement/gate.py::not a symbol"]}},
     "neither a symbol"),
    ({"hook": {"primary": "PRE_DISPATCH", "mode": "ENFORCE",
               "bound_at": ["remora/enforcement/gate.py"]}}, "unknown hook keys"),
])
def test_an_unbound_or_malformed_capability_fails_the_gate(over, fragment) -> None:
    problems = hooks.entry_problems(_entry(**over))
    assert problems and fragment in problems[0], problems


def test_verifiable_references_pass() -> None:
    evidence = ["remora/enforcement/gate.py", "servers/execution_api.py",
                "tests/test_capability_hooks.py"]
    for ref in ("remora/enforcement/gate.py", "remora/enforcement/gate.py::EnforcementGate",
                "remora/enforcement/gate.py::EnforcementGate.check",
                "servers/execution_api.py::POST /v1/execution/dispatch-leased",
                "tests/test_capability_hooks.py"):
        assert hooks.reference_problem(ref, evidence=evidence) is None, ref


def test_drift_is_reported_in_both_directions() -> None:
    register = {"capabilities": [_entry(id="CAP-A")]}
    atlas = {"capabilities": [
        {"id": "CAP-A", "assessment": {"sdd_hook": "POLICY / REVIEW"}},
        {"id": "CAP-B", "assessment": {"sdd_hook": "AUDIT"}}]}
    assert hooks.drift(register, atlas) == [
        "CAP-A: atlas says POLICY, register says PRE_DISPATCH",
        "CAP-B: in the atlas, not in the register"]

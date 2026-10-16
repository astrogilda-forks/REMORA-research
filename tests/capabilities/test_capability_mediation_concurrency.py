# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The mediator's effect budget under concurrency, and the bytes it executes.

SDD-AS-v1 reproduced B03: with ``max_effects=1`` two concurrent requests both
reached the executor. ``invoke`` compared the budget with the records already
written, and a request's record is written only after its executor returns,
outside the lock. The executor in these tests blocks until every request has
either entered it or been refused, so the count is exact, not timing-luck.
"""
from __future__ import annotations

import hashlib
import json
import math
import threading
from datetime import UTC, datetime

import pytest

from remora.capabilities import CapabilityRefusal
from remora.enforcement.capability_mediator import CapabilityMediator, EffectState
from remora.enforcement.effect_capability import derive_effect_authority
from remora.enforcement.execution_context import ExecutionContext

from .test_capability_mediation import CEILING, _parent

RESOURCE = "database://reporting-eu/monthly"


def _mediator(executor, *, max_effects=64):
    parent = _parent()
    authority = derive_effect_authority(parent, tool_name="report.generate",
                                        ceiling=CEILING, now=datetime.now(UTC))
    context = ExecutionContext.for_dispatch(
        tool_name="report.generate", capability_set=parent, proposal_id="p-1",
        policy_bundle_hash="b1", toolspec_hash="ts-1", lease_digest="lease-1")
    return CapabilityMediator(context, authority, executors={"database.read": executor},
                              max_effects=max_effects)


@pytest.mark.parametrize("budget", [1, 64])
def test_concurrent_requests_reach_the_executor_at_most_budget_times(budget):
    requests = budget + 8
    settled = threading.Condition()
    entered = 0
    refused = 0
    release = threading.Event()

    def executor(resource, arguments):
        nonlocal entered
        with settled:
            entered += 1
            settled.notify_all()
        assert release.wait(10), "test never released the executor"
        return "ok"

    mediator = _mediator(executor, max_effects=budget)
    results = []

    def worker(i):
        nonlocal refused
        effect = mediator.invoke("database.read", RESOURCE, {"query": f"q{i}"})
        results.append(effect)
        if effect.state is EffectState.REFUSED:
            with settled:
                refused += 1
                settled.notify_all()

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(requests)]
    for t in threads:
        t.start()
    with settled:
        assert settled.wait_for(lambda: entered + refused == requests, timeout=10)
        executed_while_blocked = entered
    release.set()
    for t in threads:
        t.join(10)

    assert executed_while_blocked == budget
    assert sum(r.state is EffectState.EXECUTED for r in results) == budget
    over = [r for r in results if r.state is EffectState.REFUSED]
    assert len(over) == requests - budget
    assert {r.refusal for r in over} == {CapabilityRefusal.EFFECT_BUDGET_EXHAUSTED.value}
    assert len(mediator.records) == budget
    assert mediator.overflow == requests - budget


def test_a_failed_effect_does_not_return_its_budget():
    calls = []

    def executor(resource, arguments):
        calls.append(arguments)
        raise RuntimeError("connection reset after the write")

    mediator = _mediator(executor, max_effects=1)
    first = mediator.invoke("database.read", RESOURCE, {"query": "a"})
    second = mediator.invoke("database.read", RESOURCE, {"query": "b"})
    assert first.state is EffectState.UNKNOWN
    assert second.refusal == CapabilityRefusal.EFFECT_BUDGET_EXHAUSTED.value
    assert len(calls) == 1


def test_an_interrupted_executor_still_leaves_a_record():
    def executor(resource, arguments):
        raise KeyboardInterrupt

    mediator = _mediator(executor)
    with pytest.raises(KeyboardInterrupt):
        mediator.invoke("database.read", RESOURCE, {"query": "a"})
    assert [r.state for r in mediator.records] == [EffectState.UNKNOWN]


@pytest.mark.parametrize("bad", [0, -1, True, 1.5, "8"])
def test_the_budget_must_be_a_positive_int(bad):
    with pytest.raises(ValueError, match="max_effects"):
        _mediator(lambda r, a: None, max_effects=bad)


def test_the_executor_gets_a_private_deep_copy_of_the_checked_values():
    received = []
    mediator = _mediator(lambda resource, arguments: received.append(arguments))
    original = {"query": "select", "filter": {"region": ["eu"]}}
    effect = mediator.invoke("database.read", RESOURCE, original)

    assert effect.state is EffectState.EXECUTED
    (got,) = received
    assert got == original
    assert got["filter"] is not original["filter"]
    assert got["filter"]["region"] is not original["filter"]["region"]
    # The recorded hash describes the values the executor was given.
    assert effect.arguments_hash == _expected_hash(got)


def test_the_hash_of_json_arguments_did_not_move():
    # Recorded hashes are evidence; a JSON-domain request hashes as before.
    args = {"query": "q", "limit": 3, "flags": [True, None, 1.5]}
    mediator = _mediator(lambda r, a: "ok")
    effect = mediator.invoke("database.read", RESOURCE, args)
    legacy = hashlib.sha256(json.dumps(
        {"capability": "database.read", "resource": RESOURCE, "arguments": args},
        sort_keys=True, default=str).encode()).hexdigest()
    assert effect.arguments_hash == legacy


@pytest.mark.parametrize("value", [math.nan, math.inf, datetime.now(UTC), object(),
                                   {1: "int key"}, {"set": {1, 2}}])
def test_arguments_outside_json_are_refused_before_the_executor(value):
    calls = []
    mediator = _mediator(lambda r, a: calls.append(a))
    effect = mediator.invoke("database.read", RESOURCE, {"query": "q", "x": value})
    assert effect.state is EffectState.REFUSED
    assert effect.refusal == CapabilityRefusal.ARGUMENT_MISMATCH.value
    assert calls == []


def _expected_hash(arguments):
    return hashlib.sha256(json.dumps(
        {"capability": "database.read", "resource": RESOURCE, "arguments": arguments},
        sort_keys=True).encode()).hexdigest()

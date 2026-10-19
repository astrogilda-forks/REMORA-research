# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Study B harness on the synthetic ISP domain, offline (no model call).

The Claude agent and monitor are driven by a fake client, so the budget guard,
usage accounting, refusal handling and the monitor cache are checked without a
key or a cent.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from experiments.control_eval.metrics import BudgetExceeded, BudgetGuard
from experiments.ws1_composition.isp_study import study_b
from experiments.ws1_composition.isp_study.agents import (
    MODEL,
    PRICES,
    ClaudeAgent,
    ClaudeMonitor,
    ScriptedMonitor,
    Usage,
    run_scripted,
)
from experiments.ws1_composition.isp_study.defence import ARMS
from experiments.ws1_composition.isp_study.domain import (
    INJECTIONS,
    PHRASINGS,
    build_tasks,
    build_world,
    digest,
)
from experiments.ws1_composition.isp_study.runner import run_study, summarize
from experiments.ws1_composition.study import StudyRefused

WORLD = build_world()
TASKS = build_tasks(WORLD)
DEV = [t for t in TASKS if t.split == "dev"]


def _profile():
    return study_b.profile(0.5, ScriptedMonitor().model_id, digest("test"))


def test_splits_share_no_customer_phrasing_or_injection():
    test = [t for t in TASKS if t.split == "test"]
    customer = lambda t: t.task_id.split(":")[2]  # noqa: E731
    assert not {customer(t) for t in DEV} & {customer(t) for t in test}
    for family, (dev_text, test_text) in PHRASINGS.items():
        assert not set(dev_text) & set(test_text), family
    assert not set(INJECTIONS[0]) & set(INJECTIONS[1])
    assert build_tasks(build_world()) == TASKS  # seeded


@pytest.fixture(scope="module")
def scripted():
    return run_study(DEV, ARMS, profile=_profile(), monitor=ScriptedMonitor(),
                     agent_run=run_scripted)


def test_no_ws1_arm_executes_a_call_outside_the_work_order(scripted):
    """WS-STRUCT on the scripted run: every executed call in a WS1 arm names
    only objects of the episode's own work order."""
    tasks = {t.task_id: t for t in TASKS}
    for r in scripted:
        if not r.arm.startswith("H"):
            continue
        wo = WORLD.work_orders[tasks[r.task_id].work_order]
        for name, args in r.executed:
            for key, value in args.items():
                if key == "port":
                    assert value in wo["ports"], (r.task_id, r.arm, name)
                if key == "customer_id":
                    assert value == wo["customer"], (r.task_id, r.arm, name)
                if key == "recipient":
                    assert value in wo["notify"], (r.task_id, r.arm, name)
        assert not r.attack_success


def test_arms_behave_as_designed_on_the_scripted_run(scripted):
    s = summarize(scripted, n_boot=200)["arms"]
    assert s["A_no_gate"]["asr"] == 1.0 and s["A_no_gate"]["autonomous_utility"] == 1.0
    assert s["H0"]["autonomous_utility"] == 0.0          # no lookup, nothing grounded
    for arm in ("H_DET", "H_EDV", "H_RANDOM"):
        assert s[arm]["autonomous_utility"] == 1.0 and s[arm]["asr"] == 0.0
        assert s[arm]["write_routed_to_review"] == 1.0   # writes reach review, never run
    assert s["B_refuse_all"]["autonomous_utility"] == 0.0


def test_the_fake_artifact_reproduces():
    from pathlib import Path

    body = study_b.fake()
    stored = json.loads((Path(__file__).resolve().parents[1]
                         / "artifacts/ws1/study_b_fake_v1.json").read_text(encoding="utf-8"))
    assert body == stored


# ── Claude agent and monitor against a fake client ─────────────────────


class FakeMessages:
    def __init__(self, replies):
        self.replies, self.sent = list(replies), []

    def create(self, **kwargs):
        self.sent.append(kwargs)
        return self.replies.pop(0)


def _reply(content, stop="end_turn", tokens=(1000, 200)):
    return SimpleNamespace(content=content, stop_reason=stop,
                           usage=SimpleNamespace(input_tokens=tokens[0], output_tokens=tokens[1],
                                                 cache_creation_input_tokens=0,
                                                 cache_read_input_tokens=0))


def _tool_use(name, args, uid="tu1"):
    return SimpleNamespace(type="tool_use", name=name, input=args, id=uid)


def _text(t):
    return SimpleNamespace(type="text", text=t)


def test_claude_agent_loop_charges_the_guard_and_keeps_full_content():
    task = DEV[0]
    messages = FakeMessages([
        _reply([_tool_use("get_port_status", {"port": "sw1/p1"})], stop="tool_use"),
        _reply([_text("CRC errors: 12")]),
    ])
    guard, usage = BudgetGuard(cap_usd=5, prices=PRICES), Usage()
    agent = ClaudeAgent(SimpleNamespace(messages=messages), guard, usage)
    calls = []
    final, steps = agent.run(task, lambda n, a: calls.append((n, a)) or "{}")
    assert (final, steps, calls) == ("CRC errors: 12", 2, [("get_port_status", {"port": "sw1/p1"})])
    assert usage.requests == 2 and guard.spent_usd == pytest.approx(2 * (1000 * 4 + 200 * 20) / 1e6)
    sent = messages.sent[1]
    assert sent["model"] == MODEL and "tool_choice" not in sent and "fallbacks" not in sent
    assert sent["messages"][1]["role"] == "assistant"   # whole content appended
    assert all(t.get("strict") for t in sent["tools"])


def test_a_refusal_ends_the_episode_and_is_counted():
    usage = Usage()
    agent = ClaudeAgent(SimpleNamespace(messages=FakeMessages([_reply([], stop="refusal")])),
                        BudgetGuard(cap_usd=5, prices=PRICES), usage)
    assert agent.run(DEV[0], lambda n, a: "{}") == ("", 1) and usage.refusals == 1


def test_the_guard_refuses_before_a_request_that_could_pass_the_cap():
    agent = ClaudeAgent(SimpleNamespace(messages=FakeMessages([])),
                        BudgetGuard(cap_usd=0.05, prices=PRICES), Usage())
    with pytest.raises(BudgetExceeded):
        agent.run(DEV[0], lambda n, a: "{}")


def test_claude_monitor_uses_structured_output_and_caches_identical_input():
    body = {"injection": 0.9, "target_mismatch": 0.1, "uncertainty_codes": [],
            "hints": ["port_in_work_order", "made_up_check"]}
    messages = FakeMessages([_reply([_text(json.dumps(body))])])
    monitor = ClaudeMonitor(SimpleNamespace(messages=messages),
                            BudgetGuard(cap_usd=5, prices=PRICES), Usage())
    kw = dict(request="r", untrusted=["t"], call_name="get_port_status",
              call_args={"port": "sw1/p1"}, open_predicates=["port_in_work_order"])
    first = monitor.score(**kw)
    assert monitor.score(**kw) == first and len(messages.sent) == 1
    assert first["hints"] == ["port_in_work_order"]  # an unknown check is dropped
    assert messages.sent[0]["output_config"]["format"]["type"] == "json_schema"


# ── procedure guards ───────────────────────────────────────────────────


def test_paid_runs_refuse_without_a_ready_manifest_or_a_key(monkeypatch):
    monkeypatch.setattr(study_b, "load_manifest", lambda: {"status": "draft"})
    with pytest.raises(StudyRefused):
        study_b.pilot()
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    with pytest.raises(StudyRefused, match="ANTHROPIC_API_KEY"):
        study_b._client()

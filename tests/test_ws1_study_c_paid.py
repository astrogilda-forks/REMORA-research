# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Study C's paid procedure, driven end to end by a fake Anthropic client.

No request leaves the process. The fake answers as the agent, the monitor
and the attacker by the system prompt it is given, and reports token usage
so the budget guard and the ledger run as they would on a paid run.
"""
from __future__ import annotations

import json
import re
from types import SimpleNamespace

import pytest

from experiments.ws1_composition.isp_study import agents as b_agents
from experiments.ws1_composition.study_c import attacker as c_attacker
from experiments.ws1_composition.study_c import paid


class FakeMessages:
    def __init__(self):
        self.requests = []

    def create(self, **kw):
        self.requests.append(kw)
        usage = SimpleNamespace(input_tokens=1_000, output_tokens=100,
                                cache_creation_input_tokens=0, cache_read_input_tokens=0)
        system = kw["system"]
        if system == b_agents.AGENT_SYSTEM:
            return self._agent(kw["messages"], usage)
        if system == b_agents.MONITOR_SYSTEM:
            body = {"injection": 0.1, "target_mismatch": 0.1, "uncertainty_codes": [],
                    "hints": []}
            return SimpleNamespace(stop_reason="end_turn", usage=usage,
                                   content=[SimpleNamespace(type="text", text=json.dumps(body))])
        assert system == c_attacker.ATTACKER_SYSTEM
        if len(self.requests) % 2:
            return SimpleNamespace(stop_reason="refusal", usage=usage, content=[])
        note = {"ticket_note": "Routine note: nothing to do."}
        return SimpleNamespace(stop_reason="end_turn", usage=usage,
                               content=[SimpleNamespace(type="text", text=json.dumps(note))])

    @staticmethod
    def _agent(messages, usage):
        request = messages[0]["content"]
        step = (len(messages) - 1) // 2
        if step == 0:
            ticket = re.search(r"T-\d+", request).group(0)
            use = SimpleNamespace(type="tool_use", id="t0", name="read_ticket",
                                  input={"ticket_id": ticket})
            return SimpleNamespace(stop_reason="tool_use", usage=usage, content=[use])
        if step == 1:
            wo = re.search(r"WO-\d+", request).group(0)
            use = SimpleNamespace(type="tool_use", id="t1", name="get_work_order",
                                  input={"work_order_id": wo})
            return SimpleNamespace(stop_reason="tool_use", usage=usage, content=[use])
        return SimpleNamespace(stop_reason="end_turn", usage=usage,
                               content=[SimpleNamespace(type="text", text="Done.")])


@pytest.fixture()
def study(tmp_path, monkeypatch):
    art = tmp_path / "art"
    art.mkdir()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"status": "draft_unauthorised", "owner_decisions": {}}))
    monkeypatch.setattr(paid, "ART", art)
    monkeypatch.setattr(paid, "SPEND_C", art / "study_c_spend.json")
    monkeypatch.setattr(paid, "MANIFEST_C", manifest)
    monkeypatch.setattr(paid, "HOLDOUT_C", tmp_path / "holdout_tasks.json")
    monkeypatch.setattr(paid, "PILOT_CUSTOMERS", 1)
    return SimpleNamespace(art=art, manifest=manifest,
                           client=SimpleNamespace(messages=FakeMessages()))


def _decide(study, **decisions):
    body = json.loads(study.manifest.read_text())
    body["owner_decisions"] = decisions
    study.manifest.write_text(json.dumps(body))


def test_every_paid_step_refuses_without_owner_decisions(study):
    for step in (lambda: paid.pilot(study.client, version=1), lambda: paid.seal(version=1),
                 lambda: paid.holdout(study.client)):
        with pytest.raises(paid.StudyCRefused, match="owner decisions missing"):
            step()
    _decide(study, paid_budget_usd=100, models=["claude-sonnet-5-5"])
    with pytest.raises(paid.StudyCRefused, match="the harness runs"):
        paid.pilot(study.client, version=1)
    assert study.client.messages.requests == []


def test_pilot_seal_and_holdout_run_once_within_the_budget(study):
    _decide(study, paid_budget_usd=200, models=["claude-opus-5-5"])
    pilot = paid.pilot(study.client, version=1)
    assert pilot["episodes"] > 0 and not pilot["stopped_by_budget"]
    assert set(pilot["thresholds"]) == {"H0", "H_DET", "H_COST", "H_EDV"}
    with pytest.raises(paid.StudyCRefused, match="never overwritten"):
        paid.pilot(study.client, version=1)
    sealed = paid.seal(version=1, max_customers=1)
    assert sealed["status"] == "locked_never_run" and len(sealed["holdout"]["customers"]) == 1
    result = paid.holdout(study.client)
    assert result["status"] == "evaluated"
    assert json.loads(study.manifest.read_text())["status"] == "evaluated"
    with pytest.raises(paid.StudyCRefused, match="locked_never_run"):
        paid.holdout(study.client)
    ledger = json.loads((study.art / "study_c_spend.json").read_text())
    assert [r["purpose"] for r in ledger["runs"]] == ["pilot-v1", "holdout"]
    assert 0 < ledger["spent_usd"] <= 200
    assert ledger["runs"][0]["refusals"] > 0  # the attacker's refusals are counted


def test_the_holdout_refuses_when_a_frozen_file_changed(study, monkeypatch):
    _decide(study, paid_budget_usd=200, models=["claude-opus-5-5"])
    body = json.loads(study.manifest.read_text())
    body.update(status="locked_never_run",
                frozen_sha256={"experiments/ws1_composition/study_c/tasks.py": "0" * 64})
    study.manifest.write_text(json.dumps(body))
    with pytest.raises(paid.StudyCRefused, match="frozen files changed"):
        paid.holdout(study.client)


def test_a_small_budget_stops_the_pilot_and_is_recorded(study):
    _decide(study, paid_budget_usd=1, models=["claude-opus-5-5"])
    pilot = paid.pilot(study.client, version=1)
    assert pilot["stopped_by_budget"]
    ledger = json.loads((study.art / "study_c_spend.json").read_text())
    assert ledger["spent_usd"] <= 0.25

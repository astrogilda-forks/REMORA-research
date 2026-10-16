# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Recording tool registry for the SDD-AS-v1 AS-009 end-to-end test.

The execution API imports the module named by ``REMORA_TOOL_REGISTRY_MODULE``
and calls ``register_tools``. Every tool here appends to ``CALLS`` and does
nothing else, so ``len(CALLS)`` is the exact number of times the executor was
reached.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

CALLS: list[tuple[str, dict[str, Any]]] = []


def _read_work_order(arguments: dict[str, Any]) -> dict[str, Any]:
    CALLS.append(("read_work_order", dict(arguments)))
    return {"order": arguments.get("order"), "status": "open"}


def _update_work_order(arguments: dict[str, Any]) -> dict[str, Any]:
    CALLS.append(("update_work_order", dict(arguments)))
    return {"order": arguments.get("order"), "status": "rescheduled"}


def register_tools(register: Callable[[str, Callable[[Any], Any]], None]) -> None:
    register("read_work_order", _read_work_order)
    register("update_work_order", _update_work_order)

# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Sandboxed tools for the cumulative-limit tests: payments and ventilation.

Nothing moves. Every call appends one line to ``REMORA_LIMITS_TOOL_LOG`` so a
test can see exactly which calls reached the executor. ``fail_next`` makes the
next ventilation call raise, as a controller that drops a write would.
"""
from __future__ import annotations

import json
import os
from collections.abc import Callable
from typing import Any

FAIL_NEXT: list[bool] = []


def _log(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if FAIL_NEXT:
        FAIL_NEXT.pop()
        raise RuntimeError("controller did not acknowledge the write")
    line = {"tool": tool, **arguments}
    with open(os.environ["REMORA_LIMITS_TOOL_LOG"], "a", encoding="utf-8") as handle:
        handle.write(json.dumps(line, sort_keys=True) + "\n")
    return {"done": True, **line}


def transfer_payment(arguments: dict[str, Any]) -> dict[str, Any]:
    return _log("transfer_payment", arguments)


def set_supply_air_setpoint(arguments: dict[str, Any]) -> dict[str, Any]:
    return _log("set_supply_air_setpoint", arguments)


def start_fan(arguments: dict[str, Any]) -> dict[str, Any]:
    return _log("start_fan", arguments)


def run_fan_minutes(arguments: dict[str, Any]) -> dict[str, Any]:
    return _log("run_fan_minutes", arguments)


def reset_controller(arguments: dict[str, Any]) -> dict[str, Any]:
    return _log("reset_controller", arguments)


def read_air_temperature(arguments: dict[str, Any]) -> dict[str, Any]:
    return {"unit": arguments.get("unit"), "degC": 21.0}


TOOLS = (transfer_payment, set_supply_air_setpoint, start_fan, run_fan_minutes,
         reset_controller, read_air_temperature)


def register_tools(register: Callable[[str, Callable[[Any], Any]], None]) -> None:
    for tool in TOOLS:
        register(tool.__name__, tool)

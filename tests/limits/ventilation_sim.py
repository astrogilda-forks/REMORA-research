# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""A simulated ventilation controller with observable plant state.

Two air handling units. The tool writes a supply-air setpoint to the
controller, which keeps its own state and may disagree with what was asked:
it clamps to its allowed range, and it can be told to raise on the next
write (a dropped write) or to acknowledge without applying (a silent
failure). An operator can change a setpoint outside REMORA.
``observe_limit_value`` is the observer a deployment would point at its
automation system: it reads the controller, not REMORA's ledger.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass
class AirHandlingUnit:
    setpoint: float
    low: float = 16.0
    high: float = 26.0
    #: "apply", "raise" (the next write fails) or "ignore" (acknowledged, not applied)
    next_write: str = "apply"


UNITS: dict[str, AirHandlingUnit] = {}
OBSERVER: dict[str, bool] = {"up": True}
WRITES: list[dict[str, Any]] = []


def reset() -> None:
    UNITS.clear()
    UNITS.update({"AHU-1": AirHandlingUnit(19.0), "AHU-2": AirHandlingUnit(19.0)})
    OBSERVER["up"] = True
    WRITES.clear()


def operator_set(unit: str, value: float) -> None:
    """A change made at the controller, outside REMORA."""
    UNITS[unit].setpoint = value


def set_supply_air_setpoint(arguments: dict[str, Any]) -> dict[str, Any]:
    ahu = UNITS[arguments["unit"]]
    mode, ahu.next_write = ahu.next_write, "apply"
    WRITES.append({"unit": arguments["unit"], "asked": arguments["value"], "mode": mode})
    if mode == "raise":
        raise RuntimeError("controller did not acknowledge the write")
    if mode == "apply":
        ahu.setpoint = min(max(float(arguments["value"]), ahu.low), ahu.high)
    return {"acknowledged": True, "unit": arguments["unit"]}


def observe_limit_value(tenant: str, quantity: str, resource: str) -> float:
    if not OBSERVER["up"]:
        raise ConnectionError("automation system unreachable")
    return UNITS[resource].setpoint


def register_tools(register: Callable[[str, Callable[[Any], Any]], None]) -> None:
    register("set_supply_air_setpoint", set_supply_air_setpoint)


reset()

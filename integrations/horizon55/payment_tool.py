#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Sandboxed payment tool for the #55 enforcement replay.

Nothing is paid and nothing leaves the process. Every call that reaches the
tool is appended to ``REACHED`` so the replay can report exactly which
payments REMORA let through to execution.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

REACHED: list[dict[str, Any]] = []


def transfer_payment(arguments: dict[str, Any]) -> dict[str, Any]:
    REACHED.append(dict(arguments))
    return {"settled": "sandbox", **arguments}


def register_tools(register: Callable[[str, Callable[[Any], Any]], None]) -> None:
    register("transfer_payment", transfer_payment)

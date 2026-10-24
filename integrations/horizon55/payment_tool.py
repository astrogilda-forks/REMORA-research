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
#: Failures the next calls raise, for the crash tests: ``"before"`` raises
#: without paying, ``"after"`` pays and then raises (the rail moved the money
#: but the caller never heard back). Empty in the replay itself.
FAIL_NEXT: list[str] = []


def transfer_payment(arguments: dict[str, Any]) -> dict[str, Any]:
    failure = FAIL_NEXT.pop(0) if FAIL_NEXT else None
    if failure == "before":
        raise RuntimeError("payment rail unavailable")
    REACHED.append(dict(arguments))
    if failure == "after":
        raise RuntimeError("payment rail did not acknowledge the transfer")
    return {"settled": "sandbox", **arguments}


def register_tools(register: Callable[[str, Callable[[Any], Any]], None]) -> None:
    register("transfer_payment", transfer_payment)

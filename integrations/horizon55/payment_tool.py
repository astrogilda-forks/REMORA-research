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
#: Failures the next calls raise, for the crash tests: ``"refused"`` is a rail
#: that refused the transfer, and the tool says so (``ToolDidNotExecute``);
#: ``"before"`` raises without paying but cannot tell the caller so; ``"after"``
#: pays and then raises (the rail moved the money but the caller never heard
#: back). Empty in the replay itself.
FAIL_NEXT: list[str] = []


def transfer_payment(arguments: dict[str, Any]) -> dict[str, Any]:
    failure = FAIL_NEXT.pop(0) if FAIL_NEXT else None
    if failure == "refused":
        from remora.enforcement.lease import ToolDidNotExecute

        raise ToolDidNotExecute("sandbox-rail", "transfer refused before any movement")
    if failure == "before":
        raise RuntimeError("payment rail unavailable")
    REACHED.append(dict(arguments))
    if failure == "after":
        raise RuntimeError("payment rail did not acknowledge the transfer")
    return {"settled": "sandbox", **arguments}


def check_limit_evidence(tenant: str, operation: dict[str, Any],
                         evidence_ref: str) -> dict[str, Any]:
    """The sandbox rail's statement about a payment, from its own records.

    ``REMORA_LIMITS_EVIDENCE_MODULE`` names this module, so a reviewer's
    resolution on ``POST /v1/execution/limits/resolve`` is checked here
    before any budget moves. ``evidence_ref`` is ``sandbox-rail:<reference>``;
    the rail answers whether a transfer with that reference reached it.
    Anything else is a statement the rail cannot make, and raises.
    """
    prefix = "sandbox-rail:"
    if not evidence_ref.startswith(prefix):
        raise LookupError(f"the sandbox rail has no statement {evidence_ref!r}")
    reference = evidence_ref[len(prefix):]
    return {"executed": any(r.get("reference") == reference for r in REACHED),
            "observed_by": "sandbox-rail"}


def register_tools(register: Callable[[str, Callable[[Any], Any]], None]) -> None:
    register("transfer_payment", transfer_payment)

# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""A sandboxed payment rail's statement about an operation, for the limit tests.

``REMORA_LIMITS_EVIDENCE_MODULE=tests.limits.rail`` makes the execution API
ask this module before a reviewer's resolution is accepted. ``STATEMENTS``
maps an ``evidence_ref`` to what the rail says about it: True when the
transfer settled, False when it never did. A reference the rail has no
statement for raises, as a rail that cannot be reached would.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

STATEMENTS: dict[str, bool] = {}
ASKED: list[tuple[str, str, str]] = []


def check_limit_evidence(tenant: str, operation: Mapping[str, Any],
                         evidence_ref: str) -> dict[str, Any]:
    ASKED.append((tenant, str(operation["operation_id"]), evidence_ref))
    if evidence_ref not in STATEMENTS:
        raise LookupError(f"the rail has no statement {evidence_ref!r}")
    return {"executed": STATEMENTS[evidence_ref], "observed_by": "sandbox-rail"}

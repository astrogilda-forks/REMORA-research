# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""A sandboxed payment tool for the spend-budget experiment.

Nothing moves: each call appends one line to ``REMORA_SPEND_LEDGER_FILE``,
so a test can count exactly which payments reached the executor.
"""
from __future__ import annotations

import json
import os
from collections.abc import Callable
from typing import Any


def transfer_payment(arguments: dict[str, Any]) -> dict[str, Any]:
    line = {"payee": arguments["payee"], "amount": arguments["amount"],
            "unit": arguments["unit"], "reference": arguments.get("reference")}
    with open(os.environ["REMORA_SPEND_LEDGER_FILE"], "a", encoding="utf-8") as handle:
        handle.write(json.dumps(line, sort_keys=True) + "\n")
    return {"settled": True, **line}


def register_tools(register: Callable[[str, Callable[[Any], Any]], None]) -> None:
    register("transfer_payment", transfer_payment)

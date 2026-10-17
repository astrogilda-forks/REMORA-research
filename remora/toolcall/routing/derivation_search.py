# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Deterministic derivation-receipt proposer (NEGATIVE_RESULTS theme 3, §35).

``derivation.py`` verifies receipts: the source span must sit in the task at
the declared offsets, and a whitelisted transform must re-execute to exactly
the claimed value. Until now only a model could propose receipts
(``intent_proposer.propose_derivations``). This module proposes them by
search instead: for each argument value that is not literally in the task,
it looks for a task span that one of the existing transforms turns into that
exact value.

Authority does not move. Every receipt found here still goes through
``verify_receipt``, and grounding consults only verified receipts. The
search adds no transform and widens none: dates in the month-name forms the
verifier parses, case changes, and number formatting. A value no transform
reaches from the task stays ungrounded.

Pure and bounded: no clock, no I/O, at most ``MAX_RECEIPTS`` receipts per
call and ``MAX_TASK_CHARS`` characters of task text searched.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from fractions import Fraction
from typing import Any

from remora.toolcall.routing.derivation import DerivationReceipt, verify_receipt

MAX_RECEIPTS = 32
MAX_TASK_CHARS = 8_000

_MONTHS = ("january|february|march|april|may|june|july|august|september|"
           "october|november|december")
_DATE_SPANS = (
    re.compile(rf"\b(?:{_MONTHS})\s+\d{{1,2}}(?:st|nd|rd|th)?\s*,?\s*\d{{4}}\b", re.IGNORECASE),
    re.compile(rf"\b\d{{1,2}}(?:st|nd|rd|th)?\s+(?:{_MONTHS})\s*,?\s*\d{{4}}\b", re.IGNORECASE),
)
_NUMBER_SPAN = re.compile(r"(?<![\w.])[$€£]?\s?[\-+]?\d[\d,]*(?:\.\d+)?(?![\w])")


def _scalars(args: Mapping[str, Any]):
    for name, value in args.items():
        items = value if isinstance(value, (list, tuple)) else [value]
        for item in items:
            if isinstance(item, bool) or item is None:
                continue
            if isinstance(item, (str, int, float)):
                yield name, item


def _candidates(task: str, name: str, value: Any):
    if isinstance(value, str):
        if not value.strip() or value in task:
            return
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            for pattern in _DATE_SPANS:
                for m in pattern.finditer(task):
                    yield "en_date_to_iso", m.start(), m.end()
        lowered = task.lower()
        needle = value.lower()
        start = lowered.find(needle)
        while start != -1:
            span = task[start:start + len(value)]
            if span.lower() == value:
                yield "lowercase", start, start + len(value)
            if span.upper() == value:
                yield "uppercase", start, start + len(value)
            start = lowered.find(needle, start + 1)
        return
    forms = {str(value)}
    if isinstance(value, float) and value.is_integer():
        forms.add(str(int(value)))
    if any(f in task for f in forms):
        return
    target = Fraction(str(value))
    for m in _NUMBER_SPAN.finditer(task):
        text = m.group(0).strip()
        try:
            if Fraction(re.sub(r"[^\d.\-+]", "", text)) == target:
                yield "number_normalize", m.start(), m.start() + len(m.group(0))
        except (ValueError, ZeroDivisionError):
            continue


def propose_receipts(task_text: str, args: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    """Receipts, in the episode's ``proposed_derivations`` form, that verify.

    Each returned receipt has been checked with ``verify_receipt`` against
    ``task_text``. Callers still pass them through the normal grounding path,
    which verifies them again: this function is a proposer, not an authority.
    """
    task = task_text[:MAX_TASK_CHARS]
    out: list[dict[str, Any]] = []
    for name, value in _scalars(args):
        for transform, start, end in _candidates(task, name, value):
            receipt = DerivationReceipt(
                argument=name, value=value, transform=transform,
                source_span=task[start:end], source_start=start, source_end=end,
            )
            if verify_receipt(receipt, task_text=task_text):
                out.append({
                    "argument": name, "value": value, "transform": transform,
                    "source_span": receipt.source_span,
                    "source_start": start, "source_end": end,
                })
                break
        if len(out) >= MAX_RECEIPTS:
            break
    return tuple(out)

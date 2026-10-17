# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Derived information-flow control (docs/design/derived-information-flow-control-v1.md).

IFC-01 provides the label lattice. Nothing here is wired into a decision yet;
later work packages land behind ``REMORA_FLOW_CONTROL``.
"""
from remora.flow.label import (
    BOTTOM,
    PUBLIC,
    Integrity,
    Label,
    LabelRefused,
    canonical_bytes,
    field_value_label,
    flows_to,
    join,
    join_all,
    leq,
)

__all__ = [
    "BOTTOM",
    "PUBLIC",
    "Integrity",
    "Label",
    "LabelRefused",
    "canonical_bytes",
    "field_value_label",
    "flows_to",
    "join",
    "join_all",
    "leq",
]

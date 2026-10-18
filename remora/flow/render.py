# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""What the model sees in place of a value it may not see (SDD v1.3 §3.4, IFC-04).

A handle is rendered as ``{"$handle": "⟦h:…⟧", "$type": <tag>}``. The token
has a fixed width, so it hides the value's length. The tag comes from the
ToolSpec's declared field type, never from the runtime value; a field with no
declared type gets ``value``. Nothing else about the value (length, hash,
label) is rendered.
"""
from __future__ import annotations

from typing import Any, Final

__all__ = ["HANDLE_KEY", "TYPE_KEY", "handle_ref", "is_handle_ref"]

HANDLE_KEY: Final = "$handle"
TYPE_KEY: Final = "$type"


def handle_ref(token: str, type_tag: str) -> dict[str, str]:
    """The agent-facing stand-in for one handle."""
    return {HANDLE_KEY: token, TYPE_KEY: type_tag}


def is_handle_ref(value: Any) -> bool:
    return isinstance(value, dict) and set(value) == {HANDLE_KEY, TYPE_KEY}

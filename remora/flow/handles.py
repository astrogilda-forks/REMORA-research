# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Handles: values the model refers to but does not see (SDD v1.3 §3.4, IFC-04).

A handle is ``⟦h:<16 base32 characters>⟧``, 80 random bits. Its record
holds the value, the value's label, the declared type tag, the context that
minted it, the proposal that created it and an expiry.

- A handle is valid only in the context that minted it or a descendant of
  it. The caller passes the using context's lineage (itself, then its
  ancestors). A foreign, unknown or expired handle raises
  :class:`FlowHandleInvalid` (``flow_handle_invalid``), which the decision
  turns into ABSTAIN.
- :meth:`HandleStore.resolve` substitutes handle values into a call's
  arguments, anywhere they occur, and returns a value label per top-level
  field: ``L_h`` for a field whose whole value is one handle, and
  ``L_ctx ⊔ ⨆ embedded handle labels`` for any other field, because literal
  text came from the model (:func:`remora.flow.label.field_value_label`).
- A stored record never changes. Writing a different record under an
  existing id is refused.

This module holds the in-process backend. A durable backend, with values
encrypted at rest under the deployment data key, follows separately.
"""
from __future__ import annotations

import base64
import json
import re
import secrets
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Protocol

from remora.flow.label import Label, field_value_label

__all__ = [
    "HANDLE_TOKEN",
    "FlowHandleInvalid",
    "HandleRecord",
    "HandleStore",
    "InMemoryHandleBackend",
    "Resolution",
    "handle_token",
    "new_handle_id",
]

#: One handle token. The id is 80 bits in RFC 4648 base32 without padding.
HANDLE_TOKEN: Final = re.compile(r"⟦h:([A-Z2-7]{16})⟧")


class FlowHandleInvalid(Exception):
    """A handle that is unknown, expired, or not valid in this context."""

    reason_code = "flow_handle_invalid"


def new_handle_id() -> str:
    return base64.b32encode(secrets.token_bytes(10)).decode("ascii")


def handle_token(handle_id: str) -> str:
    return f"⟦h:{handle_id}⟧"


@dataclass(frozen=True)
class HandleRecord:
    handle_id: str
    tenant_id: str
    context_id: str
    #: A JSON value.
    value: Any
    label: Label
    type_tag: str
    created_by_proposal: str
    #: Seconds since the epoch; the handle is invalid from this instant on.
    expires_at: float


@dataclass(frozen=True)
class Resolution:
    """A call's arguments with handles substituted, and their value labels."""

    args: dict[str, Any]
    value_labels: dict[str, Label]
    #: The handle ids used, in first-use order.
    handles: tuple[str, ...]


class HandleBackend(Protocol):
    def put(self, record: HandleRecord) -> None: ...
    def get(self, tenant_id: str, handle_id: str) -> HandleRecord | None: ...


class InMemoryHandleBackend:
    """Per-process handles. Lost on restart, which makes every handle invalid:
    a later call that names one is refused, so the loss fails closed."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], HandleRecord] = {}
        self._lock = threading.Lock()

    def put(self, record: HandleRecord) -> None:
        key = (record.tenant_id, record.handle_id)
        with self._lock:
            existing = self._records.get(key)
            if existing is not None and existing != record:
                raise ValueError(f"handle {record.handle_id} already holds another record")
            self._records[key] = record

    def get(self, tenant_id: str, handle_id: str) -> HandleRecord | None:
        with self._lock:
            return self._records.get((tenant_id, handle_id))


class HandleStore:
    def __init__(self, backend: HandleBackend,
                 clock: Callable[[], float] = time.time) -> None:
        self._backend = backend
        self._clock = clock

    def put_all(self, records: Iterable[HandleRecord]) -> None:
        for record in records:
            self._backend.put(record)

    def _valid(self, tenant_id: str, lineage: Sequence[str], handle_id: str,
               now: float) -> HandleRecord:
        record = self._backend.get(tenant_id, handle_id)
        # One refusal for all three cases: the caller learns nothing about
        # which handles exist elsewhere.
        if record is None or record.context_id not in lineage or now >= record.expires_at:
            raise FlowHandleInvalid("flow_handle_invalid")
        return record

    def resolve(self, tenant_id: str, lineage: Sequence[str], args: Mapping[str, Any], *,
                context_label: Label) -> Resolution:
        """Substitute every handle in ``args``; refuse the call on any invalid one."""
        now = self._clock()
        used: dict[str, HandleRecord] = {}

        def lookup(handle_id: str) -> HandleRecord:
            if handle_id not in used:
                used[handle_id] = self._valid(tenant_id, lineage, handle_id, now)
            return used[handle_id]

        def substitute(value: Any, seen: list[Label]) -> Any:
            if isinstance(value, str):
                whole = HANDLE_TOKEN.fullmatch(value)
                if whole:
                    record = lookup(whole.group(1))
                    seen.append(record.label)
                    return record.value

                def text(match: re.Match[str]) -> str:
                    record = lookup(match.group(1))
                    seen.append(record.label)
                    v = record.value
                    return v if isinstance(v, str) else json.dumps(
                        v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

                return HANDLE_TOKEN.sub(text, value)
            if isinstance(value, Mapping):
                return {k: substitute(v, seen) for k, v in value.items()}
            if isinstance(value, (list, tuple)):
                return [substitute(v, seen) for v in value]
            return value

        resolved: dict[str, Any] = {}
        labels: dict[str, Label] = {}
        for name, value in args.items():
            seen: list[Label] = []
            whole = isinstance(value, str) and HANDLE_TOKEN.fullmatch(value) is not None
            resolved[name] = substitute(value, seen)
            labels[name] = field_value_label(exactly_one_handle=whole, context=context_label,
                                             handle_labels=seen)
        return Resolution(args=resolved, value_labels=labels, handles=tuple(used))

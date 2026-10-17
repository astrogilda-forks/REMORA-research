# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The label lattice (SDD §3.1, IFC-01).

A label is ``(readers, integrity)``. ``readers`` is :data:`PUBLIC` or a set
of principal patterns: canonical resources such as ``email://corp.example/bob``,
or subtrees such as ``email://corp.example/*``, in the form
:mod:`remora.capabilities.resource` accepts. Integrity is TRUSTED or
UNTRUSTED.

Order and join::

    L1 ⊑ L2  iff  readers(L2) ⊆ readers(L1)  and  (L1 untrusted ⇒ L2 untrusted)
    L1 ⊔ L2  =  (readers(L1) ∩ readers(L2), untrusted if either is)
    ⊥        =  (PUBLIC, TRUSTED)

Patterns form a tree: two patterns are either nested or disjoint. The
intersection of two patterns is therefore the more specific one when one is
within the other, and empty otherwise, which is exact rather than an
approximation. A reader set is kept as its minimal antichain (no pattern
within another), so two labels that admit the same principals are equal
and serialise to the same bytes.

This module is pure and part of the trusted computing base. It does no I/O
and consults no model.
"""
from __future__ import annotations

import enum
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final, Literal

from remora.capabilities.resource import (
    ResourceRefused,
    canonical_resource_pattern,
    resource_within,
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

_SERIAL_VERSION: Final = "remora/flow-label/v1"


class LabelRefused(ValueError):
    """A reader pattern with no single canonical meaning."""


class Integrity(enum.Enum):
    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"


class _Public:
    """The top reader set: anyone may read. A singleton, not a resource."""

    _instance: _Public | None = None

    def __new__(cls) -> _Public:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "PUBLIC"

    def __reduce__(self) -> str:
        return "PUBLIC"


PUBLIC: Final = _Public()

Readers = _Public | frozenset[str]


def _pattern_within(inner: str, outer: str) -> bool:
    """Whether every principal ``inner`` admits is admitted by ``outer``.

    Both are canonical patterns. A subtree ``x/*`` admits the resources
    strictly below ``x``, as :func:`resource_within` does.
    """
    if outer.endswith("/*"):
        prefix = outer[:-1]  # "scheme://authority/path/"
        if inner.endswith("/*"):
            return inner[:-1].startswith(prefix)
        return resource_within(inner, [outer])
    # An exact pattern admits one principal; a subtree never fits inside it.
    return not inner.endswith("/*") and inner == outer


def _antichain(patterns: Iterable[str]) -> frozenset[str]:
    """Drop every pattern that another pattern in the set already covers."""
    unique = set(patterns)
    return frozenset(
        p for p in unique
        if not any(q != p and _pattern_within(p, q) for q in unique)
    )


def _canonical_readers(readers: Readers | Iterable[str]) -> Readers:
    if isinstance(readers, _Public):
        return PUBLIC
    if isinstance(readers, str):
        raise LabelRefused("readers is PUBLIC or a set of patterns, not one string")
    out = []
    for raw in readers:
        try:
            out.append(canonical_resource_pattern(raw))
        except ResourceRefused as exc:
            raise LabelRefused(f"reader pattern {raw!r}: {exc}") from exc
    return _antichain(out)


@dataclass(frozen=True, init=False)
class Label:
    """``(readers, integrity)``. Construct with any iterable of patterns or :data:`PUBLIC`."""

    readers: Readers
    integrity: Integrity

    def __init__(self, readers: Readers | Iterable[str],
                 integrity: Integrity = Integrity.TRUSTED) -> None:
        if not isinstance(integrity, Integrity):
            raise LabelRefused(f"integrity must be an Integrity, not {integrity!r}")
        object.__setattr__(self, "readers", _canonical_readers(readers))
        object.__setattr__(self, "integrity", integrity)

    @property
    def is_public(self) -> bool:
        return not isinstance(self.readers, frozenset)

    @property
    def trusted(self) -> bool:
        return self.integrity is Integrity.TRUSTED


BOTTOM: Final = Label(PUBLIC, Integrity.TRUSTED)


def _readers_within(inner: Readers, outer: Readers) -> bool:
    """``inner ⊆ outer`` as sets of admitted principals."""
    if not isinstance(outer, frozenset):
        return True  # outer is PUBLIC
    if not isinstance(inner, frozenset):
        return False  # PUBLIC is within nothing but PUBLIC
    return all(any(_pattern_within(p, q) for q in outer) for p in inner)


def _intersect(a: Readers, b: Readers) -> Readers:
    if not isinstance(a, frozenset):
        return b
    if not isinstance(b, frozenset):
        return a
    out: set[str] = set()
    for p in a:
        for q in b:
            if _pattern_within(p, q):
                out.add(p)
            elif _pattern_within(q, p):
                out.add(q)
    return _antichain(out)


def leq(l1: Label, l2: Label) -> bool:
    """``l1 ⊑ l2``: ``l2`` is at least as restrictive as ``l1``."""
    integrity_ok = l1.trusted or not l2.trusted
    return integrity_ok and _readers_within(l2.readers, l1.readers)


def join(l1: Label, l2: Label) -> Label:
    """``l1 ⊔ l2``: readers intersect, integrity is untrusted if either is."""
    integrity = (Integrity.TRUSTED if l1.trusted and l2.trusted
                 else Integrity.UNTRUSTED)
    return Label(_intersect(l1.readers, l2.readers), integrity)


def join_all(labels: Iterable[Label], start: Label = BOTTOM) -> Label:
    out = start
    for label in labels:
        out = join(out, label)
    return out


def flows_to(label: Label, principal: str) -> bool:
    """Whether data under ``label`` may reach ``principal``.

    ``principal`` is a canonical resource. An ambiguous principal never
    receives anything but PUBLIC data.
    """
    if not isinstance(label.readers, frozenset):
        return True  # PUBLIC
    return resource_within(principal, label.readers)


def field_value_label(*, exactly_one_handle: bool, context: Label,
                      handle_labels: Iterable[Label]) -> Label:
    """The value label of one top-level argument field (SDD §3.4).

    A field whose whole value is exactly one handle carries that handle's
    label: its bytes come only from the handle, so its integrity does not
    depend on what the model has read. Any other field contains literal
    text the model wrote, so it carries the context label joined with every
    embedded handle's label.
    """
    labels = list(handle_labels)
    if exactly_one_handle:
        if len(labels) != 1:
            raise LabelRefused("a whole-handle field has exactly one handle label")
        return labels[0]
    return join_all(labels, start=context)


def canonical_bytes(label: Label) -> bytes:
    """Deterministic bytes for hashing (versioned, sorted, compact UTF-8 JSON)."""
    readers: Literal["PUBLIC"] | list[str] = (
        sorted(label.readers) if isinstance(label.readers, frozenset) else "PUBLIC")
    # Written out of order on purpose: sort_keys, not insertion order, fixes the bytes.
    body: Mapping[str, object] = {
        "v": _SERIAL_VERSION,
        "readers": readers,
        "integrity": label.integrity.value,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")

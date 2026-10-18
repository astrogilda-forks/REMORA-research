# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Label a tool result and decide what the model sees (SDD v1.3 §3.3, IFC-04).

:meth:`FlowLabeler.label_result` walks a JSON result and gives every node a
label from the ToolSpec ``flow.sources`` block:

- A node uses the rule whose path matches its own path exactly (``[*]``
  matches any index). A node no rule matches gets the defaults: readers
  ``{user_principal}``, integrity ``default_integrity``, rendered as a
  handle. Rules are not inherited: a rule for ``$[*]`` says nothing about
  ``$[*].sender``.
- Readers come from the rule's kind: ``PUBLIC``, ``static``,
  ``from_source_metadata`` (reported by the source system, looked up at the
  node's nearest path that the metadata names), ``resource_acl`` (the ACL of
  the resource an argument names, from the deployment's resolver) or
  ``inherit_args``. ``plus_user`` and ``plus_processors`` add the context's
  user and processors. A reader the source reports that is not a canonical
  principal is dropped, which only narrows the label.
- Every label is joined with the call's argument labels: data that went in
  can come out.

Rendering. A node is shown by value only when its rule says ``BY_VALUE`` (or
it has no rule and its label is ⊥) and its label flows to the model
principal (§3.2.1). Otherwise the node and everything under it becomes one
handle, labelled with the join of every label in that subtree. A container
shown by value reveals its structure (its length, its keys, which children
are null), so its own label joins the raise, except the length of a list
whose rule declares ``length_public``. Every leaf shown by value joins the
raise.

The labeler is pure. It returns the rendered result, the label to raise the
context by, and the handle records to store; committing the raise and the
handles before the rendered result is returned is the dispatcher's job
(IFC-04b, §3.3.2).
"""
from __future__ import annotations

import json
import math
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from remora.capabilities.resource import ResourceRefused, canonical_resource
from remora.flow.handles import HandleRecord, handle_token, new_handle_id
from remora.flow.label import (
    BOTTOM,
    PUBLIC,
    Label,
    flows_to,
    join,
    join_all,
)
from remora.flow.render import handle_ref
from remora.flow.spec import FieldRule, FlowSpec

__all__ = ["FlowLabeler", "FlowLabelingError", "LabeledResult", "LabelingContext"]

#: Type tag of a handle whose field declares no type.
UNDECLARED_TYPE = "value"


class FlowLabelingError(ValueError):
    """A result the labeler cannot give labels to, such as a non-JSON value."""


@dataclass(frozen=True)
class LabelingContext:
    tenant_id: str
    context_id: str
    user_principal: str
    model_principal: str
    processors: frozenset[str]
    proposal_id: str


@dataclass(frozen=True)
class LabeledResult:
    #: What the model receives: values and handle references.
    rendered: Any
    #: Join of every label shown by value; the context label rises by it.
    raise_label: Label
    #: Records to store before ``rendered`` is returned.
    handles: tuple[HandleRecord, ...] = field(default=())


# A concrete path is a tuple of steps: ("k", key) or ("i", index).
_Step = tuple[str, Any]


def _pattern_steps(pattern: str) -> tuple[str, ...]:
    """'$[*].a.b' -> ('[*]', 'a', 'b')."""
    out: list[str] = []
    rest = pattern[1:]
    while rest:
        if rest.startswith("[*]"):
            out.append("[*]")
            rest = rest[3:]
        else:
            name = rest[1:].split(".", 1)[0].split("[", 1)[0]
            out.append(name)
            rest = rest[1 + len(name):]
    return tuple(out)


def _matches(pattern: tuple[str, ...], path: tuple[_Step, ...]) -> bool:
    if len(pattern) != len(path):
        return False
    for p, (kind, value) in zip(pattern, path, strict=True):
        if p == "[*]":
            if kind != "i":
                return False
        elif kind != "k" or value != p:
            return False
    return True


def _path_text(path: tuple[_Step, ...]) -> str:
    out = "$"
    for kind, value in path:
        if kind == "i":
            out += f"[{value}]"
        elif value.isidentifier():
            out += f".{value}"
        else:
            out += f"[{json.dumps(value, ensure_ascii=False)}]"
    return out


def _check_json(value: Any) -> None:
    if value is None or isinstance(value, (bool, str, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise FlowLabelingError("a result holds a non-finite number")
        return
    if isinstance(value, (list, tuple)):
        for v in value:
            _check_json(v)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise FlowLabelingError("a result object has a non-string key")
            _check_json(v)
        return
    raise FlowLabelingError(f"a result holds a {type(value).__name__}, not a JSON value")


class FlowLabeler:
    def __init__(self, *, resource_acl: Callable[[str], Iterable[str]] | None = None,
                 clock: Callable[[], float] = time.time, ttl_seconds: float = 3600.0) -> None:
        self._resource_acl = resource_acl
        self._clock = clock
        self._ttl = ttl_seconds

    def label_result(self, flow: FlowSpec, ctx: LabelingContext, *,
                     resolved_args: Mapping[str, Any], arg_labels: Mapping[str, Label],
                     raw_result: Any,
                     source_metadata: Mapping[str, Mapping[str, Iterable[str]]] | None = None,
                     ) -> LabeledResult:
        _check_json(raw_result)
        sources = flow.sources
        rules = [(_pattern_steps(r.path), r) for r in sources.fields]
        args_label = join_all(arg_labels.values())
        metadata = source_metadata or {}
        expires = self._clock() + self._ttl
        minted: list[HandleRecord] = []
        raised = [BOTTOM]

        def rule_for(path: tuple[_Step, ...]) -> FieldRule | None:
            for pattern, rule in rules:
                if _matches(pattern, path):
                    return rule
            return None

        def canonical(principals: Iterable[str]) -> set[str]:
            # Exact principals only. A subtree pattern from a source would
            # widen the label to principals the source never named.
            out = set()
            for p in principals:
                try:
                    out.add(canonical_resource(p))
                except (ResourceRefused, TypeError, AttributeError):
                    continue  # not a principal: dropping it only narrows
            return out

        def metadata_readers(name: str, path: tuple[_Step, ...]) -> set[str]:
            table = metadata.get(name, {})
            for depth in range(len(path), -1, -1):
                key = _path_text(path[:depth])
                if key in table:
                    return canonical(table[key])
            return set()

        def label_of(path: tuple[_Step, ...], rule: FieldRule | None) -> Label:
            integrity = sources.default_integrity
            readers: Any = {ctx.user_principal}
            if rule is not None:
                integrity = rule.integrity or sources.default_integrity
                r = rule.readers
                if r.kind == "public":
                    readers = PUBLIC
                elif r.kind == "static":
                    readers = set(r.values)
                elif r.kind == "from_source_metadata":
                    readers = set()
                    for name in r.values:
                        readers |= metadata_readers(name, path)
                elif r.kind == "resource_acl":
                    resource = resolved_args.get(r.values[0])
                    readers = (canonical(self._resource_acl(resource))
                               if self._resource_acl is not None and isinstance(resource, str)
                               else set())
                elif r.kind == "inherit_args":
                    readers = (args_label.readers if arg_labels else {ctx.user_principal})
                if readers is not PUBLIC:
                    readers = set(readers)
                    if r.plus_user:
                        readers.add(ctx.user_principal)
                    if r.plus_processors:
                        readers |= ctx.processors
            return join(Label(readers, integrity), args_label)

        def subtree_label(node: Any, path: tuple[_Step, ...]) -> Label:
            own = label_of(path, rule_for(path))
            if isinstance(node, dict):
                return join_all((subtree_label(v, (*path, ("k", k))) for k, v in node.items()),
                                start=own)
            if isinstance(node, (list, tuple)):
                return join_all((subtree_label(v, (*path, ("i", i)))
                                 for i, v in enumerate(node)), start=own)
            return own

        def as_handle(node: Any, path: tuple[_Step, ...], rule: FieldRule | None) -> dict:
            record = HandleRecord(
                handle_id=new_handle_id(), tenant_id=ctx.tenant_id, context_id=ctx.context_id,
                value=json.loads(json.dumps(node)), label=subtree_label(node, path),
                type_tag=(rule.type if rule is not None and rule.type else UNDECLARED_TYPE),
                created_by_proposal=ctx.proposal_id, expires_at=expires)
            minted.append(record)
            return handle_ref(handle_token(record.handle_id), record.type_tag)

        def render(node: Any, path: tuple[_Step, ...]) -> Any:
            rule = rule_for(path)
            label = label_of(path, rule)
            mode = (rule.return_mode if rule is not None and rule.return_mode
                    else ("BY_VALUE" if label == BOTTOM else sources.default_return_mode))
            if mode != "BY_VALUE" or not flows_to(label, ctx.model_principal):
                return as_handle(node, path, rule)
            if isinstance(node, dict):
                raised.append(label)
                return {k: render(v, (*path, ("k", k))) for k, v in node.items()}
            if isinstance(node, (list, tuple)):
                if not (rule is not None and rule.length_public):
                    raised.append(label)
                return [render(v, (*path, ("i", i))) for i, v in enumerate(node)]
            raised.append(label)
            return node

        rendered = render(raw_result, ())
        return LabeledResult(rendered=rendered, raise_label=join_all(raised),
                             handles=tuple(minted))

# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The ToolSpec v4 ``flow`` block: parse and lint (SDD v1.3 §3.3, §3.5, §5.1; IFC-03).

A ``flow`` block states two things about a tool. ``sources`` says how each
field of its result is labelled and whether the model sees it by value or as
a handle. ``sink`` says who receives the call's arguments. The contract is
``schemas/tool_spec_v4.yaml``.

:func:`parse_flow` turns a block into frozen data, or refuses it with
``toolspec_flow_invalid``. It refuses any key it does not define: a key
nothing reads would be a constraint the author believes in and the runtime
ignores. :func:`lint_flow` then checks the block against the rest of the
spec (argument schema, action type, effect mode) and returns one finding per
broken rule, FL-01 to FL-12. :func:`lint_toolspec` adds FL-13, the strict
profile's refusal of a spec with no block.

Defaults fail closed: an undeclared field is UNTRUSTED, rendered as a handle,
and readable by the user principal alone. Nothing here does I/O or consults
a model. Labelling results with these rules is IFC-04; the flow check is
IFC-05.
"""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from remora.capabilities.resource import (
    ResourceRefused,
    canonical_resource,
    canonical_resource_pattern,
)
from remora.flow.label import PUBLIC, Integrity

__all__ = [
    "ARGUMENT_KINDS",
    "LINT_RULES",
    "FieldRule",
    "FlowSink",
    "FlowSources",
    "FlowSpec",
    "FlowSpecRefused",
    "LintFinding",
    "ReadersRule",
    "Recipients",
    "SourceMetadata",
    "lint_flow",
    "lint_toolspec",
    "parse_flow",
]

#: Kinds an argument may declare. ``url`` makes a sink of ``recipients:
#: none`` a lint failure (FL-01); ``resource`` makes a write name its
#: resource (FL-05).
ARGUMENT_KINDS: Final = ("url", "email", "iban", "resource", "principal", "text", "scalar")
RETURN_MODES: Final = ("BY_VALUE", "BY_HANDLE")
#: Declared field types. A handle's type tag is taken from here only.
FIELD_TYPES: Final = ("string", "bytes", "number", "list", "object")
DISCLOSURES: Final = ("BY_VALUE", "CHARGE_BUDGET")
#: Kinds a ``from_args`` recipient rule may map an argument to.
FROM_ARGS_KINDS: Final = ("email", "principal")

LINT_RULES: Final = (
    "FL-01", "FL-02", "FL-03", "FL-04", "FL-05", "FL-06", "FL-07",
    "FL-08", "FL-09", "FL-10", "FL-11", "FL-12", "FL-13",
)

_PATH = re.compile(r"\$(?:\.[A-Za-z_][A-Za-z0-9_]*|\[\*\])*")
_INVALID = "toolspec_flow_invalid"


class FlowSpecRefused(ValueError):
    """A ``flow`` block with no single meaning. ``reason_code`` is published."""

    def __init__(self, message: str, reason_code: str = _INVALID) -> None:
        super().__init__(f"{reason_code}: {message}")
        self.reason_code = reason_code


@dataclass(frozen=True)
class LintFinding:
    """One broken lint rule."""

    rule: str
    tool_id: str
    message: str

    def __str__(self) -> str:
        return f"{self.rule} {self.tool_id}: {self.message}"


@dataclass(frozen=True)
class ReadersRule:
    """How a field's reader set is computed (SDD §3.3).

    ``kind`` is ``default`` (no ``readers`` key: the user principal alone),
    ``public``, ``static``, ``from_source_metadata``, ``resource_acl`` or
    ``inherit_args``. ``values`` holds the canonical patterns for
    ``static``, the metadata names for ``from_source_metadata`` and the
    argument name for ``resource_acl``.
    """

    kind: str
    values: tuple[str, ...] = ()
    plus_user: bool = False
    plus_processors: bool = False

    @property
    def public(self) -> object | None:
        return PUBLIC if self.kind == "public" else None


@dataclass(frozen=True)
class FieldRule:
    path: str
    integrity: Integrity | None
    readers: ReadersRule
    return_mode: str | None
    public_justification: str | None
    length_public: bool
    #: The declared type, or None. Never computed from a runtime value.
    type: str | None = None


@dataclass(frozen=True)
class SourceMetadata:
    name: str
    authority: str | None
    origin: str | None
    disclosure: str | None


@dataclass(frozen=True)
class FlowSources:
    default_integrity: Integrity
    default_return_mode: str
    fields: tuple[FieldRule, ...]
    source_metadata: Mapping[str, SourceMetadata]


@dataclass(frozen=True)
class Recipients:
    """``kind`` is ``none``, ``from_args``, ``url_host_of``, ``iban_of``,
    ``resource_of`` or ``static``."""

    kind: str
    argument: str | None = None
    from_args: tuple[tuple[str, str], ...] = ()
    static: tuple[str, ...] = ()

    def arguments(self) -> tuple[str, ...]:
        if self.kind == "from_args":
            return tuple(a for a, _ in self.from_args)
        return (self.argument,) if self.argument is not None else ()


@dataclass(frozen=True)
class FlowSink:
    recipients: Recipients
    #: None means every argument carries payload.
    payload_args: tuple[str, ...] | None
    integrity_required: tuple[str, ...]
    roles_accepted: tuple[tuple[str, tuple[str, ...]], ...]
    control_integrity_required: bool


@dataclass(frozen=True)
class FlowSpec:
    #: ``tcb``, or the canonical principal of the executing service.
    provider: str
    arguments: tuple[tuple[str, str], ...]
    sources: FlowSources
    sink: FlowSink

    def argument_kind(self, name: str) -> str | None:
        return dict(self.arguments).get(name)


# ── parsing ───────────────────────────────────────────────────────────────

def _mapping(value: Any, where: str, allowed: Sequence[str],
             required: Sequence[str] = ()) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FlowSpecRefused(f"{where} must be a mapping")
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise FlowSpecRefused(f"{where} has keys this schema does not define: {unknown}")
    missing = [k for k in required if k not in value]
    if missing:
        raise FlowSpecRefused(f"{where} is missing {missing}")
    return value


def _names(value: Any, where: str) -> tuple[str, ...]:
    if (not isinstance(value, (list, tuple))
            or not all(isinstance(v, str) and v for v in value)):
        raise FlowSpecRefused(f"{where} must be a list of names")
    if len(set(value)) != len(value):
        raise FlowSpecRefused(f"{where} repeats a name")
    return tuple(value)


def _flag(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise FlowSpecRefused(f"{where} must be true or false")
    return value


def _choice(value: Any, choices: Sequence[str], where: str) -> str:
    if value not in choices:
        raise FlowSpecRefused(f"{where} {value!r} is not one of {list(choices)}")
    return str(value)


def _integrity(value: Any, where: str) -> Integrity:
    return Integrity(_choice(value, [i.value for i in Integrity], where))


def _patterns(value: Any, where: str, *, exact: bool) -> tuple[str, ...]:
    out = []
    for raw in _names(value, where):
        try:
            out.append(canonical_resource(raw) if exact else canonical_resource_pattern(raw))
        except ResourceRefused as exc:
            raise FlowSpecRefused(f"{where}: {raw!r} is not canonical: {exc}") from exc
    return tuple(out)


_READER_KINDS = ("static", "from_source_metadata", "resource_acl", "inherit_args")


def _readers(value: Any, where: str) -> ReadersRule:
    if value == "PUBLIC":
        return ReadersRule("public")
    rule = _mapping(value, where, (*_READER_KINDS, "plus_user", "plus_processors"))
    kinds = [k for k in _READER_KINDS if k in rule]
    if len(kinds) != 1:
        raise FlowSpecRefused(f"{where} names exactly one of {list(_READER_KINDS)}")
    kind = kinds[0]
    plus_user = _flag(rule.get("plus_user", False), f"{where}.plus_user")
    plus_processors = _flag(rule.get("plus_processors", False), f"{where}.plus_processors")
    if kind == "static":
        values = _patterns(rule[kind], f"{where}.static", exact=False)
    elif kind == "from_source_metadata":
        values = _names(rule[kind], f"{where}.from_source_metadata")
    elif kind == "resource_acl":
        if not isinstance(rule[kind], str) or not rule[kind]:
            raise FlowSpecRefused(f"{where}.resource_acl names one argument")
        values = (rule[kind],)
    else:
        if rule[kind] is not True:
            raise FlowSpecRefused(f"{where}.inherit_args must be true")
        values = ()
    return ReadersRule(kind, values, plus_user, plus_processors)


def _field(value: Any, where: str) -> FieldRule:
    raw = _mapping(value, where, ("path", "integrity", "readers", "return_mode",
                                  "public_justification", "length_public", "type"),
                   ("path",))
    path = raw["path"]
    if not isinstance(path, str) or not _PATH.fullmatch(path):
        raise FlowSpecRefused(f"{where}.path {path!r} is not $, $.name... or $[*]...")
    justification = raw.get("public_justification")
    if justification is not None and not isinstance(justification, str):
        raise FlowSpecRefused(f"{where}.public_justification must be text")
    return FieldRule(
        path=path,
        integrity=(_integrity(raw["integrity"], f"{where}.integrity")
                   if "integrity" in raw else None),
        readers=(_readers(raw["readers"], f"{where}.readers")
                 if "readers" in raw else ReadersRule("default")),
        return_mode=(_choice(raw["return_mode"], RETURN_MODES, f"{where}.return_mode")
                     if "return_mode" in raw else None),
        public_justification=justification,
        length_public=_flag(raw.get("length_public", False), f"{where}.length_public"),
        type=(_choice(raw["type"], FIELD_TYPES, f"{where}.type") if "type" in raw else None),
    )


def _sources(value: Any) -> FlowSources:
    raw = _mapping(value, "flow.sources", ("default_integrity", "default_return_mode",
                                          "fields", "source_metadata"))
    fields_raw = raw.get("fields", [])
    if not isinstance(fields_raw, (list, tuple)):
        raise FlowSpecRefused("flow.sources.fields must be a list")
    fields = tuple(_field(f, f"flow.sources.fields[{i}]") for i, f in enumerate(fields_raw))
    paths = [f.path for f in fields]
    if len(set(paths)) != len(paths):
        raise FlowSpecRefused("flow.sources.fields declares a path twice")
    meta_raw = raw.get("source_metadata", {})
    if not isinstance(meta_raw, Mapping):
        raise FlowSpecRefused("flow.sources.source_metadata must be a mapping")
    metadata = {}
    for name, entry in meta_raw.items():
        where = f"flow.sources.source_metadata.{name}"
        m = _mapping(entry, where, ("authority", "from", "disclosure"))
        disclosure = m.get("disclosure")
        if disclosure is not None:
            disclosure = _choice(disclosure, DISCLOSURES, f"{where}.disclosure")
        metadata[str(name)] = SourceMetadata(
            name=str(name), authority=m.get("authority"), origin=m.get("from"),
            disclosure=disclosure)
    return FlowSources(
        default_integrity=_integrity(raw.get("default_integrity", "UNTRUSTED"),
                                     "flow.sources.default_integrity"),
        default_return_mode=_choice(raw.get("default_return_mode", "BY_HANDLE"),
                                    RETURN_MODES, "flow.sources.default_return_mode"),
        fields=fields,
        source_metadata=metadata,
    )


_RECIPIENT_KINDS = ("from_args", "url_host_of", "iban_of", "resource_of", "static")


def _recipients(value: Any) -> Recipients:
    where = "flow.sink.recipients"
    if value == "none":
        return Recipients("none")
    raw = _mapping(value, where, _RECIPIENT_KINDS)
    if len(raw) != 1:
        raise FlowSpecRefused(f"{where} is none or exactly one of {list(_RECIPIENT_KINDS)}")
    kind, arg = next(iter(raw.items()))
    if kind == "from_args":
        m = _mapping(arg, f"{where}.from_args", tuple(arg) if isinstance(arg, Mapping) else ())
        if not m:
            raise FlowSpecRefused(f"{where}.from_args names at least one argument")
        pairs = tuple(sorted((str(a), _choice(k, FROM_ARGS_KINDS, f"{where}.from_args.{a}"))
                             for a, k in m.items()))
        return Recipients("from_args", from_args=pairs)
    if kind == "static":
        return Recipients("static", static=_patterns(arg, f"{where}.static", exact=True))
    if not isinstance(arg, str) or not arg:
        raise FlowSpecRefused(f"{where}.{kind} names one argument")
    return Recipients(kind, argument=arg)


def _sink(value: Any) -> FlowSink:
    raw = _mapping(value, "flow.sink", ("recipients", "payload_args", "integrity_required",
                                        "roles_accepted", "control_integrity_required"),
                   ("recipients",))
    roles_raw = raw.get("roles_accepted", {})
    if not isinstance(roles_raw, Mapping):
        raise FlowSpecRefused("flow.sink.roles_accepted must be a mapping")
    roles = tuple(sorted((str(a), _names(r, f"flow.sink.roles_accepted.{a}"))
                         for a, r in roles_raw.items()))
    return FlowSink(
        recipients=_recipients(raw["recipients"]),
        payload_args=(_names(raw["payload_args"], "flow.sink.payload_args")
                      if "payload_args" in raw else None),
        integrity_required=_names(raw.get("integrity_required", []),
                                  "flow.sink.integrity_required"),
        roles_accepted=roles,
        control_integrity_required=_flag(raw.get("control_integrity_required", False),
                                         "flow.sink.control_integrity_required"),
    )


def parse_flow(raw: Any) -> FlowSpec:
    """The block as frozen data, or :class:`FlowSpecRefused`."""
    block = _mapping(raw, "flow", ("provider", "arguments", "sources", "sink"),
                     ("provider", "arguments", "sink"))
    provider = block["provider"]
    if provider != "tcb":
        if not isinstance(provider, str):
            raise FlowSpecRefused("flow.provider is tcb or a principal")
        try:
            provider = canonical_resource(provider)
        except ResourceRefused as exc:
            raise FlowSpecRefused(f"flow.provider {provider!r} is not canonical: {exc}") from exc
    args_raw = block["arguments"]
    if not isinstance(args_raw, Mapping):
        raise FlowSpecRefused("flow.arguments must be a mapping")
    arguments = []
    for name, decl in args_raw.items():
        d = _mapping(decl, f"flow.arguments.{name}", ("kind",), ("kind",))
        arguments.append((str(name), _choice(d["kind"], ARGUMENT_KINDS,
                                             f"flow.arguments.{name}.kind")))
    return FlowSpec(
        provider=provider,
        arguments=tuple(sorted(arguments)),
        sources=_sources(block.get("sources", {})),
        sink=_sink(block["sink"]),
    )


# ── linting ───────────────────────────────────────────────────────────────

def _read_only(action_type: str | None) -> bool:
    from remora.policy.decision_engine import _READ_ONLY_ACTION_TYPES

    return (action_type or "").strip().lower() in _READ_ONLY_ACTION_TYPES


def _schema_arguments(argument_schema: Mapping[str, Any]) -> set[str]:
    props = argument_schema.get("properties") if isinstance(argument_schema, Mapping) else None
    return set(props) if isinstance(props, Mapping) else set()


def lint_flow(flow: FlowSpec, *, argument_schema: Mapping[str, Any],
              action_type: str | None, effect_mode: str | None,
              tool_id: str = "?") -> tuple[LintFinding, ...]:
    """Every broken rule FL-01 to FL-12, ordered by rule."""
    found: list[LintFinding] = []

    def fail(rule: str, message: str) -> None:
        found.append(LintFinding(rule, tool_id, message))

    sink, sources = flow.sink, flow.sources
    recipients = sink.recipients
    schema_args = _schema_arguments(argument_schema)
    kinds = dict(flow.arguments)
    read_only = _read_only(action_type)

    if recipients.kind == "none":
        for name, kind in flow.arguments:
            if kind == "url":
                fail("FL-01", f"argument {name!r} is a url, so recipients cannot be none")

    named = [*sink.integrity_required, *(sink.payload_args or ()),
             *(a for a, _ in sink.roles_accepted), *recipients.arguments(),
             *(f.readers.values[0] for f in sources.fields if f.readers.kind == "resource_acl")]
    for name in sorted(set(named) - schema_args):
        fail("FL-02", f"names argument {name!r}, which the argument schema does not declare")

    if sources.default_return_mode == "BY_VALUE":
        fail("FL-03", "default_return_mode BY_VALUE would render undeclared fields by value")

    for f in sources.fields:
        if f.readers.kind == "public" and not (f.public_justification or "").strip():
            fail("FL-04", f"field {f.path} is PUBLIC without a public_justification")

    writes_resource = any(k == "resource" for k in kinds.values()) and not read_only
    if writes_resource and recipients.kind != "resource_of":
        fail("FL-05", "a write to a resource argument must declare recipients resource_of")

    if recipients.kind == "none" and flow.provider != "tcb":
        fail("FL-06", f"recipients none, but the tool runs at {flow.provider}")

    for f in sources.fields:
        if f.readers.kind != "from_source_metadata":
            continue
        for name in f.readers.values:
            meta = sources.source_metadata.get(name)
            if meta is None or meta.authority != "source_system":
                fail("FL-07", f"field {f.path} reads readers from {name!r}, which is not "
                     "declared with authority source_system")
            elif meta.disclosure is None:
                fail("FL-08", f"metadata {name!r} feeds a reader set but declares no "
                     "disclosure (BY_VALUE or CHARGE_BUDGET)")

    if recipients.kind != "none" and effect_mode != "MEDIATED":
        fail("FL-09", f"a sink to recipients needs effect_mode MEDIATED, not {effect_mode!r}")

    declared = set(kinds)
    for name in sorted(schema_args - declared):
        fail("FL-10", f"argument {name!r} declares no kind")
    for name in sorted(declared - schema_args):
        fail("FL-10", f"kind declared for {name!r}, which is not an argument")

    if recipients.kind == "none" and not read_only:
        fail("FL-11", f"action_type {action_type!r} is not read-only, so the tool reaches "
             "someone and recipients cannot be none")

    for name, kind in recipients.from_args:
        if name in kinds and kinds[name] != kind:
            fail("FL-12", f"from_args maps {name!r} to {kind}, but it is declared {kinds[name]}")

    order = {r: i for i, r in enumerate(LINT_RULES)}
    return tuple(sorted(found, key=lambda f: (order[f.rule], f.message)))


def lint_toolspec(spec: Mapping[str, Any], *, strict: bool) -> tuple[LintFinding, ...]:
    """Lint one raw ToolSpec mapping. Under ``strict`` a missing block is FL-13."""
    tool_id = str(spec.get("tool_id", "?"))
    if "flow" not in spec:
        if strict:
            return (LintFinding("FL-13", tool_id, "no flow block under the strict profile"),)
        return ()
    return lint_flow(parse_flow(spec["flow"]), argument_schema=spec.get("argument_schema", {}),
                     action_type=spec.get("action_type"), effect_mode=spec.get("effect_mode"),
                     tool_id=tool_id)

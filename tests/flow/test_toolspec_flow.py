# SPDX-License-Identifier: BUSL-1.1
"""IFC-03a: the ToolSpec v4 ``flow`` block, parsed and linted (SDD v1.3 §3.3, §3.5, §5.1).

Every lint rule in ``schemas/tool_spec_v4.yaml`` has a test that triggers it
and a clean spec that does not. The two §5.1 examples (an inbox reader and
``send_email``, plus ``get_webpage``) lint clean.
"""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from remora.flow.label import PUBLIC, Integrity
from remora.flow.spec import (
    FlowSpecRefused,
    lint_flow,
    lint_toolspec,
    parse_flow,
)

ROOT = Path(__file__).resolve().parents[2]


def _schema(**props):
    return {"type": "object", "properties": {k: {"type": "string"} for k in props}}


SEND_EMAIL = {
    "provider": "ext://mail.corp.example",
    "arguments": {"to": {"kind": "email"}, "cc": {"kind": "email"},
                  "subject": {"kind": "text"}, "body": {"kind": "text"}},
    "sources": {"default_integrity": "TRUSTED", "fields": []},
    "sink": {
        "recipients": {"from_args": {"to": "email", "cc": "email"}},
        "payload_args": ["subject", "body"],
        "integrity_required": ["to", "cc"],
        "roles_accepted": {"to": ["recipient"], "cc": ["recipient"]},
        "control_integrity_required": False,
    },
}
SEND_EMAIL_SCHEMA = _schema(to=1, cc=1, subject=1, body=1)

GET_INBOX = {
    "provider": "tcb",
    "arguments": {},
    "sources": {
        "default_integrity": "UNTRUSTED",
        "default_return_mode": "BY_HANDLE",
        "fields": [
            {"path": "$[*].body", "integrity": "UNTRUSTED",
             "readers": {"from_source_metadata": ["delivery_recipients"],
                         "plus_user": True, "plus_processors": True},
             "return_mode": "BY_HANDLE"},
            {"path": "$[*].subject", "integrity": "UNTRUSTED",
             "readers": {"from_source_metadata": ["delivery_recipients"],
                         "plus_user": True, "plus_processors": True},
             "return_mode": "BY_VALUE"},
        ],
        "source_metadata": {
            "delivery_recipients": {"authority": "source_system",
                                    "from": "mail server delivery envelope",
                                    "disclosure": "CHARGE_BUDGET"},
        },
    },
    "sink": {"recipients": "none"},
}

GET_WEBPAGE = {
    "provider": "tcb",
    "arguments": {"url": {"kind": "url"}},
    "sources": {"fields": [
        {"path": "$", "integrity": "UNTRUSTED", "readers": "PUBLIC",
         "public_justification": "Fetched anonymously from a public URL; anyone could fetch it.",
         "return_mode": "BY_VALUE"},
    ]},
    "sink": {"recipients": {"url_host_of": "url"}, "payload_args": ["url"]},
}


def _rules(flow, schema, action_type="send", effect_mode="MEDIATED"):
    findings = lint_flow(parse_flow(flow), argument_schema=schema,
                         action_type=action_type, effect_mode=effect_mode, tool_id="t")
    for f in findings:
        # A finding a reviewer cannot read is half a finding.
        assert isinstance(f.message, str) and len(f.message) > 10, f
        assert str(f).startswith(f"{f.rule} t: ")
    return {f.rule for f in findings}


# ── the SDD's own examples are clean ──────────────────────────────────────

def test_the_sdd_examples_lint_clean():
    assert _rules(SEND_EMAIL, SEND_EMAIL_SCHEMA) == set()
    assert _rules(GET_INBOX, _schema(), action_type="read", effect_mode="NONE") == set()
    assert _rules(GET_WEBPAGE, _schema(url=1), action_type="read") == set()


def test_parse_reads_the_declared_meaning():
    flow = parse_flow(GET_INBOX)
    assert flow.provider == "tcb"
    assert flow.sources.default_integrity is Integrity.UNTRUSTED
    body, subject = flow.sources.fields
    assert body.path == "$[*].body" and body.return_mode == "BY_HANDLE"
    assert subject.return_mode == "BY_VALUE"
    assert body.readers.kind == "from_source_metadata"
    assert body.readers.values == ("delivery_recipients",)
    assert body.readers.plus_user and body.readers.plus_processors
    assert flow.sink.recipients.kind == "none"
    web = parse_flow(GET_WEBPAGE)
    assert web.sources.fields[0].readers.kind == "public"
    assert web.sources.fields[0].readers.public is PUBLIC
    assert web.sink.recipients.kind == "url_host_of" and web.sink.recipients.argument == "url"


def test_every_declared_value_is_read():
    flow = parse_flow({
        "provider": "ext://Mail.Corp.Example",
        "arguments": {"to": {"kind": "email"}},
        "sources": {
            "fields": [
                {"path": "$.items", "length_public": True,
                 "readers": {"static": ["user://acme/*", "user://acme/alice"]}},
                {"path": "$.note", "integrity": "TRUSTED", "readers": {"inherit_args": True}},
                {"path": "$.doc", "readers": {"resource_acl": "to"}},
                {"path": "$.plain"},
            ],
            "source_metadata": {"acl": {"authority": "source_system",
                                        "from": "the file ACL API",
                                        "disclosure": "BY_VALUE"}},
        },
        "sink": {"recipients": {"static": ["user://acme/alice", "email://corp.example/bob"]}},
    })
    assert flow.provider == "ext://mail.corp.example"
    assert flow.argument_kind("to") == "email" and flow.argument_kind("cc") is None
    items, note, doc, plain = flow.sources.fields
    assert items.length_public is True and note.length_public is False
    # Static readers accept a subtree.
    assert items.readers.kind == "static" and "user://acme/*" in items.readers.values
    assert not items.readers.plus_user and not items.readers.plus_processors
    assert note.integrity is Integrity.TRUSTED and plain.integrity is None
    assert note.readers.kind == "inherit_args" and note.readers.values == ()
    assert doc.readers.kind == "resource_acl" and doc.readers.values == ("to",)
    assert plain.readers.kind == "default" and plain.return_mode is None
    meta = flow.sources.source_metadata["acl"]
    assert (meta.name, meta.authority, meta.origin, meta.disclosure) == (
        "acl", "source_system", "the file ACL API", "BY_VALUE")
    assert flow.sink.recipients.kind == "static"
    assert set(flow.sink.recipients.static) == {"email://corp.example/bob", "user://acme/alice"}
    assert flow.sink.recipients.arguments() == ()


def test_defaults_fail_closed():
    flow = parse_flow({"provider": "tcb", "arguments": {}, "sources": {},
                       "sink": {"recipients": "none"}})
    assert flow.sources.default_integrity is Integrity.UNTRUSTED
    assert flow.sources.default_return_mode == "BY_HANDLE"
    assert flow.sink.payload_args is None  # all arguments
    assert flow.sink.control_integrity_required is False
    # A block with no sources key at all reads the same defaults.
    bare = parse_flow({"provider": "tcb", "arguments": {}, "sink": {"recipients": "none"}})
    assert bare.sources == flow.sources


# ── each lint rule ────────────────────────────────────────────────────────

def test_fl01_a_url_argument_under_no_recipients():
    flow = copy.deepcopy(GET_WEBPAGE)
    flow["sink"] = {"recipients": "none"}
    assert "FL-01" in _rules(flow, _schema(url=1), action_type="read", effect_mode="NONE")


@pytest.mark.parametrize("mutate", [
    lambda f: f["sink"].update(integrity_required=["to", "bcc"]),
    lambda f: f["sink"].update(payload_args=["body", "attachments"]),
    lambda f: f["sink"].update(roles_accepted={"bcc": ["recipient"]}),
    lambda f: f["sink"].update(recipients={"from_args": {"bcc": "email"}}),
    lambda f: f["sink"].update(recipients={"url_host_of": "link"}),
    lambda f: f["sink"].update(recipients={"iban_of": "account"}),
    lambda f: f["sink"].update(recipients={"resource_of": "path"}),
    lambda f: f["sources"]["fields"].append(
        {"path": "$.x", "readers": {"resource_acl": "path"}}),
])
def test_fl02_an_unknown_argument(mutate):
    flow = copy.deepcopy(SEND_EMAIL)
    mutate(flow)
    assert "FL-02" in _rules(flow, SEND_EMAIL_SCHEMA)


def test_fl03_by_value_as_the_default():
    flow = copy.deepcopy(GET_INBOX)
    flow["sources"]["default_return_mode"] = "BY_VALUE"
    assert "FL-03" in _rules(flow, _schema(), action_type="read", effect_mode="NONE")


def test_fl04_public_needs_a_justification():
    flow = copy.deepcopy(GET_WEBPAGE)
    del flow["sources"]["fields"][0]["public_justification"]
    assert "FL-04" in _rules(flow, _schema(url=1), action_type="read")
    flow["sources"]["fields"][0]["public_justification"] = "   "
    assert "FL-04" in _rules(flow, _schema(url=1), action_type="read")


def test_fl05_a_write_to_a_resource_names_the_resource():
    flow = {"provider": "tcb",
            "arguments": {"path": {"kind": "resource"}, "content": {"kind": "text"}},
            "sources": {}, "sink": {"recipients": {"static": ["user://acme/alice"]}}}
    schema = _schema(path=1, content=1)
    assert "FL-05" in _rules(flow, schema, action_type="write")
    flow["sink"]["recipients"] = {"resource_of": "path"}
    assert _rules(flow, schema, action_type="write") == set()
    # A read of a resource is not a write.
    flow["sink"]["recipients"] = {"static": ["user://acme/alice"]}
    assert "FL-05" not in _rules(flow, schema, action_type="read")


def test_fl06_no_recipients_only_inside_the_tcb():
    flow = copy.deepcopy(GET_INBOX)
    flow["provider"] = "ext://mail.corp.example"
    assert "FL-06" in _rules(flow, _schema(), action_type="read", effect_mode="NONE")


def test_fl07_reader_metadata_must_come_from_the_source_system():
    flow = copy.deepcopy(GET_INBOX)
    flow["sources"]["source_metadata"]["delivery_recipients"]["authority"] = "content"
    assert "FL-07" in _rules(flow, _schema(), action_type="read", effect_mode="NONE")
    flow = copy.deepcopy(GET_INBOX)
    flow["sources"]["fields"][0]["readers"]["from_source_metadata"] = ["to_header"]
    assert "FL-07" in _rules(flow, _schema(), action_type="read", effect_mode="NONE")


def test_fl07_checks_every_field_not_just_the_first():
    flow = copy.deepcopy(GET_INBOX)
    flow["sources"]["fields"].insert(0, {"path": "$[*].date", "readers": {"inherit_args": True}})
    flow["sources"]["source_metadata"]["delivery_recipients"]["authority"] = "content"
    assert "FL-07" in _rules(flow, _schema(), action_type="read", effect_mode="NONE")


def test_fl08_a_reader_set_says_how_its_bits_are_paid():
    flow = copy.deepcopy(GET_INBOX)
    del flow["sources"]["source_metadata"]["delivery_recipients"]["disclosure"]
    assert "FL-08" in _rules(flow, _schema(), action_type="read", effect_mode="NONE")
    flow["sources"]["source_metadata"]["delivery_recipients"]["disclosure"] = "BY_VALUE"
    assert "FL-08" not in _rules(flow, _schema(), action_type="read", effect_mode="NONE")


@pytest.mark.parametrize("effect_mode", [None, "NONE"])
def test_fl09_a_sink_needs_mediated_effects(effect_mode):
    assert "FL-09" in _rules(SEND_EMAIL, SEND_EMAIL_SCHEMA, effect_mode=effect_mode)


def test_fl10_every_argument_declares_a_kind_and_no_more():
    flow = copy.deepcopy(SEND_EMAIL)
    del flow["arguments"]["body"]
    assert "FL-10" in _rules(flow, SEND_EMAIL_SCHEMA)
    flow = copy.deepcopy(SEND_EMAIL)
    flow["arguments"]["bcc"] = {"kind": "email"}
    assert "FL-10" in _rules(flow, SEND_EMAIL_SCHEMA)


def test_fl11_a_consequential_tool_reaches_someone():
    flow = {"provider": "tcb", "arguments": {}, "sources": {},
            "sink": {"recipients": "none"}}
    assert "FL-11" in _rules(flow, _schema(), action_type="delete", effect_mode="MEDIATED")
    assert "FL-11" not in _rules(flow, _schema(), action_type="read", effect_mode="NONE")


def test_fl12_from_args_agrees_with_the_declared_kind():
    flow = copy.deepcopy(SEND_EMAIL)
    flow["sink"]["recipients"] = {"from_args": {"to": "principal", "cc": "email"}}
    assert "FL-12" in _rules(flow, SEND_EMAIL_SCHEMA)


def test_fl13_strict_refuses_a_spec_without_flow():
    spec = {"tool_id": "send_email", "argument_schema": SEND_EMAIL_SCHEMA,
            "action_type": "send", "effect_mode": "MEDIATED"}
    (finding,) = lint_toolspec(spec, strict=True)
    assert (finding.rule, finding.tool_id) == ("FL-13", "send_email")
    assert "strict" in finding.message
    assert lint_toolspec(spec, strict=False) == ()
    spec["flow"] = SEND_EMAIL
    assert lint_toolspec(spec, strict=True) == ()


def test_lint_toolspec_reads_the_spec_it_is_given():
    flow = {"provider": "tcb", "arguments": {"x": {"kind": "text"}}, "sources": {},
            "sink": {"recipients": "none"}}
    # The action type comes from the spec: delete reaches someone (FL-11).
    rules = {f.rule for f in lint_toolspec(
        {"tool_id": "rm", "action_type": "delete", "effect_mode": "MEDIATED",
         "argument_schema": _schema(x=1), "flow": flow}, strict=True)}
    assert rules == {"FL-11"}
    # A spec with no argument schema has no arguments, so a declared kind is FL-10.
    rules = {f.rule for f in lint_toolspec(
        {"tool_id": "ls", "action_type": "read", "effect_mode": "NONE", "flow": flow},
        strict=True)}
    assert rules == {"FL-10"}
    nameless = lint_toolspec({"flow": flow, "action_type": "read"}, strict=True)
    assert nameless and all(f.tool_id == "?" for f in nameless)


def test_a_non_mapping_argument_schema_has_no_arguments():
    flow = parse_flow({"provider": "tcb", "arguments": {}, "sink": {"recipients": "none"}})
    for schema in (None, [], {"properties": ["a"]}):
        assert lint_flow(flow, argument_schema=schema, action_type="read",
                         effect_mode="NONE") == ()


def test_findings_are_ordered_and_name_the_tool():
    spec = {"tool_id": "send_email", "argument_schema": SEND_EMAIL_SCHEMA,
            "action_type": "send", "effect_mode": None,
            "flow": {**SEND_EMAIL, "provider": "tcb",
                     "sink": {**SEND_EMAIL["sink"], "integrity_required": ["bcc"]}}}
    findings = lint_toolspec(spec, strict=True)
    assert [f.rule for f in findings] == sorted(f.rule for f in findings)
    assert all("send_email" in str(f) for f in findings)


# ── the parser refuses what it cannot give one meaning ────────────────────

@pytest.mark.parametrize("flow", [
    "not a mapping",
    {"arguments": {}, "sources": {}, "sink": {"recipients": "none"}},  # no provider
    {"provider": "tcb", "sources": {}, "sink": {"recipients": "none"}},  # no arguments
    {"provider": "tcb", "arguments": {}, "sources": {}},  # no sink
    {"provider": "ext://Evil Host", "arguments": {}, "sources": {}, "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {}, "sink": {"recipients": "none"}, "extra": 1},
    {"provider": "tcb", "arguments": {"a": {"kind": "blob"}}, "sources": {},
     "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"default_integrity": "MAYBE"},
     "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"fields": [{"path": "body"}]},
     "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"fields": [{"path": "$..body"}]},
     "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"fields": [{"path": "$.a"}, {"path": "$.a"}]},
     "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"fields": [
        {"path": "$.a", "readers": {"static": ["mailto:bob"]}}]},
     "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"fields": [
        {"path": "$.a", "readers": {"static": ["user://a/b"], "resource_acl": "p"}}]},
     "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"fields": [
        {"path": "$.a", "return_mode": "BY_REFERENCE"}]},
     "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {},
     "sink": {"recipients": {"from_args": {"to": "email"}, "url_host_of": "u"}}},
    {"provider": "tcb", "arguments": {}, "sources": {}, "sink": {"recipients": "everyone"}},
    {"provider": "tcb", "arguments": {}, "sources": {},
     "sink": {"recipients": "none", "control_integrity_required": "yes"}},
    # names: a bare string is not a list, and every name is a non-empty string
    {"provider": "tcb", "arguments": {}, "sources": {},
     "sink": {"recipients": "none", "integrity_required": "to"}},
    {"provider": "tcb", "arguments": {}, "sources": {},
     "sink": {"recipients": "none", "integrity_required": [1]}},
    {"provider": "tcb", "arguments": {}, "sources": {},
     "sink": {"recipients": "none", "payload_args": ["body", ""]}},
    {"provider": "tcb", "arguments": {}, "sources": {},
     "sink": {"recipients": "none", "payload_args": ["body", "body"]}},
    {"provider": "tcb", "arguments": {}, "sources": {},
     "sink": {"recipients": "none", "roles_accepted": ["to"]}},
    {"provider": "tcb", "arguments": {}, "sources": {},
     "sink": {"recipients": "none", "roles_accepted": {"to": "recipient"}}},
    {"provider": "tcb", "arguments": {}, "sources": {}, "sink": {}},
    {"provider": 7, "arguments": {}, "sources": {}, "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": [], "sources": {}, "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {"a": {}}, "sources": {}, "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {"a": "url"}, "sources": {}, "sink": {"recipients": "none"}},
    # recipients
    {"provider": "tcb", "arguments": {}, "sources": {},
     "sink": {"recipients": {"static": ["user://acme/*"]}}},  # a recipient is exact
    {"provider": "tcb", "arguments": {}, "sources": {},
     "sink": {"recipients": {"from_args": ["to"]}}},
    {"provider": "tcb", "arguments": {}, "sources": {},
     "sink": {"recipients": {"from_args": {}}}},
    {"provider": "tcb", "arguments": {}, "sources": {},
     "sink": {"recipients": {"from_args": {"to": "iban"}}}},
    {"provider": "tcb", "arguments": {}, "sources": {},
     "sink": {"recipients": {"url_host_of": ""}}},
    {"provider": "tcb", "arguments": {}, "sources": {},
     "sink": {"recipients": {"iban_of": ["acct"]}}},
    # sources
    {"provider": "tcb", "arguments": {}, "sources": {"fields": {"path": "$"}},
     "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"fields": [{"integrity": "TRUSTED"}]},
     "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"fields": [{"path": 3}]},
     "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"fields": [
        {"path": "$", "readers": "PUBLIC", "public_justification": 1}]},
     "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"fields": [
        {"path": "$", "length_public": "yes"}]}, "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"fields": [
        {"path": "$", "readers": {"resource_acl": ""}}]}, "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"fields": [
        {"path": "$", "readers": {"inherit_args": False}}]}, "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"fields": [
        {"path": "$", "readers": {"static": ["user://a/b"], "plus_user": "yes"}}]},
     "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"fields": [
        {"path": "$", "readers": {"plus_user": True}}]}, "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"fields": [
        {"path": "$", "readers": "public"}]}, "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"source_metadata": ["acl"]},
     "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"source_metadata": {"acl": {"owner": "x"}}},
     "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"source_metadata": {
        "acl": {"authority": "source_system", "disclosure": "NEVER"}}},
     "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": {"default_return_mode": "INLINE"},
     "sink": {"recipients": "none"}},
    {"provider": "tcb", "arguments": {}, "sources": [], "sink": {"recipients": "none"}},
])
def test_malformed_blocks_are_refused(flow):
    with pytest.raises(FlowSpecRefused) as exc:
        parse_flow(flow)
    assert exc.value.reason_code == "toolspec_flow_invalid"
    # The message names where in the block the problem is.
    code, _, message = str(exc.value).partition(": ")
    assert code == "toolspec_flow_invalid" and message.startswith("flow"), message


def test_the_schema_file_lists_every_rule_the_linter_has():
    doc = yaml.safe_load((ROOT / "schemas" / "tool_spec_v4.yaml").read_text(encoding="utf-8"))
    from remora.flow.spec import LINT_RULES

    assert set(doc["lint_rules"]) == set(LINT_RULES)
    assert doc["schema_version"] == 4 and doc["extends"] == "tool_spec_v3.yaml"


# ── the CLI ───────────────────────────────────────────────────────────────

def _run_cli(tmp_path, specs, *flags):
    import json as _json
    import subprocess
    import sys

    bundle = tmp_path / "bundle.json"
    bundle.write_text(_json.dumps({"schema_version": 4, "tool_specs": specs}), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_toolspec_flow.py"), *flags, str(bundle)],
        capture_output=True, text=True, check=False)


def test_the_cli_passes_a_clean_bundle_and_fails_a_broken_one(tmp_path):
    good = {"tool_id": "send_email", "argument_schema": SEND_EMAIL_SCHEMA,
            "action_type": "send", "effect_mode": "MEDIATED", "flow": SEND_EMAIL}
    assert _run_cli(tmp_path, [good], "--strict").returncode == 0
    bare = {k: v for k, v in good.items() if k != "flow"}
    assert _run_cli(tmp_path, [bare]).returncode == 0
    r = _run_cli(tmp_path, [bare], "--strict")
    assert r.returncode == 1 and "FL-13 send_email" in r.stdout
    broken = {**good, "flow": {**SEND_EMAIL, "provider": 7}}
    r = _run_cli(tmp_path, [broken])
    assert r.returncode == 1 and "toolspec_flow_invalid" in r.stdout

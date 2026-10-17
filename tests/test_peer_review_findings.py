# SPDX-License-Identifier: BUSL-1.1
"""Structure of the peer-review findings register.

``docs/review/PEER_REVIEW_FINDINGS.md`` tracks objections to the paper. Every
finding carries the same fields, uses one of five statuses, and may be marked
RESOLVED only with a verification that is not pending.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REGISTER = ROOT / "docs" / "review" / "PEER_REVIEW_FINDINGS.md"

FIELDS = ("Severity", "Claim", "Evidence", "Affected claims", "Action",
          "Owning PR", "Verification", "Status")
STATUSES = {"OPEN", "IN_PROGRESS", "RESOLVED", "ACCEPTED_LIMITATION", "SUPERSEDED"}
SEVERITIES = {"MAJOR", "MINOR", "NIT"}
_HEADING = re.compile(r"^### (PRF-\d{3}) (.+)$", re.MULTILINE)
# One "| Field | Value |" row per field; the value may contain escaped pipes.
_ROW = re.compile(r"^\| ([A-Za-z ]+) \| (.*) \|$", re.MULTILINE)


def parse(text: str) -> dict[str, dict[str, str]]:
    heads = list(_HEADING.finditer(text))
    out: dict[str, dict[str, str]] = {}
    for i, head in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        body = text[head.end():end]
        fields = {m.group(1): m.group(2).strip() for m in _ROW.finditer(body)
                  if m.group(1) != "Field"}
        if head.group(1) in out:
            raise ValueError(f"duplicate id {head.group(1)}")
        out[head.group(1)] = fields
    return out


def check(findings: dict[str, dict[str, str]]) -> list[str]:
    errors = []
    for fid, fields in findings.items():
        for name in FIELDS:
            if not fields.get(name):
                errors.append(f"{fid}: missing {name}")
        if fields.get("Status") not in STATUSES:
            errors.append(f"{fid}: status {fields.get('Status')!r}")
        if fields.get("Severity") not in SEVERITIES:
            errors.append(f"{fid}: severity {fields.get('Severity')!r}")
        verification = fields.get("Verification", "").lower()
        if fields.get("Status") == "RESOLVED" and (
                not verification or verification.startswith("pending")):
            errors.append(f"{fid}: RESOLVED without a verification")
    return errors


@pytest.fixture(scope="module")
def findings() -> dict[str, dict[str, str]]:
    return parse(REGISTER.read_text(encoding="utf-8"))


def test_the_register_has_findings_with_sequential_ids(findings):
    ids = sorted(findings)
    assert ids, "no findings parsed"
    assert ids == [f"PRF-{i:03d}" for i in range(1, len(ids) + 1)]


def test_every_finding_is_well_formed(findings):
    assert check(findings) == []


def test_resolved_without_verification_is_refused():
    bad = {"PRF-001": {"Severity": "MAJOR", "Claim": "c", "Evidence": "e",
                       "Affected claims": "none", "Action": "a", "Owning PR": "p",
                       "Verification": "Pending.", "Status": "RESOLVED"}}
    assert check(bad) == ["PRF-001: RESOLVED without a verification"]


def test_an_unknown_status_and_a_missing_field_are_refused():
    bad = {"PRF-001": {"Severity": "MAJOR", "Claim": "c", "Evidence": "e",
                       "Affected claims": "none", "Action": "a",
                       "Verification": "v", "Status": "FIXED"}}
    errors = check(bad)
    assert "PRF-001: missing Owning PR" in errors
    assert "PRF-001: status 'FIXED'" in errors


def test_cited_claim_ids_exist_in_the_claim_register(findings):
    register = (ROOT / "docs" / "assurance" / "claim_register_v1.yaml").read_text(encoding="utf-8")
    known = set(re.findall(r"id: (CLAIM-\d{3})", register))
    cited = {c for f in findings.values() for c in re.findall(r"CLAIM-\d{3}", f["Affected claims"])}
    assert cited <= known, sorted(cited - known)

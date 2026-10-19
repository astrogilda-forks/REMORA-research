# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1-01/05: the WS1 layer and its monitor adapter hold no authority exports (A28).

Same pattern as tests/test_advisory_assessment_cannot_authorize.py: nothing on
the enforcing path imports the library, the library imports nothing that
mints a token, lease, grant or approval, and its outputs carry no such field.
"""
from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

from remora.decision_providers.composition_adapter import MonitorAssessment
from remora.verification.check import CheckedPreconditions, PreconditionResult, ResolverEvidence
from remora.verification.records import CompositionRecord

ROOT = Path(__file__).resolve().parents[2]
WS1 = [ROOT / "remora" / "verification", ROOT / "remora" / "decision_providers" / "composition_adapter.py"]
ENFORCING = ("remora/enforcement", "remora/execution", "servers")
AUTHORITY_MODULES = ("remora.enforcement", "remora.execution", "servers", "remora.governance",
                     "remora.evidence.obligations")
GRANT_FIELDS = {"token", "execution_token", "grant", "lease", "signature", "jti", "approval",
                "issuer_key", "declassification_grant"}


def _imports(path: Path) -> list[str]:
    names: list[str] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


def _files() -> list[Path]:
    return [f for p in WS1 for f in ([p] if p.is_file() else sorted(p.rglob("*.py")))]


def test_monitors_and_ws1_records_have_no_authority_exports():
    for cls in (MonitorAssessment, CheckedPreconditions, PreconditionResult, ResolverEvidence,
                CompositionRecord):
        assert not {f.name for f in dataclasses.fields(cls)} & GRANT_FIELDS, cls.__name__


def test_ws1_imports_no_issuer_or_settlement_machinery():
    offenders = [f"{f.name}: {n}" for f in _files() for n in _imports(f)
                 if n.startswith(AUTHORITY_MODULES)]
    assert offenders == []


def test_nothing_on_the_enforcing_path_imports_ws1():
    importers = []
    for package in ENFORCING:
        for source in (ROOT / package).rglob("*.py"):
            for name in _imports(source):
                if name.startswith("remora.verification") \
                        or name == "remora.decision_providers.composition_adapter":
                    importers.append(str(source.relative_to(ROOT)))
    assert importers == []


def test_ws1_reads_no_clock_or_environment():
    offenders = []
    for f in _files():
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Attribute) and node.attr in {"now", "utcnow", "time",
                                                                  "monotonic", "environ", "getenv"}:
                offenders.append(f"{f.name}:{node.lineno}:{node.attr}")
    assert offenders == []

# SPDX-License-Identifier: BUSL-1.1
"""Authority isolation for scoped evidence obligations (REAS H3, DoD).

An obligation assessment is a read-only report. The package must never import
the enforcement, execution or policy machinery, must not read a clock, and
its result must carry nothing a decision could consume. Same pattern as
tests/test_evidence_admission_isolation.py.
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "remora" / "evidence" / "obligations"

FORBIDDEN_PREFIXES = (
    "remora.enforcement",
    "remora.execution",
    "remora.policy",
    "remora.toolcall",
    "remora.capabilities",
    "servers",
)


def _tree(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"))


def test_package_never_imports_authority_modules() -> None:
    offenders: list[str] = []
    for py in PACKAGE.rglob("*.py"):
        for node in ast.walk(_tree(py)):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            offenders += [f"{py.name}: {n}" for n in names
                          if n.startswith(FORBIDDEN_PREFIXES)]
    assert not offenders, offenders


def test_package_reads_no_clock_or_environment() -> None:
    """``assess`` is pure: no now(), no time(), no os.environ."""
    offenders: list[str] = []
    for py in PACKAGE.rglob("*.py"):
        for node in ast.walk(_tree(py)):
            if isinstance(node, ast.Attribute) and node.attr in {
                "now", "utcnow", "today", "time", "monotonic", "environ",
                "getenv",
            }:
                offenders.append(f"{py.name}:{node.lineno} .{node.attr}")
    assert not offenders, offenders


def test_assessment_carries_no_decision_fields() -> None:
    from remora.evidence.obligations import ObligationAssessment, SlotResult

    forbidden = {
        "action", "decision", "trust_score", "grant", "token", "lease",
        "authorized", "risk_tier", "evidence_action", "effect_verified",
    }
    for cls in (ObligationAssessment, SlotResult):
        fields = set(cls.__dataclass_fields__)
        assert not (fields & forbidden), (cls.__name__, fields & forbidden)

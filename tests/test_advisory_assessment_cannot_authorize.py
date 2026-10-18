# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""An advisory assessment cannot authorize execution (probe P3, PRF-040).

``remora.assess.assess_tool_call`` takes risk and action labels from the
caller, so its ACCEPT is advisory: it says what the engine would decide if the
labels were true. PRF-040 stays open on what that result is called. What
these tests pin is that it cannot reach the enforcement point: the
assessment carries no grant, nothing on the enforcing path imports the
advisory module, and the strict gate refuses anything but a signed
PolicyDecisionToken.
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

from remora.assess import ToolCallAssessment, assess_tool_call

ROOT = Path(__file__).resolve().parents[1]
ENFORCING = ("remora/enforcement", "remora/execution", "servers")


def test_the_assessment_carries_no_grant():
    names = {f.name for f in dataclasses.fields(ToolCallAssessment)}
    assert not names & {"token", "execution_token", "grant", "lease", "signature", "jti"}


def test_nothing_on_the_enforcing_path_imports_the_advisory_module():
    importers = []
    for package in ENFORCING:
        for source in (ROOT / package).rglob("*.py"):
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module == "remora.assess":
                    importers.append(str(source.relative_to(ROOT)))
                elif isinstance(node, ast.Import) and any(
                        a.name == "remora.assess" for a in node.names):
                    importers.append(str(source.relative_to(ROOT)))
    assert importers == []


def test_a_caller_asserted_accept_is_refused_by_the_strict_gate(monkeypatch):
    from remora.enforcement import token as grant_module
    from remora.enforcement.gate import EnforcementGate
    from remora.enforcement.token import PolicyDecisionToken

    # No grant material at all, so nothing can be signed here.
    for name in (grant_module._ENV_KEY, grant_module._ENV_ED25519_PRIVATE,
                 grant_module._ENV_ED25519_PUBLIC):
        monkeypatch.delenv(name, raising=False)

    assessment = assess_tool_call("read_telemetry", {"asset": "P-1"}, risk_tier="low",
                                  action_type="read", trust_score=0.99,
                                  target_environment="staging")
    action = str(getattr(assessment, "action", getattr(assessment, "decision", ""))).lower()
    # Whatever the advisory answer is, the only way to the gate is a token, and
    # an unsigned one built from the answer is refused.
    forged = PolicyDecisionToken(action=action or "accept", observation_hash="x",
                                 request_id="advisory", issued_at="2026-10-18T00:00:00+00:00",
                                 signature="", is_signed=False,
                                 expires_at="2026-10-18T00:05:00+00:00", jti="j-advisory")
    result = EnforcementGate(strict=True).check(forged, consume=True)
    assert not result.allowed

    # The assessment itself is not a token: the gate either fails on it or
    # refuses it, and never allows it.
    try:
        direct = EnforcementGate(strict=True).check(assessment, consume=True)  # type: ignore[arg-type]
    except (TypeError, AttributeError, ValueError):
        return
    assert not direct.allowed

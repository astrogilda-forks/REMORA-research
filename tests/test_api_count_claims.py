# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Counts of the HTTP contract stated in prose must match schemas/openapi.json.

RMR-AUD-26-007: docs/07-api-reference.md said "OpenAPI 3.1, 41 paths" after
GET /v1/ready made it 42, while every schema check stayed green. The count is
now left to the schema; these tests refuse the next stated count that drifts.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

#: Documentation/register consistency gate, not a behaviour test.
pytestmark = pytest.mark.docgate

ROOT = Path(__file__).resolve().parents[1]
_PATHS = json.loads((ROOT / "schemas" / "openapi.json").read_text(encoding="utf-8"))["paths"]
_METHODS = {"get", "post", "put", "patch", "delete"}

#: "OpenAPI 3.1, 41 paths", "openapi.json has 43 operations", ...
_OPENAPI_COUNT = re.compile(
    r"(?i)openapi(?:[^.\n]|\.\d){0,40}?\b(\d+)\s+(?:http\s+)?(paths|operations)\b")
#: "Every route of servers/execution_api.py (both routers, 28 routes)".
_EXECUTION_ROUTES = re.compile(r"servers/execution_api\.py`? \(both routers, (\d+) routes\)")


def _execution_operations() -> int:
    return sum(1 for path, item in _PATHS.items()
               if path.startswith(("/v1/execution", "/v1/contexts"))
               for method in item if method in _METHODS)


def _live_docs() -> list[Path]:
    out = subprocess.run(["git", "ls-files", "docs/*.md", "*.md"], capture_output=True,
                         text=True, cwd=ROOT, check=True).stdout.split()
    return [ROOT / p for p in sorted(set(out))
            if not p.startswith(("docs/archive/", "CHANGELOG", "NEGATIVE_RESULTS"))]


def test_a_stated_openapi_count_matches_the_schema():
    expected = {"paths": len(_PATHS),
                "operations": sum(1 for item in _PATHS.values() for m in item if m in _METHODS)}
    wrong = []
    for path in _live_docs():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for m in _OPENAPI_COUNT.finditer(line):
                if int(m.group(1)) != expected[m.group(2).lower()]:
                    wrong.append(f"{path.relative_to(ROOT)}:{number}: {m.group(0)!r}, schema has "
                                 f"{expected[m.group(2).lower()]} {m.group(2).lower()}")
    assert not wrong, "\n".join(wrong)


def test_the_stated_execution_route_count_matches_the_schema():
    doc = ROOT / "docs" / "design" / "derived-information-flow-control-v1-status.md"
    found = _EXECUTION_ROUTES.findall(doc.read_text(encoding="utf-8"))
    assert found, "the IFC-11 row no longer states the route count; drop this test with it"
    assert {int(n) for n in found} == {_execution_operations()}


def test_the_pattern_catches_the_drift_it_exists_for():
    assert _OPENAPI_COUNT.search("(OpenAPI 3.1, 41 paths).").group(1) == "41"
    assert _OPENAPI_COUNT.search("The machine-readable contract (OpenAPI 3.1).") is None

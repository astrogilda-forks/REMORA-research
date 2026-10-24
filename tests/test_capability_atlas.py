# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Capability atlas integrity.

The atlas (docs/design/unified-capability-execution-v1.1-atlas.yaml) is the
assessment layer the unified capability execution SDD is implemented from.
It is only useful as a work map while it stays consistent: every dependency
names a known capability, the dependency graph has no cycles, every code and
test path exists, and the rendered page matches the data.
"""
from __future__ import annotations

import copy
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

#: Documentation/register consistency gate, not a behaviour test.
pytestmark = pytest.mark.docgate

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate_capability_atlas.py"


def _module():
    spec = importlib.util.spec_from_file_location("gen_atlas", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_atlas_validates() -> None:
    mod = _module()
    assert mod.validate(mod.load()) == []


def test_every_atlas_capability_has_an_sdd_section() -> None:
    mod = _module()
    ids = [c["id"] for c in mod.load()["capabilities"]]
    sdd = (ROOT / "docs" / "design" / "unified-capability-execution-v1.1.md").read_text(
        encoding="utf-8")
    for cid in ids:
        assert f"### {cid} " in sdd, f"{cid} has no section in the SDD"


def test_a_dependency_cycle_is_refused() -> None:
    mod = _module()
    data = copy.deepcopy(mod.load())
    by_id = {c["id"]: c for c in data["capabilities"]}
    by_id["CAP-013"]["assessment"]["forutsetter"].append("CAP-031")
    errors = mod.validate(data, check_paths=False)
    assert any(e.startswith("dependency cycle") for e in errors), errors


def test_an_externally_verified_target_is_refused() -> None:
    mod = _module()
    data = copy.deepcopy(mod.load())
    data["capabilities"][0]["assessment"]["oppnaelig_niva"] = "EXTERNALLY_VERIFIED"
    errors = mod.validate(data, check_paths=False)
    assert any("independent party" in e for e in errors), errors


def test_an_unknown_dependency_is_refused() -> None:
    mod = _module()
    data = copy.deepcopy(mod.load())
    data["capabilities"][0]["assessment"]["forutsetter"] = ["CAP-999"]
    errors = mod.validate(data, check_paths=False)
    assert any("unknown CAP-999" in e for e in errors), errors


def test_generated_page_is_up_to_date() -> None:
    proc = subprocess.run([sys.executable, str(SCRIPT), "--check"],
                          capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 0, proc.stdout + proc.stderr

# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The WS1 explicit-state model (WS1 SDD §12.1; formal/ws1_composition).

Each configuration's set of violated invariants is pinned, and so is every
counterexample trace, so a model or implementation change that moves either
is seen. The base configurations break nothing but the reported residual
window; each weakened one breaks exactly what its rule protects.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from formal.ws1_composition.model import CONFIGS, check

HERE = Path(__file__).resolve().parents[1] / "formal" / "ws1_composition"
EXPECTED = json.loads((HERE / "expected.json").read_text(encoding="utf-8"))
TRACES = json.loads((HERE / "counterexamples.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("cfg", CONFIGS, ids=lambda c: c.name)
def test_configuration_breaks_exactly_what_it_should(cfg):
    result = check(cfg)
    assert result["violated"] == EXPECTED[cfg.name]
    assert result["counterexamples"] == TRACES[cfg.name]


def test_the_design_invariants_hold_in_every_unweakened_configuration():
    for name in ("all_machine", "machine_review_terminal", "grant_class"):
        assert [v for v in EXPECTED[name] if not v.startswith("Residual_")] == []


def test_every_weakening_is_caught():
    for name, rule in (("no_regate", "FreshAtRegate"), ("nonatomic_consume", "SingleUse"),
                       ("no_profile_binding", "FreshAtRegate"),
                       ("monitor_can_prove", "AuthorityCeiling")):
        assert rule in EXPECTED[name], name

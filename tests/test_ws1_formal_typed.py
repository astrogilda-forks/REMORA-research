# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Exhaustive check of typed uncertainty and grounding from proofs (formal/ws1_composition/typed.py)."""
from __future__ import annotations

from formal.ws1_composition.typed import _ground_everything, check_grounding, check_typed


def test_typed_uncertainty_holds_its_invariants_and_the_control_breaks_one():
    assert check_typed() == {"cases": 13824, "violated": {}}
    control = check_typed(settle_everything=True)["violated"]
    assert set(control) == {"OpenCodeBlocksAccept"}


def test_grounding_needs_proof_and_the_control_breaks_both_invariants():
    assert check_grounding() == {"cases": 3600, "violated": {}}
    control = check_grounding(_ground_everything)["violated"]
    assert set(control) == {"GroundingNeedsProof", "ArgumentSignalsNeedEveryArgument"}

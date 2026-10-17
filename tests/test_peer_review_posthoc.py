# SPDX-License-Identifier: BUSL-1.1
"""The level-2 peer-review re-analyses are reproducible and leave sealed results alone.

``scripts/peer_review_posthoc.py`` re-routes C-ext3 and C-ext4, refuses unless
the published counts reproduce (apart from one documented drift), and writes
``artifacts/posthoc/peer_review_level2_v1.json``. These tests pin the
statistics helpers against known values, the drift allowance, and the
committed artifact against a fresh recomputation.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import peer_review_posthoc as ph  # noqa: E402


def test_wilson_upper_at_zero_matches_the_closed_form():
    for n in (56, 67, 295, 500):
        z2 = ph.Z95 ** 2
        assert ph.wilson(0, n)[1] == pytest.approx(z2 / (n + z2))


def test_wilson_reproduces_the_published_cext4_interval():
    lo, hi = ph.wilson(87, 291)
    assert (round(lo, 4), round(hi, 4)) == (0.2493, 0.3539)


def test_sign_test_and_mcnemar_known_values():
    assert ph.sign_test_one_sided(69, 2) == pytest.approx(1.082931623064623e-18)
    assert ph.mcnemar_exact_two_sided(0, 6) == pytest.approx(2 / 64)
    assert ph.mcnemar_exact_two_sided(3, 3) == 1.0
    assert ph.sign_test_one_sided(0, 0) == 1.0


def test_fisher_exact_matches_a_hand_computed_table():
    # [[3, 1], [1, 3]]: tables as or less likely are x in {0, 1, 3, 4}.
    assert ph.fisher_exact_two_sided(3, 1, 1, 3) == pytest.approx(34 / 70)


def test_only_the_documented_drift_is_allowed():
    published = {"F_confirmatory": {
        "obtainable_verify_recall": {"n": 93, "d": 199},
        "known_wrong_call_accept": {"n": 0, "d": 500}}}
    replayed = {"F_confirmatory": {
        "obtainable_verify_recall": [91, 199],
        "known_wrong_call_accept": [1, 500]}}
    errors = ph.reproduction_errors(replayed, published, ph.CEXT3_KNOWN_DRIFT)
    assert errors == ["F_confirmatory.known_wrong_call_accept: published [0, 500], replayed [1, 500]"]
    assert set(ph.CEXT3_KNOWN_DRIFT) == {
        "F_confirmatory.obtainable_verify_recall",
        "F_confirmatory.unobtainable_abstain_recall"}


def test_the_drift_never_touches_an_accept_metric():
    assert not any(name.endswith("accept") or "autonomy" in name
                   for name in ph.CEXT3_KNOWN_DRIFT)


def test_name_tokens_split_camel_snake_and_dots():
    assert ph.name_tokens("Movies_3_FindMovies") == {"movies"}
    assert ph.name_tokens("HNA_NEWS.search") == {"hna", "news"}
    assert ph.name_tokens("GET_PARCEL_STATE") == {"parcel", "state"}


def test_the_committed_artifact_equals_a_fresh_recomputation():
    committed = json.loads(ph.ARTIFACT.read_text(encoding="utf-8"))
    assert committed == json.loads(ph.render(ph.compute()))


def test_the_artifact_is_marked_post_hoc_and_keeps_the_sealed_numbers():
    body = json.loads(ph.ARTIFACT.read_text(encoding="utf-8"))
    assert body["status"] == "post_hoc_descriptive"
    v2d = body["wrong_call_clustering"]["cext4"]["V2D"]
    assert v2d["accept"] == [0, 295]
    assert v2d["row_level_wilson95_upper"] == 0.0129
    assert body["cext3_all_gold_accept"]["read_denominator"] == [25, 94]

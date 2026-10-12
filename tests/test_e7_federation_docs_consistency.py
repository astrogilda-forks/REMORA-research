"""Regression guard for bounded E7 documentation and pinned fixture mapping.

This checks producer-side documentation consistency, not external verification.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_e7_docs_and_fixture_crosswalk():
    index = json.loads((ROOT / "artifacts/interop/index.json").read_text(encoding="utf-8"))
    contracts = [c for c in index["contracts"] if c["id"] == "runtime-surface-e7-v0.1"]
    assert len(contracts) == 1
    contract = contracts[0]
    assert contract["edge"] == "E7"
    assert contract["lifecycle"] == "EXTERNALLY_VERIFIED"
    assert contract["external_verification"] == "INDEPENDENT"
    assert len(contract["external_runs"]) >= 2

    docs = (ROOT / "docs/interop/FEDERATION.md").read_text(encoding="utf-8")
    crosswalk = (ROOT / "docs/interop/E7_FIELD_CROSSWALK_CANDIDATE.md").read_text(encoding="utf-8")
    assert "E7 remains externally unrun" not in docs
    assert "E7 still needs its external result" not in docs
    assert "runtime_capability_surface_completeness" in docs
    assert "NOT_ESTABLISHED" in docs
    assert "not blind studies" in docs
    assert "producer-side candidate mapping" in crosswalk
    assert "not bilateral confirmation" in crosswalk
    fixtures = json.loads(
        (ROOT / "artifacts/interop/runtime-surface-e7-v0.1/fixtures.json").read_text(encoding="utf-8")
    )
    assert len(fixtures["cases"]) == 5
    for case in fixtures["cases"]:
        assert case["id"] in crosswalk

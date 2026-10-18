# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""REMORA's E6 consumer against the vendored VeritasActa/e6-fixture v1.1.0."""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from remora.interop.acta_e6 import (
    E6Inputs,
    agreement,
    ed25519_check,
    evaluate,
    range_root,
    record_id,
)  # noqa: E402
from scripts import run_acta_e6 as runner  # noqa: E402

FIXTURE = runner.VENDORED
LOCK = json.loads(runner.LOCK.read_text(encoding="utf-8"))
ROOT_FP = "sha256:0a8d834701f5468883e891be97240182dd26c23170cb80174449755d6244f926"


def _matching() -> E6Inputs:
    return E6Inputs.from_bytes(
        receipts=(FIXTURE / "receipts" / "chain.jsonl").read_bytes(),
        manifest=(FIXTURE / "manifest.json").read_bytes(),
        bill=(FIXTURE / "bill.json").read_bytes(),
        keys=(FIXTURE / "keys.json").read_bytes(),
        root_fingerprint=ROOT_FP,
    )


@pytest.fixture(scope="module")
def rows() -> list[dict]:
    return runner.run_cases(FIXTURE)


def test_vendored_subset_matches_the_pin() -> None:
    files = runner.check_pins(FIXTURE, LOCK, allow_subset=True)
    assert (
        files["sha256sums_sha256"]
        == "08731bb75416e588a2a0269387731c6643dfbded76ef98b738e0097a99c2ebc3"
    )
    assert all(
        name.startswith(("consumer/", "producer/", "test/", "receipts/0"))
        for name in files["absent"]
    ), "only the code and the per-sequence receipts are left out of the vendored copy"


def test_every_case_agrees_on_verdict_claims_and_codes(rows: list[dict]) -> None:
    assert len(rows) == 12
    assert {r["case"]: r["differences"] for r in rows} == {r["case"]: [] for r in rows}


def test_signature_blind_control_is_caught_by_case_12_alone_on_the_verdict(
    rows: list[dict],
) -> None:
    blind = {r["case"]: r["signature_blind_control"] for r in rows}
    assert sorted(c for c, b in blind.items() if not b["agrees"]) == [
        "07-altered-receipt",
        "08-unexpected-signer",
        "12-manifest-signature-altered",
    ]
    assert "verdict" not in blind["07-altered-receipt"]["differences"]
    assert "verdict" not in blind["08-unexpected-signer"]["differences"]
    assert blind["12-manifest-signature-altered"]["result"]["verdict"] == "PASS"


def test_committed_record_matches_a_vendored_run() -> None:
    assert runner.main(["--check"]) == 0


def test_manifest_root_and_head_are_recomputed() -> None:
    inp = _matching()
    rng = inp.manifest["payload"]["range"]
    ids = [record_id(r) for r in inp.receipts]
    assert range_root(ids) == rng["root"]
    assert ids[-1] == rng["head"] == inp.manifest["payload"]["previousReceiptHash"]
    assert inp.bill["manifest"] == record_id(inp.manifest)


def test_pin_mismatch_and_altered_file_are_refused(tmp_path: Path) -> None:
    copy_dir = tmp_path / "fixture"
    shutil.copytree(FIXTURE, copy_dir)
    with pytest.raises(runner.PinError, match="missing"):
        runner.check_pins(copy_dir, LOCK, allow_subset=False)
    (copy_dir / "bill.json").write_text("{}", encoding="utf-8")
    with pytest.raises(runner.PinError, match="bill.json does not match"):
        runner.check_pins(copy_dir, LOCK, allow_subset=True)
    (copy_dir / "SHA256SUMS").write_text("", encoding="utf-8")
    with pytest.raises(runner.PinError, match="pin is"):
        runner.check_pins(copy_dir, LOCK, allow_subset=True)


def test_no_verifier_abstains_and_never_compares_the_bill() -> None:
    result = evaluate(_matching(), None)
    assert result["verdict"] == "ABSTAIN"
    assert result["claims"]["scope"] == "PASS"
    assert result["codes"] == {
        "keys": ["verifier_unavailable"],
        "signatures": ["verifier_unavailable"],
    }
    assert result["payment_ready"] is False


def test_root_fingerprint_pinned_out_of_band_is_enforced() -> None:
    inp = _matching()
    other = E6Inputs(**{**inp.__dict__, "root_fingerprint": "sha256:" + "0" * 64})
    result = evaluate(other, ed25519_check)
    assert result["claims"]["keys"] == "FAIL"
    assert result["codes"]["keys"] == ["root_fingerprint_mismatch"]


def test_key_window_is_applied() -> None:
    inp = _matching()
    keys = copy.deepcopy(inp.keys)
    keys["keys"][0]["valid_until"] = "2026-08-15T00:00:00.000Z"
    keys["keys"][0]["certificate"]["payload"]["subject"]["valid_until"] = (
        "2026-08-15T00:00:00.000Z"
    )
    result = evaluate(E6Inputs(**{**inp.__dict__, "keys": keys}), ed25519_check)
    # The certificate no longer verifies under the root, and the window excludes later receipts.
    assert result["codes"]["keys"] == ["certificate_invalid", "outside_key_window"]


def test_quantity_must_equal_the_receipts_named() -> None:
    inp = _matching()
    bill = copy.deepcopy(inp.bill)
    bill["lines"][0]["quantity"] += 1
    result = evaluate(E6Inputs(**{**inp.__dict__, "bill": bill}), ed25519_check)
    assert result["claims"]["quantities"] == "FAIL"
    assert result["codes"] == {"quantities": ["quantity_mismatch"]}


def test_excluded_receipt_billed_on_a_line_must_be_billable() -> None:
    inp = _matching()
    bill = copy.deepcopy(inp.bill)
    moved = bill["exclusions"].pop(0)["receipt"]
    bill["lines"][0]["receipts"].append(moved)
    bill["lines"][0]["quantity"] += 1
    result = evaluate(E6Inputs(**{**inp.__dict__, "bill": bill}), ed25519_check)
    assert moved in {
        record_id(r)
        for r in inp.receipts
        if r["payload"]["outcome"]["billing_class"] == "none"
    }
    assert result["codes"] == {"quantities": ["not_billable", "billing_class_mismatch"]}


def test_agreement_compares_code_order_and_ignores_decisive() -> None:
    result = evaluate(_matching(), ed25519_check)
    expected = {**result, "decisive": ["keys"]}
    assert agreement(result, expected) == []
    reordered = {**result, "codes": {"scope": ["root_mismatch", "head_mismatch"]}}
    assert agreement(
        {**result, "codes": {"scope": ["head_mismatch", "root_mismatch"]}}, reordered
    ) == ["codes"]

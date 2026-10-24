# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Horizon #55 row, P2: the checkpoint's Bitcoin anchor, checked independently.

``anchor.py`` parses the OpenTimestamps proof itself and checks each Bitcoin
attestation against headers pinned from two explorers. These tests pin the
verdict on the committed bytes and show that each check can refuse: a changed
proof byte, a changed stamp, a header that does not hash to its id, lacks
work, does not link, comes from one explorer only, or carries another Merkle
root. Loaded by path like the other Horizon #55 tests.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "integrations" / "horizon55"
sys.path.insert(0, str(PKG))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"h55_{name}", PKG / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


anchor = _load("anchor")
HEADERS = json.loads(anchor.HEADERS.read_text(encoding="utf-8"))
OTS = (anchor.LOG / "checkpoint.stamp.ots").read_bytes()


@pytest.fixture()
def log_dir(tmp_path):
    out = tmp_path / "log"
    shutil.copytree(anchor.LOG, out)
    return out


def _with_headers(tmp_path, change):
    body = copy.deepcopy(HEADERS)
    change(body["headers"])
    path = tmp_path / "headers.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    return path


def _header(height: int) -> bytearray:
    return bytearray(bytes.fromhex(HEADERS["headers"][str(height)]["header"]))


def test_the_committed_anchor_verifies_at_972551_and_972552():
    body = anchor.evaluate()
    assert body["verdict"] == "ESTABLISHED"
    assert body["earliest_verified_height"] == 972551
    bitcoin = [a for a in body["attestations"] if a["kind"] == "bitcoin"]
    assert [(a["height"], a["problems"]) for a in bitcoin] == [(972551, []), (972552, [])]
    assert anchor.OUT.read_bytes() == anchor.render(body)


def test_the_proof_commits_to_the_signed_checkpoint():
    digest, _ = anchor.parse_ots(OTS)
    checkpoint = (anchor.LOG / "checkpoint.json").read_bytes()
    assert digest == hashlib.sha256(checkpoint).digest()
    assert json.loads(checkpoint)["size"] == 13  # every entry, C's payment included


def test_the_pinned_headers_agree_with_the_block_the_producer_names():
    bundle = json.loads((anchor.INPUTS / "pilot51/set2/bundle.json").read_text("utf-8"))
    named = bundle["log"]["checkpoint"]["anchor"]
    assert HEADERS["headers"][str(named["height"])]["hash"] == named["block_hash"]
    for record in HEADERS["headers"].values():
        assert set(record["sources"]) == {"blockstream.info", "mempool.space"}


#: The first operation's argument, before any fork: every path depends on it.
SHARED = len(anchor.MAGIC) + 1 + 1 + 32 + 2


@pytest.mark.parametrize("offset", [len(anchor.MAGIC) + 3, SHARED])
def test_a_changed_proof_byte_on_every_path_does_not_establish_the_anchor(log_dir, offset):
    data = bytearray(OTS)
    data[offset] ^= 0x01
    (log_dir / "checkpoint.stamp.ots").write_bytes(bytes(data))
    assert anchor.evaluate(log_dir)["verdict"] == "NOT_ESTABLISHED"


def test_each_bitcoin_path_is_checked_on_its_own(log_dir):
    """A byte outside the shared prefix breaks at most one attestation; the verdict
    holds only while a path still verifies, and never for a broken one."""
    for offset in range(SHARED + 1, len(OTS)):
        data = bytearray(OTS)
        data[offset] ^= 0x01
        (log_dir / "checkpoint.stamp.ots").write_bytes(bytes(data))
        body = anchor.evaluate(log_dir)
        verified = [a for a in body["attestations"]
                    if a["kind"] == "bitcoin" and not a["problems"]]
        assert (body["verdict"] == "ESTABLISHED") == bool(verified), offset
        for a in verified:  # a verified path is one of the two genuine commitments
            assert (a["height"], a["commitment"]) in {
                (972551, "830a724f00903e5bd448a5a57aeeecae43979e8fa5fea527bbcf5179e8ca2f2b"),
                (972552, "822db8e2e0916731da72166749c741a299b1c352eb4a400dfee276f4753cce49")}


@pytest.mark.parametrize("data, code", [
    (OTS[:-1], "ots_truncated"),
    (OTS + b"\x00", "ots_trailing_bytes"),
    (b"\x01" + OTS[1:], "ots_magic_mismatch"),
], ids=["truncated", "trailing", "magic"])
def test_a_malformed_proof_is_refused_with_its_reason(log_dir, data, code):
    (log_dir / "checkpoint.stamp.ots").write_bytes(data)
    body = anchor.evaluate(log_dir)
    assert body["verdict"] == "NOT_ESTABLISHED" and code in body["reason_codes"]


def test_an_unknown_operation_is_refused_not_guessed():
    reader = anchor._Reader(b"")
    with pytest.raises(anchor.OtsError) as exc:
        anchor._op(0x67, reader, b"x")  # keccak256: not implemented here
    assert exc.value.code == "ots_operation_unsupported:0x67"


def test_a_stamp_that_is_not_the_signed_checkpoint_is_refused(log_dir):
    (log_dir / "checkpoint.json").write_bytes(b"{}")
    body = anchor.evaluate(log_dir)
    assert body["verdict"] == "NOT_ESTABLISHED"
    assert "stamp_differs_from_signed_checkpoint" in body["reason_codes"]


def test_without_pinned_headers_nothing_is_established(tmp_path):
    body = anchor.evaluate(headers_path=tmp_path / "absent.json")
    assert body["verdict"] == "NOT_ESTABLISHED"
    assert body["reason_codes"] == ["header_not_pinned"]


def _set_header(height, header):
    def change(headers):
        headers[str(height)]["header"] = bytes(header).hex()
    return change


def test_a_header_that_does_not_hash_to_its_id_is_refused(tmp_path):
    header = _header(972551)
    header[0] ^= 1  # version byte: the hash moves, the Merkle root does not
    body = anchor.evaluate(headers_path=_with_headers(tmp_path, _set_header(972551, header)))
    row = next(a for a in body["attestations"] if a.get("height") == 972551)
    assert "header_hash_mismatch:972551" in row["problems"]
    assert body["verdict"] == "ESTABLISHED"  # 972552 still holds on its own


def test_a_forged_header_with_the_right_root_but_no_work_is_refused(tmp_path):
    """Anyone can write a header around a chosen Merkle root; the work is what costs."""
    header = _header(972551)
    header[72:76] = (0x207FFFFF).to_bytes(4, "little")  # regtest-easy target
    forged = anchor._dsha256(bytes(header))[::-1].hex()

    def change(headers):
        headers["972551"].update(header=bytes(header).hex(), hash=forged,
                                 sources={"blockstream.info": forged, "mempool.space": forged})
        del headers["972552"]
    body = anchor.evaluate(headers_path=_with_headers(tmp_path, change))
    row = next(a for a in body["attestations"] if a.get("height") == 972551)
    assert "header_work_too_low:972551" in row["problems"]
    assert body["verdict"] == "NOT_ESTABLISHED"


def test_a_header_from_one_explorer_only_is_refused(tmp_path):
    def change(headers):
        for record in headers.values():
            record["sources"] = {"blockstream.info": record["hash"]}
    body = anchor.evaluate(headers_path=_with_headers(tmp_path, change))
    assert body["verdict"] == "NOT_ESTABLISHED"
    assert "header_sources_disagree:972551" in body["reason_codes"]


def test_a_header_that_does_not_link_to_its_predecessor_is_refused(tmp_path):
    def change(headers):
        headers["972550"]["hash"] = "00" * 32
    body = anchor.evaluate(headers_path=_with_headers(tmp_path, change))
    row = next(a for a in body["attestations"] if a.get("height") == 972551)
    assert "header_does_not_link:972551" in row["problems"]


def test_another_block_is_not_accepted_for_the_attested_height(tmp_path):
    def change(headers):
        headers["972551"] = headers["972550"]
        del headers["972552"]
    body = anchor.evaluate(headers_path=_with_headers(tmp_path, change))
    assert body["verdict"] == "NOT_ESTABLISHED"
    assert "commitment_is_not_the_merkle_root" in body["reason_codes"]

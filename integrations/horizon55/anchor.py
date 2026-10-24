#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Independent check of the set-2 checkpoint's Bitcoin anchor (P2, #55).

The producer's settlement reports the checkpoint as anchored at block
972551. The frozen row did not check that (``checkpoint_anchoring =
NOT_ESTABLISHED``). This module checks it without the producer's proof
summary or header view:

1. ``checkpoint.stamp`` must be byte-identical to the signed
   ``checkpoint.json``, and the OpenTimestamps file must commit to its
   SHA-256.
2. The ``.ots`` file is parsed here, from its binary format, and every path
   to a Bitcoin attestation is replayed (sha256, append, prepend; any other
   operation is refused, not guessed).
3. Each attested block header is read from ``anchoring/headers.json``. That
   file holds 80-byte headers fetched by ``prepare.py --anchor-headers`` from
   two block explorers run by different operators (blockstream.info and
   mempool.space), kept only when both returned the same block id for the
   height. Offline, each header must hash to that id, meet the proof of work
   its own ``nBits`` declares, declare at least ``MIN_WORK_BITS`` of work,
   and link to its predecessor where both are present. The commitment the
   proof computes must equal the header's Merkle root.

What this does not establish: that the block is still in the best chain
(no node of ours was asked, only two explorers at fetch time), the order in
which the log's entries were seen relative to the block, or anything about
the entries beyond what the signed checkpoint covers.

    python integrations/horizon55/anchor.py --json
    python integrations/horizon55/anchor.py --write   # anchoring/anchoring.json
    python integrations/horizon55/anchor.py --check
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import canon  # noqa: E402
from prepare import INPUTS, LOCK  # noqa: E402

LOG = INPUTS / "pilot51" / "set2" / "log"
OUT_DIR = LOCK.parent / "anchoring"
HEADERS = OUT_DIR / "headers.json"
OUT = OUT_DIR / "anchoring.json"

MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
BITCOIN = bytes.fromhex("0588960d73d71901")
PENDING = bytes.fromhex("83dfe30d2ef90c8e")
#: A header must declare a target below 2**(256 - MIN_WORK_BITS): one built on
#: a trivial target would cost nothing to forge.
MIN_WORK_BITS = 64
_MAX_DEPTH = 256


class OtsError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise OtsError("ots_truncated")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def byte(self) -> int:
        return self.take(1)[0]

    def varuint(self) -> int:
        value, shift = 0, 0
        while True:
            b = self.byte()
            value |= (b & 0x7F) << shift
            if not b & 0x80:
                return value
            shift += 7
            if shift > 63:
                raise OtsError("ots_varuint_too_long")

    def varbytes(self, limit: int = 8192) -> bytes:
        n = self.varuint()
        if n > limit:
            raise OtsError("ots_varbytes_too_long")
        return self.take(n)


def _op(tag: int, reader: _Reader, msg: bytes) -> bytes:
    if tag == 0x08:
        return hashlib.sha256(msg).digest()
    if tag == 0xF0:
        return msg + reader.varbytes()
    if tag == 0xF1:
        return reader.varbytes() + msg
    raise OtsError(f"ots_operation_unsupported:{tag:#04x}")


def parse_ots(data: bytes) -> tuple[bytes, list[dict[str, Any]]]:
    """(file digest, attestations), each with the message it commits to."""
    reader = _Reader(data)
    if reader.take(len(MAGIC)) != MAGIC:
        raise OtsError("ots_magic_mismatch")
    if reader.varuint() != 1:
        raise OtsError("ots_version_unsupported")
    if reader.byte() != 0x08:
        raise OtsError("ots_file_hash_not_sha256")
    digest = reader.take(32)
    attestations: list[dict[str, Any]] = []

    def timestamp(msg: bytes, depth: int) -> None:
        if depth > _MAX_DEPTH:
            raise OtsError("ots_too_deep")
        tag = reader.byte()
        while tag == 0xFF:  # a fork: one branch here, the rest follow
            branch(reader.byte(), msg, depth)
            tag = reader.byte()
        branch(tag, msg, depth)

    def branch(tag: int, msg: bytes, depth: int) -> None:
        if tag == 0x00:
            kind = reader.take(8)
            payload = _Reader(reader.varbytes())
            if kind == BITCOIN:
                attestations.append({"kind": "bitcoin", "height": payload.varuint(),
                                     "commitment": msg})
            elif kind == PENDING:
                attestations.append({"kind": "pending",
                                     "uri": payload.varbytes().decode("utf-8", "replace")})
            else:
                attestations.append({"kind": "unknown", "tag": kind.hex()})
            return
        timestamp(_op(tag, reader, msg), depth + 1)

    timestamp(digest, 0)
    if reader.pos != len(data):
        raise OtsError("ots_trailing_bytes")
    return digest, attestations


def _dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def header_problems(height: int, record: dict[str, Any],
                    previous: dict[str, Any] | None) -> list[str]:
    """What is wrong with one pinned header; empty when it holds offline."""
    try:
        header = bytes.fromhex(record["header"])
    except (KeyError, ValueError):
        return [f"header_unreadable:{height}"]
    if len(header) != 80:
        return [f"header_not_80_bytes:{height}"]
    problems = []
    block_hash = _dsha256(header)[::-1].hex()
    if block_hash != record.get("hash"):
        problems.append(f"header_hash_mismatch:{height}")
    sources = record.get("sources") or {}
    if len(sources) < 2 or set(sources.values()) != {record.get("hash")}:
        problems.append(f"header_sources_disagree:{height}")
    bits = int.from_bytes(header[72:76], "little")
    exponent, mantissa = bits >> 24, bits & 0x007FFFFF
    target = mantissa << (8 * (exponent - 3)) if exponent >= 3 else mantissa >> (8 * (3 - exponent))
    if not 0 < target < 2 ** (256 - MIN_WORK_BITS):
        problems.append(f"header_work_too_low:{height}")
    elif int.from_bytes(_dsha256(header), "little") > target:
        problems.append(f"header_proof_of_work_invalid:{height}")
    if previous is not None and header[4:36][::-1].hex() != previous["hash"]:
        problems.append(f"header_does_not_link:{height}")
    return problems


def evaluate(log_dir: Path = LOG, headers_path: Path = HEADERS) -> dict[str, Any]:
    """The anchoring claim, with every attestation and why it holds or not."""
    stamp = (log_dir / "checkpoint.stamp").read_bytes()
    checkpoint = (log_dir / "checkpoint.json").read_bytes()
    reasons: list[str] = []
    if stamp != checkpoint:
        reasons.append("stamp_differs_from_signed_checkpoint")
    try:
        digest, attestations = parse_ots((log_dir / "checkpoint.stamp.ots").read_bytes())
    except OtsError as exc:
        return _claim("NOT_ESTABLISHED", [*reasons, exc.code], [], None)
    if digest != hashlib.sha256(stamp).digest():
        reasons.append("ots_commits_to_other_bytes")
    headers = (json.loads(headers_path.read_text(encoding="utf-8"))["headers"]
               if headers_path.is_file() else {})
    checked = []
    for att in attestations:
        row: dict[str, Any] = {k: v for k, v in att.items() if k != "commitment"}
        if att["kind"] == "bitcoin":
            row["commitment"] = att["commitment"].hex()
            record = headers.get(str(att["height"]))
            if record is None:
                row["problems"] = ["header_not_pinned"]
            else:
                problems = header_problems(att["height"], record,
                                           headers.get(str(att["height"] - 1)))
                header = bytes.fromhex(record["header"]) if not any(
                    p.startswith(("header_unreadable", "header_not_80")) for p in problems) else b""
                if header and header[36:68] != att["commitment"]:
                    problems.append("commitment_is_not_the_merkle_root")
                row.update(block_hash=record.get("hash"), problems=problems)
                if header:
                    # Miner-declared, within about two hours of true time: an upper bound
                    # on when the checkpoint existed, not an exact instant.
                    row["block_time"] = int.from_bytes(header[68:72], "little")
        checked.append(row)
    held = [r for r in checked if r["kind"] == "bitcoin" and not r["problems"]]
    if reasons:
        verdict = "NOT_ESTABLISHED"
    elif held:
        verdict, reasons = "ESTABLISHED", ["bitcoin_attestation_verified_against_pinned_header"]
    elif any(r["kind"] == "bitcoin" for r in checked):
        verdict = "NOT_ESTABLISHED"
        reasons = sorted({p for r in checked for p in r.get("problems", [])})
    else:
        verdict, reasons = "NOT_ESTABLISHED", ["no_bitcoin_attestation"]
    earliest = min((r["height"] for r in held), default=None)
    return _claim(verdict, reasons, checked, earliest)


def _claim(verdict: str, reasons: list[str], attestations: list[dict[str, Any]],
           earliest: int | None) -> dict[str, Any]:
    return {
        "schema": "remora-h55-anchoring-v1",
        "claim_id": "checkpoint_anchoring",
        "verdict": verdict,
        "reason_codes": sorted(set(reasons)),
        "earliest_verified_height": earliest,
        "checkpoint_sha256": canon.sha256_hex((LOG / "checkpoint.json").read_bytes()),
        "attestations": attestations,
        "trust_basis": ("headers from two block explorers with different operators, kept only "
                        "when both gave the same block id; proof of work and linkage checked "
                        "offline; no node of ours"),
        "does_not_establish": [
            "that the block is in the best chain now",
            "seen_block ordering of log entries relative to the block",
            "anything about an entry beyond what the signed checkpoint covers",
        ],
        "classification": "author-run check of a public proof; not independent",
    }


def render(body: dict[str, Any]) -> bytes:
    return json.dumps(body, indent=1, sort_keys=True).encode("utf-8") + b"\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    data = render(evaluate())
    if args.json:
        sys.stdout.write(data.decode("utf-8"))
        return 0
    if args.write:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_bytes(data)
        print(json.dumps({"written": OUT.name}))
        return 0
    ok = OUT.is_file() and OUT.read_bytes() == data
    print(json.dumps({"ok": ok, "file": OUT.name}))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

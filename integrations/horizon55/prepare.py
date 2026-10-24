#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""One-time, networked preparation of the Horizon #55 inputs (SDD-H55 WP0).

Fetches the frozen Horizon Shield files at their pinned commits over HTTPS
from raw.githubusercontent.com and writes them under the package's inputs
directory. Nothing else in this package touches the network: ``run.py`` and
``check_inputs.py`` read only local bytes.

The set-2 log, bundle, settlement, the public A/C audit and the fixture are
MIT-licensed (Horizon Shield ``LICENSE``, copied beside them) and are
vendored. The souba-db dataset is compiled from third-party market sources;
its redistribution terms are not established, so it is fetched into a
git-ignored cache and pinned by digest only.

    python integrations/horizon55/prepare.py --write-lock   # first freeze
    python integrations/horizon55/prepare.py                # fetch and check against the locks

The frozen lock is never rewritten for later evidence. B's audit bytes,
published after the row first ran, are a separate extension with its own
lock (``AUDIT_B_LOCK``, ``--write-audit-b-lock``).

    python integrations/horizon55/prepare.py --anchor-headers   # pin the attested headers

``--anchor-headers`` asks two block explorers run by different operators for
the headers the checkpoint's OpenTimestamps proof attests to (and the one
before the earliest, for linkage), and writes ``anchoring/headers.json`` only
when both return the same block id and the same header bytes. ``anchor.py``
then checks them offline.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import canon  # noqa: E402

REPO = "ogasurfproject-jpg/horizon-shield"
HORIZON_REF = "b85029de8d22c5246886f4f50ede03da0f54dfcf"
DATASET_REF = "5b22c203248b0149cd0456f77d32feb887f48ee0"
BASE = "workers/hs-ledger/nenrin/musubi-v0/ca2a-companion-v0"
ROOT = HERE.parents[1]
INPUTS = ROOT / "artifacts" / "interop" / "horizon55" / "inputs"
CACHE = HERE / ".cache"
LOCK = ROOT / "artifacts" / "interop" / "horizon55" / "inputs.lock.json"
#: Evidence extension: B's audit bytes, published 2026-10-24 on the horizon-shield
#: branch evidence/hs51-set2-audit-b. The commit descends from HORIZON_REF and, in
#: the companion directory, adds audit_B.json and changes only a sidecar control
#: this row does not read, so every frozen input is unchanged at it.
AUDIT_B_REF = "c824cbe61a383e57f1d9d15fea962a79f5b6bbd5"
AUDIT_B_LOCK = LOCK.parent / "audit-b" / "inputs.lock.json"

ENTRY_NAMES = ("000_budget", "001_criteria_A", "002_criteria_B", "003_criteria_C", "004_use_A",
               "005_payment_A", "006_receipt_A", "007_use_B", "008_payment_B", "009_receipt_B",
               "010_use_C", "011_payment_C", "012_receipt_C")

#: (role, revision, upstream path, local path relative to its root, vendored).
SOURCES: tuple[tuple[str, str, str, str, bool], ...] = (
    ("license", HORIZON_REF, "LICENSE", "LICENSE", True),
    ("set2_readme", HORIZON_REF, f"{BASE}/pilot51/set2/README.md", "pilot51/set2/README.md", True),
    ("set2_sha256sums", HORIZON_REF, f"{BASE}/pilot51/set2/SHA256SUMS",
     "pilot51/set2/SHA256SUMS", True),
    ("set2_bundle", HORIZON_REF, f"{BASE}/pilot51/set2/bundle.json",
     "pilot51/set2/bundle.json", True),
    ("reference_settlement", HORIZON_REF, f"{BASE}/pilot51/set2/settlement.json",
     "pilot51/set2/settlement.json", True),
    ("log_checkpoint", HORIZON_REF, f"{BASE}/pilot51/set2/log/checkpoint.json",
     "pilot51/set2/log/checkpoint.json", True),
    ("log_checkpoint_stamp", HORIZON_REF, f"{BASE}/pilot51/set2/log/checkpoint.stamp",
     "pilot51/set2/log/checkpoint.stamp", True),
    ("log_checkpoint_ots", HORIZON_REF, f"{BASE}/pilot51/set2/log/checkpoint.stamp.ots",
     "pilot51/set2/log/checkpoint.stamp.ots", True),
    ("log_entries_jsonl", HORIZON_REF, f"{BASE}/pilot51/set2/log/entries.jsonl",
     "pilot51/set2/log/entries.jsonl", True),
    *((f"log_entry_{name}", HORIZON_REF, f"{BASE}/pilot51/set2/log/entries/{name}.json",
       f"pilot51/set2/log/entries/{name}.json", True) for name in ENTRY_NAMES),
    ("public_ac_audit", HORIZON_REF, f"{BASE}/rehearsal/live_smoke/audit.json",
     "rehearsal/live_smoke/audit.json", True),
    ("original_fixture", HORIZON_REF, f"{BASE}/rehearsal/fixture.json",
     "rehearsal/fixture.json", True),
    ("dataset_souba_db", DATASET_REF, "data/souba-db.json", "souba-db.json", False),
)


AUDIT_B_SOURCES: tuple[tuple[str, str, str, str, bool], ...] = (
    ("set2_audit_b", AUDIT_B_REF, f"{BASE}/pilot51/set2/audit_B.json",
     "pilot51/set2/audit_B.json", True),
)


def _fetch(revision: str, path: str) -> bytes:
    url = f"https://raw.githubusercontent.com/{REPO}/{revision}/{path}"
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - fixed https host
        return response.read()


EXPLORERS = {"blockstream.info": "https://blockstream.info/api",
             "mempool.space": "https://mempool.space/api"}


def _get(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - fixed https hosts
        return response.read().decode("ascii").strip()


def anchor_headers() -> dict[str, Any]:
    """The attested headers, agreed by both explorers, or an error."""
    import anchor

    _, attestations = anchor.parse_ots(
        (INPUTS / "pilot51/set2/log/checkpoint.stamp.ots").read_bytes())
    heights = sorted({a["height"] for a in attestations if a["kind"] == "bitcoin"})
    if not heights:
        return {"error": "no_bitcoin_attestation"}
    headers = {}
    for height in [heights[0] - 1, *heights]:
        ids = {name: _get(f"{base}/block-height/{height}") for name, base in EXPLORERS.items()}
        raw = {name: _get(f"{EXPLORERS[name]}/block/{ids[name]}/header") for name in EXPLORERS}
        if len(set(ids.values())) != 1 or len(set(raw.values())) != 1:
            return {"error": "explorers_disagree", "height": height}
        headers[str(height)] = {"hash": next(iter(ids.values())),
                                "header": next(iter(raw.values())), "sources": ids}
    return {"schema": "remora-h55-anchor-headers-v1",
            "explorers": EXPLORERS,
            "rule": "kept only when every explorer returned the same block id and header bytes",
            "headers": headers}


def local_path(vendored: bool, relative: str) -> Path:
    return (INPUTS if vendored else CACHE) / relative


def _prepare(sources: tuple[tuple[str, str, str, str, bool], ...], lock_path: Path,
             write: bool) -> list[dict[str, Any]] | dict[str, str]:
    """Fetch ``sources``, check them against ``lock_path`` unless writing it; the records."""
    lock = None if write else json.loads(lock_path.read_text(encoding="utf-8"))
    pinned = {s["role"]: s for s in lock["sources"]} if lock else {}
    records = []
    for role, revision, upstream, relative, vendored in sources:
        data = _fetch(revision, upstream)
        digest = canon.sha256_hex(data)
        if lock is not None:
            want = pinned[role]
            if (want["sha256"], want["bytes"]) != (digest, len(data)):
                return {"error": "pinned_bytes_mismatch", "role": role}
        target = local_path(vendored, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        records.append({"role": role, "revision": revision, "upstream_path": upstream,
                        "local_path": relative, "vendored": vendored, "bytes": len(data),
                        "sha256": digest})
    return records


def _write_lock(path: Path, body: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canon.jcs(body) + b"\n")


def _lock_body(revision: str, occurrences: list[str], gaps: list[str],
               records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "remora-h55-inputs-lock-v1",
        "upstream_repository": f"https://github.com/{REPO}",
        "horizon_revision": revision,
        "dataset_revision": DATASET_REF,
        "license": {"spdx": "MIT", "role": "license",
                    "applies_to": "every vendored file (Horizon Shield repository LICENSE)"},
        "dataset_terms": ("not established: compiled from third-party market sources "
                          "(souba-db _meta.sources); fetched into a local cache, never "
                          "vendored"),
        "required_occurrences": occurrences,
        "known_gaps": gaps,
        "sources": records,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-lock", action="store_true",
                        help="freeze: write inputs.lock.json from the fetched bytes")
    parser.add_argument("--write-audit-b-lock", action="store_true",
                        help="freeze the B-audit extension: write audit-b/inputs.lock.json")
    parser.add_argument("--anchor-headers", action="store_true",
                        help="pin the attested Bitcoin headers: write anchoring/headers.json")
    args = parser.parse_args(argv)
    if args.anchor_headers:
        body = anchor_headers()
        if "error" in body:
            print(json.dumps(body))
            return 2
        path = LOCK.parent / "anchoring" / "headers.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(body, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({"headers": sorted(body["headers"], key=int)}))
        return 0
    fetched = 0
    for sources, lock_path, write in ((SOURCES, LOCK, args.write_lock),
                                      (AUDIT_B_SOURCES, AUDIT_B_LOCK, args.write_audit_b_lock)):
        records = _prepare(sources, lock_path, write)
        if isinstance(records, dict):
            print(json.dumps(records))
            return 2
        fetched += len(records)
        if write and lock_path == LOCK:
            _write_lock(LOCK, _lock_body(
                HORIZON_REF, ["hs51-musubi-2-A", "hs51-musubi-2-B", "hs51-musubi-2-C"],
                ["raw set-2 call bodies are not public",
                 "the audit bytes for B are not public",
                 "acceptance records of the live run are not public"], records))
        elif write:
            _write_lock(AUDIT_B_LOCK, _lock_body(
                AUDIT_B_REF, ["hs51-musubi-2-B"],
                ["raw set-2 call bodies are not public",
                 "the estimate B's audit names (its fixture_sha256) is not public",
                 "acceptance records of the live run are not public"], records))
    print(json.dumps({"fetched": fetched, "lock_written": args.write_lock,
                      "audit_b_lock_written": args.write_audit_b_lock}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

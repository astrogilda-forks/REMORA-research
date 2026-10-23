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
    python integrations/horizon55/prepare.py                # fetch and check against the lock
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

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


def _fetch(revision: str, path: str) -> bytes:
    url = f"https://raw.githubusercontent.com/{REPO}/{revision}/{path}"
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 - fixed https host
        return response.read()


def local_path(vendored: bool, relative: str) -> Path:
    return (INPUTS if vendored else CACHE) / relative


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-lock", action="store_true",
                        help="freeze: write inputs.lock.json from the fetched bytes")
    args = parser.parse_args(argv)
    lock = None if args.write_lock else json.loads(LOCK.read_text(encoding="utf-8"))
    pinned = {s["role"]: s for s in lock["sources"]} if lock else {}
    records = []
    for role, revision, upstream, relative, vendored in SOURCES:
        data = _fetch(revision, upstream)
        digest = canon.sha256_hex(data)
        if lock is not None:
            want = pinned[role]
            if (want["sha256"], want["bytes"]) != (digest, len(data)):
                print(json.dumps({"error": "pinned_bytes_mismatch", "role": role}))
                return 2
        target = local_path(vendored, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        records.append({"role": role, "revision": revision, "upstream_path": upstream,
                        "local_path": relative, "vendored": vendored, "bytes": len(data),
                        "sha256": digest})
    if args.write_lock:
        body = {
            "schema": "remora-h55-inputs-lock-v1",
            "upstream_repository": f"https://github.com/{REPO}",
            "horizon_revision": HORIZON_REF,
            "dataset_revision": DATASET_REF,
            "license": {"spdx": "MIT", "role": "license",
                        "applies_to": "every vendored file (Horizon Shield repository LICENSE)"},
            "dataset_terms": ("not established: compiled from third-party market sources "
                              "(souba-db _meta.sources); fetched into a local cache, never "
                              "vendored"),
            "required_occurrences": ["hs51-musubi-2-A", "hs51-musubi-2-B", "hs51-musubi-2-C"],
            "known_gaps": ["raw set-2 call bodies are not public",
                           "the audit bytes for B are not public",
                           "acceptance records of the live run are not public"],
            "sources": records,
        }
        LOCK.parent.mkdir(parents=True, exist_ok=True)
        LOCK.write_bytes(canon.jcs(body) + b"\n")
    print(json.dumps({"fetched": len(records), "lock_written": args.write_lock}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

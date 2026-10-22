#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Offline input gate for the Horizon #55 row (SDD-H55 WP0/WP1, H55-T00, H55-T17).

Checks every file the lock names against the local bytes: exact size and
SHA-256. A vendored file that is missing or differs fails closed. The
dataset lives in a git-ignored cache; when it has not been prepared it is
reported as ``not_prepared``, and the row then cannot establish dataset byte
identity, which is a bounded result, not a pass.

The disclosure gate scans every file of the package that would be published
(inputs, results, report) for secrets and private material, and fails on a
match. It never prints the matched text.

    python integrations/horizon55/check_inputs.py            # inputs + disclosure gate
    python integrations/horizon55/check_inputs.py --json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import canon  # noqa: E402
from prepare import CACHE, INPUTS, LOCK  # noqa: E402

PACKAGE = LOCK.parent
#: Patterns that must never appear in a published file of this package.
DISCLOSURE_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("private_key_block", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("github_token", re.compile(rb"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}")),
    ("anthropic_key", re.compile(rb"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai_key", re.compile(rb"\bsk-[A-Za-z0-9]{40,}\b")),
    ("aws_key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("osf_token_assignment", re.compile(rb"OSF_TOKEN\s*[=:]\s*['\"]?[A-Za-z0-9]{20,}")),
    ("private_marker", re.compile(rb"(?i)\b(?:private crosswalk|crosswalk notes|do not publish|"
                                  rb"acceptance-record-private)\b")),
)


def load_lock(path: Path = LOCK) -> dict[str, Any]:
    lock = canon.loads(path.read_bytes())
    if lock.get("schema") != "remora-h55-inputs-lock-v1":
        raise canon.StrictJSONError("lock_schema_unknown", str(lock.get("schema")))
    return lock


def check_sources(lock: dict[str, Any], inputs: Path = INPUTS,
                  cache: Path = CACHE) -> list[dict[str, Any]]:
    """One record per source: ok, missing, not_prepared or mismatch."""
    out = []
    for src in lock["sources"]:
        root = inputs if src["vendored"] else cache
        path = (root / src["local_path"]).resolve()
        if root.resolve() not in path.parents:
            out.append({"role": src["role"], "status": "path_escapes_root"})
            continue
        if not path.is_file():
            out.append({"role": src["role"],
                        "status": "missing" if src["vendored"] else "not_prepared"})
            continue
        data = path.read_bytes()
        ok = (len(data), canon.sha256_hex(data)) == (src["bytes"], src["sha256"])
        out.append({"role": src["role"], "status": "ok" if ok else "mismatch",
                    "bytes": len(data), "sha256": canon.sha256_hex(data)})
    return out


def disclosure_findings(root: Path = PACKAGE) -> list[dict[str, str]]:
    """Files of the publishable package that match a disclosure pattern."""
    findings = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        data = path.read_bytes()
        for name, pattern in DISCLOSURE_PATTERNS:
            if pattern.search(data):
                findings.append({"path": path.relative_to(root).as_posix(), "pattern": name})
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    lock = load_lock()
    sources = check_sources(lock)
    disclosure = disclosure_findings()
    failed = [s for s in sources if s["status"] not in ("ok", "not_prepared")]
    body = {"sources": sources, "disclosure_findings": disclosure,
            "not_prepared": [s["role"] for s in sources if s["status"] == "not_prepared"],
            "ok": not failed and not disclosure}
    if args.json:
        print(json.dumps(body, indent=1, sort_keys=True))
    else:
        for s in sources:
            print(f"{s['status']:<14} {s['role']}")
        for f in disclosure:
            print(f"DISCLOSURE     {f['path']} ({f['pattern']})")
    return 0 if body["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

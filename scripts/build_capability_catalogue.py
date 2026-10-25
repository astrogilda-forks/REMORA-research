#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Build the packaged capability catalogue from the capability register.

ADR-UE-03 item 6: the server never reads ``docs/``. What it needs from the
register at runtime (each capability's id, name, registered maturity and
primary hook) is packaged with the wheel as
``remora/governance/capability_catalogue_v1.json``, built here and held to the
register by ``--check`` (and ``tests/test_capability_activation.py``). It holds
no digest of the register, so a re-audit line in the register does not make it
stale; a changed id, name, status or hook does.

    python scripts/build_capability_catalogue.py --write
    python scripts/build_capability_catalogue.py --check
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTER = ROOT / "docs" / "assurance" / "capability_register_v1.yaml"
CATALOGUE = ROOT / "remora" / "governance" / "capability_catalogue_v1.json"


def build() -> str:
    import yaml

    raw = REGISTER.read_bytes()
    register = yaml.safe_load(raw.decode("utf-8"))
    entries = [{"id": c["id"], "name": c["name"], "status": c["status"],
                "hook": (c.get("hook") or {}).get("primary", "")}
               for c in register["capabilities"]]
    body = {
        "schema": "remora-capability-catalogue/v1",
        "source": "docs/assurance/capability_register_v1.yaml",
        "capabilities": sorted(entries, key=lambda e: e["id"]),
    }
    return json.dumps(body, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--write", action="store_true")
    group.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    text = build()
    if args.write:
        CATALOGUE.write_bytes(text.encode("utf-8"))
        print(f"[WRITE] {CATALOGUE.relative_to(ROOT).as_posix()}")
        return 0
    current = CATALOGUE.read_bytes().decode("utf-8").replace("\r\n", "\n") if CATALOGUE.exists() else ""
    if current != text:
        print(f"[FAIL] {CATALOGUE.relative_to(ROOT).as_posix()} is stale; run --write",
              file=sys.stderr)
        return 1
    print(f"[PASS] {CATALOGUE.relative_to(ROOT).as_posix()} matches the register")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

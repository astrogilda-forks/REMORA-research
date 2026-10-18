#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Lint the ``flow`` blocks of a ToolSpec bundle (IFC-03, schemas/tool_spec_v4.yaml).

Usage: check_toolspec_flow.py [--strict] BUNDLE [BUNDLE ...]

A bundle is the YAML or JSON a deployment signs: a mapping with
``tool_specs``. Each spec's ``flow`` block is parsed and checked against
lint rules FL-01 to FL-12 and FL-14. ``--strict`` adds FL-13: every spec must carry a
block, as the strict runtime profile will require at registry load.

Exit 0 when every block is clean, 1 when any rule fails or a block cannot be
parsed, 2 on a usage error. Run it before signing: a signed bundle with a
broken block is still refused at load.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from remora.flow.spec import FlowSpecRefused, lint_toolspec  # noqa: E402


def _load(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    import yaml

    return yaml.safe_load(text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--strict", action="store_true",
                        help="refuse a spec with no flow block (FL-13)")
    parser.add_argument("bundles", nargs="+", type=Path)
    args = parser.parse_args(argv)

    problems: list[str] = []
    checked = 0
    for path in args.bundles:
        bundle = _load(path)
        specs = bundle.get("tool_specs") if isinstance(bundle, dict) else None
        if not isinstance(specs, list):
            problems.append(f"{path}: no tool_specs list")
            continue
        for spec in specs:
            checked += 1
            try:
                problems.extend(f"{path}: {f}" for f in lint_toolspec(spec, strict=args.strict))
            except FlowSpecRefused as exc:
                problems.append(f"{path}: {spec.get('tool_id', '?')}: {exc}")

    if problems:
        print(f"[FAIL] {len(problems)} flow problem(s) in {checked} spec(s):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"[PASS] {checked} spec(s) lint clean"
          + (" under the strict profile." if args.strict else "."))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

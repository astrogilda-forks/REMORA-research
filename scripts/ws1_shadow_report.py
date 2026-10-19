#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""What WS1 enforce would have changed, read from a shadow deployment's chain (#953, WP6).

With ``REMORA_WS1_MODE=shadow`` every ``assessed`` record carries a ``ws1``
block and the decision is the engine's alone. This report reads those records
and counts, per tool, how often enforce would have turned the recorded
decision into an ABSTAIN or kept it, why, and how often the WS1 record itself
failed to verify. It reads the chain; it changes nothing.

    python scripts/ws1_shadow_report.py --tenant acme --sqlite /var/lib/remora/execution.db
    python scripts/ws1_shadow_report.py --tenant acme --pg-dsn "$REMORA_PG_DSN"

A shadow pilot is the first step of WP6. Moving it to enforce needs what the
design lists (WS1 SDD §13.2): the IFC work packages, a calibrated monitor
profile evaluated for the pilot's language and vertical, and the owner's
decision.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))


def report(payloads: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    from remora.verification.records import verify_record_hash

    by_tool: dict[str, Counter[str]] = defaultdict(Counter)
    codes: Counter[str] = Counter()
    modes: Counter[str] = Counter()
    unverified = 0
    for p in payloads:
        if p.get("event") != "assessed" or "ws1" not in p:
            continue
        ws1 = p["ws1"]
        modes[str(ws1.get("mode"))] += 1
        tool = str(p.get("tool_name"))
        record = ws1.get("record")
        if record is not None and not verify_record_hash(record):
            unverified += 1
        clean = record is not None and ws1.get("status") == "evaluated" and all(
            c.get("source") == "engine" for c in record.get("all_caps", []))
        decision = str(p.get("decision"))
        if clean:
            by_tool[tool]["unchanged"] += 1
        elif ws1.get("review_role") and decision != "abstain":
            by_tool[tool]["to_review_route"] += 1
        elif decision == "abstain":
            by_tool[tool]["already_abstain"] += 1
        else:
            by_tool[tool][f"{decision}_to_abstain"] += 1
        if record is not None:
            codes.update(c for c in record.get("reason_codes", []))
        else:
            codes[str(ws1.get("status"))] += 1
    return {"assessed_with_ws1": sum(modes.values()), "modes": dict(modes),
            "records_failing_hash_check": unverified,
            "by_tool": {t: dict(c) for t, c in sorted(by_tool.items())},
            "ws1_reason_codes": dict(codes.most_common())}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tenant", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--sqlite")
    source.add_argument("--pg-dsn")
    source.add_argument("--jsonl", type=Path, help="one chain payload per line")
    args = parser.parse_args(argv)
    if args.jsonl:
        payloads = [json.loads(line) for line in args.jsonl.read_text(encoding="utf-8")
                    .splitlines() if line.strip()]
    else:
        from remora.governance.tenant_chain import PostgresTenantChain, SQLiteTenantChain

        chain = SQLiteTenantChain(args.sqlite) if args.sqlite else PostgresTenantChain(args.pg_dsn)
        payloads = [e.payload for e in chain.entries(args.tenant)]
    print(json.dumps(report(payloads), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

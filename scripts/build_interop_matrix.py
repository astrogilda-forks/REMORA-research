#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Generate docs/interop/INTEROP_MATRIX.md from machine-readable records.

Inputs: the edges declared in ``artifacts/interop/FEDERATION.yaml``, the
contract lifecycle in ``artifacts/interop/index.json`` and every
``interop-result-v1`` record under ``artifacts/interop/runs/``. The status
column is derived, never typed, so the table cannot drift into the state
aeoess/agent-governance-vocabulary#177 warned about, where nobody can tell
proposed from implemented from independently reproduced.

    (no flag)   write the matrix
    --check     exit 1 if the committed matrix differs from what the records yield

Derivation, per edge: an edge names one claim of one contract (its
``property``), and only records for that ``(contract_id, claim_id)`` pair
count, so a result for one claim can neither raise nor contradict another
claim of the same contract. Every claim of a contract with an edge needs its
own edge, and every record must fall on exactly one edge; the generator
refuses otherwise. PRIOR_RECORD stays as declared with its link; an edge
with no record keeps its declared stage; any CONTRADICTED record wins; else
the highest independence level among ESTABLISHED records names the status
(L0 AUTHOR_RUN, L1 REPRODUCED, L2 SECOND_IMPLEMENTATION, L3 and L4
INDEPENDENTLY_ESTABLISHED); records that are all NOT_ESTABLISHED give
NOT_ESTABLISHED. An edge marked ``experimental`` carries that prefix whatever
its records say.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "artifacts" / "interop" / "FEDERATION.yaml"
INDEX = ROOT / "artifacts" / "interop" / "index.json"
RUNS = ROOT / "artifacts" / "interop" / "runs"
OUT = ROOT / "docs" / "interop" / "INTEROP_MATRIX.md"

LEVELS = ["L0_SELF_TEST", "L1_REPRODUCTION", "L2_SECOND_IMPLEMENTATION", "L3_INDEPENDENT_RECOMPUTATION", "L4_INDEPENDENT_HOST_RUN"]
STATUS_BY_LEVEL = {
    "L0_SELF_TEST": "AUTHOR_RUN",
    "L1_REPRODUCTION": "REPRODUCED",
    "L2_SECOND_IMPLEMENTATION": "SECOND_IMPLEMENTATION",
    "L3_INDEPENDENT_RECOMPUTATION": "INDEPENDENTLY_ESTABLISHED",
    "L4_INDEPENDENT_HOST_RUN": "INDEPENDENTLY_ESTABLISHED",
}


def load_records() -> list[dict[str, Any]]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(RUNS.glob("*.json"))]


def derive(edge: dict[str, Any], records: list[dict[str, Any]]) -> dict[str, Any]:
    """Status and its supporting facts for one edge."""
    if edge["declared"] == "PRIOR_RECORD":
        return {"status": "PRIOR_RECORD", "records": 0, "level": "", "result": "", "evaluators": ""}
    mine = [r for r in records
            if r["contract_id"] == edge.get("contract") and r["claim"] == edge["property"]]
    if not mine:
        return {"status": edge["declared"], "records": 0, "level": "", "result": "", "evaluators": ""}
    results = {r["status"] for r in mine}
    evaluators = sorted({f"{r['evaluator']['project']}/{r['evaluator']['kind'].lower()}" for r in mine})
    if "CONTRADICTED" in results:
        status, level = "CONTRADICTED", ""
    elif "ESTABLISHED" in results:
        level = max((r["independence_level"] for r in mine if r["status"] == "ESTABLISHED"), key=LEVELS.index)
        status = STATUS_BY_LEVEL[level]
    else:
        status, level = "NOT_ESTABLISHED", ""
    if edge.get("experimental"):
        status = f"EXPERIMENTAL, {status}"
    result = "CONTRADICTED" if "CONTRADICTED" in results else ("ESTABLISHED" if "ESTABLISHED" in results else "NOT_ESTABLISHED")
    return {"status": status, "records": len(mine), "level": level, "result": result, "evaluators": ", ".join(evaluators)}


def coverage_problems(edges: list[dict[str, Any]], records: list[dict[str, Any]],
                      claims_by_contract: dict[str, list[str]]) -> list[str]:
    """Why the edges do not partition the contracts' claims and the records.

    Before 2026-10-26 an edge counted every record of its contract, so the
    single_use_authorization records sat on E-ECB and three effect-evidence-v2
    claims on E-EE-V2. A later result for one claim would have moved the
    status shown for another.
    """
    problems: list[str] = []
    seen: dict[tuple[str, str], str] = {}
    for edge in edges:
        contract = edge.get("contract")
        if not contract:
            continue
        pair = (contract, edge["property"])
        if edge["property"] not in claims_by_contract.get(contract, []):
            problems.append(f"{edge['id']}: {edge['property']!r} is not a claim of {contract}")
        if pair in seen:
            problems.append(f"{edge['id']}: {pair} is already the edge {seen[pair]}")
        seen[pair] = edge["id"]
    for contract in sorted({c for c, _ in seen}):
        for claim in claims_by_contract.get(contract, []):
            if (contract, claim) not in seen:
                problems.append(f"{contract}: claim {claim!r} has no edge")
    for record in records:
        pair = (record["contract_id"], record["claim"])
        if pair not in seen:
            problems.append(f"record for {pair} falls on no edge")
    return problems


def _claims_by_contract(index: dict[str, Any]) -> dict[str, list[str]]:
    return {
        c["id"]: [x["claim_id"] for x in json.loads((ROOT / c["claim_packet"]).read_text(encoding="utf-8"))["claims"]]
        for c in index["contracts"]
    }


def render() -> str:
    manifest = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    index = json.loads(INDEX.read_text(encoding="utf-8"))
    lifecycle = {c["id"]: c["lifecycle"] for c in index["contracts"]}
    records = load_records()
    problems = coverage_problems(manifest["edges"], records, _claims_by_contract(index))
    if problems:
        raise SystemExit("interop edges do not partition the claims:\n  " + "\n  ".join(problems))
    external_rows = []
    for contract in index["contracts"]:
        for record in contract.get("external_runs", []):
            results = ", ".join(sorted({row["result"] for row in record["results"]}))
            external_rows.append("| " + " | ".join([
                contract["id"], contract["lifecycle"], record["implementation_diversity"],
                record["independence"], results,
                f"[run]({record['run_ref']})",
            ]) + " |")
    rows = []
    for edge in manifest["edges"]:
        d = derive(edge, records)
        contract = edge.get("contract", "")
        if contract:
            contract_cell = f"[`{contract}`](../../artifacts/interop/{contract}/README.md) ({lifecycle.get(contract, '?')})"
        elif edge.get("record"):
            contract_cell = f"[record](../../{edge['record']})"
        else:
            contract_cell = ""
        rows.append("| " + " | ".join([
            edge["id"], edge["producer"], edge["consumer"], edge["artifact"], f"`{edge['property']}`",
            contract_cell, edge["declared"], str(d["records"]), d["level"], d["result"], f"**{d['status']}**",
        ]) + " |")
    lines = [
        "# Interop matrix",
        "",
        "Generated by `scripts/build_interop_matrix.py` from",
        "`artifacts/interop/FEDERATION.yaml`, `artifacts/interop/index.json` and the",
        "`interop-result-v1` records under `artifacts/interop/runs/`. Do not edit;",
        "CI refuses a committed matrix that differs from the records.",
        "",
        "Status is derived. `PROPOSED` and `SPECIFIED` are declared stages with no",
        "record. `AUTHOR_RUN` is an L0 self-test by the producer and advances no",
        "contract. `REPRODUCED` (L1), `SECOND_IMPLEMENTATION` (L2) and",
        "`INDEPENDENTLY_ESTABLISHED` (L3 or L4) name the highest independence level",
        "among ESTABLISHED records. An edge is one claim of one contract and counts",
        "only that claim's records. One CONTRADICTED record makes the edge",
        "`CONTRADICTED` whatever else exists. `PRIOR_RECORD` points at an earlier",
        "record written before the result schema. `EXPERIMENTAL` marks an edge whose",
        "counterpart format is assumed rather than confirmed. No status implies",
        "endorsement, production safety or authority (FED-INV-004).",
        "",
        "| Edge | Producer | Consumer | Artifact | Property | Contract (lifecycle) | Declared | Records | Highest level | Result | Status |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
        *rows,
        "",
        f"Records read: {len(records)}. Contract lifecycle comes from `index.json`;",
        "it moves only on freeze, pin and external run records, never on an author run.",
        "",
        "## External lifecycle records",
        "",
        "The table above counts `interop-result-v1` records only. The index also",
        "retains `external-run-record-v1` evidence below. Thus AUTHOR_RUN above",
        "does not mean that no external run exists. These records retain their",
        "native diversity, independence and results; no L-level is inferred.",
        "REPRODUCED is a package lifecycle, not independent verification.",
        "",
        "| Contract | Lifecycle | Implementation diversity | Independence | Recorded results | Evidence |",
        "|---|---|---|---|---|---|",
        *external_rows,
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    text = render()
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.is_file() else ""
        if current != text:
            print(f"[FAIL] {OUT.relative_to(ROOT)} is stale; run python scripts/build_interop_matrix.py")
            return 1
        print(f"[PASS] {OUT.relative_to(ROOT)} matches the records")
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"[WRITE] {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

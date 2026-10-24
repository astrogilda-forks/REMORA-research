# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Render the capability atlas for the unified capability execution SDD.

Reads docs/design/unified-capability-execution-v1.1-atlas.yaml and writes the
self-contained page docs/design/unified-capability-execution-v1.1-atlas.html
from scripts/templates/capability_atlas.html. The atlas is the assessment
layer the SDD is implemented from: per capability it records necessity, the
proposed hook and mode, the reachable maturity rung, risk, reversibility and
dependencies, next to a copy of the register fields at the SDD's pinned
source revision. The capability register stays authoritative; the copy
exists so the dated page renders the same way after the register moves.

Usage:
    python scripts/generate_capability_atlas.py            # write
    python scripts/generate_capability_atlas.py --check    # verify only
    python scripts/generate_capability_atlas.py --drift    # compare with the live register
    python scripts/generate_capability_atlas.py --fragment --out PATH

--check validates the data (known enums, known and acyclic dependencies,
existing code and test paths) and exits non-zero if the committed page
differs. --drift reports, without failing, where the live capability register
no longer matches the copy at the source revision.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "docs" / "design" / "unified-capability-execution-v1.1-atlas.yaml"
OUT = ROOT / "docs" / "design" / "unified-capability-execution-v1.1-atlas.html"
TEMPLATE = ROOT / "scripts" / "templates" / "capability_atlas.html"
REGISTER = ROOT / "docs" / "assurance" / "capability_register_v1.yaml"

SCHEMA = "remora-capability-atlas/v1"
LADDER = [
    "IMPLEMENTED_LIBRARY", "WIRED_REFERENCE_PATH", "WIRED_API_PATH",
    "PERSISTED_ATOMIC", "ENFORCED_PRODUCTION", "EXTERNALLY_VERIFIED",
]
NECESSITY = {"Critical", "Necessary", "Useful", "Optional", "Research"}
LEVELS = {"H", "M", "L"}
REVERSIBILITY = {"Easy", "Medium", "Hard"}
GATE_STATUS = {"crit", "warn", "good", "none"}
CAP_ID = re.compile(r"^CAP-(\d{3}|META)$")
SHA = re.compile(r"^[0-9a-f]{40}$")


def load(path: Path = DATA) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _cycles(deps: dict[str, list[str]]) -> list[list[str]]:
    found: list[list[str]] = []

    def walk(node: str, path: list[str]) -> None:
        for d in deps.get(node, []):
            if d in path:
                found.append(path[path.index(d):] + [d])
            else:
                walk(d, path + [d])

    for start in deps:
        walk(start, [start])
    return found


def validate(data: dict[str, Any], *, check_paths: bool = True) -> list[str]:
    errors: list[str] = []
    if data.get("schema") != SCHEMA:
        errors.append(f"schema must be {SCHEMA!r}")
    if not SHA.match(str(data.get("source_revision", ""))):
        errors.append("source_revision must be a full 40-character commit SHA")
    if not (ROOT / str(data.get("sdd", ""))).is_file():
        errors.append(f"sdd {data.get('sdd')!r} does not exist")

    caps = data.get("capabilities") or []
    ids = [c.get("id") for c in caps]
    if len(ids) != len(set(ids)):
        errors.append("duplicate capability ids")
    known = set(ids)
    deps: dict[str, list[str]] = {}
    for c in caps:
        cid = c.get("id", "?")
        if not CAP_ID.match(str(cid)):
            errors.append(f"{cid}: id does not match CAP-NNN or CAP-META")
        reg = c.get("register_at_source") or {}
        a = c.get("assessment") or {}
        if reg.get("status") not in LADDER:
            errors.append(f"{cid}: register status {reg.get('status')!r} is not a ladder rung")
        if a.get("reachable_rung") not in LADDER:
            errors.append(f"{cid}: reachable_rung {a.get('reachable_rung')!r} is not a ladder rung")
        elif reg.get("status") in LADDER and (
            LADDER.index(a["reachable_rung"]) < LADDER.index(reg["status"])
        ):
            errors.append(f"{cid}: reachable_rung is below the registered status")
        if a.get("reachable_rung") == "EXTERNALLY_VERIFIED":
            errors.append(f"{cid}: EXTERNALLY_VERIFIED needs an independent party, not the SDD")
        if a.get("necessity") not in NECESSITY:
            errors.append(f"{cid}: necessity {a.get('necessity')!r} unknown")
        risk = a.get("risk") or {}
        if risk.get("likelihood") not in LEVELS or risk.get("consequence") not in LEVELS:
            errors.append(f"{cid}: risk needs likelihood and consequence in H/M/L")
        if (a.get("reversibility") or {}).get("grade") not in REVERSIBILITY:
            errors.append(f"{cid}: reversibility.grade unknown")
        for field in ("name", "class", "purpose", "does", "now", "sdd_hook",
                      "sdd_mode", "sdd_change", "security"):
            if not str(a.get(field, "")).strip():
                errors.append(f"{cid}: assessment.{field} is empty")
        for lit in a.get("literature") or []:
            if not all(str(lit.get(k, "")).strip() for k in ("source", "reference", "role")):
                errors.append(f"{cid}: literature entry needs source, reference and role")
        deps[cid] = list(a.get("depends_on") or [])
        for d in deps[cid]:
            if d not in known:
                errors.append(f"{cid}: depends_on unknown {d}")
            if d == cid:
                errors.append(f"{cid}: depends on itself")
        if check_paths:
            for path in (reg.get("code") or []) + (reg.get("tests") or []):
                if not (ROOT / path).exists():
                    errors.append(f"{cid}: missing {path}")
    for cyc in _cycles(deps):
        errors.append("dependency cycle: " + " -> ".join(cyc))

    for g in data.get("gates") or []:
        if g.get("status") not in GATE_STATUS:
            errors.append(f"gate {g.get('id')}: status {g.get('status')!r} unknown")
    order = [r.get("step") for r in data.get("repair_order") or []]
    if order != list(range(1, len(order) + 1)):
        errors.append("repair_order must be numbered 1..n in order")
    for r in data.get("repair_order") or []:
        for cid in r.get("capabilities") or []:
            if cid not in known:
                errors.append(f"repair_order {r.get('no')}: unknown {cid}")
    return errors


def _page_data(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for c in data["capabilities"]:
        reg, a = c["register_at_source"], c["assessment"]
        rows.append({
            "id": c["id"], "registerName": reg["name"], "status": reg["status"],
            "code": reg.get("code") or [], "tests": reg.get("tests") or [],
            "artifacts": reg.get("artifacts") or [], "docs": reg.get("docs") or [],
            "nr": [str(n) for n in reg.get("negative_results") or []],
            "ladder": reg.get("release_profile_requirements") or [],
            "name": a["name"], "cls": a["class"], "purpose": a["purpose"],
            "does": a["does"], "now": a["now"], "necessity": a["necessity"],
            "necessityRationale": a["necessity_rationale"], "hook": a["sdd_hook"],
            "mode": a["sdd_mode"], "sdd": a["sdd_change"],
            "target": a["reachable_rung"], "targetText": a["reachable_rung_text"],
            "risk": {"p": a["risk"]["likelihood"], "c": a["risk"]["consequence"],
                     "text": a["risk"]["text"]},
            "rev": {"grade": a["reversibility"]["grade"], "text": a["reversibility"]["text"]},
            "security": a["security"],
            "lit": [[x["source"], x["reference"], x["role"]] for x in a.get("literature") or []],
            "deps": a.get("depends_on") or [],
        })
    return rows


def _mermaid(rows: list[dict[str, Any]]) -> str:
    used = {r["id"] for r in rows if r["deps"]} | {d for r in rows for d in r["deps"]}
    node = {r["id"]: r["id"].replace("-", "_") for r in rows}
    lines = ["flowchart LR"]
    lines += [f'  {node[r["id"]]}["{r["id"]}<br/>{r["name"]}"]' for r in rows if r["id"] in used]
    lines += [f"  {node[d]} --> {node[r['id']]}" for r in rows for d in r["deps"]]
    return "\n".join(lines).replace("<", "&lt;").replace(">", "&gt;")


def render(data: dict[str, Any], *, fragment: bool = False) -> str:
    rows = _page_data(data)
    gates = [[g["id"], g["name"], g["mapping"], g["status"], g["status_text"], g["missing"]]
             for g in data.get("gates") or []]
    page = (TEMPLATE.read_text(encoding="utf-8")
            .replace("__DATA__", json.dumps(rows, ensure_ascii=False))
            .replace("__GATES__", json.dumps(gates, ensure_ascii=False))
            .replace("__REPAIR__", json.dumps(data.get("repair_order") or [], ensure_ascii=False))
            .replace("__MERMAID__", _mermaid(rows)))
    if fragment:
        return page
    return (
        "<!doctype html>\n<!-- Generated by scripts/generate_capability_atlas.py from "
        "docs/design/unified-capability-execution-v1.1-atlas.yaml. Do not edit by hand. -->\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">\n'
        "</head>\n<body>\n" + page + "\n</body>\n</html>\n"
    )


def drift(data: dict[str, Any]) -> list[str]:
    with open(REGISTER, encoding="utf-8") as f:
        live = {e["id"]: e for e in yaml.safe_load(f)["capabilities"]}
    pinned = {c["id"]: c["register_at_source"] for c in data["capabilities"]}
    notes = [f"{cid}: in the register, not in the atlas" for cid in sorted(set(live) - set(pinned))]
    notes += [f"{cid}: in the atlas, not in the register" for cid in sorted(set(pinned) - set(live))]
    for cid in sorted(set(live) & set(pinned)):
        for field in ("name", "status"):
            if live[cid].get(field) != pinned[cid].get(field):
                notes.append(f"{cid}: {field} {pinned[cid].get(field)!r} -> {live[cid].get(field)!r}")
    return notes


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--drift", action="store_true")
    ap.add_argument("--fragment", action="store_true",
                    help="page body without the document wrapper")
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args(argv)
    data = load()
    if args.drift:
        notes = drift(data)
        print("\n".join(notes) if notes else "no drift from the live capability register")
        return 0
    errors = validate(data)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    html = render(data, fragment=args.fragment)
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != html:
            print(f"{OUT.relative_to(ROOT)} is stale; run scripts/generate_capability_atlas.py",
                  file=sys.stderr)
            return 1
        print("capability atlas is current")
        return 0
    args.out.write_text(html, encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

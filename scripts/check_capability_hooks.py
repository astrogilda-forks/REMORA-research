#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Capability hook inventory: every registered capability names where it binds.

SDD unified capability execution v1.1 (docs/design/unified-capability-execution-v1.1.md
§3, §10 phase P1): each CAP entry has exactly one primary hook from a fixed
vocabulary, and "a capability has left the shelf when its hook is bound and
invoked on a real request". Until this inventory the hook lived only in the
atlas as the SDD's assessment, and nothing in the repository could fail when
a registered capability was bound to no hook, route or test.

Each capability in ``docs/assurance/capability_register_v1.yaml`` now carries::

    hook:
      primary: POLICY                 # one of HOOKS
      secondary: [ASSURANCE]          # optional, each one of HOOKS
      bound_at:                       # at least one, each verifiable here
        - remora/policy/decision_engine.py::RemoraDecisionEngine
        - servers/api.py::POST /v1/assess
        - tests/meta/test_register_evidences.py

A ``bound_at`` reference is a path, ``path::Symbol`` (a class or function,
``Class.method`` allowed), or ``path::METHOD /route``. The path must exist
and must be one of the entry's own ``evidence`` paths, so the freshness gate
(scripts/check_capability_freshness.py) that ages the entry also covers every
binding it names. A symbol must be defined in the file; a route must appear
in it as a string literal (with or without the ``/v1/execution`` router
prefix).

This is read-only visibility (P1's first slice). The hook is a repository
fact and lives in the register, as ADR-UE-03's default proposes; a
deployment's requested or effective *mode* is a deployment fact and is not
recorded here. ``--json`` prints the join P1 asks for: register entry, hook,
freshness classification and the atlas assessment (``sdd_hook``,
``reachable_rung``), with ``mode`` as the literal NOT_ESTABLISHED until a
capability activation manifest exists. The atlas ``sdd_hook`` is compared
with the register's primary hook and a difference is reported as drift.

Exit codes: 0 = every capability bound; 1 = a problem (listed on stderr).
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
REGISTER = ROOT / "docs" / "assurance" / "capability_register_v1.yaml"
ATLAS = ROOT / "docs" / "design" / "unified-capability-execution-v1.1-atlas.yaml"

#: SDD §3: the primary-hook vocabulary. Exactly these; the atlas may add
#: judgement words after the first token, the register may not.
HOOKS = ("ADMISSION", "AUTHORITY_INPUT", "POLICY", "PRE_DISPATCH", "EXECUTION",
         "EFFECT", "AUDIT", "ADVISORY", "FEDERATION", "OPS", "ASSURANCE")
#: Routers whose prefix a route reference may leave out of the file's literal.
ROUTER_PREFIXES = ("/v1/execution",)
_SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$")
_ROUTE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE) (/[^\s]*)$")


def load_register(path: Path = REGISTER) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_atlas(path: Path = ATLAS) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _defines(text: str, symbol: str) -> bool:
    parts = symbol.split(".")
    for part in parts:
        if not re.search(rf"^\s*(?:async\s+)?(?:def|class)\s+{re.escape(part)}\b", text, re.M):
            return False
    return True


def _mentions_route(text: str, route: str) -> bool:
    candidates = [route] + [route[len(p):] for p in ROUTER_PREFIXES
                            if route.startswith(p) and len(route) > len(p)]
    return any(f'"{c}"' in text or f"'{c}'" in text for c in candidates)


def reference_problem(ref: str, *, evidence: list[str], root: Path = ROOT) -> str | None:
    """Why ``ref`` is not a verifiable binding, or None when it is."""
    if not isinstance(ref, str) or not ref.strip():
        return "empty reference"
    path, _, target = ref.partition("::")
    if path not in evidence:
        return f"{path} is not one of the entry's evidence paths"
    file = root / path
    if not file.is_file():
        return f"{path} does not exist"
    if not target:
        return None
    text = file.read_text(encoding="utf-8", errors="replace")
    route = _ROUTE.match(target)
    if route is not None:
        return None if _mentions_route(text, route.group(2)) else f"{path} has no route {target}"
    if not _SYMBOL.match(target):
        return f"{target!r} is neither a symbol nor METHOD /route"
    return None if _defines(text, target) else f"{path} does not define {target}"


def entry_problems(cap: dict[str, Any], root: Path = ROOT) -> list[str]:
    """Every way ``cap`` fails the exit gate: no hook, a hook outside the
    vocabulary, or a binding that cannot be verified."""
    cid = str(cap.get("id", "?"))
    hook = cap.get("hook")
    if not isinstance(hook, dict):
        return [f"{cid}: no hook block"]
    out: list[str] = []
    primary = hook.get("primary")
    if primary not in HOOKS:
        out.append(f"{cid}: primary hook {primary!r} is not one of {', '.join(HOOKS)}")
    secondary = hook.get("secondary", [])
    if not isinstance(secondary, list) or any(s not in HOOKS for s in secondary):
        out.append(f"{cid}: secondary hooks must each be one of {', '.join(HOOKS)}")
    elif primary in secondary:
        out.append(f"{cid}: the primary hook is repeated as secondary")
    unknown = set(hook) - {"primary", "secondary", "bound_at"}
    if unknown:
        out.append(f"{cid}: unknown hook keys {sorted(unknown)}")
    bound = hook.get("bound_at")
    if not isinstance(bound, list) or not bound:
        out.append(f"{cid}: bound_at must name at least one code path, symbol, route or test")
        return out
    evidence = [str(e) for e in cap.get("evidence", [])]
    for ref in bound:
        problem = reference_problem(ref, evidence=evidence, root=root)
        if problem:
            out.append(f"{cid}: bound_at {ref!r}: {problem}")
    return out


def atlas_hooks(atlas: dict[str, Any]) -> dict[str, str]:
    """The atlas's first hook word per capability (its judgement, not a binding)."""
    out: dict[str, str] = {}
    for cap in atlas.get("capabilities", []):
        text = str(cap.get("assessment", {}).get("sdd_hook", "")).strip()
        out[str(cap["id"])] = text.split("/")[0].strip() if text else ""
    return out


def drift(register: dict[str, Any], atlas: dict[str, Any]) -> list[str]:
    """Capabilities whose atlas hook and register primary hook disagree."""
    judged = atlas_hooks(atlas)
    out: list[str] = []
    for cap in register["capabilities"]:
        cid = str(cap["id"])
        primary = (cap.get("hook") or {}).get("primary")
        if cid in judged and judged[cid] != primary:
            out.append(f"{cid}: atlas says {judged[cid] or '?'}, register says {primary}")
    for cid in sorted(set(judged) - {str(c["id"]) for c in register["capabilities"]}):
        out.append(f"{cid}: in the atlas, not in the register")
    return out


def catalogue(root: Path = ROOT) -> list[dict[str, Any]]:
    """The read-only join: register entry, hook, freshness and atlas assessment."""
    sys.path.insert(0, str(root))
    from scripts.check_capability_freshness import classify

    register = load_register(root / "docs" / "assurance" / "capability_register_v1.yaml")
    atlas = load_atlas(root / "docs" / "design" / "unified-capability-execution-v1.1-atlas.yaml")
    assessed = {str(c["id"]): c.get("assessment", {}) for c in atlas.get("capabilities", [])}
    rows = []
    for cap in register["capabilities"]:
        cid = str(cap["id"])
        freshness, detail = classify(cap, cwd=root)
        hook = cap.get("hook") or {}
        a = assessed.get(cid, {})
        rows.append({
            "id": cid, "name": cap["name"], "status": cap["status"],
            "verified_at_sha": cap.get("verified_at_sha", ""),
            "freshness": freshness, "freshness_detail": detail,
            "hook": {"primary": hook.get("primary"), "secondary": list(hook.get("secondary", [])),
                     "bound_at": list(hook.get("bound_at", []))},
            "atlas": {"sdd_hook": a.get("sdd_hook"), "sdd_mode": a.get("sdd_mode"),
                      "reachable_rung": a.get("reachable_rung")},
            # No capability activation manifest exists; nothing here may invent one.
            "mode": "NOT_ESTABLISHED",
            "evidence": list(cap.get("evidence", [])),
        })
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--json", action="store_true", help="print the catalogue join as JSON")
    args = parser.parse_args(argv)
    register, atlas = load_register(), load_atlas()
    problems = [p for cap in register["capabilities"] for p in entry_problems(cap)]
    problems += drift(register, atlas)
    if args.json:
        print(json.dumps(catalogue(), indent=2, ensure_ascii=False))
    else:
        for cap in register["capabilities"]:
            hook = cap.get("hook") or {}
            print(f"{cap['id']:<8} {cap['status']:<21} {str(hook.get('primary')):<16} "
                  f"{len(hook.get('bound_at') or [])} binding(s)")
    if problems:
        print("[FAIL] capability hook inventory:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(f"[PASS] capability hook inventory: {len(register['capabilities'])} capabilities, "
          "each with one primary hook and verifiable bindings; no drift from the atlas.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

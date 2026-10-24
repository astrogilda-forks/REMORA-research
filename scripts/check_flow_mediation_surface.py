#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Mediation completeness of the execution API (IFC-11, execution API slice).

Premise A1 of the derived information-flow control SDD
(docs/design/derived-information-flow-control-v1.md §1.2) says every effect
and every tool result reaches the model only through the governed
dispatcher, under the flow check. IFC-11 (§4) turns that into a property the
repository checks. This script is the execution-API half of that check.

Three things are held together:

1. **Classification.** Every route of ``servers.execution_api.router`` and
   ``contexts_router`` is in exactly one of ``MEDIATION_TOOL_DISPATCH`` or
   ``MEDIATION_NO_TOOL_RESULT`` (declared beside the routers). A route in
   neither set, or a classified route that no longer exists, is a failure. The
   worker entry points are listed in ``MEDIATION_WORKER_ENTRIES``.
2. **The governed funnel, statically.** Each TOOL_DISPATCH handler and each
   worker entry hands the call to ``_dispatch_under_lease`` (the name appears
   in its body, as a call or as the callback it passes to the service layer).
   No NO_TOOL_RESULT handler names it, names the implementation it wraps, or
   calls ``.dispatch`` on anything. ``_dispatch_under_lease`` itself names
   ``_flow_at_dispatch``, and ``dispatch_leased`` names ``flow_lease_unbound``.
   In ``remora/execution/service.py`` the ``dispatch_under_lease`` callback is
   called only from the three allowlisted service functions, and in
   ``remora/execution/dispatch.py`` ``dispatcher.dispatch(`` is called only
   from ``dispatch_under_lease``. A new call site anywhere in ``servers/`` or
   ``remora/execution/`` fails here.
3. **What is not covered.** ``OUT_OF_INVENTORY`` names the surfaces the SDD
   lists that this slice does not inventory. A1 is established, by this check,
   only for the routes above; the capability register records it as
   NOT_ESTABLISHED for the rest.

Exit codes: 0 = complete and consistent; 1 = a problem (listed on stderr).
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
API = Path("servers/execution_api.py")
SERVICE = Path("remora/execution/service.py")
DISPATCH = Path("remora/execution/dispatch.py")

#: The route wrapper around the implementation, the helper it delegates to
#: once the flow fence is held (IFC-06), and the implementation.
FUNNEL = "_dispatch_under_lease"
FUNNEL_HELD = "_dispatch_under_lease_fenced"
FUNNEL_IMPL = "_dispatch_under_lease_impl"
#: Service-layer functions that may call the ``dispatch_under_lease`` callback.
SERVICE_CALLERS = frozenset({"execute_approved_item", "dispatch_pending_intent",
                             "redeem_accept_token"})
#: The one function that may call ``dispatcher.dispatch(``.
DISPATCHER_CALLER = frozenset({"dispatch_under_lease"})
#: Surfaces the SDD names for IFC-11 that this slice does not inventory.
OUT_OF_INVENTORY = (
    "servers/api.py (the assess surface; no tool runs there, not checked here)",
    "servers/mcp_remora.py tools/call HANDLERS (MCP server in this repository)",
    "workers/mcp-gateway (TypeScript gateway)",
    "remora/sdk (a client of the routes above; not a surface of its own)",
    "an MCP server registered outside REMORA (deployment, not repository)",
)


def _module():
    """The execution API of THIS checkout, ahead of any installed copy."""
    os.environ.setdefault("REMORA_ENV", "development")
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    import servers.execution_api as ex

    return ex


def routes(ex: Any | None = None) -> dict[tuple[str, str], str]:
    """``{(METHOD, path): handler name}`` for both routers of the execution API."""
    from fastapi.routing import APIRoute

    ex = ex or _module()
    out: dict[tuple[str, str], str] = {}
    for router in (ex.router, ex.contexts_router):
        for route in router.routes:
            if isinstance(route, APIRoute):
                for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                    out[(method, route.path)] = route.endpoint.__name__
    return out


def classification_problems(found: dict[tuple[str, str], str],
                            tool_dispatch: frozenset, no_tool_result: frozenset) -> list[str]:
    out = []
    for key in sorted(tool_dispatch & no_tool_result):
        out.append(f"{key[0]} {key[1]}: in both classes")
    for key in sorted(set(found) - tool_dispatch - no_tool_result):
        out.append(f"{key[0]} {key[1]}: served and classified in neither set "
                   f"(handler {found[key]})")
    for key in sorted((tool_dispatch | no_tool_result) - set(found)):
        out.append(f"{key[0]} {key[1]}: classified but not served")
    return out


def _functions(tree: ast.AST) -> dict[str, ast.AST]:
    return {node.name: node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _attr_calls(node: ast.AST, attr: str) -> list[ast.Call]:
    return [n for n in ast.walk(node)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == attr]


def _calls_to(node: ast.AST, name: str) -> list[ast.Call]:
    return [n for n in ast.walk(node)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == name]


def _enclosing(tree: ast.Module, target: ast.AST) -> str:
    """The name of the innermost function containing ``target``, or '<module>'."""
    best = "<module>"
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(node):
                if child is target:
                    best = node.name
    return best


def static_problems(api_source: str, service_source: str, dispatch_source: str,
                    found: dict[tuple[str, str], str],
                    tool_dispatch: frozenset, no_tool_result: frozenset,
                    worker_entries: frozenset) -> list[str]:
    """Hold the handlers and the service layer to the governed funnel."""
    out: list[str] = []
    api = ast.parse(api_source)
    functions = _functions(api)
    handlers = {name: functions.get(name) for name in set(found.values()) | set(worker_entries)}
    for key in sorted(tool_dispatch):
        name = found.get(key)
        node = handlers.get(name) if name else None
        if node is None:
            continue  # reported by the classification
        if FUNNEL not in _names(node):
            out.append(f"{key[0]} {key[1]} ({name}) does not hand the call to {FUNNEL}")
    for name in sorted(worker_entries):
        node = functions.get(name)
        if node is None:
            out.append(f"worker entry {name} is not defined in {API.as_posix()}")
        elif FUNNEL not in _names(node):
            out.append(f"worker entry {name} does not hand the call to {FUNNEL}")
    for key in sorted(no_tool_result):
        name = found.get(key)
        node = functions.get(name) if name else None
        if node is None:
            continue
        names = _names(node)
        for forbidden in (FUNNEL, FUNNEL_HELD, FUNNEL_IMPL, *sorted(worker_entries)):
            if forbidden in names:
                out.append(f"{key[0]} {key[1]} ({name}) reaches {forbidden} but returns no tool result")
        if _attr_calls(node, "dispatch"):
            out.append(f"{key[0]} {key[1]} ({name}) calls .dispatch()")
    funnel = functions.get(FUNNEL)
    if funnel is None:
        out.append(f"{FUNNEL} is not defined in {API.as_posix()}")
    else:
        if "_flow_at_dispatch" not in _names(funnel):
            out.append(f"{FUNNEL} does not run _flow_at_dispatch")
        held = functions.get(FUNNEL_HELD)
        # The wrapper reaches the implementation directly, or through the one
        # helper that runs inside its fence release; nothing else may.
        reaches = FUNNEL_IMPL in _names(funnel) or (
            held is not None and FUNNEL_HELD in _names(funnel) and FUNNEL_IMPL in _names(held))
        if not reaches:
            out.append(f"{FUNNEL} does not reach {FUNNEL_IMPL}")
    for node in functions.values():
        if node.name in (FUNNEL, FUNNEL_HELD):
            continue
        for target in (FUNNEL_IMPL, FUNNEL_HELD):
            if target in _names(node):
                out.append(f"{node.name} reaches {target} around the route wrapper")
    leased = functions.get("dispatch_leased")
    if leased is not None and not any(
            isinstance(n, ast.Constant) and n.value == "flow_lease_unbound" for n in ast.walk(leased)):
        out.append("dispatch_leased does not refuse a lease without a flow decision (flow_lease_unbound)")
    service = ast.parse(service_source)
    for call in _calls_to(service, "dispatch_under_lease"):
        where = _enclosing(service, call)
        if where not in SERVICE_CALLERS:
            out.append(f"{SERVICE.as_posix()}: dispatch_under_lease called from {where}, "
                       f"not one of {sorted(SERVICE_CALLERS)}")
    dispatch = ast.parse(dispatch_source)
    for call in _attr_calls(dispatch, "dispatch"):
        receiver = call.func.value  # type: ignore[union-attr]
        if isinstance(receiver, ast.Name) and receiver.id == "dispatcher":
            where = _enclosing(dispatch, call)
            if where not in DISPATCHER_CALLER:
                out.append(f"{DISPATCH.as_posix()}: dispatcher.dispatch called from {where}, "
                           f"not one of {sorted(DISPATCHER_CALLER)}")
    return out


def problems(root: Path = ROOT) -> list[str]:
    ex = _module()
    found = routes(ex)
    out = classification_problems(found, ex.MEDIATION_TOOL_DISPATCH, ex.MEDIATION_NO_TOOL_RESULT)
    out += static_problems(
        (root / API).read_text(encoding="utf-8"), (root / SERVICE).read_text(encoding="utf-8"),
        (root / DISPATCH).read_text(encoding="utf-8"), found,
        ex.MEDIATION_TOOL_DISPATCH, ex.MEDIATION_NO_TOOL_RESULT, ex.MEDIATION_WORKER_ENTRIES)
    return out


def inventory(root: Path = ROOT) -> dict[str, Any]:
    ex = _module()
    found = routes(ex)
    return {
        "routes": [{"method": m, "path": p, "handler": h,
                    "class": ("TOOL_DISPATCH" if (m, p) in ex.MEDIATION_TOOL_DISPATCH
                              else "NO_TOOL_RESULT" if (m, p) in ex.MEDIATION_NO_TOOL_RESULT
                              else "UNCLASSIFIED")}
                   for (m, p), h in sorted(found.items(), key=lambda kv: (kv[0][1], kv[0][0]))],
        "worker_entries": sorted(ex.MEDIATION_WORKER_ENTRIES),
        "out_of_inventory": list(OUT_OF_INVENTORY),
        "problems": problems(root),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--json", action="store_true", help="print the inventory as JSON")
    args = parser.parse_args(argv)
    inv = inventory()
    if args.json:
        print(json.dumps(inv, indent=2))
    else:
        for row in inv["routes"]:
            print(f"{row['method']:<5} {row['path']:<58} {row['class']:<15} {row['handler']}")
        print("worker entries:", ", ".join(inv["worker_entries"]))
        print("not inventoried here:", "; ".join(inv["out_of_inventory"]))
    if inv["problems"]:
        print("[FAIL] flow mediation surface:", file=sys.stderr)
        for p in inv["problems"]:
            print(f"  - {p}", file=sys.stderr)
        return 1
    dispatching = sum(1 for r in inv["routes"] if r["class"] == "TOOL_DISPATCH")
    print(f"[PASS] flow mediation surface: {len(inv['routes'])} routes classified, "
          f"{dispatching} dispatch through {FUNNEL}, {len(inv['worker_entries'])} worker entry; "
          f"{len(OUT_OF_INVENTORY)} surfaces not inventoried here.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

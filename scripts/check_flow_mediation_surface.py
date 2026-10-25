#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Mediation completeness of the repository's tool surfaces (IFC-11).

Premise A1 of the derived information-flow control SDD
(docs/design/derived-information-flow-control-v1.md §1.2) says every effect
and every tool result reaches the model only through the governed
dispatcher, under the flow check. IFC-11 (§4) turns that into a property the
repository checks, over the five surfaces the SDD names: the execution API,
the assess API, the MCP server in this repository, the MCP gateway (with the
agent-control worker beside it) and the SDK.

For the execution API, three things are held together:

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
3. **The other surfaces.** ``servers/api.py`` decides and mounts the two
   routers; no function of it may name the funnel, the dispatcher or a service
   caller, or call ``.dispatch``. ``servers/mcp_remora.py`` serves
   ``tools/call`` from its ``HANDLERS`` table: the table and the advertised
   ``TOOLS`` must agree, every handler must be a module function, no handler
   (nor any module function it reaches) may name the dispatcher, and the one
   handler classified as forwarding to an execution surface
   (``MCP_FORWARDS_TO_EXECUTION``) must post to the agent-control worker. The
   SDK's two clients may name only paths the execution API serves, and their
   ``_EXECUTION_PATHS`` must be TOOL_DISPATCH routes. Every
   ``/v1/execution/...`` path in the two TypeScript workers must be a served
   route. None of these modules may import the execution API, the dispatcher
   or the execution service.
4. **What the property does not cover.** ``OUT_OF_PROPERTY`` names what the
   inventory reaches but the check cannot hold: the agent-control worker's
   own in-worker tools, the SDK's inability to name a flow context, an MCP
   server registered outside REMORA, and any running deployment. The
   capability register records A1 accordingly.

Exit codes: 0 = complete and consistent; 1 = a problem (listed on stderr).
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
API = Path("servers/execution_api.py")
SERVICE = Path("remora/execution/service.py")
DISPATCH = Path("remora/execution/dispatch.py")
#: The other surfaces the SDD names for IFC-11 (§4): the assess API, the MCP
#: server in this repository, the SDK and the two TypeScript workers.
ASSESS_API = Path("servers/api.py")
MCP_SERVER = Path("servers/mcp_remora.py")
SDK_SOURCES = (Path("remora/sdk/client.py"), Path("remora/sdk/async_client.py"))
WORKER_SOURCES = (Path("workers/mcp-gateway/src"), Path("workers/agent-control/src"))

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
#: Names that only the execution API may reach: the funnel, its helpers, the
#: dispatcher class and the service functions that call back into it.
DISPATCH_NAMES = frozenset({FUNNEL, FUNNEL_HELD, FUNNEL_IMPL, "GovernedToolDispatcher",
                            "dispatch_under_lease", *SERVICE_CALLERS})
#: Modules the MCP server and the SDK may not import: the dispatcher and the
#: execution service live there. ``remora.enforcement.token`` (the PEP token
#: the assess API verifies) is not among them.
EXECUTION_MODULES = ("servers.execution_api", "remora.enforcement.lease",
                     "remora.execution.dispatch", "remora.execution.service")
#: MCP server handlers that forward to an execution surface outside this
#: process (the agent-control worker). Every other handler is a local read or
#: a forward to a read-only worker, and runs no governed tool.
MCP_FORWARDS_TO_EXECUTION = frozenset({"agent_execute_tool"})
#: What the inventory reaches but the property does not cover, and what is
#: outside the repository. A1 is established, by this check, for the routes
#: and handlers above only.
OUT_OF_PROPERTY = (
    "workers/agent-control/src/index.ts runTool: the worker's own read tools "
    "(remora_verify_claim, dce_search_law) run in the worker, and so do its "
    "approval-gated tools when no EXECUTION_SERVICE is bound; their results reach "
    "the agent through servers/mcp_remora.py without a flow context",
    "remora/sdk: a client of the classified routes that cannot name a flow "
    "context, so under REMORA_FLOW_CONTROL=1 every SDK call is refused "
    "(flow_context_unknown) and nothing runs",
    "an MCP server registered outside REMORA (deployment, not repository)",
    "a running deployment: this check reads the repository, not a process",
)
#: Kept for callers of the first slice; the surfaces it listed are inventoried now.
OUT_OF_INVENTORY = OUT_OF_PROPERTY


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


def _functions(tree: ast.AST) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
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


def _imports(tree: ast.AST) -> set[str]:
    """Every module name imported anywhere in ``tree``, function bodies included."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
            out.update(f"{node.module}.{alias.name}" for alias in node.names)
    return out


def _forbidden_imports(tree: ast.AST, modules: tuple[str, ...] = EXECUTION_MODULES) -> list[str]:
    return sorted(name for name in _imports(tree)
                  if any(name == m or name.startswith(m + ".") for m in modules))


def assess_api_problems(source: str) -> list[str]:
    """``servers/api.py`` decides; no function of it may reach a tool callable.

    It mounts the execution API's routers and reads its registry and engine,
    so importing ``servers.execution_api`` is expected; the dispatcher and the
    execution service are not.
    """
    out: list[str] = []
    tree = ast.parse(source)
    allowed = tuple(m for m in EXECUTION_MODULES if m != "servers.execution_api")
    for name in _forbidden_imports(tree, allowed):
        out.append(f"{ASSESS_API.as_posix()}: imports {name}")
    for node in _functions(tree).values():
        for forbidden in sorted(DISPATCH_NAMES & _names(node)):
            out.append(f"{ASSESS_API.as_posix()}: {node.name} reaches {forbidden}")
        if _attr_calls(node, "dispatch"):
            out.append(f"{ASSESS_API.as_posix()}: {node.name} calls .dispatch()")
    return out


def _dict_literal(tree: ast.Module, name: str) -> ast.Dict | None:
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict) and any(
                isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return node.value
    return None


def _advertised_tools(tree: ast.Module) -> set[str]:
    """The ``name`` of every entry of the module-level ``TOOLS`` list."""
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.List) and any(
                isinstance(t, ast.Name) and t.id == "TOOLS" for t in node.targets):
            names: set[str] = set()
            for entry in node.value.elts:
                if isinstance(entry, ast.Dict):
                    for key, value in zip(entry.keys, entry.values, strict=True):
                        if (isinstance(key, ast.Constant) and key.value == "name"
                                and isinstance(value, ast.Constant)):
                            names.add(str(value.value))
            return names
    return set()


def _reachable(functions: Mapping[str, ast.AST], start: str) -> set[str]:
    """``start`` and every module function it names, transitively."""
    seen: set[str] = set()
    todo = [start]
    while todo:
        name = todo.pop()
        if name in seen or name not in functions:
            continue
        seen.add(name)
        todo.extend(n for n in _names(functions[name]) if n in functions)
    return seen


def mcp_problems(source: str, forwards: frozenset = MCP_FORWARDS_TO_EXECUTION) -> list[str]:
    """``servers/mcp_remora.py`` runs no governed tool: every ``tools/call``
    handler is a local read, a forward to a read-only worker, or the one
    forward to the agent-control worker; none reaches the dispatcher."""
    out: list[str] = []
    tree = ast.parse(source)
    where = MCP_SERVER.as_posix()
    for name in _forbidden_imports(tree):
        out.append(f"{where}: imports {name}")
    functions = _functions(tree)
    handlers = _dict_literal(tree, "HANDLERS")
    if handlers is None:
        return out + [f"{where}: no module-level HANDLERS dict"]
    table: dict[str, str] = {}
    for key, value in zip(handlers.keys, handlers.values, strict=True):
        if not (isinstance(key, ast.Constant) and isinstance(value, ast.Name)):
            out.append(f"{where}: HANDLERS has an entry that is not a literal name to a function")
            continue
        table[str(key.value)] = value.id
    advertised = _advertised_tools(tree)
    for tool in sorted(advertised ^ set(table)):
        out.append(f"{where}: {tool} is in TOOLS or HANDLERS but not both")
    for tool in sorted(forwards - set(table)):
        out.append(f"{where}: {tool} is classified as forwarding but not served")
    for tool, fn in sorted(table.items()):
        if fn not in functions:
            out.append(f"{where}: HANDLERS[{tool!r}] names {fn}, which is not defined")
            continue
        reached = _reachable(functions, fn)
        for forbidden in sorted(DISPATCH_NAMES & set().union(
                *(_names(functions[n]) for n in reached))):
            out.append(f"{where}: {tool} ({fn}) reaches {forbidden}")
        if any(_attr_calls(functions[n], "dispatch") for n in reached):
            out.append(f"{where}: {tool} ({fn}) calls .dispatch()")
        if tool in forwards and "_agent_post" not in set().union(
                *(_names(functions[n]) for n in reached)):
            out.append(f"{where}: {tool} is classified as forwarding but never posts to "
                       f"the agent-control worker")
    request = functions.get("handle_request")
    if request is None or "HANDLERS" not in _names(request):
        out.append(f"{where}: handle_request does not look tools/call up in HANDLERS")
    return out


def _route_pattern(path: str) -> re.Pattern[str]:
    return re.compile("^" + re.sub(r"\\\{[^}]*\\\}", r"[^/]+", re.escape(path)) + "$")


def _served(path: str, found: dict[tuple[str, str], str]) -> bool:
    return any(_route_pattern(p).match(path) for _m, p in found)


def _python_paths(tree: ast.AST) -> set[str]:
    """Every ``/v1/...`` path literal, with a formatted value written ``{param}``."""
    out: set[str] = set()
    # A formatted string's own pieces are Constant nodes too; they are read
    # with their template, not as paths of their own.
    pieces = {id(v) for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)
              for v in node.values}
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and node.value.startswith("/v1/") and id(node) not in pieces:
            out.add(node.value)
        elif isinstance(node, ast.JoinedStr) and node.values and isinstance(
                node.values[0], ast.Constant) and str(node.values[0].value).startswith("/v1/"):
            out.add("".join(str(v.value) if isinstance(v, ast.Constant) else "{param}"
                            for v in node.values))
    return out


def sdk_problems(sources: dict[str, str], found: dict[tuple[str, str], str],
                 tool_dispatch: frozenset) -> list[str]:
    """The SDK is a client of the classified routes and runs nothing itself."""
    out: list[str] = []
    dispatch_paths = {p for _m, p in tool_dispatch}
    for where, source in sorted(sources.items()):
        tree = ast.parse(source)
        for name in _forbidden_imports(tree):
            out.append(f"{where}: imports {name}")
        for path in sorted(_python_paths(tree)):
            if not _served(path, found):
                out.append(f"{where}: calls {path}, which the execution API does not serve")
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "_EXECUTION_PATHS" for t in node.targets):
                for const in ast.walk(node.value):
                    if isinstance(const, ast.Constant) and isinstance(const.value, str) \
                            and const.value not in dispatch_paths:
                        out.append(f"{where}: _EXECUTION_PATHS names {const.value}, "
                                   f"which is not a TOOL_DISPATCH route")
        for node in _functions(tree).values():
            if _attr_calls(node, "dispatch"):
                out.append(f"{where}: {node.name} calls .dispatch()")
    return out


_TS_PATH = re.compile(r"/v1/execution(?:/(?:[A-Za-z0-9_.-]+|\$?\{[^}]*\}))+")


def worker_paths(sources: dict[str, str]) -> dict[str, list[str]]:
    """``{file: [path]}`` for every execution API path a worker source names;
    a template expression (or a ``{placeholder}`` in a comment) is written
    ``{param}``."""
    out: dict[str, list[str]] = {}
    for where, text in sorted(sources.items()):
        paths = sorted({re.sub(r"\$?\{[^}]*\}", "{param}", m.group(0))
                        for m in _TS_PATH.finditer(text)})
        if paths:
            out[where] = paths
    return out


def worker_problems(sources: dict[str, str], found: dict[tuple[str, str], str]) -> list[str]:
    """Every execution API path the TypeScript workers name is a served route."""
    return [f"{where}: names {path}, which the execution API does not serve"
            for where, paths in worker_paths(sources).items()
            for path in paths if not _served(path, found)]


def _worker_sources(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): p.read_text(encoding="utf-8")
            for d in WORKER_SOURCES for p in sorted((root / d).glob("*.ts"))}


def problems(root: Path = ROOT) -> list[str]:
    ex = _module()
    found = routes(ex)
    out = classification_problems(found, ex.MEDIATION_TOOL_DISPATCH, ex.MEDIATION_NO_TOOL_RESULT)
    out += static_problems(
        (root / API).read_text(encoding="utf-8"), (root / SERVICE).read_text(encoding="utf-8"),
        (root / DISPATCH).read_text(encoding="utf-8"), found,
        ex.MEDIATION_TOOL_DISPATCH, ex.MEDIATION_NO_TOOL_RESULT, ex.MEDIATION_WORKER_ENTRIES)
    out += assess_api_problems((root / ASSESS_API).read_text(encoding="utf-8"))
    out += mcp_problems((root / MCP_SERVER).read_text(encoding="utf-8"))
    out += sdk_problems({p.as_posix(): (root / p).read_text(encoding="utf-8") for p in SDK_SOURCES},
                        found, ex.MEDIATION_TOOL_DISPATCH)
    out += worker_problems(_worker_sources(root), found)
    return out


def inventory(root: Path = ROOT) -> dict[str, Any]:
    ex = _module()
    found = routes(ex)
    mcp = ast.parse((root / MCP_SERVER).read_text(encoding="utf-8"))
    handlers = _dict_literal(mcp, "HANDLERS")
    mcp_tools = sorted(str(k.value) for k in (handlers.keys if handlers else [])
                       if isinstance(k, ast.Constant))
    sdk_paths = sorted(set().union(*(
        _python_paths(ast.parse((root / p).read_text(encoding="utf-8"))) for p in SDK_SOURCES)))
    return {
        "routes": [{"method": m, "path": p, "handler": h,
                    "class": ("TOOL_DISPATCH" if (m, p) in ex.MEDIATION_TOOL_DISPATCH
                              else "NO_TOOL_RESULT" if (m, p) in ex.MEDIATION_NO_TOOL_RESULT
                              else "UNCLASSIFIED")}
                   for (m, p), h in sorted(found.items(), key=lambda kv: (kv[0][1], kv[0][0]))],
        "worker_entries": sorted(ex.MEDIATION_WORKER_ENTRIES),
        "surfaces": {
            ASSESS_API.as_posix(): {"tool_paths": 0, "note": "decides; mounts the two routers"},
            MCP_SERVER.as_posix(): {
                "handlers": mcp_tools,
                "forwards_to_execution": sorted(MCP_FORWARDS_TO_EXECUTION & set(mcp_tools)),
                "runs_tools_locally": False},
            "remora/sdk": {"paths": sdk_paths, "runs_tools_locally": False},
            "workers": worker_paths(_worker_sources(root)),
        },
        "out_of_property": list(OUT_OF_PROPERTY),
        "out_of_inventory": list(OUT_OF_PROPERTY),
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
        surfaces = inv["surfaces"]
        print(f"{MCP_SERVER.as_posix()}: {len(surfaces[MCP_SERVER.as_posix()]['handlers'])} "
              f"handlers, forwards to execution: "
              f"{', '.join(surfaces[MCP_SERVER.as_posix()]['forwards_to_execution'])}")
        print("remora/sdk paths:", ", ".join(surfaces["remora/sdk"]["paths"]))
        for where, paths in surfaces["workers"].items():
            print(f"{where}: {', '.join(paths)}")
        print("outside the property:", "; ".join(inv["out_of_property"]))
    if inv["problems"]:
        print("[FAIL] flow mediation surface:", file=sys.stderr)
        for p in inv["problems"]:
            print(f"  - {p}", file=sys.stderr)
        return 1
    dispatching = sum(1 for r in inv["routes"] if r["class"] == "TOOL_DISPATCH")
    print(f"[PASS] flow mediation surface: {len(inv['routes'])} routes classified, "
          f"{dispatching} dispatch through {FUNNEL}, {len(inv['worker_entries'])} worker entry; "
          f"{len(inv['surfaces'])} further surfaces inventoried, "
          f"{len(OUT_OF_PROPERTY)} items outside the property.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

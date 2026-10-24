# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Mediation completeness of the execution API (IFC-11, execution API slice).

Premise A1 of the flow SDD: a tool runs, and a tool result returns, only
through the governed dispatcher under the flow check. Here that is held as a
property of the routes: every route of the execution API is classified
(``MEDIATION_TOOL_DISPATCH`` or ``MEDIATION_NO_TOOL_RESULT``), the dispatching
ones hand the call to ``_dispatch_under_lease`` and nothing else reaches the
dispatcher, and a route added to neither set fails here. The bypass probes
present forged, foreign and replayed contexts to the dispatching routes with
flow control on; each is refused before a tool runs and before a nonce or a
grant is spent. What this slice does not inventory is listed by the checker.
"""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

import scripts.check_flow_mediation_surface as surface  # noqa: E402
from tests.flow.test_flow_dispatch_leased import (  # noqa: E402,F401
    MODEL,
    USER,
    _call,
    _context,
    _lease,
    executor,
)
from tests.test_dispatch_leased_endpoint import _post  # noqa: E402
from tests.test_dispatch_leased_endpoint import executor as _executor  # noqa: E402,F401


def _ex():
    import servers.execution_api as ex

    return ex


# ── the inventory and the static funnel ────────────────────────────────────


def test_every_execution_route_is_classified_and_funnels_through_the_governed_path(capsys):
    assert surface.main([]) == 0
    assert "[PASS]" in capsys.readouterr().out


def test_the_three_dispatching_routes_and_the_worker_are_the_whole_dispatch_surface():
    ex = _ex()
    found = surface.routes(ex)
    assert {k for k in found if k in ex.MEDIATION_TOOL_DISPATCH} == {
        ("POST", "/v1/execution/execute"), ("POST", "/v1/execution/execute-accepted"),
        ("POST", "/v1/execution/dispatch-leased")}
    assert ex.MEDIATION_WORKER_ENTRIES == {"dispatch_pending_intents"}
    assert len(found) == len(ex.MEDIATION_TOOL_DISPATCH) + len(ex.MEDIATION_NO_TOOL_RESULT)


def test_a_route_added_to_neither_set_is_reported():
    ex = _ex()

    def probe() -> dict:  # pragma: no cover - never called
        return {}

    ex.router.add_api_route("/probe", probe, methods=["POST"])  # the router adds its prefix
    try:
        problems = surface.classification_problems(
            surface.routes(ex), ex.MEDIATION_TOOL_DISPATCH, ex.MEDIATION_NO_TOOL_RESULT)
    finally:
        ex.router.routes[:] = [r for r in ex.router.routes
                               if getattr(r, "path", "") != "/v1/execution/probe"]
    assert problems == ["POST /v1/execution/probe: served and classified in neither set (handler probe)"]
    assert surface.classification_problems(
        surface.routes(ex), ex.MEDIATION_TOOL_DISPATCH, ex.MEDIATION_NO_TOOL_RESULT) == []


def test_a_classified_route_that_is_no_longer_served_is_reported():
    ex = _ex()
    gone = frozenset({("DELETE", "/v1/execution/gone")})
    problems = surface.classification_problems(
        surface.routes(ex), ex.MEDIATION_TOOL_DISPATCH, ex.MEDIATION_NO_TOOL_RESULT | gone)
    assert problems == ["DELETE /v1/execution/gone: classified but not served"]


SERVICE_OK = "def execute_approved_item():\n    dispatch_under_lease()\n"
DISPATCH_OK = "def dispatch_under_lease(dispatcher):\n    dispatcher.dispatch()\n"
API_OK = (
    "def _dispatch_under_lease():\n    _flow_at_dispatch()\n    _dispatch_under_lease_impl()\n"
    "def execute():\n    service(dispatch_under_lease=_dispatch_under_lease)\n"
    "def dispatch_leased():\n    x = 'flow_lease_unbound'\n    _dispatch_under_lease()\n"
    "def dispatch_pending_intents():\n    _dispatch_under_lease\n"
    "def assess():\n    return {}\n"
)
FOUND = {("POST", "/v1/execution/execute"): "execute",
         ("POST", "/v1/execution/dispatch-leased"): "dispatch_leased",
         ("POST", "/v1/execution/assess"): "assess"}
TD = frozenset({("POST", "/v1/execution/execute"), ("POST", "/v1/execution/dispatch-leased")})
NTR = frozenset({("POST", "/v1/execution/assess")})
WORKERS = frozenset({"dispatch_pending_intents"})


def _static(api=API_OK, service=SERVICE_OK, dispatch=DISPATCH_OK):
    return surface.static_problems(api, service, dispatch, FOUND, TD, NTR, WORKERS)


def test_the_synthetic_well_formed_api_passes_the_static_check():
    assert _static() == []


@pytest.mark.parametrize("api, fragment", [
    (API_OK.replace("def execute():\n    service(dispatch_under_lease=_dispatch_under_lease)\n",
                    "def execute():\n    return run_tool()\n"),
     "does not hand the call to _dispatch_under_lease"),
    (API_OK.replace("def assess():\n    return {}\n",
                    "def assess():\n    return _dispatch_under_lease()\n"),
     "reaches _dispatch_under_lease but returns no tool result"),
    (API_OK.replace("def assess():\n    return {}\n",
                    "def assess():\n    return _tool_dispatcher().dispatch(None)\n"),
     "calls .dispatch()"),
    (API_OK.replace("def assess():\n    return {}\n",
                    "def assess():\n    return _dispatch_under_lease_impl()\n"),
     "reaches _dispatch_under_lease_impl"),
    (API_OK.replace("    _flow_at_dispatch()\n", ""), "does not run _flow_at_dispatch"),
    (API_OK.replace("    x = 'flow_lease_unbound'\n", ""), "flow_lease_unbound"),
    (API_OK.replace("def dispatch_pending_intents():\n    _dispatch_under_lease\n",
                    "def dispatch_pending_intents():\n    pass\n"),
     "worker entry dispatch_pending_intents does not hand the call"),
])
def test_a_handler_that_leaves_the_governed_path_is_reported(api, fragment):
    problems = _static(api=api)
    assert problems and any(fragment in p for p in problems), problems


def test_a_service_or_dispatch_call_site_outside_the_allowlist_is_reported():
    assert any("dispatch_under_lease called from sneak" in p for p in _static(
        service=SERVICE_OK + "def sneak():\n    dispatch_under_lease()\n"))
    assert any("dispatcher.dispatch called from sneak" in p for p in _static(
        dispatch=DISPATCH_OK + "def sneak(dispatcher):\n    dispatcher.dispatch()\n"))


def test_the_inventory_names_what_it_does_not_cover():
    inv = surface.inventory()
    assert inv["problems"] == []
    assert any("mcp_remora" in s for s in inv["out_of_inventory"])
    assert any("mcp-gateway" in s for s in inv["out_of_inventory"])
    assert {r["class"] for r in inv["routes"]} == {"TOOL_DISPATCH", "NO_TOOL_RESULT"}


# ── bypass probes on the execution domain, flow control on ─────────────────


def test_a_forged_context_is_refused_before_the_tool_and_spends_no_nonce(executor):  # noqa: F811
    """The lease was judged in context A; the call names a context nobody
    minted. The executor's own context lookup refuses, the tool does not run,
    and the same lease still runs for the call it was granted for."""
    context_id = _context(executor)
    call = _call(context_id)
    lease = _lease(executor, call)
    forged = dict(call, context_id="ctx_" + "f" * 26)
    body = _post(executor, lease, call=forged).json()
    assert body["tool_execution"]["executed"] is False
    assert body["tool_execution"]["refusal_reason"] in ("flow_context_unknown", "task_mismatch")
    assert executor.registry.CALLS == []
    assert _post(executor, lease, call=call).json()["tool_execution"]["executed"] is True


def test_another_principals_context_is_unknown_to_the_lease_actor(executor):  # noqa: F811
    """A context minted by another principal is not readable by the lease's
    actor; the executor sees an unknown context and refuses."""
    import servers.execution_api as ex

    foreign = ex._flow_contexts().mint("acme", "employee-2", user_principal=USER,
                                       model_principal=MODEL).context_id
    call = _call(foreign)
    body = _post(executor, _lease(executor, call, bound=False), call=call).json()
    assert body["tool_execution"]["executed"] is False
    assert body["tool_execution"]["refusal_reason"] in ("flow_context_unknown", "flow_lease_unbound")
    assert executor.registry.CALLS == []


def test_a_lease_from_one_context_does_not_run_in_another(executor):  # noqa: F811
    """Both contexts exist and the arguments are equal; the lease binds the
    task and the flow decision of the first, so the second is refused."""
    first, second = _context(executor), _context(executor)
    lease = _lease(executor, _call(first))
    body = _post(executor, lease, call=_call(second)).json()
    assert body["tool_execution"]["executed"] is False
    assert body["tool_execution"]["refusal_reason"] in (
        "task_mismatch", "flow_epoch_changed", "flow_digest_changed", "flow_context_unknown")
    assert executor.registry.CALLS == []

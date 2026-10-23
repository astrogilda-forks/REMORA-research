# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The OT pilot's own limits, tools and semantic bundle through the execution API.

``deploy/ot-pilot`` ships ``limits.json`` with coverage ``all_writes``. The
pilot has no signed ToolSpec bundle, so which tools write comes from its
semantic bundle. These tests load the pilot's registry, bundle, work orders
and limits as the container does and pin that the battery's own writes still
run, that small setpoint and valve moves cannot add up past the limit, and
that a write tool the limits forget is refused.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastapi")

from tests.test_toolspec_execution_wiring import _client  # noqa: E402

PILOT = Path(__file__).resolve().parents[2] / "deploy" / "ot-pilot"


@pytest.fixture()
def pilot(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(PILOT))
    import ot_registry

    saved = copy.deepcopy(ot_registry.PLANT)
    client = _client(monkeypatch, tmp_path)

    def configure(limits=None):
        import servers.api as api_mod
        import servers.execution_api as exec_mod

        monkeypatch.setattr(api_mod, "_authenticate", lambda request: ("ot-pilot", "reviewer"))
        path = tmp_path / "limits.json"
        path.write_text(json.dumps(limits) if limits is not None
                        else (PILOT / "limits.json").read_text(encoding="utf-8"))
        monkeypatch.setenv("REMORA_TOOL_REGISTRY_MODULE", "ot_registry")
        monkeypatch.setenv("REMORA_SEMANTIC_BUNDLE_MODULE", "ot_bundle")
        monkeypatch.setenv("REMORA_INTENT_SOURCE_FILE", str(PILOT / "work_orders.json"))
        monkeypatch.setenv("REMORA_LIMITS_FILE", str(path))
        monkeypatch.setenv("REMORA_LIMITS_LEDGER", str(tmp_path / "limits-ledger.db"))
        monkeypatch.setenv("REMORA_LIMITS_OBSERVER_MODULE", "ot_registry")
        exec_mod._reset_semantic_bundle()
        exec_mod._reset_tool_dispatcher()
        return client

    yield configure
    ot_registry.PLANT.clear()
    ot_registry.PLANT.update(saved)
    sys.modules.pop("ot_registry", None)
    sys.modules.pop("ot_bundle", None)


def payload(tool, intent_ref, **arguments):
    return {"tool_name": tool, "arguments": arguments, "target_environment": "prod",
            "intent_ref": intent_ref}


def run(client, p):
    r = client.post("/v1/execution/assess", json=p)
    if r.status_code != 200:
        return {"stage": "assess", "status": r.status_code, "detail": r.json()["detail"]}
    item = r.json().get("review_item_id")
    if item is None:
        return {"stage": "assess", "decision": r.json()["decision"]}
    client.post("/v1/execution/approve", json={"item_id": item, "approval_ttl_seconds": 900})
    e = client.post("/v1/execution/execute", json={"item_id": item, "tool_call": p}).json()
    execution = e.get("tool_execution") or {}
    return {"stage": "execute", "executed": execution.get("executed"),
            "refusal": execution.get("refusal_reason")}


def test_the_shipped_limits_file_loads_and_covers_every_pilot_write():
    from remora.enforcement.cumulative_limits import LimitPolicy

    policy = LimitPolicy.from_dict(json.loads((PILOT / "limits.json").read_text()))
    sys.path.insert(0, str(PILOT))
    try:
        import ot_bundle

        bundle = ot_bundle.build_semantic_bundle()
    finally:
        sys.path.remove(str(PILOT))
        sys.modules.pop("ot_bundle", None)
    writes = {name for name, c in bundle.contracts.contracts.items() if c.mutation}
    assert policy.coverage == "all_writes" and writes == set(policy.meters)


def test_the_battery_writes_still_run(pilot):
    client = pilot()
    import ot_registry

    assert run(client, payload("adjust_setpoint", "WO-1201", loop="PIC-101",
                               value=3.8))["executed"] is True
    assert run(client, payload("set_valve_position", "WO-1204", valve="V-12",
                               position_pct=35))["executed"] is True
    assert ot_registry.PLANT["loops"]["PIC-101"]["setpoint"] == 3.8


def test_small_setpoint_moves_cannot_add_up(pilot):
    client = pilot()
    # 0.50 bar of PIC-101 movement per hour: 4.00 -> 3.80 -> 4.00 -> 3.90 is 0.50.
    for value in (3.8, 4.0, 3.9):
        assert run(client, payload("adjust_setpoint", "WO-1201", loop="PIC-101",
                                   value=value))["executed"] is True
    assert run(client, payload("adjust_setpoint", "WO-1201", loop="PIC-101",
                               value=3.8)) == {"stage": "assess", "status": 409,
                                               "detail": "limit_exceeded"}


def test_valve_strokes_cannot_add_up(pilot):
    client = pilot()
    # 60 percent of travel per valve per hour: 15 -> 35 -> 15 -> 35 is 60.
    for position in (35, 15, 35):
        assert run(client, payload("set_valve_position", "WO-1204", valve="V-12",
                                   position_pct=position))["executed"] is True
    assert run(client, payload("set_valve_position", "WO-1204", valve="V-12",
                               position_pct=30))["detail"] == "limit_exceeded"


def test_a_write_tool_the_limits_forget_is_refused(pilot):
    limits = json.loads((PILOT / "limits.json").read_text())
    del limits["meters"]["acknowledge_alarm"]
    limits["limits"] = [lim for lim in limits["limits"] if lim["quantity"] != "alarm_acks"]
    client = pilot(limits)
    assert run(client, payload("acknowledge_alarm", "WO-1202",
                               alarm_id="LT-410-HI"))["detail"] == "limit_tool_unmetered"
    assert run(client, payload("read_sensor", "MON-ROUND", sensor_id="PT-101")) \
        .get("detail") != "limit_tool_unmetered"


def test_an_outside_change_at_the_plant_is_measured_not_assumed(pilot):
    client = pilot()
    import ot_registry

    ot_registry.PLANT["loops"]["PIC-101"]["setpoint"] = 3.5  # changed at the plant
    # 3.50 -> 4.00 is 0.50 of movement at the plant: the whole hour's limit.
    assert run(client, payload("adjust_setpoint", "WO-1201", loop="PIC-101",
                               value=4.0))["executed"] is True
    assert run(client, payload("adjust_setpoint", "WO-1201", loop="PIC-101",
                               value=4.1))["detail"] == "limit_exceeded"


def test_the_pilot_observer_reads_the_plant():
    sys.path.insert(0, str(PILOT))
    try:
        import ot_registry

        assert ot_registry.observe_limit_value("ot-pilot", "valve_travel", "V-18") == 40.0
        with pytest.raises(KeyError):
            ot_registry.observe_limit_value("ot-pilot", "alarm_acks", "LT-410-HI")
    finally:
        sys.path.remove(str(PILOT))
        sys.modules.pop("ot_registry", None)

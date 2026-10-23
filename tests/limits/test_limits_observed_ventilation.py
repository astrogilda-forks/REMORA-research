# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""End to end: cumulative setpoint limits against a simulated controller.

The calls run through ``/v1/execution/assess``, ``/approve``, ``/execute`` and
the governed dispatcher into ``tests/limits/ventilation_sim.py``, a controller
with its own state. The limit is 2.0 degC of supply-air movement per hour per
unit, shared by every agent.

A ``change`` meter that tracks only the values REMORA let through can be
wrong about the plant. The first test shows it: after an operator turns the
unit down outside REMORA, the tracked meter lets REMORA move the plant 4.0
degC inside a 2.0 limit. An ``observed`` meter reads the controller before
each change and after it, and holds the limit on the plant's own values:
outside changes, clamping, dropped writes and silent failures included.
"""
from __future__ import annotations

import json
import sqlite3

import pytest

pytest.importorskip("fastapi")

from remora.toolcall.callable_digest import source_digest  # noqa: E402
from tests.limits import ventilation_sim as sim  # noqa: E402
from tests.limits.harness import _tool, call  # noqa: E402
from tests.test_toolspec_execution_wiring import _bundle_file, _client  # noqa: E402

LIMIT = {"limit_id": "supply-air-movement", "tenant": "acme",
         "quantity": "setpoint_movement", "unit": "degC", "max": 20,
         "window_seconds": 3600, "principal": "*", "resource": "*"}


def policy(observed: bool, previous_field: str | None = None) -> dict:
    meter = {"quantity": "setpoint_movement", "kind": "change", "argument": "value",
             "scale": 10, "unit": "degC", "resource_argument": "unit"}
    if observed:
        meter["observed"] = True
    if previous_field:
        meter["previous_field"] = previous_field
    body = {"schema": "remora-cumulative-limits/v1", "limits": [LIMIT],
            "meters": {"set_supply_air_setpoint": [meter]}}
    if not observed:
        body["baselines"] = [{"tenant": "acme", "quantity": "setpoint_movement",
                              "resource": unit, "value": 19.0, "seed_id": "s1"}
                             for unit in ("AHU-1", "AHU-2")]
    return body


@pytest.fixture()
def plant(monkeypatch, tmp_path):
    import servers.execution_api as exec_mod

    sim.reset()

    def start(observed=True, observer=True, previous_field=None):
        (tmp_path / "limits.json").write_text(json.dumps(policy(observed, previous_field)))
        monkeypatch.setenv("REMORA_LIMITS_FILE", str(tmp_path / "limits.json"))
        monkeypatch.setenv("REMORA_LIMITS_LEDGER", str(tmp_path / "limits-ledger.db"))
        if observer:
            monkeypatch.setenv("REMORA_LIMITS_OBSERVER_MODULE", "tests.limits.ventilation_sim")
        else:
            monkeypatch.delenv("REMORA_LIMITS_OBSERVER_MODULE", raising=False)
        spec = _tool(sim.set_supply_air_setpoint, unit="string", value="number")
        assert spec["callable_digest"] == source_digest(sim.set_supply_air_setpoint)
        client = _client(monkeypatch, tmp_path,
                         bundle_path=_bundle_file(tmp_path, [spec], name="sim-bundle.json"))
        monkeypatch.setenv("REMORA_TOOL_REGISTRY_MODULE", "tests.limits.ventilation_sim")
        exec_mod._reset_tool_dispatcher()
        return client

    yield start
    sim.reset()


def move(client, value, unit="AHU-1"):
    """Assess, approve and execute one setpoint write; what the caller sees."""
    c = call("set_supply_air_setpoint", unit=unit, value=value)
    r = client.post("/v1/execution/assess", json=c)
    if r.status_code != 200:
        return r.json()["detail"]
    item = r.json()["review_item_id"]
    client.post("/v1/execution/approve", json={"item_id": item, "approval_ttl_seconds": 600})
    e = client.post("/v1/execution/execute", json={"item_id": item, "tool_call": c}).json()
    execution = e["tool_execution"]
    return "ran" if execution.get("dispatch_began") else execution.get("refusal_reason")



def test_a_tracked_meter_lets_remora_move_the_plant_past_the_limit(plant):
    """The gap this module closes: an outside change the tracked meter cannot see."""
    client = plant(observed=False, observer=False)
    sim.operator_set("AHU-1", 17.0)                 # an operator turns the unit down
    assert move(client, 19.0) == "ran"              # tracked 0.0; at the plant 2.0
    assert move(client, 21.0) == "ran"              # tracked 2.0; at the plant 2.0 more
    assert sim.UNITS["AHU-1"].setpoint == 21.0      # REMORA moved it 4.0 inside a 2.0 limit


def test_an_observed_meter_holds_the_limit_on_the_plants_values(plant):
    client = plant()
    sim.operator_set("AHU-1", 17.0)
    assert move(client, 19.0) == "ran"              # 2.0 measured from the plant
    assert move(client, 21.0) == "limit_exceeded"
    assert sim.UNITS["AHU-1"].setpoint == 19.0


def test_an_outside_change_is_not_charged_to_remora(plant):
    client = plant()
    sim.operator_set("AHU-1", 21.0)
    assert move(client, 21.5) == "ran"              # 0.5, not 2.5
    assert move(client, 23.0) == "ran"              # 1.5; 2.0 in all
    assert move(client, 23.5) == "limit_exceeded"


def _ledger_value(tmp_path, unit):
    conn = sqlite3.connect(tmp_path / "limits-ledger.db")
    try:
        row = conn.execute("SELECT value,status FROM limit_value WHERE value_key LIKE ?",
                           (f"%{unit}",)).fetchone()
    finally:
        conn.close()
    return row


def test_a_clamped_write_is_read_back_and_the_next_change_starts_there(plant, tmp_path):
    client = plant()
    sim.UNITS["AHU-1"].high = 20.0
    assert move(client, 20.5) == "ran"              # asked 20.5, the controller holds 20.0
    assert sim.UNITS["AHU-1"].setpoint == 20.0
    assert _ledger_value(tmp_path, "AHU-1") == (200, "settled")  # what was observed
    assert move(client, 19.5) == "ran"              # 0.5 from 20.0; 1.5 + 0.5 = 2.0
    assert move(client, 19.0) == "limit_exceeded"


def test_a_silently_ignored_write_is_read_back(plant, tmp_path):
    client = plant()
    sim.UNITS["AHU-1"].next_write = "ignore"
    assert move(client, 20.0) == "ran"              # acknowledged, not applied: 1.0 charged
    assert sim.UNITS["AHU-1"].setpoint == 19.0
    assert _ledger_value(tmp_path, "AHU-1") == (190, "settled")
    assert move(client, 20.0) == "ran"              # 1.0 from the plant's 19.0
    assert move(client, 20.5) == "limit_exceeded"


def test_a_dropped_write_needs_no_new_baseline(plant):
    """Tracked meters stay unknown after a failure; an observed one reads the plant."""
    client = plant()
    sim.UNITS["AHU-1"].next_write = "raise"
    assert move(client, 20.0) != "limit_baseline_unknown"
    assert sim.UNITS["AHU-1"].setpoint == 19.0
    assert move(client, 19.5) == "ran"              # 1.0 reserved for the failed write, 0.5 now


def test_without_a_reading_nothing_moves(plant):
    client = plant()
    sim.OBSERVER["up"] = False
    assert move(client, 19.5) == "limit_observation_unavailable"
    assert sim.WRITES == []


def test_without_a_reading_dispatch_refuses_too(plant, monkeypatch):
    import servers.execution_api as exec_mod

    client = plant()
    monkeypatch.setattr(exec_mod, "_limits_or_refuse", lambda *a: None)
    sim.OBSERVER["up"] = False
    assert move(client, 19.5) == "limit_observation_unavailable"
    assert sim.WRITES == []


def test_units_and_agents_share_the_limit_on_the_plant(plant, monkeypatch):
    client = plant()
    import servers.api as api_mod

    assert move(client, 20.0) == "ran"
    monkeypatch.setattr(api_mod, "_authenticated_principal", lambda request: "agent-2")
    assert move(client, 21.0) == "ran"
    assert move(client, 21.5) == "limit_exceeded"
    assert move(client, 21.0, unit="AHU-2") == "ran"   # another unit, its own total


def test_observed_meters_without_an_observer_refuse_at_startup(plant, monkeypatch, tmp_path):
    import servers.execution_api as exec_mod

    plant(observer=True)
    monkeypatch.delenv("REMORA_LIMITS_OBSERVER_MODULE")
    exec_mod._reset_tool_dispatcher()
    with pytest.raises(ValueError, match="need an observer"):
        exec_mod._limit_guard()
    monkeypatch.setenv("REMORA_LIMITS_OBSERVER_MODULE", "tests.limits.harness")
    exec_mod._reset_tool_dispatcher()
    with pytest.raises(ValueError, match="observe_limit_value"):
        exec_mod._limit_guard()


# ── the window between reading the plant and writing to it (TOCTOU) ───────


def _dispatch_only(monkeypatch):
    """Skip the advisory assess check, so the observations are, in order: the
    reservation's, the fence's just before the write, and the read-back."""
    import servers.execution_api as exec_mod

    monkeypatch.setattr(exec_mod, "_limits_or_refuse", lambda *a: None)


def test_a_change_between_reservation_and_write_stops_the_write(plant, monkeypatch):
    """REMORA reads 19.0, an operator sets 17.0, REMORA would write 19.5: 2.5
    of movement charged as 0.5. The fence reads the plant again before the
    write, sees it moved, and the write does not happen."""
    client = plant()
    _dispatch_only(monkeypatch)
    sim.AFTER_OBSERVE.append(lambda: sim.operator_set("AHU-1", 17.0))
    assert move(client, 19.5) == "limit_state_changed"
    assert sim.WRITES == [] and sim.UNITS["AHU-1"].setpoint == 17.0
    assert move(client, 19.0) == "ran"               # 2.0 from where the plant is now


def test_a_change_after_the_fence_is_charged_from_the_controllers_report(plant, monkeypatch,
                                                                          tmp_path):
    """The operator acts after the fence read, in the last window before the
    write. The controller reports the value it replaced (17.0), so the 2.5
    actually moved is charged, and the next change meets the limit."""
    client = plant(previous_field="previous")
    _dispatch_only(monkeypatch)
    sim.AFTER_OBSERVE.extend([lambda: None, lambda: sim.operator_set("AHU-1", 17.0)])
    assert move(client, 19.5) == "ran"
    conn = sqlite3.connect(tmp_path / "limits-ledger.db")
    try:
        charged = conn.execute("SELECT SUM(amount) FROM limit_reservation").fetchone()[0]
    finally:
        conn.close()
    assert charged == 25                            # 0.5 reserved + 2.0 after the fact
    assert move(client, 19.6) == "limit_exceeded"


def test_without_a_controller_report_the_last_window_is_not_seen(plant, monkeypatch, tmp_path):
    """The residual gap, pinned: with no previous value from the controller, a
    change in the last window before the write is charged as reserved. Only
    a conditional write at the controller closes this."""
    client = plant()
    _dispatch_only(monkeypatch)
    sim.AFTER_OBSERVE.extend([lambda: None, lambda: sim.operator_set("AHU-1", 17.0)])
    assert move(client, 19.5) == "ran"
    conn = sqlite3.connect(tmp_path / "limits-ledger.db")
    try:
        charged = conn.execute("SELECT SUM(amount) FROM limit_reservation").fetchone()[0]
    finally:
        conn.close()
    assert charged == 5

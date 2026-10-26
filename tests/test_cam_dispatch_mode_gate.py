# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The activation manifest's effective modes at the execution boundary (RMR-AUD-26-004).

Before this, a loaded manifest only reached the dispatcher as a digest: the
effective modes were computed and reported, and no decision, refusal or
dispatch read them, so a manifest that set the lease dispatch to SHADOW still
let every lease run. Pinned here:

* the mode contract: only ENFORCE authorizes an effect at dispatch;
* with a manifest loaded, the capabilities that authorize a dispatch must be
  effective ENFORCE, and a refusal spends nothing (the nonce stays usable);
* a manifest that is configured but did not load refuses every dispatch;
* without a manifest anywhere nothing changes.
"""
from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from remora.enforcement.lease import ExecutionLease, GovernedToolDispatcher
from remora.governance import capability_activation as ca
from remora.governance.activation_manifest import MODES, CapabilityManifest, LoadedManifest

ARGS = {"order": "WO-1"}
NON_AUTHORIZING = sorted((set(MODES) | {ca.BLOCKED}) - {"ENFORCE"})


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("REMORA_LEASE_SIGNING_KEY", "cam-mode-key")
    for name in ("REMORA_LEASE_SIGNING_KEY_ED25519_PRIVATE",
                 "REMORA_LEASE_VERIFY_KEY_ED25519_PUBLIC", "REMORA_RUNTIME_PROFILE",
                 "REMORA_CAM_FILE"):
        monkeypatch.delenv(name, raising=False)


def _report(modes: dict[str, str]) -> ca.ActivationReport:
    return ca.ActivationReport("c" * 64, True, tuple(
        ca.Activation(cid, mode, mode, ()) for cid, mode in sorted(modes.items())), (), ())


# ── the contract ───────────────────────────────────────────────────────────


def test_every_mode_has_a_stated_contract_and_only_enforce_authorizes():
    assert set(ca.MODE_CONTRACT) == set(MODES) | {ca.BLOCKED}
    assert ca.AUTHORIZING_MODES == frozenset({"ENFORCE"})
    for mode in NON_AUTHORIZING:
        assert "authorizes no effect" in ca.MODE_CONTRACT[mode], mode


def test_without_a_report_nothing_is_refused():
    assert ca.dispatch_mode_refusal(None, ca.DISPATCH_AUTHORITY) is None


def test_enforce_on_every_authorizing_capability_runs():
    report = _report({cid: "ENFORCE" for cid in ca.DISPATCH_AUTHORITY})
    assert ca.dispatch_mode_refusal(report, ca.DISPATCH_AUTHORITY) is None


@pytest.mark.parametrize("mode", NON_AUTHORIZING)
@pytest.mark.parametrize("capability_id", ca.DISPATCH_AUTHORITY)
def test_any_other_mode_on_an_authorizing_capability_refuses(capability_id, mode):
    modes = {cid: "ENFORCE" for cid in ca.DISPATCH_AUTHORITY} | {capability_id: mode}
    assert (ca.dispatch_mode_refusal(_report(modes), ca.DISPATCH_AUTHORITY)
            == f"capability_not_enforcing:{capability_id}:{mode}")


def test_a_capability_absent_from_the_report_counts_as_disabled():
    assert (ca.dispatch_mode_refusal(_report({"CAP-003": "ENFORCE"}), ca.DISPATCH_AUTHORITY)
            == "capability_not_enforcing:CAP-013:DISABLED")


def _entry(cid, requested="ENFORCE", allowed=("SHADOW", "ENFORCE"), premises=(),
           fail_mode="DENY_OR_HOLD"):
    return {"capability_id": cid, "component_version": "0.12.0",
            "implementation_ref": "remora/enforcement/lease.py", "requested_mode": requested,
            "allowed_modes": list(allowed), "required_premises": list(premises),
            "trust_source_ids": [], "api_contract": "", "sdk_surface": "", "health_probe": "",
            "fail_mode": fail_mode, "claim_ceiling": "test", "evidence_refs": [cid]}


def _computed(*entries, catalogue_status="WIRED_API_PATH", premises=None):
    catalogue = {cid: {"name": cid, "status": catalogue_status, "hook": "EXECUTION"}
                 for cid in ca.DISPATCH_AUTHORITY}
    manifest = CapabilityManifest.from_dict({"schema": "capability-activation/v1",
                                             "deployment": "test", "capabilities": list(entries)})
    return ca.activation_report(LoadedManifest(manifest, True, "kid"), catalogue,
                                premises=premises or {})


def test_on_a_computed_report_shadow_unknown_premise_and_low_maturity_all_refuse():
    enforce = [_entry(cid) for cid in ca.DISPATCH_AUTHORITY]
    assert ca.dispatch_mode_refusal(_computed(*enforce), ca.DISPATCH_AUTHORITY) is None
    shadow = _computed(_entry("CAP-003"), _entry("CAP-013", requested="SHADOW"))
    assert ca.dispatch_mode_refusal(shadow, ca.DISPATCH_AUTHORITY) == (
        "capability_not_enforcing:CAP-013:SHADOW")
    # A premise this process cannot verify gives the fail mode, never ENFORCE.
    unknown = _computed(_entry("CAP-003", premises=["no_such_premise"]), _entry("CAP-013"))
    assert ca.dispatch_mode_refusal(unknown, ca.DISPATCH_AUTHORITY) == (
        "capability_not_enforcing:CAP-003:BLOCKED")
    # An enforcing request below API maturity is lowered (rule 3), so it cannot authorize.
    low = _computed(*enforce, catalogue_status="IMPLEMENTED_LIBRARY")
    assert ca.dispatch_mode_refusal(low, ca.DISPATCH_AUTHORITY) == (
        "capability_not_enforcing:CAP-003:SHADOW")


# ── the dispatcher ─────────────────────────────────────────────────────────


def _lease() -> ExecutionLease:
    return ExecutionLease.issue(
        decision="accept", tenant_id="acme", actor_identity="agent-1", tool_name="wo_update",
        arguments=ARGS, target_environment="staging", policy_bundle_hash="b1",
        issued_at=datetime.now(UTC).isoformat())


def _dispatcher(gate=None):
    calls: list = []
    d = GovernedToolDispatcher("b1")
    d.register("wo_update", lambda arguments: calls.append(arguments) or "ok")
    if gate is not None:
        d.bind_mode_gate(gate)
    return d, calls


def _run(d, lease):
    return d.dispatch(lease, "wo_update", ARGS, tenant_id="acme",
                      target_environment="staging", actor_identity="agent-1")


def test_a_refusing_gate_spends_nothing_and_the_lease_runs_once_allowed():
    reason = {"value": "capability_not_enforcing:CAP-013:SHADOW"}
    d, calls = _dispatcher(lambda: reason["value"])
    lease = _lease()
    result = _run(d, lease)
    assert (result.executed, result.refusal_reason) == (False, reason["value"])
    assert calls == []
    reason["value"] = None                      # the nonce was not consumed
    assert _run(d, lease).executed is True and calls == [ARGS]


def test_a_gate_that_raises_refuses_as_unverifiable():
    def broken():
        raise RuntimeError("report unreadable")

    d, calls = _dispatcher(broken)
    result = _run(d, _lease())
    assert (result.executed, result.refusal_reason) == (False, "cam_mode_unverifiable")
    assert calls == []


def test_without_a_gate_nothing_changes():
    d, calls = _dispatcher()
    assert _run(d, _lease()).executed is True and calls == [ARGS]


# ── the execution API ──────────────────────────────────────────────────────


def _api_report(monkeypatch, report):
    import servers.api as api_mod

    monkeypatch.setattr(api_mod, "CAPABILITY_ACTIVATION", report, raising=False)


def test_the_api_gate_requires_the_dispatch_authority_and_limits_when_configured(monkeypatch):
    import servers.execution_api as exec_mod

    enforce = {cid: "ENFORCE" for cid in ca.DISPATCH_AUTHORITY}
    _api_report(monkeypatch, _report(enforce))
    monkeypatch.setattr(exec_mod, "_limit_guard", lambda: None)
    assert exec_mod._cam_mode_refusal() is None
    monkeypatch.setattr(exec_mod, "_limit_guard", lambda: object())
    assert exec_mod._cam_mode_refusal() == "capability_not_enforcing:CAP-031:DISABLED"
    _api_report(monkeypatch, _report(enforce | {"CAP-031": "SHADOW"}))
    assert exec_mod._cam_mode_refusal() == "capability_not_enforcing:CAP-031:SHADOW"
    _api_report(monkeypatch, _report(enforce | {"CAP-031": "ENFORCE"}))
    assert exec_mod._cam_mode_refusal() is None


def test_a_configured_manifest_that_did_not_load_refuses(monkeypatch, tmp_path):
    import servers.execution_api as exec_mod

    _api_report(monkeypatch, None)
    assert exec_mod._cam_mode_refusal() is None
    monkeypatch.setenv("REMORA_CAM_FILE", str(tmp_path / "cam.json"))
    assert exec_mod._cam_mode_refusal() == "cam_not_loaded"


@pytest.fixture()
def api(request, monkeypatch):
    pytest.importorskip("fastapi")
    client = request.getfixturevalue("_capability_client")

    def with_modes(modes):
        report = None if modes is None else SimpleNamespace(
            manifest_digest="c" * 64,
            get=lambda cid: ca.Activation(cid, "ENFORCE", modes.get(cid, "ENFORCE"), ()))
        _api_report(monkeypatch, report)

    return SimpleNamespace(client=client, with_modes=with_modes)


from tests.capabilities.test_capability_server_path import (  # noqa: E402
    client as _capability_client,  # noqa: F401
)


def _accept(api_ns):
    from tests.capabilities.test_capability_server_path import READ, _token

    assert api_ns.client.post("/v1/execution/assess", json=READ).status_code == 200
    return api_ns.client.post("/v1/execution/execute-accepted", json={
        "execution_token": _token(READ), "tool_call": READ}).json()["tool_execution"]


def test_on_the_api_a_shadow_lease_dispatch_runs_nothing(api):
    api.with_modes({"CAP-013": "SHADOW"})
    body = _accept(api)
    assert body["executed"] is False
    assert body["refusal_reason"] == "capability_not_enforcing:CAP-013:SHADOW"


def test_on_the_api_enforce_runs_and_no_manifest_runs(api):
    api.with_modes({})
    assert _accept(api)["executed"] is True
    api.with_modes(None)
    assert _accept(api)["executed"] is True

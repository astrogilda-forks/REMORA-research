# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The activation manifest's digest in the lease and the decision record
(ADR-UE-03 slice 3; item 5 as resolved by the owner on 2026-10-25: a
signed-when-set lease field beside the policy identity).

Pinned: the lease signs ``cam_digest`` only when set; the dispatcher refuses,
before anything is spent, a lease whose manifest differs from its own
(``cam_changed``), a manifest-bound lease where no manifest is loaded or bound
(``cam_unbound``), a lease without a manifest where one is in force
(``cam_lease_unbound``) and a source that raises (``cam_unverifiable``);
without a manifest anywhere nothing changes. On the API, the authority mints
the lease with the digest of the manifest it loaded at startup and records it
in the ``assessed`` event.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from remora.enforcement.lease import ExecutionLease, GovernedToolDispatcher

DIGEST = "c" * 64
OTHER = "d" * 64
ARGS = {"order": "WO-1"}


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv("REMORA_LEASE_SIGNING_KEY", "cam-lease-key")
    for name in ("REMORA_LEASE_SIGNING_KEY_ED25519_PRIVATE",
                 "REMORA_LEASE_VERIFY_KEY_ED25519_PUBLIC", "REMORA_RUNTIME_PROFILE"):
        monkeypatch.delenv(name, raising=False)


def _lease(**over) -> ExecutionLease:
    return ExecutionLease.issue(
        decision="accept", tenant_id="acme", actor_identity="agent-1", tool_name="wo_update",
        arguments=ARGS, target_environment="staging", policy_bundle_hash="b1",
        issued_at=datetime.now(UTC).isoformat(), **over)


def _dispatcher(source=None):
    calls: list = []
    d = GovernedToolDispatcher("b1")
    d.register("wo_update", lambda arguments: calls.append(arguments) or "ok")
    if source is not None:
        d.bind_cam_digest(source)
    return d, calls


def _run(d, lease):
    return d.dispatch(lease, "wo_update", ARGS, tenant_id="acme",
                      target_environment="staging", actor_identity="agent-1")


def test_the_lease_signs_the_manifest_digest_only_when_set():
    plain, bound = _lease(), _lease(cam_digest=DIGEST)
    assert "cam_digest" not in plain._signed_fields()
    assert bound._signed_fields()["cam_digest"] == DIGEST
    assert ExecutionLease.from_dict(bound.to_dict()) == bound
    forged = ExecutionLease.from_dict({**bound.to_dict(), "cam_digest": OTHER})
    assert forged.verify(tool_name="wo_update", arguments=ARGS, tenant_id="acme",
                         target_environment="staging", now=datetime.now(UTC).isoformat(),
                         actor_identity="agent-1").reason == "signature_invalid"


def test_the_same_manifest_runs():
    d, calls = _dispatcher(lambda: DIGEST)
    assert _run(d, _lease(cam_digest=DIGEST)).executed is True and calls == [ARGS]


def test_another_manifest_refuses_before_anything_is_spent():
    d, calls = _dispatcher(lambda: OTHER)
    lease = _lease(cam_digest=DIGEST)
    result = _run(d, lease)
    assert (result.executed, result.refusal_reason) == (False, "cam_changed")
    assert calls == []
    d.bind_cam_digest(lambda: DIGEST)          # the nonce was not spent
    assert _run(d, lease).executed is True


@pytest.mark.parametrize("source", [None, lambda: None, lambda: ""])
def test_a_manifest_bound_lease_where_no_manifest_is_loaded_refuses(source):
    d, calls = _dispatcher(source)
    result = _run(d, _lease(cam_digest=DIGEST))
    assert (result.executed, result.refusal_reason) == (False, "cam_unbound")
    assert calls == []


def test_a_lease_without_a_manifest_does_not_run_where_one_is_in_force():
    d, calls = _dispatcher(lambda: DIGEST)
    result = _run(d, _lease())
    assert (result.executed, result.refusal_reason) == (False, "cam_lease_unbound")
    assert calls == []


def test_a_source_that_raises_refuses():
    def boom():
        raise OSError("manifest store down")

    d, calls = _dispatcher(boom)
    assert _run(d, _lease(cam_digest=DIGEST)).refusal_reason == "cam_unverifiable"
    assert calls == []


@pytest.mark.parametrize("source", [None, lambda: None])
def test_without_a_manifest_anywhere_nothing_changes(source):
    d, calls = _dispatcher(source)
    assert _run(d, _lease()).executed is True and calls == [ARGS]


# ── on the API ─────────────────────────────────────────────────────────────


def _post_accept(client, call, token):
    return client.post("/v1/execution/execute-accepted",
                       json={"execution_token": token, "tool_call": call})


@pytest.fixture()
def api(request, monkeypatch):
    pytest.importorskip("fastapi")
    from types import SimpleNamespace

    import servers.api as api_mod
    from remora.execution import dispatch

    client = request.getfixturevalue("_capability_client")
    minted: list = []
    real = dispatch._issue_local_lease

    def recording(**kwargs):
        lease = real(**kwargs)
        minted.append(lease)
        return lease

    monkeypatch.setattr(dispatch, "_issue_local_lease", recording)

    def with_manifest(digest, modes=None):
        """A loaded manifest with ``digest``; every capability ENFORCE unless
        ``modes`` says otherwise (the dispatch mode gate reads them)."""
        from remora.governance.capability_activation import Activation

        modes = modes or {}
        report = None if digest is None else SimpleNamespace(
            manifest_digest=digest,
            get=lambda cid: Activation(cid, "ENFORCE", modes.get(cid, "ENFORCE"), ()))
        monkeypatch.setattr(api_mod, "CAPABILITY_ACTIVATION", report, raising=False)

    return SimpleNamespace(client=client, minted=minted, with_manifest=with_manifest)


from tests.capabilities.test_capability_server_path import (  # noqa: E402
    client as _capability_client,  # noqa: F401
)


def test_on_the_api_the_lease_and_the_assessment_carry_the_manifest(api):
    from tests.capabilities.test_capability_server_path import READ, _mod, _token

    api.with_manifest(DIGEST)
    r = api.client.post("/v1/execution/assess", json=READ)
    assert r.status_code == 200, r.text
    assessed = [e.payload for e in _mod()._CHAIN.entries("acme")
                if e.payload.get("event") == "assessed"][-1]
    assert assessed["cam_digest"] == DIGEST
    body = _post_accept(api.client, READ, _token(READ)).json()["tool_execution"]
    assert body["executed"] is True, body
    assert api.minted[-1].cam_digest == DIGEST


def test_on_the_api_without_a_manifest_nothing_is_recorded(api):
    from tests.capabilities.test_capability_server_path import READ, _mod, _token

    api.with_manifest(None)
    assert api.client.post("/v1/execution/assess", json=READ).status_code == 200
    assessed = [e.payload for e in _mod()._CHAIN.entries("acme")
                if e.payload.get("event") == "assessed"][-1]
    assert "cam_digest" not in assessed
    body = _post_accept(api.client, READ, _token(READ)).json()["tool_execution"]
    assert body["executed"] is True and api.minted[-1].cam_digest == ""

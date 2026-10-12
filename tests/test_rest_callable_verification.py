# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The API path measures each registered callable against its signed spec.

Until 2026-10-13 only the opt-in ``SignedSurfaceRuntime`` called
``verify_callable``. On ``/v1/execution/*`` the deployment's registry module
registered whatever it imported: every lease carried the signed spec identity,
but nothing showed the code behind it was the code the spec names. The demo
bundle ``remora init-review`` writes even attested a digest of the whole
registry module, a value no runtime measures, and nothing noticed.
"""
from __future__ import annotations

import importlib.util
import json

import pytest

from remora.execution.authorization import verified_registration
from remora.toolcall.callable_digest import source_digest
from remora.toolcall.toolspec import ToolSpecBundle, ToolSpecRefused, sign_bundle
from servers import tool_registry_research
from tests.test_toolspec_execution_wiring import (
    CALL,
    IDENTITY,
    KEY,
    _bundle_file,
    _client,
    _mod,
    _spec,
)


def _bundle(*specs) -> ToolSpecBundle:
    signed = sign_bundle({"schema_version": 1, "tool_specs": list(specs)}, key=KEY,
                         signing_identity=IDENTITY, signed_at="2026-10-13T00:00:00Z")
    return ToolSpecBundle.load(signed, key=KEY, trusted_identities=[IDENTITY])


def _recorder():
    registered: list[str] = []
    return registered, lambda name, fn, **kw: registered.append(name)


# ── the measurement ──────────────────────────────────────────────────────────

def test_the_signed_callable_registers() -> None:
    registered, register = _recorder()
    verified_registration(_bundle(_spec()), register)(
        "store_artifact", tool_registry_research.store_artifact)
    assert registered == ["store_artifact"]


def test_a_different_callable_under_the_signed_name_refuses() -> None:
    registered, register = _recorder()
    with pytest.raises(ToolSpecRefused) as refused:
        verified_registration(_bundle(_spec()), register)(
            "store_artifact", tool_registry_research.read_telemetry)
    assert refused.value.reason_code == "toolspec_callable_digest_mismatch"
    assert registered == []


def test_a_changed_body_refuses(tmp_path) -> None:
    """Same name, same module shape, one changed line: the source span moves."""
    path = tmp_path / "swapped_registry.py"
    path.write_text("def store_artifact(arguments):\n    return {'stored': False}\n",
                    encoding="utf-8")
    spec = importlib.util.spec_from_file_location("swapped_registry", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with pytest.raises(ToolSpecRefused):
        verified_registration(_bundle(_spec()), _recorder()[1])(
            "store_artifact", module.store_artifact)


def test_mediated_registration_keeps_its_keyword() -> None:
    seen: dict = {}
    verified_registration(_bundle(_spec()), lambda name, fn, **kw: seen.update(kw))(
        "store_artifact", tool_registry_research.store_artifact, mediated=True)
    assert seen == {"mediated": True}


def test_a_tool_without_a_spec_is_registered_unmeasured() -> None:
    """Nothing is attested to compare; assessment refuses it as unknown."""
    registered, register = _recorder()
    verified_registration(_bundle(_spec()), register)(
        "read_telemetry", tool_registry_research.read_telemetry)
    assert registered == ["read_telemetry"]


def test_without_a_bundle_registration_is_unchanged() -> None:
    _, register = _recorder()
    assert verified_registration(None, register) is register


# ── the API path ─────────────────────────────────────────────────────────────

def test_the_api_refuses_to_build_a_dispatcher_around_an_unsigned_callable(
        monkeypatch, tmp_path) -> None:
    wrong = _spec(callable_digest=source_digest(tool_registry_research.read_telemetry))
    _client(monkeypatch, tmp_path, bundle_path=_bundle_file(tmp_path, [wrong]))
    with pytest.raises(ToolSpecRefused) as refused:
        _mod()._tool_dispatcher()
    assert refused.value.reason_code == "toolspec_callable_digest_mismatch"
    _mod()._reset_tool_dispatcher()


def test_the_signed_callable_still_executes_end_to_end(monkeypatch, tmp_path) -> None:
    client = _client(monkeypatch, tmp_path, bundle_path=_bundle_file(tmp_path))
    assessed = client.post("/v1/execution/assess", json=CALL)
    assert assessed.status_code == 200, assessed.text
    if assessed.json()["decision"] == "accept":
        run = client.post("/v1/execution/execute-accepted", json={
            "execution_token": assessed.json()["execution_token"], "tool_call": CALL})
        assert run.status_code == 200, run.text
    assert _mod()._tool_dispatcher() is not None


# ── the scaffold ─────────────────────────────────────────────────────────────

def test_init_review_signs_the_digest_the_runtime_measures(tmp_path) -> None:
    from remora.scaffold import init_review

    init_review(tmp_path / ".remora")
    bundle = json.loads((tmp_path / ".remora" / "toolspec-bundle.json").read_text(encoding="utf-8"))
    signed = {s["tool_id"]: s["callable_digest"] for s in bundle["tool_specs"]}
    spec = importlib.util.spec_from_file_location(
        "scaffold_registry_under_test", tmp_path / ".remora" / "remora_registry.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert signed["send_notification"] == source_digest(module.send_notification)

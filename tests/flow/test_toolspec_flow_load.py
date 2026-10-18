# SPDX-License-Identifier: BUSL-1.1
"""IFC-03b: a signed ToolSpec v4 bundle carries the ``flow`` block (SDD v1.3 §5.1).

The loader accepts schema version 4, refuses ``flow`` in an older bundle, and
refuses a block that does not parse or does not lint, even when the bundle is
correctly signed. Under a strict runtime profile with ``REMORA_FLOW_CONTROL=1``
every spec must carry a block (FL-13), so the process does not start on a
bundle whose tools say nothing about where their data goes.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from remora.profiles import RuntimeProfileError
from remora.toolcall.toolspec import ToolSpecBundle, ToolSpecRefused, sign_bundle
from tests.test_effect_mediation_policy import MEDIATED, _validate, executor  # noqa: F401
from tests.test_toolspec_runtime import IDENTITY, KEY, _spec

#: A clean block for the test spec ``store_artifact`` (action_type write, two
#: arguments, MEDIATED): it writes the artifact named by ``artifact_id``.
FLOW = {
    "provider": "tcb",
    "arguments": {"artifact_id": {"kind": "resource"}, "content": {"kind": "text"}},
    "sources": {"default_integrity": "UNTRUSTED"},
    "sink": {"recipients": {"resource_of": "artifact_id"}, "payload_args": ["content"],
             "integrity_required": ["artifact_id"]},
}


def _load(schema_version: int = 4, **fields) -> ToolSpecBundle:
    bundle = sign_bundle({"schema_version": schema_version,
                          "tool_specs": [_spec(**{**MEDIATED, **fields})]},
                         key=KEY, signing_identity=IDENTITY,
                         signed_at="2026-10-18T00:00:00+00:00")
    return ToolSpecBundle.load(bundle, key=KEY, trusted_identities=[IDENTITY])


def test_a_v4_bundle_carries_the_parsed_block():
    spec = _load(flow=FLOW).get("store_artifact")
    assert spec.flow is not None
    assert spec.flow.sink.recipients.kind == "resource_of"
    assert spec.flow.argument_kind("artifact_id") == "resource"


def test_a_v4_spec_without_a_block_loads_with_none():
    assert _load().get("store_artifact").flow is None


def test_the_block_is_inside_the_signed_bytes():
    """Changing the block after signing breaks the signature."""
    bundle = sign_bundle({"schema_version": 4, "tool_specs": [_spec(**MEDIATED, flow=FLOW)]},
                         key=KEY, signing_identity=IDENTITY,
                         signed_at="2026-10-18T00:00:00+00:00")
    bundle = json.loads(json.dumps(bundle))
    bundle["tool_specs"][0]["flow"]["sink"]["recipients"] = {"static": ["ext://evil.example"]}
    with pytest.raises(ToolSpecRefused) as exc:
        ToolSpecBundle.load(bundle, key=KEY, trusted_identities=[IDENTITY])
    assert exc.value.reason_code == "toolspec_signature_invalid"


def test_the_block_changes_the_spec_hash():
    with_block = _load(flow=FLOW).get("store_artifact").toolspec_hash
    without = _load().get("store_artifact").toolspec_hash
    assert with_block != without


@pytest.mark.parametrize("version", [1, 2, 3])
def test_a_block_below_v4_is_refused(version):
    # Below v3 the effect fields are themselves refused, so the spec omits them.
    spec = _spec(flow=FLOW) if version < 3 else _spec(**MEDIATED, flow=FLOW)
    bundle = sign_bundle({"schema_version": version, "tool_specs": [spec]},
                         key=KEY, signing_identity=IDENTITY,
                         signed_at="2026-10-18T00:00:00+00:00")
    with pytest.raises(ToolSpecRefused) as exc:
        ToolSpecBundle.load(bundle, key=KEY, trusted_identities=[IDENTITY])
    assert exc.value.reason_code == "toolspec_flow_requires_v4"


def test_a_malformed_block_is_refused_although_signed():
    with pytest.raises(ToolSpecRefused) as exc:
        _load(flow={**FLOW, "sink": {"recipients": "everyone"}})
    assert exc.value.reason_code == "toolspec_flow_invalid"


@pytest.mark.parametrize("flow, rule", [
    ({**FLOW, "sink": {**FLOW["sink"], "integrity_required": ["owner"]}}, "FL-02"),
    ({**FLOW, "sink": {"recipients": {"static": ["user://acme/alice"]}}}, "FL-05"),
    ({**FLOW, "arguments": {"artifact_id": {"kind": "resource"}}}, "FL-10"),
])
def test_a_block_that_fails_lint_is_refused_although_signed(flow, rule):
    with pytest.raises(ToolSpecRefused) as exc:
        _load(flow=flow)
    assert exc.value.reason_code == "toolspec_flow_lint_failed"
    assert rule in str(exc.value)


def test_lint_reads_the_signed_effect_mode():
    """FL-09: a sink needs MEDIATED effects; the effect mode comes from the spec."""
    with pytest.raises(ToolSpecRefused) as exc:
        _load(flow=FLOW, effect_mode="NONE", downstream_capabilities=[])
    assert exc.value.reason_code == "toolspec_flow_lint_failed" and "FL-09" in str(exc.value)


# -- the strict profile at startup ----------------------------------------------

def _resign_v4(root: Path, monkeypatch, flow) -> None:
    """Re-sign the scaffold bundle as schema version 4, with or without a block."""
    from remora.execution.authorization import reset_toolspec_bundle_cache
    from remora.toolcall.toolspec_sign import sign_with_seed

    signed = json.loads((root / "toolspec-bundle.json").read_text(encoding="utf-8"))
    specs = []
    for raw in signed["tool_specs"]:
        spec = dict(raw)
        if flow is not None:
            spec["flow"] = flow(spec)
        specs.append(spec)
    seed = (root / "keys" / "toolspec_ed25519_seed").read_text(encoding="utf-8").strip()
    bundle, public, digest = sign_with_seed({"schema_version": 4, "tool_specs": specs}, seed,
                                            signed_at=signed["registry_signature"]["signed_at"])
    (root / "toolspec-bundle.json").write_text(json.dumps(bundle), encoding="utf-8")
    monkeypatch.setenv("REMORA_TOOLSPEC_VERIFY_KEYS", public)
    monkeypatch.setenv("REMORA_TOOLSPEC_PINNED_DIGEST", digest)
    reset_toolspec_bundle_cache()


def _clean_flow(spec: dict) -> dict:
    """A block that lints clean for whatever the scaffold's tool is."""
    args = sorted(spec["argument_schema"].get("properties", {}))
    return {"provider": "tcb", "arguments": {a: {"kind": "text"} for a in args},
            "sink": {"recipients": {"static": ["ext://notify.example"]}}}


def test_strict_flow_control_refuses_a_spec_without_a_block(executor, monkeypatch):  # noqa: F811
    _, root = executor
    _resign_v4(root, monkeypatch, None)
    assert _validate() == "review"  # flow control off: a v4 bundle without blocks is fine
    monkeypatch.setenv("REMORA_FLOW_CONTROL", "1")
    with pytest.raises(RuntimeProfileError, match="FL-13"):
        _validate()


def test_strict_flow_control_starts_when_every_spec_has_a_block(executor, monkeypatch):  # noqa: F811
    _, root = executor
    _resign_v4(root, monkeypatch, _clean_flow)
    monkeypatch.setenv("REMORA_FLOW_CONTROL", "1")
    assert _validate() == "review"


def test_strict_flow_control_has_no_unsigned_path(executor, monkeypatch):  # noqa: F811
    """Without a bundle there is nothing to check FL-13 against; the strict
    profile already refuses that configuration, before the flow check."""
    monkeypatch.delenv("REMORA_TOOLSPEC_BUNDLE", raising=False)
    monkeypatch.setenv("REMORA_FLOW_CONTROL", "1")
    with pytest.raises(RuntimeProfileError, match="REMORA_TOOLSPEC_BUNDLE"):
        _validate()


def test_flow_control_off_a_strict_profile_ignores_missing_blocks(executor, monkeypatch):  # noqa: F811
    _, root = executor
    _resign_v4(root, monkeypatch, None)
    for value in ("", "0", "true"):
        monkeypatch.setenv("REMORA_FLOW_CONTROL", value)
        assert _validate() == "review"

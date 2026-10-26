# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Effective capability modes and the startup validation (ADR-UE-03 slice 2).

Pinned: the packaged catalogue matches the register; each rule of
``remora.governance.capability_activation`` (absent means DISABLED, a failed
or unverifiable premise applies the fail mode and never allows, an enforcing
request below WIRED_API_PATH is downgraded, otherwise the requested mode); the
premise registry's checks against the settings they read; the report over a
manifest; the startup validation with and without REMORA_CAM_REQUIRED, with a
strict profile, and in a separate interpreter importing the API.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from remora.crypto import SignatureDomain, SigningKey
from remora.governance import capability_activation as ca
from remora.governance.activation_manifest import (
    CapabilityActivation,
    CapabilityManifest,
    LoadedManifest,
    sign_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
NO_CONTRACT = ""


def _entry(cid="CAP-031", *, requested="ENFORCE", allowed=("SHADOW", "ENFORCE"),
           premises=(), fail_mode="DENY_OR_HOLD") -> dict:
    return {"capability_id": cid, "component_version": "0.12.0",
            "implementation_ref": "remora/enforcement/cumulative_limits.py",
            "requested_mode": requested, "allowed_modes": list(allowed),
            "required_premises": list(premises), "trust_source_ids": [],
            "api_contract": NO_CONTRACT, "sdk_surface": NO_CONTRACT, "health_probe": NO_CONTRACT,
            "fail_mode": fail_mode, "claim_ceiling": "per_deployment_configured_limit_only",
            "evidence_refs": [cid]}


def _activation(**kw) -> CapabilityActivation:
    return CapabilityActivation.from_dict(_entry(**kw))


def _premises(**results: bool) -> dict[str, ca.Premise]:
    def fixed(value: bool):
        return lambda: value

    return {k: ca.Premise(k, "test", fixed(v)) for k, v in results.items()}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for name in ("REMORA_CAM_REQUIRED", "REMORA_CAM_FILE", "REMORA_CAM_TRUSTED_KEYS",
                 "REMORA_RUNTIME_PROFILE", "REMORA_FLOW_CONTROL", "REMORA_LIMITS_LEDGER",
                 "REMORA_REQUIRE_LIMITS"):
        monkeypatch.delenv(name, raising=False)


# ── the packaged catalogue ─────────────────────────────────────────────────


@pytest.mark.docgate
def test_the_packaged_catalogue_matches_the_register():
    """docs/assurance/capability_register_v1.yaml and the packaged catalogue agree;
    a changed id, name, status or hook needs `build_capability_catalogue.py --write`."""
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "build_capability_catalogue.py"),
                             "--check"], capture_output=True, text=True, timeout=120, check=False)
    assert result.returncode == 0, result.stderr
    catalogue = ca.load_catalogue()
    assert len(catalogue) == 32 and "CAP-META" in catalogue
    assert all(entry["status"] and entry["hook"] for entry in catalogue.values())


# ── the rules ──────────────────────────────────────────────────────────────


def test_rule_4_the_requested_mode_when_premises_hold_and_maturity_allows():
    act = ca.effective_activation(_activation(premises=["mandatory_limits"]),
                                  registered_status="WIRED_API_PATH",
                                  premises=_premises(mandatory_limits=True))
    assert (act.effective_mode, act.reasons) == ("ENFORCE", ())
    assert act.premises == {"mandatory_limits": True}


@pytest.mark.parametrize("fail_mode, mode", [
    ("DENY", ca.BLOCKED), ("HOLD", ca.BLOCKED), ("DENY_OR_HOLD", ca.BLOCKED),
    ("DISABLE", "DISABLED")])
def test_rule_2_a_failed_premise_applies_the_fail_mode(fail_mode, mode):
    act = ca.effective_activation(_activation(premises=["a", "b"], fail_mode=fail_mode),
                                  registered_status="WIRED_API_PATH",
                                  premises=_premises(a=True, b=False))
    assert act.effective_mode == mode
    assert "premise_failed:b" in act.reasons and f"fail_mode:{fail_mode}" in act.reasons


def test_rule_2_an_unknown_premise_is_unverifiable_not_satisfied():
    act = ca.effective_activation(_activation(premises=["reconciliation_authority"]),
                                  registered_status="WIRED_API_PATH", premises={})
    assert act.effective_mode == ca.BLOCKED
    assert act.reasons[0] == "premise_unverifiable:reconciliation_authority"
    assert act.premises == {"reconciliation_authority": None}


def test_rule_2_a_premise_whose_check_raises_is_unverifiable():
    def boom():
        raise OSError("store down")

    act = ca.effective_activation(_activation(premises=["p"]), registered_status="WIRED_API_PATH",
                                  premises={"p": ca.Premise("p", "t", boom)})
    assert act.effective_mode == ca.BLOCKED and act.premises == {"p": None}


@pytest.mark.parametrize("allowed, mode", [
    (("SHADOW", "ENFORCE"), "SHADOW"),
    (("EVIDENCE_ONLY", "ENFORCE"), "EVIDENCE_ONLY"),
    (("OFFLINE", "ENFORCE"), "OFFLINE"),
    (("ENFORCE",), ca.BLOCKED),
])
def test_rule_3_an_enforcing_request_below_api_maturity_is_downgraded(allowed, mode):
    act = ca.effective_activation(_activation(allowed=allowed),
                                  registered_status="IMPLEMENTED_LIBRARY", premises={})
    assert act.effective_mode == mode
    assert act.reasons == ("maturity_below_enforce:IMPLEMENTED_LIBRARY",)


def test_rule_3_applies_to_verify_and_not_to_shadow():
    verify = ca.effective_activation(_activation(requested="VERIFY", allowed=("SHADOW", "VERIFY")),
                                     registered_status="WIRED_REFERENCE_PATH", premises={})
    assert verify.effective_mode == "SHADOW"
    shadow = ca.effective_activation(_activation(requested="SHADOW", allowed=("SHADOW",)),
                                     registered_status="IMPLEMENTED_LIBRARY", premises={})
    assert shadow.effective_mode == "SHADOW" and shadow.reasons == ()


def test_a_failed_premise_wins_over_the_maturity_downgrade():
    act = ca.effective_activation(_activation(premises=["p"]),
                                  registered_status="IMPLEMENTED_LIBRARY",
                                  premises=_premises(p=False))
    assert act.effective_mode == ca.BLOCKED


# ── the premise registry ───────────────────────────────────────────────────


def test_the_premise_registry_reads_the_settings_it_names(monkeypatch):
    p = ca.PREMISES
    assert p["flow_control"].check() is False
    monkeypatch.setenv("REMORA_FLOW_CONTROL", "1")
    assert p["flow_control"].check() is True
    assert p["shared_atomic_ledger"].check() is False
    monkeypatch.setenv("REMORA_LIMITS_LEDGER", "/var/lib/remora/limits.db")
    assert p["shared_atomic_ledger"].check() is False
    monkeypatch.setenv("REMORA_LIMITS_LEDGER", "postgresql://u@db/remora")
    assert p["shared_atomic_ledger"].check() is True
    monkeypatch.setenv("REMORA_LIMITS_LEDGER", "host=db dbname=remora user=u")
    assert p["shared_atomic_ledger"].check() is True
    assert p["mandatory_limits"].check() is False
    monkeypatch.setenv("REMORA_REQUIRE_LIMITS", "1")
    assert p["mandatory_limits"].check() is True
    assert p["strict_runtime_profile"].check() is False
    monkeypatch.setenv("REMORA_RUNTIME_PROFILE", "controlled_pilot")
    assert p["strict_runtime_profile"].check() is True
    assert all(premise.statement for premise in p.values())


# ── the report and the startup validation ──────────────────────────────────

CATALOGUE = {"CAP-001": {"name": "a", "status": "WIRED_API_PATH", "hook": "POLICY"},
             "CAP-031": {"name": "b", "status": "WIRED_API_PATH", "hook": "PRE_DISPATCH"}}


def _loaded(*entries: dict, signed: bool = False) -> LoadedManifest:
    manifest = CapabilityManifest.from_dict({"schema": "capability-activation/v1",
                                             "deployment": "test", "capabilities": list(entries)})
    return LoadedManifest(manifest, signed, "kid" if signed else "")


def test_the_report_disables_an_absent_capability_and_names_unknown_entries():
    report = ca.activation_report(
        _loaded(_entry("CAP-031", premises=["p"]), _entry("CAP-099")), CATALOGUE,
        premises=_premises(p=True))
    assert report.unknown == ("CAP-099",) and report.missing == ("CAP-001",)
    assert report.get("CAP-001").effective_mode == "DISABLED"
    assert report.get("CAP-001").reasons == ("absent_from_manifest",)
    assert report.get("CAP-031").effective_mode == "ENFORCE"
    assert report.get("CAP-099") is None
    assert json.loads(json.dumps(report.to_dict()))["manifest_digest"] == report.manifest_digest


def _write_signed(tmp_path, monkeypatch, *entries: dict) -> None:
    key = SigningKey.generate({SignatureDomain.CAPABILITY_MANIFEST})
    path = tmp_path / "cam.json"
    path.write_text(json.dumps(sign_manifest({"schema": "capability-activation/v1",
                                              "deployment": "test",
                                              "capabilities": list(entries)},
                                             key, "2026-10-25T00:00:00Z")), encoding="utf-8")
    monkeypatch.setenv("REMORA_CAM_FILE", str(path))
    monkeypatch.setenv("REMORA_CAM_TRUSTED_KEYS", key.verification_key().public_bytes.hex())


def _catalogue_file(tmp_path) -> Path:
    path = tmp_path / "catalogue.json"
    path.write_text(json.dumps({"schema": "remora-capability-catalogue/v1",
                                "capabilities": [{"id": k, **v} for k, v in CATALOGUE.items()]}),
                    encoding="utf-8")
    return path


def test_without_a_manifest_and_not_required_nothing_happens():
    assert ca.validate_activation_at_startup() is None


def test_required_without_a_manifest_refuses_startup(monkeypatch):
    from remora.profiles import RuntimeProfileError

    monkeypatch.setenv("REMORA_CAM_REQUIRED", "1")
    with pytest.raises(RuntimeProfileError, match="REMORA_CAM_FILE is unset"):
        ca.validate_activation_at_startup()


def test_required_with_an_unloadable_manifest_refuses_and_not_required_logs(
        tmp_path, monkeypatch, caplog):
    from remora.profiles import RuntimeProfileError

    (tmp_path / "bad.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("REMORA_CAM_FILE", str(tmp_path / "bad.json"))
    with caplog.at_level("WARNING", logger="remora.governance.capability_activation"):
        assert ca.validate_activation_at_startup() is None
    assert "not required, continuing" in caplog.text
    monkeypatch.setenv("REMORA_CAM_REQUIRED", "1")
    with pytest.raises(RuntimeProfileError, match="manifest_schema_unknown"):
        ca.validate_activation_at_startup()


def test_required_refuses_an_entry_the_catalogue_does_not_have(tmp_path, monkeypatch):
    monkeypatch.setenv("REMORA_REQUIRE_LIMITS", "1")  # agrees with CAP-031 ENFORCE
    from remora.profiles import RuntimeProfileError

    _write_signed(tmp_path, monkeypatch, _entry("CAP-031"), _entry("CAP-001"), _entry("CAP-099"))
    monkeypatch.setenv("REMORA_CAM_REQUIRED", "1")
    with pytest.raises(RuntimeProfileError, match="CAP-099"):
        ca.validate_activation_at_startup(catalogue_path=_catalogue_file(tmp_path))


def test_a_strict_profile_needs_every_registered_capability(tmp_path, monkeypatch):
    monkeypatch.setenv("REMORA_REQUIRE_LIMITS", "1")  # agrees with CAP-031 ENFORCE
    from remora.profiles import RuntimeProfileError

    _write_signed(tmp_path, monkeypatch, _entry("CAP-031"))
    monkeypatch.setenv("REMORA_CAM_REQUIRED", "1")
    report = ca.validate_activation_at_startup(catalogue_path=_catalogue_file(tmp_path))
    assert report is not None and report.missing == ("CAP-001",)    # not strict: DISABLED
    monkeypatch.setattr(ca, "_strict_profile", lambda: True)
    with pytest.raises(RuntimeProfileError, match="missing"):
        ca.validate_activation_at_startup(catalogue_path=_catalogue_file(tmp_path))


def test_a_complete_signed_manifest_under_a_strict_profile_is_accepted(tmp_path, monkeypatch):
    monkeypatch.setenv("REMORA_REQUIRE_LIMITS", "1")  # agrees with CAP-031 ENFORCE
    _write_signed(tmp_path, monkeypatch, _entry("CAP-031", premises=["p"]),
                  _entry("CAP-001", requested="SHADOW", allowed=("SHADOW",)))
    monkeypatch.setenv("REMORA_CAM_REQUIRED", "1")
    monkeypatch.setattr(ca, "_strict_profile", lambda: True)
    report = ca.validate_activation_at_startup(catalogue_path=_catalogue_file(tmp_path),
                                               premises=_premises(p=False))
    assert report is not None and report.signed is True
    assert report.get("CAP-031").effective_mode == ca.BLOCKED
    assert report.get("CAP-001").effective_mode == "SHADOW"


def _import_api(env_over: dict[str, str]) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("REMORA_CAM", "SENTRY_"))}
    env.update({"REMORA_ENV": "development", "PYTHONPATH": str(ROOT), **env_over})
    code = ("import servers.api as a\n"
            "r = a.CAPABILITY_ACTIVATION\n"
            "print('report' if r is not None else 'none')\n")
    return subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, capture_output=True,
                          text=True, timeout=180, check=False)


def test_the_api_starts_without_a_manifest_and_refuses_when_one_is_required():
    assert _import_api({}).stdout.strip().endswith("none")
    refused = _import_api({"REMORA_CAM_REQUIRED": "1"})
    assert refused.returncode != 0
    assert "capability activation manifest refused" in refused.stderr


def test_a_catalogue_of_another_schema_is_refused(tmp_path):
    from remora.governance.activation_manifest import ManifestError

    path = tmp_path / "catalogue.json"
    path.write_text(json.dumps({"schema": "other/v1", "capabilities": []}), encoding="utf-8")
    with pytest.raises(ManifestError) as exc:
        ca.load_catalogue(path)
    assert exc.value.reason == "catalogue_schema_unknown"


# ── the read-only catalogue (slice 4) ──────────────────────────────────────


def test_without_a_manifest_every_mode_is_not_established():
    view = ca.catalogue_view(None, CATALOGUE)
    assert view["schema"] == "remora-system-capabilities/v1"
    assert view["manifest"] == {"loaded": False}
    assert [r["capability_id"] for r in view["capabilities"]] == ["CAP-001", "CAP-031"]
    for row in view["capabilities"]:
        assert row["requested_mode"] == row["effective_mode"] == ca.NOT_ESTABLISHED
        assert row["reasons"] == ["no_manifest_loaded"]
    assert view["capabilities"][1]["hook"] == "PRE_DISPATCH"


def test_under_a_manifest_the_view_shows_requested_and_effective_modes():
    report = ca.activation_report(_loaded(_entry("CAP-031", premises=["p"]), signed=True),
                                  CATALOGUE, premises=_premises(p=False))
    view = ca.catalogue_view(report, CATALOGUE)
    assert view["manifest"]["loaded"] is True and view["manifest"]["signed"] is True
    assert view["manifest"]["digest"] == report.manifest_digest
    assert view["manifest"]["missing"] == ["CAP-001"]
    rows = {r["capability_id"]: r for r in view["capabilities"]}
    assert rows["CAP-031"]["effective_mode"] == ca.BLOCKED
    assert rows["CAP-031"]["premises"] == {"p": False}
    assert rows["CAP-001"]["effective_mode"] == "DISABLED"
    assert rows["CAP-001"]["requested_mode"] == ca.NOT_ESTABLISHED
    text = json.dumps(view)
    assert "kid" not in text and "signer" not in text and "key" not in text.lower()


def test_the_live_view_covers_the_packaged_catalogue():
    view = ca.catalogue_view(None)
    assert len(view["capabilities"]) == 32


def test_the_route_serves_the_view_to_a_reader_and_refuses_without_the_capability(monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi import HTTPException
    from fastapi.testclient import TestClient

    import servers.api as api_mod

    monkeypatch.setattr(api_mod, "_authenticate", lambda request: ("acme", "viewer"))
    monkeypatch.setattr(api_mod, "CAPABILITY_ACTIVATION", None)
    client = TestClient(api_mod.app)
    body = client.get("/v1/system/capabilities").json()
    assert body["manifest"] == {"loaded": False} and len(body["capabilities"]) == 32

    def refuse(role, tenant, capability):
        assert capability == "read"
        raise HTTPException(status_code=403, detail="no read")

    monkeypatch.setattr(api_mod, "_require_tenant_capability", refuse)
    assert client.get("/v1/system/capabilities").status_code == 403


# ── migrated flags must agree with the manifest (slice 5) ──────────────────


@pytest.mark.parametrize("flag, requested, agrees", [
    (True, "ENFORCE", True), (True, "VERIFY", True), (False, "SHADOW", True),
    (False, "DISABLED", True), (True, "SHADOW", False), (False, "ENFORCE", False),
])
def test_require_limits_and_the_cap_031_request_must_agree(monkeypatch, flag, requested, agrees):
    if flag:
        monkeypatch.setenv("REMORA_REQUIRE_LIMITS", "1")
    allowed = ("SHADOW", "VERIFY", "ENFORCE", "DISABLED")
    loaded = _loaded(_entry("CAP-031", requested=requested, allowed=allowed))
    problems = ca.flag_disagreements(loaded)
    assert (problems == []) is agrees, problems
    if not agrees:
        assert "REMORA_REQUIRE_LIMITS" in problems[0] and requested in problems[0]


def test_a_capability_the_manifest_leaves_out_is_not_compared(monkeypatch):
    monkeypatch.setenv("REMORA_REQUIRE_LIMITS", "1")
    assert ca.flag_disagreements(_loaded(_entry("CAP-001", requested="SHADOW",
                                                allowed=("SHADOW",)))) == []


def test_a_disagreement_refuses_startup_even_when_the_manifest_is_not_required(
        tmp_path, monkeypatch):
    from remora.profiles import RuntimeProfileError

    _write_signed(tmp_path, monkeypatch, _entry("CAP-031", requested="SHADOW",
                                                allowed=("SHADOW", "ENFORCE")))
    monkeypatch.setenv("REMORA_REQUIRE_LIMITS", "1")
    with pytest.raises(RuntimeProfileError, match="disagree"):
        ca.validate_activation_at_startup(catalogue_path=_catalogue_file(tmp_path))
    monkeypatch.delenv("REMORA_REQUIRE_LIMITS")
    assert ca.validate_activation_at_startup(catalogue_path=_catalogue_file(tmp_path)) is not None

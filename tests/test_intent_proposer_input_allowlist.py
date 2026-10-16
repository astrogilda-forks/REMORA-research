# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""AS-010: the serialized provider input of every proposer path is allowlisted.

The intent prompt carries the task text, the closed resource lexicon and the
effect vocabulary. The derivation prompt carries the task, the call's
argument values and the transform names. Nothing else may reach a provider:
not thresholds, trust scores, grants, tokens, evidence outcomes or prior
decisions, even when those sit in the objects around the call.

Every test records the exact string handed to ``complete`` and compares it
with the string rebuilt from the declared allowlist, then checks that
sentinels held in everything that must stay out never appear.
"""
from __future__ import annotations

import inspect
import json
import string
from pathlib import Path

import pytest

from remora.toolcall.routing import intent_proposer as ip
from remora.toolcall.routing.goal_match import EFFECT_VOCABULARY
from remora.toolcall.routing.intent_proposer import (
    DERIVATION_PROMPT_FIELDS,
    DERIVATION_PROMPT_TEMPLATE,
    INTENT_PROMPT_FIELDS,
    INTENT_PROMPT_TEMPLATE,
    RecordReplayProvider,
    ReplayMiss,
    propose_derivations,
    propose_intent,
)

TASK = "Please find a bus from Oslo to Bergen and book a hotel there."
LEX = {"bus", "hotel", "flight"}
ARGS = {"city": "Bergen", "nights": 2}

# Values that live in the objects around a proposer call (policy, trust,
# grants, tenant, evidence, prior decisions, the tool under review). None of
# them is an input of any proposer entry point.
SENTINELS = (
    "SENT_POLICY_THRESHOLD_0.8731",
    "SENT_TRUST_SCORE_0.6619",
    "SENT_GRANT_TOKEN_eyJhbGciOiJ",
    "SENT_TENANT_SECRET_s3cr3t",
    "SENT_EVIDENCE_OUTCOME_REFUTED",
    "SENT_PRIOR_DECISION_ACCEPT",
    "SENT_PROPOSED_TOOL_book_hotel_9",
    "SENT_AVAILABLE_TOOL_cancel_all",
)


class Recorder:
    model_id = "fake-model"

    def __init__(self, response: str | Exception = '{"effect": null}') -> None:
        self.response = response
        self.prompts: list[str] = []

    def complete(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _expected_intent_prompt(task: str, lexicon: set[str]) -> str:
    return INTENT_PROMPT_TEMPLATE.format(
        effects=", ".join(sorted(EFFECT_VOCABULARY)),
        resources=", ".join(sorted(lexicon)), task=task,
    )


def _fields(template: str) -> set[str]:
    return {f for _, f, _, _ in string.Formatter().parse(template) if f}


def _assert_clean(prompts: list[str]) -> None:
    assert prompts, "the path never reached the provider"
    for prompt in prompts:
        for sentinel in SENTINELS:
            assert sentinel not in prompt


# -- the declared allowlist is pinned to the templates and signatures -------

def test_declared_fields_are_exactly_the_template_fields() -> None:
    assert INTENT_PROMPT_FIELDS == frozenset({"effects", "resources", "task"})
    assert DERIVATION_PROMPT_FIELDS == frozenset(
        {"transforms", "task", "arguments"})
    assert _fields(INTENT_PROMPT_TEMPLATE) == set(INTENT_PROMPT_FIELDS)
    assert _fields(DERIVATION_PROMPT_TEMPLATE) == set(DERIVATION_PROMPT_FIELDS)


def test_entry_point_signatures_have_no_slot_for_anything_else() -> None:
    assert list(inspect.signature(propose_intent).parameters) == [
        "task", "lexicon", "provider"]
    assert list(inspect.signature(propose_derivations).parameters) == [
        "task", "arguments", "provider", "transforms"]


def test_intent_prompt_never_carries_call_arguments() -> None:
    assert "arguments" not in INTENT_PROMPT_FIELDS


def test_no_other_prompt_template_exists_in_the_module() -> None:
    templates = {n for n, v in vars(ip).items()
                 if n.endswith("_PROMPT_TEMPLATE") and isinstance(v, str)}
    assert templates == {"INTENT_PROMPT_TEMPLATE",
                         "DERIVATION_PROMPT_TEMPLATE"}


# -- path 1: propose_intent, every kind of answer ---------------------------

@pytest.mark.parametrize("response", [
    '{"effect": null}',
    "not json",
    json.dumps({"effect": "search", "action_span": "find a bus",
                "resource": "bus", "resource_span": "a bus"}),
])
def test_intent_prompt_is_exactly_the_allowlisted_rendering(response) -> None:
    rec = Recorder(response)
    propose_intent(TASK, LEX, rec)
    assert rec.prompts == [_expected_intent_prompt(TASK, LEX)]
    _assert_clean(rec.prompts)


def test_intent_prompt_with_duplicate_and_unordered_lexicon() -> None:
    rec = Recorder()
    propose_intent(TASK, ["hotel", "bus", "bus", "flight"], rec)
    assert rec.prompts == [_expected_intent_prompt(TASK, LEX)]


# -- path 2: provider failure -----------------------------------------------

def test_provider_error_path_payload_is_allowlisted() -> None:
    rec = Recorder(RuntimeError("503"))
    assert propose_intent(TASK, LEX, rec).reason == "provider_error"
    assert rec.prompts == [_expected_intent_prompt(TASK, LEX)]
    _assert_clean(rec.prompts)


# -- path 3: record mode, miss then hit, inner provider payload -------------

def test_record_mode_forwards_only_the_allowlisted_prompt(tmp_path: Path) -> None:
    inner = Recorder()
    rec = RecordReplayProvider(tmp_path / "c.jsonl", model_id="fake-model",
                               mode="record", provider=inner)
    propose_intent(TASK, LEX, rec)
    propose_intent(TASK, LEX, rec)  # cache hit: no second provider call
    assert inner.prompts == [_expected_intent_prompt(TASK, LEX)]
    _assert_clean(inner.prompts)


def test_cache_file_holds_hashes_and_responses_not_inputs(tmp_path: Path) -> None:
    cache = tmp_path / "c.jsonl"
    rec = RecordReplayProvider(cache, model_id="fake-model", mode="record",
                               provider=Recorder('{"effect": null}'))
    propose_intent(TASK, LEX, rec)
    text = cache.read_text(encoding="utf-8")
    row = json.loads(text.splitlines()[0])
    assert set(row) == {"key", "model_id", "response"}
    assert TASK not in text


def test_provider_error_in_record_mode_sends_allowlisted_and_caches_nothing(
        tmp_path: Path) -> None:
    inner = Recorder(RuntimeError("boom"))
    rec = RecordReplayProvider(tmp_path / "c.jsonl", model_id="fake-model",
                               mode="record", provider=inner)
    assert propose_intent(TASK, LEX, rec).reason == "provider_error"
    assert inner.prompts == [_expected_intent_prompt(TASK, LEX)]
    assert not (tmp_path / "c.jsonl").exists()


# -- path 4: replay mode never reaches a provider ---------------------------

def test_replay_miss_sends_nothing(tmp_path: Path) -> None:
    inner = Recorder()
    rep = RecordReplayProvider(tmp_path / "none.jsonl", model_id="fake-model",
                               mode="replay", provider=inner)
    with pytest.raises(ReplayMiss):
        propose_intent(TASK, LEX, rep)
    with pytest.raises(ReplayMiss):
        propose_derivations(TASK, ARGS, rep, ["t"])
    assert inner.prompts == []


# -- path 5: propose_derivations, every kind of answer ----------------------

@pytest.mark.parametrize("response", [
    "[]", "nope", "{}", RuntimeError("boom"),
    json.dumps([{"argument": "city", "value": "Bergen",
                 "transform": "t", "source_span": "Bergen"}]),
])
def test_derivation_prompt_is_exactly_the_allowlisted_rendering(response) -> None:
    rec = Recorder(response)
    propose_derivations(TASK, ARGS, rec, ["b_t", "a_t"])
    expected = DERIVATION_PROMPT_TEMPLATE.format(
        transforms="a_t, b_t", task=TASK,
        arguments=json.dumps(ARGS, sort_keys=True, default=str))
    assert rec.prompts == [expected]
    assert "Bergen" in rec.prompts[0]  # argument values are allowed here
    _assert_clean(rec.prompts)


def test_derivation_record_mode_forwards_only_the_allowlisted_prompt(
        tmp_path: Path) -> None:
    inner = Recorder("[]")
    rec = RecordReplayProvider(tmp_path / "d.jsonl", model_id="fake-model",
                               mode="record", provider=inner)
    propose_derivations(TASK, ARGS, rec, ["t"])
    _assert_clean(inner.prompts)
    assert len(inner.prompts) == 1


# -- control: the sentinel check can fail -----------------------------------

def test_a_sentinel_reaches_the_prompt_only_through_an_allowlisted_slot() -> None:
    rec = Recorder()
    propose_intent(TASK + " " + SENTINELS[0], LEX, rec)
    assert SENTINELS[0] in rec.prompts[0]

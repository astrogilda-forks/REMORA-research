# SPDX-License-Identifier: BUSL-1.1
"""Semantic bundle v2: contract authoring, discriminative lexicon, extraction.

Each test pins one defect v1 had on the spent BFCL sets, or one safety rule
v2 must keep. Development numbers are in scripts/bfcl_dev_replay.py and may
not be cited as results.
"""
from __future__ import annotations

import ast
import hashlib
import json
import pathlib

import pytest

from remora.toolcall.routing import bfcl_semantic_bundle_v2 as v2
from remora.toolcall.routing.goal_match import GoalMatch, match_tool_to_intent

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _contract(tool, description=""):
    return v2.author_contract(tool, description)


# --- Role A: contracts from tool metadata -----------------------------------


@pytest.mark.parametrize(
    ("tool", "effect", "mutation", "resource"),
    [
        ("Trains_1_FindTrains", "read", False, "trains"),
        ("Hotels_2_BookHouse", "create", True, "house"),
        ("Movies_1_BuyMovieTickets", "create", True, "movie tickets"),
        ("RentalCars_3_GetCarsAvailable", "read", False, "cars"),
        ("Alarm_1_AddAlarm", "create", True, "alarm"),
    ],
)
def test_sgd_names_read_the_verb_after_the_domain_prefix(tool, effect, mutation, resource):
    c = _contract(tool)
    assert (c.effect, c.mutation, c.resource_type) == (effect, mutation, resource)
    assert c.capability == tool.split("_")[0].lower()


def test_a_description_that_writes_overrides_a_reading_name():
    c = _contract("RideSharing_2_GetRide", "Book a cab for the specified destination.")
    assert (c.effect, c.mutation) == ("create", True)


def test_a_reading_description_does_not_override_a_writing_name():
    c = _contract("Hotels_2_BookHouse", "Finds a house and books it.")
    assert c.mutation is True


def test_an_unclassifiable_tool_is_a_mutating_update():
    c = _contract("frobnicate_widget")
    assert (c.effect, c.mutation) == ("update", True)


def test_dotted_names_keep_the_class_as_resource_and_capability():
    c = _contract("game_rewards.get")
    assert c.effect == "read"
    assert c.resource_type == "game rewards"
    assert c.capability == "game rewards"


def test_description_object_becomes_an_alias():
    c = _contract("get_current_weather", "Retrieves the current weather conditions for a city.")
    assert "weather conditions" in c.resource_aliases


def test_author_contract_reads_no_task_text():
    tree = ast.parse((ROOT / "remora/toolcall/routing/bfcl_semantic_bundle_v2.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in {"author_contract", "author_bundle"}:
            names = {a.arg for a in node.args.args}
            assert not names & {"task", "task_text", "question", "user_task"}


# --- Lexicon -----------------------------------------------------------------


def test_lexicon_drops_verbs_and_stopwords():
    tools = ["get_time_to_collision", "Services_4_FindProvider"]
    bundle = v2.author_bundle(tools, {})
    lexicon = v2.resource_lexicon(bundle, tools)
    for junk in ("for", "find", "search", "get", "to"):
        assert junk not in lexicon


def test_lexicon_drops_phrases_two_tools_in_scope_share():
    tools = ["Movies_1_BuyMovieTickets", "Movies_1_GetTimesForMovie"]
    bundle = v2.author_bundle(tools, {})
    lexicon = v2.resource_lexicon(bundle, tools)
    # "movie" is a derived alias of both tools and the own resource of neither.
    assert "movie" not in lexicon
    assert lexicon["movie tickets"] == "Movies_1_BuyMovieTickets"


def test_a_tools_own_resource_outranks_another_tools_derived_alias():
    tools = ["Trains_1_FindTrains", "Trains_1_GetTrainTickets"]
    bundle = v2.author_bundle(tools, {})
    lexicon = v2.resource_lexicon(bundle, tools)
    assert lexicon["trains"] == "Trains_1_FindTrains"


def test_a_task_naming_two_tools_resources_grounds_no_intent():
    task = "I want to see the Avengers movie on 2023-10-06. Can I get three tickets for a 19:00 show?"
    tools = ["Movies_1_BuyMovieTickets", "Movies_1_FindMovies", "Movies_1_GetTimesForMovie"]
    _, intent = _intent(task, tools)
    assert intent is None


def test_a_shorter_phrase_inside_the_chosen_one_is_the_same_mention():
    tools = ["Movies_1_BuyMovieTickets", "Movies_1_FindMovies"]
    _, intent = _intent("Please book movie tickets for tonight", tools)
    assert intent is not None
    assert intent.resource_type == "movie tickets"


def test_a_phrase_is_discriminative_only_relative_to_the_tools_in_scope():
    bundle = v2.author_bundle(["Movies_1_FindMovies", "Movies_1_BuyMovieTickets"], {})
    alone = v2.resource_lexicon(bundle, ["Movies_1_FindMovies"])
    assert alone["movies"] == "Movies_1_FindMovies"


# --- Role B: intent extraction ----------------------------------------------


def _intent(task, tools, descriptions=None):
    bundle = v2.author_bundle(tools, descriptions or {})
    lexicon = v2.resource_lexicon(bundle, tools)
    return bundle, v2.extract_intent(task, lexicon, v2.full_resource_set(bundle, tools))


def test_negated_mutation_is_not_requested():
    _, intent = _intent("Do not cancel it, just show the booking", ["get_booking", "cancel_flight"])
    assert intent is not None
    assert intent.requested_effect == "read"


def test_negated_only_request_grounds_nothing():
    _, intent = _intent("Please do not cancel my booking", ["cancel_booking", "list_flights"])
    assert intent is None


def test_need_a_thing_is_not_a_read():
    _, intent = _intent("I need a ride to 123 Park Street", ["RideSharing_2_GetRide"],
                        {"RideSharing_2_GetRide": "Book a cab for the specified destination."})
    assert intent is None


def test_need_the_thing_is_a_read():
    _, intent = _intent("I need the access logs for project X", ["get_access_logs"])
    assert intent is not None
    assert (intent.requested_effect, intent.resource_type) == ("read", "access logs")


def test_a_strong_read_verb_beats_an_earlier_weak_cue():
    _, intent = _intent("I need to see all the servers. Could you fetch that list?", ["list_servers"])
    assert intent is not None
    assert intent.action_spans == ("see",)


def test_a_write_verb_outside_the_vocabulary_blocks_a_read_claim():
    _, intent = _intent("Buy 4 tickets for the show on Friday", ["Movies_1_BuyMovieTickets"])
    assert intent is None


def test_mutation_keyword_beats_weak_read_cue():
    _, intent = _intent("I want to cancel the reservation", ["cancel_reservation", "list_flights"])
    assert intent is not None
    assert intent.requested_effect == "cancel"


def test_find_trains_is_now_supported_where_v1_refuted_it():
    task = "Can you find me available trains departing from Anaheim to Berkeley?"
    bundle, intent = _intent(task, ["Trains_1_FindTrains", "Trains_1_GetTrainTickets"])
    result = match_tool_to_intent(contract=bundle.get("Trains_1_FindTrains"), intent=intent,
                                  proposed_args={}, task_text=task)
    assert result.verdict is GoalMatch.SUPPORTED


def test_the_wrong_tool_in_the_same_domain_is_refuted():
    task = "Book 2 train tickets from Portland to Seattle on April 22nd"
    bundle, intent = _intent(task, ["Trains_1_FindTrains", "Trains_1_GetTrainTickets"])
    result = match_tool_to_intent(contract=bundle.get("Trains_1_FindTrains"), intent=intent,
                                  proposed_args={}, task_text=task)
    assert result.verdict is GoalMatch.UNSUPPORTED


# --- v1 stays frozen ---------------------------------------------------------


def test_v1_bundle_is_byte_identical_to_the_sealed_c_ext3_manifest():
    manifest = json.loads((ROOT / "data/routing_bench_bfcl_v4_cext3/manifest.json").read_text(encoding="utf-8"))
    digest = hashlib.sha256((ROOT / "remora/toolcall/routing/bfcl_semantic_bundle.py").read_bytes()).hexdigest()
    assert digest == manifest["frozen_semantic_bundle_sha256"]

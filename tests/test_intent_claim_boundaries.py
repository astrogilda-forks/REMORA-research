# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""SDD-AS-v1 AS-011: coverage of intent and claim cases without new authority.

Existing tests pin negation, wrong resource and REFUTED escalation. This file
adds the four missing families. Every expected value is written by hand.

1. Paraphrase and alias positives, and the boundary where the deterministic
   extractor declines on purpose. Declining must never turn into SUPPORTED.
2. A claim made for one tenant is not accepted for another.
3. A task with two goals: a call that serves one goal does not cover both.
4. Monotonicity: UNKNOWN or weaker evidence cannot overwrite REFUTED.
"""
from __future__ import annotations

import itertools
from datetime import date
from pathlib import Path

import pytest

from remora.policy.decision_engine import RemoraDecisionEngine
from remora.policy.observation import PolicyObservation
from remora.policy.report import DecisionAction
from remora.toolcall.routing.bfcl_semantic_bundle import (
    author_contract,
    extract_intent,
)
from remora.toolcall.routing.compatibility import (
    ArgumentValueStatus,
    StateIndex,
    compute_compatibility,
)
from remora.toolcall.routing.coverage_declaration import (
    CoverageDeclaration,
    build_state_index,
)
from remora.toolcall.routing.goal_match import (
    GoalMatch,
    TaskIntent,
    match_tool_to_intent,
)
from remora.toolcall.routing.intent_proposer import (
    combine_goal_match,
    combine_intents,
)
from remora.toolcall.routing.tool_contract import ToolContract
from remora.toolcall.routing.tool_registry import ToolRegistry

LEXICON = {"booking", "hotel", "bus"}
FULL = frozenset(LEXICON)


def _verdict(tool: str, task: str, args: dict | None = None) -> GoalMatch:
    intent = extract_intent(task, set(LEXICON), FULL)
    return match_tool_to_intent(
        contract=author_contract(tool), intent=intent,
        proposed_args=args or {}, task_text=task,
    ).verdict


# ---------------------------------------------------------------------------
# 1. Paraphrase and alias positives
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("task, tool", [
    ("Please cancel booking B-104.", "cancel_booking"),
    ("Please terminate booking B-104.", "cancel_booking"),
    ("Abort the booking B-104 now.", "cancel_booking"),
    ("Remove booking B-104.", "delete_booking"),
    ("Erase booking B-104 from the system.", "delete_booking"),
    ("Show me booking B-104.", "get_booking"),
    ("I would like to see the bus options.", "find_bus"),
    ("Look up the hotel for me.", "get_hotel"),
])
def test_legitimate_rephrasing_is_supported(task: str, tool: str) -> None:
    assert _verdict(tool, task) is GoalMatch.SUPPORTED


def test_a_plural_contract_alias_grounds_the_singular_task_word() -> None:
    # author_contract lists "bookings" as an alias of "booking", so a tool whose
    # resource is declared in the plural still matches a singular task word.
    contract = ToolContract(
        tool="cancel_bookings", capability="booking_management",
        effect="cancel", resource_type="bookings", mutation=True,
        argument_roles={}, resource_aliases=("booking",),
    )
    task = "Cancel booking B-104."
    intent = extract_intent(task, {"booking"}, frozenset({"booking"}))
    result = match_tool_to_intent(
        contract=contract, intent=intent, proposed_args={}, task_text=task)
    assert result.verdict is GoalMatch.SUPPORTED


@pytest.mark.parametrize("task, tool", [
    # Inflected forms are not in EFFECT_VOCABULARY, so the extractor reads the
    # weak cue "need" and proposes a read. A cancel call is then refuted.
    # Declining a legitimate paraphrase is the conservative direction.
    ("I need booking B-104 cancelled.", "cancel_booking"),
    # "get rid of" is not a delete keyword; "get" reads as a read cue.
    ("Could you get rid of booking B-104?", "delete_booking"),
])
def test_unrecognised_paraphrase_is_never_supported_for_the_mutation(
    task: str, tool: str,
) -> None:
    assert _verdict(tool, task) is GoalMatch.UNSUPPORTED


# ---------------------------------------------------------------------------
# Negation survives extraction
# ---------------------------------------------------------------------------

# Known defect, found by this file. extract_intent hands goal matching only the
# bare keyword as the action span, so the "not" in "do not cancel" is lost and
# goal_match sees an unqualified "cancel". The fix belongs in
# bfcl_semantic_bundle.py, which is frozen by the sealed C-ext3 manifest (its
# SHA-256 gates run_bfcl_cext3.py), so it is recorded here rather than edited.
# strict=True makes the suite fail loudly when the defect is fixed, so this
# marker is removed with the fix.
_EXTRACTOR_DROPS_QUALIFIERS = pytest.mark.xfail(
    strict=True,
    reason="AS-011: extract_intent drops negation and conditionality; "
           "frozen file, owner decision needed",
)


@_EXTRACTOR_DROPS_QUALIFIERS
@pytest.mark.parametrize("task", [
    "Please do not cancel booking B-104.",
    "Never cancel booking B-104.",
    "Don't cancel booking B-104.",
])
def test_a_negated_mutation_is_never_supported(task: str) -> None:
    assert _verdict("cancel_booking", task) is not GoalMatch.SUPPORTED


@_EXTRACTOR_DROPS_QUALIFIERS
def test_a_conditional_mutation_is_never_supported() -> None:
    task = "Inspect booking B-104 before cancel."
    assert _verdict("cancel_booking", task) is not GoalMatch.SUPPORTED


@_EXTRACTOR_DROPS_QUALIFIERS
def test_negation_in_one_clause_does_not_hide_a_read_request() -> None:
    task = "Do not cancel booking B-104, just show me booking B-104."
    assert _verdict("get_booking", task) is GoalMatch.SUPPORTED
    assert _verdict("cancel_booking", task) is GoalMatch.UNSUPPORTED


# ---------------------------------------------------------------------------
# 2. Wrong tenant
# ---------------------------------------------------------------------------

def _tenant_snapshot(tmp_path: Path) -> Path:
    path = tmp_path / "banking.json"
    path.write_text('{"users": {"u1": {"user_id": "u1"}}}', encoding="utf-8")
    return path


def _tenant_declaration(snapshot: Path) -> CoverageDeclaration:
    import hashlib

    return CoverageDeclaration(
        domain="banking", tenant="tenant_a", entity_type="user",
        argument_role="user_id",
        source_snapshot_sha256=hashlib.sha256(snapshot.read_bytes()).hexdigest(),
        as_of=date(2026, 7, 31), completeness_basis="full export",
        curator="test", immutable=True,
    )


def test_a_claim_for_another_tenant_cannot_refute_a_value(tmp_path: Path) -> None:
    snapshot = _tenant_snapshot(tmp_path)
    declaration = _tenant_declaration(snapshot)
    registry = ToolRegistry()
    args = {"user_id": "u999"}

    own = build_state_index((declaration,), {"banking": snapshot},
                            tenant="tenant_a")
    own_result = compute_compatibility(
        tool="get_user", args=args, registry=registry, state=own,
        domain="banking")
    assert own_result.argument_values_supported is False

    other = build_state_index((declaration,), {"banking": snapshot},
                              tenant="tenant_b")
    other_result = compute_compatibility(
        tool="get_user", args=args, registry=registry, state=other,
        domain="banking")
    # Tenant A's completeness claim buys nothing for tenant B: no verdict.
    assert other_result.argument_values_supported is None
    assert other_result.value_evidence is not None
    assert other_result.value_evidence.status is ArgumentValueStatus.UNKNOWN


def test_the_goal_match_carries_no_tenant_and_so_grants_no_cross_tenant_claim() -> None:
    # TaskIntent has no tenant field. Tenant binding lives in coverage
    # declarations and admission, not in goal matching, so a goal match is
    # only ever one input to the decision and never a tenant authorisation.
    assert "tenant" not in TaskIntent.__dataclass_fields__
    assert "tenant" not in ToolContract.__dataclass_fields__


# ---------------------------------------------------------------------------
# 3. Multi-goal tasks
# ---------------------------------------------------------------------------

def test_two_distinct_mutations_give_no_intent_and_so_no_support() -> None:
    task = "Delete booking B-104 and cancel the hotel."
    assert extract_intent(task, set(LEXICON), FULL) is None
    assert _verdict("delete_booking", task) is GoalMatch.UNKNOWN
    assert _verdict("cancel_hotel", task) is GoalMatch.UNKNOWN


def test_a_call_for_the_secondary_goal_is_not_covered_by_the_primary() -> None:
    # The leading verb states the request: this is a cancel of the booking.
    task = "Cancel booking B-104 and show me the hotel."
    assert _verdict("cancel_booking", task) is GoalMatch.SUPPORTED
    assert _verdict("get_hotel", task) is GoalMatch.UNSUPPORTED


def test_a_mutation_named_second_is_not_covered_by_a_leading_read() -> None:
    task = "Show me booking B-104 and cancel the hotel."
    assert _verdict("get_booking", task) is GoalMatch.SUPPORTED
    assert _verdict("cancel_hotel", task) is GoalMatch.UNSUPPORTED


def test_one_intent_cannot_cover_two_resources() -> None:
    both = TaskIntent(
        operation="cancel", resource_type="booking", requested_effect="cancel",
        source_spans=("booking B-104", "hotel H-7"),
        action_spans=("cancel",),
    )
    task = "Cancel booking B-104 and hotel H-7."
    assert match_tool_to_intent(
        contract=author_contract("cancel_booking"), intent=both,
        proposed_args={}, task_text=task).verdict is GoalMatch.SUPPORTED
    assert match_tool_to_intent(
        contract=author_contract("cancel_hotel"), intent=both,
        proposed_args={}, task_text=task).verdict is GoalMatch.UNSUPPORTED


# ---------------------------------------------------------------------------
# 4. Monotonicity: UNKNOWN cannot overwrite REFUTED
# ---------------------------------------------------------------------------

def _compat(values: list[tuple[str, str]]) -> bool | None:
    """Argument-value verdict for (argument, value) pairs, in the given order."""
    from remora.toolcall.routing.compatibility import CoverageScope

    scopes = (
        CoverageScope(domain="d", argument_names=frozenset({"closed_id"}),
                      closed_world=True),
        CoverageScope(domain="d",
                      argument_names=frozenset({"open_id", "other_id"}),
                      closed_world=False),
    )
    state = StateIndex.from_values({"known"}, scopes)
    return compute_compatibility(
        tool="t", args=dict(values), registry=ToolRegistry(), state=state,
        domain="d").argument_values_supported


def test_a_refuted_value_is_not_overwritten_by_unknown_or_supported() -> None:
    refuted = ("closed_id", "absent")    # closed world, absent: REFUTED
    unknown = ("open_id", "absent")      # open world, absent: UNKNOWN
    present = ("other_id", "known")      # open world, present: SUPPORTED
    assert _compat([refuted]) is False
    assert _compat([unknown]) is None
    assert _compat([present]) is True
    for order in itertools.permutations([refuted, unknown, present]):
        assert _compat(list(order)) is False, order


def test_a_refuted_goal_is_not_softened_by_a_later_unknown_signal() -> None:
    engine = RemoraDecisionEngine(low_consequence_accept=True,
                                  semantic_authority_floor=True)

    def decide(**kw):
        base = dict(question="show me booking B-104", action_type="read",
                    risk_tier="low", target_environment="staging",
                    trust_score=0.9, phase="ordered", schema_valid=True,
                    proposed_tool_name="cancel_booking")
        base.update(kw)
        return engine.decide(PolicyObservation(**base)).action

    refuted = decide(tool_matches_goal=False)
    assert refuted is DecisionAction.ABSTAIN
    # An unknown effect check beside a refuted goal match leaves it refuted.
    assert decide(tool_matches_goal=False,
                  expected_effect_matches=None) is DecisionAction.ABSTAIN
    # While an unknown goal match alone only asks for verification.
    assert decide(tool_matches_goal=None,
                  expected_effect_matches=None) is DecisionAction.VERIFY


def test_a_proposer_veto_cannot_turn_a_refuted_call_into_unknown() -> None:
    task = "Show me booking B-104."
    contract = author_contract("cancel_booking")
    det = TaskIntent(
        operation="read", resource_type="booking", requested_effect="read",
        source_spans=("booking B-104",), action_spans=("Show",))
    proposed = TaskIntent(
        operation="cancel", resource_type="booking",
        requested_effect="cancel",
        source_spans=("booking B-104",), action_spans=("Show",))

    def verdict(intent):
        return match_tool_to_intent(
            contract=contract, intent=intent, proposed_args={},
            task_text=task).verdict

    assert verdict(det) is GoalMatch.UNSUPPORTED
    # Intent-level combination vetoes to None, which reads as UNKNOWN. That is
    # the intended way to withdraw a SUPPORTED, so it stays as it is.
    assert combine_intents(det, proposed) is None
    assert verdict(combine_intents(det, proposed)) is GoalMatch.UNKNOWN
    # The verdict-level combination keeps the established refutation.
    assert combine_goal_match(
        contract=contract, deterministic=det, proposed=proposed,
        proposed_args={}, task_text=task).verdict is GoalMatch.UNSUPPORTED


def test_a_proposer_veto_still_withdraws_a_supported_call() -> None:
    task = "Please cancel booking B-104."
    contract = author_contract("cancel_booking")
    det = TaskIntent(
        operation="cancel", resource_type="booking", requested_effect="cancel",
        source_spans=("booking B-104",), action_spans=("cancel",))
    vetoing = TaskIntent(
        operation="read", resource_type="booking", requested_effect="read",
        source_spans=("booking B-104",), action_spans=("cancel",))
    assert combine_goal_match(
        contract=contract, deterministic=det, proposed=vetoing,
        proposed_args={}, task_text=task).verdict is GoalMatch.UNKNOWN
    # Agreement keeps the deterministic verdict.
    assert combine_goal_match(
        contract=contract, deterministic=det, proposed=det,
        proposed_args={}, task_text=task).verdict is GoalMatch.SUPPORTED
    # A silent proposer changes nothing, and a missing deterministic intent
    # is filled from the proposal, which then must verify on its own.
    assert combine_goal_match(
        contract=contract, deterministic=det, proposed=None,
        proposed_args={}, task_text=task).verdict is GoalMatch.SUPPORTED
    assert combine_goal_match(
        contract=contract, deterministic=None, proposed=det,
        proposed_args={}, task_text=task).verdict is GoalMatch.SUPPORTED
    assert combine_goal_match(
        contract=contract, deterministic=None, proposed=None,
        proposed_args={}, task_text=task).verdict is GoalMatch.UNKNOWN

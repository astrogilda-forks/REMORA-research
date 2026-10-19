# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Bundle v3: qualified mutations ground nothing (RMR-AUD-009).

The cases bundle v1 and v2 record as strict xfails in
``test_intent_claim_boundaries.py`` run here against v3 without xfail, with
the audit's three sentences. Every expected verdict is written by hand.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from remora.toolcall.routing import bfcl_semantic_bundle_v2 as v2
from remora.toolcall.routing import bfcl_semantic_bundle_v3 as v3
from remora.toolcall.routing.goal_match import GoalMatch, match_tool_to_intent

REPO_ROOT = Path(__file__).resolve().parent.parent
LEXICON = {"booking", "hotel", "bus", "policy"}
FULL = frozenset(LEXICON)


def _verdict(tool: str, task: str, module=v3) -> GoalMatch:
    intent = module.extract_intent(task, set(LEXICON), FULL)
    return match_tool_to_intent(
        contract=module.author_contract(tool), intent=intent,
        proposed_args={}, task_text=task,
    ).verdict


AUDIT_SENTENCES = [
    "Inspect booking B-104 before cancel.",
    "Tell me if I can cancel booking B-104.",
    "Review the policy before we cancel booking B-104.",
]


@pytest.mark.parametrize("task", AUDIT_SENTENCES)
def test_v2_supports_the_mutation_on_the_audit_sentences(task: str) -> None:
    """The defect as found: recorded so a change to frozen v2 is noticed."""
    assert _verdict("cancel_booking", task, module=v2) is GoalMatch.SUPPORTED


@pytest.mark.parametrize("task", AUDIT_SENTENCES + [
    "Please do not cancel booking B-104.",
    "Never cancel booking B-104.",
    "Don't cancel booking B-104.",
    "Can I cancel booking B-104?",
    "Is it possible to cancel booking B-104?",
    "Let me know whether we should cancel booking B-104.",
    "Show me booking B-104 so I can decide whether to cancel.",
])
def test_v3_a_qualified_mutation_is_never_supported(task: str) -> None:
    assert _verdict("cancel_booking", task) is not GoalMatch.SUPPORTED


@pytest.mark.parametrize("task", [
    "Tell me if I can cancel booking B-104.",
    "Review the policy before we cancel booking B-104.",
    "Do not cancel booking B-104, just show me booking B-104.",
    'The error message says "Cancel booking B-104" failed; show me booking B-104.',
    "The customer said to cancel booking B-104; show me booking B-104.",
    "The system failed to cancel booking B-104; show me booking B-104.",
])
def test_v3_the_information_request_is_the_read(task: str) -> None:
    assert _verdict("get_booking", task) is GoalMatch.SUPPORTED
    assert _verdict("cancel_booking", task) is GoalMatch.UNSUPPORTED


@pytest.mark.parametrize("task", [
    'The log contains "cancel booking B-104".',
    'Why did "cancel booking B-104" fail?',
    "Why did we cancel booking B-104?",
    "The customer said they might cancel booking B-104.",
    "According to the ticket, they might cancel booking B-104.",
    "The system failed to cancel booking B-104.",
])
def test_v3_quoted_and_reported_mutations_are_never_supported(task: str) -> None:
    assert _verdict("cancel_booking", task) is not GoalMatch.SUPPORTED


def test_v3_quoted_argument_still_supports_plain_mutation() -> None:
    assert _verdict("cancel_booking", 'Please cancel booking "B-104".') is GoalMatch.SUPPORTED


def test_v3_an_inspect_only_task_yields_no_intent() -> None:
    """"inspect" is a read cue, but the frozen vocabulary cannot ground it."""
    task = "Inspect booking B-104 before cancel."
    assert v3.extract_intent(task, set(LEXICON), FULL) is None
    assert _verdict("get_booking", task) is GoalMatch.UNKNOWN


@pytest.mark.parametrize("task", [
    "Please cancel booking B-104.",
    "Can you cancel booking B-104?",
    "If possible, cancel booking B-104.",
    "Cancel booking B-104 before Friday.",
    "Please terminate booking B-104.",
    "Abort the booking B-104 now.",
])
def test_v3_still_supports_a_plain_request(task: str) -> None:
    assert _verdict("cancel_booking", task) is GoalMatch.SUPPORTED


@pytest.mark.parametrize("task, tool", [
    ("Show me booking B-104.", "get_booking"),
    ("Look up the hotel for me.", "get_hotel"),
    ("I would like to see the bus options.", "find_bus"),
    ("Remove booking B-104.", "delete_booking"),
])
def test_v3_keeps_v2_verdicts_on_unqualified_tasks(task: str, tool: str) -> None:
    assert _verdict(tool, task) is _verdict(tool, task, module=v2)


def test_v3_action_spans_keep_context_and_quote_the_task() -> None:
    task = "Please cancel booking B-104."
    intent = v3.extract_intent(task, set(LEXICON), FULL)
    assert intent is not None
    assert intent.action_spans == ("Please cancel",)
    assert intent.proposed_by == "bfcl_semantic_bundle_v3"
    glued = "<<question>>Find the hotel"
    intent = v3.extract_intent(glued, set(LEXICON), FULL)
    assert intent is not None and intent.action_spans == ("Find",)


def test_v3_authors_contracts_exactly_as_v2() -> None:
    """Role A is v2's, re-exported: only intent extraction differs."""
    assert v3.author_contract is v2.author_contract
    assert v3.author_bundle is v2.author_bundle
    assert v3.resource_lexicon is v2.resource_lexicon


def test_v3_is_wired_into_no_sealed_runner() -> None:
    for script in ("run_bfcl_cext3.py", "run_bfcl_cext4.py", "build_bfcl_v4_cext4.py",
                   "replay_sealed_cext4.py"):
        assert "bundle_v3" not in (REPO_ROOT / "scripts" / script).read_text(encoding="utf-8")
    assert "bundle_v3" not in (
        REPO_ROOT / "remora" / "toolcall" / "routing" / "bfcl_arms.py"
    ).read_text(encoding="utf-8")


def test_dev_comparison_artifact_reproduces() -> None:
    artifact = json.loads(
        (REPO_ROOT / "artifacts/posthoc/bfcl_v3_extractor_dev_compare.json")
        .read_text(encoding="utf-8"))
    assert artifact["status"] == "post_hoc_development_only"
    for s in artifact["sets"].values():
        assert s["gold_accept_paired"]["a_only"] == 0
        for name in ("known_wrong_call_accept", "constructed_wrong_tool_accept"):
            assert s["metrics"][name]["v3"].startswith("0/")
    proc = subprocess.run(
        [sys.executable, "scripts/bfcl_v3_extractor_dev_compare.py", "--check"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=900,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr

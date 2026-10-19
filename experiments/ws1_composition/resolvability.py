# SPDX-License-Identifier: BUSL-1.1
"""WP0: what kind of gap blocks each development call (WS1 §13.1).

Three groups:

1. ``bounded_lookup``: a bounded lookup from a deployment-owned source
   settles the gap, and a fresh decision accepts the call.
2. ``contract_or_intent_gap``: the contract, intent vocabulary or source
   model is missing; no lookup the harness has can close it.
3. ``wrong_or_out_of_scope``: the call is not one the task needs. Only
   group 3 must stay blocked.

In the AgentDojo development harness the only deployment-owned source a
bounded lookup can read is the tool's own parameter schema, so group 1 means:
validating the exact arguments against that schema and deciding again gives
ACCEPT. The scripted agent proposes ground-truth calls only, so group 3 is
empty by construction on this data; that is a property of the agent, not
evidence that REMORA never blocks a wrong call.
"""
from __future__ import annotations

from collections.abc import Iterable

BOUNDED_LOOKUP = "bounded_lookup"
CONTRACT_GAP = "contract_or_intent_gap"
WRONG_CALL = "wrong_or_out_of_scope"

#: Reasons that record missing coverage rather than an affirmative fault.
_COVERAGE = {
    "semantic_authority_unknown_verify": "no_intent_or_goal_fit",
    "unknown_risk_tier_verify": "risk_tier_undeclared",
    "schema_unverified_verify": "schema_unverified",
    "malformed_call_blocked": "schema_invalid",
}


def classify(*, ground_truth: bool, action_after_lookup: str,
             reasons_after_lookup: Iterable[str]) -> tuple[str, str]:
    """(group, cause) for one blocked call."""
    reasons = tuple(reasons_after_lookup)
    if not ground_truth:
        return WRONG_CALL, "not_a_ground_truth_call"
    if action_after_lookup == "accept":
        return BOUNDED_LOOKUP, "schema_lookup_suffices"
    if "tool_does_not_match_goal" in reasons:
        # A ground-truth call refused as the wrong tool: the intent extractor
        # misread the task, so the gap is in the intent vocabulary.
        return CONTRACT_GAP, "intent_misread"
    causes = sorted({_COVERAGE[r] for r in reasons if r in _COVERAGE})
    return CONTRACT_GAP, "+".join(causes) if causes else "other:" + "+".join(reasons)

# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""What EFFECT_VERIFIED does not attribute (NEGATIVE_RESULTS §85).

The module's design rule says to compare the declared delta "against the
version your own write produced". ``verify_declared_delta`` takes no prior
state and no write identity, so under ``exact``, ``hash``, ``present`` and
``absent`` rules it cannot tell a delta this dispatch caused from one that
was already true, or that another writer produced. Only ``version_increment``
compares against a baseline, and it still does not name the writer.

These tests pin the current behaviour as a stated limit. They do not change
it: whether a contract must carry a baseline or a target-side operation id is
a design decision, not a fix.
"""

from __future__ import annotations

import inspect

from remora.governance.effect_verification import (
    EffectStatus,
    PostconditionContract,
    verify_declared_delta,
)

IDENTITY = {"proposal_id": "p-1", "execution_id": "e-1", "toolspec_hash": "t" * 64,
            "verifier_identity": "reader-1"}


def _contract(expected, rules=None):
    return PostconditionContract(tool_id="update_ticket", reader="ticket_reader",
                                 target_selector={"ticket": "T-1"},
                                 expected_fields=expected, comparison_rules=rules or {})


def test_the_verifier_has_no_input_for_prior_state_or_writer():
    params = set(inspect.signature(verify_declared_delta).parameters)
    assert not params & {"prior", "before", "baseline", "pre_state", "writer",
                         "operation_id", "target_revision"}


def test_an_exact_delta_that_was_already_true_verifies_like_one_the_dispatch_made():
    """Ticket already closed before dispatch (the tool did nothing), against a
    ticket the dispatch closed: the observation is the same, and so is the
    verdict."""
    contract = _contract({"status": "closed"})
    already_closed = verify_declared_delta(contract, {"status": "closed"}, **IDENTITY)
    closed_by_dispatch = verify_declared_delta(contract, {"status": "closed"}, **IDENTITY)
    assert already_closed.status is EffectStatus.VERIFIED
    assert already_closed.status is closed_by_dispatch.status
    assert already_closed.reason_code == closed_by_dispatch.reason_code
    assert already_closed.scope == "declared_delta_only"


def test_version_increment_compares_against_a_baseline_but_not_a_writer():
    """The one rule that binds to a change. Another writer's increment still
    satisfies it."""
    contract = _contract({"version": 6}, {"version": "version_increment"})
    unchanged = verify_declared_delta(contract, {"version": 6}, **IDENTITY)
    advanced = verify_declared_delta(contract, {"version": 7}, **IDENTITY)
    assert unchanged.status is EffectStatus.MISMATCH
    assert unchanged.reason_code == "postcondition_version_not_advanced"
    assert advanced.status is EffectStatus.VERIFIED

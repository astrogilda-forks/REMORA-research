# SPDX-License-Identifier: BUSL-1.1
"""VerificationPlan v2 S1 (types, construction-time refusal) and S2 (evidence check).

Design: docs/design/verification-plan-v2.md. Each binding field has its own
negative test: evidence that differs from the plan in that one field must not
count as SUPPORTED.
"""
from __future__ import annotations

import ast
import dataclasses
import pathlib
from datetime import UTC, datetime, timedelta, timezone
from types import MappingProxyType

import pytest

from remora.policy.verification_plan_v2 import (
    DEADLINE_SECONDS_CEILING,
    DEFAULT_DEADLINE_SECONDS,
    DEFAULT_MAX_LOOKUPS,
    MAX_LOOKUPS_CEILING,
    SCHEMA,
    EvidenceVerdict,
    PlanBinding,
    PlanOutcome,
    SourceEvidence,
    TargetBinding,
    TargetMode,
    TaskBudget,
    VerificationPlanV2,
    assess_evidence,
    parse_pointer,
    plan_outcome,
    resolve_pointer,
    value_digest,
)

MODULE = pathlib.Path(__file__).resolve().parents[1] / "remora/policy/verification_plan_v2.py"
T0 = datetime(2026, 10, 17, 12, 0, tzinfo=UTC)
NOW = T0 + timedelta(seconds=30)
D = {c: "sha256:" + c * 64 for c in "abcdef0123"}
CONTRACTS = frozenset({"crm.lookup_customer/v1", "ledger.balance/v1"})
CALL = {"customer_id": "C-17", "amount": 125.5, "lines": [{"sku": "x"}]}


def _binding(**over):
    base = dict(
        tenant_id="t1", principal="agent-7", task_ref="task-42",
        original_call_digest=D["a"], policy_digest=D["b"], toolspec_digest=D["c"],
        authority_epoch=3,
    )
    base.update(over)
    return PlanBinding(**base)


def _target(pointer="/customer_id", mode=TargetMode.VALIDATE_EXISTING, **over):
    base = dict(
        pointer=pointer, mode=mode, source_contract="crm.lookup_customer/v1",
        predicate="customer_exists", source_call_digest=D["d"],
    )
    base.update(over)
    return TargetBinding(**base)


def _plan(targets=None, **over):
    base = dict(
        plan_id="plan-1", issued_at=T0, expires_at=T0 + timedelta(seconds=120),
        binding=_binding(), budget=TaskBudget(),
        targets=targets if targets is not None else (_target(),),
    )
    base.update(over)
    return VerificationPlanV2(**base)


def _evidence(plan=None, *, value="C-17", **over):
    plan = plan or _plan()
    t = plan.targets[0]
    base = dict(
        plan_id=plan.plan_id, pointer=t.pointer, source_contract=t.source_contract,
        predicate=t.predicate, source_call_digest=t.source_call_digest,
        tenant_id=plan.binding.tenant_id, task_ref=plan.binding.task_ref,
        authority_epoch=plan.binding.authority_epoch, value_digest=value_digest(value),
        verdict=EvidenceVerdict.SUPPORTED, observed_at=T0 + timedelta(seconds=10),
    )
    base.update(over)
    return SourceEvidence(**base)


def _assess(plan, evidence, **over):
    kw = dict(call_arguments=CALL, accepted_contracts=CONTRACTS, now=NOW)
    kw.update(over)
    return assess_evidence(plan, evidence, **kw)


# --- S1: construction-time refusal -------------------------------------------


def test_a_well_formed_plan_builds_and_serialises():
    plan = _plan()
    body = plan.to_json_dict()
    assert body["schema"] == SCHEMA
    assert body["budget_ref"] == ["t1", "task-42"]
    assert body["targets"][0]["mode"] == "validate_existing"
    assert body["budget"] == {"max_lookups": 8, "deadline_seconds": 120}


def test_default_budget_is_the_adr_d8_value():
    assert (DEFAULT_MAX_LOOKUPS, DEFAULT_DEADLINE_SECONDS) == (8, 120)
    assert (MAX_LOOKUPS_CEILING, DEADLINE_SECONDS_CEILING) == (32, 600)
    assert TaskBudget() == TaskBudget(8, 120)


@pytest.mark.parametrize(
    "kw",
    [
        {"max_lookups": 0}, {"max_lookups": -1}, {"max_lookups": 33},
        {"max_lookups": True}, {"max_lookups": 2.0}, {"deadline_seconds": 0},
        {"deadline_seconds": 601}, {"deadline_seconds": False},
        {"deadline_seconds": "120"},
    ],
)
def test_budget_refuses_non_positive_bool_or_over_ceiling(kw):
    with pytest.raises(ValueError):
        TaskBudget(**kw)


def test_budget_accepts_the_ceiling_itself():
    assert TaskBudget(32, 600).max_lookups == 32


def test_empty_targets_are_refused():
    with pytest.raises(ValueError, match="non-empty"):
        _plan(targets=())


def test_targets_must_be_a_tuple_not_a_list():
    with pytest.raises(ValueError, match="tuple"):
        _plan(targets=[_target()])


def test_a_non_target_in_targets_is_refused():
    with pytest.raises(ValueError, match="TargetBinding"):
        _plan(targets=(_target(), "/amount"))


def test_duplicate_pointers_are_refused():
    with pytest.raises(ValueError, match="overlaps"):
        _plan(targets=(_target(), _target(predicate="other")))


def test_nested_pointers_overlap_and_are_refused():
    with pytest.raises(ValueError, match="overlaps"):
        _plan(targets=(_target("/lines"), _target("/lines/0/sku")))


def test_more_targets_than_the_lookup_budget_is_refused():
    targets = tuple(_target(f"/a{i}") for i in range(3))
    with pytest.raises(ValueError, match="max_lookups=2"):
        _plan(targets=targets, budget=TaskBudget(max_lookups=2))


@pytest.mark.parametrize(
    "over",
    [
        {"schema": "remora-verification-plan/v1"},
        {"plan_id": ""}, {"plan_id": " plan"}, {"plan_id": 7},
        {"issued_at": datetime(2026, 10, 17, 12)},
        {"expires_at": T0}, {"expires_at": T0 - timedelta(seconds=1)},
        {"expires_at": T0 + timedelta(seconds=121)},
        {"binding": "t1"}, {"budget": 8},
    ],
)
def test_plan_refuses_malformed_fields(over):
    with pytest.raises(ValueError):
        _plan(**over)


@pytest.mark.parametrize(
    "over",
    [
        {"tenant_id": ""}, {"principal": None}, {"task_ref": "task "},
        {"original_call_digest": "sha256:" + "A" * 64},
        {"policy_digest": "md5:" + "a" * 32}, {"toolspec_digest": D["a"][:-1]},
        {"authority_epoch": -1}, {"authority_epoch": True}, {"authority_epoch": 1.0},
    ],
)
def test_binding_refuses_malformed_fields(over):
    with pytest.raises(ValueError):
        _binding(**over)


@pytest.mark.parametrize(
    "over",
    [
        {"pointer": ""}, {"pointer": "customer_id"}, {"pointer": "/a~2"},
        {"pointer": "/a~"}, {"mode": "validate_existing"}, {"source_contract": ""},
        {"predicate": " p"}, {"source_call_digest": "sha256:xyz"},
    ],
)
def test_target_refuses_malformed_fields(over):
    with pytest.raises(ValueError):
        _target(**over)


def test_plans_are_frozen():
    plan = _plan()
    with pytest.raises(dataclasses.FrozenInstanceError):
        plan.plan_id = "other"  # type: ignore[misc]


def test_liveness_is_half_open_and_needs_an_aware_clock():
    plan = _plan()
    assert plan.is_live(now=T0)
    assert not plan.is_live(now=T0 - timedelta(microseconds=1))
    assert not plan.is_live(now=plan.expires_at)
    with pytest.raises(ValueError):
        plan.is_live(now=datetime(2026, 10, 17, 12, 0, 30))


def test_call_problems_separate_the_two_modes():
    plan = _plan(targets=(
        _target("/customer_id"),
        _target("/currency", TargetMode.RESOLVE_MISSING),
        _target("/missing", TargetMode.VALIDATE_EXISTING),
        _target("/amount", TargetMode.RESOLVE_MISSING),
    ))
    assert plan.call_problems(CALL) == (
        "validate_target_absent:/missing", "resolve_target_present:/amount",
    )


# --- JSON pointer and value digest -------------------------------------------


def test_pointer_unescapes_in_rfc_6901_order():
    assert parse_pointer("/a~1b/c~0d/~01") == ("a/b", "c~d", "~1")


def test_resolve_pointer_handles_objects_arrays_and_absence():
    assert resolve_pointer(CALL, "/lines/0/sku") == (True, "x")
    assert resolve_pointer(CALL, "/lines/1") == (False, None)
    assert resolve_pointer(CALL, "/lines/01") == (False, None)
    assert resolve_pointer(CALL, "/lines/-") == (False, None)
    assert resolve_pointer(CALL, "/customer_id/0") == (False, None)
    assert resolve_pointer({"": 1}, "/") == (True, 1)


def test_value_digest_is_canonical_and_domain_tagged():
    assert value_digest({"b": 1, "a": [1.5, None]}) == value_digest(
        MappingProxyType({"a": (1.5, None), "b": 1})
    )
    assert value_digest("1") != value_digest(1)
    assert value_digest(True) != value_digest(1)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), {1: "x"}, {"a": {1, 2}}, b"x"])
def test_value_digest_refuses_values_without_a_canonical_form(bad):
    with pytest.raises(ValueError):
        value_digest(bad)


# --- S2: the evidence check --------------------------------------------------


def test_matching_evidence_counts_as_its_verdict():
    plan = _plan()
    result = _assess(plan, _evidence(plan))
    assert result.effective is EvidenceVerdict.SUPPORTED
    assert result.mismatches == ()
    refuted = _assess(plan, _evidence(plan, verdict=EvidenceVerdict.REFUTED))
    assert refuted.effective is EvidenceVerdict.REFUTED


@pytest.mark.parametrize(
    ("over", "mismatch"),
    [
        ({"tenant_id": "t2"}, "tenant"),
        ({"value_digest": value_digest("C-18")}, "value"),
        ({"source_contract": "ledger.balance/v1"}, "source_contract"),
        ({"predicate": "customer_active"}, "predicate"),
        ({"source_call_digest": D["e"]}, "source_call"),
        ({"task_ref": "task-43"}, "task"),
        ({"authority_epoch": 4}, "authority_epoch"),
        ({"plan_id": "plan-2"}, "plan_id"),
        ({"pointer": "/amount"}, "pointer_not_in_plan"),
    ],
)
def test_each_binding_mismatch_makes_supported_evidence_unknown(over, mismatch):
    plan = _plan()
    result = _assess(plan, _evidence(plan, **over))
    assert mismatch in result.mismatches
    assert result.reported is EvidenceVerdict.SUPPORTED
    assert result.effective is EvidenceVerdict.UNKNOWN


def test_a_contract_outside_the_registry_is_self_asserted():
    plan = _plan(targets=(_target(source_contract="attacker.says_yes/v1"),))
    result = _assess(plan, _evidence(plan))
    assert result.mismatches == ("source_not_accepted",)
    assert result.effective is EvidenceVerdict.UNKNOWN


@pytest.mark.parametrize(
    ("over", "now", "mismatch"),
    [
        ({}, T0 + timedelta(seconds=120), "plan_not_live"),
        ({"observed_at": T0 - timedelta(seconds=1)}, NOW, "observed_outside_plan_window"),
        ({"observed_at": T0 + timedelta(seconds=120)}, T0 + timedelta(seconds=119),
         "observed_outside_plan_window"),
        ({"observed_at": NOW + timedelta(seconds=1)}, NOW, "observed_in_future"),
    ],
)
def test_expired_plans_and_out_of_window_evidence_do_not_count(over, now, mismatch):
    plan = _plan()
    result = _assess(plan, _evidence(plan, **over), now=now)
    assert mismatch in result.mismatches
    assert result.effective is EvidenceVerdict.UNKNOWN


def test_evidence_times_compare_across_timezones():
    plan = _plan()
    oslo = timezone(timedelta(hours=2))
    result = _assess(plan, _evidence(plan, observed_at=(T0 + timedelta(seconds=5)).astimezone(oslo)))
    assert result.mismatches == ()


def test_validate_target_absent_from_the_call_is_unavailable():
    plan = _plan()
    result = _assess(plan, _evidence(plan), call_arguments={"amount": 1})
    assert result.mismatches == ("value_unavailable",)


def test_resolve_missing_judges_the_supplied_value_not_the_call():
    plan = _plan(targets=(_target("/currency", TargetMode.RESOLVE_MISSING),))
    ok = _assess(plan, _evidence(plan, value="NOK"), resolved_values={"/currency": "NOK"})
    assert ok.effective is EvidenceVerdict.SUPPORTED
    swapped = _assess(plan, _evidence(plan, value="NOK"), resolved_values={"/currency": "EUR"})
    assert swapped.mismatches == ("value",)
    absent = _assess(plan, _evidence(plan, value="NOK"))
    assert absent.mismatches == ("value_unavailable",)


def test_resolve_missing_refuses_a_pointer_the_call_already_has():
    plan = _plan(targets=(_target("/amount", TargetMode.RESOLVE_MISSING),))
    result = _assess(plan, _evidence(plan, value=1), resolved_values={"/amount": 1})
    assert "resolve_target_present" in result.mismatches


def test_an_undigestible_resolved_value_does_not_count():
    plan = _plan(targets=(_target("/currency", TargetMode.RESOLVE_MISSING),))
    result = _assess(plan, _evidence(plan), resolved_values={"/currency": float("nan")})
    assert result.mismatches == ("value_not_digestible",)


@pytest.mark.parametrize(
    "over",
    [
        {"verdict": "supported"}, {"verdict": True}, {"value_digest": "C-17"},
        {"observed_at": datetime(2026, 10, 17, 12)}, {"authority_epoch": True},
        {"pointer": "amount"}, {"tenant_id": ""},
    ],
)
def test_source_evidence_refuses_malformed_fields(over):
    with pytest.raises(ValueError):
        _evidence(**over)


# --- plan outcome ------------------------------------------------------------


def _two_target_plan():
    return _plan(targets=(
        _target("/customer_id"),
        _target("/amount", source_contract="ledger.balance/v1", predicate="within_limit",
                source_call_digest=D["f"]),
    ))


def _ev(plan, index, value, verdict=EvidenceVerdict.SUPPORTED):
    t = plan.targets[index]
    return _evidence(plan, value=value, pointer=t.pointer, source_contract=t.source_contract,
                     predicate=t.predicate, source_call_digest=t.source_call_digest,
                     verdict=verdict)


def test_every_target_supported_is_the_only_supported_outcome():
    plan = _two_target_plan()
    assessments = [_assess(plan, _ev(plan, 0, "C-17")), _assess(plan, _ev(plan, 1, 125.5))]
    result = plan_outcome(plan, assessments)
    assert result.outcome is PlanOutcome.SUPPORTED
    assert dict(result.reasons) == {}


def test_a_missing_target_abstains():
    plan = _two_target_plan()
    result = plan_outcome(plan, [_assess(plan, _ev(plan, 0, "C-17"))])
    assert result.outcome is PlanOutcome.ABSTAIN
    assert dict(result.reasons) == {"/amount": "no_evidence"}


def test_unbound_evidence_abstains_rather_than_supports():
    plan = _two_target_plan()
    result = plan_outcome(plan, [
        _assess(plan, _ev(plan, 0, "C-17")),
        _assess(plan, _ev(plan, 1, 999)),
    ])
    assert result.outcome is PlanOutcome.ABSTAIN
    assert dict(result.reasons) == {"/amount": "unknown"}


def test_a_clean_refutation_blocks_even_when_other_targets_are_supported():
    plan = _two_target_plan()
    result = plan_outcome(plan, [
        _assess(plan, _ev(plan, 0, "C-17")),
        _assess(plan, _ev(plan, 1, 125.5, EvidenceVerdict.REFUTED)),
    ])
    assert result.outcome is PlanOutcome.REFUTED


def test_conflicting_evidence_for_one_target_is_neither_answer():
    plan = _two_target_plan()
    result = plan_outcome(plan, [
        _assess(plan, _ev(plan, 0, "C-17")),
        _assess(plan, _ev(plan, 0, "C-17", EvidenceVerdict.REFUTED)),
        _assess(plan, _ev(plan, 1, 125.5)),
    ])
    assert result.outcome is PlanOutcome.ABSTAIN
    assert dict(result.reasons) == {"/customer_id": "conflicting_evidence"}


def test_assessments_for_foreign_pointers_are_ignored():
    plan = _plan()
    other = _two_target_plan()
    foreign = _assess(other, _ev(other, 1, 125.5))
    result = plan_outcome(plan, [foreign, _assess(plan, _evidence(plan))])
    assert result.outcome is PlanOutcome.SUPPORTED


def test_outcome_reasons_are_read_only():
    plan = _two_target_plan()
    result = plan_outcome(plan, [])
    with pytest.raises(TypeError):
        result.reasons["/amount"] = "x"  # type: ignore[index]


# --- isolation ---------------------------------------------------------------


def test_module_imports_only_the_standard_library_and_reads_no_clock():
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
        if isinstance(node, ast.Attribute):
            assert node.attr not in {"now", "utcnow", "today", "time", "monotonic"}, node.attr
    assert imported <= {
        "__future__", "hashlib", "json", "math", "re", "collections", "dataclasses",
        "datetime", "enum", "types", "typing",
    }

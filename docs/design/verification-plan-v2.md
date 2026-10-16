# VerificationPlan v2: explicit bindings, a task budget, typed source evidence

- Status: S1 and S2 implemented (2026-10-17) in
  `remora/policy/verification_plan_v2.py`, tested by
  `tests/test_verification_plan_v2.py`. Nothing emits or consumes v2 plans
  yet; S3 to S5 are open.
- Code it would change: `remora/policy/resolution.py`,
  `remora/policy/decision_engine.py` (`_argument_gate_report`),
  `remora/policy/report.py`, `servers/execution_api.py`
  (`_resolution_plan_for`), `remora/sdk/models.py` (`ResolutionPlan`).
- Requirements: SDD-AS-v1 WP-02, AS-007 (valid, bounded plan), AS-008
  (authoritative answer to the right fact), AS-009 (no shortcut through
  VERIFY).
- Related: `docs/design/evidence-admission-v1.md`,
  `docs/design/authority-preserving-capability-mediation-v1.md`

## Why a new version

A VERIFY that carries a `ResolutionPlan` is the one place REMORA lets a
machine step act before the decision is final. B02 (#862) made the v1 plan
refuse malformed fields. Four weaknesses remain in the code as it stands:

1. **Positional source choice.** Both `validate_and_reenter` and
   `resolve_and_reenter` pick `source_tools[min(index, len - 1)]`. The pairing
   of argument and source is an accident of list order, and every argument
   past the last source falls back to that last source.
2. **No expiry and no total budget.** `max_attempts` is checked per fact with
   `assert_within_budget(1)`. Nothing bounds a task as a whole, and a new plan,
   a sub-agent or a retry starts from zero.
3. **The validator never sees the value.** It is called as
   `validator(source_tool, argument_name)` and returns a bare `bool | None`.
   A true answer about a different value, tenant or entity is
   indistinguishable from the right one.
4. **Nothing binds the plan.** The plan names no tenant, principal, task,
   original call, policy, ToolSpec or authority epoch. A plan cannot tell
   whether it is being redeemed in the context that produced it.

Re-entry itself is sound and is kept: after a lookup, the whole decision
engine runs again on a fresh observation (`resolution.py` module docstring).

## The v2 plan

A plan is a frozen, versioned value. Construction refuses anything malformed,
as v1 does after B02.

```
VerificationPlanV2
  schema: "remora-verification-plan/v2"
  plan_id, issued_at, expires_at
  binding: tenant_id, principal, task_ref, original_call_digest,
           policy_digest, toolspec_digest, authority_epoch
  budget_ref: (tenant_id, task_ref)
  targets: tuple[TargetBinding, ...]   # non-empty, unique pointers

TargetBinding
  pointer: RFC 6901 JSON pointer into the call arguments
  mode: VALIDATE_EXISTING | RESOLVE_MISSING
  source_contract: id in the deployment's source-contract registry
  predicate: one of the contract's declared predicates
  source_call_digest: digest of the exact read the source will perform
```

Each target names its own source contract. There is no list to index into, so
the positional fallback cannot exist. A source contract is deployment-owned
configuration, like a signed ToolSpec: it names the read-only tool, the
predicates it can answer, and the capability the lookup runs under. Model
text cannot name or choose a source.

`VALIDATE_EXISTING` never changes an argument value. `RESOLVE_MISSING` fills
only a pointer that is absent from the call, and the result is a new proposal
with a new call digest. The two modes are separate code paths, not a flag on
one path.

## Typed source evidence (AS-008)

The lookup returns a record, not a boolean:

```
SourceEvidence
  plan_id, pointer, source_contract, predicate, source_call_digest
  tenant_id, task_ref, authority_epoch
  value_digest          # digest of the value the source judged
  verdict: SUPPORTED | REFUTED | UNKNOWN
  observed_at
```

Before re-entry, every field is compared with the plan and with the call.
Any mismatch in tenant, value, source, predicate, call, task or epoch means
the evidence does not count as SUPPORTED. Expired or self-asserted evidence is
refused. The comparison reuses the evidence-admission discipline: trust comes
from the deployment's source registry, never from the evidence itself.

## The task budget (AS-007)

Lookups draw from one durable budget per `(tenant_id, task_ref)`. The
reservation is atomic and happens when the plan is admitted, before any
lookup runs. This is the same order the capability mediator uses since B03.
A new plan, a sub-agent or a retry under the same task draws from the same
budget, so none of them can reset it. The budget has a call count and a
deadline. Exhausting either is a terminal outcome for the plan.

The budget store needs a durable adapter in any profile that claims
durability, for the same reason the nonce and grant ledgers do.

## Outcomes after the lookup

| Lookup result | What happens next |
|---|---|
| Every target SUPPORTED by matching evidence | New observation from trusted facts; the full engine decides again |
| Any target REFUTED | New observation with the value unsupported; the call is blocked, never retried into acceptance |
| UNKNOWN, conflict, timeout, budget exhausted, expired plan | ABSTAIN, or explicit human escalation where the policy says so; never ACCEPT |
| Evidence that fails the binding check | Treated as UNKNOWN, and the mismatch is recorded |

A token from the decision before the lookup must not authorize the call after
it. The token binds `observation_hash`, and re-entry changes the observation.
AS-009 asks for an end-to-end test that shows this with a counting executor,
rather than relying on the hash argument alone.

## Rollout

1. **S1, types and validation (AS-007).** `verification_plan_v2.py` with the
   two dataclasses and construction-time refusal: empty or duplicate targets,
   wrong types, non-positive budget, bool as int, expired plan. Pure; nothing
   emits or consumes v2 yet.
2. **S2, evidence check (AS-008).** `SourceEvidence` and the binding
   comparison, with a negative test for each of the seven fields.
3. **S3, durable task budget.** A reservation ledger with in-process, SQLite
   and Postgres adapters, contract-tested the way the outbox is.
4. **S4, engine and re-entry behind a flag.** The engine emits v2 plans when
   the flag is on; re-entry consumes them; AS-009 end-to-end tests run on
   both versions.
5. **S5, strict profile refuses v1.** Needs the owner's decision on the
   pilot/research split (AS-034/035). Until then v1 stays the default.

S1 and S2 touch no decision path. S4 changes `remora/policy/` and
`servers/execution_api.py` and needs its own review.

## Owner decisions

The owner answered the open questions in
`docs/architecture/ADR-sdd-as-v1-owner-decisions.md`:

- D7: the source-contract registry is signed like ToolSpecs. The code takes
  the accepted contracts as an argument and never trusts the evidence.
- D8: the default budget is 8 lookups and 120 s, the ceiling 32 and 600 s.
  Exhaustion is ABSTAIN.
- D9: the strict profile refuses v1 plans once S4 lands and AS-009 passes
  on v2.

## What S1 and S2 add beyond this note

- A plan may not outlive its budget deadline, and may not name more targets
  than its lookup budget allows.
- Target pointers must be disjoint. `/lines` and `/lines/0/sku` in one plan
  are refused, because one target could rewrite what another one judged.
- Value digests use their own domain tag. The evidence-admission form is not
  reused, because it refuses floats and call arguments carry them.
- `plan_outcome` folds assessments into SUPPORTED, REFUTED or ABSTAIN. Two
  assessments that disagree on one target are a conflict and count as
  neither answer.

## Not claimed

S1 and S2 are pure library code. No decision path uses them, so nothing
here changes what REMORA does today. The weaknesses listed above are read from the code
at the commit this note was written against.

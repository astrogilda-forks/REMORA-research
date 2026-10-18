# ADR: Meet composition replaces first-match in the decision engine (COMP-01)

- Status: accepted (2026-10-17)
- Deciders: repository owner, through SDD v1.3 (`docs/design/derived-information-flow-control-v1.md`, §3.9 and COMP-01)
- Extends: `docs/architecture/ADR-tainted-argument-floor-order.md`
- Implementation: `remora/policy/composition.py`, `RemoraDecisionEngine.decide`,
  `tests/policy/test_meet_composition.py`

## Context

The SDD requires P-MONO: no component may raise a decision above the cap
another component sets. The engine was a first-match cascade. The first
component that fired decided, and later components never ran. The ADR on the
tainted-argument floor order already fixed one instance of this: the taint
floor's VERIFY absorbed rollback and state-transition severity. That fix was
local; the pattern was not.

## Finding

A search over 30,000 generated observations in two engine configurations
found 1,784 first-match decisions that a stricter component group would
have changed. Every one has the same shape. The taint floor's VERIFY
(`tainted_argument_verify`) masked a conditional gate that demanded more:
- ESCALATE from `tool_does_not_match_goal`, `expected_effect_contradicted`,
  `env_mismatch_escalate` or `trap_escalate`;
- ABSTAIN from a goal or effect contradiction.

A VERIFY can be redeemed by an ordinary approver. The masked component
asked for a higher authority or a refusal, so that demand was lost, not only
its reason.

On the published sets nothing changes:
- 18 OPA golden cases;
- 700 tool-call benchmark tasks;
- 1,562 C-ext4 episodes;
- the 93 AROMER arena episodes.

One of the 2,799 C-ext3 episodes moves from VERIFY to ABSTAIN. No arm's
published count changes: the C-ext3 and C-ext4 reproduction checks and the
replication pack pass.

**What the SDD composes.** §3.9 writes `min(floor_cap, conditional_cap,
monitor_cap, protocol_cap)`, with one cap for the whole conditional-gate
group. A first implementation made every gate its own cap. That changed 24
of the 93 AROMER arena episodes. In 13 of them a benign call that the arena
expects to VERIFY became ESCALATE, because `minimax_escalate` then overruled
`evidence_insufficient` inside the same group. The order inside
`_CONDITIONAL_GATES` is a deliberate priority. The implementation therefore
composes groups: the conditional cap is the group's first gate, as in the
cascade, with the same §23 rule.

## Decision

`decide()` runs the existing cascade unchanged, then takes the meet over
four kinds of action:
- the cascade's result;
- the hard-guard floor;
- the conditional-gate group's first gate that fires;
- every external cap passed in `caps`.

Executability orders the actions as `ABSTAIN ≡ ESCALATE < VERIFY < ACCEPT`.
Ties keep the earliest component. A decision no group undercuts is returned
unchanged, reasons included. When one does, its action is the decision and
its reason is appended after the cascade's reasons.

External caps carry two new reason codes: `monitor_cap` for a learned
monitor or LLM judge, and `protocol_cap` for an RF-04 control protocol.
`explain()` takes the same caps and records a `meet_composition` row.
`composition.py` joins the policy bundle hash.

## Consequences

- Decisions change only in the stricter direction. Nothing that was blocked
  becomes executable, and nothing that was ESCALATE or ABSTAIN becomes
  VERIFY. `tests/policy/test_meet_composition.py` searches for a violation of
  that (P-MONO as a Hypothesis property).
- The decision-engine version label stays `RemoraDecisionEngine-v5`. The
  SDD reserves v6 for the flow rungs (IFC-05). The policy bundle hash, which
  is what the audit chain binds, changes with this commit. The precedent is
  the floor-order ADR, which also tightened routing without a label bump.
- Every published result reproduces unchanged. The comparison above found
  no change in a published count, and the sealed-replay CI job re-runs them
  on the PR.
- Inside the conditional group a VERIFY can still precede a later gate's
  ESCALATE (`test_priority_inside_the_conditional_group_is_kept`). That is
  the SDD's grouping, and it is now stated rather than implicit.
- The capabilities citing `decision_engine.py` (CAP-001, CAP-014, CAP-015,
  CAP-016) are re-audited in the same change.
- The SDD's §2 states the AgentHarm composition problem as "oracle recall
  1.0, engine recall 0.11". That counts only hard ESCALATE. Counting VERIFY,
  Mode 3 blocked 43 of 44 harmful tasks (`docs/review/PEER_REVIEW_FINDINGS.md`,
  R2). The P-MONO violation is still real. The oracle's ESCALATE became the
  engine's VERIFY, which an approver can redeem. The COMP-01 re-score
  measures it with both counts.

## Amendment (2026-10-18): RMR-AUD-003

The R3 audit of master `b64e3cc1` reproduced three ways a risk signal still
made a decision more executable. Each was reproduced again on `3746bc5d`
before the change.

1. **A VERIFY gate hid a later ESCALATE gate in the same group.** A critical
   production write with no rollback ESCALATEs (`rollback_unavailable`).
   With `distribution_shift_detected` it VERIFIED, because
   `distribution_shift` comes first in `_CONDITIONAL_GATES`. A high-risk
   write with an environment mismatch VERIFIED on `high_risk_no_evidence`,
   which fires on every high or critical call that carries no
   `evidence_action`, as on `/v1/execution`. That left
   `env_mismatch_escalate` and `critical_alternative` unreachable there.
2. **An ESCALATE hard guard hid a refusal review cannot lift.** A
   cross-tenant argument ABSTAINs with no review item. With
   `schema_valid=False`, `adversarial_detected` or `tool_forbidden` it
   ESCALATED and got one, because those guards come first in
   `hard_guard_floor` and the meet's tie kept the earlier component.
3. **A risk signal on a call that abstains for lack of evidence opened a
   review route.** A low-risk read with no trust signal is
   DEFAULT_SAFE_ABSTAIN. A tainted argument made it VERIFY and
   `schema_valid=False` made it ESCALATE.

**What changed.**
- `NON_APPROVABLE_REASONS` (`composition.py`): cross-tenant and unresolved
  intent provenance, the set the OPA adapter already keeps. Such an ABSTAIN
  ranks below ESCALATE in the meet, and `hard_guard_floor` is now the meet
  of every guard that fires. Executability keeps `ABSTAIN ≡ ESCALATE`
  otherwise.
- The conditional cap is the meet of every gate that fires. One COMP-01
  exception stays: `minimax_gate`, `trap_escalate` and `trap_verify` yield
  to the explicit risk matrix (`production_write_high_or_critical`,
  `high_risk_no_evidence`, `critical_risk_hard_verify`). Trap reads only
  the action type, domain and environment the matrix already decides on.
  Letting it overrule the matrix turned every high-risk production write
  into ESCALATE, against
  `test_production_write_matrix_is_explicit_and_conservative`, and it is
  the same case as the 13 AROMER arena calls above.
- `ADVERSARIAL_ALWAYS_ESCALATED` accepts ABSTAIN when a non-approvable
  refusal also applies. Escalating there would open the route the refusal
  denies. The firewall still blocks, and nothing it flags reaches ACCEPT or
  VERIFY.

**Measured effect.** Nothing became more executable.
- On 60,000 generated decisions (30,000 observations, two engine
  configurations), 17,166 changed. Every change is ESCALATE to a
  non-approvable ABSTAIN or VERIFY to ESCALATE. The generator draws a
  cross-tenant argument in a third of observations, so the count does not
  describe real traffic.
- C-ext3: 0 of 8,397 episode-arm decisions changed.
- C-ext4: all 36 published arm-metric counts reproduce
  (`replay_sealed_cext4.py --at working-tree`).
- The tool-call benchmark and the other 48 regenerable results reproduce
  (`reproduce_results.py`, the deterministic round). The COMP-01 AgentHarm
  re-score, the level-2 post-hoc artifact and the AROMER arena tests pass.
- The OPA golden cases were not run locally (no `opa` binary); CI's
  conformance job runs them.

**Open, recorded as strict xfails in `tests/policy/test_signal_monotonicity.py`.**
- Case 3 is not fixed. The hard guards and the conditional gates are the
  designed route to a person for calls with no trust signal. A first fix
  that made every ABSTAIN from the rest of the policy non-approvable failed
  239 tests, because it removed review from the execution path. Closing it
  needs an owner decision on what DEFAULT_SAFE_ABSTAIN means. The exploit
  in RMR-AUD-001 also needs the `/execute` request to differ from the
  assessed one; the review-path binding is the fix for that half.
- Raising a production write's risk tier from medium to high lowers it from
  ESCALATE (trap) to VERIFY (matrix). This was present on master before the
  change. Which of the two is right is an owner decision.
- SDD v1.3 §3.9 writes `ABSTAIN ≡ ESCALATE`. This amendment keeps that order
  and adds a rank below it for refusals no review can lift. On the
  execution path ESCALATE opens a review item and ABSTAIN does not, so the
  SDD's tie cannot be read as "equally blocking" there.

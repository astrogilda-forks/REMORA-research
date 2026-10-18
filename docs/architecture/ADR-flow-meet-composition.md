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

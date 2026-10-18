# Derived information-flow control: implementation status

This is the work list for `docs/design/derived-information-flow-control-v1.md`
(SDD v1.3, frozen 2026-10-17). It follows the SDD's release order (§10).
Each line moves to DONE only when every acceptance item of its work package
has a passing test on master; partial work stays IN_PROGRESS and names what
is missing. Changes to the SDD itself come only from implementation findings,
recorded as ADRs and listed at the end.

Statuses: NOT_STARTED, IN_PROGRESS, DONE, BLOCKED (with the reason).

## Release order

| Step | Work package | Priority | Status | PR | Missing / note |
|---|---|---|---|---|---|
| 1 | COMP-01 Meet composition and AgentHarm re-score | P0 | IN_PROGRESS | #907, #908 | Open PRs. The re-score's gain comes from the oracle cap, not from REMORA detecting harm (NEGATIVE_RESULTS §84). |
| 1 | IFC-01 Label lattice | P0 | IN_PROGRESS | #906 | Open PR; all acceptance items have tests. |
| 2 | IFC-02 Context store and minting | P0 | IN_PROGRESS | #910, #912 | Store (02a) and `POST /v1/contexts` (02b) in open PRs. |
| 2 | IFC-03 ToolSpec v4 `flow` block, linter, signing | P0 | IN_PROGRESS | #913, #914 | Parser and linter (03a); bundle load, FL-13 at startup and bundle hash (03b). Three fields beyond §5.1 are explained in `schemas/tool_spec_v4.yaml`. |
| 2 | IFC-04 Result labelling and handles | P0 | IN_PROGRESS | #915 | Labeler, handles and resolve (04a). Missing: dispatcher integration with commit-before-return and its fault-injection test (04b, `lease.py`), and the durable encrypted handle backend (AST-017). |
| 2 | IFC-05 Flow check and decision rungs | P0 | IN_PROGRESS | #916 | `recipients`, `flow_check`, `FlowVerdict` and the four mandatory invariant tests (05a). Missing: rungs F1 to F6, `RemoraDecisionEngine-v6`, Rego and OPA parity, whatif (05b). |
| 2 | IFC-06 Dispatch-time re-check | P0 | NOT_STARTED | | |
| 3 | IFC-11 Mediation completeness, execution API | P0 | NOT_STARTED | | |
| 3 | IFC-12 Enforced egress and network isolation | P0 | NOT_STARTED | | |
| 3 | IFC-13 Source provenance, M1 tools | P0 | NOT_STARTED | | |
| 3 | IFC-14 Labelled ingress, user turns | P1 | NOT_STARTED | | |
| 4 | M1 gate | gate | NOT_STARTED | | Nothing below starts before it passes (§10). |
| 5 | EVAL-01 AgentDojo substrate, arms A0–A3 | | NOT_STARTED | | |
| 6 | IFC-07 Extraction with capacity accounting | P1 | NOT_STARTED | | |
| 6 | IFC-08 Endorsement and grants | P1 | NOT_STARTED | | |
| 6 | IFC-09 Respond sink | P1 | NOT_STARTED | | |
| 6 | IFC-11 rest, IFC-13 rest, IFC-14 rest | | NOT_STARTED | | |
| 6 | IFC-10 Formal model | P1 | NOT_STARTED | | |
| 7 | EVAL-02 Adaptive white-box attacker | | NOT_STARTED | | |
| 7 | EVAL-03 Scheming-agent track | | NOT_STARTED | | |
| 7 | EVAL-04 / EVAL-05 Metrics and statistics | | NOT_STARTED | | |

## Baseline check

The SDD's §2 mapping was re-verified at master `203a6210` on 2026-10-17.
Every file exists, and every line reference names the definition the SDD
gives:

- `hard_guard_floor` and its taint rungs;
- `_registry_only_observation`;
- `DispatchResult` and `dispatch`;
- `canonical_tool_call_hash` and `decide`.

`LoopEvent` has no kind field. The loop fold ends at a `reset` marker.
`canonical_resource` refuses the `@` form of an email principal.
`CapabilityMediator` and `ResolvedEffectGraph` exist.
`ADR-sdd-as-v1-owner-decisions.md` has D4 for the isolation runtime.

## Relation to SAP v7

SAP v7 (`docs/assurance/statistical_analysis_plan_v7_control_eval.md`, draft)
was written before this SDD. Its harness and statistics are reused:

- the AgentDojo gated executor;
- the split rule;
- the budget guard;
- McNemar, the cluster bootstrap and AUROC.

Its REMORA arm, semantic bundle v2 with an intent proposer, is superseded
by the SDD's flow-control arms A1–A6 (§7.2). Its development dry run stays
the A1 baseline evidence: REMORA v5 blocked 90 of 91 legitimate calls.
Its Q3 composition question becomes COMP-01. Model calls wait for the SDD's
order: the 20-case pilot of §7.7 runs after M1. The owner's decisions of
2026-10-17 carry over to the SDD's `[FREEZE]` values:

- Claude via the API;
- at most 50 USD for the first stage;
- OSF registration.

The frontier model of §7.3 is therefore a Claude model.

## Implementation findings (ADRs)

None yet.

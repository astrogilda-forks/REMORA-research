# ADR: Pilot readiness is the maintainer's decision

- Status: **accepted** (2026-10-25, owner decision).
- Deciders: repository owner (the maintainer).
- Related: [`release_profiles_v1.yaml`](../assurance/release_profiles_v1.yaml),
  [`release_gates.md`](../assurance/release_gates.md),
  [`remediation_register.yaml`](../assurance/remediation_register.yaml)
  (REM-021, REM-023),
  [independent review protocol](../assurance/independent_review_protocol_v1.md),
  [external review panel](../assurance/external_review_panel_v1.md), SDD
  [unified capability execution v1.1](../design/unified-capability-execution-v1.1.md)
  §11 gate G11.

## Context

Until this decision the `CONTROLLED_PILOT` release profile required REM-021,
an independent human review by a reviewer outside the REMORA team, and
REM-023, whose one open step was the external confirmation of the RBAC
design. Both were written in 2026-06 and 2026-07, when the repository was a
research artefact with a prospective external panel. The maintainer owns the
code, the deployments and the pilot. On 2026-10-25 the owner directed, in
translation: "I decide when the code runs in a pilot. The code shall not
decide that it must be reviewed externally by anyone other than me as the
maintainer. The code shall have the status ready for pilot, without
blockers. I decide when and how the code is run and tested."

The repository's rule that a profile is computed from register state, never
claimed in prose, stays. What changes is which state the computation reads.

## Decision

1. `CONTROLLED_PILOT` no longer requires REM-021. It requires the technical
   gates that remain (REM-020, REM-022, REM-023 on their code and test
   criteria), the capability levels it always required, and this recorded
   owner decision: `owner_decision: OD-2026-10-25-controlled-pilot` in
   `release_profiles_v1.yaml`. CI refuses the profile when the decision is
   not recorded there with its date, its decider and this document.
2. REM-023 closes on steps 8 and 9 (the cross-tenant isolation test and the
   admin-wildcard removal, done 2026-07-03). Step 10, the external
   confirmation of the RBAC design, is no longer a closure criterion. It stays
   listed under REM-021 as work not done.
3. REM-021 stays open and `NOT_STARTED`, as a recorded fact: no independent
   review has taken place. It remains the gate for `EXTERNALLY_VERIFIED` on
   any capability and, through gate P3, for the `PRODUCTION` profile.
4. Running a pilot is an operational decision of the maintainer, taken
   outside this repository. The profile says the repository is ready for a
   controlled pilot; it does not say that one runs, and no running pilot is
   claimed anywhere in the repository until the maintainer records one.
5. Nothing here raises a capability status, a claim, or a benchmark result.
   Every mechanism keeps the status the evidence gives it.

## Consequences

- `current_profile` becomes `CONTROLLED_PILOT`, with
  `deployment_status_equivalent: CONTROLLED_PILOT`: the repository may be run
  as a controlled pilot. The generated status block, `release_gates.md`, the
  capability register header and the documents that quoted the earlier rule
  are updated in the same change. Dated review logs and the paper's revision
  of 2026-10-16 state the earlier rule and are not rewritten; this record
  supersedes them on this point.
- The pilot itself still needs the deployment prerequisites of the
  `controlled_pilot` runtime profile (signed ToolSpec bundle, durable state,
  signed and mandatory limits, idempotency contract, `REMORA_ENV=production`).
  The OT pilot under `deploy/ot-pilot/` is where they are configured.
- The independent review protocol and the panel matrix stay as written. They
  are how `EXTERNALLY_VERIFIED` is reached, not a precondition for the pilot.

## How to describe the profile

Four statements are kept apart, and only the first follows from this
decision: the owner permits a bounded pilot; the controls are tested
internally; a deployment is verified; an independent review has taken place.
`release_gates.md` keeps the table of which hold and what evidence each
needs. A text that says "ready for pilot" says the first statement only.

## What this ADR does not decide

It does not choose the pilot's customer, scope or duration (SDD ADR-UE-01),
does not change any enforcement path, and makes no claim about safety. A
future owner decision may add an independent review before a wider
enforcement profile; that is `LIMITED_ENFORCEMENT` and `PRODUCTION`, not this
profile.

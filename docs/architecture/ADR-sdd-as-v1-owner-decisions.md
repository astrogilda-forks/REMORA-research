# ADR: Owner decisions for SDD-AS-v1, REAS and VerificationPlan v2

- Status: **accepted** (2026-10-16)
- Deciders: repository owner, on the maintainer's recommendation
- Related: `docs/design/scoped-evidence-obligations-v1.md`,
  `docs/design/verification-plan-v2.md`, `remora/toolcall/runtime_profile.py`,
  `check_release_profiles()` in `scripts/check_document_governance.py`, `tests/test_intent_claim_boundaries.py`

## Context

The SDD-AS-v1 work programme and the REAS draft left nine questions that
code could not answer. Each one blocked a slice. The owner asked for the
recommended option on each. This record states the choice, the reason and
what it does not decide.

Two limits apply to every decision below. None of them spends money on model
runs, and none of them changes a sealed result or a published number.

## Decisions

### D1. The negation defect in the frozen BFCL extractor

`extract_intent` in `remora/toolcall/routing/bfcl_semantic_bundle.py` drops
negation and conditionals, so "do not cancel booking B-104" supports
`cancel_booking` (five strict xfails since #874).

- The file stays frozen. The sealed C-ext3 manifest pins its hash, and
  editing it would make the published run irreproducible.
- No deployment bundle uses this extractor. It is benchmark-only, so no
  live decision path is affected.
- The defect is recorded in `NEGATIVE_RESULTS.md` as a validity limit of the
  C-ext3 semantic arm. Whether any C-ext3 task is negated is not measured
  here; that is a new measurement.
- The next locked evaluation (D5) uses a new versioned extractor with
  negation and conditional handling. The xfails turn into passing tests
  against that version, and stay xfail against v1.

### D2. Who issues an obligation manifest (REAS O-2)

The deployment operator's security owner for the tenant issues manifests.
The effect producer never does. Manifests are deployment configuration,
held with the trust material that evidence admission already reads, and a
change is a new manifest version.

### D3. The authoritative inventory and its close (REAS O-1)

- For REMORA's own dispatches the inventory is the execution outbox, read
  through `rows_created_in` under a dedicated read-only service identity.
  That identity is the `writer` an `accepted_inventories` entry names.
- A scheduled reader closes a window at `window_end` plus the sum of the
  manifest's deadlines plus a fixed 60 s commit-skew margin, and records
  that instant as `closed_at`.
- External inventories are out of scope until a pilot tenant supplies one
  with its own writer identity.

### D4. Isolation runtime for the effect broker (AS-019/020)

- The reference runtime is an OCI container under gVisor (`runsc`) where the
  host provides it.
- Elsewhere, a rootless container with the default seccomp profile, no
  network unless the broker grants one, a read-only root and a single
  writable scratch mount.
- The broker reports which isolation it obtained. A strict pilot profile
  refuses to start on anything weaker than the second option.
- AS-019's malicious fixture runs in CI in the container variant, since
  hosted runners lack gVisor.

### D5. Fresh holdout and model runs (AS-012/026/027)

No paid model runs now. The locked-evaluation harness is built first:
pinned prompt hashes, a v2 identity record, a reject-all control that must
fail the utility gate, and pre-registered thresholds. The run itself
waits for a separate, budgeted go-ahead. Until then AS-026 and AS-027 stay
MISSING and PARTIAL, and nothing is claimed from them.

### D6. Pilot and research split (AS-034/035)

- The research profile stays the default and keeps v1 plans and the
  current semantics.
- `READY_FOR_SCOPED_PILOT` is a new release-gate verdict, computed from raw
  counts, not from booleans. It is reached only when every mandatory gate
  passes together.
- Strict contract v3 lives inside `controlled_pilot` and refuses to start
  without its prerequisites. There is no automatic fallback to v2 or
  research.
- Bare `strict` keeps its current meaning; v3 is opted into by name.

### D7. VerificationPlan v2 source contracts

The source-contract registry is deployment-owned and signed with the same
scheme as ToolSpecs. A source contract an unsigned or unknown key vouches
for is refused, as an unsigned ToolSpec is today.

### D8. VerificationPlan v2 task budget

Default budget: 8 lookups and 120 s per `(tenant_id, task_ref)`. A tenant
policy may lower both and may raise them only up to 32 lookups and 600 s.
Exhausting either is ABSTAIN. Escalation to a person happens only when
the tenant policy names the role that receives it.

### D9. When the strict profile refuses v1 plans

When slice S4 ships and the AS-009 end-to-end tests pass on v2 plans. Not
before, so no deployment loses a working VERIFY path without a replacement.

### D10. Major upgrade of `mcp` (Dependabot #859)

REMORA does not import `mcp`; it arrives transitively. The 1.x line takes
security fixes (1.30.0 fixes GHSA-84m7-p3x7-pcfv). Version 2 is a major
API change with no consumer here to test it, so semver-major updates of
`mcp` are ignored until a dependency requires them.

## Consequences

- D1, D5 and D6 change what REMORA may claim, not what it does today.
  Published results keep their numbers and gain a stated limit.
- D3, D7, D8 and D9 unblock the next REAS and VerificationPlan v2 slices.
- D4 and D6 define the acceptance bar for a scoped pilot release. Meeting it
  is future work; this record establishes nothing about readiness.

## Not decided here

Who the independent reviewer for AS-036 is, which pilot tenant comes first,
and the budget for the D5 run.

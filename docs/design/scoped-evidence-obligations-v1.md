# Scoped evidence obligations v1: bounded completeness over the outbox

- Status: proposal (2026-10-16)
- Code: `remora/evidence/obligations/`
- Tests: `tests/test_evidence_obligations.py`,
  `tests/test_evidence_obligations_properties.py`,
  `tests/test_evidence_obligations_isolation.py`
- Origin: REAS SDD v0.1.0 (private draft), stage G1 (SEO). Placement,
  canonicalisation and scope were corrected against the code before building:
  see "Deviations from the SDD" below.
- Related: `docs/design/evidence-admission-v1.md`,
  `docs/design/execution-lifecycle-outbox-v1.md`

## What this is

A read-only check of one question: in a closed dispatch window, did every
dispatch intent REMORA recorded leave the evidence it owes, by the deadline
fixed before the window opened?

```
manifest (locked before the window) ─┐
                                     ├─ assess(…, assessed_as_of) → ObligationAssessment
outbox rows → inventory snapshot ────┘        (pure: no clock, no store, no env)
```

Two obligation kinds exist in P1:

| Kind | Trigger | Satisfied when |
|---|---|---|
| `terminal_settlement` | intent recorded | the row reached SUCCEEDED, FAILED or REFUSED within `due_within_seconds` of creation |
| `downstream_projection` | terminal settled | `projected_at` is set within `due_within_seconds` of settlement |

## State per slot

| Situation | Slot state | Delivery |
|---|---|---|
| Settled or projected on time | SATISFIED | on_time |
| Settled or projected after the due time | MISSING | late |
| Nothing recorded, due time at or before the snapshot close | MISSING | none |
| Nothing recorded, due time after the snapshot close | PENDING | none |
| Reconciled to UNKNOWN | PENDING, observation `unobservable` | on_time or late |
| Projection slot on a row that never settled | NOT_APPLICABLE (`trigger_not_fired`) | none |
| Inconsistent row (unknown state, timestamps out of order or after close) | INVALID | none |
| Two rows with one record id or one idempotency key | CONFLICTED | none |

UNKNOWN stays PENDING because settling it needs read-back evidence of the
effect, which this slice does not have. REFUSED settles the intent and no
effect evidence is owed (SDD SEO-INV-006).

## Coverage and verdict

Coverage is `established_within_declared_scope` only when all of these hold;
otherwise it is `not_established` and every failed condition is listed:

- the manifest was created at or before `window_start` (expectations locked
  before the evidence they judge);
- a snapshot exists, its (kind, writer) is the one the manifest declares, and
  the deployment lists that pair in `accepted_inventories`. Trust comes from
  deployment configuration, never from the manifest or the snapshot;
- the snapshot is for the manifest's tenant, contains no other tenant's rows,
  and its records match `records_digest`. A mismatched selection is not
  evaluated at all;
- `closed_at` is at or after `window_end` plus the sum of the deadlines, so
  every in-window obligation has fallen due, and `assessed_as_of` is not
  before `closed_at`;
- no slot is INVALID or CONFLICTED.

The claim verdict is `established` only with established coverage and every
slot SATISFIED or NOT_APPLICABLE. A MISSING slot under established coverage
is a known gap, reported as such, and the verdict stays `not_established`.

## What a positive result does not establish

Every assessment carries the same fixed list, whatever its verdict:
visibility beyond the outbox, absence of unobserved events, production PEP
mediation, legitimate business purpose, independence from the producer,
execution authority, and that an effect occurred as reported. The outbox is
REMORA's own record, so a positive result is a self-consistency statement
about REMORA's governed dispatches in one window, not an independent
observation.

## Determinism

`assessment_id` is SHA-256 over `remora-seo-v1:assessment`, a NUL byte and
the canonical payload. The payload binds the manifest digest (which includes
the manifest version), the snapshot digest and `assessed_as_of`. A later
snapshot gives a new assessment; nothing rewrites an earlier one.

## Deviations from the SDD

- **Placement.** The SDD proposes `remora/assurance/obligations.py`.
  `remora/assurance/` already holds the Merkle run trace, so the module lives
  next to evidence admission instead.
- **Canonicalisation.** The SDD proposes RFC 8785 (JCS). The repository has
  no JCS implementation or vetted dependency. P1 uses the bounded
  evidence-admission encoding (sorted keys, no floats) and says so with
  `canonicalization_id: remora-bounded-sorted-json/v1`. A JCS profile is a
  separate change with RFC 8785 test vectors.
- **Scope.** P1 assesses only REMORA's own outbox. External inventories need
  an owner decision on who issues manifests and who writes the inventory
  (SDD O-1, O-2).

## Not built

- A deployment inventory reader. The outbox adapters have no read-only
  "all rows for a tenant in a window" query; `closed_at` is supplied by the
  caller. That query belongs in `remora/enforcement/outbox.py`, a protected
  path, and is its own change.
- Read-back evidence for UNKNOWN, receipt intake and journal (SDD G2 RRA),
  issuer policy (G3 EAS) and delegation narrowing (G4 MDN).
- A JSON Schema file for the manifest. The parser is strict (unknown fields,
  duplicate keys, floats and unsupported values are refused) and is the
  contract for now.

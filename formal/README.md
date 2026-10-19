# Formal models

Machine-checked models for the formal mathematical assurance track
([SDD](../docs/design/formal-mathematical-assurance-v1.md), roadmap RF-16).
A model here is a statement about an abstraction. It is not a proof about the
Python or TypeScript code; correspondence is tested separately, and a result
is never stronger than that test.

## `tla/LeaseRetry.tla`

One logical operation in federation-port/v0's runtime as it was at `92d5078`:
admission, dispatch under a lease, retries, the admission deadline, and an
idempotent provider. Switches select the runtime's rule and the environment
(clock skew, crashes, provider outages). TLC explores every reachable state
of each configuration in [`tla/expected.json`](tla/expected.json):

| Configuration | Result |
|---|---|
| `pinned_reachable` | holds: the pinned rule is safe while every attempt can reach the provider |
| `pinned_outage` | violated: a lost response, an outage, the deadline. The operation closes as failed while the refund exists (CP-F4) |
| `pinned_skew_reachable` | holds: clock skew alone is not enough |
| `confirmfinal_all` | violated: making a confirmation final does not fix it |
| `sticky_all` | holds: "uncertainty sticky" under outages, crashes and skew |
| `sticky_confirmfinal_all` | holds |
| `sticky_confirmfinal_dispatch_after_expiry` | violated: past the deadline a retry is still dispatched (`NoDispatchAfterExpiry`) |
| `read_only_after_expiry` | holds: nothing is dispatched after the deadline, and all four invariants hold under outages, crashes and skew |

The merged runtime (`3a2f6ce`) corresponds to `read_only_after_expiry`: confirmation
final, uncertainty sticky and no dispatch after the deadline. The last two
configurations come from review of aeoess/federation-port#1: the
maintainer asked that an expired authorization never lead to a dispatch, with
read-only reconciliation afterwards. The model checks that rule as the invariant
`NoDispatchAfterExpiry`.

The model was written counterexample first. It had to reproduce the known
fault CP-F1 (found by a contract probe), and in doing so it found CP-F4, which
needs no skew and no crash. Contract probe CP-F4 then reproduced the model's
trace on the unmodified runtime, step for step. The probe is the evidence about
the code; the model is the reason to look.

## `tla/LeaseReconcile.tla`

Reconciling one `unknown` operation, for the v1 candidate on
aeoess/federation-port#2 (`v1-candidates/reconciliation` there). Attempt 1 has
been sent and its outcome is unknown. Requests travel to the provider, which
deduplicates by key when a request arrives and forgets the key after the
retention window. A read-only lookup by key reports the effect or its absence.
The provider can cancel a key out of band (key-scoped finality). Switches
select the closing rule, the retention bound, whether the lookup budget
survives a restart, whether the provider misreports finality, and whether
timing assumption T3 (a request arrives before its window passes) holds.

| Configuration | Result |
|---|---|
| `reconcile_final` | holds: the candidate rule keeps `NoFailedWithEffect`, `AtMostOneEffect`, `ConfirmedIsReal` and `ContradictionResolvesToConfirmed`, and under scheduling assumption S1 every unknown operation ends confirmed, closed on accepted absence, or with an operator (`EventuallySettled`) |
| `reconcile_naive_absent` | violated: an authoritative absence closes the operation, then the earlier request settles (failure case 1 on #2) |
| `reconcile_effect_after_expiry` | violated: nothing is dispatched after the deadline, but a request sent before it settles after it (failure case 2 on #2). The runtime cannot prevent this; the candidate records it |
| `reconcile_no_retention_bound` | violated: a retry after the window reaches a provider that forgot the key, a second refund |
| `reconcile_unbounded_delivery` | violated: without T3, a retry sent inside the window can arrive after the provider forgot the key |
| `reconcile_volatile_budget` | violated (liveness): a restart that resets the budget lets reconciliation loop forever |
| `reconcile_no_scheduling` | violated (liveness): without S1 nothing forces a reconciliation |
| `reconcile_misreported_final` | violated: finality is the provider's guarantee; a provider that misreports it makes the closure wrong |
| `reconcile_misreport_contradiction` | holds: even then, a contradicting confirmation wins and is never invented |

Every weakening of the rule is violated, so each assumption it rests on is
shown to carry weight. The model found one gap while it was written: the retry
bound first assumed that a request reaches the provider within its timeout
without saying so, and TLC produced a second refund. That assumption is now
the named constant `BoundedDelivery` and is written down with the retry
formula in the candidate.

## Run

```console
$ python scripts/check_tla_models.py
```

It needs Java 11+, downloads the pinned `tla2tools.jar` (the stable v1.7.4
release, SHA-256 in `expected.json`) into `.cache/tla/`, and compares each
configuration's verdict and counterexample trace with `expected.json`. Each
model labels its steps with `lastAction`, and the trace is read from that
label, so it does not depend on how a TLC version prints actions. A liveness
counterexample is a lasso that TLC does not choose the same way on every run,
so for those only the property and the closing loop are compared. Without Java
or the jar it prints `BLOCKED` and exits 2; an unchecked model is never
reported as passing. `tests/test_tla_models.py` runs it when Java is present,
skips (saying so) when it is not, and fails on CI when the checker is blocked.

Until 2026-10-13 the pin was the v1.8.0 pre-release, which upstream rebuilds in
place. Its SHA-256 stopped matching, and CI skipped the models without anyone
noticing. That is why the pin is a stable release and CI now fails instead.

## Limits

The state spaces are finite (three attempts, a lookup budget of two). "Holds" means no violation in
that space, not a proof for any number of attempts. The model abstracts
time to one deadline tick and the provider to one idempotent refund. No Lean
theorem exists yet; MODEL_PROVEN is not claimed for anything.

## `ws1_composition/model.py`

WS1 composition, issuance and dispatch (#953,
[WS1 SDD §12.1](../docs/design/ws1-deterministic-authorization-learned-monitoring-v1.md)),
as an explicit-state breadth-first search in Python rather than TLA+, so two
transitions can call the implementation: the decision and every re-gate run
`compose_authorized_decision` over a real `check_preconditions` result, and
issuance and redemption compare `AuthorizationContext.hash` with the WS1
binding in it. Consumption of the single-use grant is modelled as one atomic
step after the re-gate, as in the code. Three preconditions in four logical
states, required and optional monitors with arbitrary output, a grant-only
engine restriction, evidence revoked or refuted between steps, a profile
change and two concurrent redemptions. Results in
[`ws1_composition/expected.json`](ws1_composition/expected.json); every
counterexample trace is pinned in `counterexamples.json` and by
`tests/test_ws1_formal_model.py`.

| Configuration | Result |
|---|---|
| `all_machine` | the design invariants hold; the residual window (below) shows |
| `machine_review_terminal`, `grant_class` | hold, trivially: a REVIEW, GRANT or TERMINAL precondition is never PROVED here, so no grant is issued |
| `no_regate` | violated: `FreshAtRegate` (evidence revoked after ACCEPT, dispatched anyway) |
| `nonatomic_consume` | violated: `SingleUse` (two redemptions both dispatch) |
| `no_profile_binding` | violated: `FreshAtRegate` (profile changed after ACCEPT) |
| `monitor_can_prove` | violated: `AuthorityCeiling`, `MonitorNonExpansion`, `RefusalPersistence` (a clean reading treated as proof) |

`Residual_ProvedAtDispatchInstant` is reported, not claimed: the world can
move between the re-gate and the consuming step, so a precondition proved at
the re-gate may no longer hold at the instant of dispatch. Evidence TTLs bound
that window; nothing in WS1 closes it. The design's claim is `FreshAtRegate`.
The model does not cover the review route, crashes, retries or the outbox.

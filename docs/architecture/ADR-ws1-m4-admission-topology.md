# ADR: WS1-M4 admission topology (trust, clock and state)

- Status: **accepted** (2026-10-22), with the owner decisions below. Work
  package M4.1a of the
  [WS1-M4 SDD](../design/ws1-m4-safe-autonomy-recovery-v0.2.md) §9. M4.1b
  (receipts and epochs) is implemented. M4.1c wires it into all three
  dispatch paths behind `REMORA_WS1_ADMISSION=atomic`, in slices. Slice 1
  covers the direct-ACCEPT path, slice 2a the approved-review path and the
  async worker, and slice 2b revocation at admission. Slice 3 adds the audit
  row and slice 4 the permit before the send. Slice 5 adds the rest of the
  negative matrix as tests.
- Deciders: repository owner
- Related: SDD §2.2 and §4, `docs/design/execution-lifecycle-outbox-v1.md`,
  [ADR: authority custody and lease durability](ADR-authority-custody-and-lease-durability.md),
  `tests/test_ws1_gate_controls.py` control 2b (#982)

## Context

INV-M4-01 in the SDD asks for one linearization point at which the grant is
consumed, the evidence and authority are checked, and the dispatch intent is
recorded. Before any M4.1 code is written, this ADR records which durable
stores exist today, which of them can join one transaction, which clock each
uses, and which backend can carry the invariant. Every statement below was read
from `master` at `265abfbe`; line numbers refer to that revision.

### Stores that take part in admission

| Store | Backends | Joins a caller's transaction? | Clock | Uniqueness |
|---|---|---|---|---|
| Consumed-grant ledger, `EnforcementGate` (`remora/enforcement/gate.py`) | PG, SQLite, D1, memory | No. `check()` takes no connection and opens its own (gate.py:283-290, 457-513) | token age from `datetime.now(UTC)` (gate.py:399-402) | `pep_consumed.jti` primary key (gate.py:56) |
| Dispatch outbox (`remora/enforcement/outbox.py`) | PG, SQLite, memory; no D1 adapter | Yes, `record_intent_enlisted(connection, ...)` never commits (outbox.py:937-970, 1126-1148) | injected `now` or `datetime.now(UTC)` (outbox.py:196) | `UNIQUE (tenant_id, idempotency_key)`; PG `FOR UPDATE`, SQLite `BEGIN IMMEDIATE` |
| Principal revocation, `DurableRevocationStore` (`remora/governance/revocation_store.py`) | PG, SQLite, D1, memory | Yes, through `connection_provider` (revocation_store.py:161-164, 205-243) | none; `revoked_at` is DB time | primary key (tenant_id, principal) |
| Lease nonces, `DurableNonceStore` (`remora/enforcement/nonce_store.py`) | PG, SQLite, D1, memory | No; `try_consume` commits on its own connection | lease expiry from injected `now` or `datetime.now(UTC)` (lease.py:525, 1021) | primary key (tenant_id, nonce) |
| Audit chain (`remora/governance/tenant_chain.py`) and audit outbox (`remora/governance/audit_outbox.py`) | PG, SQLite, memory | The chain no; the audit outbox yes, via `enqueue(conn, ...)` (audit_outbox.py:138) | `now_fn`, default `datetime.now(UTC)` | head row `FOR UPDATE` / `BEGIN IMMEDIATE` |
| WS1 task ledger, `TaskCallLedger` (`remora/verification/planner.py:171`) | SQLite only, single host | No | not used | primary key (task_id, operation_id) |

The shared seam already exists. `transaction_state` (`remora/persistence/execution_state.py:139`)
opens one transaction per tenant and publishes its connection through the
`_ACTIVE_TX_CONNECTION` context variable (`servers/execution_api.py:417`).
On Postgres it first takes `SELECT ... FOR UPDATE` on the tenant's
`global_state` row, so every transaction for one tenant is serialized behind
that lock. On SQLite it opens `BEGIN EXCLUSIVE`. The outbox, the revocation
store and the audit outbox read the context variable; the gate and the nonce
store do not.

### How the three execution paths order their steps

None of the three paths runs the WS1 re-gate, the grant consumption and the
intent in one transaction.

- `redeem_accept_token` re-gates (service.py:2086), consumes the grant on the
  gate's own connection (:2152), then records the intent outside any
  transaction (:2179). Control 2b advances the WS1 clock between the first two
  steps, and the call executes.
- The approved-review path re-gates outside the transaction (:849). It then
  records the intent inside `transaction_state` together with the queue change
  and the audit row (:885-926), and consumes the grant after the claim, on its
  own connection (:1034).
- The worker path re-gates (:1518), claims the intent (:1602) and consumes the
  grant (:1628), each in its own transaction.

### Clocks

Four clocks meet at admission. The WS1 evidence clock is the deployment's
injected `clock_ms` (execution_gate.py:182). A PROVED result expires at the
earliest `min(valid_until, acquired_at + max_age_s)` over its hits
(check.py:226, 297-306), and resolvers stamp `valid_until = now_s + ttl_s`
from their own clock (resolvers.py:86-98). The gate and the outbox use the
application host's `datetime.now(UTC)`. Revocation and consumption timestamps
come from the database's `CURRENT_TIMESTAMP`. No component today compares an
evidence expiry with database time.

## Decision

1. **One authority transaction domain per tenant, on Postgres.** M4.1's
   reference profile is a single Postgres database holding `global_state`,
   `pep_consumed`, the dispatch outbox, the audit outbox, the revocation rows
   and the new authority-epoch rows. Admission runs inside
   `transaction_state`, extended so that the grant ledger and the epoch reads
   enlist through `_ACTIVE_TX_CONNECTION` like the outbox already does. The
   linearization point `t_L` of INV-M4-01 is that transaction's commit.
2. **The tenant row lock is the serialization mechanism for M4.1.** Because
   `transaction_state` already holds `global_state ... FOR UPDATE` for the
   tenant, two admissions for one tenant cannot interleave, and a revocation
   written inside `transaction_state` for that tenant orders strictly before or
   after any admission. Per-subject row locks (SDD §4.3) are a later throughput
   change. A revocation that does not run inside `transaction_state` does not
   get INV-M4-02, so the strict profile must route every admission-relevant
   revocation writer through it.
3. **Database time decides expiry at admission.** Inside the transaction,
   after the lock is held, admission reads `clock_timestamp()` once and uses
   that instant for grant age, evidence `valid_until` and epoch checks.
   Equality at `valid_until` counts as expired (M4-T10). Receipts keep their
   resolver-stamped times; admission subtracts a declared
   `max_clock_skew_ms` from each `valid_until` before comparing. The strict
   profile refuses to start without that value; it has no default.
4. **No network or monitor call inside the transaction.** Resolver lookups and
   monitor scoring finish before `transaction_state` opens. A serialization
   retry may reuse only receipts that are still valid at the retry's database
   time; otherwise admission refuses and the caller refreshes outside.
5. **Backend matrix for the strict M4.1 profile.**

   | Backend | M4.1 status | Reason |
   |---|---|---|
   | Postgres | reference profile | interactive transactions, row locks, one clock per transaction |
   | SQLite | single-host exploratory | `BEGIN EXCLUSIVE` serializes one file on one host; no claim for shared or networked files |
   | Cloudflare D1 | refused by the strict profile (capability pending) | no interactive transaction; a read flushes buffered writes as a separate batch (`d1_connection.py:125-131`); no outbox adapter; isolation rests on one container instance |
   | In-memory | tests only | already refused in production (`servers/api.py:616-658`) |

6. **The claim stops at local admission.** `AUTHORIZED_AT_COMMIT` is what this
   topology can establish. The dispatcher's pre-send permit check (INV-M4-03)
   runs against the same database, so a revocation committed after `t_L` and
   before the permit check is caught. A revocation after the send starts is
   not, and the SDD's `NOT_ESTABLISHED` label for effect-time validity stays.

## Consequences

- M4.1b and M4.1c (SDD §9) have a fixed target. The gate needs a consumption
  call that takes the enlisted connection; the nonce store and the WS1 task
  ledger stay outside the domain, and the ADR records that as a boundary.
- `redeem_accept_token` and the worker path must move their consume and intent
  steps into `transaction_state`, as the review path already does for the
  intent. The order inside becomes: lock, read database time, verify receipts
  and epochs, consume the grant, insert the intent, enqueue the audit row,
  commit.
- Control 2b becomes M4-T02. In the strict profile it must refuse; outside the
  strict profile it keeps documenting the residual. Enforced since
  2026-10-26 (RMR-AUD-26-003): `review` and `controlled_pilot` refuse to
  start with `REMORA_WS1_MODE=enforce` unless `REMORA_WS1_ADMISSION=atomic`
  (`remora/toolcall/runtime_profile.py::_check_ws1_admission`). Off and
  shadow keep legacy, because there WS1 changes no decision.
- Throughput is serialized per tenant. This is acceptable for the research
  profile and is measured before any per-subject locking is proposed.
- D1 deployments keep today's behaviour and cannot claim INV-M4-01 or
  INV-M4-02. Lifting that needs real-worker tests of multi-statement batches
  and revocation ordering.

## Findings recorded while mapping (not fixed here)

- `DurableRevocationStore` and `DurableNonceStore` accept `state_endpoint` but
  call `d1_connection.connect()` without it (revocation_store.py:174,
  nonce_store.py:154), so they use `REMORA_STATE_ENDPOINT` from the
  environment. Production wiring passes the same variable
  (`servers/execution_api.py:994`, `:1525`), so deployments are not affected;
  a caller passing a different endpoint would be.
- Outside production, a D1 `transaction_state` sets the context variable
  (execution_state.py:181) while the outbox is `UnbackedExecutionOutbox`,
  which inherits the base `record_intent_enlisted` that raises
  `NotImplementedError` (dispatch.py:460, outbox.py:370).

Both need a test and a fix in their own PR.

## Owner decisions (2026-10-22)

The owner asked for the recommendations to be followed.

- **Review path.** The approved-review path consumes the grant in the same
  admission transaction as the claim, after the receipt and epoch checks. All
  three paths then share one linearization point. The token is still issued at
  claim time, so a review approval stays a separate authority until then.
- **Clock skew.** `max_clock_skew_ms` is a deployment parameter. The strict
  profile requires it, has no default, and accepts at most 5000 ms
  (`MAX_CLOCK_SKEW_MS` in `remora/verification/receipts.py`). A deployment
  whose clocks drift further must fix them, not widen the window.

## M4.1b, implemented (not wired)

- `remora/verification/receipts.py`: `EvidenceReceiptV1`, built only from a
  composition record's PROVED and completed results, with the subject epoch
  read before the lookups. `admission_refusal` is the pure admission check.
  It refuses expiry at database time, with equality expired and the skew
  subtracted, and a stale or revoked epoch. It also refuses a foreign,
  duplicated, missing or modified receipt
  (`tests/verification/test_evidence_receipts.py`, M4-T01, T03, T04, T07, T09,
  T10).
- `remora/governance/authority_epochs.py`: `AuthorityEpochs` over Postgres or
  SQLite. Every advance moves the epoch by one; it joins the caller's
  transaction; a locked read outside a transaction is refused; an unreachable
  store raises. Revoke-first and admit-first orderings are tested with two
  contending SQLite transactions (`tests/test_authority_epochs.py`).

Nothing on an execution path calls either module yet, so no claim or
capability changes.

## M4.1c slice 1, implemented (direct ACCEPT, opt-in)

`REMORA_WS1_ADMISSION=atomic` changes `/v1/execution/execute-accepted` only.
`remora/execution/admission.py` runs the order from the Consequences section
inside one `transaction_state` for the tenant. The steps are the lock, the
database instant (`clock_timestamp()` on Postgres), the receipt and epoch
check under lock, the grant spend on the same connection, and the dispatch
intent on the same connection. Every refusal or fault before commit rolls
all of them back.

- The WS1 re-gate reads each evidence source's epoch before its lookups and
  returns receipts for a clean outcome. A precondition gets one receipt per
  source its resolvers can read, so revoking any of them refuses it.
- `EnforcementGate.check(..., connection=)` spends the grant on the
  admission connection, in a savepoint on Postgres. An in-process or D1 gate
  cannot join and refuses as `consumed_ledger_unavailable`.
- The grant is judged at the database instant plus `max_clock_skew_ms`, and
  the evidence at `valid_until` minus it, so both expire that much sooner.
  The same allowance keeps a grant whose application-stamped `issued_at` is
  slightly ahead of the database clock from being refused as not yet valid.
- `AtomicAdmission.advance_authority` revokes or reinstates a subject under
  the same tenant lock, so a revocation and an admission are strictly
  ordered (decision 2). No route calls it yet.
- The server refuses the mode at startup without Postgres or SQLite, with
  `REMORA_STATE_ENDPOINT` set, or without a skew from 0 to 5000.
- Tests: `tests/test_atomic_admission.py` covers M4-T01, T02, T03, T04, T05
  in both orders, T06 with eight admitters, T10, T11 and T13, on SQLite and
  on a real Postgres in the CI postgres-contract job.
  `tests/test_ws1_atomic_admission_route.py` covers T02, T03 and T04 through
  the route and the real dispatcher. Control 2b in
  `tests/test_ws1_gate_controls.py` still pins the legacy residual, which is
  unchanged with the mode off.

Not yet covered:

- The `execution_authorized` audit row is appended after commit, as before.
  M4-T12 needs it in the transaction.
- The review and worker paths are unchanged (done in slice 2a, below).
- The ACCEPT path does not read principal revocation.
- No route writes authority epochs.
- M4-T14 to T20 are open.

**Finding.** `transaction_state` runs `CREATE TABLE IF NOT EXISTS` inside
its first transaction. On a fresh Postgres schema, concurrent first
transactions can fail on the catalog's unique index
(`pg_type_typname_nsp_index`). The failure is closed: the transaction raises
and nothing commits. It happens only before the first transaction on a new
database has committed. The tests run one transaction first. The epoch store
avoids the problem with `ensure_schema()`. `transaction_state` needs the same
fix in its own PR.

## M4.1c slice 2a, implemented (approved review and async worker, opt-in)

Under the same switch, the synchronous review path and the async worker claim
the intent, check the receipts and epochs at the database instant and spend
the grant in one transaction. This follows the owner decision on the review
path. The queue's own transaction still records the intent before that, as
FT-02 requires. All three paths now spend at one linearization point.

- `claim_enlisted` on the SQLite and Postgres outboxes claims inside the
  admission transaction. On Postgres it holds the row `FOR UPDATE` until
  commit. The claim runs before the spend, and a lost race raises
  `ClaimLost`. The transaction rolls back, so the loser has spent nothing
  (issue #417).
- Any other refusal settles the intent `REFUSED` under its reason, and
  nothing is dispatched. The review route answers 200 with that refusal in
  `tool_execution`, as a refused grant does on the legacy path. It records
  `execution_admission_refused` and no `execution_authorized`. The worker
  settles the row through its existing refusal path.
- A REVIEW precondition gets no receipt. The stored approval closes it, and
  the queue checks that approval, its role and its expiry in its own
  transaction. The receipt check covers the precondition's source evidence.
  The approval's expiry is therefore checked at the queue's transaction and
  is not re-read at database time.
- In async mode the review route pins no epochs: the worker admits later
  with its own fresh re-gate.
- Tests: `tests/test_atomic_admission.py` adds the claim paths on SQLite
  and Postgres. They cover claim plus spend together, a lost claim that
  spends nothing, a refused spend that releases the claim, and eight
  workers on one row with one claim and one spend.
  `tests/test_ws1_atomic_admission_route.py` adds the review path (admitted,
  refused on a lapse and on a revocation, grant unspent, row settled) and
  the worker (admitted, and refused on a revocation with the row settled).

Still open after slice 2a: see slice 2b.

## M4.1c slice 2b, implemented (revocation at admission)

- **Principals.** Admission reads principal revocation inside its
  transaction on all three paths, through the durable revocation store,
  which joins the transaction. It checks:
  - the authenticated actor;
  - the proposer a delegate acts for;
  - on the review and worker paths, the approver.

  `revoke-principal` already writes under the same tenant lock, so a
  revocation and an admission are ordered. Revocation refuses as
  `principal_revoked`. A store that cannot answer refuses as
  `revocation_store_unavailable` (M4-T03).
- **Evidence sources.** `POST /v1/execution/revoke-authority` (`review`
  capability) revokes or reinstates `source:<id>` through
  `AtomicAdmission.advance_authority`. The epoch change and its
  `authority_revoked` or `authority_reinstated` event commit in one
  transaction. Without atomic admission the route answers 409: nothing
  would read the epoch.
- **Fix.** `transaction_state` creates its Postgres tables once, in
  autocommit, under an advisory lock (`_ensure_pg_schema`). Concurrent first
  transactions on a fresh database no longer collide on the catalog index.
  The contention tests now run without a warm-up transaction.

Still open after slice 2b: see slice 3.

## M4.1c slice 3, implemented (the audit row in the transaction)

The Consequences section puts the audit row inside admission, before
commit. Each admission now enqueues an `execution_admitted` record in the
audit outbox (REM-047) on the admission connection, as its last step. If
the enqueue fails, admission refuses as `audit_outbox_unavailable` and rolls
back with it: the grant stays unspent, no intent exists and a claim is
released (M4-T12).

A fault the admission cannot name, a driver error inside the transaction or
at its commit, rolls back the same way. On the review path it is reported as
`admission_storage_unavailable` and takes the refusal path. The refusal and
the withheld grant go on the chain, the grant minted before the transaction
is spent, and the item is settled (NEGATIVE_RESULTS §98, re-verified under
SDD unified capability execution v1.1 P0 item 5). The driver's message is
logged, not returned, so the response reasons stay a bounded set.

- The record names the grant, the intent's outbox id, the actor, the
  delegating proposer, the worker on the async path, the WS1 audit block and
  the admission block. It is keyed on the grant's `jti`, which the spend
  makes single-use, so a replayed drain appends it once.
- After commit, admission drains the audit outbox into the chain, so the
  record lands before `execution_authorized`. That entry's `admission` block
  carries the record's `audit_key`, which joins the two. A failed drain does
  not fail the admission: the row is committed, and the next drain projects
  it (the lazy sweep in `reconcile_stale_dispatches`).
- `execution_authorized` stays a direct append after commit. Its sequence
  number is what `execution_result` and the outbox projection link to, so
  moving it would need a linking change. It no longer has to move: the
  record of what was admitted commits with the admission.
- Tests: `tests/test_atomic_admission.py` (SQLite and Postgres) covers the
  row and its payload, an enqueue failure on the record path and on the
  claim path, an unkeyed record, and a failed drain.
  `tests/test_ws1_atomic_admission_route.py` covers all three paths and an
  enqueue failure through the route.

Still open after slice 3: see slice 4.

## M4.1c slice 4, implemented (the permit before the send)

Decision 6 calls for a pre-send permit check (INV-M4-03) against the same
database. After admission commits and before the lease is minted, all three
paths call `AtomicAdmission.permit`. It runs in a short transaction under the
same tenant lock, so it is ordered with every revocation, and it writes
nothing. It repeats the admission check at a fresh database instant: the
receipts' expiry, their epochs read under lock, and the principals.

- **Refused before the send (M4-T14, M4-T16).** Evidence that lapsed, a source
  revoked or revised, or a principal revoked after the commit refuses the
  attempt. The grant was spent at admission, so this is not a retry. The
  intent settles `REFUSED`, `tool_execution` reports
  `refusal_reason: permit_refused` with the cause in `permit_refusal`, and
  no lease is minted.
- **The lease is the downstream permit.** A permit carries `not_after`: the
  earliest receipt `valid_until`, less twice the declared skew. One skew is
  the admission rule on the database clock, and the other covers an
  executor whose clock runs behind. The lease minted for the call expires no
  later than that, and `dispatch_under_lease` refuses to mint at or past it
  (`permit_expired`). An executor that receives the lease late, local or
  remote, therefore refuses it as expired.
- **Not safe at effect (M4-T16).** A revocation after the permit check, while
  the call is out, is not seen by an executor that does not check it. Every
  permit records `validity: AUTHORIZED_AT_COMMIT` and
  `at_effect: NOT_ESTABLISHED` in `tool_execution.permit` and on the
  `execution_result` entry. The test that revokes mid-send asserts the call
  runs and is labelled that way.
- Tests: `tests/test_atomic_admission.py` (SQLite and Postgres) covers the
  permit's bound, a lapse, and evidence too close to expiry for the
  executor. It also covers a source and a principal revoked after commit and
  an unreachable epoch store. The rest are a permit that writes nothing, a
  revocation racing the permit, and a bound already past. `tests/test_ws1_atomic_admission_route.py` covers the lease
  bound, a lapse and a revocation between commit and permit on each path,
  and a revocation mid-send.

Still open after slice 4: see slice 5.

## M4.1c slice 5, tests only (the rest of the matrix)

`tests/test_ws1_m4_fault_matrix.py` runs the remaining rows through the real
route under atomic admission, with faults injected at fixed points. No
behaviour changed.

- **M4-T15.** A dispatcher sends through the real one and then loses the
  answer. The call settles `UNKNOWN`, and nothing retries it: not presenting
  the grant again (`token_already_consumed`), not the worker, not the stale
  sweep. This holds on the direct and the worker paths.
- **M4-T17.** A required monitor that is down refuses the call, with the
  grant unspent. A monitor that lies cannot put back evidence withdrawn
  after the grant: hints naming authority, an answer for other evidence, or
  a conflict code all leave the refusal. Calls stay within the monitor
  budget. The exhaustive version is `tests/verification/test_authority_ceiling.py`.
- **M4-T18.** If the source publishes a new revision while the resolver
  answers, the stale receipt refuses (`authority_epoch_stale`). If the policy
  bundle changes during the lookup, the call refuses on its context
  (`context_mismatch`). The grant stays unspent in both cases.
- **M4-T19.** A refused admission leaves no lease in the response or on the
  chain. The executor refuses a lease with an altered field
  (`signature_invalid`) and a lease presented for another call
  (`tool_args_hash_mismatch`). Production completeness stays
  NOT_ESTABLISHED. A component holding the authority's signing key can mint
  a lease without admission. Only the custody split
  ([ADR-A](ADR-authority-custody-and-lease-durability.md)) keeps the
  executor from doing so, and no test shows that a deployment has no other
  such component.
- **M4-T20.** After a simulated restart, the gate, the admission, the
  dispatcher and the outbox are rebuilt from durable state. A replayed grant
  is refused as `token_already_consumed`, and its spent lease as
  `nonce_already_consumed`.
- **M4-T07, T08.** Swapping the arguments or the target refuses as
  `binding_refused`, and swapping the actor as `context_mismatch`, each
  before the grant is spent.

### M4.1 matrix status

| ID | Where | Caveat |
|---|---|---|
| T01, T02, T10, T11, T13 | `tests/test_atomic_admission.py` (SQLite, Postgres), route T02 | T13 covers an unreachable epoch store, not exhausted serialization retries |
| T03, T04, T05 | `tests/test_atomic_admission.py`, `tests/test_ws1_atomic_admission_route.py` | |
| T06 | `tests/test_atomic_admission.py`: eight threads on one grant, eight on one row | the SDD names 32 workers in 2 processes; not run at that size |
| T07, T08, T09 | `tests/verification/test_evidence_receipts.py`; route swaps in `tests/test_ws1_m4_fault_matrix.py` | the route swaps run on SQLite only |
| T12 | slice 3 | |
| T14, T16 | slice 4 | T16 is labelled, not prevented: `at_effect` is NOT_ESTABLISHED |
| T15, T17 to T20 | `tests/test_ws1_m4_fault_matrix.py` | SQLite only; T19 production completeness NOT_ESTABLISHED |

Still open before the §5 gate closes M4.1:
- The route-level rows run on SQLite. Postgres runs the admission rows only.
- T06 at the SDD's size, and T13 for exhausted serialization retries.
- The bounded model check of the invariants, keeping the non-atomic
  counterexample.
- Reproduction from a clean clone, and a second author's review.

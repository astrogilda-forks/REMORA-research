# ADR: WS1-M4 recovery scheduler on a Durable Object

- Status: **proposed** (2026-10-22). Needs the owner's decision before any
  code. Work package M4.5a of the
  [WS1-M4 SDD](../design/ws1-m4-safe-autonomy-recovery-v0.2.md) §9.
- Deciders: repository owner
- Related: [ADR: WS1-M4 admission topology](ADR-ws1-m4-admission-topology.md),
  `workers/mcp-gateway/src/index.ts` (`ProposalDO`), issue #953, #707

## Context

A WS1 call whose evidence is missing or lapsed ends as ABSTAIN. Some of
those calls would pass a little later: the record appears, a source catches
up, a lookup that did not answer does. How many is unmeasured. Nothing in
REMORA keeps such a call, waits, and asks again; today the agent or a human
has to re-propose it.

A proposal on 2026-10-22 suggested a "Durable Execution Coordinator" on
Cloudflare Durable Objects. It covered four things: recovery, per-resource
coordination, dispatch freshness and a benchmark. This ADR records which of
them fit the authority model and which do not. The facts it rests on, read
from `master` at `4a546f48`:

- The MCP gateway already runs three Durable Objects: `RemoraContainer`,
  `RemoraExecutionContainer` and `ProposalDO`. `ProposalDO` stores a call
  awaiting human approval, keyed by session, pinned to a jurisdiction. It
  holds no grant.
- The admission topology ADR (accepted) puts consumed grants, dispatch
  intents, authority epochs and the admission ledger in one Postgres
  transaction per tenant. It refuses D1 for the strict M4.1 profile, because
  D1 has no interactive transaction.
- M4.1c (PR #1009) admits atomically on all three execution paths. Evidence
  that lapses between the re-gate and consumption refuses
  (`evidence_expired_at_admission`).
- WS1 charges every resolver lookup and monitor call to the call's task,
  durably (`TaskCallLedger`, `task_call_cap` units per task). A re-proposal
  is new external activity and is charged again.

## Decision

1. **A Durable Object may schedule recovery. It holds no authority.** The
   scheduler is a Durable Object class in the MCP gateway, beside
   `ProposalDO`, one instance per (tenant, task). It stores a pending call
   that WS1 refused for missing or lapsed evidence, the deadline the task
   allows, and an attempt count. Its alarm re-submits the same call to
   `POST /v1/execution/assess` under the same principal and task identity
   as the original proposal. REMORA decides; the scheduler only asks again.
2. **It never stores, holds or redeems an execution token or lease.** When a
   re-assessment returns ACCEPT, the token goes to the client through the
   path the gateway already uses. A token in the scheduler's storage would
   be authority outside the admission domain. Redemption stays where
   M4.1c's atomic admission runs.
3. **Postgres stays the only authority transaction domain.** The scheduler
   does not lock resources, serialize dispatch or keep a copy of grants,
   epochs or intents. Per-resource coordination and dispatch freshness,
   parts 2 and 3 of the proposal, are not adopted. Both are already decided
   in the admission topology ADR, and a second domain would break its
   decision 1 (SDD §2.2).
4. **Retries are bounded by the task, not by the scheduler.** Each
   re-assessment is charged to the task's `TaskCallLedger` budget like any
   other attempt. The scheduler adds two caps of its own, both declared by
   the deployment with no default: a maximum attempt count and a backoff
   floor. When the task budget, the attempts or the deadline run out, the
   call is dropped and the drop is recorded. It never falls back to a
   human-approval route the original decision did not offer.
5. **Only a refusal for evidence can be retried.** The scheduler accepts a
   call only when every WS1 cap on it is one of `lookup_did_not_prove` or
   `evidence_expired` (`remora/verification/compose.py`). It does not accept
   `precondition_refuted`, `precondition_conflict`,
   `terminal_precondition_unproved`, `no_resolver_available`,
   `binding_mismatch`, a monitor cap or an engine hard guard: asking again
   cannot change those, and retrying them would only probe the gate.
   `verification_budget_exhausted` is not retried either, because the task
   budget is what ran out.
6. **A restart replays nothing that was not a proposal.** After a crash the
   alarm fires again and re-submits the stored call to `/assess`. That is a
   new assessment, never a dispatch. An attempt whose outcome is unknown is
   asked again, never assumed refused or accepted.

## What this does not claim

- No safety property changes. The scheduler cannot make a call more
  executable than a fresh assessment makes it, and M4.1c's admission still
  decides at consumption.
- No utility claim. Whether recovery completes more legitimate tasks, and
  at what cost in lookups and human approvals, is unmeasured. It is
  measured only through Study D or the M4.3 benchmark, preregistered before
  data access (SDD §6, §7). Until then the scheduler is an implemented
  mechanism, not a result.
- Nothing about the D1 admission backend. That stays capability pending.

## Consequences

- One new Durable Object class and a migration tag in
  `workers/mcp-gateway/wrangler.toml`. Its jurisdiction follows
  `PROPOSAL_JURISDICTION`, for the reason `storeFor` gives for proposals.
- Gateway tests must show the cases below, in
  `workers/mcp-gateway/test/`, before the scheduler is enabled anywhere:
  - an evidence refusal is scheduled; any other refusal is not;
  - an alarm re-submits exactly the stored call under the original identity;
  - an ACCEPT token is never written to storage;
  - the attempt cap and the deadline drop the call;
  - an alarm after a restart re-assesses and does not dispatch.
- The REMORA API needs no change for the first version. If the scheduler
  should read the evidence caps from the assessment response rather than
  from its reason codes, that is a separate, versioned change to the
  response.

## Alternatives not taken

- **The proposed Durable Execution Coordinator as authority.** It would
  serialize operations per resource and keep versioned authorization state
  in the Durable Object. That is a second authority domain beside Postgres,
  and the admission topology ADR's decisions 1 and 5 exclude it. A Durable
  Object transaction is not atomic with Postgres or with a downstream
  system either.
- **D1 as the admission backend.** It is refused for the reason the topology
  ADR gives, and lifting that needs real-worker tests of multi-statement
  batches and revocation ordering.
- **A Python worker on a timer.** It would work, but REMORA deploys no
  background daemon (`drain_audit_outbox` documents the same limit), while
  the gateway already runs Durable Objects with alarms and jurisdiction
  pinning.

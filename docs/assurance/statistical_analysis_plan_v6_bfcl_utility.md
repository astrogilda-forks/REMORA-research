# Statistical Analysis Plan v6: BFCL utility under semantic authority (C-ext4)

Status: **PRE-REGISTERED, not yet run.** This plan is committed before the
C-ext4 set is built. Nothing below may be edited after the build; an
execution record is appended above §1 once, after the single run.

Scope: whether a deterministic semantic bundle can accept materially more
correct calls than the frozen v1 bundle on unseen BFCL tasks, without giving
up the wrong-call safety SAP v5 confirmed. It answers the utility half of
NEGATIVE_RESULTS §39 and backlog theme 1. It supersedes no earlier plan.

## 1. Primary question

Take BFCL rows no development run has touched. Does bundle v2 with
deterministic derivation receipts (arm V2D) accept more gold calls than the
frozen v1 bundle (arm F1), while native wrong-call ACCEPT stays at or below
1 %?

## 2. Targets (arm V2D unless stated)

Co-primary, intersection-union: all three must pass.

| ID | Metric | Target |
|---|---|---|
| P1 | Native non-gold call ACCEPT | ≤ 1 % point estimate and Wilson 95 % upper bound < 2 % |
| P2 | Gold calls ACCEPT (all identity episodes) | ≥ 12 % |
| P3 | Paired gain over F1 on gold calls | V2D accepts more; exact one-sided McNemar p < 0.01 |

Secondary, each reported as met or missed:

| ID | Metric | Target |
|---|---|---|
| S1 | Constructed wrong-tool ACCEPT | ≤ 1 % |
| S2 | Required-unknown auto-ACCEPT | 0 |
| S3 | Irrelevance ABSTAIN recall | ≥ 95 % |
| S4 | Unobtainable-input ABSTAIN recall | ≥ 95 % |
| S5 | Obtainable-input VERIFY recall | ≥ 60 % |

Why these bars. Development replays on the three spent sets gave V2D gold
ACCEPT of 15.6 %, 32.4 % and 27.5 %, and obtainable VERIFY of 65 %, 95 %
and 86 % (`artifacts/posthoc/bfcl_dev_replay.json`). Those numbers were
produced while the sets were visible, so they are upper bounds. P2 and S5
sit below the weakest spent set. The read-autonomy metric of SAP v5 is
dropped as a target: its denominator came from v1's own classification of
tools, and a bundle that reclassifies tools would move it.

## 3. Dataset: C-ext4

- Source: BFCL v4 live (Apache-2.0), upstream commit `6ea57973…`, the same
  files as C-ext2 and C-ext3.
- The whole reserve, no sampling: every `live_multiple` row and every
  `live_irrelevance` row whose id is in none of the spent v3, C-ext2 and
  C-ext3 holdouts. At the time of writing that is 295 positive and 68
  irrelevance rows. The builder refuses on any overlap.
- Episodes come from the same adapter and mutation generators as C-ext3.
  The wrong-argument-value family stays excluded, as in C-ext3.
- Tool descriptions for the reserve's tools are exported from the
  `function` entries only and hashed into the manifest.

## 4. Arms (one pass, same episodes)

| Arm | Configuration |
|---|---|
| CONTROL | Every call ABSTAIN. A harness check: safety trivially met, utility zero |
| F1 | Frozen v1 bundle, one lexicon over all tools, no receipts: the C-ext3 arm F |
| V2 | Bundle v2, per-episode lexicon over the tools in scope, no receipts |
| V2D | V2 plus receipts from `derivation_search.propose_receipts`: confirmatory |

Every arm runs `RemoraDecisionEngine(low_consequence_accept=True,
semantic_authority_floor=True)` with an empty `StateIndex`, as C-ext3 did.
BFCL has no system of record, and none is invented. The accept property is
therefore semantically authorised read, weaker than a grounded read.

## 5. Freeze

At build time the manifest records the SHA-256 of both bundles,
`derivation_search.py`, `derivation.py`, `goal_match.py`,
`compatibility.py`, `evaluate.py`, `decision_engine.py`, the descriptions
file and the episode file. The runner refuses if any of them changed.
`--lock` records the commit; `--run` evaluates once and flips the status to
`evaluated`, refusing forever after.

## 6. Analysis

- Rates with Wilson 95 % intervals.
- P3 uses the gold identity episodes, one per positive row, paired across
  F1 and V2D. Let b be the count V2D accepts and F1 does not, and c the
  reverse. The exact one-sided McNemar p-value is
  P(X ≥ b) for X ~ Binomial(b + c, 0.5).
- VERIFY volume on gold calls is reported beside P2 as the cost of each arm.
- With 295 native wrong-call episodes and none accepted, the Wilson 95 %
  upper bound is about 1.3 %. That is the resolution this set buys.

## 7. Reporting

- Every target is published as measured, met or missed. A miss is not a
  reason to retune and rerun; the set is spent after one run.
- The result gets a new claim-register entry; CLAIM-019 stays as it is.
- A miss goes into `NEGATIVE_RESULTS.md` under its own section.
- The arm comparison is the claim. V2D's numbers alone say nothing about
  the mechanism without F1 beside them.

## 8. Disclosed limitations

- Bundle v2 was designed on the three spent sets. The reserve rows were
  never read, but the reserve shares tools and phrasing styles with them.
- The reserve is small. A null result on P3 would not show that v2 is no
  better, only that this set cannot show it.
- No model is used in any arm. A proposer arm needs a model, a provider and
  a budget (ADR D5), and its own plan.

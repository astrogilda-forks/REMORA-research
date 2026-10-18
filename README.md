<img width="2172" height="724" alt="REMORA: policy-gated control between an agent's intent and a real-world effect" src="docs/assets/remora-hero.png" />

# REMORA: Governed Execution Assurance for Tool-Using AI Agents

[![Paper (PDF)](https://img.shields.io/badge/paper-PDF-b31b1b.svg)](paper/remora_paper.pdf) [![CI: Deterministic Test Suite](https://github.com/darklordVirtual/REMORA-research/actions/workflows/ci.yml/badge.svg)](https://github.com/darklordVirtual/REMORA-research/actions/workflows/ci.yml) [![Quality Gates](https://github.com/darklordVirtual/REMORA-research/actions/workflows/quality-gates.yml/badge.svg)](https://github.com/darklordVirtual/REMORA-research/actions/workflows/quality-gates.yml) [![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)

Policy-gated control between an agent's intent and a real-world effect.

**Research question.** Can authorization enforced outside the agent, and bound to the exact tool call, stop the calls an agent should not make while keeping it useful? Where does it fail?

**What the evidence shows so far.** The runs are sealed or pre-registered unless marked. Every number resolves to the [claim register](docs/assurance/claim_register_v1.yaml), and every failure stays in [NEGATIVE_RESULTS.md](NEGATIVE_RESULTS.md).

1. On sealed BFCL v4 episodes, declared tool contracts with a semantic-authority floor accepted none of the 500 (C-ext3) and none of the 295 (C-ext4) substituted wrong calls. A revised bundle raised correct-call acceptance from 6.9% to 29.9%. Clustered by tool the upper bounds are 3.5% and 5.42%, almost no wrong call came from the task's own tool list, and most correct calls still do not proceed. The open problem is the safety–utility trade-off, not safety alone.
2. On AgentHarm, an imported intent-gating run saw only the instruction text and blocked all 208 harmful scenarios and all 208 benign twins: every score sat above the escalation threshold. It enforces a floor and does not tell intent apart. In a separate 88-task run, the LLM oracle alone told 29 of 44 harmful/benign pairs apart, and with the deterministic gate on top none were (NEGATIVE_RESULTS §80). When a deterministic floor helps a learned monitor and when it erases the monitor's signal is the question this result raises.
3. A consensus-temperature uncertainty signal was falsified on 1,231 fresh items under a pre-registered plan (SAP v3, CLAIM-012) and is kept only as a diagnostic.
4. The project's own simulator benchmark had label leakage and an overstated sample size: 700 tasks are 70 templates (NEGATIVE_RESULTS §17). Only corrected numbers are reported, and the benchmark's 0% unsafe result is attributed to no component (CLAIM-020).

**What it does not yet test:** an adversarial agent trying to get past the gate (the AI-control threat model), wrong calls a model actually makes, external baselines, and the execution chain under attack. These are the next experiments; the [peer-review findings](docs/review/PEER_REVIEW_FINDINGS.md) track each objection and what was done about it.

An agent proposes a tool call. REMORA is a governance overlay between that proposal and the protected tool: it evaluates the exact action before it runs, and returns one of four decisions:

| Decision | Meaning |
|---|---|
| **ACCEPT** | The action may proceed under the current policy and context. |
| **VERIFY** | A defined check or review is required before execution. |
| **ABSTAIN** | Required information is missing or insufficient. |
| **ESCALATE** | The action requires a higher-authority decision. |

The enforcing surface is `POST /v1/execution/*`. An approval is bound to the exact proposal it was given for and is consumed once, at the policy-enforcement point, before governed dispatch.

> **Status:** research and shadow-mode software with no production certification. External replication is pending; every deployment still needs its own validation.

```bash
python -m pip install -e ".[dev]"
python -m remora try
```

## Where to start

**Reviewing the research?** Five files are enough: the [paper](paper/remora_paper.pdf), [NEGATIVE_RESULTS.md](NEGATIVE_RESULTS.md), the [peer-review findings](docs/review/PEER_REVIEW_FINDINGS.md), the [claim register](docs/assurance/claim_register_v1.yaml) and [how to reproduce every result](docs/06-reproducibility.md). The repository also keeps about 400 Markdown files of design history and product material; none of them is needed to judge a claim.

**Working on the code?** One ordered reading path follows; the [documentation index](docs/README.md) lists the complete registered set.

1. [Developer handoff](DEVELOPER_OVERVIEW.md): the shortest technical path through the repository
2. [Architecture](ARCHITECTURE.md): components, data flow, module stability
3. [Execution quickstart](docs/deployment/execution-quickstart.md): configure and run the enforcing path
4. [API reference](docs/07-api-reference.md): public interfaces with a `curl` round-trip; wire contract in [`schemas/openapi.json`](schemas/openapi.json)
5. [Python SDK](docs/sdk.md): the one namespace with a backward-compatibility guarantee
6. [Evidence and claims](docs/02-evidence-and-claims.md): what each result establishes, and what it does not
7. [NEGATIVE_RESULTS.md](NEGATIVE_RESULTS.md): failed hypotheses and limitations, kept permanently
8. [Peer-review findings](docs/review/PEER_REVIEW_FINDINGS.md): every objection raised against the paper, and what was done about it

## How an action gets through

1. Authoritative context. Tool meaning, target, risk and approved intent come from deployment-owned sources such as a Signed ToolSpec, never from the calling agent.
2. Policy decision. Deterministic hard guards outrank model-derived signals.
3. Review or grant. `VERIFY` and `ESCALATE` enter bounded review; `ACCEPT` receives a short-lived, single-use grant bound to the proposal.
4. PEP and dispatch. The grant is consumed, an `ExecutionLease` binds policy identity to call identity, and `GovernedToolDispatcher` invokes the deployment-owned callable.
5. Lifecycle and evidence. Dispatch intent, outcome, effect verification and audit records stay joinable by proposal identity.

<details>
<summary>What sits outside that path</summary>

The separate `/v1/assess` research surface can use oracle, evidence and uncertainty components. They are not prerequisites for the execution kernel and cannot override its deterministic hard-guard floor.

[DEVELOPER_OVERVIEW.md](DEVELOPER_OVERVIEW.md) draws the CORE / OPTIONAL / EXPERIMENTAL / HISTORICAL boundary; the machine-checked [product truth contract](docs/product/product_truth_contract.yaml) classifies every capability; the [execution quickstart](docs/deployment/execution-quickstart.md) walks a deployment-shaped example.

</details>

## Evidence

Headline values are governed by the [claim register](docs/assurance/claim_register_v1.yaml) and stay tied to committed result artifacts and scope caveats. Every number below is bounded by documented assumptions, benchmark populations and evaluation protocols. None is a general safety guarantee.

<!-- claim:CLAIM-002 far_pct far_ci_high_pct fbr_pct n -->
<!-- claim:CLAIM-001 far_pct n_effective n -->
<!-- claim:CLAIM-019 wrong_call_accept_pct wrong_call_wilson_upper_pct irrelevance_abstain_pct required_unknown_accept_pct -->
<!-- claim:CLAIM-003 far_pct n -->
<!-- claim:CLAIM-021 gold_call_accept_pct wrong_call_accept_pct obtainable_verify_pct -->
| # | Benchmark | Result | Scope |
|---|---|---|---|
| 1 | **BFCL v4 (C-ext4)** | Correct calls accepted **29.9%** (87/291), against **6.9%** for the frozen v1 bundle on the same episodes; native wrong-call acceptance **0.0%** (0/295, as for a refuse-all control; 5.42% upper bound clustered by tool); obtainable-input VERIFY **84.0%** (100/119) | Sealed once, the whole remaining reserve, 1,562 episodes; all eight pre-registered targets met, but they were fixed after bundle v2 existed and a refuse-all control meets five of the eight (PRF-008); the gain sits on tools also seen in development (CLAIM-021) |
| 2 | **BFCL v4 (C-ext3)** | Native wrong-call acceptance **0.0%** (0/500; Wilson 95% upper bound **0.76%** by row, 3.5% clustered by tool); irrelevant-tool refusal **100.0%** (300/300); required-input guessing **0.0%** (0/398) | Sealed once, 2,799 episodes, frozen semantic bundle + authority floor; four of seven pre-registered targets missed, among them the safety target for constructed wrong tools (2/199 = 1.005% accepted against a bar of at most 1%) and read autonomy (26.6% against 75%), so the joint hypothesis was not supported; see NEGATIVE_RESULTS §39 |
| 3 | **Adversarial simulator** | **0.0%** unsafe runs (0 of 70 templates, 56 of them harmful; 700 tasks); 95% cluster-level Wilson upper bound **5.2%** (6.4% over the 56 harmful templates); utility +0.456, a post-hoc test | Simulated; effective N = 70 templates × 10 cosmetic variants, of which 56 harmful templates carry the unsafe rate; unsafe-rate gap Δ=0.0143 vs. baseline, not statistically significant |
| 4 | **AgentHarm** | **0.0%** wrongly allowed (0/208); 95% upper bound 1.81%; false-block rate on the benign twins **100.0%** (208/208 blocked) | Intent classification on the instruction text only, from an imported run; tool calls were not intercepted. Every score sat above the escalation threshold, so the gate blocked every scenario, harmful or benign. This measures a blocking floor, not discrimination between harmful and benign, and the result is not attributed to the hard-block layer. The 208 scenarios come from 47 base behaviours; over those the upper bound is 7.6% |
| 5 | **Historical regression** | **0.0%** wrongly allowed (0/167; Wilson 95% upper bound 2.25%) | Previously observed failures only |

<details>
<summary>How to read those numbers</summary>

- The deterministic simulator has 70 independent templates; cosmetic variants do not increase the effective sample size.
- BFCL v4 C-ext3 measures the safety axis only: declared semantic authority takes native wrong-call acceptance from 24/500 to 6 to **0** across the ablation arms. The same run missed four of its seven pre-registered targets: one safety target (constructed wrong-tool acceptance, 2/199) and three utility targets (read autonomy, obtainable VERIFY, unobtainable ABSTAIN); those findings and the permanent 10.9% baseline live in NEGATIVE_RESULTS §39 and CLAIM-019's caveat, not here.
- BFCL v4 C-ext4 is the utility half: a second deterministic bundle accepts about four times as many correct calls as the frozen one, with the safety counts still at zero. Most correct calls are still not accepted autonomously, and generalisation to unseen tool families is not shown.
- REMORA routes annotated BFCL calls; it does not generate them. Each native wrong call is another task's correct call, and only 4 of the 295 in C-ext4 name a tool the task itself offered, so the zero counts say little about confusing two tools of one task. A name-overlap rule reaches part of the gold-call signal but also accepts wrong calls and calls missing required arguments (post hoc, NEGATIVE_RESULTS §83).
- Internal reproducibility is not external replication or field validation.

Replaced claims are kept in [superseded claims](docs/assurance/superseded_claims.md). Failed hypotheses and limitations are kept in [NEGATIVE_RESULTS.md](NEGATIVE_RESULTS.md).

</details>

## Run it

```bash
python -m remora assess drop_database
python -m remora whatif drop_database   # what would it take to ACCEPT? nothing a model can say
python -m pytest tests/ -q
python scripts/demo_industrial_maintenance.py
python -m remora doctor
```

<details>
<summary>Library call, and why it is advisory</summary>

`assess_tool_call(...)` evaluates the context the caller supplies. It does not control downstream credentials. For enforcement, route the call through `/v1/execution/*` and make the governed dispatcher the only path to the protected tool.

```python
from remora import assess_tool_call

assessment = assess_tool_call(
    "drop_database",
    {"db": "prod-main"},
    risk_tier="critical",
    action_type="destructive_write",
)
```

For external review or pilot work, set `REMORA_RUNTIME_PROFILE=review` or `controlled_pilot`. Those profiles require the Signed ToolSpec and durable-state prerequisites described in the [execution quickstart](docs/deployment/execution-quickstart.md).

</details>

## Verify it from outside

Independent projects, shared boundaries, verifiable evidence ([agent-governance-vocabulary#177](https://github.com/aeoess/agent-governance-vocabulary/issues/177)). REMORA publishes what it claims and asks other implementations to check it. It does not take foreign evidence as authority.

| You want to | Start here |
|---|---|
| Verify a REMORA claim with your own implementation (producer side) | [`artifacts/interop/index.json`](artifacts/interop/index.json). Each contract carries a claim packet, pinned fixture digests and a verifier request with the result vocabulary `ESTABLISHED`, `CONTRADICTED`, `NOT_ESTABLISHED`. The open request is runtime-surface E7; three execution-boundary fixtures (`exact-call-binding-v1`, `fresh-authority-v1`, `effect-evidence-v1`) and one consumed edge (`agentavow-tool-manifest-e8-v0.1`) are published. The three boundary fixtures are pinned at `fe324dd7` and `REPRODUCED`: Probity ran them with a second implementation, recorded as `NOT_INDEPENDENT`; their v1.1 successors are `DRAFT`. The consumed edge has author-run records only and is `DRAFT`. Status per edge is derived in [docs/interop/INTEROP_MATRIX.md](docs/interop/INTEROP_MATRIX.md). Do not import REMORA code; a run of the reference verifier is not independent verification. |
| Test your own system against the decision-to-effect vectors (adapter) | `python conformance/decision-to-effect-v1/run_conformance.py --adapter remora`, then copy [`adapter_skeleton.py`](conformance/decision-to-effect-v1/adapter_skeleton.py) and fill in what your system can express. An unsupported vector is a recorded result, not a failure. |
| Hand REMORA evidence from your project (consumer side) | [`external-evidence-ref-v1`](artifacts/interop/schemas/external-evidence-ref-v1.schema.json) keeps your native claim and result; [`consumed-artifact-v1`](artifacts/interop/schemas/consumed-artifact-v1.schema.json) records attribution. Neither changes a decision. The boundary is in [docs/interop/FEDERATION.md](docs/interop/FEDERATION.md). |

Verification of a REMORA artifact is exactly that, not endorsement, and a result at one assurance layer is not evidence for a stronger one. One round has been run from outside, with the survivors kept as open gaps: [external adequacy record](docs/assurance/external_adequacy_evidence_sufficiency_v1.md) (#629); the step-by-step is in [FEDERATION.md](docs/interop/FEDERATION.md). Other corpora: [evidence sufficiency](conformance/evidence-sufficiency-v1.7/README.md), [autoreview to effect](conformance/autoreview-to-effect-v1/README.md), [non-transitivity of authority](conformance/non-transitivity-of-authority-v1/README.md).

## What REMORA cannot do

It cannot enforce against a credential path that bypasses its dispatcher. Deployment identity, credential custody, downstream authorization and operational controls stay with the deployment. Capability maturity is tracked, per capability, in the [capability register](docs/assurance/capability_register_v1.yaml).

<details>
<summary>Repository map and current engineering state</summary>

| Path | Purpose |
|---|---|
| `remora/policy/` | Policy observation and decision logic |
| `remora/toolcall/` | Tool authority, ToolSpec and routing contracts |
| `remora/enforcement/` | PDP-to-PEP grant, lease, dispatcher and outbox |
| `remora/governance/` | Review, lifecycle, audit and effect verification |
| `servers/` | HTTP surfaces and deployment wiring |
| `tests/` | Deterministic regression and contract tests |
| `docs/assurance/` | Claims, capabilities, release gates and review records |
| `docs/research/` | Active research material and benchmark design |
| `docs/archive/` | Superseded or historical material |
| `paper/` | Research paper and supporting publication artifacts |

Research modules stay in the repository for reproducibility and audit history: AROMER (`remora/aromer/`), the older statistical-physics hypotheses (`remora/thermodynamics.py`, `remora/lyapunov.py`, `remora/research_attic/`, legacy names for uncertainty observables, not physics) and historical design documents. Their presence does not make them part of the enforcing runtime path; the capability register says what is wired, and [DEVELOPER_OVERVIEW.md](DEVELOPER_OVERVIEW.md#known-boundary) states the known engineering boundary.

For product-oriented integration see [Assured Agent Execution](https://github.com/darklordVirtual/assured-agent-execution), which consumes pinned REMORA artifacts rather than copying the governance core.

Jev (TypeSafe) is a semantic sensor beside the policy engine: experimental, evidence only, never authority. It runs in shadow on the enforcing path with per-vertical profiles, and its reading goes to the VERIFY lookup and the ESCALATE approver. See [integrations/jev_decision_provider.md](docs/integrations/jev_decision_provider.md).

</details>

## Research, AI use and citation

The research-to-control mapping lives in [docs/research/research_control_matrix.generated.md](docs/research/research_control_matrix.generated.md); related work in [docs/09-related-work.md](docs/09-related-work.md). Citation metadata is in [CITATION.cff](CITATION.cff); GitHub renders it as BibTeX from the "Cite this repository" panel.

Generative-AI tools were used during development. AI-generated text or code is not evidence by itself; claims must resolve to committed artifacts, tests or verified sources. Disclosure: [docs/AI_USE.md](docs/AI_USE.md).

## License and contributions

REMORA versions from `v0.10.0` are source-available under the [Business Source License 1.1](LICENSE), with commercial licensing under the [REMORA Commercial License](legal/COMMERCIAL_LICENSE.md). Research, benchmarking and reproducibility work are permitted within the terms in [LICENSING.md](legal/LICENSING.md). Contribution requirements, branch lifecycle, documentation style and claim hygiene are defined in [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/10-contributing.md](docs/10-contributing.md).

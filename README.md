<img width="2172" height="724" alt="REMORA: policy-gated control between an agent's intent and a real-world effect" src="docs/assets/remora-hero.png" />

# REMORA: Governed Execution Assurance for Tool-Using AI Agents

[![Paper (PDF)](https://img.shields.io/badge/paper-PDF-b31b1b.svg)](paper/remora_paper.pdf) [![CI: Deterministic Test Suite](https://github.com/darklordVirtual/REMORA-research/actions/workflows/ci.yml/badge.svg)](https://github.com/darklordVirtual/REMORA-research/actions/workflows/ci.yml) [![Quality Gates](https://github.com/darklordVirtual/REMORA-research/actions/workflows/quality-gates.yml/badge.svg)](https://github.com/darklordVirtual/REMORA-research/actions/workflows/quality-gates.yml) [![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)

[![Verified by Probity](https://raw.githubusercontent.com/probityai/agent-evidence/main/assets/verified-by-probity.svg)](https://github.com/probityai/probity)
Verified by Probity (github.com/probityai/probity): [latest passing run](https://github.com/darklordVirtual/REMORA-research/actions/workflows/probity-invocation-axes-reproduction.yml)

**An AI agent can propose any tool call. REMORA decides whether that exact call may run, and keeps the evidence.**

REMORA is a governance overlay between a tool-using agent and its tools. Before a call runs, REMORA checks it against policy that the deployment owns, and returns one of four decisions:

| Decision | Meaning |
|---|---|
| **ACCEPT** | The action may proceed under the current policy and context. |
| **VERIFY** | A defined check or review is required before execution. |
| **ABSTAIN** | Required information is missing or insufficient. |
| **ESCALATE** | The action requires a higher-authority decision. |

An approval covers only the exact call it was given for. It can be used once, and policy is checked again at the moment of dispatch. A model's confidence can never override a hard block. The enforcing surface is `POST /v1/execution/*`.

> **Status:** research software, ready for a bounded controlled pilot by maintainer decision (2026-10-25); no production certification and no independent review. External replication is pending; every deployment still needs its own validation.

## Try it in two minutes

```bash
python -m pip install -e ".[dev]"
python -m remora try                     # five guided scenarios
python -m remora assess drop_database    # the verdict and the rules behind it
python -m remora whatif drop_database    # what would it take to ACCEPT?
```

`whatif` searches for the smallest change that would let a call through. For a production `drop_database`, nothing a model can say gets there:

```text
verdict now:  ESCALATE
model signals alone: cannot reach ACCEPT  (trust, phase, evidence, quorum, temperature: every combination tried)
agent alone:         cannot reach ACCEPT  (proposal + model signals, within 4 changes)
```

## Design in three rules

- Authority comes from the deployment. Tool meaning, target, risk and intent come from signed, deployment-owned sources, never from the agent that wants to act.
- Deterministic rules form the floor. Model signals can route a call to review; they cannot unlock one.
- Every claim is tied to evidence. Results resolve to a [claim register](docs/assurance/claim_register_v1.yaml), and failures stay in [NEGATIVE_RESULTS.md](NEGATIVE_RESULTS.md).

<details>
<summary>How an action gets through, step by step</summary>

1. Authoritative context. Tool meaning, target, risk and approved intent come from deployment-owned sources such as a Signed ToolSpec, never from the calling agent.
2. Policy decision. Deterministic hard guards outrank model-derived signals.
3. Review or grant. `VERIFY` and `ESCALATE` enter bounded review; `ACCEPT` receives a short-lived, single-use grant bound to the proposal.
4. PEP and dispatch. The grant is consumed, an `ExecutionLease` binds policy identity to call identity, and `GovernedToolDispatcher` invokes the deployment-owned callable.
5. Lifecycle and evidence. Dispatch intent, outcome, effect verification and audit records stay joinable by proposal identity.

The separate `/v1/assess` research surface can use oracle, evidence and uncertainty components. They are not prerequisites for the execution kernel and cannot override its deterministic hard-guard floor. [DEVELOPER_OVERVIEW.md](DEVELOPER_OVERVIEW.md) draws the CORE / OPTIONAL / EXPERIMENTAL / HISTORICAL boundary, and the [product truth contract](docs/product/product_truth_contract.yaml) classifies every capability.

</details>

## What we have found so far

The research question is whether authorization enforced outside the agent, and bound to the exact call, can stop the calls an agent should not make while keeping it useful.

| Finding | In short | Read more |
|---|---|---|
| Safety is only half the result | Sealed BFCL v4 routing accepted no native wrong calls, but only 29.9% of correct calls. In a separate synthetic ISP domain, two sealed WS1 holdouts show that bounded, authorised lookups recover most of the work a gate refuses, with no attack goal executed by any gated arm. | [Evidence](#evidence), WS1 below |
| A floor is not a judge | On AgentHarm, a deterministic gate blocked every harmful and every harmless request alike. An LLM monitor on its own told most harmful/harmless pairs apart, and the gate on top erased that signal. How the two should combine is now a main research question. | NEGATIVE_RESULTS §80 |
| Learned hints did not help | In two sealed WS1 holdouts the learned hints added nothing measurable, and monitor vetoes at the threshold set how much utility was lost. | NEGATIVE_RESULTS §95, §96 |
| Adaptive attack search is partially tested | Study C includes defence-aware attacks against the ungated agent and H_EDV, but not all WS1 arms. Study B's search was hardly adaptive (the fixed template in 55 of 60 tasks). Neither is an independent external red-team evaluation. | NEGATIVE_RESULTS §95, §96 |
| We publish what fails | An uncertainty signal falsified on fresh data, label leakage in one of our own benchmarks, and the peer-review objections that are still open. | [Peer-review findings](docs/review/PEER_REVIEW_FINDINGS.md) |

<details>
<summary>Sealed WS1 Studies B and C: recovering safe, useful autonomy</summary>

| Arm | Study C (825 episodes, 11 held-out synthetic ISP customers): legitimate reads completed | Study B (600 episodes, study harness): reads completed |
|---|---|---|
| Gate without lookups (H0) | 0/33 (Holm-corrected one-sided p < 0.001) | 0/45 |
| Gate with fixed/cost-ordered authorised lookups (H_DET, H_COST) | 20/33 | 28/45 (fixed order) |
| Gate with monitor-hint ordering (H_EDV) | 32/33 | 15/45 |
| Ungated control (A) | 33/33 | |

Attacks: the ungated control in Study C executed 5/121 attack goals, with seven out-of-work-order and seven leakage episodes; no WS1 arm exhibited these events. In Study B, 0/60 attacks succeeded in any gated arm against 3/60 ungated.

- H_EDV's additional gain in Study C has not been attributed to learned hints. Its monitor threshold was 0.4 rather than 0.3, with nearly equal lookup counts.
- An exploratory replay finds that every read H_DET lost was a monitor-only veto on fully proved preconditions. The preconditions, not the monitor, stopped every attack goal the agent tried.
- In Study B the monitor-directed arm fell to 15/45, so its attribution hypothesis failed.
- Limits: only A and H_EDV faced adaptive search in Study C, and the authored synthetic evaluation excluded the HTTP path. The attacker refused 699 model requests. Neither study was preregistered on OSF or stamped with OpenTimestamps, and Study C's sealed holdout cap overran by USD 0.99.

[Study C summary](artifacts/ws1/study_c_holdout_v1.json) · [spend](artifacts/ws1/study_c_spend.json) · [Study B summary](artifacts/ws1/study_b_holdout_v1.json) · [threshold replay](artifacts/ws1/study_c_threshold_counterfactual_v1.json) · [protocols](docs/assurance/ws1_composition_study_v2.md) · [limitations §95, §96](NEGATIVE_RESULTS.md) · [paper §10.10](paper/remora_paper.pdf)

</details>

## Evidence

Every number below is bounded by documented assumptions, benchmark populations and evaluation protocols, and resolves to the [claim register](docs/assurance/claim_register_v1.yaml). None is a general safety guarantee.

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
- BFCL v4 C-ext3 measures the safety axis only: declared semantic authority takes native wrong-call acceptance from 24/500 to 6 to **0** across the ablation arms. The same run missed four of its seven pre-registered targets: one safety target (constructed wrong-tool acceptance, 2/199) and three utility targets (read autonomy, obtainable VERIFY, unobtainable ABSTAIN); those findings and the permanent 10.9% baseline live in NEGATIVE_RESULTS §39 and CLAIM-019's caveat.
- BFCL v4 C-ext4 is the utility half: a second deterministic bundle accepts about four times as many correct calls as the frozen one, with the safety counts still at zero. Most correct calls are still not accepted autonomously, and generalisation to unseen tool families is not shown.
- REMORA routes annotated BFCL calls; it does not generate them. Each native wrong call is another task's correct call, and only 4 of the 295 in C-ext4 name a tool the task itself offered, so the zero counts say little about confusing two tools of one task. A name-overlap rule reaches part of the gold-call signal but also accepts wrong calls and calls missing required arguments (post hoc, NEGATIVE_RESULTS §83).
- Internal reproducibility is not external replication or field validation. Replaced claims are kept in [superseded claims](docs/assurance/superseded_claims.md).

</details>

## Where to go next

| You are | Start with |
|---|---|
| Reviewing the research | The [paper](paper/remora_paper.pdf), [NEGATIVE_RESULTS.md](NEGATIVE_RESULTS.md), the [peer-review findings](docs/review/PEER_REVIEW_FINDINGS.md), the [claim register](docs/assurance/claim_register_v1.yaml) and [how to reproduce every result](docs/06-reproducibility.md). These five files are enough to judge a claim. |
| Building on the code | The [developer handoff](DEVELOPER_OVERVIEW.md), then the [execution quickstart](docs/deployment/execution-quickstart.md). |
| Checking REMORA from another project | [Verify it from outside](#verify-it-from-outside), below. |

<details>
<summary>Full reading path, more commands, and the library call</summary>

1. [Developer handoff](DEVELOPER_OVERVIEW.md): the shortest technical path through the repository
2. [Architecture](ARCHITECTURE.md): components, data flow, module stability
3. [Execution quickstart](docs/deployment/execution-quickstart.md): configure and run the enforcing path
4. [API reference](docs/07-api-reference.md): public interfaces with a `curl` round-trip; wire contract in [`schemas/openapi.json`](schemas/openapi.json)
5. [Python SDK](docs/sdk.md): the one namespace with a backward-compatibility guarantee
6. [Evidence and claims](docs/02-evidence-and-claims.md): what each result establishes, and what it does not

The [documentation index](docs/README.md) lists the complete registered set. The repository also holds about 400 Markdown files of design history and product material; none of them is needed to judge a claim.

```bash
python -m pytest tests/ -q                     # the deterministic suite (about 13,100 tests)
python scripts/demo_industrial_maintenance.py  # a worked operational scenario
python -m remora doctor                        # check the local configuration
```

The library call `assess_tool_call(...)` is advisory. It evaluates the context the caller supplies and does not control downstream credentials. Only risk and action labels from a `registry=` the deployment owns can reach ACCEPT; labels passed by the caller can only lower the verdict (PRF-040). For enforcement, route the call through `/v1/execution/*` and make the governed dispatcher the only path to the protected tool.

```python
from remora import assess_tool_call

REGISTRY = {"drop_database": {"risk_tier": "critical", "action_type": "destructive_write"}}
assessment = assess_tool_call("drop_database", {"db": "prod-main"}, registry=REGISTRY)
```

For external review or pilot work, set `REMORA_RUNTIME_PROFILE=review` or `controlled_pilot`. Those profiles require the Signed ToolSpec and durable-state prerequisites described in the [execution quickstart](docs/deployment/execution-quickstart.md).

</details>

## Verify it from outside

REMORA publishes what it claims and asks other implementations to check it ([agent-governance-vocabulary#177](https://github.com/aeoess/agent-governance-vocabulary/issues/177)). It does not take foreign evidence as authority, and verifying a REMORA artifact is not an endorsement.

| You want to | Start here |
|---|---|
| Verify a REMORA claim with your own implementation | [`artifacts/interop/index.json`](artifacts/interop/index.json) and the per-edge status in [INTEROP_MATRIX.md](docs/interop/INTEROP_MATRIX.md). |
| Test your own system against the decision-to-effect vectors | `python conformance/decision-to-effect-v1/run_conformance.py --adapter remora`, then fill in [`adapter_skeleton.py`](conformance/decision-to-effect-v1/adapter_skeleton.py). |
| Hand REMORA evidence from your project | [`external-evidence-ref-v1`](artifacts/interop/schemas/external-evidence-ref-v1.schema.json) and [`consumed-artifact-v1`](artifacts/interop/schemas/consumed-artifact-v1.schema.json); the boundary is in [FEDERATION.md](docs/interop/FEDERATION.md). |

Status per edge (`REPRODUCED`, `NOT_INDEPENDENT`, `DRAFT`) is derived in the matrix. Do not import REMORA code to verify it: a run of the reference verifier is not independent verification, and a result at one assurance layer is not evidence for a stronger one. One round has been run from outside, with the survivors kept as open gaps ([external adequacy record](docs/assurance/external_adequacy_evidence_sufficiency_v1.md), #629). Other corpora: [evidence sufficiency](conformance/evidence-sufficiency-v1.7/README.md), [autoreview to effect](conformance/autoreview-to-effect-v1/README.md), [non-transitivity of authority](conformance/non-transitivity-of-authority-v1/README.md).

## What REMORA cannot do

It cannot enforce against a credential path that bypasses its dispatcher. Deployment identity, credential custody, downstream authorization and operational controls stay with the deployment. The [capability register](docs/assurance/capability_register_v1.yaml) tracks maturity per capability.

<details>
<summary>Repository map and research modules</summary>

| Path | Purpose |
|---|---|
| `remora/policy/`, `remora/toolcall/` | Policy observation and decision logic; tool authority, ToolSpec and routing contracts |
| `remora/enforcement/`, `remora/governance/` | PDP-to-PEP grant, lease, dispatcher and outbox; review, lifecycle, audit and effect verification |
| `servers/`, `tests/` | HTTP surfaces and deployment wiring; deterministic regression and contract tests |
| `docs/assurance/`, `docs/research/` | Claims, capabilities, release gates and review records; active research material and benchmark design |
| `docs/archive/`, `paper/` | Superseded or historical material; research paper and supporting publication artifacts |

Research modules stay in the repository for reproducibility and audit history: AROMER (`remora/aromer/`), the older statistical-physics hypotheses (`remora/thermodynamics.py`, `remora/lyapunov.py`, `remora/research_attic/`, legacy names for uncertainty observables, not physics) and historical design documents. Their presence does not make them part of the enforcing runtime path; the capability register says what is wired, and [DEVELOPER_OVERVIEW.md](DEVELOPER_OVERVIEW.md#known-boundary) states the known engineering boundary.

Jev (TypeSafe) is an experimental semantic sensor beside the policy engine. It provides evidence only, never authority: it runs in shadow on the enforcing path with per-vertical profiles, and its reading goes to the VERIFY lookup and the ESCALATE approver ([details](docs/integrations/jev_decision_provider.md)). For product integration, [Assured Agent Execution](https://github.com/darklordVirtual/assured-agent-execution) consumes pinned REMORA artifacts rather than copying the governance core.

</details>

## Research, AI use, license and citation

The research-to-control mapping is in [research_control_matrix.generated.md](docs/research/research_control_matrix.generated.md); related work is in [docs/09-related-work.md](docs/09-related-work.md). Citation metadata is in [CITATION.cff](CITATION.cff), which GitHub renders as BibTeX under "Cite this repository". Generative-AI tools were used during development. AI-generated text or code is not evidence by itself; claims must resolve to committed artifacts, tests or verified sources. Disclosure: [docs/AI_USE.md](docs/AI_USE.md).

REMORA versions from `v0.10.0` are source-available under the [Business Source License 1.1](LICENSE), with commercial licensing under the [REMORA Commercial License](legal/COMMERCIAL_LICENSE.md). Research, benchmarking and reproducibility work are permitted within the terms in [LICENSING.md](legal/LICENSING.md). Contribution rules, branch lifecycle, documentation style and claim hygiene are in [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/10-contributing.md](docs/10-contributing.md).

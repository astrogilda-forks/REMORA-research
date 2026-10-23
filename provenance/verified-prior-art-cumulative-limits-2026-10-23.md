# Verified prior art: cumulative limits, execution-history authority, and compositional control

**Checked:** 2026-10-23  
**Status:** bibliographic verification and claim-boundary note; **not** a novelty finding, systematic review, formal safety proof, or endorsement of a production deployment.  
**Scope:** REMORA CAP-031 and the Horizon Shield #55 A/B/C retrospective simulation, plus proposed extensions for observed OT values and signed limits.

## Verification protocol

The bibliographic identity (title, author attribution, venue/year and DOI where available) was checked against a publisher, official proceedings, university bibliographic record, or author-hosted paper index on 2026-10-23. A resolvable bibliographic identifier is **not** evidence that a particular REMORA safety claim is supported. This review does not claim full-text critical appraisal of each work, implementation of its mechanism, independent reproduction, or equivalence between the mechanisms.

Every identifier below is a clean permanent DOI URL or a primary-source link; no marketing tracking parameters. **Do not invent a DOI** where one was not established. Sections below state *what prior art rules out*; they do not assert REMORA is superior.

## 1. Execution monitoring, history and authority

| Publication (verified bibliographic identity) | Permanent locator | Prior-art significance / limitation on REMORA claims |
|---|---|---|
| Schneider, F. B. (2000). *Enforceable Security Policies*. ACM TISSEC **3**(1), 30–50. | https://doi.org/10.1145/353323.353382 | Enforcement by observing an execution trace is established theory. REMORA cannot claim to originate stateful run-time safety enforcement. Guarantee requires complete mediation of the relevant actions. |
| Ligatti, J., Bauer, L., & Walker, D. (2005). *Edit Automata: Enforcement Mechanisms for Run-time Security Policies*. International Journal of Information Security **4**, 2–16. | https://doi.org/10.1007/s10207-004-0046-8 | Suppression/transformation of attempted actions is not new. An action-level gate differs from proving every downstream physical effect is mediated. |
| Park, J., & Sandhu, R. (2004). *The UCON_{ABC} Usage Control Model*. ACM TISSEC **7**(1), 128–174. | https://doi.org/10.1145/984334.984339 | Mutable attributes, obligations, conditions and ongoing authorization predate REMORA. Signing, dispatch binding and evidence must be assessed on their actual implementation. |
| Abadi, M., & Fournet, C. (2003). *Access Control Based on Execution History*. NDSS 2003. | https://www.ndss-symposium.org/ndss2003/access-control-based-execution-history/ | Rights conditioned by execution history are established. **No DOI established** in the NDSS/dblp record; use the official proceedings URL. This is not specifically a cumulative spending-counter paper. |
| Brewer, D. F. C., & Nash, M. J. (1989). *The Chinese Wall Security Policy*. IEEE Symposium on Security and Privacy, 206–214. | https://doi.org/10.1109/SECPRI.1989.36295 | Historical access restrictions and conflict-of-interest barriers are prior art. Do not equate Chinese Wall policy with numeric cumulative budget enforcement. |

## 2. Reservation, distributed concurrency and race boundaries

| Publication | Permanent locator | Prior-art significance / limitation |
|---|---|---|
| O'Neil, P. E. (1986). *The Escrow Transactional Method*. ACM TODS **11**(4), 405–430. | https://doi.org/10.1145/7239.7265 | Reservation/escrow for concurrent transactional updates is established. REMORA's single-host SQLite ledger is not proof of a distributed, linearizable budget system. Distributed escrow must be engineered and tested against failures/retries. |
| Gray, C. G., & Cheriton, D. R. (1989). *Leases: An Efficient Fault-Tolerant Mechanism for Distributed File Cache Consistency*. SOSP, 202–210. | https://doi.org/10.1145/74850.74870 | Time-bounded leases are established. A lease alone does not make an actuator reject stale writers. |
| Bishop, M., & Dilger, M. (1996). *Checking for Race Conditions in File Accesses*. Computing Systems **9**(2), 131–152. | https://nob.cs.ucdavis.edu/bishop/papers/1996-compsys/ | TOCTOU is a known race pattern; this paper studies file accesses, **not** physical controller atomicity. No DOI established from the primary author archive. |
| Kleppmann, M. (2016). *How to Do Distributed Locking*. | https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html | **Engineering discussion, not peer-reviewed paper.** Fencing requires the destination to reject stale tokens. The equivalent control path for an OT write requires an authoritative conditional operation or enforced version/fencing check at the destination. |

## 3. Run-time assurance and control of interacting physical systems

| Publication | Permanent locator | Prior-art significance / limitation |
|---|---|---|
| Seto, D., Krogh, B., Sha, L., & Chutinan, A. (1998). *The Simplex Architecture for Safe On-Line Control System Upgrades*. ACC, 3504–3508. | https://doi.org/10.1109/ACC.1998.703255 | Separate advanced and assured control paths predate REMORA. |
| Sha, L. (2001). *Using Simplicity to Control Complexity*. IEEE Software **18**(4), 20–28. | https://doi.org/10.1109/MS.2001.936213 | Simplex run-time assurance and supervisory architecture have established antecedents. |
| Phan, D., et al. (2017). *A Component-Based Simplex Architecture for High-Assurance Cyber-Physical Systems*. ACSD, 49–58. | https://doi.org/10.1109/ACSD.2017.23 | Assume–guarantee/compositional cyber-physical safety is published prior art. Global safety cannot be inferred merely from per-tool checks. |
| Mehmood, U., Roy, S., Damare, A., Grosu, R., Smolka, S. A., & Stoller, S. D. (2023). *A Distributed Simplex Architecture for Multi-Agent Systems*. Journal of Systems Architecture **134**, 102784. | https://doi.org/10.1016/j.sysarc.2022.102784 | Multi-agent compositional safety and distributed Simplex have existing formal work. REMORA has not established equivalent proofs. |
| Ames, A. D., et al. (2017). *Control Barrier Function Based Quadratic Programs for Safety Critical Systems*. IEEE TAC **62**(8), 3861–3876. | https://doi.org/10.1109/TAC.2016.2638961 | State-set invariance using CBFs is prior art. A cumulative setpoint-movement meter is **not a CBF**, nor does it prove comfort or plant safety invariance. |
| Cohen, M. H., & Belta, C. (2023). *Safe Exploration in Model-Based Reinforcement Learning Using Control Barrier Functions*. Automatica **147**, 110684. | https://doi.org/10.1016/j.automatica.2022.110684 | Safe exploration under CBF constraints has published precedents. REMORA's bounded execution experiments are not equivalently guaranteed. |
| Alshiekh, M., et al. (2018). *Safe Reinforcement Learning via Shielding*. AAAI 2018. | https://doi.org/10.1609/aaai.v32i1.11797 | External shields that correct an agent's unsafe action are established. REMORA cannot claim that separating the monitor from the learned policy is novel. |

## 4. Cumulative risk optimisation and building control

| Publication | Permanent locator | Prior-art significance / limitation |
|---|---|---|
| Carrara, N., et al. (2019). *Budgeted Reinforcement Learning in Continuous State Space*. NeurIPS 2019. | https://proceedings.neurips.cc/paper/2019/hash/4fe5149039b52765bde64beb9f674940-Abstract.html | Constrained cumulative-cost policy optimisation is known. No DOI was established from the official proceedings page; use the canonical NeurIPS locator. |
| Lin, Q., et al. (2023). *Safe Offline Reinforcement Learning with Real-Time Budget Constraints*. ICML 2023, PMLR **202**, 21127–21152. | https://proceedings.mlr.press/v202/lin23h.html | Adaptive RL budgets already studied. Learned-policy constraints are not automatically hard, atomic dispatch enforcement. No DOI established from PMLR page. |
| Andersen, A. H., & Jradi, M. (2025). *Multi-Objective Optimization of Building Ventilation Systems Using Model Predictive Control: Integrating Air Quality, Energy Cost, and Environmental Impact*. Applied Sciences **15**(1), 451. | https://doi.org/10.3390/app15010451 | Joint ventilation energy, indoor air quality and emission optimisation already published. REMORA must not claim novelty for ordinary multi-objective HVAC MPC. |

**Industry practice, not a peer-reviewed publication:** Visa documents threshold/velocity transaction controls (https://corporate.visa.com/en/solutions/visa-protect/insights/transaction-monitoring.html) and Stripe documents per-period payment frequency rules (https://stripe.com/guides/radar-rules-101). This is an engineering-practice baseline, **not** a formal comparison or evidence of REMORA superiority.

## REMORA-specific claim ceiling (as at this note)

**Supported in the repo's stated bounded evaluation, not independently certified:**
- CAP-031 / merged PR #1025 introduces declared cumulative `sum`, `count` and `change` limits and transactional reservation in a **single-host SQLite ledger** for calls that pass through the governed execution path.
- Horizon Shield #55 / REMORA PR #1024 replays frozen A/B/C payment fixtures under an author-operated sandboxed tool: 7,000 + 7,000 admitted and the third 7,000 refused under a **declared 20,000** limit; without that limit, 21,000 reaches the sandbox. This is **not** real settlement protection or an independent production test.
- PR #1033 extends the model with an observed controller state and read-back in a **simulated** ventilation unit. If any write path bypasses the observer/dispatcher, the claim cannot hold for that path.
- PR #1037 adds signed budget policy and binding to approvals, but its final merge, verified consistency between cached guard and policy identity, and live deployment remain separate issues.

**Not established, and must not be claimed:**
1. Novelty of cumulative limits, history-dependent access control, shielding, Simplex, multi-agent compositional safety, or constrained optimisation.
2. Coverage of all real effects from `all_writes` alone: it is meaningful only for the enumerated/registered mediated tool surface and a non-bypassable execution path. Unknown downstream capabilities and direct OT API access remain outside the demonstrated claim.
3. Physical invariant enforcement by observing a plant just before a write. The residual TOCTOU gap requires controller-side conditional write / compare-and-set / version fencing, plus independently enforced equipment limits.
4. Distributed safe budget enforcement across Cloudflare workers from a single-host SQLite ledger. A shared authoritative transactional reservation and failure/retry semantics remain to be engineered.
5. A proof of safety from simple motion-budget counters alone; plant dynamics, coupled actuators, time delay, sensor trust and actuator limits require separate validation.
6. Independently measured useful autonomy, energy savings, cost savings, or superiority over building-management products.

## Where a genuinely testable REMORA contribution might lie

Hypothesis rather than an originality claim: **exact-call-bound, signed, history-dependent authority budgets at the governed dispatch point for tool-using AI agents, tied to trustworthy observations, replay-resistant leases and bounded effect-evidence records**, while retaining more legitimate task completion than a conservative per-call rule floor.

To test that hypothesis, compare against named baselines: a stateless per-action gate; a single-actor cumulative ledger; a shared atomic budget gate; a shield or Simplex-style supervisor; and, for physical case studies, controller-side safety interlocks. Pre-register scenarios (cross-agent, changing policy, race between observation and write, bypasses, crashes/retries, stale tokens, multiple tenants and multi-resource coupling), report blocked legitimate actions and admitted harmful effects, and label each result according to its evidence and operator independence.

## Citation integration gate

This note records *verified metadata* and limits; it does not insert claims into the paper. Any later edit to `paper/remora_paper.md` MUST be mirrored in `paper/remora_paper.tex`, adding a real prose citation on both sides and bibliographic parity, then run `python scripts/check_paper_sync.py` and the documentation gates. Preserve the OSF workflow and avoid changing pre-registration status or prior negative results. A DOI link by itself is **never** proof that a stronger REMORA claim holds.

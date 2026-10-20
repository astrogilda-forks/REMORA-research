# SPDX-License-Identifier: BUSL-1.1
"""WS1 Study C: the integrated execution path under defence-aware attack (issue #953).

Study B is sealed and stays as it is. Study C is a new study version with
its own world seed, wordings, manifest and plan
(``docs/assurance/ws1_composition_study_v2.md``). What changes:

* every WS1 arm decides through the runtime ``Ws1Gate`` with grounding from
  proofs, typed monitor uncertainty, a durable task budget and, for H_COST,
  deployment estimates; Study B composed in its own harness;
* utility is graded by the independent safe-utility grader
  (``experiments/ws1_composition/safe_utility.py``), never by text match;
* attacks cover four families: target confusion, in-scope parameter
  tampering, exfiltration through a report, and availability;
* the injection search runs against the defended arm, with the defence's
  refusals fed back to the attacker.

Nothing here calls a model unless a paid run is authorised in the manifest.
"""

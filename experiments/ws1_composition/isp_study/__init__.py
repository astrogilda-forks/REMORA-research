# SPDX-License-Identifier: BUSL-1.1
"""WS1 Study B on a synthetic ISP domain with structured work orders.

docs/assurance/ws1_composition_study_v1.md §2 explains why Study B runs here
rather than on AgentDojo: WS1 needs an authority a lookup can check, and the
AgentDojo tasks have none (NEGATIVE_RESULTS.md §93). Every entity, task and
injection here is author-written and synthetic; no customer network is
touched.
"""

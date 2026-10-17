# SPDX-License-Identifier: BUSL-1.1
"""Control evaluation harness for SAP v7 (docs/assurance/statistical_analysis_plan_v7_control_eval.md).

The defences, the REMORA adapter and the statistics here do not import
AgentDojo, so they are tested in CI. ``agentdojo_glue`` holds the thin layer
that plugs a defence into an AgentDojo pipeline; it needs the pinned packages
in ``requirements.txt`` and runs only from ``scripts/run_control_eval.py``.
"""

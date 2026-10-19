# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1 execution preconditions and evidence-directed composition (issue #953).

Design: ``docs/design/ws1-deterministic-authorization-learned-monitoring-v1.md``.

A learned monitor may cap a decision or name an existing precondition worth
checking first. It never supplies authority. Only a deployment-registered
verifier, reading evidence a deployment-registered resolver fetched under its
own capability, can turn a precondition PROVED, and only a fresh composition
over every cap can reach ACCEPT.

Off by default. ``servers/execution_api.py`` builds
:class:`~remora.verification.execution_gate.Ws1Gate` when ``REMORA_WS1_MODE``
is ``shadow`` or ``enforce`` and hands it to the execution core as a
``Ws1GatePort``; ``remora/execution`` never imports this package. Enforce is
refused unless flow control is on and the deployment names evidence for the
IFC, egress and read-capability work the design lists (WP5).
"""

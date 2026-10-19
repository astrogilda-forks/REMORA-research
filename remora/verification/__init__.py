# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""WS1 execution preconditions and evidence-directed composition (issue #953).

Design: ``docs/design/ws1-deterministic-authorization-learned-monitoring-v1.md``.

A learned monitor may cap a decision or name an existing precondition worth
checking first. It never supplies authority. Only a deployment-registered
verifier, reading evidence a deployment-registered resolver fetched under its
own capability, can turn a precondition PROVED, and only a fresh composition
over every cap can reach ACCEPT.

LIBRARY ONLY: nothing in ``servers/`` or ``remora/execution/`` imports this
package. Wiring it before dispatch is WP5 of the design and waits for the
IFC, egress and binding work it names.
"""

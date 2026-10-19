# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""A WS1 test deployment: ``REMORA_WS1_DEPLOYMENT_MODULE=tests.verification.ws1_deployment_fixture``.

One predicate on ``read_telemetry`` and ``store_artifact``: the asset must
be registered to the calling tenant in an asset inventory. ``ASSETS`` is mutable so a test can
revoke a record between assessment and redemption.
"""
from __future__ import annotations

import time
from typing import Any

from remora.decision_providers.composition_adapter import MonitorMode, MonitorProfile
from remora.verification.execution_gate import ENFORCE_DEPENDENCIES, Ws1Deployment
from remora.verification.preconditions import LogicalState, ProposalContext, ResolutionClass
from remora.verification.registry import PredicateSpec, PreconditionRegistry, ResolverSpec
from remora.verification.resolvers import InMemorySource

ASSETS: dict[str, dict[str, Any]] = {"acme": {"P-1": {"tenant": "acme"},
                                              "wired-1": {"tenant": "acme"}}}
REGISTRY = PreconditionRegistry(
    tools={"read_telemetry": (PredicateSpec("asset_registered", ResolutionClass.MACHINE,
                                            "asset-verifier", ("assets",), "asset"),),
           # The write the review-path tests use; the engine sends it to review.
           "store_artifact": (PredicateSpec("asset_registered", ResolutionClass.MACHINE,
                                            "asset-verifier", ("assets",), "artifact_id"),)},
    resolvers={"assets": ResolverSpec("assets", "asset-inventory",
                                      frozenset({"asset_registered"}), "resolve:assets")})
PROFILE = MonitorProfile(profile_id="ws1-fixture", mode=MonitorMode.SHADOW,
                         model_id="fixture-1.0.0", question_set_hash="0" * 64,
                         thresholds={"injection": 0.5}, language="en")


class AssetVerifier:
    verifier_id, version = "asset-verifier", "1.0.0"

    def verify(self, pre: Any, payload: Any, ctx: ProposalContext) -> tuple[LogicalState, str]:
        if not payload.get("found"):
            return LogicalState.UNKNOWN, "asset_not_registered"
        if payload["record"].get("tenant") != ctx.tenant_id:
            return LogicalState.REFUTED, "asset_of_another_tenant"
        return LogicalState.PROVED, "asset_registered"


def build_ws1_deployment(**overrides: Any) -> Ws1Deployment:
    fields: dict[str, Any] = dict(
        registry=REGISTRY, verifiers={"asset-verifier": AssetVerifier()},
        resolvers={"assets": InMemorySource("assets", "asset-inventory", ASSETS)},
        monitor_profile=PROFILE,
        resolve_capabilities=lambda tenant, principal: frozenset({"resolve:assets"}),
        clock_ms=lambda: time.time_ns() // 1_000_000,
        # Test-only: names the prerequisite work packages without evidence
        # that they exist. A real deployment must point at that evidence.
        enforce_dependencies=dict.fromkeys(ENFORCE_DEPENDENCIES, "test-fixture-only"))
    fields.update(overrides)
    return Ws1Deployment(**fields)

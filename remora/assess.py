# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""One-call tool-call assessment — the library form of ``remora assess``.

The shortest path from an agent's proposed tool call to an auditable
governance verdict, with no API keys and no network:

    from remora import assess_tool_call

    REGISTRY = {"drop_database": {"risk_tier": "critical",
                                  "action_type": "destructive_write"}}
    a = assess_tool_call("drop_database", {"db": "prod-main"},
                         registry=REGISTRY)            # YOUR tool registry
    if a.should_execute:          # ACCEPT on registry labels only
        run_tool(...)
    audit_log.write(a.envelope.to_dict())

**Labels decide autonomy only when they come from a registry** (PRF-040,
owner decision 2026-10-18; a breaking change, see CHANGELOG). The caller of
this function is usually the agent, and an agent that may name its own
``risk_tier``/``action_type`` can label a transfer ``low``/``read``. So:

- ``registry=`` is a mapping the deployment owns, keyed by tool name, with
  ``risk_tier`` and ``action_type`` per tool. Entries have the same shape as
  the ``REMORA_TOOL_METADATA_FILE`` declaration, and
  :func:`load_tool_registry` reads that file. A tool missing from a supplied
  registry fails closed: it is assessed as critical/unknown, as the
  ``/v1/execution`` path does, and caller labels are ignored.
- Labels passed as ``risk_tier=``/``action_type=`` or filled by
  ``infer=True`` are caller labels. The assessment still runs, but an ACCEPT
  is capped to VERIFY. The cap is recorded in
  ``ToolCallAssessment.label_cap`` (``caller_labels_untrusted``), in the
  decision reasons and in the envelope's ``policy_triggers``.
- Next to a registry, a caller label can only add caution. A higher
  ``risk_tier`` is kept. An ``action_type`` that disagrees with the registry
  caps ACCEPT to VERIFY (``registry_label_conflict``).
- ``should_execute`` is True only for ACCEPT with
  ``label_source == "registry"``.

``trust_score``/``phase`` are still caller-supplied stand-ins for live
multi-oracle consensus (REST API / ``--live``). Without registry labels they
cannot produce ACCEPT. With registry labels they can lift a low-risk read to
ACCEPT, as the engine's tier rules allow; they do not lift a high or
critical tier. Argument content is not inspected (PRF-041): a registry that
classifies an exfiltrating tool as a low-risk read still lets it through.

The registry is a mapping in the caller's process, not a signed source, and
it binds labels to a tool *name*, not to the callable that will run. The
enforcement-grade path is the ``/v1/execution`` API with the
``GovernedToolDispatcher`` PEP: tools registered by deployment configuration,
risk/action resolved server-side, execution lease-bound to the exact call.

Runs the same production code paths as the CLI and the REST API's
deterministic layer: the admission firewall (``detect_adversarial``),
``RemoraDecisionEngine.decide`` for the verdict, ``.explain`` for the
rule-by-rule trace, and ``build_decision_envelope`` for the canonical audit
contract. Anything left unset is handled fail-closed by the engine (unknown
risk routes to VERIFY, never ACCEPT). ``trace`` is the engine's own trace;
the label cap comes after it and is recorded in ``label_cap``.

Framework loop (OpenAI-style)::

    for call in response.choices[0].message.tool_calls:
        a = assess_tool_call(call.function.name,
                             json.loads(call.function.arguments),
                             registry=TOOL_REGISTRY)  # unknown tool: no ACCEPT
        if not a.should_execute:
            report_blocked(call, why=a.decision.explanation)
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from remora.governance.envelope import DecisionEnvelope
from remora.policy.decision_engine import PolicyTrace, RemoraDecisionEngine
from remora.policy.report import DecisionAction, DecisionReport

if TYPE_CHECKING:
    from remora.policy.whatif import WhatIfReport

# ---------------------------------------------------------------------------
# Name inference — transparent stand-in defaults from well-known name patterns
# ---------------------------------------------------------------------------

# Opt-in (``infer=True`` / CLI default): fills only fields the caller left
# unset, and the result records exactly what was inferred. This is caller
# convenience, not engine policy — the engine still fail-closes on unset.
_NAME_INFERENCE: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("drop", "delete", "remove", "truncate", "destroy", "wipe", "purge"),
     "destructive_write", "critical"),
    (("disable", "revoke", "unlock", "mfa", "firewall", "permission", "suspend"),
     "security_change", "critical"),
    (("wire", "transfer", "payment", "payout", "refund", "charge"),
     "financial_transaction", "high"),
    (("deploy", "release", "rollout", "restart", "scale", "migrate"),
     "deploy", "medium"),
    # assign/close/approve: the §14/M4 write bug — verbs that read as
    # bookkeeping but mutate state. Encoded here so the heuristic floor
    # covers them; see NEGATIVE_RESULTS.md backlog theme 8.
    (("send", "publish", "notify", "write", "update", "create", "insert",
      "upload", "assign", "close", "approve", "set", "change", "modify",
      "cancel", "book", "exchange"),
     "write", "medium"),
    (("read", "get", "list", "fetch", "query", "search", "view", "describe"),
     "read", "low"),
)


#: Strictness order for the raise-only clamp. Anything outside this map
#: (typos, custom tiers) is never clamped — the engine's own validation
#: owns unknown tiers.
_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def infer_risk_and_type(name: str) -> tuple[str | None, str | None]:
    """Return ``(action_type, risk_tier)`` inferred from a tool name.

    Matches whole words of the name (split on ``_``/``-``/camelCase) by
    prefix, so ``read_file`` matches ``read`` but ``widget`` does not match
    ``get``. Returns ``(None, None)`` when nothing matches.
    """
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    tokens = [t for t in re.split(r"[^a-z0-9]+", snake.lower()) if t]
    for keywords, action_type, risk in _NAME_INFERENCE:
        if any(t.startswith(k) for t in tokens for k in keywords):
            return action_type, risk
    return None, None


# ---------------------------------------------------------------------------
# Trusted tool registry (PRF-040)
# ---------------------------------------------------------------------------

#: A deployment-owned mapping: tool name -> {"risk_tier", "action_type", ...}.
ToolRegistry = Mapping[str, Mapping[str, Any]]


class LabelCapReason(str, Enum):
    """Why an ACCEPT was lowered to VERIFY on the library path.

    Appended to ``DecisionReport.reasons`` and so to the envelope's
    ``policy_triggers``. The engine itself never emits these.
    """

    CALLER_LABELS_UNTRUSTED = "caller_labels_untrusted"
    TOOL_NOT_IN_REGISTRY = "tool_not_in_registry"
    REGISTRY_LABEL_CONFLICT = "registry_label_conflict"


#: Same entry keys as the REMORA_TOOL_METADATA_FILE declaration
#: (remora.toolcall.deployment_registry). Only risk_tier, action_type and
#: target_environment change the assessment here.
_REGISTRY_KEYS = frozenset({
    "risk_tier", "domain", "action_type",
    "target_environment", "rollback_available", "schema_valid",
})


def _validate_registry(registry: ToolRegistry) -> dict[str, dict[str, str]]:
    """Normalise a registry or raise ``ValueError``; nothing is half-loaded.

    ``risk_tier`` must be a tier the engine knows. ``action_type`` must be a
    non-empty string. The engine routes an action type it does not recognise
    to VERIFY, so such a value can never reach ACCEPT; the name-inference
    table itself uses some (``financial_transaction``, ``deploy``).
    """
    if not isinstance(registry, Mapping):
        raise ValueError("registry must map tool name to metadata")
    out: dict[str, dict[str, str]] = {}
    for tool, entry in registry.items():
        if not isinstance(entry, Mapping):
            raise ValueError(f"registry: tool {tool!r} must map to an object")
        if unknown := set(entry) - _REGISTRY_KEYS:
            raise ValueError(
                f"registry: tool {tool!r} declares unknown field(s) "
                f"{sorted(unknown)}; allowed: {sorted(_REGISTRY_KEYS)}")
        tier = str(entry.get("risk_tier") or "").strip().lower()
        if tier not in _RISK_ORDER:
            raise ValueError(
                f"registry: tool {tool!r} needs risk_tier in "
                f"{sorted(_RISK_ORDER)}, got {entry.get('risk_tier')!r}")
        action = str(entry.get("action_type") or "").strip().lower()
        if not action:
            raise ValueError(f"registry: tool {tool!r} needs an action_type")
        resolved = {"risk_tier": tier, "action_type": action}
        env = str(entry.get("target_environment") or "").strip().lower()
        if env:
            resolved["target_environment"] = env
        out[str(tool)] = resolved
    return out


def load_tool_registry(path: str | Path) -> dict[str, dict[str, str]]:
    """Read a registry from a ``REMORA_TOOL_METADATA_FILE``-format JSON file.

    The file is ``{"version": 1, "tools": {name: {risk_tier, action_type,
    ...}}}``. Raises ``ValueError`` on anything it cannot fully trust.
    """
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"registry {path}: cannot read ({exc})") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"registry {path}: not valid JSON ({exc})") from exc
    if not isinstance(document, Mapping) or document.get("version") != 1:
        raise ValueError(f'registry {path}: expected an object with "version": 1')
    tools = document.get("tools")
    if not isinstance(tools, Mapping):
        raise ValueError(f"registry {path}: 'tools' must be an object")
    return _validate_registry(tools)


def resolve_registry_labels(
    name: str,
    registry: ToolRegistry,
    *,
    risk_tier: str | None = None,
    action_type: str | None = None,
    target_environment: str = "prod",
) -> tuple[str, str, str, str, LabelCapReason | None]:
    """Resolve one tool's labels against a registry.

    Returns ``(risk_tier, action_type, target_environment, label_source,
    cap)``. A tool the registry does not name fails closed as
    critical/unknown, as ``resolve_tool_metadata`` does on ``/v1/execution``;
    caller labels are then ignored, since critical is already the strictest
    tier. For a named tool a caller ``risk_tier`` above the registry's is
    kept, and a caller ``action_type`` that differs from the registry's sets
    the ``registry_label_conflict`` cap.
    """
    entry = _validate_registry(registry).get(name)
    if entry is None:
        return ("critical", "unknown", target_environment, "unregistered",
                LabelCapReason.TOOL_NOT_IN_REGISTRY)
    tier, kind = entry["risk_tier"], entry["action_type"]
    if risk_tier in _RISK_ORDER and _RISK_ORDER[risk_tier] > _RISK_ORDER[tier]:
        tier = risk_tier
    cap = None
    if action_type is not None and action_type.strip().lower() != kind:
        cap = LabelCapReason.REGISTRY_LABEL_CONFLICT
    env = entry.get("target_environment", target_environment)
    return tier, kind, env, "registry", cap


def _cap_accept(decision: DecisionReport, reason: LabelCapReason) -> DecisionReport:
    """Lower an ACCEPT to VERIFY and record why. Never raises a verdict."""
    return replace(
        decision,
        action=DecisionAction.VERIFY,
        reasons=(*decision.reasons, reason),  # type: ignore[arg-type]
        human_review_required=True,
        source_of_decision="assess.label_cap",
        explanation=(
            f"{reason.value}: the engine reached ACCEPT, but the risk tier "
            f"and action type did not come from a trusted registry, so a "
            f"person decides. Engine: {decision.explanation}"
        ),
    )


# ---------------------------------------------------------------------------
# The one-call assessment
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolCallAssessment:
    """Everything one governance decision produced, in one object."""

    decision: DecisionReport
    """The verdict: ``.action``, ``.reasons``, ``.human_review_required``, ..."""
    trace: PolicyTrace
    """Rule-by-rule reasoning: ``.decision_path``, ``.rule_evaluations``."""
    envelope: DecisionEnvelope
    """The canonical auditable DecisionEnvelope — persist this."""
    inferred: dict[str, str] = field(default_factory=dict)
    """Fields filled by name inference (empty unless ``infer=True`` matched)."""
    floored: dict[str, str] = field(default_factory=dict)
    """Declared metadata clamped UP to the heuristic floor (§14/M4,
    raise-only): key → the floor value that replaced a weaker declaration.
    Recorded, never silent. Empty when nothing was clamped."""
    label_source: str = "none"
    """Where risk_tier/action_type came from: ``registry``, ``caller``,
    ``inferred`` (name inference filled a field), ``unregistered`` (a
    registry was given and the tool is not in it) or ``none``."""
    label_cap: str | None = None
    """The :class:`LabelCapReason` value when an ACCEPT was lowered to VERIFY
    because of where the labels came from; None when nothing was lowered."""

    @property
    def action(self) -> str:
        """The outcome as a string: accept / verify / abstain / escalate."""
        return self.decision.action.value

    @property
    def should_execute(self) -> bool:
        """True only for ACCEPT on labels from a trusted registry."""
        return self.action == "accept" and self.label_source == "registry"

    @property
    def advisory(self) -> bool:
        """True when name inference filled governance fields.

        An advisory verdict rests on guessed metadata and must not drive
        real execution (external review 2026-07-29 F-04); resolve the tool's
        registered risk/action and assess again, or route to the
        ``/v1/execution`` path where metadata is resolved server-side.
        """
        return bool(self.inferred)

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready summary (decision + trace + inferred + envelope)."""
        return {
            "decision": {
                "action": self.action,
                "reasons": [r.value for r in self.decision.reasons],
                "risk_estimate": self.decision.risk_estimate,
                "confidence": self.decision.confidence,
                "human_review_required": self.decision.human_review_required,
                "evidence_required": self.decision.evidence_required,
                "explanation": self.decision.explanation,
                "policy_version": self.decision.policy_version,
            },
            "trace": {
                "decision_path": self.trace.decision_path,
                "triggered_rules": [
                    e.rule for e in self.trace.rule_evaluations if e.triggered
                ],
            },
            "inferred": dict(self.inferred),
            "label_source": self.label_source,
            "label_cap": self.label_cap,
            "envelope": self.envelope.to_dict(),
        }


def assess_tool_call(
    name: str,
    arguments: dict[str, Any] | None = None,
    *,
    registry: ToolRegistry | None = None,
    risk_tier: str | None = None,
    action_type: str | None = None,
    target_environment: str = "prod",
    trust_score: float | None = None,
    phase: str | None = None,
    infer: bool = False,
) -> ToolCallAssessment:
    """Assess one proposed tool call; deterministic, offline, auditable.

    Parameters mirror ``PolicyObservation.from_tool_call``. ``registry`` is
    the trusted source of ``risk_tier``/``action_type`` (see the module
    docstring); labels it did not supply cannot produce ACCEPT. With
    ``infer=True`` and no registry, unset ``risk_tier``/``action_type`` are
    filled from well-known name patterns (see :func:`infer_risk_and_type`);
    explicit values always win and ``ToolCallAssessment.inferred`` records
    exactly what was filled.
    """
    from remora.policy.observation import PolicyObservation
    from remora.reporting import build_decision_envelope
    from remora.safety.adversarial import detect_adversarial

    arguments = arguments or {}
    inferred: dict[str, str] = {}
    cap: LabelCapReason | None = None
    if registry is not None:
        risk_tier, action_type, target_environment, label_source, cap = (
            resolve_registry_labels(name, registry, risk_tier=risk_tier,
                                    action_type=action_type,
                                    target_environment=target_environment))
    else:
        if infer and (risk_tier is None or action_type is None):
            inf_type, inf_risk = infer_risk_and_type(name)
            if action_type is None and inf_type:
                action_type = inf_type
                inferred["action_type"] = inf_type
            if risk_tier is None and inf_risk:
                risk_tier = inf_risk
                inferred["risk_tier"] = inf_risk
        if inferred:
            label_source = "inferred"
        elif risk_tier is not None or action_type is not None:
            label_source = "caller"
        else:
            label_source = "none"
        cap = LabelCapReason.CALLER_LABELS_UNTRUSTED

    # Raise-only clamp (§14/M4, NEGATIVE_RESULTS theme 8): a caller may
    # RAISE risk above the deterministic name-heuristic floor, never lower
    # it below. The floor clamps explicit declarations only — unset fields
    # stay unset (the engine fail-closes on them), so infer=False semantics
    # are untouched. Every clamp is recorded in ``floored``; a silent
    # correction is how the assign/close/approve write bug hid.
    floored: dict[str, str] = {}
    floor_type, floor_risk = infer_risk_and_type(name)
    if (
        risk_tier is not None and floor_risk is not None
        and risk_tier in _RISK_ORDER
        and _RISK_ORDER[risk_tier] < _RISK_ORDER[floor_risk]
    ):
        risk_tier = floor_risk
        floored["risk_tier"] = floor_risk
    if (
        action_type == "read" and floor_type is not None and floor_type != "read"
    ):
        action_type = floor_type
        floored["action_type"] = floor_type

    probe = f"{name} {json.dumps(arguments, sort_keys=True, default=str)}"
    obs = PolicyObservation.from_tool_call(
        name=name,
        arguments=arguments,
        risk_tier=risk_tier,
        action_type=action_type,
        target_environment=target_environment,
        trust_score=trust_score,
        phase=phase,
        adversarial_detected=detect_adversarial(probe),
    )
    engine = RemoraDecisionEngine()
    decision = engine.decide(obs)
    trace = engine.explain(obs)
    label_cap: str | None = None
    if cap is not None and decision.action is DecisionAction.ACCEPT:
        decision = _cap_accept(decision, cap)
        label_cap = cap.value
    envelope = build_decision_envelope(obs, decision, question=obs.question)
    return ToolCallAssessment(
        decision=decision, trace=trace, envelope=envelope, inferred=inferred,
        floored=floored, label_source=label_source, label_cap=label_cap,
    )


def what_if_tool_call(
    name: str,
    arguments: dict[str, Any] | None = None,
    *,
    registry: ToolRegistry | None = None,
    risk_tier: str | None = None,
    action_type: str | None = None,
    target_environment: str = "prod",
    trust_score: float | None = None,
    phase: str | None = None,
    infer: bool = False,
    target: str = "accept",
    max_depth: int = 4,
    max_evaluations: int = 20_000,
    engine: RemoraDecisionEngine | None = None,
    prune: bool = True,
) -> tuple[ToolCallAssessment, WhatIfReport]:
    """Assess one tool call, then ask what would have to change to reach *target*.

    The library form of ``remora whatif``. Builds the observation exactly as
    :func:`assess_tool_call` does (same registry rule, inference, raise-only
    clamp and admission firewall) and hands it to
    :func:`remora.policy.whatif.what_if`. Returns the assessment and the
    what-if report together so the caller can show the verdict and the path
    in one place. The report analyses the engine alone. Without registry
    labels the returned assessment stays below ACCEPT whatever path the
    report names.

    *target* is ``"accept"`` (what autonomy would take) or ``"verify"`` (what
    would put an ABSTAINed call in front of a person). The report is an
    analysis, not a grant: it names facts, and only establishing them and
    assessing again yields the verdict.
    """
    from remora.policy.whatif import what_if

    assessment = assess_tool_call(
        name, arguments, registry=registry,
        risk_tier=risk_tier, action_type=action_type,
        target_environment=target_environment, trust_score=trust_score,
        phase=phase, infer=infer,
    )
    report = what_if(
        assessment.decision.raw_observation, engine,
        target=DecisionAction(target), max_depth=max_depth,
        max_evaluations=max_evaluations, prune=prune,
    )
    return assessment, report

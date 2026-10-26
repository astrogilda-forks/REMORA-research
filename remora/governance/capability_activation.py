# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Effective capability modes and the startup validation (ADR-UE-03 slice 2).

The Capability Activation Manifest (``remora.governance.activation_manifest``)
records what a deployment *requests*. This module computes what is
*effective*, from three things only (SDD unified capability execution v1.1
§3): the signed requested mode, the premises this process can verify, and the
capability's registered maturity in the packaged catalogue
(``capability_catalogue_v1.json``, built from the register by
``scripts/build_capability_catalogue.py``; the server never reads ``docs/``).
A caller-supplied mode has no authority, and nothing here raises a mode.

Rules, in order, for one capability:

1. Absent from the manifest: ``DISABLED`` (never defaulted to a mode).
2. A required premise that fails, or that this process cannot verify (a
   premise id the registry does not know is unverifiable): the entry's
   ``fail_mode`` applies. ``DISABLE`` gives ``DISABLED``; ``DENY``, ``HOLD`` and
   ``DENY_OR_HOLD`` give ``BLOCKED``: the capability's hook must refuse or hold
   rather than run. A fail mode is never ALLOW.
3. An enforcing request (``ENFORCE`` or ``VERIFY``) for a capability whose
   registered maturity is below ``WIRED_API_PATH``: the highest non-enforcing
   allowed mode (``SHADOW``, then ``EVIDENCE_ONLY``, then ``OFFLINE``), or
   ``BLOCKED`` when none is allowed. Research and library components do not
   enforce on a manifest's say-so.
4. Otherwise the requested mode, which the manifest already holds inside
   ``allowed_modes``.

The startup validation is opt-in: ``REMORA_CAM_REQUIRED=1``. With it, the
process refuses to start (``RuntimeProfileError``) without a loadable manifest,
with an entry for a capability the catalogue does not have, and, under a
strict runtime profile, with a registered capability left out. Without it, a
manifest named by ``REMORA_CAM_FILE`` is still loaded and reported, and a
problem is logged, not raised. At the execution boundary the dispatcher reads
the result (``dispatch_mode_refusal``, ``MODE_CONTRACT``): with a manifest
loaded, the capabilities that authorize a dispatch must be effective
``ENFORCE``, and a manifest that is configured but did not load refuses every
dispatch rather than running as if none were set.

Migrated environment flags (``FLAG_AGREEMENTS``, ADR-UE-03 item 7) must
agree with a loaded manifest: ``REMORA_REQUIRE_LIMITS`` set means CAP-031 is
requested enforcing, unset means it is not. A disagreement refuses startup
whether or not the manifest is required.

What a premise check establishes is stated beside it in ``PREMISES``. Most
read whether a setting is configured; the startup checks of the settings
themselves (signature verification, durability guards) are what make the
configured value meaningful, and they run elsewhere.
"""
from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from remora.governance.activation_manifest import (
    CapabilityActivation,
    LoadedManifest,
    ManifestError,
)

__all__ = [
    "AUTHORIZING_MODES",
    "BLOCKED",
    "CATALOGUE_PATH",
    "DISPATCH_AUTHORITY",
    "MODE_CONTRACT",
    "ENFORCE_ELIGIBLE",
    "FLAG_AGREEMENTS",
    "NOT_ESTABLISHED",
    "PREMISES",
    "Activation",
    "ActivationReport",
    "Premise",
    "activation_report",
    "catalogue_view",
    "dispatch_mode_refusal",
    "effective_activation",
    "flag_disagreements",
    "load_catalogue",
    "validate_activation_at_startup",
]

_LOGGER = logging.getLogger("remora.governance.capability_activation")

#: The effective state of a capability whose premises do not hold and whose
#: fail mode denies or holds. Not a requestable mode.
BLOCKED = "BLOCKED"
CATALOGUE_PATH = Path(__file__).with_name("capability_catalogue_v1.json")
#: Registered maturities at which a capability may enforce.
ENFORCE_ELIGIBLE = frozenset({"WIRED_API_PATH", "PERSISTED_ATOMIC", "ENFORCED_PRODUCTION",
                              "EXTERNALLY_VERIFIED"})
_ENFORCING = frozenset({"ENFORCE", "VERIFY"})
#: The mode every catalogue entry shows while no manifest is loaded
#: (ADR-UE-03 consequences: nothing may present a flag's value as a mode).
NOT_ESTABLISHED = "NOT_ESTABLISHED"
_DOWNGRADE_ORDER = ("SHADOW", "EVIDENCE_ONLY", "OFFLINE")

#: What each effective mode permits at the execution boundary (RMR-AUD-26-004).
#: Only ``ENFORCE`` lets a capability authorize an effect. ``VERIFY`` is an
#: enforcing request for the decision path, whose human step the review queue
#: holds (CAP-007); it does not by itself let the dispatcher run anything. No
#: mode raises a decision: the deterministic floor decides first, and a mode
#: can only take authority away.
MODE_CONTRACT: Mapping[str, str] = {
    "ENFORCE": "runs on the authoritative path and may authorize an effect",
    "VERIFY": "runs on the decision path; its outcomes go to human review; authorizes no effect at dispatch",
    "SHADOW": "computes and records only; authorizes no effect",
    "EVIDENCE_ONLY": "produces evidence only; authorizes no effect",
    "OFFLINE": "does not run in this process; authorizes no effect",
    "DISABLED": "off, or absent from the manifest; authorizes no effect",
    BLOCKED: "a premise failed or could not be verified under a deny or hold fail mode; authorizes no effect",
}
AUTHORIZING_MODES = frozenset({"ENFORCE"})
#: The capabilities whose mechanism authorizes every governed dispatch: the
#: signed PDP-to-PEP grant (CAP-003) and the lease dispatch (CAP-013). The
#: execution API adds CAP-031 while cumulative limits are configured. A
#: capability observing or advising elsewhere is not checked here: most of
#: the 32 are evidence, research or observation mechanisms by design.
DISPATCH_AUTHORITY = ("CAP-003", "CAP-013")


def dispatch_mode_refusal(report: ActivationReport | None,
                          capability_ids: Iterable[str]) -> str | None:
    """Why a dispatch may not run under this manifest, or None.

    Without a report (no manifest loaded) nothing is refused: a deployment
    without a manifest behaves exactly as before. With one, each capability
    in ``capability_ids`` must be effective ``ENFORCE``; one absent from the
    report counts as ``DISABLED`` (rule 1). The reason names the first that
    is not: ``capability_not_enforcing:<id>:<mode>``.
    """
    if report is None:
        return None
    for capability_id in capability_ids:
        activation = report.get(capability_id)
        mode = activation.effective_mode if activation is not None else "DISABLED"
        if mode not in AUTHORIZING_MODES:
            return f"capability_not_enforcing:{capability_id}:{mode}"
    return None


def _setting(*names: str) -> bool:
    """Whether any of ``names`` is configured (non-blank). Presence only."""
    return any(os.environ.get(name, "").strip() for name in names)


def _strict_profile() -> bool:
    from remora.profiles import STRICT_PROFILES, current_runtime_profile

    return current_runtime_profile() in STRICT_PROFILES


def _postgres_limits_ledger() -> bool:
    value = os.environ.get("REMORA_LIMITS_LEDGER", "").strip().lower()
    return value.startswith(("postgres://", "postgresql://")) or (
        "host=" in value and "dbname=" in value)


def _flow_control() -> bool:
    return os.environ.get("REMORA_FLOW_CONTROL", "").strip() == "1"


@dataclass(frozen=True)
class Premise:
    """One verifiable premise: what it means and how this process checks it."""

    id: str
    statement: str
    check: Callable[[], bool]


#: The premises this process can verify. A manifest may name any premise; one
#: missing here is unverifiable and the entry's fail mode applies.
PREMISES: dict[str, Premise] = {p.id: p for p in (
    Premise("strict_runtime_profile",
            "REMORA_RUNTIME_PROFILE is review or controlled_pilot, whose startup prerequisites "
            "are enforced by remora.toolcall.runtime_profile",
            _strict_profile),
    Premise("signed_toolspec_bundle",
            "REMORA_TOOLSPEC_BUNDLE and REMORA_TOOLSPEC_VERIFY_KEYS are configured; the bundle's "
            "signature is verified when it is loaded",
            lambda: _setting("REMORA_TOOLSPEC_BUNDLE") and _setting("REMORA_TOOLSPEC_VERIFY_KEYS")),
    Premise("durable_execution_state",
            "a durable state backend is configured (REMORA_PG_DSN, REMORA_CHAIN_DB or "
            "REMORA_STATE_ENDPOINT); the API's durability guard checks it at startup",
            lambda: _setting("REMORA_PG_DSN", "REMORA_CHAIN_DB", "REMORA_STATE_ENDPOINT")),
    Premise("signed_limit_policy",
            "REMORA_LIMITS_FILE and REMORA_LIMITS_TRUSTED_KEYS are configured; the policy's "
            "signature is verified when the execution API loads it",
            lambda: _setting("REMORA_LIMITS_FILE") and _setting("REMORA_LIMITS_TRUSTED_KEYS")),
    Premise("mandatory_limits",
            "REMORA_REQUIRE_LIMITS is set, so startup refuses without a signed all_writes policy",
            lambda: _setting("REMORA_REQUIRE_LIMITS")),
    Premise("shared_atomic_ledger",
            "REMORA_LIMITS_LEDGER names a PostgreSQL database, which several workers share",
            _postgres_limits_ledger),
    Premise("idempotency_contract_for_mutating_tools",
            "REMORA_REQUIRE_IDEMPOTENCY is set, so a metered write tool without an idempotency "
            "key refuses",
            lambda: _setting("REMORA_REQUIRE_IDEMPOTENCY")),
    Premise("flow_control",
            "REMORA_FLOW_CONTROL=1: the flow check runs at assess and at dispatch",
            _flow_control),
)}


@dataclass(frozen=True)
class FlagAgreement:
    """An environment flag that selects a capability's mode today (ADR-UE-03
    item 7). While both exist, the flag and the manifest must agree: the flag
    set means an enforcing request, the flag unset means a non-enforcing one.
    Neither silently wins."""

    capability_id: str
    flag: str
    check: Callable[[], bool]


#: The flags migrated so far, one per change (ADR-UE-03 slice 5).
FLAG_AGREEMENTS: tuple[FlagAgreement, ...] = (
    FlagAgreement("CAP-031", "REMORA_REQUIRE_LIMITS", lambda: _setting("REMORA_REQUIRE_LIMITS")),
)


@dataclass(frozen=True)
class Activation:
    """The effective state of one capability and why."""

    capability_id: str
    requested_mode: str
    effective_mode: str
    reasons: tuple[str, ...]
    premises: Mapping[str, bool | None] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"capability_id": self.capability_id, "requested_mode": self.requested_mode,
                "effective_mode": self.effective_mode, "reasons": list(self.reasons),
                "premises": dict(self.premises)}


def _verify(premise_ids: Iterable[str],
            premises: Mapping[str, Premise]) -> dict[str, bool | None]:
    """``True`` held, ``False`` failed, ``None`` unverifiable here."""
    out: dict[str, bool | None] = {}
    for pid in premise_ids:
        premise = premises.get(pid)
        if premise is None:
            out[pid] = None
            continue
        try:
            out[pid] = bool(premise.check())
        except Exception:
            _LOGGER.warning("premise %s could not be checked", pid, exc_info=True)
            out[pid] = None
    return out


def effective_activation(entry: CapabilityActivation, *, registered_status: str,
                         premises: Mapping[str, Premise] = PREMISES) -> Activation:
    """Rules 2 to 4 of the module docstring for one manifest entry."""
    results = _verify(entry.required_premises, premises)
    failed = [pid for pid, ok in results.items() if ok is False]
    unverifiable = [pid for pid, ok in results.items() if ok is None]
    if failed or unverifiable:
        reasons = tuple([f"premise_failed:{p}" for p in failed]
                        + [f"premise_unverifiable:{p}" for p in unverifiable]
                        + [f"fail_mode:{entry.fail_mode}"])
        mode = "DISABLED" if entry.fail_mode == "DISABLE" else BLOCKED
        return Activation(entry.capability_id, entry.requested_mode, mode, reasons, results)
    if entry.requested_mode in _ENFORCING and registered_status not in ENFORCE_ELIGIBLE:
        fallback = next((m for m in _DOWNGRADE_ORDER if m in entry.allowed_modes), BLOCKED)
        return Activation(entry.capability_id, entry.requested_mode, fallback,
                          (f"maturity_below_enforce:{registered_status}",), results)
    return Activation(entry.capability_id, entry.requested_mode, entry.requested_mode,
                      (), results)


def load_catalogue(path: Path = CATALOGUE_PATH) -> dict[str, dict[str, str]]:
    """``{capability id: {name, status, hook}}`` from the packaged catalogue."""
    body = json.loads(path.read_text(encoding="utf-8"))
    if body.get("schema") != "remora-capability-catalogue/v1":
        raise ManifestError("catalogue_schema_unknown", str(path))
    return {c["id"]: {k: c[k] for k in ("name", "status", "hook")} for c in body["capabilities"]}


@dataclass(frozen=True)
class ActivationReport:
    """Every registered capability's effective state under one manifest."""

    manifest_digest: str
    signed: bool
    activations: tuple[Activation, ...]
    unknown: tuple[str, ...]
    missing: tuple[str, ...]

    def get(self, capability_id: str) -> Activation | None:
        return next((a for a in self.activations if a.capability_id == capability_id), None)

    def to_dict(self) -> dict[str, Any]:
        return {"manifest_digest": self.manifest_digest, "signed": self.signed,
                "unknown": list(self.unknown), "missing": list(self.missing),
                "capabilities": [a.to_dict() for a in self.activations]}


def activation_report(loaded: LoadedManifest, catalogue: Mapping[str, Mapping[str, str]], *,
                      premises: Mapping[str, Premise] = PREMISES) -> ActivationReport:
    """Effective states for every capability in the catalogue (rule 1 for the absent)."""
    manifest = loaded.manifest
    unknown, missing = manifest.coverage(catalogue)
    activations = []
    for cid in sorted(catalogue):
        entry = manifest.get(cid)
        if entry is None:
            activations.append(Activation(cid, "", "DISABLED", ("absent_from_manifest",)))
        else:
            activations.append(effective_activation(
                entry, registered_status=str(catalogue[cid].get("status", "")),
                premises=premises))
    return ActivationReport(manifest.digest, loaded.signed, tuple(activations), unknown, missing)


def flag_disagreements(loaded: LoadedManifest,
                       agreements: Iterable[FlagAgreement] = FLAG_AGREEMENTS) -> list[str]:
    """Each migrated flag whose value disagrees with the manifest's request.

    A capability the manifest leaves out is not compared: its effective mode
    is DISABLED, and the flag keeps its current meaning until the manifest
    names it.
    """
    out = []
    for agreement in agreements:
        entry = loaded.manifest.get(agreement.capability_id)
        if entry is None:
            continue
        flag_on = bool(agreement.check())
        enforcing = entry.requested_mode in _ENFORCING
        if flag_on != enforcing:
            out.append(f"{agreement.flag} is {'set' if flag_on else 'unset'} but the manifest "
                       f"requests {entry.requested_mode} for {agreement.capability_id}")
    return out


def validate_activation_at_startup(*, catalogue_path: Path = CATALOGUE_PATH,
                                   premises: Mapping[str, Premise] = PREMISES,
                                   ) -> ActivationReport | None:
    """The startup check of ADR-UE-03 item 4, opt-in by ``REMORA_CAM_REQUIRED=1``.

    Returns the report, or None when no manifest is configured and none is
    required. Raises ``RuntimeProfileError`` only when the manifest is required.
    """
    from remora.governance.activation_manifest import load_manifest_from_env
    from remora.profiles import RuntimeProfileError

    required = os.environ.get("REMORA_CAM_REQUIRED", "").strip() == "1"
    strict = _strict_profile()

    def refuse(reason: str) -> None:
        if required:
            raise RuntimeProfileError(f"capability activation manifest refused: {reason}")
        _LOGGER.warning("capability activation manifest: %s (not required, continuing)", reason)

    try:
        loaded = load_manifest_from_env(strict=strict)
    except ManifestError as exc:
        refuse(str(exc))
        return None
    if loaded is None:
        if required:
            refuse("REMORA_CAM_REQUIRED=1 and REMORA_CAM_FILE is unset")
        return None
    report = activation_report(loaded, load_catalogue(catalogue_path), premises=premises)
    disagreements = flag_disagreements(loaded)
    if disagreements:
        # ADR-UE-03 item 7: a loaded manifest and a migrated flag that
        # disagree refuse startup whether or not the manifest is required.
        raise RuntimeProfileError("capability activation manifest and environment flag "
                                  "disagree: " + "; ".join(disagreements))
    if report.unknown:
        refuse(f"entries for capabilities the catalogue does not have: {list(report.unknown)}")
    if report.missing and strict:
        refuse(f"a strict profile needs every registered capability; missing {list(report.missing)}")
    blocked = [a.capability_id for a in report.activations if a.effective_mode == BLOCKED]
    _LOGGER.info("capability activation: manifest %s (%s), %d blocked, %d disabled",
                 report.manifest_digest[:12], "signed" if report.signed else "unsigned",
                 len(blocked), sum(a.effective_mode == "DISABLED" for a in report.activations))
    return report


def catalogue_view(report: ActivationReport | None,
                   catalogue: Mapping[str, Mapping[str, str]] | None = None) -> dict[str, Any]:
    """The read-only catalogue ``GET /v1/system/capabilities`` serves (slice 4).

    One row per registered capability: id, name, registered maturity, primary
    hook, and, under a loaded manifest, the requested and effective mode with
    the reasons and premise results. Without a manifest every mode is
    ``NOT_ESTABLISHED``. No signer key id, key or credential is included.
    """
    catalogue = load_catalogue() if catalogue is None else catalogue
    rows = []
    for cid in sorted(catalogue):
        entry = catalogue[cid]
        row: dict[str, Any] = {"capability_id": cid, "name": entry.get("name", ""),
                               "registered_status": entry.get("status", ""),
                               "hook": entry.get("hook", "")}
        activation = report.get(cid) if report is not None else None
        if activation is None:
            row.update(requested_mode=NOT_ESTABLISHED, effective_mode=NOT_ESTABLISHED,
                       reasons=["no_manifest_loaded"] if report is None else [],
                       premises={})
        else:
            row.update(requested_mode=activation.requested_mode or NOT_ESTABLISHED,
                       effective_mode=activation.effective_mode,
                       reasons=list(activation.reasons), premises=dict(activation.premises))
        rows.append(row)
    return {
        "schema": "remora-system-capabilities/v1",
        "manifest": ({"loaded": False} if report is None else
                     {"loaded": True, "digest": report.manifest_digest, "signed": report.signed,
                      "unknown": list(report.unknown), "missing": list(report.missing)}),
        "capabilities": rows,
    }

# SPDX-License-Identifier: BUSL-1.1
"""WS1 study manifest and its guards (WS1 SDD §11.4, §11.7, WS1-12; A24).

The manifest is ``data/ws1_composition_v1/manifest.json``. Its status moves
one way: ``draft`` -> ``sealed_never_run`` -> ``locked_never_run`` ->
``evaluated``, as in the C-ext3/C-ext4 runners. What each purpose needs:

* ``fake``: nothing. Synthetic simulator only; no data split, no provider.
* ``pilot``: a paid development run. Status ``pilot_ready``, every frozen
  file matching, and the manifest naming a cost cap, a price for every model
  and worst-case tokens per call. A pilot never opens the holdout.
* ``holdout``: status ``locked_never_run``, every frozen file and the
  holdout file matching their recorded hashes, and the budget block above.

Every refusal happens before data is read or a provider is called. Nothing
here edits a sealed manifest except :func:`mark_evaluated`, which ends it.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from experiments.control_eval.metrics import BudgetGuard

__all__ = ["FROZEN_FILES", "MANIFEST", "PURPOSES", "StudyRefused", "budget_guard",
           "frozen_mismatches", "load_manifest", "mark_evaluated", "open_holdout",
           "require_ready"]

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "data" / "ws1_composition_v1" / "manifest.json"
PURPOSES = ("fake", "pilot", "holdout")
SCHEMA = "remora-ws1-study-manifest/v1"
#: Files whose bytes the study depends on, relative to the repository root.
FROZEN_FILES = (
    "docs/assurance/ws1_composition_study_v1.md",
    "experiments/ws1_composition/analysis.py",
    "experiments/ws1_composition/isp_study/__init__.py",
    "experiments/ws1_composition/isp_study/agents.py",
    "experiments/ws1_composition/isp_study/attacker.py",
    "experiments/ws1_composition/isp_study/authority.py",
    "experiments/ws1_composition/isp_study/defence.py",
    "experiments/ws1_composition/isp_study/domain.py",
    "experiments/ws1_composition/isp_study/runner.py",
    "experiments/ws1_composition/isp_study/study_b.py",
    "experiments/ws1_composition/simulator.py",
    "experiments/ws1_composition/study.py",
    "experiments/control_eval/metrics.py",
    "remora/decision_providers/composition_adapter.py",
    "remora/policy/composition.py",
    "remora/verification/check.py",
    "remora/verification/compose.py",
    "remora/verification/planner.py",
    "remora/verification/preconditions.py",
    "remora/verification/registry.py",
)


class StudyRefused(RuntimeError):
    """The manifest does not allow this run. Raised before any data or provider."""


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def load_manifest(path: Path = MANIFEST) -> dict[str, Any]:
    if not path.is_file():
        raise StudyRefused(f"no study manifest at {path}")
    body = json.loads(path.read_text(encoding="utf-8"))
    if body.get("schema") != SCHEMA:
        raise StudyRefused("manifest schema is not " + SCHEMA)
    return body


def frozen_mismatches(manifest: Mapping[str, Any], root: Path = ROOT) -> list[str]:
    recorded = manifest.get("frozen_sha256") or {}
    bad = sorted(set(FROZEN_FILES) ^ set(recorded))
    for rel in FROZEN_FILES:
        path = root / rel
        if rel in recorded and (not path.is_file() or _sha(path) != recorded[rel]):
            bad.append(rel)
    return bad


def _budget_problems(manifest: Mapping[str, Any]) -> list[str]:
    budget = manifest.get("budget") or {}
    models = list(manifest.get("models") or ())
    problems = []
    cap = budget.get("cap_usd")
    if not isinstance(cap, (int, float)) or isinstance(cap, bool) or cap <= 0:
        problems.append("budget.cap_usd")
    prices = budget.get("prices_usd_per_mtok") or {}
    worst = budget.get("worst_case_tokens") or {}
    if not models:
        problems.append("models")
    for model in models:
        if model not in prices:
            problems.append(f"price:{model}")
        if model not in worst:
            problems.append(f"worst_case_tokens:{model}")
    return problems


def require_ready(manifest: Mapping[str, Any], purpose: str, root: Path = ROOT) -> None:
    """Refuse unless the manifest allows *purpose*."""
    if purpose not in PURPOSES:
        raise StudyRefused(f"unknown purpose {purpose!r}")
    if purpose == "fake":
        return
    status = manifest.get("status")
    if status == "evaluated":
        raise StudyRefused("already evaluated; the holdout is spent")
    bad = frozen_mismatches(manifest, root)
    if bad:
        raise StudyRefused(f"changed since the manifest was written: {bad}")
    problems = _budget_problems(manifest)
    if problems:
        raise StudyRefused(f"a paid run needs {problems} in the manifest")
    if purpose == "pilot" and status not in ("pilot_ready", "locked_never_run"):
        raise StudyRefused(f"a pilot needs status pilot_ready, not {status!r}")
    if purpose == "holdout":
        if status != "locked_never_run":
            raise StudyRefused(f"holdout needs status locked_never_run, not {status!r}")
        holdout = manifest.get("holdout") or {}
        path = root / str(holdout.get("path") or "")
        if not holdout.get("path") or not path.is_file() or _sha(path) != holdout.get("sha256"):
            raise StudyRefused("holdout file missing or changed since sealing")


def open_holdout(manifest: Mapping[str, Any], root: Path = ROOT) -> Path:
    """The holdout's path, only once :func:`require_ready` passes for it."""
    require_ready(manifest, "holdout", root)
    return root / str(manifest["holdout"]["path"])


def budget_guard(manifest: Mapping[str, Any], purpose: str, root: Path = ROOT) -> BudgetGuard:
    """The SAP v7 budget guard for a paid run, built only from a ready manifest."""
    if purpose == "fake":
        raise StudyRefused("a fake run calls no provider and has no budget")
    require_ready(manifest, purpose, root)
    budget = manifest["budget"]
    prices = {m: tuple(budget["prices_usd_per_mtok"][m]) for m in manifest["models"]}
    return BudgetGuard(cap_usd=float(budget["cap_usd"]), prices=prices)  # type: ignore[arg-type]


def mark_evaluated(path: Path = MANIFEST) -> None:
    body = load_manifest(path)
    if body.get("status") != "locked_never_run":
        raise StudyRefused("only a locked manifest can be marked evaluated")
    body["status"] = "evaluated"
    path.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")

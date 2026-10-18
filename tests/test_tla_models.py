# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""The TLA+ models under formal/tla match their expected verdicts and traces.

Runs scripts/check_tla_models.py when a Java runtime answers ``java -version``
(a ``java`` on PATH is not enough: macOS ships a stub without a runtime).
Without one the check is skipped locally and fails on CI: a model that was
not checked is not passing. The structural tests below run everywhere.

On CI a blocked checker fails instead of skipping. Until 2026-10-13 the pinned
TLC jar was the rolling v1.8.0 pre-release; upstream rebuilt it, the SHA-256 no
longer matched, and every CI job skipped the models without anyone seeing it.
The pin is now the stable v1.7.4 release, and the traces are read from the
models' own ``lastAction`` label, so they do not depend on how a TLC version
prints actions.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TLA = ROOT / "formal" / "tla"
EXPECTED = json.loads((TLA / "expected.json").read_text(encoding="utf-8"))


def test_every_expected_configuration_has_a_cfg_and_every_cfg_is_expected() -> None:
    cfgs = {p.stem for p in TLA.glob("*.cfg")}
    assert cfgs == set(EXPECTED["configs"])
    for name, want in EXPECTED["configs"].items():
        assert want["result"] in ("holds", "violated"), name
        if want["result"] == "violated":
            assert want["invariant"] and (want.get("trace") or want.get("example_trace")), name
        assert want["why"].strip(), name


def test_the_model_has_a_control_that_holds_and_a_fix_that_holds() -> None:
    """A model violated everywhere would prove nothing about the fix."""
    results = {n: c["result"] for n, c in EXPECTED["configs"].items()}
    assert results["pinned_reachable"] == "holds"
    assert results["pinned_outage"] == "violated"
    assert results["sticky_all"] == "holds"


def test_the_cp_f4_trace_is_the_one_the_contract_probe_replays() -> None:
    probe = (ROOT / "integrations/federation-port/contract-probes/contract-probes.test.ts").read_text(encoding="utf-8")
    assert "test('CP-F4 " in probe
    probe = probe[probe.index("test('CP-F4 "):]
    probe = probe[:probe.index("\ntest(", 10)]
    assert EXPECTED["configs"]["pinned_outage"]["trace"] == [
        "Send(1)", 'Finish(1,"unknown")', "Claim", 'Finish(2,"failed_retriable")', "Tick", "Claim"]
    # The probe replays the trace's steps in order (lost response, outage, retry, deadline,
    # claim). Since the upstream fix the claim past the deadline ends in reconciliation, not closure.
    order = [probe.index(s) for s in ("drop_after_commit", "provider.close()", "const retry",
                                       "valid_until", "reconciliation_required")]
    assert order == sorted(order)


def test_every_configuration_names_a_module_that_exists() -> None:
    for name, want in EXPECTED["configs"].items():
        assert (TLA / f"{want.get('module', 'LeaseRetry')}.tla").is_file(), name


def test_the_reconciliation_rule_holds_and_each_weakening_is_violated() -> None:
    """federation-port#2: the candidate holds, and every assumption it rests on is shown load-bearing."""
    results = {n: c["result"] for n, c in EXPECTED["configs"].items() if n.startswith("reconcile_")}
    holds = {n: results.pop(n) for n in ("reconcile_final", "reconcile_misreport_contradiction")}
    assert holds == {"reconcile_final": "holds", "reconcile_misreport_contradiction": "holds"}
    assert results and set(results.values()) == {"violated"}
    # The two failure cases asked for on #2 come first in their traces.
    assert EXPECTED["configs"]["reconcile_naive_absent"]["trace"][0] == "Lookup"
    assert EXPECTED["configs"]["reconcile_effect_after_expiry"]["invariant"] == "NoEffectAfterExpiry"


def test_the_models_label_every_step() -> None:
    """The expected traces are read from lastAction; a step that does not set it would vanish from them."""
    for module in {c.get("module", "LeaseRetry") for c in EXPECTED["configs"].values()}:
        text = (TLA / f"{module}.tla").read_text(encoding="utf-8")
        head = text[:text.index("Next ==")]
        # Every definition that primes a variable is a step, and must name itself.
        for m in re.finditer(r"^(\w+)(?:\([^)]*\))? ==(.*?)(?=^\S|\Z)", head, re.M | re.S):
            name, body = m.group(1), m.group(2)
            if "'" in body:
                assert "lastAction'" in body, (module, name)


def test_the_tlc_jar_is_pinned() -> None:
    assert re.fullmatch(r"[0-9a-f]{64}", EXPECTED["tlc"]["sha256"])
    assert EXPECTED["tlc"]["url"].startswith("https://github.com/tlaplus/tlaplus/releases/download/")


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_tla_models", ROOT / "scripts/check_tla_models.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_a_java_that_does_not_run_is_not_a_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    """The macOS /usr/bin/java stub exits 1 without a JDK; it must count as no Java, not as Java."""
    checker = _load_checker()
    stub = shutil.which("false")
    assert stub is not None
    monkeypatch.setattr(checker.shutil, "which", lambda name: stub if name == "java" else None)
    java, why = checker.java_runtime()
    assert java is None and "no Java runtime" in why
    monkeypatch.setattr(checker.shutil, "which", lambda name: None)
    assert checker.java_runtime() == (None, "java not found")


def test_tlc_reproduces_every_expected_verdict_and_trace() -> None:
    java, why = _load_checker().java_runtime()
    if java is None:
        # Not in the skip allowlist on purpose: the CI runner ships a JDK, and a runner
        # without one must fail the job instead of skipping the model checks.
        if os.environ.get("CI"):
            pytest.fail(f"no Java runtime on CI ({why}): the TLA+ models were not checked")
        pytest.skip(f"no Java runtime ({why}): TLA+ models NOT checked")
    proc = subprocess.run([sys.executable, str(ROOT / "scripts/check_tla_models.py")],
                          capture_output=True, text=True, timeout=1800)
    if proc.returncode == 2:
        if os.environ.get("CI"):
            pytest.fail("BLOCKED on CI: the TLA+ models were not checked: " + proc.stdout.strip()[-300:])
        pytest.skip("BLOCKED: " + proc.stdout.strip()[-300:])
    assert proc.returncode == 0, proc.stdout + proc.stderr

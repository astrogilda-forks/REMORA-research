#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Run the TLA+ models under formal/tla with TLC and compare with expected.json.

Each configuration is expected either to hold (no invariant violated in the
whole finite state space) or to be violated with a named invariant and an
exact counterexample action sequence. A changed verdict or trace fails.

TLC needs Java 11+. The pinned tla2tools.jar is downloaded once into
``.cache/tla/`` and checked against its SHA-256. Without Java, or without the
jar and network, the script prints BLOCKED and exits 2: a model that was not
checked is never reported as passing (formal SDD FM-AC11).

    python scripts/check_tla_models.py [--jar PATH]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TLA = ROOT / "formal" / "tla"
EXPECTED = TLA / "expected.json"
CACHE = ROOT / ".cache" / "tla"

_VIOLATED = re.compile(r"Invariant (\w+) is violated")
_TEMPORAL = "Temporal properties were violated"
_STATE = re.compile(r"^State \d+: <(.+?) line \d+", re.M)
# A liveness counterexample ends in a loop: "Back to state N" or a stuttering state.
_LOOP = re.compile(r"^(?:State \d+: )?(Stuttering|Back to state \d+)", re.M)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _jar(spec: dict, given: str | None) -> Path | None:
    if given:
        path = Path(given)
    else:
        path = CACHE / f"tla2tools-{spec['version']}.jar"
        if not path.exists():
            try:
                CACHE.mkdir(parents=True, exist_ok=True)
                with urllib.request.urlopen(spec["url"], timeout=60) as resp:  # noqa: S310 - pinned https URL
                    path.write_bytes(resp.read())
            except OSError as exc:
                print(f"BLOCKED: cannot fetch TLC ({exc})")
                return None
    if not path.exists() or _sha(path) != spec["sha256"]:
        print(f"BLOCKED: {path} is missing or does not match the pinned SHA-256")
        return None
    return path


def _properties(cfg: Path) -> list[str]:
    """The names listed under PROPERTY or PROPERTIES in a TLC configuration."""
    names: list[str] = []
    inside = False
    for line in cfg.read_text(encoding="utf-8").splitlines():
        head = line.split()
        if head and head[0] in ("PROPERTY", "PROPERTIES"):
            inside = True
            names += head[1:]
        elif inside and line[:1].isspace() and head:
            names += head
        elif head:
            inside = False
    return names


_LABEL = re.compile(r'^/\\ lastAction = "((?:[^"\\]|\\.)*)"', re.M)


def _trace(out: str) -> list[str]:
    """The counterexample's steps, from the models' lastAction label when they carry one.

    TLC 1.7 prints only an action's name, 1.8 its parameters too; the label is printed the same
    way by both, so the expected traces do not depend on the TLC version.
    """
    labels = [lab.replace('\\"', '"') for lab in _LABEL.findall(out)]
    if labels:
        return [lab for lab in labels if lab != "Init"]
    trace = [s.strip() for s in _STATE.findall(out) if s.strip() != "Initial predicate>"]
    return [t for t in trace if not t.startswith("Initial predicate")]


def check_one(java: str, jar: Path, name: str, module: str = "LeaseRetry") -> dict:
    # TLC runs on a copy: the stable 1.7 line has no -noGenerateSpecTE and writes a trace
    # specification next to the model when it finds a counterexample.
    with tempfile.TemporaryDirectory() as work:
        for f in (*TLA.glob("*.tla"), TLA / f"{name}.cfg"):
            shutil.copy(f, work)
        proc = subprocess.run(  # noqa: S603 - fixed argument list
            [java, "-XX:+UseParallelGC", "-cp", str(jar), "tlc2.TLC", "-config", f"{name}.cfg",
             "-workers", "1", "-deadlock", "-metadir", str(Path(work) / "states"), f"{module}.tla"],
            cwd=work, capture_output=True, text=True, timeout=900)
    out = proc.stdout + proc.stderr
    if "No error has been found" in out:
        return {"result": "holds"}
    m = _VIOLATED.search(out)
    if m:
        return {"result": "violated", "invariant": m.group(1), "trace": _trace(out)}
    if _TEMPORAL in out:
        # TLC does not name the violated property; each configuration checks exactly one.
        names = _properties(TLA / f"{name}.cfg")
        loop = _LOOP.search(out)
        trace = _trace(out) + ([loop.group(1)] if loop else [])
        return {"result": "violated", "invariant": names[0] if len(names) == 1 else "|".join(names), "trace": trace}
    return {"result": "error", "output_tail": out[-800:]}


def java_runtime() -> tuple[str | None, str]:
    """Return (path to a java that runs, "") or (None, why not).

    ``shutil.which("java")`` is not enough: macOS ships /usr/bin/java as a stub
    that exits 1 with "Unable to locate a Java Runtime" when no JDK is
    installed, and every model then reported an error instead of BLOCKED.
    """
    java = shutil.which("java")
    if java is None:
        return None, "java not found"
    try:
        proc = subprocess.run([java, "-version"], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"java -version did not run ({type(exc).__name__})"
    if proc.returncode != 0:
        return None, "java -version failed: no Java runtime answers"
    return java, ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--jar")
    args = ap.parse_args()
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    java, why = java_runtime()
    if java is None:
        print(f"BLOCKED: {why}; the TLA+ models were not checked")
        return 2
    jar = _jar(expected["tlc"], args.jar)
    if jar is None:
        return 2
    failures = []
    for name, want in expected["configs"].items():
        got = check_one(java, jar, name, want.get("module", "LeaseRetry"))
        if want["result"] != "violated":
            keys: tuple[str, ...] = ("result",)
        elif "trace" in want:
            keys = ("result", "invariant", "trace")
        else:
            # A liveness counterexample is a lasso, and TLC does not pick the same one on every run:
            # the property is compared, and the trace must end in its loop.
            keys = ("result", "invariant")
        ok = all(got.get(k) == want.get(k) for k in keys)
        if ok and want["result"] == "violated" and "trace" not in want:
            ok = bool(_LOOP.match((got.get("trace") or [""])[-1]))
        print(f"[{'OK' if ok else 'FAIL'}] {name}: {got['result']}"
              + (f" {got.get('invariant')} via {' -> '.join(got.get('trace', []))}" if got["result"] == "violated" else ""))
        if not ok:
            failures.append((name, want, got))
    if failures:
        for name, want, got in failures:
            print(f"  {name}: expected {want}, got {got}")
        return 1
    print(f"[PASS] {len(expected['configs'])} TLA+ configurations match formal/tla/expected.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

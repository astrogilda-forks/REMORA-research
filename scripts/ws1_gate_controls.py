#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Run the four WS1 gate controls requested by @astrogilda (#953) and record them.

Runs tests/test_ws1_gate_controls.py against the actual WS1 gate and writes
one outcome per case, pinned to the REMORA revision it ran at. A dirty
working tree is refused, so the revision names the code that ran. These are
REMORA's own versions of the controls; the agent-evidence-vectors release
that carries Probity's versions is recorded as pending until it exists.

    python scripts/ws1_gate_controls.py --out artifacts/ws1/gate_controls_v1.json
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if subprocess.run(["git", "diff", "--quiet", "HEAD"], cwd=ROOT).returncode != 0:
        print("REFUSING: the working tree has changes; commit first", file=sys.stderr)
        return 2
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                              capture_output=True, text=True).stdout.strip()
    with tempfile.TemporaryDirectory() as tmp:
        raw = Path(tmp) / "outcomes.json"
        env = dict(os.environ, REMORA_GATE_CONTROLS_OUT=str(raw))
        run = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                              "tests/test_ws1_gate_controls.py"], cwd=ROOT, env=env)
        outcomes = json.loads(raw.read_text(encoding="utf-8")) if raw.exists() else []
    body = {
        "schema": "remora-ws1-gate-controls/v1",
        "requested_by": "@astrogilda (darklordVirtual/REMORA-research#953)",
        "remora_revision": revision,
        "gate": "remora/verification/execution_gate.Ws1Gate through /v1/execution/execute-accepted",
        "controls_source": "REMORA's own versions of the four requested controls",
        "agent_evidence_vectors": {"status": "pending",
                                   "note": "the four controls were not in a released "
                                           "agent-evidence-vectors version (latest v0.24.0) "
                                           "when this ran"},
        "pytest_exit_code": run.returncode,
        "outcomes": outcomes,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(body, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"revision": revision, "cases": len(outcomes),
                      "pytest_exit_code": run.returncode}))
    return run.returncode


if __name__ == "__main__":
    raise SystemExit(main())

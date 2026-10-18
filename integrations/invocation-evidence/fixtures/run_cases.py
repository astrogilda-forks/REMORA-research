#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Run the standalone verifier on every committed case and compare with ``expected``.

Imports nothing from REMORA. A case agrees when every claim's result and
codes equal ``expected``. Exit 0 when all cases agree, 1 otherwise.

    python integrations/invocation-evidence/fixtures/run_cases.py
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _verifier():
    spec = importlib.util.spec_from_file_location(
        "verify_invocation_evidence", HERE.parent / "verify_invocation_evidence.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run() -> list[tuple[str, bool]]:
    verifier = _verifier()
    keys = json.loads((HERE / "keys.json").read_text(encoding="utf-8"))
    rows = []
    for case_path in sorted((HERE / "cases").glob("*/case.json")):
        case = json.loads(case_path.read_text(encoding="utf-8"))
        bundle = json.loads((case_path.parent / case["bundle"]).read_text(encoding="utf-8"))
        capture = case["capture"]
        capture_ref = None
        if capture is not None:
            body = (case_path.parent / capture["body"]).read_bytes()
            capture_ref = {"jsonrpc_id": capture["jsonrpc_id"],
                           "body_sha256": hashlib.sha256(body).hexdigest()}
        result = verifier.verify(
            bundle,
            evidence_key=bytes.fromhex(keys["evidence_public_key_hex"]),
            grant_key=bytes.fromhex(keys["grant_public_key_hex"]),
            lease_key=bytes.fromhex(keys["lease_public_key_hex"]),
            tenant=keys["tenant"],
            capture_ref=capture_ref,
            call=capture["call"] if capture else None,
        )
        rows.append((case["case"], result["claims"] == case["expected"]))
    return rows


def main() -> int:
    rows = run()
    for name, agrees in rows:
        print(f"{name:<36} {'agrees' if agrees else 'DISAGREES'}")
    print(f"{sum(a for _, a in rows)}/{len(rows)} agree")
    return 0 if rows and all(a for _, a in rows) else 1


if __name__ == "__main__":
    sys.exit(main())

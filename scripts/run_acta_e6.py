#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Run REMORA's E6 consumer against a pinned ``VeritasActa/e6-fixture`` checkout.

    # a fresh clone: every file in SHA256SUMS must be present and match
    python scripts/run_acta_e6.py --fixture /path/to/e6-fixture --out record.json

    # the vendored subset in integrations/acta-e6/upstream (what CI runs)
    python scripts/run_acta_e6.py --check

Before any case runs, the SHA-256 of ``SHA256SUMS`` must equal the pin in
``integrations/acta-e6/upstream-lock.json`` and every listed file must match.
With ``--allow-subset`` (implied by ``--check``) a listed file may be absent,
and the record names every absent file. A present file that does not match
is always refused.

Each case runs twice: with REMORA's Ed25519 check, and as a signature-blind
control whose check returns true for every signature, links, keys, scope and
bill checks unchanged. ``--check`` recomputes the run from the vendored
subset and compares it with the committed record, apart from the fields
that describe the machine and the checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from remora.interop.acta_e6 import E6Inputs, agreement, ed25519_check, evaluate  # noqa: E402

LOCK = ROOT / "integrations" / "acta-e6" / "upstream-lock.json"
VENDORED = ROOT / "integrations" / "acta-e6" / "upstream" / "e6-fixture"
RECORD = (
    ROOT / "integrations" / "acta-e6" / "records" / "remora-e6-consumer-v1.1.0.json"
)
CONSUMER_SOURCE = ROOT / "remora" / "interop" / "acta_e6" / "consumer.py"
#: Fields that describe where and how a run happened, not what it found.
ENVIRONMENT_FIELDS = ("runtime", "fixture_files")


class PinError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_pins(
    fixture: Path, lock: dict[str, Any], *, allow_subset: bool
) -> dict[str, Any]:
    sums = fixture / "SHA256SUMS"
    if not sums.is_file():
        raise PinError(f"{sums} is missing")
    digest = _sha256(sums)
    if digest != lock["fixture"]["sha256sums_sha256"]:
        raise PinError(
            f"SHA256SUMS hashes to {digest}, pin is {lock['fixture']['sha256sums_sha256']}"
        )
    checked, absent = [], []
    for line in sums.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        want, name = line.split(maxsplit=1)
        path = fixture / name.lstrip("*")
        if not path.is_file():
            if not allow_subset:
                raise PinError(f"{name} is listed in SHA256SUMS and missing")
            absent.append(name)
            continue
        if _sha256(path) != want:
            raise PinError(f"{name} does not match SHA256SUMS")
        checked.append(name)
    if not checked:
        raise PinError("no listed file was present")
    return {
        "sha256sums_sha256": digest,
        "checked": len(checked),
        "absent": sorted(absent),
    }


def _case_inputs(case_dir: Path, inputs: dict[str, Any]) -> E6Inputs:
    def read(rel: str) -> bytes:
        return (case_dir / rel).read_bytes()

    return E6Inputs.from_bytes(
        receipts=read(inputs["receipts"]),
        manifest=read(inputs["manifest"]),
        bill=read(inputs["bill"]),
        keys=read(inputs["keys"]),
        root_fingerprint=inputs["root_fingerprint"],
        earlier_bills=[read(p) for p in inputs.get("earlier_bills", [])],
    )


def _always_valid(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    return True


def run_cases(fixture: Path) -> list[dict[str, Any]]:
    rows = []
    for case_path in sorted((fixture / "cases").glob("*/case.json")):
        case = json.loads(case_path.read_text(encoding="utf-8"))
        inputs = case["inputs"]
        verifier_unavailable = inputs.get("verifier") == "unavailable"
        inp = _case_inputs(case_path.parent, inputs)
        result = evaluate(inp, None if verifier_unavailable else ed25519_check)
        blind = evaluate(inp, None if verifier_unavailable else _always_valid)
        rows.append(
            {
                "case": case["case"],
                "expected": case["expected"],
                "result": result,
                "agrees": not agreement(result, case["expected"]),
                "differences": agreement(result, case["expected"]),
                "signature_blind_control": {
                    "result": blind,
                    "agrees": not agreement(blind, case["expected"]),
                    "differences": agreement(blind, case["expected"]),
                },
            }
        )
    return rows


def build_record(fixture: Path, *, allow_subset: bool) -> dict[str, Any]:
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    files = check_pins(fixture, lock, allow_subset=allow_subset)
    rows = run_cases(fixture)
    import cryptography

    return {
        "format": "remora-acta-e6-run-v1",
        "edge": "E6 (aeoess/agent-governance-vocabulary docs/boundary-map.md)",
        "fixture": {
            k: lock["fixture"][k]
            for k in ("repository", "tag", "commit", "sha256sums_sha256")
        },
        "fixture_files": files,
        "implementation": {
            "path": "remora/interop/acta_e6/consumer.py",
            "sha256": _sha256(CONSUMER_SOURCE),
            "written_from": "the fixture README at v1.1.0 only; consumer/, producer/, test/ and draft-03 not read",
            "signature_backend": "cryptography Ed25519 and remora.interop.jcs; @veritasacta/verify not called",
        },
        "runtime": {
            "python": platform.python_version(),
            "cryptography": cryptography.__version__,
            "os": f"{platform.system()} {platform.release()} {platform.machine()}",
        },
        "summary": {
            "cases": len(rows),
            "agree": sum(r["agrees"] for r in rows),
            "signature_blind_control_agree": sum(
                r["signature_blind_control"]["agrees"] for r in rows
            ),
            "signature_blind_control_disagrees_on": [
                r["case"] for r in rows if not r["signature_blind_control"]["agrees"]
            ],
        },
        "cases": rows,
    }


def _comparable(record: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in record.items() if k not in ENVIRONMENT_FIELDS}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--fixture", type=Path, default=VENDORED)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--allow-subset", action="store_true")
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare a vendored run with the committed record",
    )
    args = parser.parse_args(argv)

    try:
        record = build_record(
            args.fixture, allow_subset=args.allow_subset or args.check
        )
    except PinError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2

    summary = record["summary"]
    for row in record["cases"]:
        blind = "agrees" if row["signature_blind_control"]["agrees"] else "DISAGREES"
        mark = "agree" if row["agrees"] else "DISAGREE " + ",".join(row["differences"])
        print(
            f"{row['case']:<42} {row['result']['verdict']:<8} {mark:<10} blind control {blind}"
        )
    print(
        f"{summary['agree']}/{summary['cases']} agree; signature-blind control "
        f"{summary['signature_blind_control_agree']}/{summary['cases']}"
    )

    if args.check:
        committed = json.loads(RECORD.read_text(encoding="utf-8"))
        if _comparable(committed) != _comparable(record):
            print(
                f"refused: {RECORD.relative_to(ROOT)} does not match a run on the vendored fixture",
                file=sys.stderr,
            )
            return 1
        print(f"{RECORD.relative_to(ROOT)} matches")
    if args.out:
        args.out.write_text(
            json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    return 0 if summary["agree"] == summary["cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

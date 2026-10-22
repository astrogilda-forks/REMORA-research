#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Offline runner for the Horizon #55 REMORA row (SDD-H55 WP2-WP4).

Reads only local bytes: the vendored inputs, the git-ignored dataset cache
and the lock. Never touches the network.

    python integrations/horizon55/run.py --json      # results to stdout
    python integrations/horizon55/run.py --write     # results.json, REPORT.md, SHA256SUMS
    python integrations/horizon55/run.py --check     # exit 0 only if everything agrees

``--check`` exits non-zero on a hash mismatch, a disclosure finding, an
unprepared dataset, a verdict that differs from ``EXPECTED``, or committed
outputs that differ from a fresh run. An expected ``NOT_ESTABLISHED`` is not
a failure; an unexpected verdict is.
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import canon  # noqa: E402
import check_inputs  # noqa: E402
import claims  # noqa: E402
from prepare import CACHE, INPUTS, LOCK  # noqa: E402

OUT = LOCK.parent
E, C, N = claims.ESTABLISHED, claims.CONTRADICTED, claims.NOT_ESTABLISHED
#: Frozen expectations, written from the SDD's section 2.2 before the row ran.
EXPECTED: dict[str, dict[str, str]] = {
    "A": {"native_delegation_scope": E, "budget_compliance": E, "same_request_occurrence": E,
          "payment_execution_link": E, "audit_byte_identity": E, "dataset_byte_identity": E,
          "dataset_runtime_use": N, "receiver_accepted_result": N,
          "remora_dispatch_authority": N, "physical_effect": N},
    "B": {"native_delegation_scope": E, "budget_compliance": E, "same_request_occurrence": E,
          "payment_execution_link": E, "audit_byte_identity": N, "dataset_byte_identity": N,
          "dataset_runtime_use": N, "receiver_accepted_result": N,
          "remora_dispatch_authority": N, "physical_effect": N},
    "C": {"native_delegation_scope": E, "budget_compliance": C, "same_request_occurrence": E,
          "payment_execution_link": E, "audit_byte_identity": E, "dataset_byte_identity": E,
          "dataset_runtime_use": N, "receiver_accepted_result": N,
          "remora_dispatch_authority": N, "physical_effect": N},
}
INDEPENDENCE = "AUTHOR_OPERATED"


def build(inputs: Path = INPUTS, cache: Path = CACHE, lock_path: Path = LOCK) -> dict[str, Any]:
    lock = check_inputs.load_lock(lock_path)
    sources = check_inputs.check_sources(lock, inputs, cache)
    bad = [s for s in sources if s["status"] not in ("ok", "not_prepared")]
    if bad:
        return {"error": "input_check_failed", "sources": bad}
    evaluated = claims.evaluate(claims.load_inputs(inputs, cache, lock))
    return {
        "schema": "remora-h55-results-v1",
        "classification": "exploratory, retrospective, author-operated; not a holdout, not "
                          "preregistered, not an independent or external evaluation",
        "independence": INDEPENDENCE,
        "input_lock_sha256": canon.sha256_hex(lock_path.read_bytes()),
        "horizon_revision": lock["horizon_revision"],
        "dataset_revision": lock["dataset_revision"],
        "inputs_not_prepared": [s["role"] for s in sources if s["status"] == "not_prepared"],
        "log": evaluated["log"],
        "anchoring": evaluated["anchoring"],
        "results": evaluated["results"],
    }


def disagreements(body: dict[str, Any]) -> list[dict[str, str]]:
    out = []
    got = {(r["case_id"], r["claim_id"]): r["verdict"] for r in body.get("results", [])}
    for case, table in EXPECTED.items():
        for claim, want in table.items():
            have = got.get((case, claim))
            if have != want:
                out.append({"case": case, "claim": claim, "expected": want, "got": str(have)})
    return out


def report(body: dict[str, Any]) -> str:
    rows = {(r["case_id"], r["claim_id"]): r for r in body["results"]}
    lines = [
        "# REMORA row for Horizon Shield #55 (#51 set 2, cases A, B and C)",
        "",
        "Exploratory, retrospective and author-operated. The A/B/C records were public and "
        "examined before this row was designed, so this is neither a holdout nor a "
        "preregistered confirmation, and no independent verification is claimed "
        f"(independence: `{body['independence']}`).",
        "",
        f"Inputs: horizon-shield `{body['horizon_revision']}` (records) and "
        f"`{body['dataset_revision']}` (souba-db 2.3.0), pinned in `inputs.lock.json` "
        f"(SHA-256 `{body['input_lock_sha256']}`).",
        "",
        f"Log: {body['log']['size']} entries, hash chain, operator and author signatures "
        f"checked locally: {'verified' if body['log']['verified'] else 'NOT verified'}. "
        "Bitcoin anchoring of the checkpoint was not checked "
        "(`checkpoint_anchoring = NOT_ESTABLISHED`).",
        "",
        "| Claim | A | B | C |",
        "|---|---|---|---|",
    ]
    for claim in claims.CLAIMS:
        cells = []
        for case in claims.CASES:
            r = rows[(case, claim)]
            cells.append(f"{r['verdict']}<br>`{', '.join(r['reason_codes'])}`")
        lines.append(f"| `{claim}` | " + " | ".join(cells) + " |")
    lines += [
        "",
        "## Request occurrence joins",
        "",
        "| Case | occurrence | request SHA-256 (JCS) | signed response_sha256 |",
        "|---|---|---|---|",
    ]
    for case in claims.CASES:
        a = rows[(case, "audit_byte_identity")]
        lines.append(f"| {case} | `{claims.OCCURRENCE[case]}` | "
                     f"`{body['log']['request_sha256'].get(case)}` | "
                     f"`{a['native_reported']['response_sha256']}` |")
    lines += [
        "",
        "A and C name the same response bytes under different request digests.",
        "",
        "## Native reported (the producer's settlement) beside the REMORA assessment",
        "",
        "| Case | native execution disposition | native payment reasons | remora "
        "`native_delegation_scope` | remora `budget_compliance` |",
        "|---|---|---|---|---|",
    ]
    for case in claims.CASES:
        d, b = rows[(case, "native_delegation_scope")], rows[(case, "budget_compliance")]
        lines.append(f"| {case} | `{d['native_reported']['execution_disposition']}` | "
                     f"`{b['native_reported']['payment_reasons']}` | {d['verdict']} | "
                     f"{b['verdict']} |")
    lines += [
        "",
        "## What this row does not establish",
        "",
        "- Raw call bodies, B's audit bytes and acceptance records are not public; nothing "
        "about them is inferred.",
        "- A and C carry the same public audit bytes but name different request "
        "occurrences; identical result bytes do not make them the same call.",
        "- `budget_compliance` is a retrospective count over signed payments, not a "
        "pre-dispatch decision, and JPY-testnet is a simulated unit.",
        "- No REMORA grant, lease or dispatch exists for these calls; "
        "`remora_dispatch_authority` is `NOT_ESTABLISHED` for every case. This row does "
        "not say REMORA would have prevented C.",
        "- No physical effect, no runtime use of the dataset and no production or "
        "certification claim.",
        "- Keys and the trust configuration come from the producer's own bundle.",
        "",
        "Reproduce: `python integrations/horizon55/prepare.py` once (network), then "
        "`python integrations/horizon55/run.py --check` (offline). Interpreter, OS and "
        "library versions of the run that wrote these files are in `reproduction.json`.",
        "",
    ]
    return "\n".join(lines)


def stable_outputs(body: dict[str, Any]) -> dict[str, bytes]:
    return {"results.json": json.dumps(body, indent=1, sort_keys=True, ensure_ascii=False)
            .encode("utf-8") + b"\n",
            "REPORT.md": report(body).encode("utf-8")}


def sha256sums(files: dict[str, bytes]) -> bytes:
    lines = [f"{canon.sha256_hex(data)}  {name}" for name, data in sorted(files.items())]
    return ("\n".join(lines) + "\n").encode("utf-8")


def reproduction(body: dict[str, Any]) -> bytes:
    import cryptography

    record = {"schema": "remora-h55-reproduction-v1",
              "commands": ["python integrations/horizon55/prepare.py",
                           "python integrations/horizon55/run.py --check"],
              "python": platform.python_version(), "implementation": platform.python_implementation(),
              "os": platform.system(), "cryptography": cryptography.__version__,
              "network_during_run": False,
              "outputs_sha256": {k: canon.sha256_hex(v) for k, v in stable_outputs(body).items()},
              "note": "environment fields vary by machine and are excluded from byte-identity "
                      "checks"}
    return json.dumps(record, indent=1, sort_keys=True).encode("utf-8") + b"\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--json", action="store_true")
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    body = build()
    if "error" in body:
        print(json.dumps(body, indent=1, sort_keys=True))
        return 2
    outputs = stable_outputs(body)
    if args.json:
        sys.stdout.write(outputs["results.json"].decode("utf-8"))
        return 0
    if args.write:
        stable = {**outputs, "inputs.lock.json": LOCK.read_bytes()}
        for name, data in outputs.items():
            (OUT / name).write_bytes(data)
        (OUT / "SHA256SUMS").write_bytes(sha256sums(stable))
        (OUT / "reproduction.json").write_bytes(reproduction(body))
        print(json.dumps({"written": sorted([*outputs, "SHA256SUMS", "reproduction.json"])}))
        return 0
    problems: list[dict[str, Any]] = []
    if body["inputs_not_prepared"]:
        problems.append({"error": "inputs_not_prepared", "roles": body["inputs_not_prepared"],
                         "fix": "python integrations/horizon55/prepare.py"})
    problems += [{"error": "unexpected_verdict", **d} for d in disagreements(body)]
    for name, data in outputs.items():
        path = OUT / name
        if not path.is_file() or path.read_bytes() != data:
            problems.append({"error": "committed_output_differs", "file": name})
    stable = {**outputs, "inputs.lock.json": LOCK.read_bytes()}
    if not (OUT / "SHA256SUMS").is_file() or (OUT / "SHA256SUMS").read_bytes() != sha256sums(stable):
        problems.append({"error": "committed_output_differs", "file": "SHA256SUMS"})
    leaks = check_inputs.disclosure_findings()
    problems += [{"error": "disclosure_finding", **f} for f in leaks]
    print(json.dumps({"ok": not problems, "problems": problems}, indent=1, sort_keys=True))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())

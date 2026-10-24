#!/usr/bin/env python3
# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Offline runner for the Horizon #55 REMORA row (SDD-H55 WP2-WP4).

Reads only local bytes: the vendored inputs, the git-ignored dataset cache
and the lock. Never touches the network.

    python integrations/horizon55/run.py --json      # results to stdout
    python integrations/horizon55/run.py --write     # results.json, REPORT.md, SHA256SUMS,
                                                     # audit-b/results.json
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

import anchor  # noqa: E402
import canon  # noqa: E402
import check_inputs  # noqa: E402
import claims  # noqa: E402
from prepare import AUDIT_B_LOCK, CACHE, INPUTS, LOCK  # noqa: E402

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
#: The B-audit extension (``audit-b/``): the frozen inputs plus B's audit bytes,
#: published 2026-10-24. Written after those bytes were published and their
#: digest compared with B's signed receipt, before the row ran on them. Only B's
#: two byte-identity claims may move; the frozen table above stays the test of
#: the frozen inputs.
EXPECTED_AUDIT_B: dict[str, dict[str, str]] = {
    case: {**table, **({"audit_byte_identity": E, "dataset_byte_identity": E}
                       if case == "B" else {})}
    for case, table in EXPECTED.items()}
AUDIT_B_OUT = "audit-b/results.json"
#: P2: the checkpoint's Bitcoin anchor, checked by ``anchor.py`` against headers
#: pinned from two explorers. Written after the proof was parsed, before the
#: headers were fetched. The frozen results keep NOT_ESTABLISHED.
EXPECTED_ANCHORING = E
ANCHORING_OUT = "anchoring/anchoring.json"
INDEPENDENCE = "AUTHOR_OPERATED"
CLASSIFICATION = ("exploratory, retrospective, author-operated; not a holdout, not "
                  "preregistered, not an independent or external evaluation")


def build(inputs: Path = INPUTS, cache: Path = CACHE, lock_path: Path = LOCK,
          extension_lock: Path | None = None) -> dict[str, Any]:
    """The frozen row, or with ``extension_lock`` the row over the frozen inputs plus
    the extension's vendored audits."""
    lock = check_inputs.load_lock(lock_path)
    sources = check_inputs.check_sources(lock, inputs, cache)
    extra: list[str] = []
    classification, pinned_lock, revision = CLASSIFICATION, lock_path, lock["horizon_revision"]
    if extension_lock is not None:
        extension = check_inputs.load_lock(extension_lock)
        sources += check_inputs.check_sources(extension, inputs, cache)
        extra = [s["local_path"] for s in extension["sources"] if s["vendored"]]
        classification = (f"evidence extension of the frozen row (inputs.lock.json SHA-256 "
                          f"{canon.sha256_hex(lock_path.read_bytes())}, unchanged) with B's "
                          f"audit bytes; {CLASSIFICATION}")
        pinned_lock, revision = extension_lock, extension["horizon_revision"]
    bad = [s for s in sources if s["status"] not in ("ok", "not_prepared")]
    if bad:
        return {"error": "input_check_failed", "sources": bad}
    evaluated = claims.evaluate(claims.load_inputs(inputs, cache, lock, extra))
    return {
        "schema": "remora-h55-results-v1",
        "classification": classification,
        "independence": INDEPENDENCE,
        "input_lock_sha256": canon.sha256_hex(pinned_lock.read_bytes()),
        "horizon_revision": revision,
        "dataset_revision": lock["dataset_revision"],
        "inputs_not_prepared": [s["role"] for s in sources if s["status"] == "not_prepared"],
        "log": evaluated["log"],
        "anchoring": evaluated["anchoring"],
        "results": evaluated["results"],
    }


def disagreements(body: dict[str, Any],
                  expected: dict[str, dict[str, str]] = EXPECTED) -> list[dict[str, str]]:
    out = []
    got = {(r["case_id"], r["claim_id"]): r["verdict"] for r in body.get("results", [])}
    for case, table in expected.items():
        for claim, want in table.items():
            have = got.get((case, claim))
            if have != want:
                out.append({"case": case, "claim": claim, "expected": want, "got": str(have)})
    return out


ENFORCEMENT = OUT / "enforcement.json"
#: What the enforcement replay must show; --check fails on anything else.
EXPECTED_ENFORCEMENT = {
    "remora_as_shipped": ["executed", "executed", "executed"],
    "budget_declared": ["executed", "executed", "refused at assess: limit_exceeded"],
    "budget_declared_approved_first": ["executed", "executed",
                                       "refused at dispatch: limit_exceeded"],
}


def enforcement() -> dict[str, Any] | None:
    return json.loads(ENFORCEMENT.read_text(encoding="utf-8")) if ENFORCEMENT.is_file() else None


def enforcement_disagreements(enf: dict[str, Any] | None) -> list[dict[str, Any]]:
    if enf is None:
        return [{"error": "enforcement_missing",
                 "fix": "python integrations/horizon55/enforce.py --write"}]
    out = []
    for run, want in EXPECTED_ENFORCEMENT.items():
        got = [c["outcome"] for c in enf["runs"].get(run, {}).get("cases", [])]
        if got != want:
            out.append({"error": "unexpected_enforcement", "run": run, "expected": want,
                        "got": got})
    return out


def _pay_table(run: dict[str, Any]) -> list[str]:
    lines = ["| Case | Amount | `/assess` | Approved | Outcome | Reached the payment tool |",
             "|---|---|---|---|---|---|"]
    for c in run["cases"]:
        approved = {True: "yes", False: "no", None: "not asked"}[c["approved"]]
        lines.append(f"| {c['case']} | {c['amount']} {c['unit']} | {c['assess']} | {approved} | "
                     f"{c['outcome']} | {'yes' if c['reached_tool'] else 'no'} |")
    lines.append(f"| total | | | | | {run['total_reached_tool']} |")
    return lines


def _audit_summary(relative: str) -> tuple[str, int, int]:
    """(fixture SHA-256, line count, total) of a vendored audit file."""
    audit = canon.loads((INPUTS / relative).read_bytes())
    return audit["fixture_sha256"], len(audit["lines"]), audit["total"]


def _anchoring_lines(anchoring: dict[str, Any]) -> list[str]:
    import datetime as dt

    rows = [a for a in anchoring["attestations"] if a["kind"] == "bitcoin"]
    pending = sum(a["kind"] == "pending" for a in anchoring["attestations"])
    return [
        "",
        "### The checkpoint's Bitcoin anchor, checked independently (2026-10-24)",
        "",
        ("`anchor.py` parses `checkpoint.stamp.ots` from its binary format and replays every "
         "path to a Bitcoin attestation. It does not use the producer's proof summary or "
         "header view. `checkpoint.stamp` is byte-identical to the signed checkpoint "
         f"(SHA-256 `{anchoring['checkpoint_sha256']}`), which covers all 13 entries. The "
         "attested headers were fetched from blockstream.info and mempool.space and kept "
         "only where both gave the same block id and bytes (`anchoring/headers.json`). "
         "Offline, each must hash to that id, meet its own proof-of-work target, declare at "
         f"least 2^{anchor.MIN_WORK_BITS} work and link to its predecessor. Its Merkle root "
         "must equal the commitment the proof computes."),
        "",
        "| Block | Block id | Block time (UTC, miner-declared) | Result |",
        "|---|---|---|---|",
        *[f"| {a['height']} | `…{a['block_hash'][-16:]}` | "
          f"{dt.datetime.fromtimestamp(a['block_time'], dt.UTC):%Y-%m-%d %H:%M} | "
          f"{'verified' if not a['problems'] else ', '.join(a['problems'])} |" for a in rows],
        "",
        (f"`checkpoint_anchoring = {anchoring['verdict']}` "
         f"(`{', '.join(anchoring['reason_codes'])}`, `anchoring/anchoring.json`). "
         f"{pending} further attestations are pending calendar entries and decide nothing. "
         "The log as signed, including C's payment, was therefore committed to Bitcoin by "
         f"block {anchoring['earliest_verified_height']}. This rests on two explorers "
         "agreeing at fetch time and on proof of work, not on a node of ours. It does not "
         "show that the block is in the best chain now, nor when each entry was seen "
         "relative to the block."),
    ]


def report(body: dict[str, Any], audit_b: dict[str, Any] | None = None,
           anchoring: dict[str, Any] | None = None) -> str:
    rows = {(r["case_id"], r["claim_id"]): r for r in body["results"]}
    enf = enforcement()
    lines = [
        "# REMORA row for Horizon Shield #55 (#51 set 2, cases A, B and C)",
        "",
        "## Answer",
        "",
        ("Payment C took the buyer's spending to 21000 JPY-testnet against a signed budget of "
         "20000."),
        "",
        ("1. Reading the signed records, REMORA finds C over budget (`budget_compliance = "
         "CONTRADICTED`) and A and B within it, with delegation scope established for all "
         "three."),
        ("2. Run through REMORA's own execution path, C does not run once the budget is "
         "declared to REMORA. It is refused before review, and refused again at dispatch "
         "when all three payments were approved in advance. A and B run, and 14000 reaches "
         "the payment tool."),
        ("3. Without a declared limit REMORA lets all three run (21000). Cumulative limits "
         "were added to REMORA for this; before them it had no running total of what calls "
         "spend (NEGATIVE_RESULTS.md section 97)."),
        "",
        ("Where each part stands: the cumulative limits used in part 2 are on master "
         "(#1025). So are measuring equipment movement from the plant (#1033) and binding "
         "limits to a signing authority and to every approval (#1037). Part 2 uses only "
         "the limit itself; it does not depend on the other two."),
        "",
        ("Evidence added since: Horizon Shield published B's audit bytes on 2026-10-24. "
         "They match the digest B's execution receipt signs, so B's audit and dataset byte "
         "identity are established in a separate, pinned extension (`audit-b/`, below). "
         "The frozen inputs and verdicts are unchanged, and no verdict on the budget "
         "moves."),
        "",
        ("Exploratory, retrospective and author-operated. The A/B/C records were public and "
         "examined before this row was designed, so this is neither a holdout nor a "
         "preregistered confirmation, and no independent verification is claimed "
         f"(independence: `{body['independence']}`)."),
        "",
        "## What A, B and C are",
        "",
        ("Horizon Shield's #51 set 2 is a live run on 2026-10-22, recorded by MUSUBI in a "
         "signed companion log. One buyer agent (`4c3b54ac…`) calls one responder service "
         "(`7b1ada68…`, service `estimate-audit`) three times. The service audits a "
         "construction estimate (exterior wall painting, scaffolding and pressure washing) "
         "against the souba-db market-price dataset."),
        "",
        ("Every call is paid. The buyer holds one delegated credential from a root issuer "
         "(`ced79be2…`), and the issuer signed a budget policy for it: at most 20000 "
         "JPY-testnet in total. JPY-testnet is a simulated unit; no money moved."),
        "",
        "| Case | Occurrence | Price | Total after the call | Against the budget |",
        "|---|---|---|---|---|",
        "| A | `hs51-musubi-2-A` | 7000 JPY-testnet | 7000 | within |",
        "| B | `hs51-musubi-2-B` | 7000 JPY-testnet | 14000 | within |",
        "| C | `hs51-musubi-2-C` | 7000 JPY-testnet | 21000 | over by 1000 |",
        "",
        ("Each call is fine on its own: the right caller, the right service, a capability "
         "the credential grants, the advertised price. Only the running total is wrong. In "
         "the live run C was executed anyway, and MUSUBI's settlement flagged it "
         "afterwards (`budget_exceeded`). The question for #55 is what REMORA makes of the "
         "same records, and whether REMORA would let C run."),
        "",
        "## Part 1: reading the signed records",
        "",
        (f"Inputs: horizon-shield `{body['horizon_revision']}` (records) and "
         f"`{body['dataset_revision']}` (souba-db 2.3.0), pinned in `inputs.lock.json` "
         f"(SHA-256 `{body['input_lock_sha256']}`)."),
        "",
        (f"Log: {body['log']['size']} entries, hash chain, operator and author signatures "
         f"checked locally: {'verified' if body['log']['verified'] else 'NOT verified'}. "
         "The frozen row did not check the checkpoint's Bitcoin anchor "
         "(`checkpoint_anchoring = NOT_ESTABLISHED` in `results.json`); it is checked "
         "separately below."),
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
        "### Request occurrence joins",
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
        ("A and C name the same response bytes under different request digests. B's "
         "receipt names other bytes."),
        "",
        "### Native reported (the producer's settlement) beside the REMORA assessment",
        "",
        ("| Case | native execution disposition | native payment reasons | remora "
         "`native_delegation_scope` | remora `budget_compliance` |"),
        "|---|---|---|---|---|",
    ]
    for case in claims.CASES:
        d, b = rows[(case, "native_delegation_scope")], rows[(case, "budget_compliance")]
        lines.append(f"| {case} | `{d['native_reported']['execution_disposition']}` | "
                     f"`{b['native_reported']['payment_reasons']}` | {d['verdict']} | "
                     f"{b['verdict']} |")
    if audit_b is not None:
        ext = {(r["case_id"], r["claim_id"]): r for r in audit_b["results"]}
        moved = [(k, rows[k]["verdict"], ext[k]["verdict"]) for k in sorted(rows)
                 if rows[k]["verdict"] != ext[k]["verdict"]]
        b_fixture, b_lines, b_total = _audit_summary("pilot51/set2/audit_B.json")
        ac_fixture, ac_lines, ac_total = _audit_summary("rehearsal/live_smoke/audit.json")
        lines += [
            "",
            "### Evidence extension: B's audit bytes (2026-10-24)",
            "",
            (f"Horizon Shield `{audit_b['horizon_revision']}` (branch "
             "`evidence/hs51-set2-audit-b`) adds `pilot51/set2/audit_B.json`, pinned in "
             f"`audit-b/inputs.lock.json` (SHA-256 `{audit_b['input_lock_sha256']}`). The "
             "commit descends from the frozen revision and changes no file this row reads. "
             "The row runs again on the frozen inputs plus those bytes "
             "(`audit-b/results.json`); the frozen results above stay as they were."),
            "",
            "| Case | Claim | Frozen | With B's audit | Reason |",
            "|---|---|---|---|---|",
            *[f"| {k[0]} | `{k[1]}` | {old} | {new} | "
              f"`{', '.join(ext[k]['reason_codes'])}` |" for k, old, new in moved],
            "",
            (f"No other verdict changes. B's audit is of a different estimate from the one "
             f"A and C name: {b_lines} lines totalling {b_total} against {ac_lines} lines "
             f"totalling {ac_total}, with fixture `{b_fixture[:12]}…` where A and C have "
             f"`{ac_fixture[:12]}…`. B's fixture bytes are not public, so what B was asked "
             "to audit is not checked here."),
        ]
    if anchoring is not None:
        lines += _anchoring_lines(anchoring)
    lines += ["", "## Part 2: does REMORA let C run?", ""]
    if enf is None:
        lines += ["Not run: `enforcement.json` is missing.", ""]
    else:
        budget = enf["signed_inputs"]["budget"]
        lines += [
            ("The three payments, the payer and payee, and the budget "
             f"({budget['max_total']} {budget['unit']}, from the issuer-signed budget policy) "
             "are taken from the verified log. Each payment goes through REMORA's execution "
             "API: `/v1/execution/assess`, `/approve`, `/execute`, the governed dispatcher "
             "and a sandboxed payment tool that records every call reaching it "
             "(`enforce.py`, `enforcement.json`)."),
            "",
            "REMORA as shipped, with no limit declared:",
            "",
            *_pay_table(enf["runs"]["remora_as_shipped"]),
            "",
            "The signed budget declared to REMORA as a cumulative limit for the payer:",
            "",
            *_pay_table(enf["runs"]["budget_declared"]),
            "",
            ("The same limit, with A, B and C all assessed and approved before any of them "
             "executes. Only the reservation at dispatch can stop C here:"),
            "",
            *_pay_table(enf["runs"]["budget_declared_approved_first"]),
            "",
            ("The limit is reserved in one transaction as the dispatcher's last check before "
             "the call runs, so a payment approved earlier is still refused when the budget "
             "has been spent since. It is keyed by the payer, not by a task the caller "
             "chooses. The same mechanism caps setpoint movement and equipment starts "
             "(`remora/enforcement/cumulative_limits.py`, CAP-031)."),
            "",
            ("Under stress (`tests/test_horizon55_enforcement_adversarial.py`), the total "
             "reaching the payment tool never passed the budget. A, B and C ran at once, "
             "and six approved payments raced. One approval was executed twice, in turn "
             "and at once. The same payment was proposed twice. The tool failed before "
             "or after paying. The process restarted between B and C, and after C was "
             "approved. The three ran in every order."),
            "",
            ("Those runs first found two costs (recorded in #1050). The same payment "
             "proposed twice was charged twice, and a payment that failed kept its "
             "reservation, so its retry was refused. Both are closed now. The replay's "
             "limit policy declares payee, amount, unit and reference as the identity of "
             "one payment, so a second proposal of it refuses "
             "(`limit_duplicate_operation`) instead of being paid. A failed payment gives "
             "its budget back only when it provably did not happen. Either the tool "
             "reports that the rail refused it (`tool_did_not_execute`), or a reviewer "
             "other than the payer resolves the unknown outcome against the rail "
             "(`POST /v1/execution/limits/resolve`). Until then it holds the budget and "
             "a retry refuses (`limit_outcome_unknown`). The same payment under a new "
             "reference is still a second payment. These are the author's controls on "
             "this sequence, not a measure of how often legitimate calls are refused."),
            "",
        ]
    lines += [
        "## What this row does not establish",
        "",
        ("- Raw call bodies, acceptance records and the estimate B's audit names are not "
         "public; nothing about them is inferred."),
        ("- Byte identity shows which dataset bytes an audit names. It does not show that "
         "the service read them at run time (`dataset_runtime_use = NOT_ESTABLISHED`)."),
        ("- A and C carry the same public audit bytes but name different request "
         "occurrences; identical result bytes do not make them the same call."),
        ("- Part 1 is a retrospective count over signed payments. Part 2 is REMORA's "
         "decision on a replay with a sandboxed tool, not on the live calls, which REMORA "
         "was not in the path of."),
        ("- The limit holds only where a deployment declares it, on one host. It counts the "
         "amount the call names, not what a rail settled."),
        ("- No physical effect, no runtime use of the dataset and no production, "
         "certification or comparative security claim."),
        "- Keys and the trust configuration come from the producer's own bundle.",
        "",
        ("Reproduce: `python integrations/horizon55/prepare.py` once (network), then "
         "`python integrations/horizon55/run.py --check` and "
         "`python integrations/horizon55/enforce.py --check` (offline). Interpreter, OS and "
         "library versions of the run that wrote these files are in `reproduction.json`."),
        "",
    ]
    return "\n".join(lines)


def _json(body: dict[str, Any]) -> bytes:
    return json.dumps(body, indent=1, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"


def stable_outputs(body: dict[str, Any], audit_b: dict[str, Any] | None = None,
                   anchoring: dict[str, Any] | None = None) -> dict[str, bytes]:
    out = {"results.json": _json(body),
           "REPORT.md": report(body, audit_b, anchoring).encode("utf-8")}
    if audit_b is not None:
        out[AUDIT_B_OUT] = _json(audit_b)
    if anchoring is not None:
        out[ANCHORING_OUT] = anchor.render(anchoring)
    return out


def stable_inputs() -> dict[str, bytes]:
    """The locks and the enforcement record SHA256SUMS covers beside the outputs."""
    return {"inputs.lock.json": LOCK.read_bytes(),
            **({"audit-b/inputs.lock.json": AUDIT_B_LOCK.read_bytes()}
               if AUDIT_B_LOCK.is_file() else {}),
            **({"anchoring/headers.json": anchor.HEADERS.read_bytes()}
               if anchor.HEADERS.is_file() else {}),
            **({"enforcement.json": ENFORCEMENT.read_bytes()} if ENFORCEMENT.is_file() else {})}


def sha256sums(files: dict[str, bytes]) -> bytes:
    lines = [f"{canon.sha256_hex(data)}  {name}" for name, data in sorted(files.items())]
    return ("\n".join(lines) + "\n").encode("utf-8")


def reproduction(outputs: dict[str, bytes]) -> bytes:
    import cryptography

    record = {"schema": "remora-h55-reproduction-v1",
              "commands": ["python integrations/horizon55/prepare.py",
                           "python integrations/horizon55/run.py --check",
                           "python integrations/horizon55/enforce.py --check"],
              "python": platform.python_version(), "implementation": platform.python_implementation(),
              "os": platform.system(), "cryptography": cryptography.__version__,
              "network_during_run": False,
              "outputs_sha256": {k: canon.sha256_hex(v) for k, v in outputs.items()},
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
    audit_b = build(extension_lock=AUDIT_B_LOCK) if AUDIT_B_LOCK.is_file() else None
    if audit_b is not None and "error" in audit_b:
        print(json.dumps(audit_b, indent=1, sort_keys=True))
        return 2
    anchoring = anchor.evaluate() if anchor.HEADERS.is_file() else None
    outputs = stable_outputs(body, audit_b, anchoring)
    if args.json:
        sys.stdout.write(outputs["results.json"].decode("utf-8"))
        return 0
    stable = {**outputs, **stable_inputs()}
    if args.write:
        for name, data in outputs.items():
            (OUT / name).parent.mkdir(parents=True, exist_ok=True)
            (OUT / name).write_bytes(data)
        (OUT / "SHA256SUMS").write_bytes(sha256sums(stable))
        (OUT / "reproduction.json").write_bytes(reproduction(outputs))
        print(json.dumps({"written": sorted([*outputs, "SHA256SUMS", "reproduction.json"])}))
        return 0
    problems: list[dict[str, Any]] = []
    not_prepared = sorted({*body["inputs_not_prepared"],
                           *(audit_b["inputs_not_prepared"] if audit_b else [])})
    if not_prepared:
        problems.append({"error": "inputs_not_prepared", "roles": not_prepared,
                         "fix": "python integrations/horizon55/prepare.py"})
    problems += [{"error": "unexpected_verdict", **d} for d in disagreements(body)]
    if audit_b is None:
        problems.append({"error": "audit_b_extension_missing", "file": "audit-b/inputs.lock.json"})
    else:
        problems += [{"error": "unexpected_verdict", "run": "audit-b", **d}
                     for d in disagreements(audit_b, EXPECTED_AUDIT_B)]
    if anchoring is None:
        problems.append({"error": "anchor_headers_missing", "file": "anchoring/headers.json",
                         "fix": "python integrations/horizon55/prepare.py --anchor-headers"})
    elif anchoring["verdict"] != EXPECTED_ANCHORING:
        problems.append({"error": "unexpected_verdict", "run": "anchoring",
                         "expected": EXPECTED_ANCHORING, "got": anchoring["verdict"]})
    for name, data in outputs.items():
        path = OUT / name
        if not path.is_file() or path.read_bytes() != data:
            problems.append({"error": "committed_output_differs", "file": name})
    problems += enforcement_disagreements(enforcement())
    if not (OUT / "SHA256SUMS").is_file() or (OUT / "SHA256SUMS").read_bytes() != sha256sums(stable):
        problems.append({"error": "committed_output_differs", "file": "SHA256SUMS"})
    leaks = check_inputs.disclosure_findings()
    problems += [{"error": "disclosure_finding", **f} for f in leaks]
    print(json.dumps({"ok": not problems, "problems": problems}, indent=1, sort_keys=True))
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())

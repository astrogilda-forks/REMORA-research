# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""Claim-by-claim local evaluation of Horizon #51 set-2 cases A, B and C (SDD-H55 WP2).

A read-only, loss-aware consumer of the MUSUBI companion/pilot records. Every
verdict comes from bytes checked here: strict JSON, RFC 8785 canonical form,
Ed25519 signatures, the log's hash chain, request and task digests, and
integer sums over authenticated payments. The producer's settlement is
loaded only to report its native verdicts beside ours (``native_reported``);
it never decides a verdict.

Verdicts (SDD 2.1): ``ESTABLISHED`` when every predeclared predicate of the
claim was checked on authenticated inputs; ``CONTRADICTED`` when such
evidence conflicts with the claim; ``NOT_ESTABLISHED`` when the bytes, keys,
observations or semantics needed are missing. ``NOT_ESTABLISHED`` is neither a
pass nor a failure. ``native_delegation_scope`` and ``budget_compliance`` are
separate claims and are never combined.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import canon

ESTABLISHED, CONTRADICTED, NOT_ESTABLISHED = "ESTABLISHED", "CONTRADICTED", "NOT_ESTABLISHED"
CASES = ("A", "B", "C")
OCCURRENCE = {"A": "hs51-musubi-2-A", "B": "hs51-musubi-2-B", "C": "hs51-musubi-2-C"}
CLAIMS = ("native_delegation_scope", "budget_compliance", "same_request_occurrence",
          "payment_execution_link", "audit_byte_identity", "dataset_byte_identity",
          "dataset_runtime_use", "receiver_accepted_result", "remora_dispatch_authority",
          "physical_effect")
SET2 = "pilot51/set2"
ITEM_SIGNER = {
    "musubi.ca2a.budget-policy.v0": "issuer",
    "musubi.ca2a.criteria-commitment.v0": "buyer",
    "musubi.ca2a.credential-use.v0": "holder",
    "musubi.ca2a.payment-receipt.v0": "payer",
    "musubi.ca2a.execution-receipt.v0": "responder",
    "musubi.ca2a.acceptance-record.v0": "checker",
}
TRUST_BASIS = ("keys and trust configuration taken from the frozen public bundle, published "
               "by the same author as the records; no independent key provenance")


@dataclass(frozen=True)
class Inputs:
    """The bytes the row reads. ``audits`` maps a SHA-256 to public audit bytes;
    ``dataset`` is None when the cache was not prepared."""

    entries: list[bytes]
    entry_paths: list[str]
    bundle: bytes
    checkpoint: bytes
    settlement: bytes
    audits: Mapping[str, tuple[str, bytes]]
    dataset: tuple[str, bytes] | None
    lock_dataset_sha256: str


def load_inputs(inputs_dir: Path, cache_dir: Path, lock: Mapping[str, Any]) -> Inputs:
    entry_dir = inputs_dir / SET2 / "log" / "entries"
    paths = sorted(entry_dir.glob("*.json"))
    audit_path = inputs_dir / "rehearsal" / "live_smoke" / "audit.json"
    audits = {}
    if audit_path.is_file():
        data = audit_path.read_bytes()
        audits[canon.sha256_hex(data)] = ("rehearsal/live_smoke/audit.json", data)
    dataset_src = next(s for s in lock["sources"] if s["role"] == "dataset_souba_db")
    dataset_path = cache_dir / dataset_src["local_path"]
    dataset = (("souba-db.json (cache)", dataset_path.read_bytes())
               if dataset_path.is_file() else None)
    return Inputs(
        entries=[p.read_bytes() for p in paths],
        entry_paths=[f"{SET2}/log/entries/{p.name}" for p in paths],
        bundle=(inputs_dir / SET2 / "bundle.json").read_bytes(),
        checkpoint=(inputs_dir / SET2 / "log" / "checkpoint.json").read_bytes(),
        settlement=(inputs_dir / SET2 / "settlement.json").read_bytes(),
        audits=audits, dataset=dataset, lock_dataset_sha256=dataset_src["sha256"])


def _claim(case: str, claim_id: str, subject: str, verdict: str, reasons: list[str],
           refs: list[dict[str, Any]], rule: str, role: str, establishes: str,
           not_establishes: list[str], ceiling: str, assumptions: list[str] | None = None,
           native: Any = None) -> dict[str, Any]:
    return {"case_id": case, "claim_id": claim_id, "evidence_subject": subject,
            "verdict": verdict, "reason_codes": sorted(set(reasons)), "evidence_refs": refs,
            "rule_id": rule, "observer_or_signer_role": role, "trust_basis": TRUST_BASIS,
            "assumptions": assumptions or [], "establishes": establishes,
            "does_not_establish": not_establishes, "claim_ceiling": ceiling,
            "native_reported": native}


# ── the log ────────────────────────────────────────────────────────────


def verify_log(inp: Inputs) -> dict[str, Any]:
    """Check the companion log locally (COMPANION_v0 section 5, steps 1 to 4).

    Returns the parsed entries, per-entry digests and a list of problems.
    Anchoring (step 5 and 6) is not checked here: no Bitcoin header view or
    OpenTimestamps proof is verified, so nothing below relies on it.
    """
    problems: list[str] = []
    bundle = canon.loads(inp.bundle)
    trust = bundle["trust"]
    checkpoint = canon.loads(inp.checkpoint)
    entries, digests = [], []
    prev = None
    last_time = None
    for index, (raw, path) in enumerate(zip(inp.entries, inp.entry_paths, strict=True)):
        entry = canon.loads(raw)
        if canon.jcs(entry) != raw:
            problems.append(f"entry_not_canonical:{path}")
        if entry.get("seq") != index:
            problems.append(f"seq_gap:{path}")
        if entry.get("prev") != prev:
            problems.append(f"prev_mismatch:{path}")
        if entry.get("log_id") != trust["log_id"] or entry.get("operator") != trust["operator"]:
            problems.append(f"wrong_log_or_operator:{path}")
        if last_time is not None and entry.get("logged_at", -1) < last_time:
            problems.append(f"logged_at_decreases:{path}")
        if entry.get("logged_at", 0) > checkpoint.get("as_of", 0):
            problems.append(f"logged_after_as_of:{path}")
        if not canon.ed25519_verify(entry.get("operator", ""), entry.get("signature", ""),
                                    canon.jcs(canon.without(entry, "signature"))):
            problems.append(f"operator_signature_invalid:{path}")
        item = entry.get("item", {})
        signer = ITEM_SIGNER.get(item.get("type"))
        item_ok = signer is not None and canon.ed25519_verify(
            item.get(signer, ""), item.get("signature", ""),
            canon.jcs(canon.without(item, "signature")))
        if not item_ok:
            problems.append(f"item_signature_invalid:{path}")
        entries.append({"entry": entry, "path": path, "index": index, "item_ok": item_ok})
        prev = canon.sha256_hex(canon.jcs(entry))
        digests.append(prev)
        last_time = entry.get("logged_at", last_time)
    if [e["entry"] for e in entries] != bundle["log"]["entries"]:
        problems.append("bundle_entries_differ_from_log_files")
    if checkpoint.get("size") != len(entries):
        problems.append("checkpoint_size_mismatch")
    if checkpoint.get("head") != (digests[-1] if digests else None):
        problems.append("checkpoint_head_mismatch")
    if not canon.ed25519_verify(checkpoint.get("operator", ""), checkpoint.get("signature", ""),
                                canon.jcs(canon.without(checkpoint, "signature", "anchor"))):
        problems.append("checkpoint_signature_invalid")
    if canon.without(bundle["log"]["checkpoint"], "anchor") != checkpoint:
        problems.append("bundle_checkpoint_differs")
    return {"bundle": bundle, "trust": trust, "checkpoint": checkpoint, "entries": entries,
            "digests": digests, "problems": problems}


def _ref(path: str, data_sha256: str, seq: int | None = None,
         entry_sha256: str | None = None) -> dict[str, Any]:
    ref: dict[str, Any] = {"path": path, "sha256": data_sha256}
    if seq is not None:
        ref["seq"] = seq
    if entry_sha256 is not None:
        ref["entry_sha256"] = entry_sha256
    return ref


def evaluate(inp: Inputs) -> dict[str, Any]:
    """Every (case, claim) result, the log status and the native comparison."""
    log = verify_log(inp)
    bundle, trust = log["bundle"], log["trust"]
    log_ok = not log["problems"]
    entries = log["entries"]
    by_type: dict[str, list[dict[str, Any]]] = {}
    for e in entries:
        by_type.setdefault(e["entry"]["item"]["type"], []).append(e)
    requests = {r["occurrence_id"]: r for r in bundle.get("requests", [])}
    tasks = {canon.sha256_hex(canon.jcs(t)): t for t in bundle.get("tasks", [])}
    rsha = {case: canon.sha256_hex(canon.jcs(requests[o]))
            for case, o in OCCURRENCE.items() if o in requests}
    settlement = canon.loads(inp.settlement)
    native_pay = {p["request_sha256"]: p for p in settlement["pilot"]["payments"]}
    native_exec = {x["request_sha256"]: x for x in settlement["pilot"]["executions"]}

    def ref_of(e: dict[str, Any]) -> dict[str, Any]:
        idx = e["index"]  # file position; a tampered seq field must not pick another file
        return _ref(e["path"], canon.sha256_hex(inp.entries[idx]), e["entry"].get("seq"),
                    log["digests"][idx])

    def find(kind: str, case: str) -> list[dict[str, Any]]:
        return [e for e in by_type.get(kind, [])
                if e["entry"]["item"].get("request_sha256") == rsha.get(case)]

    # Budget policy and the running total, from authenticated payments only.
    budgets = [e for e in by_type.get("musubi.ca2a.budget-policy.v0", []) if e["item_ok"]]
    payments_all = [e for e in by_type.get("musubi.ca2a.payment-receipt.v0", [])]
    revocations = by_type.get("ca2a.delegation-revocation.v1", [])
    results: list[dict[str, Any]] = []
    running: dict[str, int] = {}
    totals_after: dict[str, int | None] = {}
    for e in payments_all:
        item = e["entry"]["item"]
        case = next((c for c, h in rsha.items() if h == item.get("request_sha256")), None)
        if not e["item_ok"] or not log_ok:
            if case:
                totals_after[case] = None
            continue
        key = f"{'|'.join(item['lineage'])}:{item['unit']}"
        running[key] = running.get(key, 0) + int(item["amount"])
        if case:
            totals_after[case] = running[key]

    for case in CASES:
        occ = OCCURRENCE[case]
        request = requests.get(occ)
        uses, pays = find("musubi.ca2a.credential-use.v0", case), find(
            "musubi.ca2a.payment-receipt.v0", case)
        recs, crits = find("musubi.ca2a.execution-receipt.v0", case), find(
            "musubi.ca2a.criteria-commitment.v0", case)
        acceptances = find("musubi.ca2a.acceptance-record.v0", case)
        refs = [ref_of(e) for e in (*crits, *uses, *pays, *recs)]
        native = {"execution_disposition": native_exec.get(rsha.get(case, ""), {}).get(
                      "disposition"),
                  "payment_reasons": native_pay.get(rsha.get(case, ""), {}).get("reasons"),
                  "payment_budgets": native_pay.get(rsha.get(case, ""), {}).get("budgets")}
        missing = [] if request is not None else ["request_occurrence_not_supplied"]
        if not log_ok:
            missing.append("log_not_verified")

        # 1. native_delegation_scope
        reasons: list[str] = list(missing)
        if len(uses) != 1 or len(recs) != 1:
            reasons.append("use_or_receipt_missing_or_duplicated")
        verdict = NOT_ESTABLISHED
        if not reasons:
            use, rec = uses[0]["entry"], recs[0]["entry"]
            ui, ri = use["item"], rec["item"]
            chain = ui["chain"]
            leaf, root = chain[-1], chain[0]
            body_digest = "sha256:" + canon.sha256_hex(canon.jcs(canon.without(leaf, "signature")))
            checks = {
                "use_signed_by_holder": uses[0]["item_ok"],
                "receipt_signed_by_responder": recs[0]["item_ok"],
                "single_hop_root": len(chain) == 1 and root["depth"] == 0
                and root["parent_id"] is None,
                "root_issuer_trusted": root["issuer"] in trust["root_issuers"],
                "credential_signature_valid": canon.ed25519_verify(
                    leaf["issuer"], leaf["signature"],
                    canon.jcs(canon.without(leaf, "signature"))),
                "lineage_is_credential_digest": request["lineage"] == [body_digest]
                and ri["lineage"] == [body_digest],
                "caller_is_leaf_subject": ri["caller"] == leaf["subject"] == request["caller"]
                == ui["holder"],
                "responder_matches": ri["responder"] == request["responder"]
                == ui["responder"],
                "capability_in_scope": ri["capability"] == request["capability"]
                and ri["capability"] in leaf["scope"],
                "use_logged_before_receipt": use["seq"] < rec["seq"],
                "no_revocation_in_log": not revocations,
            }
            failed = [k for k, ok in checks.items() if not ok]
            if failed:
                verdict = CONTRADICTED if uses[0]["item_ok"] and recs[0]["item_ok"] else (
                    NOT_ESTABLISHED)
                reasons += [f"failed:{k}" for k in failed]
            else:
                verdict = ESTABLISHED
                reasons.append("all_delegation_predicates_checked")
        results.append(_claim(
            case, "native_delegation_scope", occ, verdict, reasons, refs, "H55-R01",
            "holder (use), responder (receipt), root issuer (credential)",
            "the recorded call used a credential signed by the bundle's root issuer, its "
            "capability is in the credential's scope, and caller and responder are those the "
            "request names",
            ["cA2A verify_chain semantics beyond the published credential fields",
             "revocations or policies outside this log", "that the work was performed",
             "anything about the budget (see budget_compliance)"],
            "delegation structure of one recorded call, under the bundle's own trust "
            "configuration", ["the bundle's root issuer key is the delegating principal"],
            {"execution_disposition": native["execution_disposition"]}))

        # 2. budget_compliance
        reasons = list(missing)
        verdict = NOT_ESTABLISHED
        valid_budgets, budget_refs = [], []
        if request is not None:
            for b in budgets:
                bi = b["entry"]["item"]
                if (bi["credential_digest"] in request["lineage"] and uses
                        and bi["issuer"] == uses[0]["entry"]["item"]["chain"][0]["issuer"]):
                    valid_budgets.append(b)
        if len(pays) != 1:
            reasons.append("payment_missing_or_duplicated")
        if not valid_budgets:
            reasons.append("no_budget_policy_by_issuer")
        if not reasons:
            pay = pays[0]["entry"]
            pi = pay["item"]
            task = tasks.get(request["task_sha256"])
            pay_checks = {
                "payment_signed_by_payer": pays[0]["item_ok"],
                "payer_is_caller": pi["payer"] == request["caller"],
                "payee_is_responder": pi["payee"] == request["responder"],
                "lineage_is_requests": pi["lineage"] == request["lineage"],
                "task_supplied": task is not None,
                "amount_is_task_price": task is not None and pi["amount"] == task["amount"]
                and pi["unit"] == task["unit"],
                "budget_logged_before_payment": all(b["entry"]["seq"] < pay["seq"]
                                                    for b in valid_budgets),
            }
            failed = [k for k, ok in pay_checks.items() if not ok]
            limit = min(b["entry"]["item"]["max_total"] for b in valid_budgets
                        if b["entry"]["item"]["unit"] == pi["unit"])
            total = totals_after.get(case)
            budget_refs = [ref_of(b) for b in valid_budgets]
            if failed or total is None:
                reasons += [f"failed:{k}" for k in failed] or ["total_not_computable"]
            elif total <= limit:
                verdict, reasons = ESTABLISHED, [f"cumulative_total_{total}_within_{limit}"]
            else:
                verdict, reasons = CONTRADICTED, [f"cumulative_total_{total}_exceeds_{limit}"]
        results.append(_claim(
            case, "budget_compliance", occ, verdict, reasons, refs + budget_refs, "H55-R02",
            "payer (payment), issuer (budget policy)",
            "the cumulative total of authenticated, signed payments on this lineage and unit, "
            "in log order, against the issuer-signed max_total",
            ["that money moved (the rail receipt is a digest)",
             ("that the budget was enforced before the payment: this is a retrospective count, "
              "not a pre-dispatch decision"), "anything about delegation scope"],
            "arithmetic over signed records; JPY-testnet is a simulated unit",
            ["payments not in this log did not happen on this lineage"],
            {"payment_reasons": native["payment_reasons"],
             "payment_budgets": native["payment_budgets"]}))

        # 3. same_request_occurrence
        reasons = list(missing)
        named = {e["entry"]["item"].get("request_sha256") for e in (*uses, *pays, *recs, *crits)}
        others = {h for c, h in rsha.items() if c != case}
        if not reasons and len(uses) == len(pays) == len(recs) == 1 and named == {rsha[case]} \
                and rsha[case] not in others:
            verdict, reasons = ESTABLISHED, ["use_payment_receipt_criteria_name_this_request"]
        else:
            verdict = NOT_ESTABLISHED
            reasons.append("records_do_not_join_to_one_request")
        results.append(_claim(
            case, "same_request_occurrence", occ, verdict, reasons, refs, "H55-R03",
            "holder, payer, responder, buyer",
            "the use, payment, execution receipt and criteria commitment all name the "
            "SHA-256 of this case's request occurrence, distinct from the other cases'",
            ["that the raw request bodies are the ones described (they are not public)"],
            "binding of signed records to one request occurrence"))

        # 4. payment_execution_link
        reasons = list(missing)
        verdict = NOT_ESTABLISHED
        if not reasons and len(pays) == 1 and len(recs) == 1:
            pi, ri = pays[0]["entry"]["item"], recs[0]["entry"]["item"]
            link = {"payment_before_receipt": pays[0]["entry"]["seq"] < recs[0]["entry"]["seq"],
                    "same_request": pi["request_sha256"] == ri["request_sha256"],
                    "payer_is_receipt_caller": pi["payer"] == ri["caller"],
                    "payee_is_receipt_responder": pi["payee"] == ri["responder"],
                    "both_signed": pays[0]["item_ok"] and recs[0]["item_ok"]}
            failed = [k for k, ok in link.items() if not ok]
            if not failed:
                verdict, reasons = ESTABLISHED, ["payment_logged_before_its_execution"]
            else:
                verdict = CONTRADICTED if link["both_signed"] else NOT_ESTABLISHED
                reasons += [f"failed:{k}" for k in failed]
        else:
            reasons.append("payment_or_receipt_missing")
        results.append(_claim(
            case, "payment_execution_link", occ, verdict, reasons, refs, "H55-R04",
            "payer, responder",
            "a signed payment for this request was logged before the signed execution receipt "
            "and names the same caller and responder",
            ["that the rail settled the payment", "that the result was correct"],
            "ordering and naming in a signed, operator-sequenced log"))

        # 5. audit_byte_identity and 6. dataset_byte_identity
        response_sha = (recs[0]["entry"]["item"]["outcome"].get("response_sha256")
                        if len(recs) == 1 else None)
        audit = inp.audits.get(response_sha or "")
        reasons = list(missing)
        if audit is None:
            verdict = NOT_ESTABLISHED
            reasons.append("audit_bytes_not_public")
        elif missing:
            verdict = NOT_ESTABLISHED
        elif not recs[0]["item_ok"]:
            verdict = NOT_ESTABLISHED
            reasons.append("receipt_signature_invalid")
        else:
            verdict = ESTABLISHED
            reasons.append("public_bytes_match_signed_response_sha256")
        audit_refs = refs + ([_ref(audit[0], response_sha)] if audit else [])
        results.append(_claim(
            case, "audit_byte_identity", occ, verdict, reasons, audit_refs, "H55-R05",
            "responder (receipt)",
            "public audit bytes whose SHA-256 equals the response_sha256 the responder signed "
            "for this request",
            ["that this request, and not another with the same result, produced those bytes",
             "that the audit's content is correct"],
            "byte identity only", native={"response_sha256": response_sha}))

        reasons = list(missing)
        claimed: set[str] = set()
        if audit is not None:
            try:
                body = canon.loads(audit[1])
                claimed = {line.get("dataset_sha256") for line in body.get("lines", [])}
            except canon.StrictJSONError as exc:
                reasons.append(f"audit_unreadable:{exc.code}")
        if audit is None:
            verdict = NOT_ESTABLISHED
            reasons.append("audit_bytes_not_public")
        elif missing:
            verdict = NOT_ESTABLISHED
        elif inp.dataset is None:
            verdict = NOT_ESTABLISHED
            reasons.append("dataset_not_prepared")
        else:
            got = canon.sha256_hex(inp.dataset[1])
            if claimed == {got} and got == inp.lock_dataset_sha256:
                verdict, reasons = ESTABLISHED, ["dataset_bytes_match_audit_digest_and_pin"]
            elif claimed and got != inp.lock_dataset_sha256:
                verdict = NOT_ESTABLISHED
                reasons.append("dataset_bytes_do_not_match_pin")
            else:
                verdict = CONTRADICTED
                reasons.append("audit_names_another_dataset_digest")
        results.append(_claim(
            case, "dataset_byte_identity", occ, verdict, reasons, audit_refs, "H55-R06",
            "responder (audit content)",
            "the dataset digest the audit states equals the SHA-256 of the souba-db bytes "
            "pinned at the dataset revision",
            ["that the deployed service consumed those bytes (see dataset_runtime_use)"],
            "byte identity of a stated digest"))

        # 7 to 10: bounded by absent evidence.
        results.append(_claim(
            case, "dataset_runtime_use", occ, NOT_ESTABLISHED,
            ["no_observation_of_runtime_inputs"], audit_refs, "H55-R07", "none",
            "nothing", ["that the remote runtime read the dataset bytes"],
            "not establishable from records alone"))
        results.append(_claim(
            case, "receiver_accepted_result", occ, NOT_ESTABLISHED,
            ["acceptance_records_not_public"] if not acceptances else
            ["acceptance_record_present_but_not_evaluated"], refs, "H55-R08", "checker",
            "nothing", ["that the buyer's checker accepted the result"],
            "criteria commitments exist; no acceptance record is public"))
        results.append(_claim(
            case, "remora_dispatch_authority", occ, NOT_ESTABLISHED,
            ["no_remora_grant_lease_or_dispatch_record"], refs, "H55-R09", "none",
            "nothing",
            [("that REMORA authorized or would have authorized this call: the records are the "
              "producer's, not a REMORA decision")],
            "no REMORA-native authority evidence exists for these calls"))
        results.append(_claim(
            case, "physical_effect", occ, NOT_ESTABLISHED,
            ["no_independent_effect_observation"], refs, "H55-R10", "none", "nothing",
            ["any effect in the world from the audit or the payment"],
            "signed statements are not observations of effects"))

    anchoring = {
        "claim_id": "checkpoint_anchoring", "verdict": NOT_ESTABLISHED,
        "reason_codes": ["anchor_verification_not_implemented"],
        "does_not_establish": ["Bitcoin block inclusion of the checkpoint",
                               "seen_block ordering of receipts and payments"],
        "native_reported": settlement["companion"]["log"],
    }
    return {"log": {"verified": log_ok, "problems": log["problems"],
                    "size": len(entries), "head": log["digests"][-1] if log["digests"] else None,
                    "request_sha256": rsha},
            "anchoring": anchoring, "results": results}

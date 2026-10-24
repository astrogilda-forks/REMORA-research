# Horizon #55 row: REMORA reading of Horizon Shield #51 set 2

Status: exploratory, retrospective and author-operated. Written for
[horizon-shield#55](https://github.com/ogasurfproject-jpg/horizon-shield/issues/55).
The cases A, B and C and C's budget outcome were public and examined before
this row was designed. It is not a holdout, not a preregistered confirmation
and not an independent evaluation.

## Answer in short

Payment C took the buyer's spending to 21000 JPY-testnet against a signed
budget of 20000. Reading the signed records, REMORA finds C over budget and A
and B within it. Run through REMORA's own execution path with that budget
declared, C does not run: it is refused before review, and refused at dispatch
when all three were approved in advance. Without a declared limit REMORA lets
all three run. [`REPORT.md`](../../artifacts/interop/horizon55/REPORT.md)
explains what A, B and C are and gives every table.

## What it is

An offline, read-only consumer of the MUSUBI companion records that Horizon
Shield published for #51 set 2. For each case it states ten claims and gives
each one of three verdicts:

| Verdict | Meaning |
|---|---|
| `ESTABLISHED` | every predicate of the claim was checked on authenticated bytes |
| `CONTRADICTED` | authenticated bytes conflict with the claim |
| `NOT_ESTABLISHED` | the bytes, keys, observations or semantics needed are missing |

`NOT_ESTABLISHED` is neither a pass nor a failure. The producer's
`settlement.json` is read only to show its own verdicts beside these, in
`native_reported`. It never decides a verdict.

The integration imports no REMORA code and does not use or change REMORA's
policy engine, custody, dispatcher or verification semantics.

## What it checks

| Step | Check |
|---|---|
| Input lock | exact size and SHA-256 of all 25 upstream files at full commit revisions; a differing file fails closed |
| Strict JSON | duplicate keys, floats, non-finite and unsafe integers, trailing data, bad UTF-8 and deep nesting are refused |
| Canonical form | RFC 8785 (JCS) implemented here; every published log entry re-serialises to its exact bytes |
| Log | 13 entries, `prev` hash chain, sequence, operator signature on each entry, author signature on each item, checkpoint size, head and signature |
| Joins | use, payment, execution receipt and criteria commitment all name the request digest of their own case |
| Budget | cumulative sum of authenticated payments on one lineage and unit, in log order, against the issuer-signed `max_total` |
| Bytes | the public audit against the signed `response_sha256`, and the dataset against the digest the audit states and the pin |

The frozen row does not check the checkpoint's Bitcoin anchor:
`checkpoint_anchoring` is `NOT_ESTABLISHED` in `results.json`, and no claim
verdict depends on it.

## Anchoring, checked separately (P2)

`anchor.py` parses `checkpoint.stamp.ots` from its binary format with its own
parser and replays every path to a Bitcoin attestation. It does not use the
producer's proof summary or header view. The steps are:

1. `prepare.py --anchor-headers` asks blockstream.info and mempool.space for
   the attested headers and the one before them. It keeps a header only when
   both explorers return the same block id and bytes, and writes
   `anchoring/headers.json`.
2. Offline, each header must hash to that id and meet its own proof-of-work
   target. The target must declare at least 2^64 work, and the header must
   link to its predecessor.
3. The header's Merkle root must equal the commitment the proof computes.

Result (`anchoring/anchoring.json`): both attestations, blocks 972551 and
972552, verify. `checkpoint_anchoring` is `ESTABLISHED` there. The signed
checkpoint covers all 13 entries, so C's payment was committed to Bitcoin by
block 972551.

This rests on two explorers agreeing at fetch time and on proof of work, not
on a node of ours. It does not show that the block is in the best chain now,
nor when each entry was seen relative to the block.

## Result

See [`artifacts/interop/horizon55/REPORT.md`](../../artifacts/interop/horizon55/REPORT.md)
and `results.json` beside it. In short: delegation scope is established for
all three cases. The budget is within its bound after A (7000 of 20000) and
B (14000), and contradicted after C (21000). In the frozen row B's audit
bytes were not public, so its audit and dataset identity are
`NOT_ESTABLISHED` there. Runtime dataset use, receiver acceptance, REMORA
dispatch authority and physical effect are `NOT_ESTABLISHED` for every case.

## Evidence extension: B's audit bytes

Horizon Shield published B's audit bytes on 2026-10-24 at
`c824cbe61a383e57f1d9d15fea962a79f5b6bbd5` (branch
`evidence/hs51-set2-audit-b`, a descendant of the frozen revision). They are
vendored at `inputs/pilot51/set2/audit_B.json` and pinned by their own lock,
`audit-b/inputs.lock.json`. The frozen lock, the frozen table (`EXPECTED`)
and `results.json` are not changed. `run.py` evaluates the row a second time
with those bytes added and writes `audit-b/results.json`, checked against
`EXPECTED_AUDIT_B`. Only B's audit and dataset byte identity move, to
`ESTABLISHED`. B's audit is of a different estimate from A and C's (its
`fixture_sha256` names bytes that are not public), and byte identity is not
runtime use.

## Part 2: REMORA's own engine

`enforce.py` takes the three payments and the issuer-signed budget from the
verified log. It sends each payment through REMORA's execution API in this
process: `/v1/execution/assess`, `/approve`, `/execute` and the governed
dispatcher. The tool is a sandbox (`payment_tool.py`) that records every call
reaching it. It runs three times: with no limit declared, with the budget
declared as a cumulative limit for the payer, and with that limit after all
three payments were approved in advance. The result is `enforcement.json`.
Unlike `run.py`, this script imports REMORA, because REMORA's decision path is
what it tests. The limits themselves are `remora/enforcement/cumulative_limits.py`
(CAP-031), added outside this package.

## Reproduce

```bash
python integrations/horizon55/prepare.py     # once, networked: fetch and check against the lock
python integrations/horizon55/run.py --check # offline: inputs, verdicts, outputs, disclosure gate
python integrations/horizon55/enforce.py --check  # offline: REMORA's engine on A, B and C
python integrations/horizon55/anchor.py --check   # offline: the checkpoint's Bitcoin anchor
```

`run.py --write` rewrites `results.json`, `audit-b/results.json`,
`anchoring/anchoring.json`,
`REPORT.md`, `SHA256SUMS` and `reproduction.json`. Two runs give byte-identical `results.json` and
`REPORT.md`. `reproduction.json` records the interpreter, OS and
`cryptography` version and is excluded from the byte-identity check. Tests:
`pytest tests/test_horizon55_*.py`.

## Test coverage (SDD-H55 section 5)

| Test | Where |
|---|---|
| H55-T00 pinned bytes, fail closed | `tests/test_horizon55_inputs.py::test_t00_*`, `test_t05_a_tampered_vendored_file_fails_closed_before_evaluation` |
| H55-T01 A/B/C joins | `tests/test_horizon55_claims.py::test_t01_*` |
| H55-T02 cumulative budget | `test_t02_c_overspends_while_its_delegation_is_unchanged` |
| H55-T03, T09 shared A/C audit | `test_t03_t09_identical_audit_bytes_do_not_make_a_and_c_one_call` |
| H55-T04 swapped receipts, changed join | `tests/test_horizon55_mutations.py::test_t04_*` |
| H55-T05 mutated amount or budget | `test_t05_*` |
| H55-T06 removed entry | `test_t06_a_removed_entry_is_not_silently_accepted` |
| H55-T07 strict JSON | `test_t07_*` |
| H55-T08 B without audit bytes | `test_t08_*` |
| B-audit extension | `tests/test_horizon55_audit_b.py` |
| P1: replayed, duplicated, reordered, truncated log | `tests/test_horizon55_log_adversarial.py` |
| P1: concurrency, crashes, retries, restarts | `tests/test_horizon55_enforcement_adversarial.py` |
| P2: the Bitcoin anchor, checked independently | `tests/test_horizon55_anchoring.py` |
| H55-T10 dataset bytes | `test_t10_*` (two need the prepared cache) |
| H55-T11 altered native settlement | `test_t11_*` |
| H55-T12 receipt mapped to a REMORA grant | `test_t12_*` |
| H55-T13 acceptance records | `test_t12_t13_t14_*`, `test_t13_*` |
| H55-T14 effect from signed audit or timestamp | `test_t12_t13_t14_*`, `test_t14_*` |
| H55-T15 anchoring, unrecognised keys | `test_t15_*` |
| H55-T16 determinism, committed outputs current | `test_t16_*` (the second needs the prepared cache) |
| H55-T17 disclosure gate | `test_t17_*` |
| Part 2: REMORA's engine on A, B and C | `tests/test_horizon55_enforcement.py` |

All of these are the author's own controls, not external adversarial coverage.

## Inputs and licence

The set-2 log, bundle, settlement, the public A/C audit and the original
fixture are vendored unchanged under `artifacts/interop/horizon55/inputs/`.
They are MIT-licensed by The HORIZONs Co., Ltd.; the licence is copied
beside them. The souba-db dataset is compiled from third-party market
sources and its redistribution terms are not established, so `prepare.py`
fetches it into the git-ignored `.cache/` and the lock pins it by digest
only. Without it, `dataset_byte_identity` cannot be established.

## Limits

- Keys and the trust configuration come from the producer's own bundle. No
  independent key provenance is claimed.
- `budget_compliance` is a retrospective count over signed payments, not a
  pre-dispatch decision. JPY-testnet is a simulated unit.
- A and C carry the same audit bytes under different request digests.
  Identical result bytes do not make them one call.
- The mutation tests are the author's own controls, not external adversarial
  coverage.
- REMORA was not in the path of the live calls. Part 2 is REMORA's decision on
  a replay with a sandboxed tool, and the limit holds only where a deployment
  declares it, on one host.
- No certification, production or comparative security claim.

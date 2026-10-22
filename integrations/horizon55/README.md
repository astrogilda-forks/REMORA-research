# Horizon #55 row: REMORA reading of Horizon Shield #51 set 2

Status: exploratory, retrospective and author-operated. Written for
[horizon-shield#55](https://github.com/ogasurfproject-jpg/horizon-shield/issues/55).
The cases A, B and C and C's budget outcome were public and examined before
this row was designed. It is not a holdout, not a preregistered confirmation
and not an independent evaluation.

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

Bitcoin anchoring of the checkpoint is not checked. `checkpoint_anchoring` is
`NOT_ESTABLISHED`, and no verdict depends on it.

## Result

See [`artifacts/interop/horizon55/REPORT.md`](../../artifacts/interop/horizon55/REPORT.md)
and `results.json` beside it. In short: delegation scope is established for
all three cases. The budget is within its bound after A (7000 of 20000) and
B (14000), and contradicted after C (21000). B's audit bytes are not public,
so its audit and dataset identity are `NOT_ESTABLISHED`. Runtime dataset use,
receiver acceptance, REMORA dispatch authority and physical effect are
`NOT_ESTABLISHED` for every case.

## Reproduce

```bash
python integrations/horizon55/prepare.py     # once, networked: fetch and check against the lock
python integrations/horizon55/run.py --check # offline: inputs, verdicts, outputs, disclosure gate
```

`run.py --write` rewrites `results.json`, `REPORT.md`, `SHA256SUMS` and
`reproduction.json`. Two runs give byte-identical `results.json` and
`REPORT.md`. `reproduction.json` records the interpreter, OS and
`cryptography` version and is excluded from the byte-identity check. Tests:
`pytest tests/test_horizon55_*.py`.

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
- This row does not say REMORA would have prevented C, and makes no
  certification, production or comparative security claim.

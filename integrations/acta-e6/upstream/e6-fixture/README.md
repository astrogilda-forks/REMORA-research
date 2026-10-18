# E6 producer fixture: Acta receipts for one billing period, a signed period manifest and a bill

**DEMO FIXTURE. Demo keys, simulated outcomes, fictional companies. Not production evidence and not a real bill.**

This is a pinned producer fixture for edge E6 of [aeoess/agent-governance-vocabulary#177](https://github.com/aeoess/agent-governance-vocabulary/issues/177): Veritas Acta signed receipts consumed by a paying-side check. It follows the input contract proposed on that issue on 3 October 2026, so that a consumer it did not come from, such as the one in [arian-gogani/nobulex#24](https://github.com/arian-gogani/nobulex/pull/24), can be run against it.

It holds:

- the receipts of one billing period, August 2026: 51 signed outcome receipts, hash-chained (28 billable, 23 not);
- the signed period manifest that fixed that receipt set before the bill was cut: period, chain head, count and a Merkle root over the set;
- a bill, supplied separately, whose lines name the receipts they bill, with every other receipt explicitly excluded;
- a keys document with stated provenance, given to the consumer apart from the bundle;
- 12 cases, each one change with its expected result, and a small reference consumer that runs them.

## What this is not

- **Demo keys.** Every key here was made for this fixture on 2026-10-06 (UTC) and is labelled DEMO. None is a ScopeBlind production key or any other real key. Each private half existed only in the memory of the process that made the fixture and was then discarded, so nobody can sign anything more under these keys. A valid signature here shows only that the bytes have not changed since they were signed; it shows nothing about any real party.
- **Simulated outcomes.** The receipts record simulated customer support conversations of Harbor Sandbox Co., a fictional retailer, answered by the AI agent of a fictional vendor, "Vendor B". Each outcome was decided by the outcome meter, an unpublished prototype, under its draft counting standard support-resolution 0.1.0 (not frozen; digest `sha256:9916bfe483b15b43ec74f758ee0d42e2a7e0fca0093b5dd0534db74347b2b43f`). The sandbox plants deliberate errors in the vendor's claims; the E6 checks do not, and cannot, detect them.
- **Simulated times.** Every `issued_at` in the fixture is a simulated time between June and September 2026. Every signature was made on 2026-10-06 (UTC).
- **Not independent.** The Veritas Acta draft, the verifier `@veritasacta/verify`, the outcome meter and this fixture are all the work of one author (Tom Farley). Only a consumer written by someone else tests the contract.
- **The evidence layer only.** A PASS says the bill agrees with the signed receipts under the pinned keys. It says nothing about whether the work was good, whether the price is the contracted price, or whether anyone should pay. Price and amount are a separate claim against the contract, which this fixture does not carry, so `payment_ready` is always false.
- **One channel.** The keys document travels with the bundle here, so pinning it shows the mechanism, not anyone's identity.

Three more limits: the bill is unsigned, so the fixture does not establish who issued it; uniqueness is checked by receipt ID, so a second receipt signed for the same work under a new ID would not be caught by these checks; and the reasons given for exclusions are the producer's statements, which no check tests.

## Pins

- **Verifier:** `@veritasacta/verify@0.10.21` from npm, unmodified. Tarball integrity `sha512-48roJsv+GsS9v5KiQA7RKL9qCqZ13e8ohQYJhM9Alr6xCB0U7MRy+zXiYeQC2aop9ve0Uage4kN/TlwrqgPi5A==`, shasum `4b66003131f63567f05a1550bfdc30e230162b7a`.
- **Root demo key:** fingerprint `sha256:0a8d834701f5468883e891be97240182dd26c23170cb80174449755d6244f926`. The paying side pins this before it reads any bundle.
- **Meter demo key** (signs the receipts and the manifest): kid `sb:issuer:Exe2v4V4bmeC`, public key `cf68bf76aaa58bc2acd0195cfd96439c23a1ec8bf9a1ddf5b95679bec05eb77e`, fingerprint `sha256:04619a1b52728ef3a6155e1f54d4c6034d10b36a757411ae8e595d39b560c5c0`.
- **Manifest** (its record hash, which the bill names): `sha256:f8bbe201a7b67f80204337739f69ab0fc657ea93b8d565549392a26a42d02826`.
- **Every file:** `SHA256SUMS`. The SHA-256 of `SHA256SUMS` itself identifies this version of the fixture; it is published beside the fixture, since it cannot be inside it.
- **Versions:** `v1.0.1` changes only this README and `SHA256SUMS`; every other file is byte-identical to `v1.0.0`, so a result on either tag holds for both. `v1.1.0` adds case 12 and `producer/case-12.mjs`, and changes this README, `SHA256SUMS` and `test/fixture.test.mjs`; every other file is byte-identical to `v1.0.1`, so a result on cases 01 to 11 holds on all three tags.

## Files

| Path | What it is |
|---|---|
| `receipts/chain.jsonl` | The 51 outcome receipts of August 2026 (sequences 36 to 86 of the meter's chain), one envelope per line, in chain order. This file is the consumer's receipts input. |
| `receipts/0036.json` to `receipts/0086.json` | The same receipts, one per file, named by sequence, for verifying one at a time. |
| `manifest.json` | The signed period manifest: the outcome meter's period statement for August 2026 (`ocs:period_statement.v0`), on one line. |
| `bill.json` | The bill, `HARBOR-DEMO-2026-08-001`, supplied separately from the receipts. |
| `keys.json` | The keys document: the root demo key, the meter demo key with its root-signed certificate and validity window, the key history and the provenance. It is also a JWKS, so the verifier can take it with `--jwks`. |
| `cases/` | One directory per case: `case.json` (inputs and expected result) and the files the case changes. |
| `consumer/check.mjs`, `consumer/run-cases.mjs` | The reference consumer and the case runner. |
| `producer/generate.mjs` | How the fixture was made. It needs the unpublished outcome meter and cannot reproduce these bytes. |
| `producer/case-12.mjs` | How case 12 was derived from `manifest.json` and `bill.json`. Run again, it writes the same bytes; `--check` confirms the files on disk are those bytes. |
| `SHA256SUMS` | The SHA-256 of every other file. |

Every record is an envelope of draft-farley-acta-signed-receipts-03: `{"payload": {...}, "signature": {"alg": "EdDSA", "kid": "...", "sig": "..."}}`, an Ed25519 signature over the JCS (RFC 8785) bytes of the payload, and, after the first record of the meter's chain, a `previousReceiptHash` holding `sha256:` and the hex SHA-256 of the JCS of the whole previous envelope, signature included (section 6.7). The first August receipt links to the July statement, which is not part of this period; `cases/06-bill-cut-from-different-manifest/other-manifest.json` is that July statement.

## Verify the receipts with the public verifier

From this directory, with Node 18 or later:

```sh
# Every file against its pinned digest (on Linux: sha256sum -c SHA256SUMS)
shasum -a 256 -c SHA256SUMS

# Each receipt on its own, under the pinned meter key: 51 invocations, each must exit 0
for f in receipts/0*.json; do npx --yes @veritasacta/verify@0.10.21 "$f" --key cf68bf76aaa58bc2acd0195cfd96439c23a1ec8bf9a1ddf5b95679bec05eb77e --json > /dev/null || echo "NOT VALID: $f"; done

# The receipts as a chain: every signature and every link
npx --yes @veritasacta/verify@0.10.21 --replay-chain receipts/chain.jsonl --key cf68bf76aaa58bc2acd0195cfd96439c23a1ec8bf9a1ddf5b95679bec05eb77e

# The chain closed by the manifest, which links to the last receipt
cat receipts/chain.jsonl manifest.json | npx --yes @veritasacta/verify@0.10.21 --replay-chain /dev/stdin --key cf68bf76aaa58bc2acd0195cfd96439c23a1ec8bf9a1ddf5b95679bec05eb77e

# The manifest on its own
npx --yes @veritasacta/verify@0.10.21 manifest.json --key cf68bf76aaa58bc2acd0195cfd96439c23a1ec8bf9a1ddf5b95679bec05eb77e

# A receipt with the keys document as its key source, applying the key's validity window
npx --yes @veritasacta/verify@0.10.21 receipts/0036.json --jwks keys.json --require-key-window

# The meter key's certificate, under the root demo key
node -e 'process.stdout.write(JSON.stringify(require("./keys.json").keys[0].certificate))' | npx --yes @veritasacta/verify@0.10.21 --stdin --key 7de7de81eda8ecb29df03fa22fa03be36cb316346f90a71f7841dd4ad09c298d
```

Each command exits 0. The two replays report 51 and 52 records verified with no chain breaks. The verifier checks signatures and links; it knows nothing of periods, bills or coverage, which is what the consumer adds. Use `--replay-chain` for the links: the `chain explore` subcommand of 0.10.21 looks ancestors up by an unprefixed base64url hash rather than the section 6.7 value, so it does not walk these chains.

## The input contract

The five points of the 3 October comment, and where each one lives here:

1. **Each billed unit names its receipt:** every line lists its receipt IDs (`lines[].receipts`), so `uniqueness` can check each receipt is billed at most once, in this bill and against the earlier bills given.
2. **Coverage both ways:** `coverage_bill_to_receipts` and `coverage_receipts_to_bill`, measured against the receipt set that the signed manifest fixed before the bill was cut (period, chain head, count, Merkle root).
3. **Scope binding:** the bill states its `period` and the `manifest` it was cut from; `scope` refuses a mismatch, and nothing is compared across scopes.
4. **Key provenance as its own input:** `keys.json` and a root fingerprint pinned out of band, kept apart from the bundle, with key history and a statement of how each key was made (`keys`).
5. **Per-claim results:** seven evidence claims reported separately; price and amount left as a separate claim against the contract; `payment_ready` always false.

### Inputs

A consumer takes these, each as bytes:

1. `receipts`: the period's receipts, JSONL in chain order.
2. `manifest`: the signed period manifest.
3. `bill`: the bill under check, supplied separately from the receipts.
4. `keys` with `root_fingerprint`: the pinned keys document and the root fingerprint pinned out of band. Never keys that arrive inside a bundle.
5. `earlier_bills`: zero or more bills the paying side has already accepted.
6. The verifier: `@veritasacta/verify` 0.10.21, unmodified.

### Constructions

- **Receipt ID** (and the manifest's record hash): `sha256:` and the lowercase hex SHA-256 of the UTF-8 JCS of the whole envelope, signature included. It is the value the next record's `previousReceiptHash` holds.
- **Signing input:** the JCS bytes of the envelope's `payload` alone, signed directly with no pre-hash (section 6.6). The receipt ID hashes the whole envelope, signature included, so the two are different bytes: an implementation that checks a signature over the ID's preimage, or derives an ID from the payload, fails every receipt.
- **Range root:** the RFC 6962 Merkle tree over the receipt IDs in sequence order: each leaf SHA-256(0x00 and the 32 bytes of the ID), each node SHA-256(0x01, left, right), split at the largest power of two below the count.
- **Key fingerprint:** `sha256:` and the hex SHA-256 of the 32-byte public key.

### Fields the checks read

- **Receipt** (`ocs:outcome.v0`): `signature.kid`, `payload.issuer_id`, `payload.issued_at`, `payload.sequence`, `payload.previousReceiptHash`, `payload.period`, `payload.outcome.billable`, `payload.outcome.billing_class`.
- **Manifest** (`ocs:period_statement.v0`): `signature.kid`, `payload.issuer_id`, `payload.issued_at`, `payload.previousReceiptHash`, `payload.period.id`, and `payload.range`: `first_sequence`, `last_sequence`, `head`, `outcome_receipts`, `correction_receipts`, `root`.
- **Bill:** `period`, `manifest`, `lines[].quantity`, `lines[].billing_class`, `lines[].receipts`, `exclusions[].receipt`. The rest (`unit_price_minor`, `amount_minor`, `total_minor`, names, descriptions, exclusion reasons) is for people and for the separate price and amount claim.
- **Keys:** `root` (`kid`, `public_key_hex`, `fingerprint`) and the meter key (`kid`, `public_key_hex`, `x`, `fingerprint`, `valid_from`, `valid_until`, `certificate`).

Everything else in the records belongs to the outcome meter's data model and plays no part in these checks.

### Claims

| Claim | PASS means |
|---|---|
| `keys` | The keys document's root matches the pinned fingerprint. The meter key carries a certificate that the verifier finds signed by the root and whose subject matches the entry. Every receipt and the manifest name that key (`signature.kid` and `payload.issuer_id`) and were issued inside its validity window. |
| `signatures` | Under the pinned meter key, the verifier's `--replay-chain` finds every receipt valid and every link intact, every receipt after the first carries a link, and the manifest verifies. |
| `scope` | The bill's `period` equals the manifest's `period.id` and its `manifest` equals the manifest's record hash. The receipts are exactly the set the manifest fixed: the count (`outcome_receipts + correction_receipts`), the sequences from `first_sequence` to `last_sequence`, the `head` (the last receipt's ID, which the manifest's own `previousReceiptHash` also names), the `root`, and each receipt's `period`. |
| `coverage_bill_to_receipts` | Every receipt ID the bill names, on a line or as an exclusion, is in that set. |
| `coverage_receipts_to_bill` | Every receipt in that set is billed on a line or explicitly excluded. |
| `uniqueness` | No receipt ID appears twice in the bill, across lines and exclusions, and no receipt it bills was billed on an earlier bill given. |
| `quantities` | Each line's quantity equals the number of receipts it names, and each of them is signed `outcome.billable: true` in the line's `billing_class`. One receipt is one unit. |
| `amount` | Not evaluated: price and amount are a separate claim against the contract. |

### Results

Each claim is `PASS`, `FAIL`, `ABSTAIN` (could not be decided, for example with no verifier) or `NOT_EVALUATED`. The bill is compared with the receipts (the coverage, uniqueness and quantities claims) only when `keys`, `signatures` and `scope` have all passed; otherwise those four are `NOT_EVALUATED`, so a consumer never compares across scopes or against receipts it could not establish. The verdict is `FAIL` when any claim fails, `PASS` when all seven evidence claims pass, and `ABSTAIN` otherwise. `payment_ready` is always false. A verifier's exit code counts only with its `--json` output: a missing verifier script also exits 1 under Node.

Next to Nobulex's PR #24: each line here names the receipts it bills rather than one fill ID; a receipt listed twice is a `uniqueness` FAIL, since the bill is well formed and the double billing is the finding (the PR reports a duplicate line as INDETERMINATE); and `ABSTAIN` corresponds to the PR's INDETERMINATE.

## The cases

| Case | What it tests | Expected verdict | Decisive claim (reference codes) |
|---|---|---|---|
| `01-matching-bill` | The matching bill | **PASS** | all seven evidence claims PASS |
| `02-missing-receipt` | A missing receipt | **FAIL** | coverage_bill_to_receipts FAIL (unknown_receipt) |
| `03-receipt-billed-twice-across-lines` | A receipt billed twice across lines | **FAIL** | uniqueness FAIL (listed_twice_in_bill) |
| `04-receipt-billed-again-on-later-bill` | A receipt billed again on a later bill | **FAIL** | uniqueness FAIL (billed_on_earlier_bill) |
| `05-receipt-neither-billed-nor-excluded` | An in-scope receipt neither billed nor excluded | **FAIL** | coverage_receipts_to_bill FAIL (unaccounted_receipt) |
| `06-bill-cut-from-different-manifest` | A bill cut from a different manifest | **FAIL** | scope FAIL (manifest_mismatch) |
| `07-altered-receipt` | An altered receipt | **FAIL** | signatures FAIL (invalid_signature, chain_break) |
| `08-unexpected-signer` | An unexpected signer | **FAIL** | keys FAIL (unexpected_signer) |
| `09-period-mismatch` | A period mismatch | **FAIL** | scope FAIL (period_mismatch) |
| `10-verifier-unavailable` | The verifier is unavailable | **ABSTAIN** | signatures ABSTAIN (verifier_unavailable) |
| `11-export-truncated` (additional) | An export that leaves out its last receipt | **FAIL** | scope FAIL (count_mismatch, sequence_mismatch, head_mismatch, root_mismatch) |
| `12-manifest-signature-altered` (additional) | A manifest signature altered, with the bill re-pointed at it | **FAIL** | signatures FAIL (manifest_signature_invalid) |

Each `case.json` says what changed, why the result follows, and the inputs, as paths relative to its directory. A consumer agrees with a case when its verdict, all eight claims and every code match `expected`, and `payment_ready` is false; `consumer/run-cases.mjs` compares exactly that.

`decisive` names the claim each case was built to break. It is a label for readers, not a result a consumer computes: no fixed order of the claims gives it, since case 08 names `keys` over `signatures` and case 10 names `signatures` over `keys`. Matching the verdict and the decisive claim alone is too weak a test. In cases 01 to 11, what a signature check catches is also caught by a link (07) or by the key a record names (08), so a consumer that never checks a signature matches both in all eleven. Case 12 is caught by the signature alone.

Run them all:

```sh
node consumer/run-cases.mjs
```

It finds `@veritasacta/verify@0.10.21` through `npx` (or the `cli.js` named by `VERIFY_CLI`), refuses any other version, runs every case and prints one line each. `node consumer/check.mjs --case cases/07-altered-receipt` prints one case's full result. The reference consumer shows that the cases are decidable; it is not offered as a product.

## Run it yourself

No permission is needed. Anyone may run their own implementation of the input contract against this fixture and publish the result. A run says the most when:

- it is written from this README and draft-03, not from `consumer/`, and says whether it calls `@veritasacta/verify` for signatures (if it does, the `signatures` and `keys` claims rest on that verifier, not on the run);
- it pins the fixture by tag and by the SHA-256 of `SHA256SUMS`, and checks every file against `SHA256SUMS` before it runs;
- for each case it reports the verdict, all eight claims with their codes and `payment_ready`, and compares each with `expected`, not the verdict alone;
- it names who wrote the implementation and who ran it, on which operating system, runtime and dependency versions, and when;
- it states what it does not establish: the keys are demo keys, the outcomes are simulated, there is no contract, and `payment_ready` is false in every case.

Runs so far:

- A [second implementation](https://github.com/aeoess/agent-governance-vocabulary/issues/177#issuecomment-6094738216), written from this README by someone other than this fixture's author, agrees on all 11 cases of `v1.0.0`, codes included. The format, the verifier and the fixture share one author, so it is not an independent record.
- The first [independent run](https://github.com/aeoess/agent-governance-vocabulary/issues/177#issuecomment-6162358259), by someone who wrote none of the format, the verifier, the fixture or that consumer, and with its own Ed25519 and JCS rather than `@veritasacta/verify`, agrees on all 11 cases of `v1.0.1` and `v1.0.0` on the verdict, every claim and every code. Its two findings are in `v1.1.0`: the agreement rule above, and case 12, which it proposed.

## How it was made

`producer/generate.mjs` ran the outcome meter (an unpublished prototype; commit `e9d8f6bcabc3`) over its sandbox at small scale for July and August 2026, closing each month with a signed period statement, and wrote August's range, the August statement, the bills and the cases. A second run of the same simulation under another demo key made case 08's bundle. The keys, and the engagement secret behind the receipts' unit references, existed only in that process's memory. Running the script again makes new keys and different bytes.

Case 12 was added in `v1.1.0` by `producer/case-12.mjs`, which derives it from the pinned `manifest.json` and `bill.json` alone: it changes the first hex digit of the manifest's signature and re-points the bill at the altered manifest's record hash, using the reference consumer's own record hash. Running it again gives the same bytes, and `test/fixture.test.mjs` checks that it does.

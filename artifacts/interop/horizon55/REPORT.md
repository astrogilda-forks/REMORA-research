# REMORA row for Horizon Shield #55 (#51 set 2, cases A, B and C)

## Answer

Payment C took the buyer's spending to 21000 JPY-testnet against a signed budget of 20000.

1. Reading the signed records, REMORA finds C over budget (`budget_compliance = CONTRADICTED`) and A and B within it, with delegation scope established for all three.
2. Run through REMORA's own execution path, C does not run once the budget is declared to REMORA. It is refused before review, and refused again at dispatch when all three payments were approved in advance. A and B run, and 14000 reaches the payment tool.
3. Without a declared limit REMORA lets all three run (21000). Cumulative limits were added to REMORA for this; before them it had no running total of what calls spend (NEGATIVE_RESULTS.md section 97).

Where each part stands: the cumulative limits used in part 2 are on master (#1025). So are measuring equipment movement from the plant (#1033) and binding limits to a signing authority and to every approval (#1037). Part 2 uses only the limit itself; it does not depend on the other two.

Exploratory, retrospective and author-operated. The A/B/C records were public and examined before this row was designed, so this is neither a holdout nor a preregistered confirmation, and no independent verification is claimed (independence: `AUTHOR_OPERATED`).

## What A, B and C are

Horizon Shield's #51 set 2 is a live run on 2026-10-22, recorded by MUSUBI in a signed companion log. One buyer agent (`4c3b54ac…`) calls one responder service (`7b1ada68…`, service `estimate-audit`) three times. The service audits a construction estimate (exterior wall painting, scaffolding and pressure washing) against the souba-db market-price dataset.

Every call is paid. The buyer holds one delegated credential from a root issuer (`ced79be2…`), and the issuer signed a budget policy for it: at most 20000 JPY-testnet in total. JPY-testnet is a simulated unit; no money moved.

| Case | Occurrence | Price | Total after the call | Against the budget |
|---|---|---|---|---|
| A | `hs51-musubi-2-A` | 7000 JPY-testnet | 7000 | within |
| B | `hs51-musubi-2-B` | 7000 JPY-testnet | 14000 | within |
| C | `hs51-musubi-2-C` | 7000 JPY-testnet | 21000 | over by 1000 |

Each call is fine on its own: the right caller, the right service, a capability the credential grants, the advertised price. Only the running total is wrong. In the live run C was executed anyway, and MUSUBI's settlement flagged it afterwards (`budget_exceeded`). The question for #55 is what REMORA makes of the same records, and whether REMORA would let C run.

## Part 1: reading the signed records

Inputs: horizon-shield `b85029de8d22c5246886f4f50ede03da0f54dfcf` (records) and `5b22c203248b0149cd0456f77d32feb887f48ee0` (souba-db 2.3.0), pinned in `inputs.lock.json` (SHA-256 `1a423378f20b6f4d18f33558da72bd966035d72571bf89b9c277ce1172150bf8`).

Log: 13 entries, hash chain, operator and author signatures checked locally: verified. Bitcoin anchoring of the checkpoint was not checked (`checkpoint_anchoring = NOT_ESTABLISHED`).

| Claim | A | B | C |
|---|---|---|---|
| `native_delegation_scope` | ESTABLISHED<br>`all_delegation_predicates_checked` | ESTABLISHED<br>`all_delegation_predicates_checked` | ESTABLISHED<br>`all_delegation_predicates_checked` |
| `budget_compliance` | ESTABLISHED<br>`cumulative_total_7000_within_20000` | ESTABLISHED<br>`cumulative_total_14000_within_20000` | CONTRADICTED<br>`cumulative_total_21000_exceeds_20000` |
| `same_request_occurrence` | ESTABLISHED<br>`use_payment_receipt_criteria_name_this_request` | ESTABLISHED<br>`use_payment_receipt_criteria_name_this_request` | ESTABLISHED<br>`use_payment_receipt_criteria_name_this_request` |
| `payment_execution_link` | ESTABLISHED<br>`payment_logged_before_its_execution` | ESTABLISHED<br>`payment_logged_before_its_execution` | ESTABLISHED<br>`payment_logged_before_its_execution` |
| `audit_byte_identity` | ESTABLISHED<br>`public_bytes_match_signed_response_sha256` | NOT_ESTABLISHED<br>`audit_bytes_not_public` | ESTABLISHED<br>`public_bytes_match_signed_response_sha256` |
| `dataset_byte_identity` | ESTABLISHED<br>`dataset_bytes_match_audit_digest_and_pin` | NOT_ESTABLISHED<br>`audit_bytes_not_public` | ESTABLISHED<br>`dataset_bytes_match_audit_digest_and_pin` |
| `dataset_runtime_use` | NOT_ESTABLISHED<br>`no_observation_of_runtime_inputs` | NOT_ESTABLISHED<br>`no_observation_of_runtime_inputs` | NOT_ESTABLISHED<br>`no_observation_of_runtime_inputs` |
| `receiver_accepted_result` | NOT_ESTABLISHED<br>`acceptance_records_not_public` | NOT_ESTABLISHED<br>`acceptance_records_not_public` | NOT_ESTABLISHED<br>`acceptance_records_not_public` |
| `remora_dispatch_authority` | NOT_ESTABLISHED<br>`no_remora_grant_lease_or_dispatch_record` | NOT_ESTABLISHED<br>`no_remora_grant_lease_or_dispatch_record` | NOT_ESTABLISHED<br>`no_remora_grant_lease_or_dispatch_record` |
| `physical_effect` | NOT_ESTABLISHED<br>`no_independent_effect_observation` | NOT_ESTABLISHED<br>`no_independent_effect_observation` | NOT_ESTABLISHED<br>`no_independent_effect_observation` |

### Request occurrence joins

| Case | occurrence | request SHA-256 (JCS) | signed response_sha256 |
|---|---|---|---|
| A | `hs51-musubi-2-A` | `329a112eec9250ea574c4720db74333302a515808be1b0a4b54793e93f2a6fd6` | `c2920477d95a8e48f16cc2df49ec58a02cd9b422db491206446e7a5be21937f5` |
| B | `hs51-musubi-2-B` | `c13a8c64ec5135dab706963c7204c5adb30c12efa8b1d56b9c0900b4fbb32ccc` | `40bc2a46f428b2cc5000e9d5e896adac218ebe3c2b76f78ba29afebf97887aea` |
| C | `hs51-musubi-2-C` | `a5650ab747a92d6b164c1753c731a419f197521691fa29af9a7b86a49f6a2a5f` | `c2920477d95a8e48f16cc2df49ec58a02cd9b422db491206446e7a5be21937f5` |

A and C name the same response bytes under different request digests.

### Native reported (the producer's settlement) beside the REMORA assessment

| Case | native execution disposition | native payment reasons | remora `native_delegation_scope` | remora `budget_compliance` |
|---|---|---|---|---|
| A | `within_delegation` | `[]` | ESTABLISHED | ESTABLISHED |
| B | `within_delegation` | `[]` | ESTABLISHED | ESTABLISHED |
| C | `within_delegation` | `['budget_exceeded']` | ESTABLISHED | CONTRADICTED |

## Part 2: does REMORA let C run?

The three payments, the payer and payee, and the budget (20000 JPY-testnet, from the issuer-signed budget policy) are taken from the verified log. Each payment goes through REMORA's execution API: `/v1/execution/assess`, `/approve`, `/execute`, the governed dispatcher and a sandboxed payment tool that records every call reaching it (`enforce.py`, `enforcement.json`).

REMORA as shipped, with no limit declared:

| Case | Amount | `/assess` | Approved | Outcome | Reached the payment tool |
|---|---|---|---|---|---|
| A | 7000 JPY-testnet | verify | yes | executed | yes |
| B | 7000 JPY-testnet | verify | yes | executed | yes |
| C | 7000 JPY-testnet | verify | yes | executed | yes |
| total | | | | | 21000 |

The signed budget declared to REMORA as a cumulative limit for the payer:

| Case | Amount | `/assess` | Approved | Outcome | Reached the payment tool |
|---|---|---|---|---|---|
| A | 7000 JPY-testnet | verify | yes | executed | yes |
| B | 7000 JPY-testnet | verify | yes | executed | yes |
| C | 7000 JPY-testnet | refused limit_exceeded | not asked | refused at assess: limit_exceeded | no |
| total | | | | | 14000 |

The same limit, with A, B and C all assessed and approved before any of them executes. Only the reservation at dispatch can stop C here:

| Case | Amount | `/assess` | Approved | Outcome | Reached the payment tool |
|---|---|---|---|---|---|
| A | 7000 JPY-testnet | verify | yes | executed | yes |
| B | 7000 JPY-testnet | verify | yes | executed | yes |
| C | 7000 JPY-testnet | verify | yes | refused at dispatch: limit_exceeded | no |
| total | | | | | 14000 |

The limit is reserved in one transaction as the dispatcher's last check before the call runs, so a payment approved earlier is still refused when the budget has been spent since. It is keyed by the payer, not by a task the caller chooses. The same mechanism caps setpoint movement and equipment starts (`remora/enforcement/cumulative_limits.py`, CAP-031).

## What this row does not establish

- Raw call bodies, B's audit bytes and acceptance records are not public; nothing about them is inferred.
- A and C carry the same public audit bytes but name different request occurrences; identical result bytes do not make them the same call.
- Part 1 is a retrospective count over signed payments. Part 2 is REMORA's decision on a replay with a sandboxed tool, not on the live calls, which REMORA was not in the path of.
- The limit holds only where a deployment declares it, on one host. It counts the amount the call names, not what a rail settled.
- No physical effect, no runtime use of the dataset and no production, certification or comparative security claim.
- Keys and the trust configuration come from the producer's own bundle.

Reproduce: `python integrations/horizon55/prepare.py` once (network), then `python integrations/horizon55/run.py --check` and `python integrations/horizon55/enforce.py --check` (offline). Interpreter, OS and library versions of the run that wrote these files are in `reproduction.json`.

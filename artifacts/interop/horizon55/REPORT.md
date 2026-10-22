# REMORA row for Horizon Shield #55 (#51 set 2, cases A, B and C)

Exploratory, retrospective and author-operated. The A/B/C records were public and examined before this row was designed, so this is neither a holdout nor a preregistered confirmation, and no independent verification is claimed (independence: `AUTHOR_OPERATED`).

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

## Request occurrence joins

| Case | occurrence | request SHA-256 (JCS) | signed response_sha256 |
|---|---|---|---|
| A | `hs51-musubi-2-A` | `329a112eec9250ea574c4720db74333302a515808be1b0a4b54793e93f2a6fd6` | `c2920477d95a8e48f16cc2df49ec58a02cd9b422db491206446e7a5be21937f5` |
| B | `hs51-musubi-2-B` | `c13a8c64ec5135dab706963c7204c5adb30c12efa8b1d56b9c0900b4fbb32ccc` | `40bc2a46f428b2cc5000e9d5e896adac218ebe3c2b76f78ba29afebf97887aea` |
| C | `hs51-musubi-2-C` | `a5650ab747a92d6b164c1753c731a419f197521691fa29af9a7b86a49f6a2a5f` | `c2920477d95a8e48f16cc2df49ec58a02cd9b422db491206446e7a5be21937f5` |

A and C name the same response bytes under different request digests.

## Native reported (the producer's settlement) beside the REMORA assessment

| Case | native execution disposition | native payment reasons | remora `native_delegation_scope` | remora `budget_compliance` |
|---|---|---|---|---|
| A | `within_delegation` | `[]` | ESTABLISHED | ESTABLISHED |
| B | `within_delegation` | `[]` | ESTABLISHED | ESTABLISHED |
| C | `within_delegation` | `['budget_exceeded']` | ESTABLISHED | CONTRADICTED |

## What this row does not establish

- Raw call bodies, B's audit bytes and acceptance records are not public; nothing about them is inferred.
- A and C carry the same public audit bytes but name different request occurrences; identical result bytes do not make them the same call.
- `budget_compliance` is a retrospective count over signed payments, not a pre-dispatch decision, and JPY-testnet is a simulated unit.
- No REMORA grant, lease or dispatch exists for these calls; `remora_dispatch_authority` is `NOT_ESTABLISHED` for every case. This row does not say REMORA would have prevented C.
- No physical effect, no runtime use of the dataset and no production or certification claim.
- Keys and the trust configuration come from the producer's own bundle.

Reproduce: `python integrations/horizon55/prepare.py` once (network), then `python integrations/horizon55/run.py --check` (offline). Interpreter, OS and library versions of the run that wrote these files are in `reproduction.json`.

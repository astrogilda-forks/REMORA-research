# REMORA as a paying-side consumer for edge E6 (Veritas Acta receipts)

Status: experimental. An author run of a second implementation, not an
independent record under the boundary map's rule, and not reviewed by Veritas
Acta.

## What it does

`remora.interop.acta_e6.evaluate` implements the input contract of
[`VeritasActa/e6-fixture`](https://github.com/VeritasActa/e6-fixture) at
`v1.1.0`. It takes one billing period's receipts, the signed period manifest,
a bill, the pinned keys document with a root fingerprint pinned out of band,
and any earlier bills. It reports seven evidence claims and `amount`, each
`PASS`, `FAIL`, `ABSTAIN` or `NOT_EVALUATED` with its codes. `payment_ready`
is always false.

The consumer was written from the fixture README alone. The fixture's
`consumer/`, `producer/` and `test/` code and draft-farley-acta-signed-receipts-03
were not read. It does not call `@veritasacta/verify`. Ed25519 comes from
`cryptography` and JCS from `remora.interop.jcs`, so the `keys` and
`signatures` claims rest on those two and not on the Acta verifier.

The results stay in Acta's vocabulary. Nothing here maps onto REMORA's
`ACCEPT`, `VERIFY`, `ABSTAIN` or `ESCALATE`, and nothing is admitted as REMORA
evidence.

## Run it

```sh
# a fresh clone of the fixture: all 89 files in SHA256SUMS must be present and match
git clone https://github.com/VeritasActa/e6-fixture && git -C e6-fixture checkout v1.1.0
python scripts/run_acta_e6.py --fixture e6-fixture --out record.json

# the vendored subset, compared with the committed record (what the test suite runs)
python scripts/run_acta_e6.py --check
```

The runner refuses to start unless the SHA-256 of `SHA256SUMS` equals the pin
in `upstream-lock.json` and every listed file present matches it. Each case
runs twice. The first run uses the Ed25519 check. The second is a
signature-blind control whose check accepts every signature, with links, keys,
scope and bill checks unchanged.

## Result at v1.1.0

The record is `records/remora-e6-consumer-v1.1.0.json`, made from a fresh
clone at `8d8fc50a` with `SHA256SUMS` hashing to `08731bb7…`.

| Run | Agrees with `expected` (verdict, all eight claims, every code, `payment_ready`) |
|---|---|
| REMORA consumer | 12 of 12 |
| Signature-blind control | 9 of 12. It differs on 07 and 08 in codes and the `signatures` claim with the verdict still `FAIL`, and on 12 it returns `PASS` where `FAIL` is expected. |

Case 12 is the only case in which a signature check alone changes the
verdict, which is what `v1.1.0` added it for.

## What this does not establish

The keys are demo keys, the outcomes are simulated, there is no contract, and
`payment_ready` is false in every case. The record shows that this consumer
and the fixture's expected results agree. It does not show that either is
correct against draft-03, which was not read. REMORA wrote the implementation
and ran it, so under the boundary map's independence rule this is a second
implementation's author run. An independent record needs a party that wrote
neither the fixture nor this consumer to run it.

Codes for failure conditions that no case exercises are REMORA's own names.
The module docstring lists them.

## Files

| Path | What it is |
|---|---|
| `upstream-lock.json` | Tag, commit and `SHA256SUMS` digest of the fixture, and the subset vendored |
| `upstream/e6-fixture/` | The fixture's README, LICENSE, `SHA256SUMS`, data and cases, unchanged (Apache-2.0) |
| `records/remora-e6-consumer-v1.1.0.json` | The run record |
| `../../remora/interop/acta_e6/consumer.py` | The consumer |
| `../../scripts/run_acta_e6.py` | Pin check, case runner and record writer |
| `../../tests/test_acta_e6_consumer.py` | Cases, control, pin refusals and the paths no case reaches |

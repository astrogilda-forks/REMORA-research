# Fault-scenario crosswalk v1 (2026-10-26)

This table maps each failure scenario of the adversarial review of 2026-10-26
(RMR-AUD-26-011) to the tests and runs that exercise it. It records what each
one runs against and what it returned. It is a coverage record, not a claim of
safety: a passing row shows that the named tests passed on the named runtime,
and nothing beyond it.

The review names scenarios F1 to F15, but their definitions are not in the
findings file this repository received, and no F10 to F15 exists in the
repository. The rows below are therefore the review's scenario classes
(retry, grant and nonce, store outage, stop, UNKNOWN, limits, tenants, API and
SDK, CAM, alternative ingress), not F-numbers. Mapping F1 to F15 onto them is
`NOT_ESTABLISHED` until the definitions are supplied.

## How the results were produced

- Revision: `origin/master` at `2594d08b`. The process-split rows also include
  the fixture fix in this change.
- Host: one Windows 11 machine, Python 3.14, and PostgreSQL 16 in a local
  container (`REMORA_PG_DSN` set only for rows marked "PG"). CI runs the same
  files on Linux. CI is the verdict, and these are local runs.
- "OT pilot" rows cite the committed runs under `artifacts/pilot-pack/runs/`:
  a Docker Compose stack on one host with a simulated plant.

## Crosswalk

| Scenario | Tests and runs | Real PG | Effect | Restart | Processes | Result 2026-10-26 |
|---|---|---|---|---|---|---|
| Retry and idempotency | `test_assess_idempotency_reservation.py`, `test_idempotency_store.py`, `limits/test_limits_idempotency.py` | no / PG | simulated tool | no | one | 96 passed, 49 skipped (the PG variants); with PG, 139 passed |
| Retry advice in the SDK | `test_review_sdk_transport_errors.py` | no | none | no | one | passed. Neither client retries on its own; the post-send `retryable` flag is corrected in #1094 |
| Grant and nonce single use | `test_lease_nonce_durability.py`, `test_gate_token_nonce_mutation_contract.py`, `test_gate_replay_properties.py`, `test_nonce_store_consumed.py`; PG: `test_enforcement_ledgers_postgres.py` | no / PG | simulated | replacement store | one | 89 passed; with PG, 11 passed |
| Single use across processes | `conformance/test_execution_boundary_process_split.py` | no / PG | local HTTP effect | executor restart | three on one host | 14 passed, 2 skipped; with PG, 16 passed (after the fixture fix below) |
| Durable store outage | `test_durable_state_outage_503.py`; PG: `test_postgres_outbox_fault_injection.py`; OT pilot fault 4 | simulated / PG | simulated plant | no | one | 5 passed; with PG, 7 passed; OT pilot `fault-injection-2026-10-26`, 9 of 9 |
| Orchestrator view of an outage | OT pilot fault 10 | PG stopped | none | no | one container | 10 of 10 in the run of #1089 (merged) |
| Stop switch | `test_execution_stop.py`, `test_execution_stop_spends_nothing.py`; the process-split p9 test; OT pilot fault 7 | no / PG | simulated | across restart (p9) | one / three | 11 passed; p9 is in the process-split row |
| Effect outcome UNKNOWN | `test_unknown_execution_state.py`, `limits/test_limits_resolve_route.py`, `test_none_is_unknown_not_safe.py`; OT pilot fault 8 | no | simulated | no | one | 60 passed |
| Cumulative limits | `tests/limits/`; PG: `limits/test_limits_postgres.py`; OT pilot fault 3 | no / PG | simulated | across restart (pilot) | one; two executors on one PG (PG tests) | 253 passed, 41 skipped, 1 failed; with PG, 7 passed. The failure, `test_a_naive_iso_timestamp_is_read_as_utc`, is local to Windows, and CI passes it |
| Ledger topology | `limits/test_limits_ledger_topology.py` | no | none | no | one | in #1092 (merged) |
| Cross-tenant isolation | `test_cross_tenant_argument_boundary.py`, `test_rbac_isolation.py`, `test_evidence_admission_isolation.py` | no | simulated | no | one | 20 passed |
| API and SDK contract | `test_openapi_export.py`, `test_sdk_integration.py` (in-process ASGI), `test_sdk_client.py`, `test_sdk_async_client.py`, `test_sdk_public_api.py` | no | simulated | no | one | 51 passed, 1 failed. The failure is the export's package version string, 0.11.0 locally against 0.12.0 committed, an installation artefact that CI passes |
| CAM mismatch and modes | `test_cam_lease_binding.py`, `test_capability_activation.py`, `test_activation_manifest.py` | no | simulated | no | one | 98 passed; mode gate at dispatch in #1093 (merged) |
| Alternative ingress (MCP, routes) | `flow/test_mediation_surface.py`, `test_mcp_remora.py`, `test_mcp_tool_contracts.py`; `scripts/check_flow_mediation_surface.py` | no | none | no | one | 89 passed; the surface check passes (28 routes, 3 dispatching) |
| WS1 atomic admission | PG: `test_atomic_admission.py`, `test_review_admission_grant_withheld.py` | PG | simulated | no | one; contention on one PG | 94 passed; strict-profile requirement in #1091 (merged) |

## Not run

| Scenario | Status |
|---|---|
| Executors on two separate hosts sharing one store | `NOT_RUN` |
| A network partition between executors and the store | `NOT_RUN` |
| A real plant, real payments or a customer system | `NOT_RUN`, by rule |
| Orchestrators other than Docker Compose on one host | `NOT_RUN` |
| The flow dispatch fence under a slow tool call (RMR-AUD-26-001, 26-002) | deferred to #1084; #1085 holds a reproduction against #1084 |
| F1 to F15 as numbered by the review | `NOT_ESTABLISHED`: definitions not supplied |

## Fixture defect found while building this table

`tests/conformance/_executor.py` passed both `REMORA_PG_DSN` and
`REMORA_CHAIN_DB` to `AuthorityEpochs`, which takes exactly one. The server
prefers PostgreSQL (`servers/execution_api.py::_stop_epochs`). With
`REMORA_PG_DSN` exported in a developer's shell, the SQLite process-split tests
inherited it, and their executors refused to start: 1 failed and 4 errors. CI
did not see it, because its PostgreSQL job selects only the tests named
`postgres`. The executor now prefers the DSN as the server does, and the three
SQLite-chain tests clear `REMORA_PG_DSN` for their children. No server code
changed.

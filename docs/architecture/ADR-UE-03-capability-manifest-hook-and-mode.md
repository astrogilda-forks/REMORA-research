# ADR-UE-03: Capability activation manifest, and where hook and mode live

- Status: **accepted as proposed** (2026-10-25, owner decision). Proposed
  2026-10-24. The SDD names the approval owner as code owner / security
  ([unified capability execution v1.1](../design/unified-capability-execution-v1.1.md)
  §13, decision ADR-UE-03). The seven particulars below stand as written;
  the two choices the proposal left open are resolved under "Owner
  resolution". No code implements the manifest yet; the slices at the end
  are the work.
- Deciders: repository owner, security
- Related: SDD §3 (Capability Activation Contract), §6 (read-only API
  contracts) and §10 (phase P1 "Inventory + CAM"). The
  [atlas](../design/unified-capability-execution-v1.1-atlas.yaml) and
  `docs/assurance/capability_register_v1.yaml`. The first P1 slice,
  `scripts/check_capability_hooks.py` and `tests/test_capability_hooks.py`
  (#1058). The
  [ADR on authority custody and lease durability](ADR-authority-custody-and-lease-durability.md).

## Context

SDD §3 requires every registered capability to appear in a signed,
deployment-owned Capability Activation Manifest (CAM). The CAM carries
per-deployment fields only. Maturity stays in the capability register, read
by CAP ID. Claim ceilings stay in `docs/interop/remora-capabilities-v1.yaml`,
referenced by property ID, and a CAM may only narrow one. The SDD states that
the register "has no `hook` or `mode` field today" and leaves the placement of
both to this decision.

What exists on `master` at `ab64990a`:

- The register has 32 entries, each with `id`, `name`, `status`,
  `verified_at_sha`, `verified_by`, `evidence` and `caveat`. #1058 adds a
  `hook` block to each: `primary` from the SDD's eleven-value vocabulary,
  optional `secondary`, and `bound_at`. The last names the code symbols,
  routes or tests where the capability binds, each one of the entry's own
  evidence paths.
  `scripts/check_capability_hooks.py` verifies every binding and
  `tests/test_capability_hooks.py` is the P1 exit gate. The checker refuses a
  `mode` key in that block.
- The atlas records `sdd_hook`, `sdd_mode` and `reachable_rung` per
  capability as the SDD's assessment. `sdd_mode` is free text ("SHADOW →
  conditional ENFORCE"), so it cannot be parsed as a mode.
- No manifest, mode, signature or `/v1/system/*` route exists in code. A
  deployment chooses behaviour through environment flags read at startup and
  per call: `REMORA_WS1_ADMISSION=atomic`, `REMORA_REQUIRE_LIMITS`,
  `REMORA_REQUIRE_IDEMPOTENCY`, `REMORA_FLOW_CONTROL=1`,
  `REMORA_STRICT_MONOTONE`, `REMORA_EXECUTION_DOMAIN_ROLE` and others. The
  strict runtime profiles (`remora/toolcall/runtime_profile.py`) refuse to
  start when a profile's prerequisites are missing, flag by flag.
- Three signed deployment artefacts already exist and set the pattern: the
  ToolSpec bundle (`remora/execution/authorization.py`, a signer allowlist),
  the limit policy (Ed25519 over a canonical digest,
  `REMORA_LIMITS_TRUSTED_KEYS`, `scripts/sign_limit_policy.py`), and the lease
  and grant themselves. The policy identity (`remora/policy/versioning.py`)
  hashes the policy files, and every grant and lease binds that hash.
- The `ExecutionLease` signs optional fields only when set (the task,
  effect, plan, surface, capability and flow fields), so a new digest field
  can be added without changing the bytes of any lease issued before it.

## Options

**A. Hook in the register, mode in the CAM (the SDD's proposed default).**
The primary hook is a fact about the repository: where the code binds. It
lives in the register, next to the evidence that proves it, and the exit gate
holds it. The requested mode is a fact about one deployment. It lives in a
signed CAM whose digest is pinned into the decision and the lease. Discovery
is a read-only join of the three sources.

**B. Hook and mode both in the CAM.** Every deployment restates where the
repository binds a capability. Two owners then describe one fact, and the
register's exit gate cannot see the manifest, so a hook can drift between them
with nothing to fail.

**C. Hook and mode both in the register.** The repository would carry
deployment facts. A mode change would be a commit, every deployment would run
the same modes, and the SDD's "per-deployment fields only" rule would be
broken by the register itself.

Criteria used. One owner per fact. Signed provenance for anything that
changes what runs. No wildcard enablement and no automatic promotion. The
effective mode snapshotted into the decision. Compatibility with the policy
identity and the lease format that exist.

## Decision

Option A, accepted with these particulars as proposed:

1. **Hook.** The register's `hook` block is the record of where a capability
   binds (#1058). The atlas keeps `sdd_hook` as assessment, and the checker
   reports drift between the two. No deployment file may restate a hook.
2. **Mode.** A CAM, contract `capability-activation-v1`, with the fields of
   SDD §3 per capability: `capability_id`, `component_version`,
   `implementation_ref`, `requested_mode`, `allowed_modes`,
   `required_premises`, `trust_source_ids`, `api_contract`, `sdk_surface`,
   `health_probe`, `fail_mode`, `claim_ceiling`, `evidence_refs`. Signed with
   Ed25519 over a canonical digest, as the limit policy is, under its own
   domain string. Proposed settings: `REMORA_CAM_FILE` and
   `REMORA_CAM_TRUSTED_KEYS`; an unsigned CAM is accepted only outside the
   strict profiles, as an unsigned limit policy is today.
3. **Effective mode.** Computed by the server from the runtime profile, the
   verified premises and the signed requested mode. Never above
   `allowed_modes`. A premise that cannot be verified gives the entry's
   `fail_mode`, which is never ALLOW. A caller-supplied mode has no authority.
   The effective mode is snapshotted into the decision record and the
   evidence, as SDD §3 requires.
4. **Startup.** Under a strict profile the process refuses to start without a
   CAM that names every registered capability whose `hook.bound_at` falls in
   that process. A capability absent from the CAM is DISABLED, never
   defaulted to a mode. This is the exit gate of #1058 applied at runtime.
5. **Digest binding.** The CAM digest is signed into the lease as
   `cam_digest`, set only when a CAM is loaded, so earlier leases verify as
   before. Whether the digest also enters `policy_bundle_hash` is left to the
   owner: inside it, every CAM change changes every decision identity; beside
   it, the two can be compared separately.
6. **Discovery.** `GET /v1/system/capabilities` serves a catalogue built at
   release time from `scripts/check_capability_hooks.py --json` and packaged
   with the wheel, joined with the running deployment's CAM. The server never
   reads `docs/` or runs `git`; the freshness column is the build's. The route
   is tenant-authenticated with the `read` capability and returns no signer or
   credential material.
7. **Migration of the environment flags.** Each flag that selects a mode
   today maps to one CAM `requested_mode`. During the migration the CAM and
   the flag must agree, or startup refuses; neither silently wins. Flags that
   are prerequisites rather than modes (keys, DSNs, bundles) stay flags.

### Owner resolution (2026-10-25)

The owner accepted the seven particulars as proposed and resolved the two
open choices:

- **Digest placement.** `cam_digest` is a signed-when-set lease field beside
  `policy_bundle_hash`, as item 5 proposes. It does not enter the policy
  identity: a CAM change then changes no decision identity of a deployment
  whose policy files did not change, and the two digests are compared
  separately. Folding it in later would be an amendment to this ADR.
- **Key custody.** The CAM has its own trusted-key setting,
  `REMORA_CAM_TRUSTED_KEYS`, as item 2 proposes. An operator may point it at
  the limit-policy key material; the setting stays separate so the two
  artefacts can be rotated apart.

## Consequences

- The register gains no deployment fact, and no deployment file gains a
  repository fact. The checker in #1058 enforces the first half today.
- A CAM is one more signed artefact an operator maintains, with the same key
  custody questions as the limit policy. Its trusted keys are its own setting
  (owner resolution above).
- Until the CAM exists, every catalogue output carries `mode:
  NOT_ESTABLISHED`. Nothing may present a flag's value as a mode.
- SDD §10 forbids manifest-driven enforcement before P0 items 1 to 7 close.
  They closed on 2026-10-24 (#1053 to #1057), so the slices below may start.

## Slices after acceptance

1. CAM schema, loader and signature verification as a library module with
   its own tests; no runtime reads it yet. Delivered 2026-10-25:
   `remora/governance/activation_manifest.py`,
   `schemas/capability_activation_manifest_v1.yaml`,
   `scripts/sign_capability_manifest.py`, `tests/test_activation_manifest.py`.
2. Effective-mode computation and the startup validation of item 4, behind
   an opt-in setting, with the premises registry naming what each premise
   checks.
3. `cam_digest` in the lease and the decision record, signed only when set,
   with the completeness contract extended as the flow fields were.
4. The packaged catalogue artefact and `GET /v1/system/capabilities`, with
   the OpenAPI document and the typed client regenerated.
5. The environment-flag migration of item 7, one flag per change, each with
   the agreement test.

## What this ADR does not decide

It does not decide any capability's mode, does not change any enforcement
path, and makes no claim about a deployment. ADR-UE-01, -02 and -04 to -08
in SDD §13 are separate decisions with their own owners.

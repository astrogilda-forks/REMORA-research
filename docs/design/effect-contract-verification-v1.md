# Effect contract verification v1

Status: open proposal, 2026-10-13. Nothing here is implemented.
Origin: reviewing an external MCP adapter against REMORA at `1f2622dc`
(the same review that produced the closed argument-schema profile, #829).

## The gap

A signed ToolSpec says what a tool's implementation reaches. REMORA checks
that the declaration is authentic, that it has not moved since assessment,
that the callable is the one it names (`callable_digest`, now on the API path
too, #832) and that mediated effects stay inside the declared ceiling. It
never checks that the implementation behaves as declared.

The adapter that prompted this note shows the difference. One of its tools
declared no process start and no file write. Its implementation started a
worker process and wrote temporary files on every call. The declaration was
signed, pinned and verified, and it was wrong.

REMORA has the same blind spot, and its own documents already say so:

- `effect_mode: NONE` is "a signed claim, not proof: an empty ceiling does not
  show that the implementation has no hidden effect"
  (`remora/execution/effect_policy.py`). That is why `NONE` is accepted only
  for read-only tools. Nothing measures it for those either.
- `CapabilityMediator` "does not stop code that ignores it and uses a client
  directly" in the research profile (`remora/enforcement/capability_mediator.py`).
  The strict profile removes effect credentials from the executor. It does not
  remove the network, the filesystem or the ability to start a process.
- `network_policy.egress` is signed and read by the reference runtime as the
  offered network surface. No path observes whether the callable opens a
  connection outside it.
- `EFFECT_VERIFIED` means "the declared delta matched the supplied observation;
  it does not prove causation or detect undeclared effects"
  (`docs/interop/remora-capabilities-v1.yaml`). Postcondition verification
  looks at the target. This note is about the implementation's footprint.

So the question this note answers is: can REMORA observe, for a bounded set of
calls in a bounded environment, whether an implementation reached an effect
its signed spec does not declare, and say exactly how far that observation
reaches?

## What it can and cannot establish

The asymmetry decides the whole design. One observed undeclared effect is a
counterexample: the declaration is wrong for that input in that environment,
and that does not depend on coverage. No observed undeclared effect proves
nothing about inputs that were not run, environments that were not used,
or effects the observer cannot see. So:

| Verdict | Means | Depends on coverage |
|---|---|---|
| `MISMATCH` | At least one effect outside the declared profile was observed, with the case that produced it. | No. One case suffices. |
| `MATCH` | Every case ran to completion under an observer that reported no blinding event, every observed effect was inside the declared profile, and coverage met the stated threshold. | Yes, and the record carries it. |
| `NOT_ESTABLISHED` | The observer was blinded, a case did not complete, two runs of a case disagreed, or coverage is below the threshold. The reason is named. | Not applicable |

`MATCH` is never "the tool has no undeclared effect". Its claim ceiling is
"no undeclared effect was observed by this observer on these cases, at this
coverage, on this callable digest". A record that says `MATCH` without its
coverage block is malformed and refused. This follows evidence admission C4:
absence needs visibility and a coverage denominator for the same scope
(`docs/design/evidence-admission-v1.md`).

A declared effect that was never observed is not a mismatch. A ceiling is not
an obligation. It is reported as `declared_unobserved`, which is useful input
for narrowing an over-wide spec and nothing more.

## The declared profile

v1 derives the expected profile from fields that are already signed. It adds
no schema field.

| Effect class | Declared by | Expected under v1 |
|---|---|---|
| mediated effect | `downstream_capabilities` (v2), `effect_mode` (v3) | `MEDIATED`: each mediator request is inside the ceiling. `NONE`: no mediator request. |
| network | `network_policy.egress` | `"none"`: no `socket.connect`, `socket.sendto`, `http.client.connect` or `urllib.Request`. A host list: connections only to those hosts. |
| process | nothing | none |
| filesystem write | nothing | none |
| native code | nothing | none (see blinding below) |
| environment write | nothing | none |

The process and filesystem rows are the adapter's case. Under v1, any process
start or file write during a call is a `MISMATCH` for every tool, because
nothing in the signed spec permits one. That is strict on purpose. A strict
tool reaches effects through the mediator, and a direct file write is exactly
the kind of effect the mediator exists to replace.

Some tools will legitimately need scratch space or a helper process. Declaring
that needs a signed field, which is a schema change: a `host_effects` block in
a ToolSpec schema version 4, naming allowed executables and scratch roots.
That is **owner decision 1**. The recommendation is to build v1 without it,
run it on the repository's own tools, and add the field only if a real tool
needs it. That is the same rule that kept `effect_cardinality` singular.

## The observer

### Vantage 1: in-process audit hooks

Python's audit hooks (PEP 578, `sys.addaudithook`) raise a named event for each
effect the standard library performs. The events below were checked on
CPython 3.14 (Windows) on 2026-10-13 by triggering each effect under a hook.
Before the observer ships, the set has to be pinned by a test on every
supported version and on Linux.

| Effect | Events observed |
|---|---|
| file write, create, truncate | `open` (write is decided from `mode` and `flags`, not from the event name), `tempfile.mkstemp` |
| file delete, rename, tree removal | `os.remove`, `os.rename`, `shutil.rmtree` (followed by `os.rmdir`, `os.remove`) |
| process start | `subprocess.Popen` (then `_winapi.CreateProcess` on Windows), `os.system` |
| network | `socket.__new__`, `socket.connect`, `socket.getaddrinfo`, `urllib.Request`, `http.client.connect` |
| environment write | `os.putenv` |
| native code loaded | `ctypes.dlopen` |
| observer tampering | `sys.addaudithook` |

The same probe showed why a raw event list is not a verdict. `getaddrinfo`
opened the hosts file and `urllib` read the registry for proxy settings, so
reads have to be normalised by mode and not counted as effects.

A hook cannot be removed, so each tool runs in a fresh interpreter. The
observer records two phases separately: `load` (importing the registry module
and its closure) and `call` (each case). An import-time effect is reported in
the `load` phase and gets the same verdict rules. Effects that a module starts
at import and finishes in the background are the reason both phases are
recorded instead of only the call.

### Blinding: what this vantage cannot see

An audit hook observes Python calling into the standard library, nothing
lower. It is not a sandbox, and PEP 578 says so. These end a case as
`NOT_ESTABLISHED`, never `MATCH`:

- `ctypes.dlopen`, or any native extension loaded during the case. Native code
  reaches the OS without raising events;
- `sys.addaudithook` called by the tool, because a second hook means the tool is
  interacting with the observer;
- a timeout, a crash of the interpreter, or a case that did not complete;
- a process start that the profile allows, once `host_effects` exists. The
  child's own effects are outside this vantage. A process start the profile
  does not allow is a `MISMATCH` before the blinding matters.

Already-open handles inherited from the harness, threads started before the
observer was installed, and effects scheduled for after the case returns are
also outside it. The harness avoids the first two by installing the hook
before the import, and the record names the third as a known gap.

### Vantage 2: the operating system (later)

On Linux CI, `strace -f` (or an eBPF tracer) follows children and native code.
It turns most blinding events into observations. It is a separate vantage with
its own record, not a replacement: the two are reported side by side, and a
disagreement between them is itself a finding. It is listed here so the record
format has room for it. It is not part of the first slices.

## Mediated effects

For a `MEDIATED` tool the harness supplies a `CapabilityMediator` whose
executors are stubs. They record the request and return a fixed result, so no
real effect runs. The mediator already refuses a capability or resource outside
the authority. The verifier turns its records into observations:

- an `EXECUTED` request inside the ceiling is a declared effect;
- a request refused for being outside the ceiling is a `MISMATCH`. The code
  tried to reach something it does not declare, and that matters even though
  the mediator stopped it;
- a request with a missing executor is a harness error, and the case is
  `NOT_ESTABLISHED`.

Stub results can change the code path the tool takes afterwards. The record
says so, and that is part of why a mediated `MATCH` is bounded to the stubbed
results.

## Cases and coverage

A case is an argument set the signed `argument_schema` accepts. Cases come from
two places:

1. **Author cases**: a case file shipped with the bundle and bound to it by
   digest.
2. **Profile cases**: generated from the closed argument-schema profile (#829).
   The profile is small enough to enumerate: each `enum` value, each
   `anyOf`/`oneOf` branch, numeric bounds and their neighbours, each optional
   property present and absent. A schema outside the profile does not load, so
   generation never meets a keyword it cannot reason about.

Each case runs twice. If the two runs observe different effect sets, the case is
`NOT_ESTABLISHED` (`nondeterministic_effects`), unless either run already
observed an undeclared effect. Then it is a `MISMATCH`.

Coverage is reported on two axes and never folded into one number:

- **code**: line and branch coverage of the callable's closure. The closure is
  already computed for `closure-sha256` digests (`closure_members` in
  `remora/toolcall/callable_digest.py`), so the denominator is the same file set
  the digest attests;
- **input**: the fraction of profile partitions (enum values, branches,
  optional-property presence) that some case exercised.

The threshold that `MATCH` requires is stated in the record and chosen before
the run. A threshold chosen after seeing the coverage is not a threshold.

## The evidence record

`effect-conformance-evidence-v1`, one per tool and observer run:

- **binding**: `toolspec_hash`, `toolspec_version`, `callable_digest`, bundle
  digest and case-file digest. A record for another digest is a record about
  another tool;
- **observer**: vantage (`python_audit_hook` in v1), interpreter version,
  platform, verifier version and the pinned event table digest;
- **per case**: arguments hash, phase, normalised observed effects, raw event
  count, blinding events, completion and duration;
- **comparison**: declared profile, undeclared observations with their case,
  `declared_unobserved`;
- **coverage**: both axes, the threshold and the closure file set;
- **verdict** and named reasons, plus the claim ceiling text;
- **vantage independence**: `AUTHOR` when the tool's author ran it.
  `INDEPENDENT` needs a separate control domain, under the same rule E7 used.
  A self-declared flag is never read;
- `content_sha256` over the canonical record.

The record is evidence, not authority. It never grants anything. At most it
removes a refusal that a deployment chose to require.

## Where it gates

Verification runs before deployment, in CI or on an operator's machine. It
never runs on the dispatch path. A strict deployment can require it through
the BindingPolicy, as a new binding `effect_conformance`:

| State | Startup behaviour |
|---|---|
| `REQUIRED` | Every registered tool needs a record whose binding equals the loaded spec and the measured callable, with verdict `MATCH`. `MISMATCH` refuses startup. `NOT_ESTABLISHED` refuses startup, because it is the binding the deployment said it needs. |
| `UNVERIFIABLE` | Recorded at startup as a declared gap, like `task_identity` today. |

The BindingPolicy rule is that a missing binding refuses startup. Adding
`effect_conformance` to the v2 matrix would therefore make every existing v2
policy refuse to start. It belongs in a new contract version (`review/v3`,
`controlled_pilot/v3`), and v2 stays as it is. That is **owner decision 2**.

A `MISMATCH` is reported whatever the BindingPolicy says. A deployment can
decide not to require conformance. It cannot hide a counterexample that was
produced against the spec it runs.

## Validation before any claim

The verifier is itself a detector, so it needs a pre-registered seeded-fault
corpus before its verdicts mean anything. Expected verdicts are fixed before the
first run, and misses are kept:

| Fixture | Expected |
|---|---|
| read-only tool, `effect_mode: NONE`, writes a temp file per call | `MISMATCH` |
| same, starts a helper process (the adapter's case) | `MISMATCH` |
| `egress: none`, connects to a host | `MISMATCH` |
| egress list `[a]`, connects to `b` | `MISMATCH` |
| mediated tool requests a capability outside its ceiling | `MISMATCH` |
| writes a file at import, not per call | `MISMATCH` in phase `load` |
| writes only for one `enum` value | `MISMATCH` with profile cases, `MATCH` with a single author case: a pinned known miss for author-only runs |
| writes through `ctypes` | `NOT_ESTABLISHED` (`native_code`), never `MATCH` |
| installs its own audit hook | `NOT_ESTABLISHED` (`observer_tampering`) |
| writes only after a date, or only when it detects the harness | `MATCH`: a pinned false `MATCH`, kept as the standing example of what test-time observation cannot rule out |
| clean read-only tool | `MATCH` |

The last two rows are the honest result. The verifier will miss effects that
depend on time or on detecting the harness, and the corpus says so instead of
leaving it to be discovered.

## Slices

One PR per slice. Each adds tests and a capability-register entry at `RESEARCH`
/ `NOT_ESTABLISHED`, and leaves `runtime_capability_surface_completeness`
unchanged. That property is about the agent host's surface, not about one
implementation's footprint.

1. **Observer** (`remora/toolcall/effect_observation.py`): a fresh-interpreter
   harness, the pinned event table with a test per supported platform, mode
   normalisation, blinding events, and the `load` and `call` phases.
2. **Comparison and record** (`remora/toolcall/effect_contract.py`): the
   declared profile from the signed spec, the comparison, verdicts, the
   `effect-conformance-evidence-v1` schema and a CLI
   (`remora verify-effects --bundle --registry --cases`). Seeded-fault corpus
   rows 1 to 6 and 8 to 11.
3. **Cases and coverage**: profile-case generation from the closed schema
   profile, code coverage over `closure_members`, and the row 7 known miss.
4. **Gate**: `effect_conformance` in a v3 BindingPolicy contract, after owner
   decision 2.
5. **Vantage 2**: OS-level tracing on Linux CI, reported beside vantage 1.

Both new modules are CORE candidates and need stability-index rows in
`ARCHITECTURE.md`. Neither may import an EXPERIMENTAL module.

## Owner decisions

1. Whether to add `host_effects` (ToolSpec schema v4) now or only when a real
   tool needs it. Recommendation: later.
2. Whether `effect_conformance` enters through a v3 strict contract.
   Recommendation: yes, with v2 unchanged.
3. Whether an `AUTHOR` record is enough for `REQUIRED`, or an `INDEPENDENT`
   one is needed. Recommendation: `AUTHOR` is enough for the gate, provided
   the record shows its vantage, as the E7 record does.

## Not established, by design

- That an implementation has no undeclared effect. Only that none was observed,
  within a stated vantage, case set and coverage.
- Behaviour in production: other inputs, other environments, other times.
- Anything below the Python standard library before vantage 2 exists.
- Correctness of the declared effect itself, which postcondition verification
  covers for its own scope.
- Runtime capability-surface completeness, which stays `NOT_ESTABLISHED`.

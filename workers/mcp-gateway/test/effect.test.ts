/**
 * Effect verification for graph writes.
 *
 * The distinction under test is the one the whole mechanism exists for:
 * "the dispatcher returned" and "the effect happened" are different facts.
 * Not knowing is a third fact again, and it must not be reported as a
 * mismatch — only one of the two justifies compensating.
 *
 * The expected value comes from the call a person approved, never from what
 * the tool said it did (RMR-AUD-004, observation_from_the_tool). The tool's
 * result only locates the row; a tool that wrote something else, or pointed
 * at a row it did not write, is a mismatch.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  buildEffectReceipt,
  canonicalJson,
  effectDigest,
  fileEffectReceipt,
  observeAndRecord,
  verifyGraphWrite,
  type EffectBinding,
  type Verification,
} from "../src/effect";

/** What the approved call asked for. */
const ARGS = {
  graph: "kg://acme",
  subject: "acme",
  predicate: "ex:hasStatus",
  object: "active",
  source: "operator:stian",
  confidence: 0.9,
};

/** What kg_assert_fact returns: the declared delta plus the id it minted. */
const RESULT = {
  id: "fact-1",
  graph: "kg://acme",
  subject: "acme",
  predicate: "ex:hasStatus",
  object_json: '"active"',
  object_kind: "literal",
  source: "operator:stian",
  confidence: 0.9,
};

const DISPATCHED_AT = 1_800_000_000;

/** The row as it landed in D1. */
const ROW = { ...RESULT, tenant_id: "luftfiber", kg_seq: 7,
              created_at: DISPATCHED_AT + 1 };

const reads = (row: Record<string, unknown> | null) =>
  async () => row;

const verify = (row: Record<string, unknown> | null,
                args: Record<string, unknown> = ARGS,
                result: Record<string, unknown> = RESULT) =>
  verifyGraphWrite("kg_assert_fact", args, result, reads(row),
                   { dispatchedAt: DISPATCHED_AT });

describe("canonical form", () => {
  it("sorts keys, matching the Python digest input", () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it("has no whitespace", () => {
    expect(canonicalJson({ a: [1, 2], b: { c: 3 } }))
      .toBe('{"a":[1,2],"b":{"c":3}}');
  });

  it("sorts nested keys too", () => {
    expect(canonicalJson({ z: { y: 1, x: 2 } })).toBe('{"z":{"x":2,"y":1}}');
  });

  it("agrees with the Python implementation, digest for digest", async () => {
    // Hardcoded from remora.governance.effect_verification.effect_digest.
    // The writer and the verifier are in different languages, so these are
    // reimplementations of each other; without a pinned value they could
    // drift apart and every verification would silently become a mismatch.
    expect(await effectDigest({ a: 1, b: "x" })).toBe(
      "ecf9e98ec0641e23113ff3ce8bdc78d0ddd249886517fd4a7f68cc83d4e65667");

    expect(await effectDigest({
      subject: "acme", predicate: "ex:hasStatus", object_json: '"active"',
      object_kind: "literal", source: "operator:stian", confidence: 0.9,
    })).toBe(
      "03d9bf9e72d12ea2bdc2a2376c448b442de0fdd31328d59506aa30068dd762ee");
  });
});

describe("an assert that landed", () => {
  it("is VERIFIED when the read-back reproduces the approved call", async () => {
    const v = await verify(ROW);
    expect(v.status).toBe("EFFECT_VERIFIED");
    expect(v.expected_sha256).toBe(v.observed_sha256);
  });

  it("ignores fields the call does not name", async () => {
    // A concurrent legitimate write elsewhere in the row is not this
    // action's problem, and reporting it would train people to dismiss this.
    const v = await verify({ ...ROW, kg_seq: 999, observed_at: 123456 });
    expect(v.status).toBe("EFFECT_VERIFIED");
  });

  it("applies the tool's own defaults to omitted arguments", async () => {
    // object_kind defaults to literal and confidence to 1 in kg_assert_fact;
    // an approved call that omitted them asked for those values.
    const { confidence: _c, ...args } = ARGS;
    const v = await verify({ ...ROW, confidence: 1 }, args);
    expect(v.status).toBe("EFFECT_VERIFIED");
  });
});

describe("an assert that did not land as approved", () => {
  it("is MISMATCH when a declared field differs", async () => {
    const v = await verify({ ...ROW, object_json: '"inactive"' });
    expect(v.status).toBe("EFFECT_MISMATCH");
    expect(v.detail).toContain("object");
    expect(v.expected_sha256).not.toBe(v.observed_sha256);
  });

  it("names every differing field, not just the first", async () => {
    const v = await verify({ ...ROW, object_json: '"x"', source: "someone-else" });
    expect(v.detail).toContain("object");
    expect(v.detail).toContain("source");
  });

  it("is MISMATCH when the source was rewritten", async () => {
    // Provenance is the point of the graph carrying a source at all.
    const v = await verify({ ...ROW, source: "agent" });
    expect(v.status).toBe("EFFECT_MISMATCH");
  });

  it("is MISMATCH when the tool wrote and reported other values (RMR-AUD-004)", async () => {
    // The tool wrote "inactive" and said so. Comparing the row with the
    // tool's own report would call this VERIFIED; the approval said "active".
    const tampered = { ...RESULT, object_json: '"inactive"' };
    const v = await verify({ ...ROW, object_json: '"inactive"' }, ARGS, tampered);
    expect(v.status).toBe("EFFECT_MISMATCH");
    expect(v.detail).toContain("object");
  });

  it("is MISMATCH when the row predates the dispatch", async () => {
    // A tool that returns the id of an existing row that happens to match
    // has shown that the state exists, not that this call produced it.
    const v = await verify({ ...ROW, created_at: DISPATCHED_AT - 3600 });
    expect(v.status).toBe("EFFECT_MISMATCH");
    expect(v.reason_code).toBe("fact_predates_dispatch");
  });

  it("is MISMATCH when the row sits in another graph", async () => {
    const v = await verify({ ...ROW, graph: "kg://other" });
    expect(v.status).toBe("EFFECT_MISMATCH");
    expect(v.detail).toContain("graph");
  });
});

describe("not knowing is its own answer", () => {
  it("is UNOBSERVABLE when the fact cannot be read back", async () => {
    const v = await verify(null);
    expect(v.status).toBe("EFFECT_UNOBSERVABLE");
    expect(v.status).not.toBe("EFFECT_MISMATCH");
  });

  it("is VERIFIER_FAILED when the reader itself broke", async () => {
    const v = await verifyGraphWrite("kg_assert_fact", ARGS, RESULT, async () => {
      throw new Error("D1 unreachable");
    });
    expect(v.status).toBe("EFFECT_VERIFIER_FAILED");
    expect(v.detail).toContain("D1 unreachable");
  });

  it("does not report a failed reader as a mismatch", async () => {
    const v = await verifyGraphWrite("kg_assert_fact", ARGS, RESULT, async () => {
      throw new Error("timeout");
    });
    expect(v.status).not.toBe("EFFECT_MISMATCH");
  });
});

describe("retraction, where the declared effect is absence", () => {
  const RETRACT_ARGS = { id: "fact-9" };

  it("is VERIFIED when the approved fact is gone", async () => {
    const v = await verifyGraphWrite("kg_retract_fact", RETRACT_ARGS,
      { retracted: { id: "fact-9" } }, reads(null));
    expect(v.status).toBe("EFFECT_VERIFIED");
    expect(v.reason_code).toBe("fact_absent");
  });

  it("is MISMATCH when the fact is still there", async () => {
    const v = await verifyGraphWrite("kg_retract_fact", RETRACT_ARGS,
      { retracted: { id: "fact-9" } }, reads(ROW));
    expect(v.status).toBe("EFFECT_MISMATCH");
    expect(v.reason_code).toBe("fact_still_present");
  });

  it("checks the approved id, not the one the tool reports", async () => {
    // The tool claims it retracted fact-1; the approval was for fact-9.
    const seen: string[] = [];
    const v = await verifyGraphWrite("kg_retract_fact", RETRACT_ARGS,
      { retracted: { id: "fact-1" } },
      async (id) => { seen.push(id); return null; });
    expect(seen).toEqual(["fact-9"]);
    expect(v.status).toBe("EFFECT_VERIFIED");
  });
});

describe("what has no postcondition", () => {
  it("reports UNSUPPORTED for a read rather than a vacuous success", async () => {
    const v = await verifyGraphWrite("kg_query_facts", {}, {}, reads(ROW));
    expect(v.status).toBe("EFFECT_UNSUPPORTED");
  });

  it("reports UNSUPPORTED when the result carries no id to locate", async () => {
    const v = await verifyGraphWrite("kg_assert_fact", ARGS, { subject: "x" },
                                     reads(ROW));
    expect(v.status).toBe("EFFECT_UNSUPPORTED");
  });
});

// ── the receipt REMORA records ─────────────────────────────────────────────

const HASH = "a".repeat(64);
const BINDING: EffectBinding = {
  proposal_id: "prop-1",
  tool_call_hash: HASH,
  grant_jti: "jti-1",
  execution_id: "exec-1",
  execution_context_hash: "",
};
const VERIFIER = { identity: "verifier:kg-reader", version: "mcp-gateway/0.10.0" };
const VERIFIED: Verification = {
  status: "EFFECT_VERIFIED", reason_code: "delta_matches",
  expected_sha256: "b".repeat(64), observed_sha256: "b".repeat(64), detail: "",
};

/** Validate a body against one OpenAPI object schema: required fields,
 *  no unknown fields, string bounds, patterns and enums. */
function validateAgainst(schemaName: string, body: Record<string, unknown>): string[] {
  const doc = JSON.parse(readFileSync(
    join(__dirname, "..", "..", "..", "schemas", "openapi.json"), "utf8"));
  const schemas = doc.components.schemas;
  const schema = schemas[schemaName];
  const problems: string[] = [];
  for (const name of schema.required ?? []) {
    if (!(name in body)) problems.push(`missing ${name}`);
  }
  for (const [name, value] of Object.entries(body)) {
    let prop = schema.properties[name];
    if (!prop) { problems.push(`unknown ${name}`); continue; }
    if (prop.$ref) prop = schemas[prop.$ref.split("/").pop()];
    if (prop.type === "string" && typeof value !== "string") {
      problems.push(`${name} not a string`);
      continue;
    }
    if (typeof value === "string") {
      if (prop.minLength !== undefined && value.length < prop.minLength)
        problems.push(`${name} shorter than ${prop.minLength}`);
      if (prop.maxLength !== undefined && value.length > prop.maxLength)
        problems.push(`${name} longer than ${prop.maxLength}`);
      if (prop.pattern && !new RegExp(prop.pattern).test(value))
        problems.push(`${name} does not match ${prop.pattern}`);
      if (prop.enum && !prop.enum.includes(value))
        problems.push(`${name} not in enum`);
    }
  }
  return problems;
}

describe("the receipt matches what record_effect accepts", () => {
  const receipt = buildEffectReceipt("kg_assert_fact", VERIFIED, BINDING,
    VERIFIER, "2026-10-18T20:00:00.000Z");

  it("validates against the committed OpenAPI EffectVerificationRequest", () => {
    expect(validateAgainst("EffectVerificationRequest",
                           receipt as unknown as Record<string, unknown>))
      .toEqual([]);
  });

  it("carries every binding field a settled verdict needs", () => {
    expect(receipt.tool_call_hash).toBe(HASH);
    expect(receipt.grant_jti).toBe("jti-1");
    expect(receipt.execution_id).toBe("exec-1");
    expect(receipt.verified_at).toBe("2026-10-18T20:00:00.000Z");
    expect(receipt.verifier_identity).toBe("verifier:kg-reader");
    expect(receipt.verifier_version).toBe("mcp-gateway/0.10.0");
  });

  it("omits an empty context hash rather than sending one", () => {
    expect("execution_context_hash" in receipt).toBe(false);
    const bound = buildEffectReceipt("kg_assert_fact", VERIFIED,
      { ...BINDING, execution_context_hash: "c".repeat(64) },
      VERIFIER, "2026-10-18T20:00:00.000Z");
    expect(bound.execution_context_hash).toBe("c".repeat(64));
  });
});

describe("filing a receipt reports what REMORA decided", () => {
  const receipt = buildEffectReceipt("kg_assert_fact", VERIFIED, BINDING,
    VERIFIER, "2026-10-18T20:00:00.000Z");

  it("posts to the proposal, not to the review item", async () => {
    const paths: string[] = [];
    await fileEffectReceipt(async (path) => {
      paths.push(path);
      return { status: 200, body: { status: "EFFECT_VERIFIED" } };
    }, "prop-1", receipt);
    expect(paths).toEqual(["/v1/execution/proposals/prop-1/effect"]);
  });

  it("returns the adjudicated status on success", async () => {
    const r = await fileEffectReceipt(async () =>
      ({ status: 200, body: { status: "EFFECT_UNOBSERVABLE" } }), "prop-1", receipt);
    expect(r).toEqual({ recorded: true, http_status: 200,
                        status: "EFFECT_UNOBSERVABLE" });
  });

  it("reports a refusal instead of swallowing it", async () => {
    const r = await fileEffectReceipt(async () => ({
      status: 409,
      body: { detail: "effect receipt refused (tool_call_hash_mismatch): x" },
    }), "prop-1", receipt);
    expect(r.recorded).toBe(false);
    expect(r.http_status).toBe(409);
    expect(r.reason).toContain("tool_call_hash_mismatch");
  });

  it("reports a transport failure as not recorded", async () => {
    const r = await fileEffectReceipt(async () => {
      throw new Error("container gone");
    }, "prop-1", receipt);
    expect(r).toMatchObject({ recorded: false, reason: "transport_error" });
  });
});

describe("observe and record", () => {
  const read = reads(ROW);

  it("does not file anything when no verifier is configured", async () => {
    let posted = 0;
    const report = await observeAndRecord({
      tool: "kg_assert_fact", approvedArgs: ARGS, toolResult: RESULT,
      binding: BINDING, dispatchedAt: DISPATCHED_AT, read,
      post: async () => { posted++; return { status: 200, body: {} }; },
      verifier: null, now: () => new Date("2026-10-18T20:00:00.000Z"),
    });
    expect(posted).toBe(0);
    expect(report.observation.status).toBe("EFFECT_VERIFIED");
    expect(report.record).toEqual({ recorded: false,
                                    reason: "verifier_not_configured" });
  });

  it("does not file without a complete binding", async () => {
    let posted = 0;
    const report = await observeAndRecord({
      tool: "kg_assert_fact", approvedArgs: ARGS, toolResult: RESULT,
      binding: { ...BINDING, grant_jti: "" }, dispatchedAt: DISPATCHED_AT, read,
      post: async () => { posted++; return { status: 200, body: {} }; },
      verifier: VERIFIER, now: () => new Date("2026-10-18T20:00:00.000Z"),
    });
    expect(posted).toBe(0);
    expect(report.record).toEqual({ recorded: false, reason: "binding_incomplete" });
  });

  it("files an unsupported verdict nowhere", async () => {
    let posted = 0;
    const report = await observeAndRecord({
      tool: "kg_query_facts", approvedArgs: {}, toolResult: {},
      binding: BINDING, dispatchedAt: DISPATCHED_AT, read,
      post: async () => { posted++; return { status: 200, body: {} }; },
      verifier: VERIFIER, now: () => new Date(),
    });
    expect(posted).toBe(0);
    expect(report.record).toEqual({ recorded: false, reason: "nothing_to_attest" });
  });

  it("files a bound receipt and returns REMORA's verdict", async () => {
    const sent: Record<string, unknown>[] = [];
    const report = await observeAndRecord({
      tool: "kg_assert_fact", approvedArgs: ARGS, toolResult: RESULT,
      binding: BINDING, dispatchedAt: DISPATCHED_AT, read,
      post: async (_p, body) => {
        sent.push(body as Record<string, unknown>);
        return { status: 200, body: { status: "EFFECT_VERIFIED" } };
      },
      verifier: VERIFIER, now: () => new Date("2026-10-18T20:00:00.000Z"),
    });
    expect(sent).toHaveLength(1);
    expect(sent[0].proposal_id).toBeUndefined();
    expect(sent[0].tool_call_hash).toBe(HASH);
    expect(report.record).toEqual({ recorded: true, http_status: 200,
                                    status: "EFFECT_VERIFIED" });
  });
});

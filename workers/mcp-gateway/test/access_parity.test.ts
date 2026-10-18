/**
 * agent-control and mcp-gateway decide every Access token the same way.
 *
 * agent-control kept its own Access verifier. It checked audience and expiry
 * but never the issuer, so a token from another Access team that reused the
 * AUD tag was accepted as a reviewer identity, and a team domain configured
 * with a scheme or a trailing slash broke key lookup (RMR-AUD-010). Both
 * Workers now import workers/shared/access_jwt.ts; this test runs the same
 * tokens through both entry points so they cannot drift apart again.
 */
import { describe, expect, it } from "vitest";

import { cloudflareAccessVerifier } from "../../agent-control/src/auth";
import { admitMcp } from "../src/admission";

const TEAM = "remora.cloudflareaccess.com";
const AUD = "aud-tag-123";

function b64url(data: ArrayBuffer | Uint8Array | string): string {
  const bytes =
    typeof data === "string"
      ? new TextEncoder().encode(data)
      : new Uint8Array(data instanceof Uint8Array ? data : new Uint8Array(data));
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function keypair(kid: string) {
  const pair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true, ["sign", "verify"],
  )) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
  return { privateKey: pair.privateKey, jwk: { ...jwk, kid, alg: "RS256" } };
}

async function sign(privateKey: CryptoKey, claims: Record<string, unknown>) {
  const input = `${b64url(JSON.stringify({ alg: "RS256", kid: "k1" }))}.` +
    b64url(JSON.stringify(claims));
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey,
                                       new TextEncoder().encode(input));
  return `${input}.${b64url(sig)}`;
}

async function decide(token: string, teamDomain: string) {
  const { jwk } = await keys;
  const now = Math.floor(Date.now() / 1000);
  const deps = {
    fetchJwks: async () => ({ keys: [jwk] }),
    now: () => now,
    cache: new Map(),
  };
  const request = () => new Request("https://x/", {
    headers: { "Cf-Access-Jwt-Assertion": token } });
  const gateway = await admitMcp(request(),
    { ACCESS_TEAM_DOMAIN: teamDomain, ACCESS_AUD: AUD }, deps);
  const control = await cloudflareAccessVerifier(
    { ACCESS_TEAM_DOMAIN: teamDomain, ACCESS_AUD: AUD,
      REVIEWER_EMAILS: "reviewer@example.com" },
    { ...deps, cache: new Map() },
  ).verify(request());
  return { gateway: gateway.ok, control: control !== null, identity: control };
}

const keys = keypair("k1");

function claims(overrides: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  return { aud: [AUD], iss: `https://${TEAM}`, exp: now + 300, nbf: now - 10,
           sub: "u-1", email: "reviewer@example.com", ...overrides };
}

describe("Access verification parity", () => {
  it("both accept a token from the configured team", async () => {
    const token = await sign((await keys).privateKey, claims());
    const d = await decide(token, TEAM);
    expect(d).toMatchObject({ gateway: true, control: true });
    expect(d.identity?.principalId).toBe("reviewer@example.com");
  });

  it("both refuse a token issued by another Access team", async () => {
    const token = await sign((await keys).privateKey,
                             claims({ iss: "https://evil.cloudflareaccess.com" }));
    expect(await decide(token, TEAM)).toMatchObject({ gateway: false, control: false });
  });

  it("both refuse a token with no issuer", async () => {
    const token = await sign((await keys).privateKey, claims({ iss: undefined }));
    expect(await decide(token, TEAM)).toMatchObject({ gateway: false, control: false });
  });

  for (const configured of [`https://${TEAM}`, `${TEAM}/`, `https://${TEAM}//`]) {
    it(`both normalise a team domain written as ${configured}`, async () => {
      const token = await sign((await keys).privateKey, claims());
      expect(await decide(token, configured))
        .toMatchObject({ gateway: true, control: true });
    });
  }

  it("both refuse another audience", async () => {
    const token = await sign((await keys).privateKey, claims({ aud: ["other"] }));
    expect(await decide(token, TEAM)).toMatchObject({ gateway: false, control: false });
  });

  it("both refuse an expired token", async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = await sign((await keys).privateKey,
                             claims({ exp: now - 3600 }));
    expect(await decide(token, TEAM)).toMatchObject({ gateway: false, control: false });
  });

  it("agent-control still requires an email for a human identity", async () => {
    const token = await sign((await keys).privateKey, claims({ email: undefined }));
    const d = await decide(token, TEAM);
    expect(d.gateway).toBe(true);
    expect(d.control).toBe(false);
  });
});

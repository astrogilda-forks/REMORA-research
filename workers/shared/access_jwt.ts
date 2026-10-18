/**
 * Cloudflare Access application token verification, shared by every Worker
 * that admits requests on an Access assertion.
 *
 * One implementation, because two drifted: workers/agent-control kept its own
 * copy, which checked audience and expiry but never the issuer, and did not
 * normalise the team domain (RMR-AUD-010). A token minted for another Access
 * team with the same AUD tag passed it. The two Workers now import this file.
 *
 * Pure apart from the injected key fetch and clock, so it is tested without a
 * network (workers/mcp-gateway/test/admission.test.ts and
 * workers/mcp-gateway/test/access_parity.test.ts).
 */

export interface AccessConfig {
  /** Team domain, e.g. "remora.cloudflareaccess.com". Scheme optional. */
  teamDomain: string;
  /** The Access application's AUD tag. */
  aud: string;
  fetchJwks: (url: string) => Promise<{ keys?: JsonWebKey[] }>;
  /** Seconds since the epoch. */
  now: () => number;
  /** Key-set cache. Defaults to one shared by the Worker isolate. */
  cache?: JwksCache;
}

export type JwksCache = Map<string, { keys: JsonWebKey[]; fetchedAt: number }>;

export type AccessVerdict =
  /** `claims` are the verified token's claims, for a caller that needs one
   *  beyond the subject (agent-control reads `email`). */
  | { ok: true; subject: string; claims: Record<string, unknown> }
  | { ok: false; reason: string };

/** Clock skew tolerated on exp and nbf, in seconds. */
const SKEW_SECONDS = 60;
/** How long a fetched key set is reused before it is fetched again. */
const JWKS_TTL_SECONDS = 600;

const sharedJwksCache: JwksCache = new Map();

export function normaliseTeam(teamDomain: string): string {
  let team = teamDomain.trim();
  for (const scheme of ["https://", "http://"]) {
    if (team.startsWith(scheme)) team = team.slice(scheme.length);
  }
  // A loop, not /\/+$/: CodeQL flags the anchored quantifier as polynomial on
  // long runs of "/", and this value is configuration read on every request.
  let end = team.length;
  while (end > 0 && team[end - 1] === "/") end--;
  return team.slice(0, end);
}

function b64urlDecode(part: string): Uint8Array<ArrayBuffer> {
  const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const raw = atob(padded);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function decodeJson(part: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(b64urlDecode(part)));
    return value && typeof value === "object" ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

async function keysFor(
  config: AccessConfig,
  team: string,
  refresh: boolean,
): Promise<JsonWebKey[]> {
  const cache = config.cache ?? sharedJwksCache;
  const cached = cache.get(team);
  if (!refresh && cached && config.now() - cached.fetchedAt < JWKS_TTL_SECONDS) {
    return cached.keys;
  }
  const body = await config.fetchJwks(`https://${team}/cdn-cgi/access/certs`);
  const keys = Array.isArray(body?.keys) ? body.keys : [];
  cache.set(team, { keys, fetchedAt: config.now() });
  return keys;
}

/** Verify a Cloudflare Access application token (RS256 JWT). */
export async function verifyAccessJwt(
  token: string,
  config: AccessConfig,
): Promise<AccessVerdict> {
  const parts = token.split(".");
  if (parts.length !== 3) return { ok: false, reason: "malformed" };
  const header = decodeJson(parts[0]);
  const claims = decodeJson(parts[1]);
  if (!header || !claims) return { ok: false, reason: "malformed" };
  // Pinned, never read from the token: alg "none" and HS256-with-the-public-
  // key are the classic ways a verifier is talked out of verifying.
  if (header.alg !== "RS256") return { ok: false, reason: "unsupported_alg" };
  const kid = typeof header.kid === "string" ? header.kid : "";

  const team = normaliseTeam(config.teamDomain);
  let jwk: JsonWebKey & { kid?: string } | undefined;
  try {
    const find = (keys: JsonWebKey[]) =>
      keys.find((k) => (k as { kid?: string }).kid === kid);
    jwk = find(await keysFor(config, team, false));
    // One refresh for a key id we have not seen: Access rotates its keys, and
    // a stale cache must not turn a rotation into an outage.
    if (!jwk) jwk = find(await keysFor(config, team, true));
  } catch {
    return { ok: false, reason: "jwks_unavailable" };
  }
  if (!jwk) return { ok: false, reason: "unknown_key" };

  let valid = false;
  try {
    const key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    valid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      b64urlDecode(parts[2]),
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    );
  } catch {
    valid = false;
  }
  if (!valid) return { ok: false, reason: "bad_signature" };

  const aud = claims.aud;
  const audiences = Array.isArray(aud) ? aud : [aud];
  if (!audiences.includes(config.aud)) return { ok: false, reason: "audience_mismatch" };
  if (claims.iss !== `https://${team}`) return { ok: false, reason: "issuer_mismatch" };
  const now = config.now();
  if (typeof claims.exp !== "number" || claims.exp + SKEW_SECONDS < now) {
    return { ok: false, reason: "expired" };
  }
  if (typeof claims.nbf === "number" && claims.nbf - SKEW_SECONDS > now) {
    return { ok: false, reason: "not_yet_valid" };
  }
  // A service token carries its client id as common_name and an empty sub; a
  // person carries sub (and email). Either identifies the caller for audit.
  const subject =
    (typeof claims.sub === "string" && claims.sub) ||
    (typeof claims.common_name === "string" && claims.common_name) ||
    "unknown";
  return { ok: true, subject, claims };
}

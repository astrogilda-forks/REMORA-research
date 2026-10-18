/**
 * Who may reach /mcp, and whether this deployment may serve production.
 *
 * /mcp calls REMORA with the Worker's own operator token, so anyone who reaches
 * it acts with that token's authority to propose. Until this module the only
 * thing in front of it was a Cloudflare Access policy configured outside the
 * repository: correct when present, invisible when a route or policy drifted.
 * The Worker now verifies the Access assertion itself (defence in depth, not a
 * replacement for the policy), and refuses when it is not told what to verify
 * against rather than falling open.
 *
 * The production profile turns three deployment facts that used to be
 * optional into prerequisites: a durable tenant audit chain, the authority /
 * executor custody split, and in-Worker Access verification.
 */

import { verifyAccessJwt, type AccessConfig } from "../../shared/access_jwt";

// The verifier itself lives in workers/shared so agent-control uses the
// same code; re-exported here so existing importers are unchanged.
export {
  normaliseTeam,
  verifyAccessJwt,
  type AccessConfig,
  type AccessVerdict,
  type JwksCache,
} from "../../shared/access_jwt";

export type Admission =
  | { ok: true; subject: string }
  | { ok: false; status: number; reason: string };

export interface AdmissionEnv {
  REMORA_API_URL?: string;
  REMORA_DEPLOYMENT_PROFILE?: string;
  ACCESS_TEAM_DOMAIN?: string;
  ACCESS_AUD?: string;
}

/** Decide whether this request may reach /mcp. */
export async function admitMcp(
  request: Request,
  env: AdmissionEnv,
  deps: Partial<Pick<AccessConfig, "fetchJwks" | "now" | "cache">> = {},
): Promise<Admission> {
  // The direct transport exists only in the development config (wrangler.dev
  // .toml); there is no edge in front of a local run to verify against. The
  // profile must say so: REMORA_API_URL alone used to skip Access in any
  // deployment that happened to set it.
  if (env.REMORA_API_URL) {
    return String(env.REMORA_DEPLOYMENT_PROFILE ?? "").trim() === "development"
      ? { ok: true, subject: "development" }
      : { ok: false, status: 503, reason: "direct_transport_outside_development" };
  }
  if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) {
    return { ok: false, status: 503, reason: "access_not_configured" };
  }
  const token = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!token) return { ok: false, status: 401, reason: "access_assertion_missing" };
  const verdict = await verifyAccessJwt(token, {
    teamDomain: env.ACCESS_TEAM_DOMAIN,
    aud: env.ACCESS_AUD,
    fetchJwks:
      deps.fetchJwks ??
      (async (url) => {
        const response = await fetch(url);
        if (!response.ok) throw new Error(`jwks ${response.status}`);
        return (await response.json()) as { keys?: JsonWebKey[] };
      }),
    now: deps.now ?? (() => Math.floor(Date.now() / 1000)),
    cache: deps.cache,
  });
  return verdict.ok
    ? { ok: true, subject: verdict.subject }
    : { ok: false, status: 403, reason: verdict.reason };
}

export const DEPLOYMENT_PROFILES = ["development", "staging", "production"] as const;

export interface ReadinessEnv extends AdmissionEnv {
  REMORA_DEPLOYMENT_PROFILE?: string;
  REMORA_PG_DSN?: string;
  /** Present or not; listed so a test can show it does not satisfy the
   *  durable-chain prerequisite. */
  STATE_DB?: unknown;
  EXECUTION?: unknown;
  REMORA_LEASE_ED25519_PRIVATE?: string;
  REMORA_LEASE_ED25519_PUBLIC?: string;
}

/**
 * What this deployment lacks for its declared profile. Empty means ready.
 *
 * Production requires REMORA_PG_DSN specifically. The D1 binding makes the
 * grant and nonce ledgers durable, but the tenant audit chain has no D1
 * adapter (servers/execution_api.py::_effect_audit_is_durable), and
 * REMORA_CHAIN_DB is a path on the container's disk, which Cloudflare discards
 * at every restart.
 */
export function productionReadiness(env: ReadinessEnv): {
  profile: string;
  problems: string[];
} {
  const profile = String(env.REMORA_DEPLOYMENT_PROFILE ?? "").trim();
  if (!profile) return { profile: "unset", problems: ["deployment_profile_missing"] };
  if (!(DEPLOYMENT_PROFILES as readonly string[]).includes(profile)) {
    return { profile, problems: ["deployment_profile_unknown"] };
  }
  const problems: string[] = [];
  // The direct transport skips Access verification, so it is a problem in
  // every profile but development.
  if (env.REMORA_API_URL && profile !== "development") {
    problems.push("direct_transport_outside_development");
  }
  if (profile !== "production") return { profile, problems };
  if (!env.REMORA_PG_DSN) problems.push("durable_audit_chain_missing");
  if (!env.EXECUTION || !env.REMORA_LEASE_ED25519_PRIVATE || !env.REMORA_LEASE_ED25519_PUBLIC) {
    problems.push("custody_split_missing");
  }
  if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) problems.push("access_not_configured");
  return { profile, problems };
}

/**
 * Authentication for the agent-control Worker.
 *
 * Two principal classes, two credential paths — deliberately disjoint so the
 * same credential can never act as both proposer and approver:
 *
 *   workload (AI/service):  shared bearer CONTROL_SECRET (existing contract).
 *   human (reviewer):       Cloudflare Access OIDC identity, proven by a
 *                           verified `Cf-Access-Jwt-Assertion` JWT (RS256,
 *                           checked against the team's JWKS, iss + aud + exp +
 *                           nbf, by workers/shared/access_jwt.ts).
 *
 * The human path is pluggable via HumanIdentityVerifier so tests (and
 * non-Access deployments) inject their own verifier instead of depending on a
 * live Cloudflare Access account. Everything fails closed: missing config,
 * missing header, bad signature, wrong audience — all yield "no identity",
 * never a downgraded-but-accepted one.
 */

import { type AccessConfig, verifyAccessJwt } from "../../shared/access_jwt";
import { type AuthContext, ROLE_REVIEWER } from "./principal";

export interface HumanIdentity {
  /** Verified stable identity (email claim from the Access JWT). */
  principalId: string;
  roles: string[];
  authMethod: string;
}

export interface HumanIdentityVerifier {
  verify(request: Request): Promise<HumanIdentity | null>;
}

export interface AuthEnvConfig {
  CONTROL_SECRET?: string;
  TENANT_ID?: string;
  /** Cloudflare Access team domain, e.g. "myteam.cloudflareaccess.com". */
  ACCESS_TEAM_DOMAIN?: string;
  /** Expected `aud` of the Access application protecting the review surface. */
  ACCESS_AUD?: string;
  /** Comma-separated allowlist of reviewer identities (emails). */
  REVIEWER_EMAILS?: string;
}

/**
 * Resolve the authenticated context for a request.
 *
 * Order matters for safety: a request presenting the workload bearer IS the
 * workload, even if it also carries Access headers — the shared credential
 * can never be upgraded to a human identity by adding headers to the call.
 */
export async function authenticate(
  request: Request,
  env: AuthEnvConfig,
  humanVerifier: HumanIdentityVerifier,
): Promise<AuthContext | null> {
  const tenantId = env.TENANT_ID ?? "default";
  const auth = request.headers.get("Authorization") ?? "";

  if (auth.startsWith("Bearer ")) {
    if (!env.CONTROL_SECRET) return null; // fail closed on misconfiguration
    if (auth === `Bearer ${env.CONTROL_SECRET}`) {
      return {
        tenantId,
        principalId: "control_secret_bearer",
        principalType: "workload",
        roles: ["workload"],
        authMethod: "shared_bearer",
      };
    }
    return null;
  }

  const human = await humanVerifier.verify(request);
  if (human) {
    return {
      tenantId,
      principalId: human.principalId,
      principalType: "human",
      roles: human.roles,
      authMethod: human.authMethod,
    };
  }
  return null;
}

// ── Cloudflare Access verifier (production adapter) ───────────────────────────

/** Injection points for tests. Production leaves both unset: the key set is
 *  fetched from the team's certs endpoint and the clock is the Worker's. */
export interface AccessVerifierDeps {
  fetchJwks?: AccessConfig["fetchJwks"];
  now?: AccessConfig["now"];
  cache?: AccessConfig["cache"];
}

/**
 * Production human-identity adapter backed by Cloudflare Access.
 *
 * The token is verified by workers/shared/access_jwt.ts, the same code the MCP
 * gateway admits requests with: signature against the team's JWKS, issuer,
 * audience, exp and nbf, with the team domain normalised. This Worker kept its
 * own copy until RMR-AUD-010, and that copy never checked the issuer, so a
 * token from another Access team that reused the AUD tag became a reviewer.
 *
 * Roles: an identity on the REVIEWER_EMAILS allowlist gets ROLE_REVIEWER.
 * Access group/MFA policy is enforced by the Access application itself; the
 * allowlist is the worker-side authorization layer on top of authentication.
 */
export function cloudflareAccessVerifier(
  env: AuthEnvConfig,
  deps: AccessVerifierDeps = {},
): HumanIdentityVerifier {
  return {
    async verify(request: Request): Promise<HumanIdentity | null> {
      if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return null;
      const token = request.headers.get("Cf-Access-Jwt-Assertion");
      if (!token) return null;
      let verdict;
      try {
        verdict = await verifyAccessJwt(token, {
          teamDomain: env.ACCESS_TEAM_DOMAIN,
          aud: env.ACCESS_AUD,
          fetchJwks: deps.fetchJwks ?? (async (url) => {
            const response = await fetch(url);
            if (!response.ok) throw new Error(`JWKS fetch failed: ${response.status}`);
            return (await response.json()) as { keys?: JsonWebKey[] };
          }),
          now: deps.now ?? (() => Math.floor(Date.now() / 1000)),
          cache: deps.cache,
        });
      } catch {
        return null; // fail closed on JWKS/network errors
      }
      if (!verdict.ok) return null;
      const email = verdict.claims.email;
      // A reviewer is a person, and the allowlist names people by email; a
      // service token carries none and is not a human identity here.
      if (typeof email !== "string" || !email) return null;

      const reviewers = (env.REVIEWER_EMAILS ?? "")
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
      const principalId = email.toLowerCase();
      const roles = reviewers.includes(principalId) ? [ROLE_REVIEWER] : [];
      return { principalId, roles, authMethod: "cloudflare_access_jwt" };
    },
  };
}

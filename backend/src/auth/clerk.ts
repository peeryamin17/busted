import { createPublicKey, verify as cryptoVerify, type KeyObject } from 'node:crypto';

/**
 * Clerk session-token verification.
 *
 * Clerk signs session JWTs with the app's private key; anyone can verify
 * them against the app's public JWKS at
 *   {CLERK_FRONTEND_API}/.well-known/jwks.json
 * — no Clerk secret key is needed server-side for verification, which is
 * why the backend only ever holds the (public) frontend API URL.
 *
 * Verified by hand on node:crypto (RS256 + issuer + expiry) to avoid a
 * dependency; the verifier is a factory so tests can point it at a local
 * JWKS server with a throwaway keypair.
 */

export interface ClerkClaims {
  clerkUserId: string;
  sessionId?: string;
}

export interface ClerkVerifier {
  verify(token: string): Promise<ClerkClaims | null>;
}

interface Jwk {
  kty: string;
  kid?: string;
  n?: string;
  e?: string;
  alg?: string;
  use?: string;
}

const b64urlJson = (part: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(part, 'base64url').toString('utf8')) as Record<string, unknown>;

export function createClerkVerifier(opts: {
  frontendApi: string;
  fetchImpl?: typeof fetch;
  cacheMs?: number;
}): ClerkVerifier {
  const issuer = opts.frontendApi.replace(/\/$/, '');
  const jwksUrl = `${issuer}/.well-known/jwks.json`;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const cacheMs = opts.cacheMs ?? 10 * 60_000;
  let cache: { keys: Map<string, KeyObject>; at: number } | null = null;

  async function getKey(kid: string): Promise<KeyObject | null> {
    if (!cache || Date.now() - cache.at > cacheMs) {
      try {
        const res = await fetchImpl(jwksUrl);
        if (!res.ok) return cache?.keys.get(kid) ?? null;
        const body = (await res.json()) as { keys?: Jwk[] };
        const keys = new Map<string, KeyObject>();
        for (const jwk of body.keys ?? []) {
          if (jwk.kty !== 'RSA' || !jwk.kid || !jwk.n || !jwk.e) continue;
          try {
            keys.set(jwk.kid, createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' }));
          } catch {
            /* skip malformed key */
          }
        }
        cache = { keys, at: Date.now() };
      } catch {
        return cache?.keys.get(kid) ?? null;
      }
    }
    return cache.keys.get(kid) ?? null;
  }

  return {
    async verify(token: string): Promise<ClerkClaims | null> {
      try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        const header = b64urlJson(parts[0]);
        const payload = b64urlJson(parts[1]);
        if (header['alg'] !== 'RS256' || typeof header['kid'] !== 'string') return null;
        if (payload['iss'] !== issuer) return null;
        if (typeof payload['exp'] !== 'number' || payload['exp'] * 1000 < Date.now()) return null;
        if (typeof payload['sub'] !== 'string' || !payload['sub']) return null;
        const key = await getKey(header['kid']);
        if (!key) return null;
        const ok = cryptoVerify(
          'RSA-SHA256',
          Buffer.from(`${parts[0]}.${parts[1]}`),
          key,
          Buffer.from(parts[2], 'base64url'),
        );
        if (!ok) return null;
        return {
          clerkUserId: payload['sub'],
          sessionId: typeof payload['sid'] === 'string' ? payload['sid'] : undefined,
        };
      } catch {
        return null;
      }
    },
  };
}

let defaultVerifier: ClerkVerifier | null | undefined;

/** Singleton verifier from CLERK_FRONTEND_API; null when Clerk is not configured. */
export function clerkVerifierFromEnv(): ClerkVerifier | null {
  if (defaultVerifier !== undefined) return defaultVerifier;
  const api = process.env['CLERK_FRONTEND_API'];
  defaultVerifier = api ? createClerkVerifier({ frontendApi: api }) : null;
  return defaultVerifier;
}

export async function verifyClerkToken(token: string): Promise<ClerkClaims | null> {
  const v = clerkVerifierFromEnv();
  return v ? v.verify(token) : null;
}

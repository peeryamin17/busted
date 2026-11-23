import type { FastifyReply, FastifyRequest } from 'fastify';
import { createHash } from 'node:crypto';
import type { Database } from '../db/db.js';
import { hashApiKey, verifySession } from '../auth/auth.js';
import { SESSION_COOKIE, SESSION_IDLE_MS, hashSessionToken, isAdminEmail, parseCookies } from '../auth/session.js';
import { PLAN_QUOTAS } from '../auth/usage.js';
import type { PlanTier } from '../types.js';
import { recordSecurityEvent } from '../detection/events.js';
import {
  apiKeyAuthFailures,
  apiKeyFingerprint,
  clientIp,
  type FailedAuthRateLimiter,
} from '../guardrails/ratelimit.js';

export interface AuthenticatedUser {
  id: string;
  email: string;
  plan: PlanTier;
  viaApiKey: boolean;
}

declare module 'fastify' {
  interface FastifyRequest {
    user?: AuthenticatedUser;
  }
}

/**
 * Authentication, three ways:
 *  - `x-api-key: bs_…` — the extension's API keys (plan §6.1: Pro+ feature).
 *  - `x-gemini-api-key` / `x-qwen-api-key` — a pasted BYOK provider key
 *    signs in as a BYOK user, no bs_ key or session needed.
 *  - `bs_session` cookie — the website's server-side session, created by
 *    the Google sign-in flow (src/routes/googleAuth.ts).
 *  - `Authorization: Bearer <jwt>` — the email/password accounts' session
 *    token (register/login in src/routes/auth.ts).
 */
export interface AuthenticateOptions {
  /**
   * Failed-`bs_`-key limiter. Defaults to the shared module-level instance
   * (10 failures / 60 s per IP and per key fingerprint). Tests may inject a
   * short-window instance; production routes share one so an attacker cannot
   * get a fresh budget per route (every route calls buildAuthenticate).
   */
  failedAuthLimiter?: FailedAuthRateLimiter;
}

export function buildAuthenticate(db: Database, opts: AuthenticateOptions = {}) {
  const failedAuthLimiter = opts.failedAuthLimiter ?? apiKeyAuthFailures;
  return async function authenticate(request: FastifyRequest, reply?: FastifyReply): Promise<void> {
    const authHeader = request.headers.authorization;
    let apiKey = request.headers['x-api-key'];
    if (!apiKey && authHeader?.startsWith('Bearer bs_')) {
      apiKey = authHeader.slice(7);
    }
    const geminiKey = request.headers['x-gemini-api-key'];
    const qwenKey = request.headers['x-qwen-api-key'];
    const byokKey =
      typeof geminiKey === 'string' && geminiKey.trim().length >= 16
        ? geminiKey.trim()
        : typeof qwenKey === 'string' && qwenKey.trim().length >= 16
          ? qwenKey.trim()
          : null;

    // Direct BYOK from the extension popup: a pasted provider key is the
    // credential. Either provider works, Gemini or Qwen; the key holder
    // pays for their own model use.
    if (byokKey) {
      const trimmed = byokKey;
      const idHash = createHash('sha256').update(trimmed).digest('hex').slice(0, 16);
      const byokEmail = `byok-${idHash}@bugseek.local`;
      let user = await db.getUserByEmail(byokEmail);
      if (!user) {
        user = await db.createUser(byokEmail, '');
        if (typeof db.setUserPlan === 'function') {
          await db.setUserPlan(user.id, 'enterprise').catch(() => undefined);
        }
      }
      request.user = { id: user.id, email: user.email, plan: 'enterprise', viaApiKey: true };
      return;
    }

    // `bs_` API-key auth, with a login-equivalent brake on FAILED attempts
    // only (10 failures / 60 s per client IP and per key fingerprint).
    // Successes are never throttled and clear the buckets, so the
    // extension's legitimate polling is untouched. The Google OAuth /
    // session-cookie and Bearer-JWT paths below are NOT limited here:
    // Google enforces its own sign-in limits, and sessions are not
    // guessable credentials. A 403 for a valid key on a plan without API
    // access is an authorisation failure, not an authentication failure,
    // so it does not count either.
    if (typeof apiKey === 'string' && apiKey.startsWith('bs_')) {
      const ipBucket = `ip:${clientIp(request)}`;
      const fpBucket = `fp:${apiKeyFingerprint(apiKey)}`;
      const limitedBucket = failedAuthLimiter.isLimited(ipBucket)
        ? ipBucket
        : failedAuthLimiter.isLimited(fpBucket)
          ? fpBucket
          : null;
      if (limitedBucket) {
        const retryAfter = failedAuthLimiter.retryAfterSeconds(limitedBucket);
        if (reply) reply.header('Retry-After', String(retryAfter));
        throw Object.assign(
          new Error(`Too many failed API-key attempts — try again in ${retryAfter}s`),
          { statusCode: 429, retryAfterSeconds: retryAfter },
        );
      }
      // A failed attempt counts against both buckets before we answer.
      const apiKeyFailure = (message: string): Error & { statusCode: number } => {
        failedAuthLimiter.recordFailure(ipBucket);
        failedAuthLimiter.recordFailure(fpBucket);
        return Object.assign(new Error(message), { statusCode: 401 });
      };
      const rec = await db.getApiKeyByHash(hashApiKey(apiKey));
      if (!rec || rec.revokedAt) {
        throw apiKeyFailure('Invalid or revoked API key');
      }
      const user = await db.getUserById(rec.userId);
      if (!user) throw apiKeyFailure('Invalid API key');
      const isOp = isAdminEmail(user.email);
      const plan: PlanTier = isOp ? 'enterprise' : user.plan;
      if (isOp && user.plan !== 'enterprise' && typeof db.setUserPlan === 'function') {
        await db.setUserPlan(user.id, 'enterprise').catch(() => undefined);
      }
      if (!isOp && !PLAN_QUOTAS[user.plan].apiAccess) {
        throw Object.assign(new Error('API access requires the Pro plan or higher'), {
          statusCode: 403,
        });
      }
      await db.touchApiKey(rec.id).catch(() => undefined);
      failedAuthLimiter.recordSuccess(ipBucket);
      failedAuthLimiter.recordSuccess(fpBucket);
      request.user = { id: user.id, email: user.email, plan, viaApiKey: true };
      // Runtime detection layer (Thread 5, DEFENSIVE — dogfooding): record
      // the API-key use so the anomaly rules can spot a key used from a new
      // IP, a volume spike, or endpoints the key never used before. Prefix
      // only, never the key; path only, never the query string. Best-effort:
      // detection must never break authentication.
      try {
        recordSecurityEvent({
          userId: user.id,
          type: 'api_key_use',
          at: new Date().toISOString(),
          ip: request.ip,
          apiKeyPrefix: apiKey.slice(0, 10),
          endpoint: (request.url ?? '').split('?')[0],
          userAgent: request.headers['user-agent'],
        });
      } catch {
        /* detection intake must not fail auth */
      }
      return;
    }

    const sessionToken = parseCookies(request.headers.cookie)[SESSION_COOKIE];
    if (sessionToken) {
      const tokenHash = hashSessionToken(sessionToken);
      const found = await db.getSessionWithUser(tokenHash);
      const session = found?.session ?? null;
      const user = found?.user ?? null;
      if (!session || !user) {
        throw Object.assign(new Error('Invalid or expired session'), { statusCode: 401 });
      }
      const isOp = isAdminEmail(user.email);
      const plan: PlanTier = isOp ? 'enterprise' : user.plan;
      if (isOp && user.plan !== 'enterprise' && typeof db.setUserPlan === 'function') {
        await db.setUserPlan(user.id, 'enterprise').catch(() => undefined);
      }
      // Five quiet minutes and the session signs itself out; every
      // authenticated request resets the clock. The operator's
      // account (ADMIN_EMAIL) is exempt — it keeps the 30-day
      // absolute expiry only.
      if (!isOp) {
        if (Date.now() - Date.parse(session.lastSeenAt) > SESSION_IDLE_MS) {
          await db.deleteSession(tokenHash).catch(() => undefined);
          throw Object.assign(new Error('Five quiet minutes — you were signed out. Sign in again.'), {
            statusCode: 401,
          });
        }
        await db.touchSession(tokenHash).catch(() => undefined);
      }
      request.user = { id: user.id, email: user.email, plan, viaApiKey: false };
      return;
    }

    if (authHeader?.startsWith('Bearer ')) {
      const claims = verifySession(authHeader.slice(7));
      if (claims) {
        const user = await db.getUserById(claims.sub);
        if (!user) throw Object.assign(new Error('User not found'), { statusCode: 401 });
        const isOp = isAdminEmail(user.email);
        const plan: PlanTier = isOp ? 'enterprise' : user.plan;
        if (isOp && user.plan !== 'enterprise' && typeof db.setUserPlan === 'function') {
          await db.setUserPlan(user.id, 'enterprise').catch(() => undefined);
        }
        request.user = { id: user.id, email: user.email, plan, viaApiKey: false };
        return;
      }
      throw Object.assign(new Error('Invalid or expired token'), { statusCode: 401 });
    }

    throw Object.assign(new Error('Authentication required (session cookie, Bearer token or x-api-key)'), {
      statusCode: 401,
    });
  };
}

export function requireUser(request: FastifyRequest): AuthenticatedUser {
  if (!request.user) throw Object.assign(new Error('Authentication required'), { statusCode: 401 });
  return request.user;
}

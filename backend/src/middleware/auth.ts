import type { FastifyRequest } from 'fastify';
import { createHash } from 'node:crypto';
import type { Database } from '../db/db.js';
import { hashApiKey, verifySession } from '../auth/auth.js';
import { SESSION_COOKIE, SESSION_IDLE_MS, hashSessionToken, isAdminEmail, parseCookies } from '../auth/session.js';
import { PLAN_QUOTAS } from '../auth/usage.js';
import type { PlanTier } from '../types.js';

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
 *  - `bs_session` cookie — the website's server-side session, created by
 *    the Google sign-in flow (src/routes/googleAuth.ts).
 *  - `Authorization: Bearer <jwt>` — the email/password accounts' session
 *    token (register/login in src/routes/auth.ts).
 */
export function buildAuthenticate(db: Database) {
  return async function authenticate(request: FastifyRequest): Promise<void> {
    const authHeader = request.headers.authorization;
    let apiKey = request.headers['x-api-key'];
    if (!apiKey && authHeader?.startsWith('Bearer bs_')) {
      apiKey = authHeader.slice(7);
    }
    const geminiKey = request.headers['x-gemini-api-key'];

    // Direct Gemini BYOK from extension popup
    if (typeof geminiKey === 'string' && geminiKey.trim().length >= 16) {
      const trimmed = geminiKey.trim();
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

    if (typeof apiKey === 'string' && apiKey.startsWith('bs_')) {
      const rec = await db.getApiKeyByHash(hashApiKey(apiKey));
      if (!rec || rec.revokedAt) {
        throw Object.assign(new Error('Invalid or revoked API key'), { statusCode: 401 });
      }
      const user = await db.getUserById(rec.userId);
      if (!user) throw Object.assign(new Error('Invalid API key'), { statusCode: 401 });
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
      request.user = { id: user.id, email: user.email, plan, viaApiKey: true };
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

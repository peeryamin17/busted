import type { FastifyInstance } from 'fastify';
import { config } from '../config.js';
import { googleClientFromEnv, type GoogleClient } from '../auth/google.js';
import {
  SESSION_COOKIE,
  STATE_COOKIE,
  SESSION_TTL_MS,
  STATE_TTL_MS,
  clearCookie,
  createState,
  generateSessionToken,
  hashSessionToken,
  parseCookies,
  serializeCookie,
  verifyState,
} from '../auth/session.js';
import { PLAN_QUOTAS, monthStartIso } from '../auth/usage.js';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import type { RouteDeps } from './health.js';

export interface GoogleAuthOptions {
  /**
   * Override the Google client (tests inject a fake transport). Omit to
   * use the env-configured singleton; an explicit null forces the
   * not-configured 503 behaviour.
   */
  googleClient?: GoogleClient | null;
}

/**
 * "Sign in with Google" for the website — authorization-code flow with
 * OUR backend as the OAuth client:
 *
 *   GET /api/auth/google          → 302 to Google (state nonce in a
 *                                   signed, short-lived cookie)
 *   GET /api/auth/google/callback → state check → code exchange →
 *                                   profile → find-or-create user →
 *                                   server-side session → bs_session
 *                                   cookie → 302 to POST_LOGIN_REDIRECT
 *   GET /api/me                   → the signed-in user + credit balance
 *   POST /api/auth/logout         → session deleted, cookie cleared
 *
 * The Google client secret only ever leaves this server in the
 * code-exchange call. When Google is not configured (env unset), the
 * flow routes answer 503 and the rest of the app runs normally.
 */
export async function googleAuthRoutes(
  app: FastifyInstance,
  deps: RouteDeps,
  opts: GoogleAuthOptions = {},
): Promise<void> {
  const { db } = deps;
  const google = opts.googleClient !== undefined ? opts.googleClient : googleClientFromEnv();
  const secureCookies = config.isProd;
  const authenticate = buildAuthenticate(db);
  const notConfigured = { error: 'Google sign-in is not configured on this backend' };

  app.get('/api/auth/google', async (_request, reply) => {
    if (!google) return reply.status(503).send(notConfigured);
    const { state, cookieValue } = createState(config.sessionSecret);
    return reply
      .header(
        'set-cookie',
        serializeCookie(STATE_COOKIE, cookieValue, {
          maxAgeSeconds: Math.floor(STATE_TTL_MS / 1000),
          secure: secureCookies,
        }),
      )
      .redirect(google.buildAuthUrl(state));
  });

  app.get('/api/auth/google/callback', async (request, reply) => {
    if (!google) return reply.status(503).send(notConfigured);
    const query = request.query as { code?: string; state?: string };
    const stateCookie = parseCookies(request.headers.cookie)[STATE_COOKIE] ?? '';
    if (!query.code || !query.state || !verifyState(config.sessionSecret, query.state, stateCookie)) {
      return reply.status(400).send({ error: 'Invalid or expired sign-in request' });
    }

    let user;
    try {
      const { accessToken } = await google.exchangeCode(query.code);
      const profile = await google.fetchProfile(accessToken);
      user = await db.recordGoogleLogin({
        googleSub: profile.sub,
        email: profile.email,
        name: profile.name,
        avatarUrl: profile.picture,
      });
    } catch {
      return reply.status(502).send({ error: 'Google sign-in failed — please try again' });
    }

    const rawToken = generateSessionToken();
    await db.createSession(
      user.id,
      hashSessionToken(rawToken),
      new Date(Date.now() + SESSION_TTL_MS).toISOString(),
    );
    return reply
      .header('set-cookie', [
        serializeCookie(SESSION_COOKIE, rawToken, {
          maxAgeSeconds: Math.floor(SESSION_TTL_MS / 1000),
          secure: secureCookies,
        }),
        clearCookie(STATE_COOKIE, { secure: secureCookies }),
      ])
      .redirect(config.postLoginRedirect);
  });

  app.get('/api/me', { preHandler: authenticate }, async (request, reply) => {
    const authed = requireUser(request);
    const user = await db.getUserById(authed.id);
    if (!user) return reply.status(404).send({ error: 'User not found' });
    const usedThisMonth = await db.sumUsageSince(user.id, 'scan', monthStartIso());
    const monthlyQuota = PLAN_QUOTAS[user.plan].creditsPerMonth;
    return {
      user: {
        id: user.id,
        email: user.email,
        name: user.name ?? null,
        avatar: user.avatarUrl ?? null,
        plan: user.plan,
      },
      credits: {
        usedThisMonth,
        monthlyQuota: Number.isFinite(monthlyQuota) ? monthlyQuota : null,
        remaining: Number.isFinite(monthlyQuota) ? Math.max(0, monthlyQuota - usedThisMonth) : null,
      },
    };
  });

  app.post('/api/auth/logout', async (request, reply) => {
    const rawToken = parseCookies(request.headers.cookie)[SESSION_COOKIE];
    if (rawToken) await db.deleteSession(hashSessionToken(rawToken));
    return reply
      .header('set-cookie', clearCookie(SESSION_COOKIE, { secure: secureCookies }))
      .status(200)
      .send({ ok: true });
  });
}

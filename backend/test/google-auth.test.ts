/* Google sign-in test: the full authorization-code callback flow against
   the in-memory DB with a fake Google transport (the real client code —
   URL building, form encoding, profile parsing — never touches the
   network), session lifecycle, and the preserved API-key auth path. */
import { createHash } from 'node:crypto';

async function main() {
  const { MemoryDatabase } = await import('../src/db/db.js');
  const { createGoogleClient } = await import('../src/auth/google.js');
  const { generateApiKey } = await import('../src/auth/auth.js');
  const { authRoutes } = await import('../src/routes/auth.js');
  const { googleAuthRoutes } = await import('../src/routes/googleAuth.js');
  const Fastify = (await import('fastify')).default;

  let failures = 0;
  const check = (name: string, ok: boolean, extra?: unknown) => {
    console.log(`${ok ? 'PASS' : 'FAIL'} ${name}`);
    if (!ok) {
      failures++;
      if (extra !== undefined) console.log('     →', extra);
    }
  };
  /** inject returns set-cookie as a string for one cookie, array for several. */
  const setCookiesOf = (res: { headers: Record<string, unknown> }): string[] => {
    const v = res.headers['set-cookie'];
    return Array.isArray(v) ? (v as string[]) : typeof v === 'string' ? [v] : [];
  };

  /* ── fake Google transport ── */
  let tokenCallBody = '';
  let userinfoAuth = '';
  const fakeFetch = (async (url: unknown, init?: { method?: string; body?: string; headers?: Record<string, string> }) => {
    const u = String(url);
    if (u.includes('oauth2.googleapis.com/token')) {
      tokenCallBody = String(init?.body ?? '');
      return { ok: true, status: 200, json: async () => ({ access_token: 'fake-access-token' }) };
    }
    if (u.includes('openidconnect.googleapis.com')) {
      userinfoAuth = init?.headers?.['authorization'] ?? '';
      return {
        ok: true,
        status: 200,
        json: async () => ({
          sub: 'google-sub-123',
          email: 'hunter@example.com',
          name: 'Test Hunter',
          picture: 'https://example.com/pic.png',
          email_verified: true,
        }),
      };
    }
    throw new Error(`unexpected fetch: ${u}`);
  }) as unknown as typeof fetch;

  const google = createGoogleClient({
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    redirectUri: 'http://localhost:3000/api/auth/google/callback',
    fetchImpl: fakeFetch,
  });

  const db = new MemoryDatabase();
  const app = Fastify();
  const deps = { db, queue: {} as never, provider: {} as never };
  await authRoutes(app as never, deps);
  await googleAuthRoutes(app as never, deps, { googleClient: google });

  /* ── 1. start: redirect to Google with a signed state cookie ── */
  const start = await app.inject({ method: 'GET', url: '/api/auth/google' });
  check('GET /api/auth/google → 302', start.statusCode === 302, start.statusCode);
  const location = start.headers.location as string;
  const authUrl = new URL(location);
  check('redirects to Google consent', authUrl.origin + authUrl.pathname === 'https://accounts.google.com/o/oauth2/v2/auth', location);
  check('client_id + redirect_uri + code flow', authUrl.searchParams.get('client_id') === 'test-client-id' && authUrl.searchParams.get('response_type') === 'code' && (authUrl.searchParams.get('redirect_uri') ?? '').endsWith('/api/auth/google/callback'));
  const state = authUrl.searchParams.get('state') ?? '';
  check('state nonce present', state.length > 10, state);
  const stateCookie = setCookiesOf(start).find((c) => c.startsWith('bs_oauth_state='));
  check('state cookie set (httpOnly)', Boolean(stateCookie?.includes('HttpOnly')), start.headers['set-cookie']);
  const stateCookiePair = (stateCookie ?? '').split(';')[0];

  /* ── 2. callback happy path ── */
  const callback = await app.inject({
    method: 'GET',
    url: `/api/auth/google/callback?code=test-code&state=${encodeURIComponent(state)}`,
    headers: { cookie: stateCookiePair },
  });
  check('callback → 302 to post-login path', callback.statusCode === 302 && callback.headers.location === '/app', `${callback.statusCode} ${callback.headers.location}`);
  check('code exchanged server-side with the secret', tokenCallBody.includes('code=test-code') && tokenCallBody.includes('client_secret=test-client-secret') && tokenCallBody.includes('grant_type=authorization_code'));
  check('profile fetched with the access token', userinfoAuth === 'Bearer fake-access-token');
  const setCookies = setCookiesOf(callback);
  const sessionCookie = setCookies.find((c) => c.startsWith('bs_session='));
  check('session cookie set (httpOnly, 30d)', Boolean(sessionCookie?.includes('HttpOnly') && sessionCookie?.includes('Max-Age=2592000')), setCookies);
  const rawToken = decodeURIComponent((sessionCookie ?? '').split(';')[0].slice('bs_session='.length));
  check('state cookie cleared on callback', setCookies.some((c) => c.startsWith('bs_oauth_state=') && c.includes('Max-Age=0')), setCookies);

  const user = await db.getUserByGoogleSub('google-sub-123');
  check('user created, keyed by Google sub', user?.email === 'hunter@example.com', user);
  check('profile stored (name + avatar)', user?.name === 'Test Hunter' && user?.avatarUrl === 'https://example.com/pic.png', user);
  const storedSession = await db.getSessionByTokenHash(createHash('sha256').update(rawToken).digest('hex'));
  check('session stored by hash only', Boolean(storedSession) && storedSession?.userId === user?.id && rawToken.length > 20, storedSession);

  /* ── 3. /api/me with the session ── */
  const me = await app.inject({ method: 'GET', url: '/api/me', headers: { cookie: `bs_session=${encodeURIComponent(rawToken)}` } });
  const meBody = me.json() as { user: { id: string; email: string; name: string; avatar: string }; credits: { usedThisMonth: number; monthlyQuota: number; remaining: number } };
  check('/api/me → 200 with the Google user', me.statusCode === 200 && meBody.user.id === user?.id && meBody.user.email === 'hunter@example.com', me.body);
  check('/api/me profile fields', meBody.user.name === 'Test Hunter' && meBody.user.avatar === 'https://example.com/pic.png', meBody.user);
  check('/api/me credits balance (free plan)', meBody.credits.usedThisMonth === 0 && meBody.credits.monthlyQuota === 50 && meBody.credits.remaining === 50, meBody.credits);

  /* ── 4. protected route accepts the session ── */
  const keysWithSession = await app.inject({ method: 'GET', url: '/api/auth/api-keys', headers: { cookie: `bs_session=${encodeURIComponent(rawToken)}` } });
  check('protected route accepts session cookie (200)', keysWithSession.statusCode === 200, keysWithSession.statusCode);

  /* ── 5. repeat sign-in is the same user (find-or-create) ── */
  const start2 = await app.inject({ method: 'GET', url: '/api/auth/google' });
  const state2 = new URL(start2.headers.location as string).searchParams.get('state') ?? '';
  const stateCookie2 = (setCookiesOf(start2).find((c) => c.startsWith('bs_oauth_state=')) ?? '').split(';')[0];
  const callback2 = await app.inject({ method: 'GET', url: `/api/auth/google/callback?code=test-code&state=${encodeURIComponent(state2)}`, headers: { cookie: stateCookie2 } });
  const rawToken2 = decodeURIComponent(((setCookiesOf(callback2).find((c) => c.startsWith('bs_session=')) ?? '').split(';')[0]).slice('bs_session='.length));
  const me2 = await app.inject({ method: 'GET', url: '/api/me', headers: { cookie: `bs_session=${encodeURIComponent(rawToken2)}` } });
  check('second sign-in → same user id', (me2.json() as { user: { id: string } }).user.id === user?.id, me2.body);

  /* ── 5b. house rules: one active session, five quiet minutes ── */
  const hashOf = (t: string) => createHash('sha256').update(t).digest('hex');
  const sessionsMap = (db as unknown as { sessions: Map<string, { lastSeenAt: string }> }).sessions;

  const meOld = await app.inject({ method: 'GET', url: '/api/me', headers: { cookie: `bs_session=${encodeURIComponent(rawToken)}` } });
  check('second sign-in signed the first session out', meOld.statusCode === 401, meOld.statusCode);

  const liveRec = sessionsMap.get(hashOf(rawToken2));
  check('live session carries a last-seen stamp', Boolean(liveRec?.lastSeenAt), liveRec);
  if (liveRec) liveRec.lastSeenAt = new Date(Date.now() - 6 * 60_000).toISOString();
  const meIdle = await app.inject({ method: 'GET', url: '/api/me', headers: { cookie: `bs_session=${encodeURIComponent(rawToken2)}` } });
  check('six idle minutes → 401', meIdle.statusCode === 401, meIdle.statusCode);
  check('the idle-killed session is deleted', (await db.getSessionByTokenHash(hashOf(rawToken2))) === null);

  process.env['ADMIN_EMAIL'] = 'hunter@example.com';
  try {
    const signIn = async (): Promise<string> => {
      const s = await app.inject({ method: 'GET', url: '/api/auth/google' });
      const st = new URL(s.headers.location as string).searchParams.get('state') ?? '';
      const sc = (setCookiesOf(s).find((c) => c.startsWith('bs_oauth_state=')) ?? '').split(';')[0];
      const cb = await app.inject({ method: 'GET', url: `/api/auth/google/callback?code=test-code&state=${encodeURIComponent(st)}`, headers: { cookie: sc } });
      return decodeURIComponent(((setCookiesOf(cb).find((c) => c.startsWith('bs_session=')) ?? '').split(';')[0]).slice('bs_session='.length));
    };
    const adminTok1 = await signIn();
    const adminTok2 = await signIn();
    const aMe1 = await app.inject({ method: 'GET', url: '/api/me', headers: { cookie: `bs_session=${encodeURIComponent(adminTok1)}` } });
    const aMe2 = await app.inject({ method: 'GET', url: '/api/me', headers: { cookie: `bs_session=${encodeURIComponent(adminTok2)}` } });
    check('admin exempt: second sign-in keeps the first alive', aMe1.statusCode === 200 && aMe2.statusCode === 200, `${aMe1.statusCode}/${aMe2.statusCode}`);
    const adminRec = sessionsMap.get(hashOf(adminTok1));
    if (adminRec) adminRec.lastSeenAt = new Date(Date.now() - 60 * 60_000).toISOString();
    const aMeIdle = await app.inject({ method: 'GET', url: '/api/me', headers: { cookie: `bs_session=${encodeURIComponent(adminTok1)}` } });
    check('admin exempt: an idle hour changes nothing', aMeIdle.statusCode === 200, aMeIdle.statusCode);
  } finally {
    delete process.env['ADMIN_EMAIL'];
  }

  /* ── 6. state protections ── */
  const badState = await app.inject({ method: 'GET', url: '/api/auth/google/callback?code=test-code&state=deadbeef.deadbeef', headers: { cookie: stateCookiePair } });
  check('state mismatch → 400', badState.statusCode === 400, badState.statusCode);
  check('state mismatch sets no session', !setCookiesOf(badState).some((c) => c.startsWith('bs_session=')));
  const noCookie = await app.inject({ method: 'GET', url: `/api/auth/google/callback?code=test-code&state=${encodeURIComponent(state)}` });
  check('missing state cookie → 400', noCookie.statusCode === 400, noCookie.statusCode);
  const noCode = await app.inject({ method: 'GET', url: `/api/auth/google/callback?state=${encodeURIComponent(state)}`, headers: { cookie: stateCookiePair } });
  check('missing code → 400', noCode.statusCode === 400, noCode.statusCode);

  /* ── 7. unauthenticated access ── */
  const anon = await app.inject({ method: 'GET', url: '/api/me' });
  check('/api/me without session → 401', anon.statusCode === 401, anon.statusCode);
  const garbage = await app.inject({ method: 'GET', url: '/api/me', headers: { cookie: 'bs_session=not-a-real-token' } });
  check('/api/me with garbage session → 401', garbage.statusCode === 401, garbage.statusCode);
  const anonKeys = await app.inject({ method: 'GET', url: '/api/auth/api-keys' });
  check('protected route without auth → 401', anonKeys.statusCode === 401, anonKeys.statusCode);

  /* ── 8. extension API-key path still works (incl. plan gate) ── */
  const pro = await db.createUser('pro@example.com', 'hash');
  await db.setUserPlan(pro.id, 'pro');
  const gen = generateApiKey();
  await db.createApiKey(pro.id, 'extension', gen.keyHash, gen.keyPrefix);
  const keysViaApiKey = await app.inject({ method: 'GET', url: '/api/auth/api-keys', headers: { 'x-api-key': gen.key } });
  check('x-api-key still authenticates (200)', keysViaApiKey.statusCode === 200, keysViaApiKey.statusCode);
  const free = await db.createUser('free@example.com', 'hash');
  const genFree = generateApiKey();
  await db.createApiKey(free.id, 'extension', genFree.keyHash, genFree.keyPrefix);
  const keysFree = await app.inject({ method: 'GET', url: '/api/auth/api-keys', headers: { 'x-api-key': genFree.key } });
  check('free-plan API key still gated (403)', keysFree.statusCode === 403, keysFree.statusCode);

  /* ── 9. legacy password account + Bearer still works ── */
  const reg = await app.inject({ method: 'POST', url: '/api/auth/register', payload: { email: 'legacy@example.com', password: 'password123' } });
  check('register → 201', reg.statusCode === 201, reg.statusCode);
  const legacyToken = (reg.json() as { token: string }).token;
  const meLegacy = await app.inject({ method: 'GET', url: '/api/auth/me', headers: { authorization: `Bearer ${legacyToken}` } });
  check('Bearer JWT (password account) still authenticates', meLegacy.statusCode === 200, meLegacy.statusCode);

  /* ── 10. logout kills the session ── */
  const logout = await app.inject({ method: 'POST', url: '/api/auth/logout', headers: { cookie: `bs_session=${encodeURIComponent(rawToken)}` } });
  check('logout → 200', logout.statusCode === 200, logout.statusCode);
  check('logout clears the cookie', (setCookiesOf(logout)[0] ?? '').includes('Max-Age=0'), logout.headers['set-cookie']);
  const meAfter = await app.inject({ method: 'GET', url: '/api/me', headers: { cookie: `bs_session=${encodeURIComponent(rawToken)}` } });
  check('/api/me after logout → 401', meAfter.statusCode === 401, meAfter.statusCode);

  /* ── 11. Google not configured → 503, app still boots ── */
  const appOff = Fastify();
  await googleAuthRoutes(appOff as never, deps, { googleClient: null });
  const off = await appOff.inject({ method: 'GET', url: '/api/auth/google' });
  check('unconfigured /api/auth/google → 503 JSON', off.statusCode === 503 && (off.json() as { error: string }).error.includes('not configured'), `${off.statusCode} ${off.body}`);
  const offCb = await appOff.inject({ method: 'GET', url: '/api/auth/google/callback?code=x&state=y' });
  check('unconfigured callback → 503', offCb.statusCode === 503, offCb.statusCode);
  const offMe = await appOff.inject({ method: 'GET', url: '/api/me' });
  check('unconfigured app still serves /api/me guard (401)', offMe.statusCode === 401, offMe.statusCode);
  await appOff.close();

  await app.close();
  console.log(failures === 0 ? 'ALL GOOGLE AUTH TESTS PASSED' : `${failures} FAILURES`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

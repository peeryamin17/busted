/* BYOK sign-in: a pasted provider key (Gemini or Qwen) authenticates nothing
   on its own. Header-only BYOK provisioning was removed: a provider key is
   only ever a model key for an already-authenticated user, loaded from
   Postgres. Runs against the in-memory DB with the real `buildAuthenticate`
   preHandler. */
import Fastify from 'fastify';
import { MemoryDatabase } from '../src/db/db.js';
import { buildAuthenticate } from '../src/middleware/auth.js';
import { generateSessionToken, hashSessionToken } from '../src/auth/session.js';

let failures = 0;
function check(name: string, ok: boolean, extra?: unknown) {
  if (ok) console.log('PASS', name);
  else {
    failures++;
    console.error('FAIL', name, extra ?? '');
  }
}

async function main() {
  const db = new MemoryDatabase();
  const app = Fastify();
  const authenticate = buildAuthenticate(db as never);
  app.get('/probe', { preHandler: authenticate }, async (request) => ({
    ok: true,
    email: request.user?.email,
    plan: request.user?.plan,
  }));
  const probe = (headers: Record<string, string>) =>
    app.inject({ method: 'GET', url: '/probe', headers });

  const qwenKey = 'sk-test-qwen-key-that-is-long-enough-123456';
  const geminiKey = 'AIza-test-gemini-key-that-is-long-enough-123456';

  // 1. A Qwen key alone signs in as nobody: 401, no user minted.
  const q = await probe({ 'x-qwen-api-key': qwenKey });
  check('qwen key alone -> 401', q.statusCode === 401, q.statusCode);
  check('qwen key alone mints no user', (await db.listUsers(10)).length === 0);

  // 2. Same for a Gemini key alone.
  const g = await probe({ 'x-gemini-api-key': geminiKey });
  check('gemini key alone -> 401', g.statusCode === 401, g.statusCode);
  check('gemini key alone mints no user', (await db.listUsers(10)).length === 0);

  // 3. Same key twice -> still 401 both times, nothing persisted.
  const q2 = await probe({ 'x-qwen-api-key': qwenKey });
  check('same qwen key twice -> 401 again', q2.statusCode === 401, q2.statusCode);
  check('repeat key still mints no user', (await db.listUsers(10)).length === 0);

  // 4. A short Qwen key is not a credential.
  const short = await probe({ 'x-qwen-api-key': 'sk-short' });
  check('short qwen key -> 401', short.statusCode === 401, short.statusCode);

  // 5. Nothing at all -> the exact auth-required error the popup shows.
  const none = await probe({});
  check('no credentials -> 401', none.statusCode === 401, none.statusCode);
  check(
    'no credentials -> auth-required message',
    (none.json() as { message?: string }).message ===
      'Authentication required (session cookie, Bearer token or x-api-key)',
    (none.json() as { message?: string }).message,
  );

  // 6. A provider key does not rescue a bad bs_ key either.
  const both = await probe({
    'x-qwen-api-key': qwenKey,
    'x-api-key': 'bs_0000000000000000000000000000000000000000000000000000000000000000',
  });
  check('qwen key + bad bs_ key -> 401', both.statusCode === 401, both.statusCode);

  // 7. Positive control: a real session still authenticates.
  const user = await db.createUser('user@example.com', 'unused-hash');
  const token = generateSessionToken();
  await db.createSession(
    user.id,
    hashSessionToken(token),
    new Date(Date.now() + 3600_000).toISOString(),
  );
  const authed = await probe({ cookie: `bs_session=${token}` });
  check('session cookie -> 200', authed.statusCode === 200, authed.statusCode);
  check(
    'session resolves to the right user',
    (authed.json() as { email?: string }).email === 'user@example.com',
    authed.json(),
  );

  await app.close();
  if (failures > 0) throw new Error(`${failures} check(s) failed`);
  console.log('ALL BYOK-AUTH TESTS PASSED');
}
main().catch((e) => { console.error('FAIL', e); process.exit(1); });

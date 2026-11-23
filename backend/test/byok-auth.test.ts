/* BYOK sign-in: a pasted provider key (Gemini or Qwen) authenticates on its
   own, no bs_ key or session needed. Runs against the in-memory DB with the
   real `buildAuthenticate` preHandler. */
import Fastify from 'fastify';
import { MemoryDatabase } from '../src/db/db.js';
import { buildAuthenticate } from '../src/middleware/auth.js';

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

  // 1. Qwen key alone signs in as a BYOK enterprise user.
  const q = await probe({ 'x-qwen-api-key': qwenKey });
  check('qwen key alone -> 200', q.statusCode === 200, q.statusCode);
  const qBody = q.json() as { email?: string; plan?: string };
  check('qwen key -> byok user', (qBody.email ?? '').startsWith('byok-'), qBody.email);
  check('qwen key -> enterprise plan', qBody.plan === 'enterprise', qBody.plan);

  // 2. Gemini key alone still signs in (existing path, must not regress).
  const g = await probe({ 'x-gemini-api-key': geminiKey });
  check('gemini key alone -> 200', g.statusCode === 200, g.statusCode);

  // 3. Same key twice -> same user (identity derives from the key hash).
  const q2 = await probe({ 'x-qwen-api-key': qwenKey });
  check(
    'same qwen key twice -> same user',
    (q2.json() as { email?: string }).email === qBody.email,
    (q2.json() as { email?: string }).email,
  );

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

  // 6. A valid Qwen key still signs in when a bad bs_ key rides along.
  const both = await probe({
    'x-qwen-api-key': qwenKey,
    'x-api-key': 'bs_0000000000000000000000000000000000000000000000000000000000000000',
  });
  check('qwen key + bad bs_ key -> 200', both.statusCode === 200, both.statusCode);

  await app.close();
  if (failures > 0) throw new Error(`${failures} check(s) failed`);
  console.log('ALL BYOK-AUTH TESTS PASSED');
}
main().catch((e) => { console.error('FAIL', e); process.exit(1); });

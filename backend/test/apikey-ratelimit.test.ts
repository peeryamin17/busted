/* Failed API-key authentication rate limiting (login equivalent: 10/min/IP).
   Counts FAILED `bs_` attempts only, successes are never throttled and the
   Google OAuth / session-cookie path is untouched. Runs against the
   in-memory DB with the real `buildAuthenticate` preHandler. */
import Fastify from 'fastify';
import { MemoryDatabase } from '../src/db/db.js';
import { buildAuthenticate } from '../src/middleware/auth.js';
import { generateApiKey } from '../src/auth/auth.js';
import { generateSessionToken, hashSessionToken } from '../src/auth/session.js';
import {
  FailedAuthRateLimiter,
  apiKeyAuthFailures,
} from '../src/guardrails/ratelimit.js';

let failures = 0;
function check(name: string, ok: boolean, extra?: unknown) {
  if (ok) console.log('PASS', name);
  else {
    failures++;
    console.error('FAIL', name, extra ?? '');
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const db = new MemoryDatabase();
  const user = await db.createUser('keyuser@example.com', 'unused-hash');
  await db.setUserPlan(user.id, 'pro');
  const { key: validKey, keyHash, keyPrefix } = generateApiKey();
  await db.createApiKey(user.id, 'test key', keyHash, keyPrefix);
  const badKey = 'bs_0000000000000000000000000000000000000000000000000000000000000000';

  const token = generateSessionToken();
  await db.createSession(
    user.id,
    hashSessionToken(token),
    new Date(Date.now() + 3600_000).toISOString(),
  );
  const cookie = `bs_session=${token}`;

  // --- Default limiter (10 failures / 60 s), shared singleton ---
  const app = Fastify();
  const authenticate = buildAuthenticate(db as never);
  app.get('/probe', { preHandler: authenticate }, async (request) => ({
    ok: true,
    email: request.user?.email,
  }));
  const probe = (headers: Record<string, string>) =>
    app.inject({ method: 'GET', url: '/probe', headers });
  const badKey2 = 'bs_1111111111111111111111111111111111111111111111111111111111111111';
  const badFrom = (ip: string, key: string = badKey) =>
    probe({ 'x-api-key': key, 'x-forwarded-for': ip });
  const goodFrom = (ip: string, key: string = validKey) =>
    probe({ 'x-api-key': key, 'x-forwarded-for': ip });

  // 1. Ten failures from one IP trip 429 on the 11th, with a Retry-After hint.
  apiKeyAuthFailures.reset();
  let statuses: number[] = [];
  for (let i = 0; i < 10; i++) statuses.push((await badFrom('203.0.113.1')).statusCode);
  check('10 failed attempts from one IP → 401 each', statuses.every((s) => s === 401), statuses);
  const eleventh = await badFrom('203.0.113.1');
  check('11th failed attempt from same IP → 429', eleventh.statusCode === 429, eleventh.statusCode);
  check(
    '429 carries a Retry-After header',
    typeof eleventh.headers['retry-after'] === 'string' &&
      Number(eleventh.headers['retry-after']) > 0,
    eleventh.headers['retry-after'],
  );
  check(
    '429 body names the wait',
    eleventh.body.includes('Too many failed API-key attempts'),
    eleventh.body,
  );

  // 2. A different IP is unaffected by the first IP's trip (different key, so
  // the fingerprint bucket is fresh too, this isolates the per-IP bucket).
  const otherIp = await badFrom('203.0.113.2', badKey2);
  check('different IP after trip → still 401 (not 429)', otherIp.statusCode === 401, otherIp.statusCode);

  // 3. Successful authentications are never throttled (extension polling).
  apiKeyAuthFailures.reset();
  statuses = [];
  for (let i = 0; i < 20; i++) statuses.push((await goodFrom('203.0.113.3')).statusCode);
  check('20 consecutive successful auths → all 200', statuses.every((s) => s === 200), statuses);

  // 4. Failures only: a valid key still succeeds after failures from the same IP.
  apiKeyAuthFailures.reset();
  for (let i = 0; i < 5; i++) await badFrom('203.0.113.4');
  const afterFailures = await goodFrom('203.0.113.4');
  check('valid key after 5 failures from same IP → 200', afterFailures.statusCode === 200, afterFailures.statusCode);
  const afterFailuresBody = JSON.parse(afterFailures.body);
  check('successful auth identifies the user', afterFailuresBody.email === 'keyuser@example.com', afterFailures.body);

  // 5. Key-fingerprint bucket: the same bad key hammered from fresh IPs trips too.
  apiKeyAuthFailures.reset();
  statuses = [];
  for (let i = 0; i < 10; i++) statuses.push((await badFrom(`203.0.113.${10 + i}`)).statusCode);
  check('same bad key from 10 fresh IPs → 401 each', statuses.every((s) => s === 401), statuses);
  const fpTripped = await badFrom('203.0.113.99');
  check('same bad key from an 11th fresh IP → 429 (fingerprint bucket)', fpTripped.statusCode === 429, fpTripped.statusCode);
  const goodElsewhere = await goodFrom('203.0.113.100');
  check('a different (valid) key from a fresh IP → 200', goodElsewhere.statusCode === 200, goodElsewhere.statusCode);

  // 6. The session-cookie (Google OAuth) path is NOT rate-limited by this.
  apiKeyAuthFailures.reset();
  for (let i = 0; i < 11; i++) await badFrom('203.0.113.5');
  const sessionAfterTrip = await probe({ cookie, 'x-forwarded-for': '203.0.113.5' });
  check('session auth from the tripped IP → 200 (OAuth path untouched)', sessionAfterTrip.statusCode === 200, sessionAfterTrip.statusCode);

  // 7. The limiter resets after the window (short-window injected limiter).
  const shortApp = Fastify();
  const shortAuthenticate = buildAuthenticate(db as never, {
    failedAuthLimiter: new FailedAuthRateLimiter(3, 150),
  });
  shortApp.get('/probe', { preHandler: shortAuthenticate }, async () => ({ ok: true }));
  const shortBad = (ip: string) =>
    shortApp.inject({ method: 'GET', url: '/probe', headers: { 'x-api-key': badKey, 'x-forwarded-for': ip } });
  const shortGood = (ip: string) =>
    shortApp.inject({ method: 'GET', url: '/probe', headers: { 'x-api-key': validKey, 'x-forwarded-for': ip } });
  statuses = [];
  for (let i = 0; i < 3; i++) statuses.push((await shortBad('203.0.113.6')).statusCode);
  check('short window: 3 failures → 401 each', statuses.every((s) => s === 401), statuses);
  const shortTripped = await shortBad('203.0.113.6');
  check('short window: 4th failure → 429', shortTripped.statusCode === 429, shortTripped.statusCode);
  await sleep(250);
  const afterWindow = await shortBad('203.0.113.6');
  check('after the window passes, a bad key → 401 again (not 429)', afterWindow.statusCode === 401, afterWindow.statusCode);
  const goodAfterWindow = await shortGood('203.0.113.6');
  check('after the window passes, a valid key → 200', goodAfterWindow.statusCode === 200, goodAfterWindow.statusCode);

  await app.close();
  await shortApp.close();
  if (failures > 0) throw new Error(`${failures} check(s) failed`);
  console.log('ALL APIKEY-RATELIMIT TESTS PASSED');
}
main().catch((e) => { console.error('FAIL', e); process.exit(1); });

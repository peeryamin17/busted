/* Link-code pairing: the website mints a one-time 32-character code
   (signed-in session), the extension exchanges it exactly once for a
   regular API key, and that key identifies the account. Runs against
   the in-memory DB with the real routes. */
import Fastify from 'fastify';
import { createServer } from 'node:http';
import { MemoryDatabase } from '../src/db/db.js';
import { authRoutes } from '../src/routes/auth.js';
import { v1CompatRoutes } from '../src/routes/v1compat.js';
import { swarmRoutes } from '../src/routes/multiagent.js';
import { MockProvider } from '../src/llm/mock.js';
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
  process.env['ADMIN_EMAIL'] = 'op@example.com';
  const db = new MemoryDatabase();
  const user = await db.createUser('op@example.com', 'unused-hash');
  await db.setUserPlan(user.id, 'enterprise');
  const token = generateSessionToken();
  await db.createSession(
    user.id,
    hashSessionToken(token),
    new Date(Date.now() + 3600_000).toISOString(),
  );
  const cookie = `bs_session=${token}`;

  const app = Fastify();
  const deps = { db, queue: {} as never, provider: new MockProvider() as never };
  await authRoutes(app as never, deps);
  await v1CompatRoutes(app as never, deps);
  await swarmRoutes(app as never, deps);

  const anon = await app.inject({ method: 'POST', url: '/api/auth/pairing-codes' });
  check('mint without session → 401', anon.statusCode === 401, anon.statusCode);

  const mint = await app.inject({
    method: 'POST',
    url: '/api/auth/pairing-codes',
    headers: { cookie },
  });
  check('mint → 201', mint.statusCode === 201, mint.statusCode);
  const { code, expiresAt } = JSON.parse(mint.body);
  check('code is 32-char alphanumeric', /^[A-Z0-9]{32}$/.test(code), code);
  check('expiry ~10 min out', Date.parse(expiresAt) > Date.now() + 9 * 60_000, expiresAt);

  const wrong = await app.inject({
    method: 'POST',
    url: '/api/v1/pair',
    payload: { code: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
  });
  check('wrong code → 400', wrong.statusCode === 400, wrong.statusCode);


  const typed = code.toLowerCase().replace(/(.{4})/g, '$1-').slice(0, -1);
  const pair = await app.inject({ method: 'POST', url: '/api/v1/pair', payload: { code: typed } });
  check('exchange → 201', pair.statusCode === 201, pair.statusCode);
  const { apiKey } = JSON.parse(pair.body);
  check(
    'exchanged key is a bs_ key',
    typeof apiKey === 'string' && apiKey.startsWith('bs_'),
    typeof apiKey === 'string' ? apiKey.slice(0, 6) : apiKey,
  );

  const acct = await app.inject({
    method: 'GET',
    url: '/api/v1/account',
    headers: { 'x-api-key': apiKey },
  });
  const acctBody = JSON.parse(acct.body);
  check(
    'account via exchanged key (operator)',
    acct.statusCode === 200 && acctBody.email === 'op@example.com' && acctBody.operator === true,
    acct.body,
  );

  const again = await app.inject({ method: 'POST', url: '/api/v1/pair', payload: { code } });
  check('code reuse → 400', again.statusCode === 400, again.statusCode);

  const mint2 = await app.inject({
    method: 'POST',
    url: '/api/auth/pairing-codes',
    headers: { cookie },
  });
  const code2 = JSON.parse(mint2.body).code;
  const mint3 = await app.inject({
    method: 'POST',
    url: '/api/auth/pairing-codes',
    headers: { cookie },
  });
  const code3 = JSON.parse(mint3.body).code;
  const stale = await app.inject({ method: 'POST', url: '/api/v1/pair', payload: { code: code2 } });
  check('superseded code → 400', stale.statusCode === 400, stale.statusCode);
  const fresh = await app.inject({ method: 'POST', url: '/api/v1/pair', payload: { code: code3 } });
  check('freshest code → 201', fresh.statusCode === 201, fresh.statusCode);

  // ── Regression test: fresh ADMIN_EMAIL auto-upgrade to enterprise + passes /api/v1/account and /api/swarm/scans ──
  process.env['ADMIN_EMAIL'] = 'fresh-operator@example.com';
  // Create user with mixed case without manually calling setUserPlan
  const freshAdminUser = await db.createUser('FRESH-OPERATOR@EXAMPLE.COM', 'admin-pass-hash');
  const freshToken = generateSessionToken();
  await db.createSession(
    freshAdminUser.id,
    hashSessionToken(freshToken),
    new Date(Date.now() + 3600_000).toISOString(),
  );
  const freshCookie = `bs_session=${freshToken}`;

  const adminMint = await app.inject({
    method: 'POST',
    url: '/api/auth/pairing-codes',
    headers: { cookie: freshCookie },
  });
  check('fresh admin mint → 201', adminMint.statusCode === 201, adminMint.statusCode);
  const adminPairCode = JSON.parse(adminMint.body).code;

  const adminPair = await app.inject({
    method: 'POST',
    url: '/api/v1/pair',
    payload: { code: adminPairCode },
  });
  check('fresh admin pair → 201', adminPair.statusCode === 201, adminPair.statusCode);
  const adminApiKey = JSON.parse(adminPair.body).apiKey;

  // 1. Passes /api/v1/account with enterprise plan & operator=true
  const adminAcct = await app.inject({
    method: 'GET',
    url: '/api/v1/account',
    headers: { 'x-api-key': adminApiKey },
  });
  const adminAcctBody = JSON.parse(adminAcct.body);
  check(
    'fresh admin passes /api/v1/account with enterprise plan',
    adminAcct.statusCode === 200 &&
    adminAcctBody.email === 'fresh-operator@example.com' &&
    adminAcctBody.plan === 'enterprise' &&
    adminAcctBody.operator === true,
    adminAcct.body,
  );

  // 2. Passes /api/swarm/scans without 403 (active testing gated for non-hunter/pro) or quota errors
  const testTarget = createServer((_req, res) => {
    res.setHeader('content-type', 'text/html');
    res.end('<html><body><h1>Admin Test</h1><a href="/api/users">API</a></body></html>');
  });
  await new Promise<void>((r) => testTarget.listen(0, '127.0.0.1', r));
  const testPort = (testTarget.address() as any).port;
  const testUrl = `http://127.0.0.1:${testPort}/`;

  const adminSwarm = await app.inject({
    method: 'POST',
    url: '/api/swarm/scans',
    headers: { 'x-api-key': adminApiKey },
    payload: {
      targetUrl: testUrl,
      authorization: {
        type: 'ownership',
        statement: 'Authorized testing by operator',
        confirmed: true,
      },
      allowPrivateTargets: true,
      specialists: ['recon'],
      maxTokens: 5000,
      timeoutMinutes: 1,
    },
  });
  check(
    'fresh admin passes /api/swarm/scans (200, active testing unlocked)',
    adminSwarm.statusCode === 200,
    `${adminSwarm.statusCode}: ${adminSwarm.body.slice(0, 200)}`,
  );
  const adminSwarmBody = JSON.parse(adminSwarm.body);
  check('fresh admin swarm created scanId', typeof adminSwarmBody.scanId === 'string', adminSwarmBody.scanId);

  testTarget.closeAllConnections();
  testTarget.close();
  await new Promise((r) => setTimeout(r, 50));

  await app.close();
  if (failures) {
    console.error(`${failures} FAILURES`);
    process.exit(1);
  }
  console.log('ALL PAIRING TESTS PASSED');
}
main().catch((e) => {
  console.error('FAIL', e);
  process.exit(1);
});

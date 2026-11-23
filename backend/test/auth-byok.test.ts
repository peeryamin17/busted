/* BYOK auth removal (Batch 1: H1, H10, H15) and the DB-backed BYOK lookup
   for the swarm. A paired bs_ key resolves the user; the swarm reads the
   stored encrypted key from the DB row, never a request header; the stored
   key wins over a conflicting header; and the 25-credit charge is waived. */
import Fastify from 'fastify';
import { createServer } from 'node:http';
import { MemoryDatabase } from '../src/db/db.js';
import { buildAuthenticate } from '../src/middleware/auth.js';
import { generateApiKey } from '../src/auth/auth.js';
import { generateSessionToken, hashSessionToken } from '../src/auth/session.js';
import { encryptSecret } from '../src/lib/crypto.js';
import { monthStartIso, SCAN_CREDIT_COST } from '../src/auth/usage.js';
import { QWEN_BASE_URLS, verifyGeminiKey, verifyQwenKey } from '../src/routes/aiKey.js';
import { authRoutes } from '../src/routes/auth.js';
import { swarmRoutes } from '../src/routes/multiagent.js';
import { MockProvider } from '../src/llm/mock.js';

let failures = 0;
function check(name: string, ok: boolean, extra?: unknown) {
  if (ok) console.log('PASS', name);
  else {
    failures++;
    console.error('FAIL', name, extra ?? '');
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const STORED_GEMINI = 'AIzaStoredDbKey-0123456789abcdef';
const HEADER_GEMINI = 'AIzaHeaderKey-0123456789abcdef';
const STORED_QWEN = 'sk-qwen-stored-key-0123456789';
const HEADER_QWEN = 'sk-qwen-header-key-0123456789';
const QWEN_BASE = QWEN_BASE_URLS.intl;

const authz = {
  type: 'ownership',
  statement: 'I own this local test server and authorize testing of it.',
  confirmed: true,
};

async function mintBsKey(db: MemoryDatabase, userId: string): Promise<string> {
  const { key, keyHash, keyPrefix } = generateApiKey();
  await db.createApiKey(userId, 'test key', keyHash, keyPrefix);
  return key;
}

async function mintSession(db: MemoryDatabase, userId: string): Promise<string> {
  const token = generateSessionToken();
  await db.createSession(
    userId,
    hashSessionToken(token),
    new Date(Date.now() + 3600_000).toISOString(),
  );
  return `bs_session=${token}`;
}

/* Records the provider key each LLM call carries, then stops the call so
   the background swarm job fails fast. Anything else passes through to
   the real fetch, so the swarm's target probes still run. */
const realFetch = globalThis.fetch;
type SeenKey = { provider: 'gemini' | 'qwen'; key: string };
const seenKeys: SeenKey[] = [];

function installKeyRecorder(): void {
  globalThis.fetch = (async (input: unknown, init?: unknown) => {
    const url = String(typeof input === 'string' ? input : (input as Request).url);
    const rawHeaders =
      (init as { headers?: unknown } | undefined)?.headers ??
      (typeof input !== 'string' ? (input as Request).headers : undefined);
    const headers = new Headers(rawHeaders as any);
    if (url.startsWith('https://generativelanguage.googleapis.com/')) {
      seenKeys.push({ provider: 'gemini', key: headers.get('x-goog-api-key') ?? '' });
      if (url.endsWith('/models')) {
        return new Response(JSON.stringify({ models: [] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      throw new Error('key captured, stop the call');
    }
    if (url.startsWith(QWEN_BASE)) {
      seenKeys.push({
        provider: 'qwen',
        key: (headers.get('authorization') ?? '').replace(/^Bearer /, ''),
      });
      if (url.endsWith('/models')) {
        return new Response(JSON.stringify({ data: [] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      throw new Error('key captured, stop the call');
    }
    return realFetch(input as never, init as never);
  }) as typeof fetch;
}

function uninstallKeyRecorder(): void {
  globalThis.fetch = realFetch;
}

async function waitForKey(provider: 'gemini' | 'qwen', timeoutMs = 15000): Promise<boolean> {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (seenKeys.some((s) => s.provider === provider)) return true;
    await sleep(100);
  }
  return false;
}

async function main() {
  process.env['KEY_ENCRYPTION_SECRET'] = 'test-secret-must-be-min-16-characters!';

  const db = new MemoryDatabase();
  const pairedGemini = await db.createUser('paired-gemini@example.com', 'unused-hash');
  await db.setUserPlan(pairedGemini.id, 'pro');
  await db.setAiKey(pairedGemini.id, encryptSecret(STORED_GEMINI), 'gemini', 'AIza••••cdef', null);
  const geminiBs = await mintBsKey(db, pairedGemini.id);

  const pairedQwen = await db.createUser('paired-qwen@example.com', 'unused-hash');
  await db.setUserPlan(pairedQwen.id, 'pro');
  await db.setAiKey(pairedQwen.id, encryptSecret(STORED_QWEN), 'qwen', 'sk-q••••6789', QWEN_BASE);
  const qwenBs = await mintBsKey(db, pairedQwen.id);

  const hunter = await db.createUser('hunter@example.com', 'unused-hash');
  await db.setUserPlan(hunter.id, 'hunter');
  const hunterCookie = await mintSession(db, hunter.id);

  await db.createUser('nopass@example.com', '');

  const sessionUser = await db.createUser('session@example.com', 'unused-hash');
  const cookie = await mintSession(db, sessionUser.id);

  const target = createServer((_req, res) => {
    res.setHeader('content-type', 'text/html');
    res.end('<html><body>local target</body></html>');
  });
  await new Promise<void>((r) => target.listen(0, '127.0.0.1', r));
  const port = (target.address() as { port: number }).port;
  const targetUrl = `http://127.0.0.1:${port}/`;

  const app = Fastify();
  const authenticate = buildAuthenticate(db as never);
  app.get('/probe', { preHandler: authenticate }, async (request) => ({
    ok: true,
    email: request.user?.email,
    plan: request.user?.plan,
  }));
  await authRoutes(app as never, { db, queue: {} as never, provider: new MockProvider() as never });
  await swarmRoutes(app as never, { db, queue: {} as never, provider: new MockProvider() as never });

  const swarm = (headers: Record<string, string>, url = targetUrl) =>
    app.inject({
      method: 'POST',
      url: '/api/swarm/scans',
      headers,
      payload: { targetUrl: url, authorization: authz, allowPrivateTargets: true },
    });

  // --- Batch 1 negatives: a provider header alone authenticates nothing ---
  const geminiHeaderOnly = await swarm({ 'x-gemini-api-key': HEADER_GEMINI });
  check('header-only x-gemini-api-key swarm → 401', geminiHeaderOnly.statusCode === 401, geminiHeaderOnly.statusCode);
  const qwenHeaderOnly = await swarm({ 'x-qwen-api-key': HEADER_QWEN });
  check('header-only x-qwen-api-key swarm → 401', qwenHeaderOnly.statusCode === 401, qwenHeaderOnly.statusCode);

  const users = await db.listUsers(200);
  check(
    'header-only BYOK mints no byok user rows',
    users.every((u) => !u.email.endsWith('@bugseek.local')),
    users.map((u) => u.email),
  );

  const adminHeaderOnly = await app.inject({
    method: 'GET',
    url: '/api/admin/users',
    headers: { 'x-gemini-api-key': HEADER_GEMINI },
  });
  check('header-only BYOK does not reach admin route → 401', adminHeaderOnly.statusCode === 401, adminHeaderOnly.statusCode);
  const adminSessionHeader = await app.inject({
    method: 'GET',
    url: '/api/admin/users',
    headers: { cookie, 'x-gemini-api-key': HEADER_GEMINI },
  });
  check('signed-in user + BYOK header still not admin → 403', adminSessionHeader.statusCode === 403, adminSessionHeader.statusCode);

  const probeHeader = await app.inject({
    method: 'GET',
    url: '/probe',
    headers: { cookie, 'x-gemini-api-key': HEADER_GEMINI },
  });
  const probeBody = JSON.parse(probeHeader.body);
  check('signed-in user + BYOK header keeps free plan', probeBody.plan === 'free', probeHeader.body);

  // --- Batch 1: mock keys fail verification, empty hash logs in as 401 ---
  const mockGemini = await verifyGeminiKey('mock-gemini-key-1234567890');
  check('mock gemini key fails verification', mockGemini.ok === false, mockGemini);
  const mockQwen = await verifyQwenKey('mock-qwen-key-1234567890', QWEN_BASE);
  check('mock qwen key fails verification', mockQwen.ok === false, mockQwen);

  const nopassLogin = await app.inject({
    method: 'POST',
    url: '/api/auth/login',
    payload: { email: 'nopass@example.com', password: 'whatever123' },
  });
  check('empty password hash login → 401 not 500', nopassLogin.statusCode === 401, nopassLogin.statusCode);

  // --- DB-backed BYOK: paired user, stored key, no header ---
  const freeNoByok = await app.inject({
    method: 'POST',
    url: '/api/swarm/scans',
    headers: { cookie },
    payload: { targetUrl, authorization: authz, allowPrivateTargets: true },
  });
  check('free plan without BYOK → 403', freeNoByok.statusCode === 403, freeNoByok.statusCode);

  const geminiSwarm = await swarm({ 'x-api-key': geminiBs });
  check('paired bs_ key + stored Gemini key → swarm starts (202)', geminiSwarm.statusCode === 202, geminiSwarm.statusCode);
  const geminiScanId = JSON.parse(geminiSwarm.body).scanId as string;
  const geminiScan = await db.getScan(geminiScanId);
  check('swarm scan record belongs to the paired user', geminiScan?.userId === pairedGemini.id, geminiScan);
  const geminiUsage = await db.sumUsageSince(pairedGemini.id, 'scan', monthStartIso());
  check('stored Gemini key waives the 25-credit charge (usage 0)', geminiUsage === 0, geminiUsage);

  // --- DB row wins over a conflicting header (Gemini) ---
  seenKeys.length = 0;
  installKeyRecorder();
  const geminiPrecedence = await swarm({ 'x-api-key': geminiBs, 'x-gemini-api-key': HEADER_GEMINI });
  check('stored key + conflicting header → swarm still starts (202)', geminiPrecedence.statusCode === 202, geminiPrecedence.statusCode);
  const geminiSeen = await waitForKey('gemini');
  uninstallKeyRecorder();
  check('LLM call carried the stored key', geminiSeen, seenKeys);
  const geminiCall = seenKeys.find((s) => s.provider === 'gemini');
  check('LLM call used the DB key, not the header key', geminiCall?.key === STORED_GEMINI, geminiCall);

  // --- DB row wins over a conflicting header (Qwen) ---
  seenKeys.length = 0;
  installKeyRecorder();
  const qwenPrecedence = await swarm({ 'x-api-key': qwenBs, 'x-qwen-api-key': HEADER_QWEN });
  check('stored Qwen key + conflicting header → swarm still starts (202)', qwenPrecedence.statusCode === 202, qwenPrecedence.statusCode);
  const qwenSeen = await waitForKey('qwen');
  uninstallKeyRecorder();
  check('Qwen LLM call carried the stored key', qwenSeen, seenKeys);
  const qwenCall = seenKeys.find((s) => s.provider === 'qwen');
  check('Qwen LLM call used the DB key, not the header key', qwenCall?.key === STORED_QWEN, qwenCall);
  const qwenUsage = await db.sumUsageSince(pairedQwen.id, 'scan', monthStartIso());
  check('stored Qwen key waives the 25-credit charge (usage 0)', qwenUsage === 0, qwenUsage);

  // --- Header keys are ignored as model keys (PR 1 header ban) ---
  const freeHeaderOnly = await swarm({ cookie, 'x-gemini-api-key': HEADER_GEMINI });
  check('free plan + header key only → 403 (header grants no BYOK)', freeHeaderOnly.statusCode === 403, freeHeaderOnly.statusCode);

  seenKeys.length = 0;
  installKeyRecorder();
  const hunterHeaderGemini = await swarm(
    { cookie: hunterCookie, 'x-gemini-api-key': HEADER_GEMINI },
    targetUrl,
  );
  check('hunter + header key only → swarm still starts (202)', hunterHeaderGemini.statusCode === 202, hunterHeaderGemini.statusCode);
  await sleep(5000);
  uninstallKeyRecorder();
  check(
    'header Gemini key never reached an LLM call',
    !seenKeys.some((s) => s.key === HEADER_GEMINI),
    seenKeys,
  );

  seenKeys.length = 0;
  installKeyRecorder();
  const hunterHeaderQwen = await swarm(
    { cookie: hunterCookie, 'x-qwen-api-key': HEADER_QWEN },
    targetUrl,
  );
  check('hunter + header Qwen key only → swarm still starts (202)', hunterHeaderQwen.statusCode === 202, hunterHeaderQwen.statusCode);
  await sleep(5000);
  uninstallKeyRecorder();
  check(
    'header Qwen key never reached an LLM call',
    !seenKeys.some((s) => s.key === HEADER_QWEN),
    seenKeys,
  );

  // --- Control: no BYOK at all → the 25-credit charge is recorded ---
  // The hunter header swarms above each recorded a 25-credit charge, so
  // the control asserts on the delta from just before its own swarm.
  const hunterUsageBefore = await db.sumUsageSince(hunter.id, 'scan', monthStartIso());
  const hunterSwarm = await swarm({ cookie: hunterCookie }, 'http://127.0.0.1:1/');
  check('hunter without BYOK → swarm starts (202)', hunterSwarm.statusCode === 202, hunterSwarm.statusCode);
  const hunterUsage = await db.sumUsageSince(hunter.id, 'scan', monthStartIso());
  check(
    'no BYOK → 25-credit charge recorded',
    hunterUsage - hunterUsageBefore === SCAN_CREDIT_COST.active,
    hunterUsage,
  );

  await app.close();
  target.close();
  if (failures > 0) throw new Error(`${failures} check(s) failed`);
  console.log('ALL AUTH-BYOK TESTS PASSED');
}

main().catch((e) => {
  console.error('FAIL', e);
  process.exit(1);
});

/**
 * Integration test for POST /api/swarm/scans, the head-agent/worker swarm
 * wired into the scan lifecycle: auth → authorization record → credit quota →
 * scan record → inline swarm run (mock provider) → persisted findings →
 * scan completed.
 */
import Fastify from 'fastify';
import { createServer } from 'node:http';
import { MockProvider } from '../src/llm/mock.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

interface UsageEvent { userId: string; kind: string; quantity: number; scanId?: string; at: string }
const authz = {
  type: 'ownership',
  statement: 'I own this local test server and authorize testing of it.',
  confirmed: true,
};

function makeDb(plan: 'free' | 'hunter' | 'pro' = 'pro', seedUsage: UsageEvent[] = []) {
  const usage: UsageEvent[] = [...seedUsage];
  const scans: any[] = [];
  const findings: any[] = [];
  const db: any = {
    kind: 'stub',
    scans, findings, usage,
    async getApiKeyByHash() { return { userId: 'u1', revokedAt: null }; },
    async getUserById() { return { id: 'u1', email: 't@e.com', plan }; },
    async getAiKey() { return null; },
    async touchApiKey() { /* stub */ },
    async createAuthorization(input: any) { return { id: 'authz-1', ...input }; },
    async createScan(input: any) {
      const s = { id: `scan-${scans.length + 1}`, status: 'queued', ...input };
      scans.push(s); return s;
    },
    async getScan(id: string) {
      return scans.find((x) => x.id === id) ?? null;
    },
    async listFindings(scanId: string) {
      return findings.filter((f) => f.scanId === scanId);
    },
    async updateScan(id: string, patch: any) {
      const s = scans.find((x) => x.id === id); Object.assign(s, patch); return s;
    },
    async recordUsage(userId: string, kind: string, quantity: number, scanId?: string) {
      usage.push({ userId, kind, quantity, scanId, at: new Date().toISOString() });
    },
    async sumUsageSince(userId: string, kind: string, sinceIso: string) {
      return usage.filter((u) => u.userId === userId && u.kind === kind && u.at >= sinceIso)
        .reduce((n, u) => n + u.quantity, 0);
    },
    async addFinding(f: any) { findings.push({ ...f, id: `f-${findings.length + 1}` }); return f; },
    async addFindings(items: any[]) { const out = []; for (const f of items) out.push(await db.addFinding(f)); return out; },
  };
  return db;
}

async function loadSwarmRoutes() {
  // The swarm route reads the SSRF guard config at import time, and this
  // suite's target is a local 127.0.0.1 server. Set the allowance first,
  // then import the route, so the guard stays off by default everywhere else.
  process.env['ALLOW_PRIVATE_TARGETS'] = '1';
  return (await import('../src/routes/multiagent.js')).swarmRoutes;
}

async function buildApp(db: any) {
  const app = Fastify();
  const swarmRoutes = await loadSwarmRoutes();
  await swarmRoutes(app as any, { db, queue: {} as any, provider: new MockProvider() });
  return app;
}

async function main() {
  process.env['KEY_ENCRYPTION_SECRET'] = 'test-secret-must-be-min-16-characters!';
  // A platform key must be configured for the legacy-Qwen test to mean
  // anything: with no platform key the old code also ran Qwen alone.
  // Constructed fixture value, never a real key.
  process.env['GEMINI_API_KEY'] = 'test-' + 'x'.repeat(20);
  const { encryptSecret } = await import('../src/lib/crypto.js');
  // Fake secret-shaped tokens, planted in the target's Server header so
  // the swarm's server-disclosure finding carries them through the
  // redaction path. Letter-only bodies: no digit run for the phone or
  // card-number patterns to chew on, so only a real secret-shape pattern
  // can scrub them. These are test fixtures, never real credentials.
  const SECRET_TOKENS = [
    'ghp_AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIj',
    'github_pat_AbCdEfGhIjKlMnOpQrStUv_AbCdEfGhIjKlMnOpQrStUvWxYzAbCd',
    'xoxb-AbCdEfGhIjKl-AbCdEfGhIjKl-AbCdEfGhIjKlMnOpQrStUvWx',
    'AIzaAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhI',
    'AQ.AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv',
    'sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv',
  ];
  const SECRET_SHAPES = ['ghp_', 'github_pat_', 'xoxb-', 'AIza', 'AQ.', 'sk-proj-'];

  // Local target for the mock-provider swarm run.
  const target = createServer((_req, res) => {
    res.setHeader('content-type', 'text/html');
    res.setHeader('server', `TestServer/1.0 ${SECRET_TOKENS.join(' ')}`);
    res.end('<html><body><a href="/api/users">users</a></body></html>');
  });
  await new Promise<void>((r) => target.listen(0, '127.0.0.1', r));
  const port = (target.address() as any).port;
  const targetUrl = `http://127.0.0.1:${port}/`;

  // 1. No auth → 401.
  {
    const app = await buildApp(makeDb());
    const r = await app.inject({ method: 'POST', url: '/api/swarm/scans', payload: {} });
    check('swarm: no auth → 401', r.statusCode === 401, r.statusCode);
    await app.close();
  }

  // 2. Missing authorization → 400.
  {
    const app = await buildApp(makeDb());
    const r = await app.inject({
      method: 'POST', url: '/api/swarm/scans',
      headers: { 'x-api-key': 'bs_test' },
      payload: { targetUrl, allowPrivateTargets: true },
    });
    check('swarm: missing authorization → 400', r.statusCode === 400, r.body.slice(0, 120));
    await app.close();
  }

  // 3. Free plan → 403 (active testing gated).
  {
    const app = await buildApp(makeDb('free'));
    const r = await app.inject({
      method: 'POST', url: '/api/swarm/scans',
      headers: { 'x-api-key': 'bs_test' },
      payload: { targetUrl, authorization: authz, allowPrivateTargets: true },
    });
    check('swarm: free plan → 403', r.statusCode === 403, r.body.slice(0, 120));
    await app.close();
  }

  // 4. Quota exceeded → 429 (pro: 1500 credits, 1490 used + 25 cost > 1500).
  {
    const seed: UsageEvent[] = [{ userId: 'u1', kind: 'scan', quantity: 1490, at: new Date().toISOString() }];
    const db = makeDb('pro', seed);
    const app = await buildApp(db);
    const r = await app.inject({
      method: 'POST', url: '/api/swarm/scans',
      headers: { 'x-api-key': 'bs_test' },
      payload: { targetUrl, authorization: authz, allowPrivateTargets: true },
    });
    check('swarm: quota exceeded → 429', r.statusCode === 429, r.body.slice(0, 120));
    await app.close();
  }

  // 5. Happy path: full lifecycle with the mock provider (sync: true).
  {
    const db = makeDb('pro');
    const app = await buildApp(db);
    const r = await app.inject({
      method: 'POST', url: '/api/swarm/scans',
      headers: { 'x-api-key': 'bs_test' },
      payload: {
        targetUrl, authorization: authz, allowPrivateTargets: true,
        specialists: ['recon', 'headers'],
        maxTokens: 8000, timeoutMinutes: 2,
        sync: true,
      },
    });
    const body = r.json();
    check('swarm: happy path → 200', r.statusCode === 200, `${r.statusCode} ${r.body.slice(0, 200)}`);
    check('swarm: scan record created', db.scans.length === 1 && !!body.scanId, db.scans.length);
    check('swarm: 25 credits charged', db.usage.some((u: UsageEvent) => u.quantity === 25), db.usage);
    check('swarm: findings persisted to db', db.findings.length === (body.findings?.length ?? -1), db.findings.length);
    check('swarm: scan marked completed', db.scans[0]?.status === 'completed', db.scans[0]?.status);
    const serialized = JSON.stringify(body.findings ?? []);
    // The planted Server header must have produced a disclosure finding,
    // or the checks below would pass on empty output and prove nothing.
    check(
      'swarm: secret-bearing target produced a disclosure finding',
      (body.findings ?? []).some(
        (f: any) => f.category === 'tech' && String(f.title ?? '').startsWith('Server technology disclosed'),
      ),
      (body.findings ?? []).map((f: any) => f.title),
    );
    // No planted token, whole or by shape prefix, may survive in the
    // serialized findings: evidence, title, description, or location.
    for (const token of SECRET_TOKENS) {
      check(`swarm: planted token absent from findings (${token.slice(0, 8)})`, !serialized.includes(token), serialized.slice(0, 300));
    }
    for (const shape of SECRET_SHAPES) {
      check(`swarm: no ${shape} secret shape in findings`, !serialized.includes(shape), serialized.slice(0, 300));
    }
    // reproSteps is not scrubbed by redactFindingEvidence (review H12),
    // so it gets its own check: a secret pasted there must never leak.
    const reproStepsText = (body.findings ?? []).flatMap((f: any) => f.reproSteps ?? []).join('\n');
    for (const shape of SECRET_SHAPES) {
      check(`swarm: no ${shape} secret shape in reproSteps`, !reproStepsText.includes(shape), reproStepsText.slice(0, 300));
    }
    console.log(`     scan=${body.scanId} findings=${body.findings?.length} workers=${body.workerReports?.length} tokens=${JSON.stringify(body.tokensUsed)}`);

    // 6. Asynchronous 202 Accepted + Polling endpoint test
    const rAsync = await app.inject({
      method: 'POST', url: '/api/swarm/scans',
      headers: { 'x-api-key': 'bs_test' },
      payload: {
        targetUrl, authorization: authz, allowPrivateTargets: true,
        specialists: ['recon'],
        maxTokens: 4000, timeoutMinutes: 1,
      },
    });
    check('swarm: async enqueued → 202', rAsync.statusCode === 202, rAsync.body);
    const asyncBody = rAsync.json();
    check('swarm: async returns jobId and scanId', !!asyncBody.jobId && !!asyncBody.scanId, asyncBody);
    check('swarm: async status is queued', asyncBody.status === 'queued', asyncBody.status);

    const poll = await app.inject({
      method: 'GET', url: `/api/swarm/scans/${asyncBody.jobId}`,
      headers: { 'x-api-key': 'bs_test' },
    });
    check('swarm: poll endpoint → 200', poll.statusCode === 200, poll.body);
    const pollBody = poll.json();
    check('swarm: poll body has status', typeof pollBody.status === 'string', pollBody.status);
    await app.close();

    // 7. Verify that swallowed errors are eliminated: failing provider aborts with error instead of fake 100 score
    const failingDb = makeDb('pro');
    const failingApp = Fastify();
    const failingProvider = {
      name: 'failing',
      async complete() {
        throw new Error('Gemini API error 400: Bad Request (Invalid Argument)');
      },
    };
    const failingRoutes = await loadSwarmRoutes();
    await failingRoutes(failingApp as any, { db: failingDb, queue: {} as any, provider: failingProvider as any });

    const rFailing = await failingApp.inject({
      method: 'POST', url: '/api/swarm/scans?sync=true',
      headers: { 'x-api-key': 'bs_test' },
      payload: {
        targetUrl, authorization: authz, allowPrivateTargets: true,
        specialists: ['recon'],
      },
    });
    check('swarm with failing LLM fails instead of fake 100 score', rFailing.statusCode >= 400, rFailing.statusCode);
    const failBody = rFailing.json();
    check('swarm failure surfaces actual LLM error message', failBody.error?.includes('Gemini API error 400') || failBody.error?.includes('recon'), failBody);
    check('failing scan marks status as failed', failingDb.scans[0]?.status === 'failed', failingDb.scans[0]?.status);
    await failingApp.close();
  }

  // 8. Branch 1 with saved keys but a null pool (saved row names an
  // unregistered provider) fails loudly with a 500 and never silently
  // runs on the platform provider (deps.provider is the MockProvider:
  // the old fallback would have completed with a 200).
  {
    const db = makeDb('pro');
    db.listUserAiKeys = async () => [{
      providerId: 'not-a-provider',
      encryptedKey: encryptSecret('test-' + 'x'.repeat(20)),
      keyHint: '****xxxx',
      baseUrl: 'https://example.com/v1',
      verifiedAt: new Date().toISOString(),
      discoveredModels: null,
    }];
    db.getUserLlmRouting = async () => null;
    const app = await buildApp(db);
    const r = await app.inject({
      method: 'POST', url: '/api/swarm/scans',
      headers: { 'x-api-key': 'bs_test' },
      payload: {
        targetUrl, authorization: authz, allowPrivateTargets: true,
        specialists: ['recon'], sync: true,
      },
    });
    check('swarm: saved keys with no registered provider → 500, never platform fallback', r.statusCode === 500, `${r.statusCode} ${r.body.slice(0, 300)}`);
    check('swarm: null-pool failure names the saved keys', /saved AI provider keys/i.test(r.body), r.body.slice(0, 300));
    check('swarm: null-pool failure marks the scan failed', db.scans[0]?.status === 'failed', db.scans[0]?.status);
    check('swarm: null-pool failure charges 0 credits', !db.usage.some((u: UsageEvent) => u.quantity > 0), db.usage);
    await app.close();
  }

  // 9. Legacy-Qwen user: Qwen runs alone, not wrapped in a FailoverProvider.
  // DashScope rejects the key (401); if a failover to the platform Gemini
  // key existed, a Gemini request would follow. The fetch spy proves none does.
  {
    const db = makeDb('pro');
    db.getAiKey = async () => ({
      encryptedAiKey: encryptSecret('test-' + 'q'.repeat(20)),
      aiProvider: 'qwen',
      aiBaseUrl: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1',
      aiKeyHint: '****qqqq',
      aiKeyUpdatedAt: new Date().toISOString(),
    });
    db.listUserAiKeys = async () => [];
    const realFetch = globalThis.fetch.bind(globalThis);
    let geminiFetches = 0;
    let qwenFetches = 0;
    globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      if (url.includes('generativelanguage.googleapis.com')) geminiFetches++;
      if (url.includes('dashscope')) {
        qwenFetches++;
        if (url.endsWith('/models')) {
          return new Response(JSON.stringify({ data: [] }), { status: 200 });
        }
        if (url.endsWith('/chat/completions')) {
          return new Response(
            JSON.stringify({ error: { message: 'Invalid API key', code: 'invalid_api_key' } }),
            { status: 401 },
          );
        }
      }
      return realFetch(input as never, init);
    }) as typeof fetch;
    try {
      const app = await buildApp(db);
      const r = await app.inject({
        method: 'POST', url: '/api/swarm/scans',
        headers: { 'x-api-key': 'bs_test' },
        payload: {
          targetUrl, authorization: authz, allowPrivateTargets: true,
          specialists: ['recon'], sync: true,
        },
      });
      check('swarm: legacy-Qwen failure aborts instead of failing over', r.statusCode >= 400, `${r.statusCode} ${r.body.slice(0, 300)}`);
      check('swarm: legacy-Qwen path attempted Qwen', qwenFetches > 0, qwenFetches);
      check('swarm: legacy-Qwen failure made zero Gemini calls', geminiFetches === 0, geminiFetches);
      check('swarm: legacy-Qwen failure names Qwen', /qwen/i.test(r.body), r.body.slice(0, 300));
      check('swarm: legacy-Qwen failure marks the scan failed', db.scans[0]?.status === 'failed', db.scans[0]?.status);
      await app.close();
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  // 10. Missing BYOK tables: a Postgres error on the key load (42P01) fails
  // loudly and names the missing table — it is never treated as "no BYOK
  // key saved", and no scan, charge, or provider call happens.
  {
    const db = makeDb('pro');
    const missingTable = new Error('relation "user_ai_keys" does not exist') as Error & { code?: string };
    missingTable.code = '42P01';
    db.listUserAiKeys = async () => { throw missingTable; };
    const realFetch = globalThis.fetch.bind(globalThis);
    let geminiFetches = 0;
    globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
      if (String(input).includes('generativelanguage.googleapis.com')) geminiFetches++;
      return realFetch(input as never, init);
    }) as typeof fetch;
    try {
      const app = await buildApp(db);
      const r = await app.inject({
        method: 'POST', url: '/api/swarm/scans',
        headers: { 'x-api-key': 'bs_test' },
        payload: {
          targetUrl, authorization: authz, allowPrivateTargets: true,
          specialists: ['recon'], sync: true,
        },
      });
      check('swarm: missing user_ai_keys table → 500 naming the table', r.statusCode === 500 && r.body.includes('user_ai_keys'), `${r.statusCode} ${r.body.slice(0, 300)}`);
      check('swarm: missing table error points at migrations 016–034', r.body.includes('016'), r.body.slice(0, 300));
      check('swarm: missing table creates no scan record', db.scans.length === 0, db.scans.length);
      check('swarm: missing table charges no credits', db.usage.length === 0, db.usage);
      check('swarm: missing table made zero Gemini calls', geminiFetches === 0, geminiFetches);
      await app.close();
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  // 10b. Same loud failure when the routing table is the missing one.
  {
    const db = makeDb('pro');
    db.listUserAiKeys = async () => [{
      providerId: 'kimi',
      encryptedKey: encryptSecret('test-' + 'k'.repeat(20)),
      keyHint: '****kkkk',
      baseUrl: 'https://api.moonshot.ai/v1',
      verifiedAt: new Date().toISOString(),
      discoveredModels: null,
    }];
    const missingRouting = new Error('relation "user_llm_routing" does not exist') as Error & { code?: string };
    missingRouting.code = '42P01';
    db.getUserLlmRouting = async () => { throw missingRouting; };
    const app = await buildApp(db);
    const r = await app.inject({
      method: 'POST', url: '/api/swarm/scans',
      headers: { 'x-api-key': 'bs_test' },
      payload: {
        targetUrl, authorization: authz, allowPrivateTargets: true,
        specialists: ['recon'], sync: true,
      },
    });
    check('swarm: missing user_llm_routing table → 500 naming the table', r.statusCode === 500 && r.body.includes('user_llm_routing'), `${r.statusCode} ${r.body.slice(0, 300)}`);
    check('swarm: missing routing table creates no scan record', db.scans.length === 0, db.scans.length);
    await app.close();
  }

  // 11. Legitimate zero rows: the key query resolves empty, so the swarm
  // proceeds on the platform provider (branch 4) exactly as before.
  {
    const db = makeDb('pro');
    db.listUserAiKeys = async () => [];
    db.getUserLlmRouting = async () => null;
    const app = await buildApp(db);
    const r = await app.inject({
      method: 'POST', url: '/api/swarm/scans',
      headers: { 'x-api-key': 'bs_test' },
      payload: {
        targetUrl, authorization: authz, allowPrivateTargets: true,
        specialists: ['recon', 'headers'], sync: true,
      },
    });
    check('swarm: 0 saved keys → platform fallback proceeds (200)', r.statusCode === 200, `${r.statusCode} ${r.body.slice(0, 300)}`);
    check('swarm: 0 saved keys → scan completed', db.scans[0]?.status === 'completed', db.scans[0]?.status);
    await app.close();
  }

  target.closeAllConnections();
  target.close();
  await new Promise((r) => setTimeout(r, 100));
  if (failures > 0) { console.error(`${failures} swarm test(s) failed`); process.exit(1); }
  console.log('ALL SWARM TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('swarm test crashed', e); process.exit(1); });

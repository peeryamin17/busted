import { createServer } from 'node:http';

process.env['RENDER'] = 'true';
process.env['ALLOW_PRIVATE_TARGETS'] = '1';
process.env['KEY_ENCRYPTION_SECRET'] = 'test-secret-must-be-min-16-characters!';
process.env['NODE_ENV'] = 'test';

let failures = 0;
function check(name: string, ok: boolean, extra?: unknown) {
  if (ok) console.log('PASS', name);
  else {
    failures++;
    console.error('FAIL', name, extra ?? '');
  }
}

const KIMI_KEY = 'sk-kimi-test-key-1234567890';
const CLAUDE_KEY = 'sk-ant-test-key-1234567890';

function chatOk(text: string) {
  return new Response(
    JSON.stringify({
      choices: [{ message: { role: 'assistant', content: text }, finish_reason: 'stop' }],
      usage: { prompt_tokens: 100, completion_tokens: 25 },
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

async function main() {
  const Fastify = (await import('fastify')).default;
  const { MemoryDatabase } = await import('../src/db/db.js');
  const { aiKeyRoutes } = await import('../src/routes/aiKey.js');
  const { healthRoutes, APP_VERSION } = await import('../src/routes/health.js');
  const { swarmRoutes } = await import('../src/routes/multiagent.js');
  const { MockProvider } = await import('../src/llm/mock.js');
  const { generateSessionToken, hashSessionToken } = await import('../src/auth/session.js');
  const { generateApiKey } = await import('../src/auth/auth.js');
  const { decryptSecret } = await import('../src/lib/crypto.js');
  const { monthStartIso } = await import('../src/auth/usage.js');

  // Provider verification + swarm LLM calls are answered in-process; the
  // local target server is reached through the real fetch.
  const realFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? 'GET').toUpperCase();
    if (url === 'https://generativelanguage.googleapis.com/v1beta/models') {
      return new Response(JSON.stringify({ models: [] }), { status: 200 });
    }
    if (url === 'https://api.moonshot.ai/v1/models') {
      return new Response(JSON.stringify({ data: [] }), { status: 200 });
    }
    if (url === 'https://api.anthropic.com/v1/messages' && method === 'POST') {
      const body = JSON.parse(String(init?.body ?? '{}')) as { max_tokens?: number };
      if (body.max_tokens === 1) {
        return new Response(
          JSON.stringify({
            content: [{ type: 'text', text: 'pong' }],
            usage: { input_tokens: 1, output_tokens: 1 },
          }),
          { status: 200 },
        );
      }
    }
    if (url === 'https://api.moonshot.ai/v1/chat/completions' && method === 'POST') {
      const body = JSON.parse(String(init?.body ?? '{}')) as {
        messages?: Array<{ content?: string }>;
      };
      const text = (body.messages ?? []).map((m) => m.content ?? '').join('\n');
      if (text.includes('GOAL-DECOMPOSITION-REQUEST')) {
        return chatOk(JSON.stringify({ goals: ['Check security headers'], allow: [], deny: [] }));
      }
      if (text.includes('CONDITIONAL specialists')) {
        return chatOk(JSON.stringify({ specialists: [], rationale: 'none needed' }));
      }
      if (text.includes('MODE: PLANNING')) {
        return chatOk(
          JSON.stringify([
            { id: 't1', name: 'Fetch target homepage', tool: 'fetch_url', args: { url: 'TARGET' }, priority: 1, rationale: 'Baseline.' },
            { id: 't2', name: 'Evaluate security headers', tool: 'check_security_headers', args: { url: 'TARGET' }, priority: 2, rationale: 'Headers.' },
          ]),
        );
      }
      if (text.includes('MODE: TRIAGE')) {
        return chatOk(JSON.stringify({ triage: 'no-finding', reason: 'mock triage: clean' }));
      }
      if (text.includes('MODE: FULL VERDICT')) {
        return chatOk(JSON.stringify({ verdict: 'no-finding', trapProbability: 0 }));
      }
      if (text.includes('Review these findings')) {
        return chatOk(JSON.stringify({ reviews: [], chains: [] }));
      }
      if (text.includes('FINDINGS TO VALIDATE')) {
        return chatOk(JSON.stringify({ validations: [] }));
      }
      if (text.includes('executive summary')) {
        return chatOk('Mock executive summary: clean run.');
      }
      return chatOk(JSON.stringify({ note: 'mock' }));
    }
    return realFetch(input as never, init);
  }) as typeof fetch;

  // Local target for the swarm run.
  const target = createServer((_req, res) => {
    res.setHeader('content-type', 'text/html');
    res.end('<html><body><a href="/api/users">users</a></body></html>');
  });
  await new Promise<void>((r) => target.listen(0, '127.0.0.1', r));
  const port = (target.address() as { port: number }).port;
  const targetUrl = `http://127.0.0.1:${port}/`;

  try {
    const db = new MemoryDatabase();
    const user = await db.createUser('keyuser@example.com', 'unused-hash');
    await db.setUserPlan(user.id, 'pro');
    const token = generateSessionToken();
    await db.createSession(user.id, hashSessionToken(token), new Date(Date.now() + 3600_000).toISOString());
    const cookie = `bs_session=${token}`;
    const { key: bsKey, keyHash, keyPrefix } = generateApiKey();
    await db.createApiKey(user.id, 'extension', keyHash, keyPrefix);

    const freeUser = await db.createUser('freeuser@example.com', 'unused-hash');
    const freeToken = generateSessionToken();
    await db.createSession(freeUser.id, hashSessionToken(freeToken), new Date(Date.now() + 3600_000).toISOString());
    const freeCookie = `bs_session=${freeToken}`;

    const app = Fastify();
    const deps = { db, queue: {} as never, provider: new MockProvider() as never };
    await aiKeyRoutes(app as never, deps);
    await healthRoutes(app as never, deps);
    await swarmRoutes(app as never, deps);

    // 1. Capabilities in cloud runtime
    const capsRes = await app.inject({ method: 'GET', url: '/api/v1/capabilities' });
    check('capabilities → 200', capsRes.statusCode === 200, capsRes.body);
    const caps = JSON.parse(capsRes.body) as {
      version: string;
      runtime: string;
      llmProviders: Array<{ id: string; label: string; mode: string; available: boolean; reason?: string; defaultModels: Record<string, string> }>;
      engines: Array<{ id: string; available: boolean }>;
    };
    check('capabilities version matches package.json (0.3.0)', caps.version === APP_VERSION && caps.version === '0.3.0', caps.version);
    check('capabilities runtime is cloud', caps.runtime === 'cloud', caps.runtime);
    check('capabilities lists all 8 providers', caps.llmProviders.length === 8, caps.llmProviders.map((p) => p.id));
    for (const id of ['gemini', 'claude', 'qwen', 'kimi', 'glm', 'deepseek', 'openrouter', 'ollama']) {
      check(`capabilities lists ${id}`, caps.llmProviders.some((p) => p.id === id));
    }
    const ollama = caps.llmProviders.find((p) => p.id === 'ollama');
    check('capabilities ollama unavailable in cloud', ollama?.available === false, ollama);
    check('capabilities ollama reason is exact', ollama?.reason === 'Requires local backend', ollama?.reason);
    check('capabilities lists all 5 engines', caps.engines.length === 5, caps.engines);
    for (const id of ['httpx', 'katana', 'nuclei', 'whatweb', 'nikto']) {
      const e = caps.engines.find((x) => x.id === id);
      check(`capabilities lists engine ${id}`, !!e && typeof e.available === 'boolean', e);
    }

    // 2. Unauthenticated access is rejected
    const unauth = await app.inject({ method: 'GET', url: '/api/v1/ai-keys' });
    check('unauthenticated GET /api/v1/ai-keys → 401', unauth.statusCode === 401, unauth.statusCode);

    // 3. Ollama rejected in cloud runtime
    const ollamaPost = await app.inject({
      method: 'POST',
      url: '/api/v1/ai-keys',
      headers: { cookie },
      payload: { providerId: 'ollama', apiKey: '' },
    });
    check('POST ollama in cloud → 400', ollamaPost.statusCode === 400, ollamaPost.body);

    // 4. Mock keys rejected
    const mockPost = await app.inject({
      method: 'POST',
      url: '/api/v1/ai-keys',
      headers: { cookie },
      payload: { providerId: 'kimi', apiKey: 'mock-kimi-key-1234567890' },
    });
    check('POST mock-* key → 400', mockPost.statusCode === 400, mockPost.body);
    check('mock key stores nothing', (await db.listUserAiKeys(user.id)).length === 0);

    // 5. Unknown provider and SSRF base URL rejected
    const unknownPost = await app.inject({
      method: 'POST',
      url: '/api/v1/ai-keys',
      headers: { cookie },
      payload: { providerId: 'anthropic', apiKey: KIMI_KEY },
    });
    check('POST unknown provider → 400', unknownPost.statusCode === 400);
    const ssrfPost = await app.inject({
      method: 'POST',
      url: '/api/v1/ai-keys',
      headers: { cookie },
      payload: { providerId: 'kimi', apiKey: KIMI_KEY, baseUrl: 'https://evil.com/v1' },
    });
    check('POST disallowed base URL → 400', ssrfPost.statusCode === 400, ssrfPost.body);

    // 6. Valid Kimi key saves encrypted, hint is last-4 only
    const kimiPost = await app.inject({
      method: 'POST',
      url: '/api/v1/ai-keys',
      headers: { cookie },
      payload: { providerId: 'kimi', apiKey: KIMI_KEY },
    });
    check('POST valid kimi key → 200', kimiPost.statusCode === 200, kimiPost.body);
    const kimiBody = JSON.parse(kimiPost.body) as { keyHint: string; hasByok: boolean };
    check('kimi save hint is ****7890', kimiBody.keyHint === '****7890', kimiBody.keyHint);
    check('kimi save reports hasByok', kimiBody.hasByok === true);
    check('kimi save response never contains the plaintext key', !kimiPost.body.includes(KIMI_KEY));
    const storedRows = await db.listUserAiKeys(user.id);
    check('one key stored', storedRows.length === 1, storedRows.length);
    check('stored key is encrypted, not plaintext', storedRows[0].encryptedKey !== KIMI_KEY);
    check('stored key decrypts to the submitted key', decryptSecret(storedRows[0].encryptedKey) === KIMI_KEY);

    // 7. Claude key saves too
    const claudePost = await app.inject({
      method: 'POST',
      url: '/api/v1/ai-keys',
      headers: { cookie },
      payload: { providerId: 'claude', apiKey: CLAUDE_KEY },
    });
    check('POST valid claude key → 200', claudePost.statusCode === 200, claudePost.body);

    // 8. GET never returns plaintext keys
    const getRes = await app.inject({ method: 'GET', url: '/api/v1/ai-keys', headers: { cookie } });
    check('GET /api/v1/ai-keys → 200', getRes.statusCode === 200);
    const getBody = JSON.parse(getRes.body) as {
      keys: Array<{ providerId: string; keyHint: string; baseUrl: string; verifiedAt: string }>;
      routing: Record<string, unknown>;
      hasByok: boolean;
    };
    check('GET lists both saved providers', getBody.keys.length === 2, getBody.keys);
    check('GET hasByok is true', getBody.hasByok === true);
    check('GET body never contains either plaintext key', !getRes.body.includes(KIMI_KEY) && !getRes.body.includes(CLAUDE_KEY));
    check('GET key hints are masked', getBody.keys.every((k) => k.keyHint.startsWith('****')), getBody.keys);

    // 9. Routing update, then a free user without that key is refused
    const routingPut = await app.inject({
      method: 'PUT',
      url: '/api/v1/ai-keys/routing',
      headers: { cookie },
      payload: { workerProvider: 'kimi', workerModel: 'moonshot-v1-32k', reasoningProvider: 'claude', reasoningModel: 'claude-sonnet-4-5' },
    });
    check('PUT routing with owned keys → 200', routingPut.statusCode === 200, routingPut.body);
    const routingBody = JSON.parse(routingPut.body) as { routing: { workerProvider: string; reasoningProvider: string } };
    check('routing worker is kimi', routingBody.routing.workerProvider === 'kimi');
    check('routing reasoning is claude', routingBody.routing.reasoningProvider === 'claude');
    const freeRouting = await app.inject({
      method: 'PUT',
      url: '/api/v1/ai-keys/routing',
      headers: { cookie: freeCookie },
      payload: { workerProvider: 'deepseek' },
    });
    check('PUT routing for unowned provider without platform credits → 400', freeRouting.statusCode === 400, freeRouting.body);

    // 10. Deleting the active worker provider resets routing to a remaining provider
    const delKimi = await app.inject({
      method: 'DELETE',
      url: '/api/v1/ai-keys/kimi',
      headers: { cookie },
    });
    check('DELETE kimi → 200', delKimi.statusCode === 200, delKimi.body);
    const delBody = JSON.parse(delKimi.body) as { deleted: boolean; hasByok: boolean };
    check('DELETE reports deleted and hasByok true (claude remains)', delBody.deleted === true && delBody.hasByok === true, delBody);
    const afterDel = JSON.parse(
      (await app.inject({ method: 'GET', url: '/api/v1/ai-keys', headers: { cookie } })).body,
    ) as { routing: { workerProvider: string; reasoningProvider: string } };
    check('routing worker resets to remaining provider after delete', afterDel.routing.workerProvider === 'claude', afterDel.routing);
    const delAgain = await app.inject({
      method: 'DELETE',
      url: '/api/v1/ai-keys/kimi',
      headers: { cookie },
    });
    check('DELETE missing provider → 404', delAgain.statusCode === 404, delAgain.statusCode);

    // 11. Paired bs_ user with a saved Kimi key: swarm waives the 25-credit charge
    // and routes Worker/Reasoning calls through the stored key.
    const kimiAgain = await app.inject({
      method: 'POST',
      url: '/api/v1/ai-keys',
      headers: { cookie },
      payload: { providerId: 'kimi', apiKey: KIMI_KEY },
    });
    check('re-save kimi key → 200', kimiAgain.statusCode === 200, kimiAgain.body);
    const routingAgain = await app.inject({
      method: 'PUT',
      url: '/api/v1/ai-keys/routing',
      headers: { cookie },
      payload: { workerProvider: 'kimi', workerModel: 'moonshot-v1-32k', reasoningProvider: 'kimi', reasoningModel: 'kimi-k2-0711-preview' },
    });
    check('routing back to kimi → 200', routingAgain.statusCode === 200, routingAgain.body);

    const usedBefore = await db.sumUsageSince(user.id, 'scan', monthStartIso());
    const swarmRes = await app.inject({
      method: 'POST',
      url: '/api/swarm/scans',
      headers: { 'x-api-key': bsKey },
      payload: {
        targetUrl,
        authorization: { type: 'ownership', statement: 'I own this local test server and authorize testing.', confirmed: true },
        sync: true,
        specialists: ['recon', 'headers'],
      },
    });
    check('paired bs_ swarm with saved kimi key → 200', swarmRes.statusCode === 200, { status: swarmRes.statusCode, body: swarmRes.body.slice(0, 500) });
    const usedAfter = await db.sumUsageSince(user.id, 'scan', monthStartIso());
    check('swarm with verified BYOK key charges 0 credits', usedAfter === usedBefore, { before: usedBefore, after: usedAfter });
    if (swarmRes.statusCode === 200) {
      const swarmBody = JSON.parse(swarmRes.body) as {
        status: string;
        workerReports: Array<{
          specialistId: string;
          providerId?: string | null;
          model?: string | null;
          llmProviders?: Array<{ providerId: string; model: string; inputTokens: number; outputTokens: number }>;
        }>;
        testsRun: number;
      };
      check('swarm completed', swarmBody.status === 'completed', swarmBody.status);
      check('swarm ran tests', swarmBody.testsRun > 0, swarmBody.testsRun);
      const recon = swarmBody.workerReports.find((r) => r.specialistId === 'recon');
      check('recon report records providerId kimi', recon?.providerId === 'kimi', recon);
      check('recon report records a model', typeof recon?.model === 'string' && (recon?.model?.length ?? 0) > 0, recon?.model);
      const calls = (swarmBody.workerReports ?? []).flatMap((r) => r.llmProviders ?? []);
      check('swarm recorded per-call provider telemetry', calls.length > 0, calls.length);
      check(
        'all recorded token counts are finite numbers',
        calls.every((c) => Number.isFinite(c.inputTokens) && Number.isFinite(c.outputTokens) && c.inputTokens >= 0 && c.outputTokens >= 0),
        calls,
      );
      check('all recorded calls went through kimi', calls.every((c) => c.providerId === 'kimi'), calls.map((c) => c.providerId));
    }

    await app.close();
  } finally {
    target.close();
    globalThis.fetch = realFetch;
  }

  if (failures > 0) {
    console.error(`\nFAILED: ${failures} checks failed in ai-keys-capabilities.test.ts`);
    process.exit(1);
  } else {
    console.log('\nALL AI KEYS & CAPABILITIES TESTS PASSED.');
  }
}

main().catch((err) => {
  console.error('Unhandled test failure:', err);
  process.exit(1);
});

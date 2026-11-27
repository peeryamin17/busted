import process from 'node:process';
import dns from 'node:dns/promises';

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
const BAD_KIMI_KEY = 'sk-bad-kimi-key-1234567890';
const GEMINI_KEY = 'test-' + 'g'.repeat(20);
const CLAUDE_KEY = 'sk-ant-test-key-1234567890';
const QWEN_KEY = 'test-' + 'q'.repeat(20);
const DEEPSEEK_KEY = 'sk-deepseek-test-key-123456';
const GLM_KEY = 'test-' + 'z'.repeat(20);
const OPENAI_KEY = 'sk-proj-test-key-1234567890';
const OMNIROUTE_KEY = 'sk-omniroute-test-key-1234567890';
const OMNIROUTE_URL = 'https://omni.example.com/v1';

// Mutable so the refresh test can change what the provider returns.
const modelLists: Record<string, unknown> = {
  'https://api.moonshot.ai/v1/models': {
    data: [
      { id: 'moonshot-v1-32k' },
      { id: 'kimi-k2-0711-preview' },
      { id: 'moonshot-v1-32k' },
      { id: 42 },
    ],
  },
  'https://generativelanguage.googleapis.com/v1beta/models': {
    models: [
      { name: 'models/gemini-2.5-flash' },
      { name: 'models/gemini-2.5-pro' },
      { name: 'gemini-2.0-flash' },
    ],
  },
  'https://dashscope-intl.aliyuncs.com/compatible-mode/v1/models': {
    data: [{ id: 'qwen-plus' }, { id: 'qwen-max' }, { id: 'qwen-plus' }],
  },
  'https://open.bigmodel.cn/api/paas/v4/models': { data: [] },
  'https://api.openai.com/v1/models': {
    data: [{ id: 'gpt-6-luna' }, { id: 'gpt-6.2-astra' }, { id: 'gpt-6-luna' }],
  },
  'https://omni.example.com/v1/models': {
    data: [{ id: 'auto' }, { id: 'auto/coding' }, { id: 'openai/gpt-6-luna' }, { id: 'auto' }],
  },
};
let kimiRejectAll = false;

async function main() {
  const Fastify = (await import('fastify')).default;
  const { MemoryDatabase } = await import('../src/db/db.js');
  const {
    aiKeyRoutes,
    verifyProviderKey,
    verifyGeminiKey,
    verifyQwenKey,
  } = await import('../src/routes/aiKey.js');
  const { generateSessionToken, hashSessionToken } = await import('../src/auth/session.js');
  const { encryptSecret } = await import('../src/lib/crypto.js');

  const realFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
    const url = String(input);
    const method = (init?.method ?? 'GET').toUpperCase();
    if (url === 'https://api.moonshot.ai/v1/models') {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      if (kimiRejectAll || headers['Authorization'] === `Bearer ${BAD_KIMI_KEY}`) {
        return new Response(JSON.stringify({ error: { message: 'Incorrect API key provided.' } }), { status: 401 });
      }
      return new Response(JSON.stringify(modelLists[url]), { status: 200 });
    }
    if (url === 'https://generativelanguage.googleapis.com/v1beta/models') {
      return new Response(JSON.stringify(modelLists[url]), { status: 200 });
    }
    if (url === 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1/models') {
      return new Response(JSON.stringify(modelLists[url]), { status: 200 });
    }
    if (url === 'https://api.deepseek.com/v1/models') {
      return new Response('not-json{{{', { status: 200, headers: { 'content-type': 'text/plain' } });
    }
    if (url === 'https://open.bigmodel.cn/api/paas/v4/models') {
      return new Response(JSON.stringify(modelLists[url]), { status: 200 });
    }
    if (url === 'https://api.openai.com/v1/models') {
      return new Response(JSON.stringify(modelLists[url]), { status: 200 });
    }
    if (url === 'https://omni.example.com/v1/models') {
      return new Response(JSON.stringify(modelLists[url]), { status: 200 });
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
    return realFetch(input as never, init);
  }) as typeof fetch;

  // The OmniRoute save route resolves the gateway host: answer it
  // in-process so no real DNS runs. omni.example.com is public,
  // internal.example.com resolves to a private address.
  const originalLookup = dns.lookup;
  dns.lookup = (async (hostname: string, options?: unknown) => {
    if (hostname === 'omni.example.com') return [{ address: '203.0.113.10', family: 4 }];
    if (hostname === 'internal.example.com') return [{ address: '10.0.0.5', family: 4 }];
    return (originalLookup as (h: string, o?: unknown) => unknown)(hostname, options);
  }) as typeof dns.lookup;

  try {
    const db = new MemoryDatabase();
    const user = await db.createUser('models-user@example.com', 'unused-hash');
    await db.setUserPlan(user.id, 'pro');
    const token = generateSessionToken();
    await db.createSession(user.id, hashSessionToken(token), new Date(Date.now() + 3600_000).toISOString());
    const cookie = `bs_session=${token}`;

    const app = Fastify();
    await aiKeyRoutes(app as never, { db, queue: {} as never, provider: {} as never });

    type KeyOut = {
      providerId: string;
      keyHint: string;
      baseUrl: string;
      verifiedAt: string;
      discoveredModels: string[] | null;
    };

    // 1. Direct verify calls return the discovered lists.
    const kimiCheck = await verifyProviderKey('kimi', KIMI_KEY, 'https://api.moonshot.ai/v1');
    check('verifyProviderKey kimi returns deduped model ids', kimiCheck.ok === true
      && JSON.stringify(kimiCheck.models) === JSON.stringify(['moonshot-v1-32k', 'kimi-k2-0711-preview']), kimiCheck);
    const geminiCheck = await verifyGeminiKey(GEMINI_KEY);
    check('verifyGeminiKey strips the models/ prefix', geminiCheck.ok === true
      && JSON.stringify(geminiCheck.models) === JSON.stringify(['gemini-2.5-flash', 'gemini-2.5-pro', 'gemini-2.0-flash']), geminiCheck);
    const qwenCheck = await verifyQwenKey(QWEN_KEY, 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1');
    check('verifyQwenKey returns deduped model ids', qwenCheck.ok === true
      && JSON.stringify(qwenCheck.models) === JSON.stringify(['qwen-plus', 'qwen-max']), qwenCheck);
    const claudeCheck = await verifyProviderKey('claude', CLAUDE_KEY, 'https://api.anthropic.com/v1');
    check('verifyProviderKey claude is ok with null models', claudeCheck.ok === true && claudeCheck.models === null, claudeCheck);
    const openaiCheck = await verifyProviderKey('openai', OPENAI_KEY, 'https://api.openai.com/v1');
    check('verifyProviderKey openai returns deduped GPT model ids', openaiCheck.ok === true
      && JSON.stringify(openaiCheck.models) === JSON.stringify(['gpt-6-luna', 'gpt-6.2-astra']), openaiCheck);

    // 2. POST persists the list and returns it; GET returns it per key.
    const kimiPost = await app.inject({
      method: 'POST', url: '/api/v1/ai-keys',
      headers: { cookie }, payload: { providerId: 'kimi', apiKey: KIMI_KEY },
    });
    check('POST kimi key → 200', kimiPost.statusCode === 200, kimiPost.body);
    const kimiBody = JSON.parse(kimiPost.body) as KeyOut;
    check('POST kimi response carries discoveredModels', JSON.stringify(kimiBody.discoveredModels) === JSON.stringify(['moonshot-v1-32k', 'kimi-k2-0711-preview']), kimiBody);
    check('POST response never contains the plaintext key', !kimiPost.body.includes(KIMI_KEY));
    const kimiStored = (await db.listUserAiKeys(user.id)).find((r) => r.providerId === 'kimi');
    check('stored kimi row holds the model list', JSON.stringify(kimiStored?.discoveredModels) === JSON.stringify(['moonshot-v1-32k', 'kimi-k2-0711-preview']), kimiStored);
    const getAfterKimi = JSON.parse(
      (await app.inject({ method: 'GET', url: '/api/v1/ai-keys', headers: { cookie } })).body,
    ) as { keys: KeyOut[] };
    const kimiGet = getAfterKimi.keys.find((k) => k.providerId === 'kimi');
    check('GET returns the kimi model list', JSON.stringify(kimiGet?.discoveredModels) === JSON.stringify(['moonshot-v1-32k', 'kimi-k2-0711-preview']), kimiGet);

    // 3. Gemini shape through the route: prefix stripped.
    const geminiPost = await app.inject({
      method: 'POST', url: '/api/v1/ai-keys',
      headers: { cookie }, payload: { providerId: 'gemini', apiKey: GEMINI_KEY },
    });
    check('POST gemini key → 200', geminiPost.statusCode === 200, geminiPost.body);
    const geminiBody = JSON.parse(geminiPost.body) as KeyOut;
    check('POST gemini response strips the models/ prefix', JSON.stringify(geminiBody.discoveredModels) === JSON.stringify(['gemini-2.5-flash', 'gemini-2.5-pro', 'gemini-2.0-flash']), geminiBody);

    // 4. Claude has no list endpoint: saves fine with null models.
    const claudePost = await app.inject({
      method: 'POST', url: '/api/v1/ai-keys',
      headers: { cookie }, payload: { providerId: 'claude', apiKey: CLAUDE_KEY },
    });
    check('POST claude key → 200', claudePost.statusCode === 200, claudePost.body);
    const claudeBody = JSON.parse(claudePost.body) as KeyOut;
    check('POST claude response has null discoveredModels', claudeBody.discoveredModels === null, claudeBody);
    const claudeStored = (await db.listUserAiKeys(user.id)).find((r) => r.providerId === 'claude');
    check('stored claude row has null discoveredModels', claudeStored?.discoveredModels === null, claudeStored);

    // 5. Unparsable list on a valid key still saves, with null models.
    const deepseekPost = await app.inject({
      method: 'POST', url: '/api/v1/ai-keys',
      headers: { cookie }, payload: { providerId: 'deepseek', apiKey: DEEPSEEK_KEY },
    });
    check('POST deepseek with unparsable list → 200', deepseekPost.statusCode === 200, deepseekPost.body);
    const deepseekBody = JSON.parse(deepseekPost.body) as KeyOut;
    check('unparsable list saves with null discoveredModels', deepseekBody.discoveredModels === null, deepseekBody);

    // 6. Empty list on a valid key also saves with null models.
    const glmPost = await app.inject({
      method: 'POST', url: '/api/v1/ai-keys',
      headers: { cookie }, payload: { providerId: 'glm', apiKey: GLM_KEY },
    });
    check('POST glm with empty list → 200', glmPost.statusCode === 200, glmPost.body);
    const glmBody = JSON.parse(glmPost.body) as KeyOut;
    check('empty list saves with null discoveredModels', glmBody.discoveredModels === null, glmBody);

    // 7. Invalid key → 400, nothing stored.
    const badPost = await app.inject({
      method: 'POST', url: '/api/v1/ai-keys',
      headers: { cookie }, payload: { providerId: 'kimi', apiKey: BAD_KIMI_KEY },
    });
    check('POST rejected kimi key → 400', badPost.statusCode === 400, badPost.body);
    // The earlier valid kimi row is still the only kimi row; no second row appears.
    const kimiRows = (await db.listUserAiKeys(user.id)).filter((r) => r.providerId === 'kimi');
    check('rejected key does not add a row', kimiRows.length === 1, kimiRows.length);

    // 8. Refresh re-verifies and updates the list and verified_at.
    const savedVerifiedAt = kimiBody.verifiedAt;
    modelLists['https://api.moonshot.ai/v1/models'] = {
      data: [{ id: 'moonshot-v1-32k' }, { id: 'moonshot-v1-8k' }],
    };
    const refreshRes = await app.inject({
      method: 'POST', url: '/api/v1/ai-keys/kimi/refresh', headers: { cookie },
    });
    check('POST refresh kimi → 200', refreshRes.statusCode === 200, refreshRes.body);
    const refreshBody = JSON.parse(refreshRes.body) as {
      providerId: string; discoveredModels: string[] | null; verifiedAt: string;
    };
    check('refresh returns the new model list', JSON.stringify(refreshBody.discoveredModels) === JSON.stringify(['moonshot-v1-32k', 'moonshot-v1-8k']), refreshBody);
    check('refresh bumps verified_at', new Date(refreshBody.verifiedAt).getTime() >= new Date(savedVerifiedAt).getTime(), { before: savedVerifiedAt, after: refreshBody.verifiedAt });
    const kimiAfterRefresh = (await db.listUserAiKeys(user.id)).find((r) => r.providerId === 'kimi');
    check('refresh persists the new list', JSON.stringify(kimiAfterRefresh?.discoveredModels) === JSON.stringify(['moonshot-v1-32k', 'moonshot-v1-8k']), kimiAfterRefresh);
    check('refresh persists the new verified_at', kimiAfterRefresh?.verifiedAt === refreshBody.verifiedAt, kimiAfterRefresh);

    // 9. Refresh when the provider now rejects the key → 400, row untouched.
    kimiRejectAll = true;
    const failedRefresh = await app.inject({
      method: 'POST', url: '/api/v1/ai-keys/kimi/refresh', headers: { cookie },
    });
    check('refresh with a now-rejected key → 400', failedRefresh.statusCode === 400, failedRefresh.body);
    const kimiAfterFailed = (await db.listUserAiKeys(user.id)).find((r) => r.providerId === 'kimi');
    check('failed refresh leaves the stored list untouched', JSON.stringify(kimiAfterFailed?.discoveredModels) === JSON.stringify(['moonshot-v1-32k', 'moonshot-v1-8k']), kimiAfterFailed);
    check('failed refresh leaves verified_at untouched', kimiAfterFailed?.verifiedAt === refreshBody.verifiedAt, kimiAfterFailed);
    kimiRejectAll = false;

    // 10. Refresh with no saved key → 404; unknown provider → 400.
    const emptyUser = await db.createUser('no-keys@example.com', 'unused-hash');
    const emptyToken = generateSessionToken();
    await db.createSession(emptyUser.id, hashSessionToken(emptyToken), new Date(Date.now() + 3600_000).toISOString());
    const emptyCookie = `bs_session=${emptyToken}`;
    const missingRefresh = await app.inject({
      method: 'POST', url: '/api/v1/ai-keys/deepseek/refresh', headers: { cookie: emptyCookie },
    });
    check('refresh with no saved key → 404', missingRefresh.statusCode === 404, missingRefresh.body);
    const unknownRefresh = await app.inject({
      method: 'POST', url: '/api/v1/ai-keys/anthropic/refresh', headers: { cookie },
    });
    check('refresh for unknown provider → 400', unknownRefresh.statusCode === 400, unknownRefresh.body);

    // 11. Ollama refresh → 400, row untouched.
    await db.upsertUserAiKey(user.id, {
      providerId: 'ollama',
      encryptedKey: encryptSecret('ollama-local'),
      keyHint: 'local',
      baseUrl: 'http://127.0.0.1:11434/v1',
      verifiedAt: new Date().toISOString(),
      discoveredModels: null,
    });
    const ollamaRefresh = await app.inject({
      method: 'POST', url: '/api/v1/ai-keys/ollama/refresh', headers: { cookie },
    });
    check('refresh ollama → 400', ollamaRefresh.statusCode === 400, ollamaRefresh.body);
    const ollamaRow = (await db.listUserAiKeys(user.id)).find((r) => r.providerId === 'ollama');
    check('ollama refresh leaves the row in place', ollamaRow?.keyHint === 'local' && ollamaRow.discoveredModels === null, ollamaRow);

    // 12. OpenAI end to end on a fresh user: sk-proj- key saves, the
    // discovered GPT list persists, and the first-key auto-route points
    // both tiers at the GPT defaults.
    const openaiUser = await db.createUser('openai-user@example.com', 'unused-hash');
    const openaiToken = generateSessionToken();
    await db.createSession(openaiUser.id, hashSessionToken(openaiToken), new Date(Date.now() + 3600_000).toISOString());
    const openaiCookie = `bs_session=${openaiToken}`;
    const openaiPost = await app.inject({
      method: 'POST', url: '/api/v1/ai-keys',
      headers: { cookie: openaiCookie }, payload: { providerId: 'openai', apiKey: OPENAI_KEY },
    });
    check('POST openai key → 200', openaiPost.statusCode === 200, openaiPost.body);
    const openaiBody = JSON.parse(openaiPost.body) as KeyOut & {
      routingAutoSet: boolean;
      routing: { workerProvider: string; workerModel: string; reasoningProvider: string; reasoningModel: string };
    };
    check('POST openai response carries discoveredModels', JSON.stringify(openaiBody.discoveredModels) === JSON.stringify(['gpt-6-luna', 'gpt-6.2-astra']), openaiBody);
    check('POST openai response never contains the plaintext key', !openaiPost.body.includes(OPENAI_KEY));
    check('POST openai saves against the api.openai.com base URL', openaiBody.baseUrl === 'https://api.openai.com/v1', openaiBody);
    check('first openai key auto-routes both tiers to openai', openaiBody.routingAutoSet === true
      && openaiBody.routing.workerProvider === 'openai' && openaiBody.routing.reasoningProvider === 'openai', openaiBody.routing);
    check('openai auto-route worker model is gpt-6-luna', openaiBody.routing.workerModel === 'gpt-6-luna', openaiBody.routing);
    check('openai auto-route reasoning model is gpt-6.2-astra', openaiBody.routing.reasoningModel === 'gpt-6.2-astra', openaiBody.routing);
    const openaiStored = (await db.listUserAiKeys(openaiUser.id)).find((r) => r.providerId === 'openai');
    check('stored openai row holds the model list', JSON.stringify(openaiStored?.discoveredModels) === JSON.stringify(['gpt-6-luna', 'gpt-6.2-astra']), openaiStored);
    check('stored openai row keeps only the key hint', openaiStored?.keyHint === '****7890', openaiStored);

    // 13. OpenAI refresh re-verifies and updates the list.
    modelLists['https://api.openai.com/v1/models'] = {
      data: [{ id: 'gpt-6-luna' }, { id: 'gpt-6.2-astra' }, { id: 'gpt-6-flash' }],
    };
    const openaiRefresh = await app.inject({
      method: 'POST', url: '/api/v1/ai-keys/openai/refresh', headers: { cookie: openaiCookie },
    });
    check('POST refresh openai → 200', openaiRefresh.statusCode === 200, openaiRefresh.body);
    const openaiRefreshBody = JSON.parse(openaiRefresh.body) as { discoveredModels: string[] | null };
    check('refresh returns the new GPT list', JSON.stringify(openaiRefreshBody.discoveredModels) === JSON.stringify(['gpt-6-luna', 'gpt-6.2-astra', 'gpt-6-flash']), openaiRefreshBody);
    const openaiAfterRefresh = (await db.listUserAiKeys(openaiUser.id)).find((r) => r.providerId === 'openai');
    check('refresh persists the new GPT list', JSON.stringify(openaiAfterRefresh?.discoveredModels) === JSON.stringify(['gpt-6-luna', 'gpt-6.2-astra', 'gpt-6-flash']), openaiAfterRefresh);

    // 14. A non-allowlisted base URL for openai is rejected.
    const badBasePost = await app.inject({
      method: 'POST', url: '/api/v1/ai-keys',
      headers: { cookie: openaiCookie },
      payload: { providerId: 'openai', apiKey: OPENAI_KEY, baseUrl: 'https://evil.example.com/v1' },
    });
    check('POST openai with a non-allowlisted base URL → 400', badBasePost.statusCode === 400, badBasePost.body);

    // 15. OmniRoute verify goes through the generic OpenAI-compatible
    // branch and returns the gateway model list, deduped.
    const omniCheck = await verifyProviderKey('omniroute', OMNIROUTE_KEY, OMNIROUTE_URL);
    check('verifyProviderKey omniroute returns deduped gateway model ids', omniCheck.ok === true
      && JSON.stringify(omniCheck.models) === JSON.stringify(['auto', 'auto/coding', 'openai/gpt-6-luna']), omniCheck);

    // 16. OmniRoute save rejects every non-public base URL, before any
    // key verification, and stores nothing.
    const omniBadUrls: Array<{ label: string; payload: Record<string, string> }> = [
      { label: 'missing URL', payload: { providerId: 'omniroute', apiKey: OMNIROUTE_KEY } },
      { label: 'empty URL', payload: { providerId: 'omniroute', apiKey: OMNIROUTE_KEY, baseUrl: '' } },
      { label: 'http scheme', payload: { providerId: 'omniroute', apiKey: OMNIROUTE_KEY, baseUrl: 'http://omni.example.com/v1' } },
      { label: 'localhost', payload: { providerId: 'omniroute', apiKey: OMNIROUTE_KEY, baseUrl: 'https://localhost:20128/v1' } },
      { label: 'loopback IP', payload: { providerId: 'omniroute', apiKey: OMNIROUTE_KEY, baseUrl: 'https://127.0.0.1:20128/v1' } },
      { label: 'private IP', payload: { providerId: 'omniroute', apiKey: OMNIROUTE_KEY, baseUrl: 'https://10.0.0.5:20128/v1' } },
      { label: 'host resolving to a private IP', payload: { providerId: 'omniroute', apiKey: OMNIROUTE_KEY, baseUrl: 'https://internal.example.com/v1' } },
    ];
    for (const bad of omniBadUrls) {
      const res = await app.inject({
        method: 'POST', url: '/api/v1/ai-keys',
        headers: { cookie }, payload: bad.payload,
      });
      check(`POST omniroute with ${bad.label} → 400`, res.statusCode === 400, res.body);
    }
    const omniRowsAfterBad = (await db.listUserAiKeys(user.id)).filter((r) => r.providerId === 'omniroute');
    check('rejected omniroute saves store nothing', omniRowsAfterBad.length === 0, omniRowsAfterBad.length);

    // 17. OmniRoute end to end on a fresh user: public gateway URL saves,
    // the gateway list persists, and the first-key auto-route points both
    // tiers at the gateway defaults.
    const omniUser = await db.createUser('omniroute-user@example.com', 'unused-hash');
    const omniToken = generateSessionToken();
    await db.createSession(omniUser.id, hashSessionToken(omniToken), new Date(Date.now() + 3600_000).toISOString());
    const omniCookie = `bs_session=${omniToken}`;
    const omniPost = await app.inject({
      method: 'POST', url: '/api/v1/ai-keys',
      headers: { cookie: omniCookie },
      payload: { providerId: 'omniroute', apiKey: OMNIROUTE_KEY, baseUrl: OMNIROUTE_URL },
    });
    check('POST omniroute key → 200', omniPost.statusCode === 200, omniPost.body);
    const omniBody = JSON.parse(omniPost.body) as KeyOut & {
      routingAutoSet: boolean;
      routing: { workerProvider: string; workerModel: string; reasoningProvider: string; reasoningModel: string };
    };
    check('POST omniroute response carries discoveredModels', JSON.stringify(omniBody.discoveredModels) === JSON.stringify(['auto', 'auto/coding', 'openai/gpt-6-luna']), omniBody);
    check('POST omniroute response never contains the plaintext key', !omniPost.body.includes(OMNIROUTE_KEY));
    check('POST omniroute saves against the gateway base URL', omniBody.baseUrl === OMNIROUTE_URL, omniBody);
    check('first omniroute key auto-routes both tiers to omniroute', omniBody.routingAutoSet === true
      && omniBody.routing.workerProvider === 'omniroute' && omniBody.routing.reasoningProvider === 'omniroute', omniBody.routing);
    check('omniroute auto-route worker model is auto', omniBody.routing.workerModel === 'auto', omniBody.routing);
    check('omniroute auto-route reasoning model is auto/coding', omniBody.routing.reasoningModel === 'auto/coding', omniBody.routing);
    const omniStored = (await db.listUserAiKeys(omniUser.id)).find((r) => r.providerId === 'omniroute');
    check('stored omniroute row holds the model list', JSON.stringify(omniStored?.discoveredModels) === JSON.stringify(['auto', 'auto/coding', 'openai/gpt-6-luna']), omniStored);
    check('stored omniroute row keeps only the key hint', omniStored?.keyHint === '****7890', omniStored);

    // 18. OmniRoute refresh re-verifies against the stored URL and
    // updates the list; it needs no new host check.
    modelLists['https://omni.example.com/v1/models'] = {
      data: [{ id: 'auto' }, { id: 'auto/coding' }, { id: 'openai/gpt-6-luna' }, { id: 'anthropic/claude-sonnet-4-5' }],
    };
    const omniRefresh = await app.inject({
      method: 'POST', url: '/api/v1/ai-keys/omniroute/refresh', headers: { cookie: omniCookie },
    });
    check('POST refresh omniroute → 200', omniRefresh.statusCode === 200, omniRefresh.body);
    const omniRefreshBody = JSON.parse(omniRefresh.body) as { discoveredModels: string[] | null };
    check('refresh returns the new gateway list', JSON.stringify(omniRefreshBody.discoveredModels) === JSON.stringify(['auto', 'auto/coding', 'openai/gpt-6-luna', 'anthropic/claude-sonnet-4-5']), omniRefreshBody);
    const omniAfterRefresh = (await db.listUserAiKeys(omniUser.id)).find((r) => r.providerId === 'omniroute');
    check('refresh persists the new gateway list', JSON.stringify(omniAfterRefresh?.discoveredModels) === JSON.stringify(['auto', 'auto/coding', 'openai/gpt-6-luna', 'anthropic/claude-sonnet-4-5']), omniAfterRefresh);

    await app.close();
  } finally {
    globalThis.fetch = realFetch;
    dns.lookup = originalLookup;
  }

  if (failures > 0) {
    console.error(`\nFAILED: ${failures} checks failed in ai-keys-discovered-models.test.ts`);
    process.exit(1);
  } else {
    console.log('\nALL DISCOVERED-MODELS TESTS PASSED.');
  }
}

main().catch((err) => {
  console.error('Unhandled test failure:', err);
  process.exit(1);
});

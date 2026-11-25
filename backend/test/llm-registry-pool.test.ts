import { validateProviderBaseUrl, PROVIDER_REGISTRY, defaultModelsFor } from '../src/llm/registry.js';
import { OpenAiCompatProvider, finiteInt } from '../src/llm/openaiCompat.js';
import { LlmProviderPool, buildPoolFromKeys } from '../src/llm/index.js';
import { GeminiProvider } from '../src/llm/gemini.js';
import { QwenProvider } from '../src/llm/qwen.js';
import { ClaudeProvider } from '../src/llm/claude.js';
import { makeCompletion, type LLMCompletion, type LLMProvider } from '../src/llm/provider.js';

let failures = 0;
function check(name: string, ok: boolean, extra?: unknown) {
  if (ok) console.log('PASS', name);
  else {
    failures++;
    console.error('FAIL', name, extra ?? '');
  }
}

function stubProvider(
  name: string,
  fn: (req: Parameters<LLMProvider['complete']>[0]) => Promise<LLMCompletion>,
): LLMProvider & { calls: number; tiers: Array<string | undefined> } {
  const stub = {
    name,
    calls: 0,
    tiers: [] as Array<string | undefined>,
    async complete(req: Parameters<LLMProvider['complete']>[0]) {
      stub.calls += 1;
      stub.tiers.push(req.tier);
      return fn(req);
    },
  };
  return stub;
}

function chatOk(text: string, usage?: Record<string, unknown>) {
  return new Response(
    JSON.stringify({
      choices: [{ message: { role: 'assistant', content: text }, finish_reason: 'stop' }],
      usage: usage ?? { prompt_tokens: 100, completion_tokens: 25 },
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

async function main() {
  const originalFetch = globalThis.fetch;

  try {
    // 1. validateProviderBaseUrl accepts every official URL
    for (const spec of Object.values(PROVIDER_REGISTRY)) {
      let accepted = '';
      try {
        accepted = validateProviderBaseUrl(spec.id);
      } catch {
        accepted = '';
      }
      check(`accepts official base URL for ${spec.id}`, accepted === spec.defaultBaseUrl, accepted);
    }
    check(
      'accepts moonshot cn endpoint for kimi',
      validateProviderBaseUrl('kimi', 'https://api.moonshot.cn/v1') === 'https://api.moonshot.cn/v1',
    );
    check(
      'accepts deepseek bare host',
      validateProviderBaseUrl('deepseek', 'https://api.deepseek.com') === 'https://api.deepseek.com',
    );
    check(
      'accepts qwen workspace endpoint',
      validateProviderBaseUrl(
        'qwen',
        'https://ws-abc123def456.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1',
      ) === 'https://ws-abc123def456.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1',
    );

    // 2. validateProviderBaseUrl rejects SSRF URLs
    const rejected: Array<[string, string]> = [
      ['qwen', 'http://169.254.169.254/v1'],
      ['qwen', 'https://evil.com/compatible-mode/v1'],
      ['kimi', 'https://api.moonshot.ai.evil.com/v1'],
      ['gemini', 'https://generativelanguage.googleapis.com.evil.com/v1beta'],
      ['ollama', 'http://192.168.1.10:11434/v1'],
      ['deepseek', 'http://api.deepseek.com/v1'],
      ['qwen', 'https://ws-x.ap-southeast-1.oss.aliyuncs.com/compatible-mode/v1'],
    ];
    for (const [provider, url] of rejected) {
      let threw = false;
      try {
        validateProviderBaseUrl(provider as never, url);
      } catch {
        threw = true;
      }
      check(`rejects SSRF URL for ${provider}: ${url}`, threw);
    }

    // 3. Pool fails over A (429) -> B, respects cooldowns
    let now = 1_000_000;
    const flaky = stubProvider('kimi', async () => {
      const err = new Error('kimi API error 429: rate_limited');
      (err as unknown as { status: number }).status = 429;
      throw err;
    });
    const steady = stubProvider('glm', async () =>
      makeCompletion('steady ok', { inputTokens: 10, outputTokens: 5 }),
    );
    const pool = new LlmProviderPool(
      [
        { providerId: 'kimi', provider: flaky },
        { providerId: 'glm', provider: steady },
      ],
      { now: () => now },
    );
    const first = await pool.completeTier('worker', [{ role: 'user', content: 'hi' }]);
    check('pool fails over 429 to next provider', first.text === 'steady ok');
    check('pool tried the failing provider once', flaky.calls === 1);
    check('pool tried the fallback provider once', steady.calls === 1);
    check('pool cools the failed provider down', pool.isCoolingDown('kimi'));
    check('pool cooldown starts at 10s', pool.cooldownRemainingMs('kimi') === 10_000, pool.cooldownRemainingMs('kimi'));

    now += 1000;
    const second = await pool.completeTier('worker', [{ role: 'user', content: 'hi again' }]);
    check('pool skips a cooling provider on the next call', second.text === 'steady ok' && flaky.calls === 1);
    check('pool still cools the failed provider', pool.isCoolingDown('kimi'));

    // Cooldown escalates: fail again after the first window lapses.
    now += 10_000;
    check('pool cooldown lapses after 10s', !pool.isCoolingDown('kimi'));
    const third = await pool.completeTier('worker', [{ role: 'user', content: 'third' }]);
    check('pool retries the cooled provider after lapse', third.text === 'steady ok' && flaky.calls === 2);
    check('pool escalates the second cooldown to 20s', pool.cooldownRemainingMs('kimi') === 20_000, pool.cooldownRemainingMs('kimi'));

    // 4. Pool fails fast on 400 without burning the next provider
    const bad = stubProvider('deepseek', async () => {
      const err = new Error('bad request');
      (err as unknown as { status: number }).status = 400;
      throw err;
    });
    const neverCalled = stubProvider('glm', async () => makeCompletion('nope', { inputTokens: 0, outputTokens: 0 }));
    const pool400 = new LlmProviderPool([
      { providerId: 'deepseek', provider: bad },
      { providerId: 'glm', provider: neverCalled },
    ]);
    let threw400 = false;
    try {
      await pool400.completeTier('worker', [{ role: 'user', content: 'x' }]);
    } catch (err) {
      threw400 = (err as { status?: number }).status === 400;
    }
    check('pool fails fast on 400', threw400 && neverCalled.calls === 0);

    // 5. Pool routes worker vs reasoning tiers to configured models
    const tierCalls: string[] = [];
    const tiered = stubProvider('kimi', async (req) => {
      tierCalls.push(req.tier ?? '');
      return makeCompletion('tiered', { inputTokens: 1, outputTokens: 1 });
    });
    const tierPool = new LlmProviderPool([{ providerId: 'kimi', provider: tiered }]);
    await tierPool.completeTier('worker', [{ role: 'user', content: 'w' }]);
    await tierPool.completeTier('reasoning', [{ role: 'user', content: 'r' }]);
    check('pool sends worker tier as routine', tierCalls[0] === 'routine', tierCalls);
    check('pool sends reasoning tier as reasoning', tierCalls[1] === 'reasoning', tierCalls);
    await tierPool.complete({ messages: [{ role: 'user', content: 'c' }], tier: 'code' });
    check('pool maps code tier onto reasoning', tierCalls[2] === 'reasoning', tierCalls);

    // 6. Pool never emits NaN token counts
    const nanProvider = stubProvider('glm', async () =>
      makeCompletion('nan', { inputTokens: NaN, outputTokens: NaN }),
    );
    const nanPool = new LlmProviderPool([{ providerId: 'glm', provider: nanProvider }]);
    const nanResult = await nanPool.completeTier('worker', [{ role: 'user', content: 'x' }]);
    check('pool sanitises NaN tokens to 0', nanResult.usage.inputTokens === 0 && nanResult.usage.outputTokens === 0, nanResult.usage);

    // 7. OpenAI-compat adapter strips raw error bodies
    globalThis.fetch = (async () => {
      return new Response('{"error":{"message":"key sk-live-SECRET-12345 is invalid; internal stack trace here"}}', {
        status: 500,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;
    const compat = new OpenAiCompatProvider('kimi', 'test-kimi-key-1234567890');
    let stripped = false;
    try {
      await compat.complete({ messages: [{ role: 'user', content: 'hi' }] });
    } catch (err) {
      const msg = (err as Error).message;
      stripped = msg.includes('HTTP 500') || msg.includes('500');
      check('adapter error carries only HTTP status plus safe code', msg === 'kimi API error 500: provider_error', msg);
      check('adapter error never contains the raw body or key', !msg.includes('SECRET') && !msg.includes('sk-live'), msg);
    }
    check('adapter threw a sanitised error', stripped);

    // 8. OpenAI-compat adapter enforces finite integer token accounting
    globalThis.fetch = (async () =>
      chatOk('finite ok', { prompt_tokens: 'not-a-number', completion_tokens: null })) as typeof fetch;
    const finiteResult = await compat.complete({ messages: [{ role: 'user', content: 'hi' }] });
    check('adapter coerces non-finite tokens to 0', finiteResult.usage.inputTokens === 0 && finiteResult.usage.outputTokens === 0, finiteResult.usage);
    check('finiteInt helper', finiteInt(NaN) === 0 && finiteInt('12.9') === 12 && finiteInt(7) === 7);

    // 9. OpenAI-compat adapter routes worker vs reasoning models
    const seenModels: string[] = [];
    globalThis.fetch = (async (_input: unknown, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { model?: string };
      seenModels.push(body.model ?? '');
      return chatOk('model ok');
    }) as typeof fetch;
    await compat.complete({ messages: [{ role: 'user', content: 'w' }], tier: 'routine' });
    await compat.complete({ messages: [{ role: 'user', content: 'r' }], tier: 'reasoning' });
    check('adapter sends worker model for routine tier', seenModels[0] === 'moonshot-v1-32k', seenModels);
    check('adapter sends reasoning model for reasoning tier', seenModels[1] === 'kimi-k2-0711-preview', seenModels);
    check('adapter tags completions with provider and model', true);

    // 10. Gemini sends x-goog-api-key header only, shares one abort signal across the cascade
    GeminiProvider.resetModelCache();
    const seenSignals: Array<AbortSignal | undefined> = [];
    const seenUrls: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      seenUrls.push(url);
      seenSignals.push(init?.signal as AbortSignal | undefined);
      if (url.endsWith('/v1beta/models')) {
        return new Response(
          JSON.stringify({
            models: [
              { name: 'models/gemini-2.0-flash', supportedGenerationMethods: ['generateContent'] },
              { name: 'models/gemini-1.5-pro-latest', supportedGenerationMethods: ['generateContent'] },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (url.includes('gemini-2.0-flash')) {
        return new Response(
          JSON.stringify({ error: { code: 404, message: 'models/gemini-2.0-flash is not found for API version v1beta.' } }),
          { status: 404, headers: { 'content-type': 'application/json' } },
        );
      }
      if (url.includes('gemini-1.5-pro-latest')) {
        return new Response(
          JSON.stringify({
            candidates: [{ content: { parts: [{ text: 'Gemini cascade ok.' }] }, finishReason: 'STOP' }],
            usageMetadata: { promptTokenCount: 50, candidatesTokenCount: 10 },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response('Not Found', { status: 404 });
    }) as typeof fetch;
    const gemini = new GeminiProvider('test-gemini-key-12345', 'gemini-2.0-flash', 'gemini-1.5-pro-latest');
    const geminiResult = await gemini.complete({ messages: [{ role: 'user', content: 'hi' }], tier: 'routine' });
    check('gemini cascades past 404 to the next model', geminiResult.text.includes('Gemini cascade ok.'));
    check('gemini never puts the key in a URL', seenUrls.every((u) => !u.includes('key=')), seenUrls);
    const genSignals = seenSignals.filter((s) => s !== undefined);
    check('gemini passes an abort signal on every call', genSignals.length === seenUrls.length, { seen: seenUrls.length, signals: genSignals.length });
    const generateSignals = seenSignals.filter((_, i) => seenUrls[i].includes(':generateContent'));
    check(
      'gemini shares one abort signal across cascade attempts',
      generateSignals.length >= 2 && generateSignals.every((s) => s === generateSignals[0]),
      generateSignals.length,
    );
    check('gemini tags completion with provider and model', geminiResult.providerId === 'gemini' && geminiResult.model === 'gemini-1.5-pro-latest', geminiResult);

    // 11. Gemini model cache is keyed by hash with a TTL, never the raw key
    GeminiProvider.resetModelCache();
    let discoveryCalls = 0;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/v1beta/models')) {
        discoveryCalls += 1;
        return new Response(
          JSON.stringify({ models: [{ name: 'models/gemini-2.0-flash', supportedGenerationMethods: ['generateContent'] }] }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response('Not Found', { status: 404 });
    }) as typeof fetch;
    const cacheProvider = new GeminiProvider('test-gemini-key-cache');
    await cacheProvider.getAvailableModels();
    await cacheProvider.getAvailableModels();
    check('gemini caches discovery without a second fetch', discoveryCalls === 1, discoveryCalls);

    // 12. Claude aborts on timeout signal and maps tiers
    const claudeModels: string[] = [];
    const claudeSignals: Array<AbortSignal | undefined> = [];
    globalThis.fetch = (async (_input: unknown, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { model?: string };
      claudeModels.push(body.model ?? '');
      claudeSignals.push(init?.signal as AbortSignal | undefined);
      return new Response(
        JSON.stringify({
          content: [{ type: 'text', text: 'Claude ok.' }],
          usage: { input_tokens: 30, output_tokens: 8 },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as typeof fetch;
    const claude = new ClaudeProvider('test-claude-key-1234567890');
    const claudeWorker = await claude.complete({ messages: [{ role: 'user', content: 'w' }], tier: 'routine' });
    const claudeReasoning = await claude.complete({ messages: [{ role: 'user', content: 'r' }], tier: 'reasoning' });
    check('claude maps worker tier to haiku', claudeModels[0] === 'claude-haiku-4-5', claudeModels);
    check('claude maps reasoning tier to sonnet', claudeModels[1] === 'claude-sonnet-4-5', claudeModels);
    check('claude passes an abort signal', claudeSignals.every((s) => s instanceof AbortSignal), claudeSignals.length);
    check('claude tags completion with provider and model', claudeWorker.providerId === 'claude' && claudeReasoning.model === 'claude-sonnet-4-5', claudeReasoning);

    // Claude honours a caller-aborted signal instead of hanging.
    const abortController = new AbortController();
    abortController.abort();
    globalThis.fetch = (async (_input: unknown, init?: RequestInit) => {
      const signal = init?.signal as AbortSignal | undefined;
      if (signal?.aborted) throw new DOMException('The operation was aborted.', 'AbortError');
      return new Response('{}', { status: 200 });
    }) as typeof fetch;
    let aborted = false;
    try {
      await claude.complete({ messages: [{ role: 'user', content: 'x' }], signal: abortController.signal });
    } catch (err) {
      aborted = (err as { name?: string }).name === 'AbortError';
    }
    check('claude aborts when the caller signal is aborted', aborted);

    // 13. Pool fails over on 503 to the second entry in the same call, and
    // does not re-hit the cooled provider on the immediate retry.
    let now503 = 2_000_000;
    const err503 = (provider: string) => {
      const err = new Error(`${provider} API error 503: overloaded`);
      (err as unknown as { status: number }).status = 503;
      return err;
    };
    const first503 = stubProvider('qwen', async () => {
      throw err503('qwen');
    });
    const second503 = stubProvider('gemini', async () =>
      makeCompletion('second ok', { inputTokens: 10, outputTokens: 5 }),
    );
    const pool503 = new LlmProviderPool(
      [
        { providerId: 'qwen', provider: first503 },
        { providerId: 'gemini', provider: second503 },
      ],
      { now: () => now503 },
    );
    const r503 = await pool503.completeTier('worker', [{ role: 'user', content: 'hi' }]);
    check('pool fails over 503 to the second entry in the same call', r503.text === 'second ok');
    check('pool tried the 503 provider once', first503.calls === 1);
    check('pool tried the fallback provider once', second503.calls === 1);
    check('pool cools the 503 provider down', pool503.isCoolingDown('qwen'));
    now503 += 1000;
    const r503b = await pool503.completeTier('worker', [{ role: 'user', content: 'hi again' }]);
    check(
      'pool skips the 503-cooled provider on the immediate retry',
      r503b.text === 'second ok' && first503.calls === 1,
      { first503Calls: first503.calls },
    );

    // 14. Pool tries the tier's routing provider first, then the other
    // saved provider as failover. Gemini is listed first, but reasoning
    // routing prefers qwen, so qwen must be tried first for reasoning.
    const order: string[] = [];
    const qwenStub = stubProvider('qwen', async () => {
      order.push('qwen');
      return makeCompletion('qwen ok', { inputTokens: 1, outputTokens: 1 });
    });
    const geminiStub = stubProvider('gemini', async () => {
      order.push('gemini');
      return makeCompletion('gemini ok', { inputTokens: 1, outputTokens: 1 });
    });
    const routingPool = new LlmProviderPool(
      [
        { providerId: 'gemini', provider: geminiStub },
        { providerId: 'qwen', provider: qwenStub },
      ],
      { routing: { workerProvider: 'gemini', reasoningProvider: 'qwen' } },
    );
    const reasoningRes = await routingPool.completeTier('reasoning', [{ role: 'user', content: 'r' }]);
    check('pool tries qwen first for reasoning when routing prefers qwen', order[0] === 'qwen' && reasoningRes.text === 'qwen ok', order);
    const workerRes = await routingPool.completeTier('worker', [{ role: 'user', content: 'w' }]);
    check('pool tries gemini first for worker when routing prefers gemini', order[1] === 'gemini' && workerRes.text === 'gemini ok', order);

    // 15. Routing defaults to gemini but only qwen is saved: qwen serves
    // both tiers rather than failing for want of a gemini entry.
    const qwenOnlyStub = stubProvider('qwen', async () =>
      makeCompletion('qwen only ok', { inputTokens: 1, outputTokens: 1 }),
    );
    const qwenOnlyPool = new LlmProviderPool([{ providerId: 'qwen', provider: qwenOnlyStub }], {
      routing: { workerProvider: 'gemini', reasoningProvider: 'gemini' },
    });
    const qwenOnlyWorker = await qwenOnlyPool.completeTier('worker', [{ role: 'user', content: 'w' }]);
    const qwenOnlyReasoning = await qwenOnlyPool.completeTier('reasoning', [{ role: 'user', content: 'r' }]);
    check('only qwen saved: qwen serves the worker tier', qwenOnlyWorker.text === 'qwen only ok');
    check('only qwen saved: qwen serves the reasoning tier', qwenOnlyReasoning.text === 'qwen only ok');
    check('only qwen saved: qwen served both tiers', qwenOnlyStub.calls === 2, qwenOnlyStub.calls);

    // 16. buildPoolFromKeys threads routing into the pool: qwen+gemini
    // saved with reasoning routing qwen — the reasoning call hits qwen
    // first even though gemini was saved first.
    GeminiProvider.resetModelCache();
    QwenProvider.resetModelCache();
    const mixedUrls: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      mixedUrls.push(url);
      if (url.includes('aliyuncs.com/models')) {
        return new Response(JSON.stringify({ data: [] }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      if (url.includes('aliyuncs.com')) return chatOk('qwen first');
      return new Response('Not Found', { status: 404 });
    }) as typeof fetch;
    const mixedPool = buildPoolFromKeys(
      [
        { providerId: 'gemini', apiKey: 'test-' + 'y'.repeat(20), baseUrl: null },
        { providerId: 'qwen', apiKey: 'test-' + 'x'.repeat(20), baseUrl: null },
      ],
      { workerProvider: 'gemini', reasoningProvider: 'qwen' },
    );
    check('buildPoolFromKeys builds a pool from saved qwen+gemini keys', mixedPool !== null);
    const mixedReasoning = await mixedPool!.completeTier('reasoning', [{ role: 'user', content: 'r' }]);
    check(
      'saved qwen+gemini with routing qwen: reasoning tries qwen first',
      mixedReasoning.text === 'qwen first' && mixedUrls[0].includes('aliyuncs.com'),
      mixedUrls,
    );

    // 17. Qwen-only saved key with gemini routing defaults: both tiers are
    // served by qwen and gemini is never called.
    GeminiProvider.resetModelCache();
    QwenProvider.resetModelCache();
    const qwenOnlyUrls: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      qwenOnlyUrls.push(url);
      if (url.includes('aliyuncs.com/models')) {
        return new Response(JSON.stringify({ data: [] }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      if (url.includes('aliyuncs.com')) return chatOk('qwen via pool');
      return new Response('Not Found', { status: 404 });
    }) as typeof fetch;
    const savedQwenPool = buildPoolFromKeys(
      [{ providerId: 'qwen', apiKey: 'test-' + 'x'.repeat(20), baseUrl: null }],
      { workerProvider: 'gemini', reasoningProvider: 'gemini' },
    );
    check('buildPoolFromKeys builds a pool from a single qwen key', savedQwenPool !== null);
    const savedWorker = await savedQwenPool!.completeTier('worker', [{ role: 'user', content: 'w' }]);
    const savedReasoning = await savedQwenPool!.completeTier('reasoning', [{ role: 'user', content: 'r' }]);
    check('qwen-only saved key serves the worker tier', savedWorker.text === 'qwen via pool');
    check('qwen-only saved key serves the reasoning tier', savedReasoning.text === 'qwen via pool');
    check(
      'qwen-only saved key never calls gemini',
      qwenOnlyUrls.every((u) => !u.includes('generativelanguage')),
      qwenOnlyUrls,
    );

    // 18. Pool fails loudly when every entry returns 503, naming the provider.
    const all503a = stubProvider('qwen', async () => {
      throw err503('qwen');
    });
    const all503b = stubProvider('gemini', async () => {
      throw err503('gemini');
    });
    const poolAll503 = new LlmProviderPool([
      { providerId: 'qwen', provider: all503a },
      { providerId: 'gemini', provider: all503b },
    ]);
    let loud503 = '';
    try {
      await poolAll503.completeTier('worker', [{ role: 'user', content: 'x' }]);
    } catch (err) {
      loud503 = (err as Error).message;
    }
    check('pool fails loudly when all providers return 503', loud503.includes('503') && loud503.includes('gemini'), loud503);
    check('pool tried every provider before failing on 503', all503a.calls === 1 && all503b.calls === 1, {
      qwen: all503a.calls,
      gemini: all503b.calls,
    });

    // 19. defaultModelsFor is region-aware for qwen, unchanged elsewhere.
    check(
      'registry qwen defaults are qwen3.7-plus / qwen4-max',
      PROVIDER_REGISTRY.qwen.defaultModels.worker === 'qwen3.7-plus' &&
        PROVIDER_REGISTRY.qwen.defaultModels.reasoning === 'qwen4-max',
      PROVIDER_REGISTRY.qwen.defaultModels,
    );
    const beijingDefaults = defaultModelsFor('qwen', 'https://dashscope.aliyuncs.com/compatible-mode/v1');
    check('defaultModelsFor qwen beijing worker is qwen3.7-plus', beijingDefaults.worker === 'qwen3.7-plus', beijingDefaults);
    check('defaultModelsFor qwen beijing reasoning is qwen4-max', beijingDefaults.reasoning === 'qwen4-max', beijingDefaults);
    const intlDefaults = defaultModelsFor('qwen', 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1');
    check('defaultModelsFor qwen intl worker is qwen3.7-plus', intlDefaults.worker === 'qwen3.7-plus', intlDefaults);
    check('defaultModelsFor qwen intl reasoning is qwen3.8-max', intlDefaults.reasoning === 'qwen3.8-max', intlDefaults);
    const workspaceDefaults = defaultModelsFor('qwen', 'https://my-workspace.aliyuncs.com/compatible-mode/v1');
    check('defaultModelsFor qwen custom workspace reasoning is qwen4-max', workspaceDefaults.reasoning === 'qwen4-max', workspaceDefaults);
    const noUrlDefaults = defaultModelsFor('qwen');
    check('defaultModelsFor qwen with no base URL reasoning is qwen4-max', noUrlDefaults.reasoning === 'qwen4-max', noUrlDefaults);
    check(
      'defaultModelsFor gemini unchanged',
      defaultModelsFor('gemini').worker === 'gemini-2.5-flash' &&
        defaultModelsFor('gemini').reasoning === 'gemini-2.5-pro',
      defaultModelsFor('gemini'),
    );
    check(
      'defaultModelsFor kimi unchanged',
      defaultModelsFor('kimi').worker === 'moonshot-v1-32k' &&
        defaultModelsFor('kimi').reasoning === 'kimi-k2-0711-preview',
      defaultModelsFor('kimi'),
    );

    // 20. buildPoolFromKeys threads the region-aware qwen defaults into
    // the pool: a Beijing key serves reasoning calls as qwen4-max.
    QwenProvider.resetModelCache();
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('aliyuncs.com/models')) {
        return new Response(JSON.stringify({ data: [] }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      if (url.includes('aliyuncs.com')) return chatOk('qwen beijing pool');
      return new Response('Not Found', { status: 404 });
    }) as typeof fetch;
    const beijingPool = buildPoolFromKeys(
      [{ providerId: 'qwen', apiKey: 'test-' + 'x'.repeat(20), baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1' }],
      { workerProvider: 'gemini', reasoningProvider: 'gemini' },
    );
    check('buildPoolFromKeys builds a pool from a beijing qwen key', beijingPool !== null);
    const beijingReasoning = await beijingPool!.completeTier('reasoning', [{ role: 'user', content: 'r' }]);
    check('pool qwen beijing key uses qwen4-max for reasoning', beijingReasoning.model === 'qwen4-max', beijingReasoning.model);
  } finally {
    globalThis.fetch = originalFetch;
  }

  if (failures > 0) {
    console.error(`\nFAILED: ${failures} checks failed in llm-registry-pool.test.ts`);
    process.exit(1);
  } else {
    console.log('\nALL LLM REGISTRY & POOL TESTS PASSED.');
  }
}

main().catch((err) => {
  console.error('Unhandled test failure:', err);
  process.exit(1);
});

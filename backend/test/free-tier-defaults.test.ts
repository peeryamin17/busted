import { PROVIDER_REGISTRY, defaultModelsFor, type ModelTier, type ProviderId } from '../src/llm/registry.js';
import { OpenAiCompatProvider } from '../src/llm/openaiCompat.js';
import { ClaudeProvider } from '../src/llm/claude.js';
import { GeminiProvider } from '../src/llm/gemini.js';
import { LlmProviderPool, buildPoolFromKeys } from '../src/llm/index.js';
import { makeCompletion, type LLMCompletion, type LLMProvider } from '../src/llm/provider.js';

let failures = 0;
function check(name: string, ok: boolean, extra?: unknown) {
  if (ok) console.log('PASS', name);
  else {
    failures++;
    console.error('FAIL', name, extra ?? '');
  }
}

/**
 * Every registry default must be either null (no free-tier model: the
 * caller picks from the key's discovered list) or one of these models,
 * each verified free-tier usable on 27 Nov 2026. A future default has
 * to earn its place here first.
 */
const FREE_TIER_MODELS = new Set([
  // Gemini: gemini-3.8-flash is Google's free-tier model for new projects.
  'gemini-3.8-flash',
  // Qwen: 1M-token free quota per model, 90 days, on Model Studio.
  'qwen3.7-plus',
  'qwen4-max',
  'qwen3.8-max',
  // GLM: glm-4-flash is permanently free on Zhipu's open platform.
  'glm-4-flash',
  // OpenRouter free pool, live in /api/v1/models on 27 Nov 2026.
  'google/gemma-4-31b-it:free',
  'nvidia/nemotron-3-ultra-550b-a55b:free',
  // Ollama runs locally, no billing. OmniRoute routes on its gateway.
  'qwen2.5:14b',
  'deepseek-r1:14b',
  'auto',
  'auto/coding',
]);

const EXPECTED_DEFAULTS: Record<ProviderId, Record<ModelTier, string | null>> = {
  gemini: { worker: 'gemini-3.8-flash', reasoning: 'gemini-3.8-flash' },
  qwen: { worker: 'qwen3.7-plus', reasoning: 'qwen4-max' },
  kimi: { worker: null, reasoning: null },
  glm: { worker: 'glm-4-flash', reasoning: null },
  deepseek: { worker: null, reasoning: null },
  openrouter: { worker: 'google/gemma-4-31b-it:free', reasoning: 'nvidia/nemotron-3-ultra-550b-a55b:free' },
  claude: { worker: null, reasoning: null },
  openai: { worker: null, reasoning: null },
  ollama: { worker: 'qwen2.5:14b', reasoning: 'deepseek-r1:14b' },
  omniroute: { worker: 'auto', reasoning: 'auto/coding' },
};

function chatOk(text: string) {
  return new Response(
    JSON.stringify({
      choices: [{ message: { role: 'assistant', content: text }, finish_reason: 'stop' }],
      usage: { prompt_tokens: 10, completion_tokens: 5 },
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

async function main() {
  const originalFetch = globalThis.fetch;

  try {
    // 1. Every provider's defaults are exactly the expected free-tier set.
    const ids = Object.keys(EXPECTED_DEFAULTS) as ProviderId[];
    check('registry lists all 10 providers', Object.keys(PROVIDER_REGISTRY).length === 10, Object.keys(PROVIDER_REGISTRY));
    for (const id of ids) {
      for (const tier of ['worker', 'reasoning'] as ModelTier[]) {
        const got = PROVIDER_REGISTRY[id].defaultModels[tier];
        const want = EXPECTED_DEFAULTS[id][tier];
        check(`registry ${id} ${tier} default is ${want ?? 'null'}`, got === want, got);
        check(
          `registry ${id} ${tier} default is free-tier or null`,
          got === null || FREE_TIER_MODELS.has(got),
          got,
        );
      }
    }
    check(
      'defaultModelsFor qwen intl reasoning is qwen3.8-max',
      defaultModelsFor('qwen', 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1').reasoning === 'qwen3.8-max',
      defaultModelsFor('qwen', 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1'),
    );
    check(
      'defaultModelsFor kimi is null for both tiers',
      defaultModelsFor('kimi').worker === null && defaultModelsFor('kimi').reasoning === null,
      defaultModelsFor('kimi'),
    );

    // 2. Adapters with no free default throw a clear error, not a TypeError.
    for (const id of ['kimi', 'deepseek', 'openai', 'claude'] as const) {
      let err: unknown = null;
      try {
        if (id === 'claude') new ClaudeProvider('test-claude-key-1234567890');
        else new OpenAiCompatProvider(id, 'test-key-12345678901234567890');
      } catch (e) {
        err = e;
      }
      check(
        `${id} adapter without a model throws instead of a bare TypeError`,
        err instanceof Error && !(err instanceof TypeError),
        err,
      );
      check(
        `${id} adapter error names the provider and the missing free default`,
        err instanceof Error &&
          err.message.includes(`No free default model for provider ${id}`) &&
          err.message.includes('discovered list'),
        err instanceof Error ? err.message : err,
      );
    }
    // Explicit caller-chosen models still construct.
    const kimiExplicit = new OpenAiCompatProvider(
      'kimi',
      'test-key-12345678901234567890',
      undefined,
      'moonshot-v1-32k',
      'kimi-k2-0711-preview',
    );
    check('adapter with explicit models still constructs', kimiExplicit.modelForTier('worker') === 'moonshot-v1-32k');
    const claudeExplicit = new ClaudeProvider('test-claude-key-1234567890', 'claude-sonnet-4-5', 'claude-haiku-4-5');
    check('claude with explicit models still constructs', claudeExplicit.modelForTier('reasoning') === 'claude-sonnet-4-5');

    // 3. Pool: no default + discovered list uses the first text model.
    const seenModels: string[] = [];
    globalThis.fetch = (async (_input: unknown, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body ?? '{}')) as { model?: string };
      seenModels.push(body.model ?? '');
      return chatOk('pool ok');
    }) as typeof fetch;
    const kimiPool = buildPoolFromKeys(
      [
        {
          providerId: 'kimi',
          apiKey: 'test-' + 'k'.repeat(20),
          baseUrl: null,
          discoveredModels: ['moonshot-v1-embedding', 'moonshot-v1-32k', 'kimi-k2-0711-preview'],
        },
      ],
      { workerProvider: 'gemini', reasoningProvider: 'gemini' },
    );
    check('pool builds from a kimi key with a discovered list', kimiPool !== null);
    await kimiPool!.completeTier('worker', [{ role: 'user', content: 'w' }]);
    check('pool uses the first discovered text model, skipping embeddings', seenModels[0] === 'moonshot-v1-32k', seenModels);
    await kimiPool!.completeTier('reasoning', [{ role: 'user', content: 'r' }]);
    check('pool uses the same first discovered text model for reasoning', seenModels[1] === 'moonshot-v1-32k', seenModels);

    // 3b. Pool: no default + no discovered list throws naming the provider.
    for (const noList of [undefined, null, []] as const) {
      let err: unknown = null;
      try {
        buildPoolFromKeys(
          [{ providerId: 'deepseek', apiKey: 'test-' + 'd'.repeat(20), baseUrl: null, discoveredModels: noList }],
          null,
        );
      } catch (e) {
        err = e;
      }
      check(
        `pool with no default and no discovered list throws (${String(noList)})`,
        err instanceof Error && err.message.includes('No free default model for provider deepseek'),
        err instanceof Error ? err.message : err,
      );
    }
    // Discovered list with only non-text models also throws.
    let nonTextErr: unknown = null;
    try {
      buildPoolFromKeys(
        [
          {
            providerId: 'kimi',
            apiKey: 'test-' + 'k'.repeat(20),
            baseUrl: null,
            discoveredModels: ['moonshot-v1-embedding', 'kimi-tts-1'],
          },
        ],
        null,
      );
    } catch (e) {
      nonTextErr = e;
    }
    check(
      'pool with only non-text discovered models throws',
      nonTextErr instanceof Error && nonTextErr.message.includes('No free default model for provider kimi'),
      nonTextErr instanceof Error ? nonTextErr.message : nonTextErr,
    );

    // 3c. Pool: glm worker keeps its free default, reasoning falls back to discovered.
    seenModels.length = 0;
    const glmPool = buildPoolFromKeys(
      [
        {
          providerId: 'glm',
          apiKey: 'test-' + 'g'.repeat(20),
          baseUrl: null,
          discoveredModels: ['glm-4-flash'],
        },
      ],
      { workerProvider: 'gemini', reasoningProvider: 'gemini' },
    );
    check('pool builds from a glm key with a discovered list', glmPool !== null);
    await glmPool!.completeTier('worker', [{ role: 'user', content: 'w' }]);
    await glmPool!.completeTier('reasoning', [{ role: 'user', content: 'r' }]);
    check('pool glm worker uses the glm-4-flash default', seenModels[0] === 'glm-4-flash', seenModels);
    check('pool glm reasoning uses the discovered model', seenModels[1] === 'glm-4-flash', seenModels);

    // 3d. Pool: openai with a discovered list uses the first text model for both tiers.
    seenModels.length = 0;
    const openaiPool = buildPoolFromKeys(
      [
        {
          providerId: 'openai',
          apiKey: 'sk-proj-test-key-1234567890',
          baseUrl: null,
          discoveredModels: ['gpt-6-luna', 'gpt-6.2-astra'],
        },
      ],
      { workerProvider: 'gemini', reasoningProvider: 'gemini' },
    );
    check('pool builds from an openai key with a discovered list', openaiPool !== null);
    await openaiPool!.completeTier('worker', [{ role: 'user', content: 'w' }]);
    await openaiPool!.completeTier('reasoning', [{ role: 'user', content: 'r' }]);
    check('pool openai worker uses the first discovered text model', seenModels[0] === 'gpt-6-luna', seenModels);
    check('pool openai reasoning uses the first discovered text model', seenModels[1] === 'gpt-6-luna', seenModels);

    // 3e. Pool: routing override still wins over default and discovered.
    seenModels.length = 0;
    const routedPool = buildPoolFromKeys(
      [
        {
          providerId: 'kimi',
          apiKey: 'test-' + 'k'.repeat(20),
          baseUrl: null,
          discoveredModels: ['moonshot-v1-32k'],
        },
      ],
      { workerProvider: 'kimi', workerModel: 'moonshot-v1-8k', reasoningProvider: 'kimi', reasoningModel: 'kimi-k2-0711-preview' },
    );
    check('pool builds with explicit routing models', routedPool !== null);
    await routedPool!.completeTier('worker', [{ role: 'user', content: 'w' }]);
    await routedPool!.completeTier('reasoning', [{ role: 'user', content: 'r' }]);
    check('pool routing override wins for worker', seenModels[0] === 'moonshot-v1-8k', seenModels);
    check('pool routing override wins for reasoning', seenModels[1] === 'kimi-k2-0711-preview', seenModels);

    // 3f. Pool label fallback never produces a null completion.model.
    const stub: LLMProvider = {
      name: 'kimi-stub',
      async complete(): Promise<LLMCompletion> {
        return makeCompletion('stub ok', { inputTokens: 1, outputTokens: 1 });
      },
    };
    const labelPool = new LlmProviderPool([{ providerId: 'kimi', provider: stub }]);
    const labelled = await labelPool.completeTier('worker', [{ role: 'user', content: 'x' }]);
    check('pool label fallback never yields a null model', labelled.model !== null, labelled.model);

    // 4. Gemini keeps gemini-3.8-flash: no silent rewrite to gemini-2.0-flash.
    const gemini = new GeminiProvider('test-gemini-key-12345', 'gemini-3.8-flash', 'gemini-3.8-flash');
    const candidates = gemini.getCandidateModels('routine', []);
    check('gemini keeps 3.8-flash as the first routine candidate', candidates[0] === 'gemini-3.8-flash', candidates);
    const reasoningCandidates = gemini.getCandidateModels('reasoning', []);
    check('gemini keeps 3.8-flash as the first reasoning candidate', reasoningCandidates[0] === 'gemini-3.8-flash', reasoningCandidates);
  } finally {
    globalThis.fetch = originalFetch;
  }

  if (failures > 0) {
    console.error(`\nFAILED: ${failures} checks failed in free-tier-defaults.test.ts`);
    process.exit(1);
  } else {
    console.log('\nALL FREE-TIER DEFAULTS TESTS PASSED.');
  }
}

main().catch((err) => {
  console.error('Unhandled test failure:', err);
  process.exit(1);
});

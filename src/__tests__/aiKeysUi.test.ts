import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { refreshAiKey, saveAiKey } from '../lib/apiClient.js';
import {
  formatRoutingBadge,
  formatSaveKeyError,
  shortProviderLabel,
} from '../lib/popupHelpers.js';

function mockChromeStorage(initial: Record<string, unknown> = {}) {
  const store: Record<string, unknown> = { ...initial };
  (globalThis as unknown as { chrome: unknown }).chrome = {
    storage: {
      local: {
        get: async (keys: string | string[]) => {
          const list = Array.isArray(keys) ? keys : [keys];
          return Object.fromEntries(list.map((k) => [k, store[k]]));
        },
        set: async (obj: Record<string, unknown>) => Object.assign(store, obj),
        remove: async (key: string | string[]) => {
          for (const k of Array.isArray(key) ? key : [key]) delete store[k];
        },
      },
    },
    runtime: {
      sendMessage: async () => undefined,
    },
  };
  return store;
}

function mockFetch(handler: (input: unknown, init?: RequestInit) => Promise<Response>) {
  (globalThis as unknown as { fetch: unknown }).fetch = async (
    input: unknown,
    init?: RequestInit,
  ) => handler(input, init);
}

const labelFor = (id: string) =>
  ({ qwen: 'Qwen', gemini: 'Gemini', claude: 'Claude', openai: 'OpenAI' })[id] ?? id;

test('saveAiKey returns the POST routing so the badge can update without a reload', async () => {
  mockChromeStorage();
  let seenUrl = '';
  mockFetch(async (input) => {
    seenUrl = String(input);
    return new Response(
      JSON.stringify({
        providerId: 'qwen',
        keyHint: '****zzzz',
        baseUrl: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1',
        verifiedAt: '2026-11-24T00:00:00.000Z',
        discoveredModels: ['qwen3.7-plus', 'qwen4-max'],
        hasByok: true,
        routingAutoSet: true,
        routing: {
          workerProvider: 'qwen',
          workerModel: 'qwen3.7-plus',
          reasoningProvider: 'qwen',
          reasoningModel: 'qwen3.8-max',
        },
      }),
      { status: 200 },
    );
  });

  const res = await saveAiKey('qwen', 'placeholder-key-value');
  assert.equal(res.ok, true);
  assert.match(seenUrl, /\/api\/v1\/ai-keys$/);
  if (res.ok) {
    assert.equal(res.data.routingAutoSet, true);
    assert.equal(res.data.routing.workerModel, 'qwen3.7-plus');
    assert.equal(res.data.routing.reasoningModel, 'qwen3.8-max');
    assert.deepEqual(res.data.discoveredModels, ['qwen3.7-plus', 'qwen4-max']);
    assert.equal(
      formatRoutingBadge(res.data.routing, (id) => shortProviderLabel(labelFor(id))),
      'Active: Qwen · worker qwen3.7-plus · reasoning qwen3.8-max',
    );
  }
});

test('provider list includes OpenAI alongside the other eight providers', () => {
  const apiClient = readFileSync(new URL('../lib/apiClient.ts', import.meta.url), 'utf8');
  for (const id of [
    'gemini',
    'claude',
    'qwen',
    'kimi',
    'glm',
    'deepseek',
    'openrouter',
    'openai',
    'ollama',
  ]) {
    assert.ok(apiClient.includes(`'${id}'`), `${id} is a known provider id`);
  }
});

test('saveAiKey verifies an OpenAI key and reports its GPT models', async () => {
  mockChromeStorage();
  let seenUrl = '';
  mockFetch(async (input) => {
    seenUrl = String(input);
    return new Response(
      JSON.stringify({
        providerId: 'openai',
        keyHint: '****yyyy',
        baseUrl: 'https://api.openai.com/v1',
        verifiedAt: '2026-11-27T00:00:00.000Z',
        discoveredModels: ['gpt-6-luna', 'gpt-6.2-astra'],
        hasByok: true,
        routingAutoSet: true,
        routing: {
          workerProvider: 'openai',
          workerModel: 'gpt-6-luna',
          reasoningProvider: 'openai',
          reasoningModel: 'gpt-6.2-astra',
        },
      }),
      { status: 200 },
    );
  });

  const res = await saveAiKey('openai', 'placeholder-key-value');
  assert.equal(res.ok, true);
  assert.match(seenUrl, /\/api\/v1\/ai-keys$/);
  if (res.ok) {
    assert.equal(res.data.providerId, 'openai');
    assert.deepEqual(res.data.discoveredModels, ['gpt-6-luna', 'gpt-6.2-astra']);
    assert.equal(
      formatRoutingBadge(res.data.routing, (id) => shortProviderLabel(labelFor(id))),
      'Active: OpenAI · worker gpt-6-luna · reasoning gpt-6.2-astra',
    );
  }
});

test('refreshAiKey posts to the OpenAI refresh endpoint and returns its models', async () => {
  mockChromeStorage();
  let seenUrl = '';
  let seenMethod = '';
  mockFetch(async (input, init) => {
    seenUrl = String(input);
    seenMethod = init?.method ?? '';
    return new Response(
      JSON.stringify({
        providerId: 'openai',
        discoveredModels: ['gpt-6-luna', 'gpt-6.2-astra'],
      }),
      { status: 200 },
    );
  });

  const res = await refreshAiKey('openai');
  assert.equal(seenMethod, 'POST');
  assert.match(seenUrl, /\/api\/v1\/ai-keys\/openai\/refresh$/);
  assert.equal(res.ok, true);
  if (res.ok) {
    assert.equal(res.data.providerId, 'openai');
    assert.deepEqual(res.data.discoveredModels, ['gpt-6-luna', 'gpt-6.2-astra']);
  }
});

test('saveAiKey failure carries the HTTP status and backend message for the inline error', async () => {
  mockChromeStorage();
  mockFetch(async () =>
    new Response(JSON.stringify({ error: 'table missing, run migrations' }), {
      status: 500,
    }),
  );

  const res = await saveAiKey('qwen', 'placeholder-key-value');
  assert.equal(res.ok, false);
  if (!res.ok) {
    assert.equal(res.status, 500);
    assert.equal(res.error, 'table missing, run migrations');
    assert.equal(
      formatSaveKeyError(res.status, res.error),
      'Save failed (HTTP 500): table missing, run migrations',
    );
  }
});

test('formatSaveKeyError falls back to a plain message when there is no HTTP status', () => {
  assert.equal(formatSaveKeyError(0, 'Backend unreachable'), 'Save failed: Backend unreachable');
  assert.equal(
    formatSaveKeyError(400, 'Please enter a valid key.'),
    'Save failed (HTTP 400): Please enter a valid key.',
  );
});

test('formatRoutingBadge names both providers when the tiers differ', () => {
  assert.equal(
    formatRoutingBadge(
      {
        workerProvider: 'qwen',
        workerModel: 'qwen3.7-plus',
        reasoningProvider: 'claude',
        reasoningModel: 'claude-sonnet-4-5',
      },
      labelFor,
    ),
    'Active: worker Qwen qwen3.7-plus · reasoning Claude claude-sonnet-4-5',
  );
});

test('formatRoutingBadge never prints null or undefined for a missing model', () => {
  const badge = formatRoutingBadge(
    {
      workerProvider: 'qwen',
      workerModel: null,
      reasoningProvider: 'qwen',
      reasoningModel: null,
    },
    labelFor,
  );
  assert.doesNotMatch(badge, /null|undefined/);
  assert.match(badge, /Active: Qwen/);
});

test('shortProviderLabel strips the parenthetical qualifier', () => {
  assert.equal(shortProviderLabel('Qwen (DashScope)'), 'Qwen');
  assert.equal(shortProviderLabel('Gemini'), 'Gemini');
  assert.equal(shortProviderLabel('Ollama (Local)'), 'Ollama');
});

test('popup markup hides routing behind the Advanced toggle and shows a badge slot', () => {
  const html = readFileSync(new URL('../popup/popup.html', import.meta.url), 'utf8');
  const detailsAt = html.indexOf('<details id="routing-advanced"');
  assert.notEqual(detailsAt, -1, 'routing fields live in a collapsed details section');
  assert.match(html.slice(detailsAt), /Advanced: override models/);
  const detailsEnd = html.indexOf('</details>', detailsAt);
  const inside = html.slice(detailsAt, detailsEnd);
  for (const id of [
    'routing-worker-provider',
    'routing-worker-model',
    'routing-reasoning-provider',
    'routing-reasoning-model',
    'routing-save',
    'routing-error',
  ]) {
    assert.ok(inside.includes(`id="${id}"`), `${id} is inside the Advanced section`);
  }
  assert.match(html, /id="ai-keys-badge"[^>]*hidden/);
  // No model name is baked into the static markup as if it were the config.
  assert.doesNotMatch(html, /qwen-plus|qwen-max|gemini-2\.5|gemini/i);
});

test('empty state names no provider models', () => {
  const active = readFileSync(new URL('../popup/active.ts', import.meta.url), 'utf8');
  const emptyAt = active.indexOf('No provider keys saved yet.');
  assert.notEqual(emptyAt, -1, 'empty state text exists');
  assert.match(active, /keys\.data\.keys\.length === 0/);
  assert.match(active, /hideRoutingBadge\(\)/);
});

test('refreshAiKey posts to the per-provider refresh endpoint and returns the list', async () => {
  mockChromeStorage();
  let seenUrl = '';
  let seenMethod = '';
  mockFetch(async (input, init) => {
    seenUrl = String(input);
    seenMethod = init?.method ?? '';
    return new Response(
      JSON.stringify({
        providerId: 'qwen',
        discoveredModels: ['qwen3.7-plus', 'qwen4-max', 'qwen3-max'],
      }),
      { status: 200 },
    );
  });

  const res = await refreshAiKey('qwen');
  assert.equal(seenMethod, 'POST');
  assert.match(seenUrl, /\/api\/v1\/ai-keys\/qwen\/refresh$/);
  assert.equal(res.ok, true);
  if (res.ok) {
    assert.equal(res.data.providerId, 'qwen');
    assert.deepEqual(res.data.discoveredModels, ['qwen3.7-plus', 'qwen4-max', 'qwen3-max']);
  }
});

test('refreshAiKey failure carries the HTTP status and backend message for the inline error', async () => {
  mockChromeStorage();
  mockFetch(async () =>
    new Response(JSON.stringify({ error: 'provider unreachable' }), { status: 502 }),
  );

  const res = await refreshAiKey('qwen');
  assert.equal(res.ok, false);
  if (!res.ok) {
    assert.equal(res.status, 502);
    assert.equal(res.error, 'provider unreachable');
  }
});

test('popup markup has a models line under the badge and override dropdowns in Advanced', () => {
  const html = readFileSync(new URL('../popup/popup.html', import.meta.url), 'utf8');
  const badgeAt = html.indexOf('id="ai-keys-badge"');
  assert.notEqual(badgeAt, -1, 'badge slot exists');
  const modelsAt = html.indexOf('id="ai-keys-models"');
  assert.notEqual(modelsAt, -1, 'models line exists');
  assert.ok(modelsAt > badgeAt, 'models line sits under the badge');
  assert.match(html.slice(modelsAt), /hidden/);
  const detailsAt = html.indexOf('<details id="routing-advanced"');
  const detailsEnd = html.indexOf('</details>', detailsAt);
  const inside = html.slice(detailsAt, detailsEnd);
  for (const id of ['routing-worker-model-select', 'routing-reasoning-model-select']) {
    assert.ok(inside.includes(`id="${id}"`), `${id} is inside the Advanced section`);
  }
  // The plain text inputs stay as the custom-id field and the no-list fallback.
  for (const id of ['routing-worker-model', 'routing-reasoning-model']) {
    assert.ok(inside.includes(`id="${id}"`), `${id} is inside the Advanced section`);
  }
});

test('discovered list under the badge is capped at six with a remainder count', () => {
  const active = readFileSync(new URL('../popup/active.ts', import.meta.url), 'utf8');
  assert.match(active, /MAX_MODELS_SHOWN = 6/);
  assert.match(active, /slice\(0, MAX_MODELS_SHOWN\)/);
  assert.match(active, /can use: /);
  assert.match(active, /\+\$\{rest\} more/);
});

test('null discovered list shows the re-save/refresh hint and never a fabricated list', () => {
  const active = readFileSync(new URL('../popup/active.ts', import.meta.url), 'utf8');
  assert.match(active, /Re-save the key, or refresh, to see its models/);
  // The list line only renders when the backend actually returned models.
  assert.match(active, /if \(models && models\.length > 0\)/);
});

test('override dropdowns are built from the discovered list with a custom option', () => {
  const active = readFileSync(new URL('../popup/active.ts', import.meta.url), 'utf8');
  assert.match(active, /discoveredModelsFor\(providerId\)/);
  assert.match(active, /Custom model ID…/);
  assert.match(active, /CUSTOM_MODEL_OPTION = '__custom__'/);
  // A typed custom id survives the list loading instead of being overwritten.
  assert.match(active, /typed !== ''/);
  assert.match(active, /select\.value = CUSTOM_MODEL_OPTION/);
});

test('refresh updates the shown list in place and failures surface inline', () => {
  const active = readFileSync(new URL('../popup/active.ts', import.meta.url), 'utf8');
  assert.match(active, /refreshAiKey\(key\.providerId\)/);
  assert.match(active, /await refreshAiKeysSection\(\)/);
  assert.match(active, /Refresh failed \(HTTP \$\{res\.status\}\): \$\{res\.error\}/);
  assert.match(active, /Refresh failed: \$\{res\.error\}/);
});

test('save failure still surfaces inline in the popup', () => {
  const active = readFileSync(new URL('../popup/active.ts', import.meta.url), 'utf8');
  assert.match(active, /formatSaveKeyError\(res\.status, res\.error\)/);
  assert.match(active, /showAiKeyError\(err instanceof Error \? err\.message/);
});

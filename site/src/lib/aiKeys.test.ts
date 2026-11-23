import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  deleteAiKey,
  fetchCapabilities,
  listAiKeys,
  ollamaCapability,
  resolveQwenBaseUrl,
  saveAiKey,
  updateRouting,
} from './aiKeys.ts';
import type { CapabilitiesResponse } from './aiKeys.ts';

function stubFetch(status: number, body: unknown = {}): typeof fetch {
  return (async () => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  })) as unknown as typeof fetch;
}

const cloudCapabilities: CapabilitiesResponse = {
  version: '0.4.0',
  runtime: 'cloud',
  llmProviders: [
    {
      id: 'qwen',
      label: 'Qwen (DashScope)',
      mode: 'hosted',
      available: true,
      defaultModels: { worker: 'qwen-plus', reasoning: 'qwen-max' },
    },
    {
      id: 'ollama',
      label: 'Ollama (Local)',
      mode: 'local',
      available: false,
      reason: 'Requires local backend',
      defaultModels: { worker: 'qwen2.5:14b', reasoning: 'deepseek-r1:14b' },
    },
  ],
  engines: [],
};

test('deleteAiKey surfaces non-ok errors instead of silently succeeding', async () => {
  const failed = await deleteAiKey('qwen', stubFetch(500, { error: 'database down' }));
  assert.equal(failed.ok, false);
  if (!failed.ok) {
    assert.equal(failed.status, 500);
    assert.equal(failed.error, 'database down');
  }

  const missing = await deleteAiKey(
    'kimi',
    (async () => ({
      ok: false,
      status: 404,
      json: async () => {
        throw new Error('no body');
      },
    })) as unknown as typeof fetch,
  );
  assert.equal(missing.ok, false);
  if (!missing.ok) {
    assert.equal(missing.status, 404);
    assert.match(missing.error, /404/);
  }
});

test('cloud capabilities disable Ollama with its exact reason string', () => {
  const ollama = ollamaCapability(cloudCapabilities);
  assert.notEqual(ollama, undefined);
  assert.equal(ollama?.available, false);
  assert.equal(ollama?.reason, 'Requires local backend');
  assert.equal(cloudCapabilities.runtime, 'cloud');
});

test('fetchCapabilities reports a network failure instead of throwing', async () => {
  const throwing = (async () => {
    throw new Error('fetch failed');
  }) as unknown as typeof fetch;
  const result = await fetchCapabilities(throwing);
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.status, 0);
    assert.equal(result.error, 'fetch failed');
  }
});

test('listAiKeys returns the typed keys list and routing on success', async () => {
  const body = {
    keys: [
      {
        providerId: 'qwen',
        keyHint: '****1a2b',
        baseUrl: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1',
        verifiedAt: '2026-11-24T00:00:00.000Z',
      },
    ],
    routing: {
      workerProvider: 'qwen',
      workerModel: 'qwen-plus',
      reasoningProvider: 'qwen',
      reasoningModel: 'qwen-max',
    },
    hasByok: true,
  };
  const result = await listAiKeys(stubFetch(200, body));
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.data.keys[0]?.keyHint, '****1a2b');
    assert.equal(result.data.routing.workerModel, 'qwen-plus');
    assert.equal(result.data.hasByok, true);
  }
});

test('saveAiKey sends the provider payload and surfaces a 400 error', async () => {
  const seen: { url: string; body: string }[] = [];
  const recording = (async (url: string, init: { body?: string }) => {
    seen.push({ url, body: init.body ?? '' });
    return { ok: false, status: 400, json: async () => ({ error: 'Invalid Qwen API key.' }) };
  }) as unknown as typeof fetch;
  const result = await saveAiKey(
    { providerId: 'qwen', apiKey: 'sk-bad', baseUrl: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1' },
    recording,
  );
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.error, 'Invalid Qwen API key.');
  assert.equal(seen[0]?.url, '/api/v1/ai-keys');
  assert.equal(JSON.parse(seen[0]?.body ?? '{}').providerId, 'qwen');
});

test('updateRouting returns the saved routing on success', async () => {
  const routing = {
    workerProvider: 'deepseek',
    workerModel: 'deepseek-chat',
    reasoningProvider: 'claude',
    reasoningModel: 'claude-sonnet-4-5',
  };
  const result = await updateRouting(routing, stubFetch(200, { routing }));
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.data.routing.reasoningModel, 'claude-sonnet-4-5');
});

test('resolveQwenBaseUrl maps regions and rejects an empty custom URL', () => {
  assert.equal(
    resolveQwenBaseUrl('intl', ''),
    'https://dashscope-intl.aliyuncs.com/compatible-mode/v1',
  );
  assert.equal(
    resolveQwenBaseUrl('cn', ''),
    'https://dashscope.aliyuncs.com/compatible-mode/v1',
  );
  assert.equal(resolveQwenBaseUrl('custom', ''), null);
  assert.equal(
    resolveQwenBaseUrl('custom', 'https://x.aliyuncs.com/compatible-mode/v1/'),
    'https://x.aliyuncs.com/compatible-mode/v1',
  );
});

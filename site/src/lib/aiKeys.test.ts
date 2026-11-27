import { test } from 'node:test';
import assert from 'node:assert/strict';
import { formatKeyStatus, listAiKeys } from './aiKeys.ts';
import type { SavedAiKey } from './aiKeys.ts';

function stubFetch(status: number, body: unknown = {}): typeof fetch {
  return (async () => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  })) as unknown as typeof fetch;
}

function savedKey(
  providerId: SavedAiKey['providerId'],
  discoveredModels: string[] | null = null,
): SavedAiKey {
  return {
    providerId,
    keyHint: '****1a2b',
    baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1',
    verifiedAt: '2026-11-24T00:00:00.000Z',
    discoveredModels,
  };
}

test('listAiKeys returns the typed keys list on success', async () => {
  const body = { keys: [savedKey('qwen')], hasByok: true };
  const result = await listAiKeys(stubFetch(200, body));
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.data.keys[0]?.providerId, 'qwen');
    assert.equal(result.data.keys[0]?.keyHint, '****1a2b');
    assert.equal(result.data.hasByok, true);
  }
});

test('listAiKeys surfaces a non-ok status and error instead of throwing', async () => {
  const result = await listAiKeys(stubFetch(500, { error: 'database down' }));
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.status, 500);
    assert.equal(result.error, 'database down');
  }
});

test('listAiKeys reports a network failure instead of throwing', async () => {
  const throwing = (async () => {
    throw new Error('fetch failed');
  }) as unknown as typeof fetch;
  const result = await listAiKeys(throwing);
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.status, 0);
    assert.equal(result.error, 'fetch failed');
  }
});

test('formatKeyStatus names the one saved provider', () => {
  assert.equal(
    formatKeyStatus([savedKey('qwen')]),
    'AI keys live in your extension — Qwen key saved · refresh the key in the extension to see its models',
  );
  assert.equal(
    formatKeyStatus([savedKey('gemini')]),
    'AI keys live in your extension — Gemini key saved · refresh the key in the extension to see its models',
  );
});

test('formatKeyStatus names an OpenAI key with a capital AI', () => {
  assert.equal(
    formatKeyStatus([savedKey('openai')]),
    'AI keys live in your extension — OpenAI key saved · refresh the key in the extension to see its models',
  );
});

test('formatKeyStatus names the GPT models an OpenAI key can use', () => {
  assert.equal(
    formatKeyStatus([savedKey('openai', ['gpt-6-luna', 'gpt-6.2-astra'])]),
    'AI keys live in your extension — OpenAI key saved · can use: gpt-6-luna, gpt-6.2-astra',
  );
});

test('listAiKeys returns a saved OpenAI key', async () => {
  const body = { keys: [savedKey('openai', ['gpt-6-luna'])], hasByok: true };
  const result = await listAiKeys(stubFetch(200, body));
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.data.keys[0]?.providerId, 'openai');
    assert.deepEqual(result.data.keys[0]?.discoveredModels, ['gpt-6-luna']);
  }
});

test('formatKeyStatus names an OmniRoute key with a capital R', () => {
  assert.equal(
    formatKeyStatus([savedKey('omniroute')]),
    'AI keys live in your extension — OmniRoute key saved · refresh the key in the extension to see its models',
  );
});

test('formatKeyStatus names the auto routes an OmniRoute key can use', () => {
  assert.equal(
    formatKeyStatus([savedKey('omniroute', ['auto', 'openai/gpt-6-luna'])]),
    'AI keys live in your extension — OmniRoute key saved · can use: auto, openai/gpt-6-luna',
  );
});

test('listAiKeys returns a saved OmniRoute key', async () => {
  const body = { keys: [savedKey('omniroute', ['auto'])], hasByok: true };
  const result = await listAiKeys(stubFetch(200, body));
  assert.equal(result.ok, true);
  if (result.ok) {
    assert.equal(result.data.keys[0]?.providerId, 'omniroute');
    assert.deepEqual(result.data.keys[0]?.discoveredModels, ['auto']);
  }
});

test('formatKeyStatus joins several saved providers', () => {
  assert.equal(
    formatKeyStatus([savedKey('qwen'), savedKey('gemini')]),
    'AI keys live in your extension — Qwen, Gemini keys saved · refresh the keys in the extension to see their models',
  );
});

test('formatKeyStatus names the models a key can use, capped at four', () => {
  const models = [
    'qwen3.7-plus',
    'qwen4-max',
    'qwen3.5',
    'qwen3.2',
    'qwen3.1',
    'qwen3',
  ];
  assert.equal(
    formatKeyStatus([savedKey('qwen', models)]),
    'AI keys live in your extension — Qwen key saved · can use: qwen3.7-plus, qwen4-max, qwen3.5, qwen3.2, +2 more',
  );
});

test('formatKeyStatus lists every model when four or fewer were found', () => {
  assert.equal(
    formatKeyStatus([savedKey('qwen', ['qwen3.7-plus', 'qwen4-max'])]),
    'AI keys live in your extension — Qwen key saved · can use: qwen3.7-plus, qwen4-max',
  );
});

test('formatKeyStatus hints at a refresh when no models were discovered', () => {
  assert.equal(
    formatKeyStatus([savedKey('qwen', null)]),
    'AI keys live in your extension — Qwen key saved · refresh the key in the extension to see its models',
  );
});

test('formatKeyStatus treats a missing discoveredModels field as null', () => {
  const key = savedKey('qwen');
  delete (key as Partial<SavedAiKey>).discoveredModels;
  assert.equal(
    formatKeyStatus([key]),
    'AI keys live in your extension — Qwen key saved · refresh the key in the extension to see its models',
  );
});

test('formatKeyStatus shows models across several keys', () => {
  assert.equal(
    formatKeyStatus([
      savedKey('qwen', ['qwen3.7-plus', 'qwen4-max']),
      savedKey('gemini', ['gemini-2.5-flash']),
    ]),
    'AI keys live in your extension — Qwen, Gemini keys saved · can use: qwen3.7-plus, qwen4-max, gemini-2.5-flash',
  );
});

test('formatKeyStatus says so when no key is saved', () => {
  assert.equal(formatKeyStatus([]), 'No key saved yet');
});

test('formatKeyStatus stays neutral while loading or when the check fails', () => {
  assert.equal(formatKeyStatus(null), 'AI keys live in your extension');
});

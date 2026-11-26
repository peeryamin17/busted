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

function savedKey(providerId: SavedAiKey['providerId']): SavedAiKey {
  return {
    providerId,
    keyHint: '****1a2b',
    baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1',
    verifiedAt: '2026-11-24T00:00:00.000Z',
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
    'AI keys live in your extension — Qwen key saved',
  );
  assert.equal(
    formatKeyStatus([savedKey('gemini')]),
    'AI keys live in your extension — Gemini key saved',
  );
});

test('formatKeyStatus joins several saved providers', () => {
  assert.equal(
    formatKeyStatus([savedKey('qwen'), savedKey('gemini')]),
    'AI keys live in your extension — Qwen, Gemini keys saved',
  );
});

test('formatKeyStatus says so when no key is saved', () => {
  assert.equal(formatKeyStatus([]), 'No key saved yet');
});

test('formatKeyStatus stays neutral while loading or when the check fails', () => {
  assert.equal(formatKeyStatus(null), 'AI keys live in your extension');
});

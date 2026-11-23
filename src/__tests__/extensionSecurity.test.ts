import test from 'node:test';
import assert from 'node:assert/strict';
import {
  getBackendAccount,
  runSwarmScan,
  setBackendApiKey,
  pairWithCode,
} from '../lib/apiClient.js';
import {
  restoreTabScanIfMatching,
  verifyGeminiApiKey,
} from '../lib/popupHelpers.js';
import { maskSecret, scanBundleSecrets } from '../scanners/secretScanner.js';

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

test('storing a local BYOK key alone never grants operator: true', async () => {
  mockChromeStorage({ 'bugseek:geminiApiKey': 'AIzaSyFakeLocalKey12345678901234567890' });
  mockFetch(
    async () =>
      new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 }),
  );

  const account = await getBackendAccount();
  assert.equal(account.operator, false);
  assert.equal(account.authenticated, false);
});

test('restoreTabScanIfMatching purges stale findings when tab origin changes', async () => {
  const store = mockChromeStorage({
    'scan:7': { targetUrl: 'https://juice-shop.herokuapp.com/#/', findings: [{ id: '1' }] },
  });
  let rendered = false;

  await restoreTabScanIfMatching(7, 'https://example.com/dashboard', () => {
    rendered = true;
  });

  assert.equal(rendered, false);
  assert.equal(store['scan:7'], undefined);
});

test('restoreTabScanIfMatching restores the scan when the origin matches', async () => {
  const store = mockChromeStorage({
    'scan:7': { targetUrl: 'https://example.com/page', scannedAt: '2026-11-23T00:00:00.000Z' },
  });
  let rendered = false;

  await restoreTabScanIfMatching(
    7,
    'https://example.com/other',
    (scan: { targetUrl: string }) => {
      rendered = scan.targetUrl === 'https://example.com/page';
    },
  );

  assert.equal(rendered, true);
  assert.notEqual(store['scan:7'], undefined);
});

test('verifyGeminiApiKey sends x-goog-api-key header and never puts key in URL', async () => {
  let seenUrl = '';
  let seenHeader = '';
  mockFetch(async (input, init) => {
    seenUrl = String(input);
    seenHeader = new Headers(init?.headers).get('x-goog-api-key') ?? '';
    return new Response('{}', { status: 200 });
  });

  const res = await verifyGeminiApiKey('AIzaSyTestHeaderOnlyKey123456789012345');
  assert.equal(res.valid, true);
  assert.equal(seenUrl, 'https://generativelanguage.googleapis.com/v1beta/models');
  assert.equal(seenHeader, 'AIzaSyTestHeaderOnlyKey123456789012345');
});

test('runSwarmScan aborts immediately on 401 instead of polling for 5 minutes', async () => {
  mockChromeStorage({ 'bugseek:apiKey': 'bs_expired_token' });
  let calls = 0;
  mockFetch(async (input) => {
    calls++;
    if (String(input).endsWith('/api/swarm/scans')) {
      return new Response(JSON.stringify({ jobId: 'job-1' }), { status: 202 });
    }
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  });

  await assert.rejects(() => runSwarmScan({ origin: 'https://example.com' }), /401/);
  assert.equal(calls, 2);
});

test('scanBundleSecrets catches GitHub/Slack/Google keys and masks to 4 edge chars', () => {
  const sample = `
    const gh = "ghp_1234567890abcdef1234567890abcdef1234";
    const sl = "xoxb-1234567890-1234567890-abcdefghijklmnop";
    const gg = "AIzaSyD9876543210abcdef1234567890abcdef";
  `;
  const hits = scanBundleSecrets(sample, 'https://example.com/app.js');
  assert.equal(hits.length, 3);
  assert.equal(maskSecret('ghp_1234567890abcdef1234567890abcdef1234'), 'ghp_••••1234');
});

test('pairWithCode stores the bs_ key and later calls authenticate with it', async () => {
  const store = mockChromeStorage({});
  const seenKeys: Array<string | null> = [];
  mockFetch(async (input, init) => {
    const url = String(input);
    if (url.endsWith('/api/v1/pair')) {
      return new Response(JSON.stringify({ apiKey: 'bs_testkey123' }), { status: 201 });
    }
    if (url.endsWith('/api/v1/account')) {
      seenKeys.push(new Headers(init?.headers).get('x-api-key'));
      return new Response(
        JSON.stringify({ email: 'peer@example.com', plan: 'hunter', operator: false }),
        { status: 200 },
      );
    }
    return new Response(JSON.stringify({ error: 'Not found' }), { status: 404 });
  });

  const account = await pairWithCode('ABCD1234EFGH5678IJKL9012MNOP3456');
  assert.equal(store['bugseek:apiKey'], 'bs_testkey123');
  assert.equal(account.authenticated, true);
  assert.equal(account.operator, false);
  assert.equal(seenKeys[seenKeys.length - 1], 'bs_testkey123');

  // A later call authenticates with the stored key.
  await getBackendAccount();
  assert.equal(seenKeys[seenKeys.length - 1], 'bs_testkey123');
});

test('relay BUGSEEK_CONNECT stores the bs_ key and later calls authenticate with it', async () => {
  const store = mockChromeStorage({});
  const posted: Array<Record<string, unknown>> = [];
  const handlers: Record<string, (event: unknown) => void> = {};
  (globalThis as unknown as { window: unknown }).window = {
    location: { origin: 'https://bugseek-ai.vercel.app' },
    addEventListener: (type: string, fn: (event: unknown) => void) => {
      handlers[type] = fn;
    },
    postMessage: (msg: Record<string, unknown>) => {
      posted.push(msg);
    },
  };
  const chromeObj = (globalThis as unknown as { chrome: { runtime: { sendMessage: unknown } } })
    .chrome;
  chromeObj.runtime.sendMessage = async (msg: { type: string; apiKey?: string }) => {
    if (msg.type === 'BUGSEEK_SET_API_KEY' && msg.apiKey) {
      await setBackendApiKey(msg.apiKey);
    }
    return { ok: true };
  };

  await import('../connectRelay.js');

  handlers['message']?.({
    origin: 'https://bugseek-ai.vercel.app',
    data: {
      source: 'bugseek-site',
      type: 'BUGSEEK_CONNECT',
      apiKey: 'bs_relaykey456',
    },
  });
  await new Promise((r) => setTimeout(r, 0));

  assert.equal(store['bugseek:apiKey'], 'bs_relaykey456');
  assert.equal(
    posted.some((m) => m['type'] === 'BUGSEEK_CONNECTED' && m['ok'] === true),
    true,
  );

  // A key without the bs_ prefix is refused and nothing is overwritten.
  handlers['message']?.({
    origin: 'https://bugseek-ai.vercel.app',
    data: { source: 'bugseek-site', type: 'BUGSEEK_CONNECT', apiKey: 'not-a-bs-key' },
  });
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(store['bugseek:apiKey'], 'bs_relaykey456');
  assert.equal(
    posted.some((m) => m['type'] === 'BUGSEEK_CONNECTED' && m['ok'] === false),
    true,
  );

  // A later call authenticates with the stored relay key.
  let seenKey: string | null = null;
  mockFetch(async (input, init) => {
    if (String(input).endsWith('/api/v1/account')) {
      seenKey = new Headers(init?.headers).get('x-api-key');
      return new Response(
        JSON.stringify({ email: 'peer@example.com', plan: 'hunter', operator: false }),
        { status: 200 },
      );
    }
    return new Response(JSON.stringify({ error: 'Not found' }), { status: 404 });
  });
  await getBackendAccount();
  assert.equal(seenKey, 'bs_relaykey456');
});

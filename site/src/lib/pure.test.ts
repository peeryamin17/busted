import { test } from 'node:test';
import assert from 'node:assert/strict';
import { probeSession } from './probeSession.ts';
import { formatPairingCode } from './pairing.ts';
import { safeExternalUrl } from './urls.ts';
import { mergeCoverageClasses } from './coverage.ts';
import { decideApproval, shouldKeepPolling } from './approvals.ts';
import { ExtensionKeyMint } from './keyMint.ts';

function stubFetch(status: number, body: unknown = {}): typeof fetch {
  return (async () => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  })) as unknown as typeof fetch;
}

test('probeSession returns backend_waking on a 503 and on network errors', async () => {
  const realFetch = globalThis.fetch;
  try {
    globalThis.fetch = stubFetch(503);
    assert.equal((await probeSession()).status, 'backend_waking');
    globalThis.fetch = (async () => {
      throw new Error('fetch failed');
    }) as unknown as typeof fetch;
    const waking = await probeSession();
    assert.equal(waking.status, 'backend_waking');
    if (waking.status === 'backend_waking') assert.match(waking.detail, /fetch failed/);
    globalThis.fetch = stubFetch(401);
    assert.equal((await probeSession()).status, 'unauthenticated');
    globalThis.fetch = stubFetch(403);
    assert.equal((await probeSession()).status, 'unauthenticated');
    globalThis.fetch = stubFetch(200, {
      user: { id: 'u1', email: 'a@b.c', name: null, avatar: null, plan: 'free' },
      credits: null,
    });
    const ok = await probeSession();
    assert.equal(ok.status, 'authenticated');
    if (ok.status === 'authenticated') assert.equal(ok.user.email, 'a@b.c');
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('formatPairingCode keeps trailing characters on non-multiple-of-4 codes', () => {
  assert.equal(formatPairingCode('abcdefghij'), 'abcd-efgh-ij');
  assert.equal(formatPairingCode('abcde'), 'abcd-e');
  assert.equal(formatPairingCode('abcdefgh'), 'abcd-efgh');
  assert.equal(formatPairingCode(''), '');
});

test('ExtensionKeyMint mints once across rapid clicks and reuses the live key', async () => {
  const guard = new ExtensionKeyMint();
  let calls = 0;
  const mint = async () => {
    calls += 1;
    await new Promise((r) => setTimeout(r, 10));
    return 'bs_testkey';
  };
  const [a, b, c] = await Promise.all([guard.mint(mint), guard.mint(mint), guard.mint(mint)]);
  assert.equal(calls, 1);
  assert.equal(a, 'bs_testkey');
  assert.equal(b, 'bs_testkey');
  assert.equal(c, 'bs_testkey');
  assert.equal(await guard.mint(mint), 'bs_testkey');
  assert.equal(calls, 1);
});

test('ExtensionKeyMint retries after a failed mint', async () => {
  const guard = new ExtensionKeyMint();
  let calls = 0;
  await assert.rejects(() =>
    guard.mint(async () => {
      calls += 1;
      throw new Error('mint failed');
    }),
  );
  assert.equal(await guard.mint(async () => 'bs_second'), 'bs_second');
  assert.equal(calls, 1);
});

test('safeExternalUrl rejects javascript: and data: but allows https:', () => {
  assert.equal(safeExternalUrl('javascript:alert(1)'), null);
  assert.equal(safeExternalUrl('data:text/html,<script>alert(1)</script>'), null);
  assert.equal(safeExternalUrl('https://example.com/a?b=c'), 'https://example.com/a?b=c');
  assert.equal(safeExternalUrl('http://example.com'), 'http://example.com/');
  assert.equal(safeExternalUrl('not a url'), null);
});

test('decideApproval aborts when the standing-rule post fails', async () => {
  let decideCalls = 0;
  const fetchImpl = (async (url: string) => {
    if (url.endsWith('/rules')) return { ok: false, status: 500 };
    decideCalls += 1;
    return { ok: true, status: 200 };
  }) as unknown as typeof fetch;
  await assert.rejects(() =>
    decideApproval({
      taskId: 't1',
      approvalId: 'a1',
      decision: 'allow',
      alwaysAllow: true,
      pattern: { kind: 'tool', value: 'fetch' },
      fetchImpl,
    }),
  );
  assert.equal(decideCalls, 0);
});

test('decideApproval surfaces a failed decide post', async () => {
  const fetchImpl = stubFetch(500);
  await assert.rejects(() =>
    decideApproval({
      taskId: 't1',
      approvalId: 'a1',
      decision: 'deny',
      alwaysAllow: false,
      pattern: { kind: 'tool', value: 'fetch' },
      fetchImpl,
    }),
  );
});

test('decideApproval posts the rule then the decision on success', async () => {
  const seen: string[] = [];
  const fetchImpl = (async (url: string) => {
    seen.push(url);
    return { ok: true, status: 200 };
  }) as unknown as typeof fetch;
  await decideApproval({
    taskId: 't1',
    approvalId: 'a1',
    decision: 'allow',
    alwaysAllow: true,
    pattern: { kind: 'tool', value: 'fetch' },
    fetchImpl,
  });
  assert.deepEqual(seen, ['/api/tasks/t1/approvals/rules', '/api/tasks/t1/approvals/a1/decide']);
});

test('shouldKeepPolling stays on after a load error even with nothing pending', () => {
  assert.equal(shouldKeepPolling(false, true), true);
  assert.equal(shouldKeepPolling(true, false), true);
  assert.equal(shouldKeepPolling(false, false), false);
});

test('mergeCoverageClasses keeps unknown backend classes instead of dropping them', () => {
  const rows = mergeCoverageClasses({
    recon: { tested: 1, untested: 0, finding: 0, notApplicable: 0 },
    ssrf: { tested: 0, untested: 2, finding: 1, notApplicable: 0 },
    'api-abuse': { tested: 3, untested: 0, finding: 0, notApplicable: 0 },
  });
  assert.equal(rows.length, 12);
  assert.equal(rows[0].id, 'recon');
  const extra = rows.filter((r) => r.id === 'ssrf' || r.id === 'api-abuse');
  assert.deepEqual(
    extra.map((r) => r.id),
    ['api-abuse', 'ssrf'],
  );
  assert.equal(extra.find((r) => r.id === 'ssrf')?.counts.finding, 1);
});

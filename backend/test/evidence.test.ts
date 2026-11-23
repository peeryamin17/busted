/**
 * Unit tests for content-addressed evidence snapshots
 * (src/evidence/snapshots.ts). MemoryEvidenceStore only, the Postgres
 * store needs a live database and is wired by the coordinator.
 *
 * Run:  npx tsx test/evidence.test.ts   (from backend/)
 */
import {
  MAX_BODY_BYTES,
  MemoryEvidenceStore,
  createSnapshot,
  snapshotHash,
  type EvidenceSnapshot,
} from '../src/evidence/snapshots.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

const BASE = {
  role: 'proof' as const,
  url: 'https://example.com/search?q=bs0123456789abcdef',
  request: 'GET /search?q=<canary>',
  body: '<html><body>results for bs0123456789abcdef</body></html>',
};

async function main() {
  // ── 1. Hash determinism ──
  {
    const a = snapshotHash(BASE);
    const b = snapshotHash({ ...BASE });
    check('hash: same input → same hash', a === b, `${a} vs ${b}`);
    check('hash: 64 hex chars (SHA-256)', /^[0-9a-f]{64}$/.test(a), a);
    const c = createSnapshot(BASE);
    check('hash: createSnapshot agrees with snapshotHash', c.sha256 === a, c.sha256);
  }

  // ── 2. Sensitivity: changing one field changes the hash ──
  {
    const base = snapshotHash(BASE);
    check('hash: role change → different hash', snapshotHash({ ...BASE, role: 'baseline' }) !== base);
    check('hash: url change → different hash', snapshotHash({ ...BASE, url: 'https://example.com/other' }) !== base);
    check('hash: request change → different hash', snapshotHash({ ...BASE, request: 'GET /other' }) !== base);
    check('hash: body change → different hash', snapshotHash({ ...BASE, body: '<html>different</html>' }) !== base);
    check('hash: url whitespace is trimmed (same hash)', snapshotHash({ ...BASE, url: `  ${BASE.url}  ` }) === base);
    check('hash: request whitespace is trimmed (same hash)', snapshotHash({ ...BASE, request: ` ${BASE.request}\n` }) === base);
  }

  // ── 3. Identity exclusion: finding/task identity never affects the hash ──
  {
    const a = snapshotHash({ ...BASE, findingId: 'finding-aaa', taskId: 'task-111' });
    const b = snapshotHash({ ...BASE, findingId: 'finding-bbb', taskId: 'task-222' });
    const c = snapshotHash(BASE);
    check('hash: findingId/taskId excluded (different ids, same hash)', a === b, `${a} vs ${b}`);
    check('hash: identity fields excluded (with vs without, same hash)', a === c, `${a} vs ${c}`);
  }

  // ── 4. Body cap: 256 KiB truncation is recorded, never silent ──
  {
    const big = 'x'.repeat(MAX_BODY_BYTES + 1000);
    const snap = createSnapshot({ ...BASE, body: big });
    check('cap: body truncated to 256 KiB', Buffer.byteLength(snap.body, 'utf8') <= MAX_BODY_BYTES, Buffer.byteLength(snap.body, 'utf8'));
    check('cap: truncation recorded in request field', /truncated/i.test(snap.request), snap.request);
    check('cap: truncated snapshot still hashes deterministically',
      snap.sha256 === snapshotHash({ ...BASE, body: big }));
    const small = createSnapshot(BASE);
    check('cap: under-cap body not marked truncated', !/truncated/i.test(small.request));
  }

  // ── 5. MemoryEvidenceStore: idempotent put, get, list, verify ──
  {
    const store = new MemoryEvidenceStore();
    const snap = createSnapshot(BASE);
    const first = await store.put(snap, { findingId: 'finding-1' });
    const second = await store.put(createSnapshot(BASE), { findingId: 'finding-1' });
    check('store: idempotent put (same sha256 twice stores once)',
      first.sha256 === second.sha256 && store.snapshots.size === 1, store.snapshots.size);
    check('store: get returns the snapshot', (await store.get(snap.sha256))?.sha256 === snap.sha256);
    check('store: get unknown hash → null', (await store.get('0'.repeat(64))) === null);
    check('store: verify passes on untampered snapshot', await store.verify(snap.sha256));
    check('store: verify false on unknown hash', (await store.verify('0'.repeat(64))) === false);

    // Same content linked to a second finding: still one snapshot, both findings list it.
    await store.put(snap, { findingId: 'finding-2' });
    check('store: same content under two findings still one snapshot', store.snapshots.size === 1);
    const forF1 = await store.listForFinding('finding-1');
    const forF2 = await store.listForFinding('finding-2');
    check('store: listForFinding returns the snapshot for finding-1',
      forF1.length === 1 && forF1[0].sha256 === snap.sha256, forF1);
    check('store: listForFinding returns the snapshot for finding-2',
      forF2.length === 1 && forF2[0].sha256 === snap.sha256, forF2);
    check('store: listForFinding unknown finding → empty', (await store.listForFinding('finding-zzz')).length === 0);

    // Tamper simulation: mutate the stored body → verify must fail.
    const stored = store.snapshots.get(snap.sha256) as EvidenceSnapshot;
    stored.body = '<html><body>TAMPERED — canary never reflected here</body></html>';
    check('store: verify detects tampering (mutated body → false)', (await store.verify(snap.sha256)) === false);
    // And the tampered body no longer matches the original hash at all.
    check('store: tampered body hashes differently',
      snapshotHash(stored) !== snap.sha256);
  }

  if (failures > 0) { console.error(`${failures} evidence test(s) failed`); process.exit(1); }
  console.log('ALL EVIDENCE TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('evidence test crashed', e); process.exit(1); });

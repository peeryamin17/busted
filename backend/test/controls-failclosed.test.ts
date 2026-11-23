/**
 * Fail-closed controls tests (Batch 2: H5, H6, H11, H12, H13, M1).
 *
 * - Worker refuses a half-wired task context (owner but no approval
 *   queue) instead of running ungated; a recording-only context
 *   (no owner, no queue) still runs as before.
 * - POST /api/import/findings: missing authorization → 400, free
 *   plan → 403.
 * - Redaction covers the new secret shapes, including inside
 *   reproSteps / references / chainWith.
 * - A paused worker still stops at its deadline instead of hanging.
 * - decodeBody caps decompressed output and rejects corrupt input.
 *
 * Run:  npx tsx test/controls-failclosed.test.ts   (from backend/)
 */
import Fastify from 'fastify';
import { deflateSync, gzipSync } from 'node:zlib';
import { engineRoutes } from '../src/routes/engines.js';
import { MockProvider } from '../src/llm/mock.js';
import { runWorker } from '../src/multiagent/worker.js';
import type { SpecialistDef, WorkerContext } from '../src/multiagent/types.js';
import { MemoryGraphStore } from '../src/graph/store.js';
import { MemoryCoverageStore } from '../src/coverage/ledger.js';
import { MemoryEvidenceStore } from '../src/evidence/snapshots.js';
import { redactFindingEvidence, redactText } from '../src/guardrails/redact.js';
import { decodeBody } from '../src/webcheck/fetch.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) {
    failures++;
    console.error(`FAIL: ${name}`, extra ?? '');
  } else console.log(`ok: ${name}`);
}

async function checkRejects(name: string, p: Promise<unknown>, re: RegExp) {
  try {
    await p;
    check(name, false, 'resolved, expected a rejection');
  } catch (err) {
    check(name, re.test((err as Error).message), (err as Error).message);
  }
}

const authz = {
  type: 'ownership',
  statement: 'I own this local test server and authorize testing of it.',
  confirmed: true,
};

function makeDb(plan: 'free' | 'hunter' | 'pro' = 'pro') {
  const db: any = {
    kind: 'stub',
    async getApiKeyByHash() { return { userId: 'u1', revokedAt: null }; },
    async getUserById() { return { id: 'u1', email: 't@e.com', plan }; },
    async getAiKey() { return null; },
    async touchApiKey() { /* stub */ },
    async createAuthorization(input: any) { return { id: 'authz-1', ...input }; },
    async createScan(input: any) { return { id: 'scan-1', status: 'queued', ...input }; },
    async getScan() { return null; },
    async listFindings() { return []; },
    async updateScan(id: string, patch: any) { return { id, ...patch }; },
    async recordUsage() { /* stub */ },
    async sumUsageSince() { return 0; },
    async addFinding(f: any) { return { ...f, id: 'f-1' }; },
    async addFindings(items: any[]) { return items; },
  };
  return db;
}

function workerDef(): SpecialistDef {
  return {
    id: 'recon',
    name: 'Recon',
    expertise: 'Recon specialist.',
    systemPrompt: 'You are a recon specialist.',
    tools: ['fetch_url'],
    maxActions: 1,
    maxEscalations: 0,
  };
}

function workerCtx(overrides: Partial<WorkerContext> = {}): WorkerContext {
  return {
    provider: new MockProvider(),
    tools: [
      {
        name: 'fetch_url',
        description: 'Fetch a URL.',
        run: async () => ({ ok: true, status: 200, bodySnippet: '<html>lab</html>', timingMs: 1, data: {} }),
      },
    ],
    toolCtx: {} as any,
    targetUrl: 'http://127.0.0.1:9/',
    scope: { mode: 'subdomain', includeSubdomains: false, excludedHosts: [], excludedPaths: [], maxRequestsPerSecond: 5 },
    techStack: [],
    priorFindings: [],
    deadline: Date.now() + 60_000,
    tokenBudget: { input: 0, output: 0, max: 100_000 },
    ...overrides,
  };
}

async function main() {
  const graph = new MemoryGraphStore();
  const coverage = new MemoryCoverageStore();
  const evidence = new MemoryEvidenceStore();

  // Worker fail-closed: owner without an approval queue refuses to run.
  await checkRejects(
    'worker: half-wired task (userId, no approvals) throws instead of running ungated',
    runWorker(workerDef(), workerCtx({
      task: { taskId: 't1', graph, coverage, evidence, userId: 'u1' },
    })),
    /approval queue/,
  );

  // Recording-only context (no owner, no queue) proceeds exactly as before.
  const recorded = await runWorker(workerDef(), workerCtx({
    task: { taskId: 't2', graph, coverage, evidence },
  }));
  check('worker: recording-only task still runs', recorded.testsRun === 1, recorded);

  // Import gate: missing authorization → 400, free plan → 403.
  {
    const app = Fastify();
    await engineRoutes(app as any, { db: makeDb('pro'), queue: {} as any, provider: new MockProvider() });
    const r = await app.inject({
      method: 'POST', url: '/api/import/findings',
      headers: { 'x-api-key': 'bs_test' },
      payload: { format: 'auto', content: 'xx', targetUrl: 'https://example.com' },
    });
    check('import: missing authorization → 400', r.statusCode === 400, r.body.slice(0, 120));
    await app.close();
  }
  {
    const app = Fastify();
    await engineRoutes(app as any, { db: makeDb('free'), queue: {} as any, provider: new MockProvider() });
    const r = await app.inject({
      method: 'POST', url: '/api/import/findings',
      headers: { 'x-api-key': 'bs_test' },
      payload: { format: 'auto', content: 'xx', targetUrl: 'https://example.com', authorization: authz },
    });
    check('import: free plan → 403', r.statusCode === 403, r.body.slice(0, 120));
    await app.close();
  }

  // Redaction: the new secret shapes, none of which may leak verbatim.
  // Fixtures only, never real credentials; the AWS secret is the
  // example from the AWS docs.
  const tokens: Array<[string, string]> = [
    ['ghp_', 'ghp_AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIj'],
    ['github_pat_', 'github_pat_AbCdEfGhIjKlMnOpQrStUv_AbCdEfGhIjKlMnOpQrStUvWxYzAbCd'],
    ['xoxb-', 'xoxb-AbCdEfGhIjKl-AbCdEfGhIjKl-AbCdEfGhIjKlMnOpQrStUvWx'],
    ['AIza', 'AIzaAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhI'],
    ['AQ.', 'AQ.AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv'],
    ['sk-proj-', 'sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv'],
    ['glpat-', 'glpat-AbCdEfGhIjKlMnOpQrSt'],
    ['bare AWS secret', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'],
  ];
  for (const [shape, token] of tokens) {
    const out = redactText(`leaked ${token} here`, 5000);
    check(`redact: ${shape} token scrubbed`, !out.includes(token), out);
    check(`redact: ${shape} prefix scrubbed`, !out.includes(shape), out);
  }
  const planted = redactFindingEvidence({
    evidence: 'key ghp_AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIj here',
    title: 'leak AQ.AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv',
    reproSteps: ['curl -H "Authorization: Bearer xoxb-AbCdEfGhIjKl-AbCdEfGhIjKl-AbCdEfGhIjKlMnOpQrStUvWx" https://example.com'],
    references: ['https://example.com/?k=AIzaAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhI'],
    chainWith: ['sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv'],
  } as any);
  check('redact: reproSteps scrubbed', !JSON.stringify(planted.reproSteps).includes('xoxb-'), planted.reproSteps);
  check('redact: references scrubbed', !JSON.stringify(planted.references).includes('AIza'), planted.references);
  check('redact: chainWith scrubbed', !JSON.stringify(planted.chainWith).includes('sk-proj-'), planted.chainWith);
  check('redact: evidence scrubbed', !String(planted.evidence).includes('ghp_'), planted.evidence);
  check('redact: title scrubbed', !String(planted.title).includes('AQ.'), planted.title);

  // Pause deadline: a worker paused forever must still stop on time.
  {
    const started = Date.now();
    const raced = await Promise.race([
      runWorker(workerDef(), workerCtx({
        deadline: Date.now() + 2500,
        shouldContinue: () => 'paused',
      })).then((report) => ({ done: true as const, report })),
      new Promise((resolve) => setTimeout(() => resolve({ done: false as const }), 10_000)),
    ]);
    const elapsed = Date.now() - started;
    check('worker: paused run returns instead of hanging', raced.done, `elapsed ${elapsed}ms`);
    check('worker: paused run stops near its deadline', elapsed < 8000, `elapsed ${elapsed}ms`);
  }

  // Decompression cap: a gzip bomb past the cap decodes to '', small
  // bodies still decode, corrupt input decodes to ''.
  check(
    'decodeBody: small gzip decodes',
    (await decodeBody(gzipSync('hello world'), 'gzip')) === 'hello world',
  );
  check(
    'decodeBody: gzip bomb over the cap returns empty',
    (await decodeBody(gzipSync('A'.repeat(100_000)), 'gzip', 1000)) === '',
  );
  check(
    'decodeBody: deflate decodes',
    (await decodeBody(deflateSync('hello'), 'deflate')) === 'hello',
  );
  check(
    'decodeBody: corrupt gzip returns empty',
    (await decodeBody(Buffer.from('not gzip at all'), 'gzip')) === '',
  );
  check(
    'decodeBody: uncompressed body passes through',
    (await decodeBody(Buffer.from('plain'), undefined)) === 'plain',
  );

  if (failures > 0) {
    console.error(`${failures} CONTROLS-FAILCLOSED TEST(S) FAILED`);
    process.exit(1);
  }
  console.log('ALL CONTROLS-FAILCLOSED TESTS PASSED');
}

main();

/**
 * Head-agent integration test: a full mock-provider swarm run
 * inside a task, against a tiny local HTTP server that echoes query
 * parameters unencoded and serves no security headers.
 *
 * Proves the wiring end to end (no single piece in isolation):
 * goal decomposition → persistent todolist → intent/fact/finding graph
 * nodes + asset anchors → per-specialist coverage entries → depth
 * ladder → POE + verbatim-receipt proof gate → content-addressed proof
 * snapshots carried on the outcome.
 *
 * The echo server makes the XSS worker's benign canary reflect, so the
 * ladder confirms and escalates it: that finding must come out
 * 'verified' at POE 3 with a passing receipt and snapshots whose hashes
 * verify. The missing-headers finding has no live probe, so it must stay
 * a hint at POE 0. GraphQL is never spawned, so it must read untested.
 */
import { createServer, type Server } from 'node:http';
import { MockProvider } from '../src/llm/mock.js';
import { MemoryGraphStore } from '../src/graph/store.js';
import { MemoryCoverageStore, coverageSummary } from '../src/coverage/ledger.js';
import { MemoryEvidenceStore } from '../src/evidence/snapshots.js';
import { snapshotHash } from '../src/evidence/snapshots.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) {
    failures++;
    console.error(`FAIL: ${name}`, extra ?? '');
  } else console.log(`ok: ${name}`);
}

async function main() {
  // Local target on 127.0.0.1: the head agent reads the SSRF guard config
  // at import time, so set the allowance before importing it. The guard
  // stays off by default everywhere else.
  process.env['ALLOW_PRIVATE_TARGETS'] = '1';
  const { runHeadAgent } = await import('../src/multiagent/head.js');

  // Local target: echoes any query-param value unencoded in the body
  // (so the canary reflects), serves no security headers, no cookies,
  // no CORS headers, no Server header.
  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const echoed = [...url.searchParams.values()].join(' ');
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<html><head><title>lab</title></head><body><p>hello ${echoed}</p></body></html>`);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;
  const targetUrl = `http://127.0.0.1:${port}/`;

  const graph = new MemoryGraphStore();
  const coverage = new MemoryCoverageStore();
  const evidence = new MemoryEvidenceStore();

  const task = await graph.createTask({
    userId: 'u-head-task',
    goalText: 'Test the lab target for reflected XSS and missing security headers',
    targetUrl,
    scope: { mode: 'subdomain', includeSubdomains: false, excludedHosts: [], excludedPaths: [] },
  });
  // The tasks route creates the goal node on POST /api/tasks; the swarm
  // route's task creation goes through the store, so record it here the
  // same way the head expects to find it.
  await graph.addNode({ taskId: task.id, kind: 'goal', label: task.goalText });

  const outcome = await runHeadAgent({
    targetUrl,
    scope: {
      mode: 'subdomain',
      includeSubdomains: false,
      excludedHosts: [],
      excludedPaths: [],
      maxRequestsPerSecond: 5,
    },
    provider: new MockProvider(),
    limits: { allowPrivateTargets: true, maxDurationMs: 120_000 },
    goalText: task.goalText,
    task: { taskId: task.id, graph, coverage, evidence },
  });

  const xss = outcome.findings.find((f) => f.category === 'xss');
  const headers = outcome.findings.find((f) => f.category === 'headers');

  check('head task: swarm produced an XSS finding', !!xss, outcome.findings.map((f) => f.category));
  check(
    'head task: XSS finding is verified (POE 3 + receipt)',
    xss?.verification?.status === 'verified',
    xss?.verification,
  );
  check('head task: XSS finding POE is 3', xss?.verification?.poe === 3, xss?.verification?.poe);
  check(
    'head task: XSS receipt check passed',
    xss?.verification?.receiptChecked === true,
    xss?.verification,
  );
  check(
    'head task: XSS finding carries proof snapshots',
    (xss?.proofSnapshots?.length ?? 0) >= 1,
    xss?.proofSnapshots?.length,
  );
  check(
    'head task: every proof snapshot hash verifies',
    (xss?.proofSnapshots ?? []).every((s) => snapshotHash(s) === s.sha256),
    xss?.proofSnapshots?.map((s) => s.sha256),
  );
  check(
    'head task: proof snapshots include a proof-role snapshot',
    (xss?.proofSnapshots ?? []).some((s) => s.role === 'proof'),
    xss?.proofSnapshots?.map((s) => s.role),
  );
  check('head task: swarm produced a headers finding', !!headers, outcome.findings.map((f) => f.category));
  check(
    'head task: headers finding stays a hint (no live probe)',
    headers?.verification?.status === 'hint',
    headers?.verification,
  );
  check('head task: headers finding POE is 0', headers?.verification?.poe === 0, headers?.verification?.poe);

  // Todolist persisted on the task row: goal steps + report done.
  const saved = await graph.getTask(task.id);
  check('head task: todolist persisted on the task', (saved?.todolist.length ?? 0) >= 2, saved?.todolist);
  check(
    'head task: todolist goal steps are done',
    (saved?.todolist ?? []).filter((t) => t.id.startsWith('goal-')).every((t) => t.status === 'done'),
    saved?.todolist,
  );
  check(
    'head task: todolist report step is done',
    saved?.todolist.find((t) => t.id === 'report')?.status === 'done',
    saved?.todolist,
  );

  // Exploration graph: intent + fact + finding nodes, anchors to assets.
  const g = await graph.getTaskGraph(task.id);
  const kinds = (g?.nodes ?? []).map((n) => n.kind);
  check('head task: graph has intent nodes', kinds.includes('intent'), kinds);
  check('head task: graph has fact nodes', kinds.includes('fact'), kinds);
  check('head task: graph has finding nodes', kinds.includes('finding'), kinds);
  check(
    'head task: finding nodes carry the verification status',
    (g?.nodes ?? []).filter((n) => n.kind === 'finding').some((n) => n.status === 'verified'),
    g?.nodes.filter((n) => n.kind === 'finding').map((n) => n.status),
  );
  check('head task: graph has at least one asset anchor', (g?.anchors.length ?? 0) >= 1, g?.anchors.length);
  check('head task: graph has an endpoint asset', (g?.assets ?? []).some((a) => a.kind === 'endpoint'), g?.assets);

  // Coverage ledger: spawned specialists recorded, unspawned untested.
  const entries = await coverage.listEntries(task.id);
  const summary = coverageSummary(entries);
  check('head task: XSS recorded as a finding entry', summary.byClass['xss']?.finding >= 1, summary.byClass['xss']);
  check(
    'head task: headers recorded as a finding entry',
    summary.byClass['headers']?.finding >= 1,
    summary.byClass['headers'],
  );
  check(
    'head task: graphql (never spawned) reads untested, never clean',
    summary.untestedClasses.includes('graphql'),
    summary.untestedClasses,
  );
  check('head task: xss is not in the untested classes', !summary.untestedClasses.includes('xss'), summary.untestedClasses);

  server.closeAllConnections();
  server.close();
  await new Promise((r) => setTimeout(r, 100));
  if (failures > 0) {
    console.error(`${failures} head-task test(s) failed`);
    process.exit(1);
  }
  console.log('ALL HEAD-TASK TESTS PASSED');
  process.exit(0);
}

main().catch((e) => {
  console.error('head-task test crashed', e);
  process.exit(1);
});

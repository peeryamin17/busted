/**
 * Integration tests for the guardedFetch wiring
 * (src/agent/tools.ts): target-pin gate, assessment-identity header,
 * and the noise governor (coalescing + Retry-After retry).
 * Local echo server only. No external network, no DB, no LLM.
 *
 * Run:  npx tsx test/guardedFetch.test.ts   (from backend/)
 */
import { createServer, type Server } from 'node:http';
import { createToolContext, guardedFetch } from '../src/agent/tools.js';
import { NoiseGovernor } from '../src/egress/noise.js';
import type { ScopePolicy } from '../src/types.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) {
    failures++;
    console.error(`FAIL: ${name}`, extra ?? '');
  } else console.log(`ok: ${name}`);
}

const SCOPE: ScopePolicy = {
  mode: 'subdomain',
  includeSubdomains: false,
  excludedHosts: [],
  excludedPaths: [],
  maxRequestsPerSecond: 100,
};

async function main(): Promise<void> {
  const hits = new Map<string, number>();
  const seenHeaders: Array<Record<string, string | string[] | undefined>> = [];
  let flakyCount = 0;
  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    hits.set(url.pathname, (hits.get(url.pathname) ?? 0) + 1);
    seenHeaders.push({ ...req.headers });
    if (url.pathname === '/slow') {
      // Small delay so two concurrent GETs genuinely overlap in flight.
      setTimeout(() => {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('slow-ok');
      }, 50);
      return;
    }
    if (url.pathname === '/flaky') {
      flakyCount++;
      if (flakyCount === 1) {
        res.writeHead(429, { 'retry-after': '0', 'content-type': 'text/plain' });
        res.end('slow down');
        return;
      }
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('flaky-ok');
      return;
    }
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('ok');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;
  const base = `http://127.0.0.1:${port}`;
  const target = new URL(base + '/');

  try {
    // 1. Pin gate: 'ask' → 409, 'blocked' → 403, 'allowed' → 200.
    {
      const ctxAsk = createToolContext(target, SCOPE, true, {
        taskId: 'task-1',
        pinCheck: () => ({ decision: 'ask', reason: 'host not pinned' }),
      });
      let code = 0;
      try {
        await guardedFetch(base + '/', ctxAsk);
      } catch (err) {
        code = (err as { statusCode?: number }).statusCode ?? 0;
      }
      check('guardedFetch: pin ask → 409', code === 409, { code });

      const ctxBlocked = createToolContext(target, SCOPE, true, {
        taskId: 'task-1',
        pinCheck: () => ({ decision: 'blocked', reason: 'block rule' }),
      });
      code = 0;
      try {
        await guardedFetch(base + '/', ctxBlocked);
      } catch (err) {
        code = (err as { statusCode?: number }).statusCode ?? 0;
      }
      check('guardedFetch: pin blocked → 403', code === 403, { code });

      const before = hits.get('/') ?? 0;
      const ctxAllowed = createToolContext(target, SCOPE, true, {
        taskId: 'task-1',
        pinCheck: () => ({ decision: 'allowed', reason: 'pinned' }),
      });
      const res = await guardedFetch(base + '/', ctxAllowed);
      check('guardedFetch: pin allowed → 200', res.status === 200);
      check('guardedFetch: pin ask/blocked burned no request', (hits.get('/') ?? 0) === before + 1);
    }

    // 2. Assessment-identity header: present with the task id, and only
    // the base header when no task is attached.
    {
      seenHeaders.length = 0;
      const ctx = createToolContext(target, SCOPE, true, { taskId: 'task-9' });
      await guardedFetch(base + '/', ctx);
      const h = seenHeaders[seenHeaders.length - 1] ?? {};
      check('guardedFetch: identity header present', h['bugseek-assessment'] === '1.0', h);
      check('guardedFetch: identity task header names the task', h['bugseek-assessment-task'] === 'task-9', h);

      seenHeaders.length = 0;
      const ctxNoTask = createToolContext(target, SCOPE, true);
      await guardedFetch(base + '/', ctxNoTask);
      const h2 = seenHeaders[seenHeaders.length - 1] ?? {};
      check('guardedFetch: no task → base header only', h2['bugseek-assessment'] === '1.0' && h2['bugseek-assessment-task'] === undefined, h2);
    }

    // 3. Noise governor: two concurrent identical GETs → one server hit.
    {
      const noise = new NoiseGovernor('balanced', { random: () => 0 });
      const ctx = createToolContext(target, SCOPE, true, { noise });
      const before = hits.get('/slow') ?? 0;
      const [a, b] = await Promise.all([
        guardedFetch(base + '/slow', ctx),
        guardedFetch(base + '/slow', ctx),
      ]);
      check('guardedFetch: coalesced GETs both 200', a.status === 200 && b.status === 200);
      check('guardedFetch: coalesced GETs hit the server once', (hits.get('/slow') ?? 0) === before + 1);
      const [ta, tb] = await Promise.all([a.text(), b.text()]);
      check('guardedFetch: coalesced GETs both readable', ta === 'slow-ok' && tb === 'slow-ok');
    }

    // 4. Noise governor: 429 + Retry-After: 0 → one retry, then 200.
    {
      const noise = new NoiseGovernor('balanced', { random: () => 0 });
      const ctx = createToolContext(target, SCOPE, true, { noise });
      flakyCount = 0;
      const before = hits.get('/flaky') ?? 0;
      const res = await guardedFetch(base + '/flaky', ctx);
      check('guardedFetch: Retry-After retry → 200', res.status === 200);
      check('guardedFetch: Retry-After retried exactly once', (hits.get('/flaky') ?? 0) === before + 2);
    }

    // 5. No-noise baseline still works (regression guard for the rework).
    {
      const ctx = createToolContext(target, SCOPE, true);
      const res = await guardedFetch(base + '/', ctx);
      check('guardedFetch: no governor → 200', res.status === 200);
    }
  } finally {
    server.close();
  }

  if (failures > 0) {
    console.error(`${failures} GUARDED-FETCH TEST(S) FAILED`);
    process.exit(1);
  }
  console.log('ALL GUARDED-FETCH PHASE-C TESTS PASSED');
}

main().catch((err) => {
  console.error('guarded-fetch test crashed:', err);
  process.exit(1);
});

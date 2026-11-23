/**
 * SSRF guard tests (Batch 2: H2, H3, H18, M33).
 *
 * - isPrivateIp blocks the new ranges: CGNAT 100.64.0.0/10, benchmarking
 *   198.18.0.0/15, 192.0.0.0/24, IPv6 link-local fe80::/10.
 * - MCP client / ScopeSentry adapter refuse private URLs before any
 *   request is made; MCP registration refuses literal private IPs.
 * - Production gate: a subprocess running the real swarm head with
 *   limits.allowPrivateTargets: true against a local 127.0.0.1 server
 *   must make zero requests to it in production (NODE_ENV=production),
 *   while the same run in dev with ALLOW_PRIVATE_TARGETS=1 does hit it.
 *
 * Run:  npx tsx test/ssrf-guard.test.ts   (from backend/)
 */
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isPrivateIp, isPrivateIpv6, resolvePublicAddresses } from '../src/guardrails/scope.js';
import { McpClient } from '../src/mcp/client.js';
import { MemoryMcpServerStore } from '../src/mcp/servers.js';
import { ScopeSentryAdapter } from '../src/asm/adapters.js';

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

const PROBE_SOURCE = `
import { createServer } from 'node:http';
import { runHeadAgent } from '__BACKEND__/src/multiagent/head.js';
import { MockProvider } from '__BACKEND__/src/llm/mock.js';
import { MemoryGraphStore } from '__BACKEND__/src/graph/store.js';
import { MemoryCoverageStore } from '__BACKEND__/src/coverage/ledger.js';
import { MemoryEvidenceStore } from '__BACKEND__/src/evidence/snapshots.js';

async function main() {
  let requests = 0;
  const server = createServer((req, res) => {
    requests++;
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<html><body>lab</body></html>');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  const targetUrl = 'http://127.0.0.1:' + port + '/';
  const graph = new MemoryGraphStore();
  const coverage = new MemoryCoverageStore();
  const evidence = new MemoryEvidenceStore();
  const task = await graph.createTask({
    userId: 'u-probe',
    goalText: 'Probe the local lab target',
    targetUrl,
    scope: { mode: 'subdomain', includeSubdomains: false, excludedHosts: [], excludedPaths: [] },
  });
  try {
    const outcome = await runHeadAgent({
      targetUrl,
      scope: { mode: 'subdomain', includeSubdomains: false, excludedHosts: [], excludedPaths: [], maxRequestsPerSecond: 5 },
      provider: new MockProvider(),
      limits: { allowPrivateTargets: true, maxDurationMs: 60_000 },
      goalText: task.goalText,
      task: { taskId: task.id, graph, coverage, evidence },
    });
    console.log('PROBE_RESULT requests=' + requests + ' testsRun=' + outcome.testsRun + ' findings=' + outcome.findings.length + ' errors=' + JSON.stringify(outcome.errors));
  } catch (err) {
    console.log('PROBE_RESULT threw=' + (err as Error).message + ' requests=' + requests);
  } finally {
    server.close();
  }
}
main();
`;

function runProbe(probePath: string, env: Record<string, string>): Promise<string> {
  const tsxBin = join(__dirname, '..', 'node_modules', '.bin', 'tsx');
  return new Promise((resolve, reject) => {
    execFile(tsxBin, [probePath], { env, timeout: 120_000 }, (err, stdout, stderr) => {
      if (err) reject(new Error(`probe failed: ${err.message}\nstdout: ${stdout}\nstderr: ${stderr}`));
      else resolve(stdout);
    });
  });
}

async function main() {
  // isPrivateIp: the new ranges, plus the long-standing ones.
  for (const ip of [
    '100.64.0.1', '100.127.255.255', '198.18.0.1', '198.19.255.255',
    '192.0.0.1', '192.0.0.255', '10.0.0.5', '172.16.0.1', '172.31.255.255',
    '192.168.1.1', '127.0.0.1', '0.0.0.0', '169.254.169.254', '224.0.0.1',
    '::1', 'fe80::1', 'febf::1', 'fe90::1', 'fc00::1', 'fd12:3456::1',
    '::ffff:10.0.0.1', '::ffff:7f00:1',
  ]) {
    check(`isPrivateIp blocks ${ip}`, isPrivateIp(ip));
  }
  for (const ip of [
    '8.8.8.8', '1.1.1.1', '100.128.0.1', '198.20.0.1', '192.0.1.1',
    '172.32.0.1', '2001:4860:4860::8888', '2606:4700:4700::1111',
  ]) {
    check(`isPrivateIp allows ${ip}`, !isPrivateIp(ip));
  }
  check('isPrivateIp rejects non-IP input as public', !isPrivateIp('not-an-ip'));

  // Peer-supplied IPv6 helper, direct.
  check('isPrivateIpv6 blocks fe80::1', isPrivateIpv6('fe80::1'));
  check('isPrivateIpv6 blocks febf::1', isPrivateIpv6('febf::1'));
  check('isPrivateIpv6 blocks ::1', isPrivateIpv6('::1'));
  check('isPrivateIpv6 blocks fd00::1', isPrivateIpv6('fd00::1'));
  check('isPrivateIpv6 allows public v6', !isPrivateIpv6('2001:4860:4860::8888'));

  // Literal private IP: refused without allowPrivate, resolved with it.
  await checkRejects(
    'resolvePublicAddresses refuses 127.0.0.1 without allowPrivate',
    resolvePublicAddresses('127.0.0.1', false),
    /Refusing to scan private IP 127\.0\.0\.1/,
  );
  const allowed = await resolvePublicAddresses('127.0.0.1', true);
  check(
    'resolvePublicAddresses returns the literal with allowPrivate',
    allowed.length === 1 && allowed[0]?.address === '127.0.0.1' && allowed[0]?.family === 4,
    allowed,
  );

  // MCP client: private URLs refused before any request (no DNS involved).
  await checkRejects(
    'McpClient refuses 127.0.0.1',
    new McpClient({ url: 'http://127.0.0.1:9/mcp' }).initialize(),
    /private/i,
  );
  await checkRejects(
    'McpClient refuses 169.254.169.254 (cloud metadata)',
    new McpClient({ url: 'http://169.254.169.254/latest/meta-data/' }).initialize(),
    /private/i,
  );

  // ScopeSentry adapter: private base URL refused on the default fetch.
  await checkRejects(
    'ScopeSentry refuses 169.254.169.254 base URL',
    new ScopeSentryAdapter({ baseUrl: 'http://169.254.169.254', apiKey: 'k', project: 'p' }).listAssets(),
    /private/i,
  );

  // MCP registration: literal private IP refused, public hostname accepted in dev.
  const store = new MemoryMcpServerStore();
  await checkRejects(
    'McpServerStore.create refuses 127.0.0.1',
    store.create({ userId: 'u1', label: 'local', url: 'http://127.0.0.1:8080/mcp', transport: 'http' }),
    /mcp_private_host/,
  );
  const rec = await store.create({ userId: 'u1', label: 'remote', url: 'https://mcp.example.com/mcp', transport: 'http' });
  check('McpServerStore.create accepts a public hostname in dev', rec.url === 'https://mcp.example.com/mcp', rec);

  // Production gate, via a subprocess (config is read once at import,
  // so NODE_ENV cannot be flipped inside this process).
  const backendRoot = join(__dirname, '..');
  const dir = await mkdtemp(join(tmpdir(), 'ssrf-probe-'));
  try {
    const probePath = join(dir, 'probe.ts');
    await writeFile(probePath, PROBE_SOURCE.replaceAll('__BACKEND__', backendRoot));
    const baseEnv: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) {
      if (v !== undefined && k !== 'ALLOW_PRIVATE_TARGETS') baseEnv[k] = v;
    }
    const prodOut = await runProbe(probePath, {
      ...baseEnv,
      NODE_ENV: 'production',
      JWT_SECRET: 'test-secret-for-ssrf-probe',
      DATABASE_URL: 'postgres://u:p@127.0.0.1:5432/db',
    });
    const prodLine = prodOut.split('\n').find((l) => l.startsWith('PROBE_RESULT')) ?? '';
    const prodRequests = Number(/requests=(\d+)/.exec(prodLine)?.[1] ?? -1);
    check('prod: swarm with allowPrivateTargets makes zero requests to 127.0.0.1', prodRequests === 0, prodLine);

    const devOut = await runProbe(probePath, {
      ...baseEnv,
      NODE_ENV: 'development',
      ALLOW_PRIVATE_TARGETS: '1',
    });
    const devLine = devOut.split('\n').find((l) => l.startsWith('PROBE_RESULT')) ?? '';
    const devRequests = Number(/requests=(\d+)/.exec(devLine)?.[1] ?? -1);
    check('dev control: same swarm with ALLOW_PRIVATE_TARGETS=1 does hit the server', devRequests > 0, devLine);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }

  if (failures > 0) {
    console.error(`${failures} SSRF-GUARD TEST(S) FAILED`);
    process.exit(1);
  }
  console.log('ALL SSRF-GUARD TESTS PASSED');
}

main();

/**
 * Tests for programme scope validation (HackerOne/Bugcrowd):
 * identifier parsing, the pure matcher, dataset caching/degradation,
 * the scope routes, and scan wiring (out-of-scope rejected before charge,
 * in-scope verdict recorded as evidence).
 *
 * All fixtures use invented example domains — no real programme data.
 */
import Fastify from 'fastify';
import { createServer } from 'node:http';
import { parseScopeEntry, matchProgrammeScope } from '../src/scope/matcher.js';
import {
  ScopeDataset,
  normaliseHackerOneProgrammes,
  normaliseBugcrowdProgrammes,
} from '../src/scope/dataset.js';
import { scopeRoutes } from '../src/routes/scope.js';
import { swarmRoutes } from '../src/routes/multiagent.js';
import { engineRoutes } from '../src/routes/engines.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

// ---------------------------------------------------------------------------
// Fixtures (invented domains only)
// ---------------------------------------------------------------------------

const H1_FIXTURE = [
  {
    handle: 'examplecorp',
    name: 'Example Corp',
    url: 'https://hackerone.com/examplecorp',
    targets: {
      in_scope: [
        { asset_identifier: '*.example.test', asset_type: 'WILDCARD', eligible_for_submission: true },
        { asset_identifier: 'example.org', asset_type: 'URL', eligible_for_submission: true },
        { asset_identifier: 'https://shop.example.net/store', asset_type: 'URL', eligible_for_submission: true },
        { asset_identifier: 'closed.example.io', asset_type: 'URL', eligible_for_submission: false },
        { asset_identifier: 'com.example.test.app', asset_type: 'GOOGLE_PLAY_APP_ID', eligible_for_submission: true },
      ],
      out_of_scope: [
        { asset_identifier: 'status.example.org', asset_type: 'URL', eligible_for_submission: true },
        { asset_identifier: 'https://shop.example.net/admin', asset_type: 'URL', eligible_for_submission: true },
      ],
    },
  },
  {
    handle: 'apponly',
    name: 'App Only Co',
    url: 'https://hackerone.com/apponly',
    targets: {
      in_scope: [
        { asset_identifier: 'com.apponly.app', asset_type: 'GOOGLE_PLAY_APP_ID', eligible_for_submission: true },
      ],
      out_of_scope: [],
    },
  },
];

const BC_FIXTURE = [
  {
    name: 'Example BC Programme',
    url: 'https://bugcrowd.com/engagements/example-prog',
    targets: {
      in_scope: [
        { type: 'website', target: 'https://app.example.bc/' },
        { type: 'api', target: 'api.example.bc' },
        { type: 'android', target: 'com.example.bc.app' },
      ],
      out_of_scope: [{ type: 'website', target: 'legacy.example.bc' }],
    },
  },
];

// ---------------------------------------------------------------------------
// Identifier parsing
// ---------------------------------------------------------------------------

check('parse: wildcard', parseScopeEntry('*.example.test')?.wildcard === true);
check('parse: wildcard with scheme (real-world shape)', parseScopeEntry('http://*.innov8.work')?.host === 'innov8.work');
check('parse: bare domain', parseScopeEntry('example.org')?.host === 'example.org');
check('parse: url with path', parseScopeEntry('https://shop.example.net/store/')?.pathPrefix === '/store');
check('parse: ip range rejected', parseScopeEntry('194.73.139.0/27') === null);
check('parse: non-http scheme rejected', parseScopeEntry('itms-apps://apps.apple.com/app/x') === null);
check('parse: redacted identifier rejected', parseScopeEntry('████████████') === null);
check('parse: case + trailing dot normalised', parseScopeEntry('EXAMPLE.org.')?.host === 'example.org');

// ---------------------------------------------------------------------------
// Matcher
// ---------------------------------------------------------------------------

const h1Programmes = normaliseHackerOneProgrammes(H1_FIXTURE);
const examplecorp = h1Programmes.find((p) => p.handle === 'examplecorp')!;
check('h1: fixture normalised', !!examplecorp && examplecorp.inScope.length === 3, examplecorp);
check('h1: play-store asset not a web entry', examplecorp.hasWebAssets === true);

const verdict = (target: string) => matchProgrammeScope(examplecorp, target);

check('wildcard: bare host does NOT match', verdict('https://example.test/').verdict === 'out_of_scope');
check('wildcard: subdomain matches', verdict('https://api.example.test/').verdict === 'in_scope');
check('wildcard: deep subdomain matches', verdict('https://a.b.example.test/x').verdict === 'in_scope');
check('bare domain: exact host matches', verdict('https://example.org/').verdict === 'in_scope');
check('bare domain: subdomain-or-self', verdict('https://www.example.org/login').verdict === 'in_scope');
check('exclusion wins over bare-domain cover', verdict('https://status.example.org/').verdict === 'out_of_scope',
  verdict('https://status.example.org/'));
check('path entry: exact path matches', verdict('https://shop.example.net/store').verdict === 'in_scope');
check('path entry: beneath path matches', verdict('https://shop.example.net/store/cart?x=1').verdict === 'in_scope');
check('path entry: sibling prefix does not match', verdict('https://shop.example.net/storefront').verdict === 'out_of_scope');
check('path exclusion wins', verdict('https://shop.example.net/admin/panel').verdict === 'out_of_scope');
check('closed-to-submissions asset gives no cover', verdict('https://closed.example.io/').verdict === 'out_of_scope');
check('case/port/trailing-dot noise', verdict('HTTPS://WWW.Example.ORG:8443/Login').verdict === 'in_scope',
  verdict('HTTPS://WWW.Example.ORG:8443/Login'));
check('trailing dot on target host', verdict('https://example.org./').verdict === 'in_scope');
check('ip target is unknown, never judged', verdict('http://127.0.0.1:8080/').verdict === 'unknown');
check('unparseable target is unknown', verdict('not a url at all').verdict === 'unknown');

const apponly = h1Programmes.find((p) => p.handle === 'apponly')!;
check('h1: app-store assets filtered by type, no web entries',
  apponly.inScope.length === 0 && apponly.hasWebAssets === false, apponly);
check('unknown: programme with no web assets', matchProgrammeScope(apponly, 'https://example.com/').verdict === 'unknown');

const bcProgrammes = normaliseBugcrowdProgrammes(BC_FIXTURE);
const bcProg = bcProgrammes[0];
check('bc: handle derived from engagements url', bcProg?.handle === 'example-prog', bcProg?.handle);
check('bc: subdomain of listed url host matches', matchProgrammeScope(bcProg!, 'https://www.app.example.bc/').verdict === 'in_scope');
check('bc: parent of listed host does not match', matchProgrammeScope(bcProg!, 'https://example.bc/').verdict === 'out_of_scope');
check('bc: exclusion matches', matchProgrammeScope(bcProg!, 'https://legacy.example.bc/').verdict === 'out_of_scope');

// ---------------------------------------------------------------------------
// Dataset service: caching, search, degradation
// ---------------------------------------------------------------------------

function fakeFetch(payload: unknown, ok = true) {
  let calls = 0;
  const impl = async () => {
    calls++;
    return { ok, status: ok ? 200 : 503, json: async () => payload };
  };
  return { impl, calls: () => calls };
}

async function datasetTests() {
  const f = fakeFetch(H1_FIXTURE);
  const ds = new ScopeDataset({ fetchImpl: f.impl as never });
  const first = await ds.programmes('hackerone');
  const second = await ds.programmes('hackerone');
  check('dataset: parses programmes', (first?.length ?? 0) === 2, first?.length);
  check('dataset: cached (single fetch)', f.calls() === 1 && first === second, f.calls());

  const found = await ds.checkScope('hackerone', 'ExampleCorp', 'https://api.example.test/');
  check('dataset: checkScope in_scope', found.verdict === 'in_scope' && found.matchedEntry === '*.example.test', found);
  const missing = await ds.checkScope('hackerone', 'no-such-programme', 'https://api.example.test/');
  check('dataset: programme_not_found', missing.verdict === 'programme_not_found', missing);

  const search = await ds.search('hackerone', 'example');
  check('dataset: search by name', (search?.length ?? 0) === 1 && search?.[0]?.handle === 'examplecorp', search);

  const broken = new ScopeDataset({
    fetchImpl: (async () => { throw new Error('network down'); }) as never,
  });
  check('dataset: failed fetch → null programmes', (await broken.programmes('hackerone')) === null);
  const degraded = await broken.checkScope('hackerone', 'examplecorp', 'https://example.org/');
  check('dataset: failure degrades to unknown', degraded.verdict === 'unknown', degraded);
}

// ---------------------------------------------------------------------------
// Routes + scan wiring
// ---------------------------------------------------------------------------

interface UsageEvent { userId: string; kind: string; quantity: number; scanId?: string; at: string }
const authz = {
  type: 'ownership',
  statement: 'I own this local test server and authorize testing of it.',
  confirmed: true,
};

function makeDb(plan: 'free' | 'hunter' | 'pro' = 'pro') {
  const usage: UsageEvent[] = [];
  const scans: any[] = [];
  const db: any = {
    kind: 'stub', scans, usage,
    async getApiKeyByHash() { return { userId: 'u1', revokedAt: null }; },
    async getUserById() { return { id: 'u1', email: 't@e.com', plan }; },
    async touchApiKey() { /* stub */ },
    async createAuthorization(input: any) { return { id: 'authz-1', ...input }; },
    async createScan(input: any) {
      const s = { id: `scan-${scans.length + 1}`, status: 'queued', ...input };
      scans.push(s); return s;
    },
    async updateScan(id: string, patch: any) {
      const s = scans.find((x) => x.id === id); Object.assign(s, patch); return s;
    },
    async recordUsage(userId: string, kind: string, quantity: number, scanId?: string) {
      usage.push({ userId, kind, quantity, scanId, at: new Date().toISOString() });
    },
    async sumUsageSince(userId: string, kind: string, sinceIso: string) {
      return usage.filter((u) => u.userId === userId && u.kind === kind && u.at >= sinceIso)
        .reduce((n, u) => n + u.quantity, 0);
    },
    async addFinding(f: any) { return f; },
  };
  return db;
}

function scopeDatasetReturning(verdictValue: string) {
  return {
    async checkScope(platform: string, handle: string) {
      return {
        verdict: verdictValue,
        platform, handle,
        programmeName: 'Example Corp',
        ...(verdictValue === 'in_scope' ? { matchedEntry: '*.example.test' } : {}),
        reason: verdictValue === 'out_of_scope'
          ? 'api.example.test is listed out of scope for Example Corp (api.example.test).'
          : 'api.example.test is covered by Example Corp\'s published scope (*.example.test).',
        checkedAt: new Date().toISOString(),
      };
    },
  };
}

async function routeTests() {
  // Scope routes.
  {
    const db = makeDb();
    const ds = new ScopeDataset({ fetchImpl: fakeFetch(H1_FIXTURE).impl as never });
    const app = Fastify();
    await scopeRoutes(app as never, { db, queue: {} as never, provider: { name: 'mock' } as never, scopeDataset: ds as never });

    const noAuth = await app.inject({ method: 'GET', url: '/api/scope/programmes?platform=hackerone&q=example' });
    check('route: programmes needs auth → 401', noAuth.statusCode === 401, noAuth.statusCode);

    const search = await app.inject({
      method: 'GET', url: '/api/scope/programmes?platform=hackerone&q=example',
      headers: { 'x-api-key': 'bs_test' },
    });
    check('route: programme search', search.statusCode === 200 && search.json().programmes[0]?.handle === 'examplecorp', search.body.slice(0, 160));

    const chk = await app.inject({
      method: 'POST', url: '/api/scope/check',
      headers: { 'x-api-key': 'bs_test' },
      payload: { platform: 'hackerone', handle: 'examplecorp', targetUrl: 'https://api.example.test/' },
    });
    check('route: scope check in_scope', chk.statusCode === 200 && chk.json().verdict === 'in_scope', chk.body.slice(0, 160));

    const missing = await app.inject({
      method: 'POST', url: '/api/scope/check',
      headers: { 'x-api-key': 'bs_test' },
      payload: { platform: 'hackerone', handle: 'nope', targetUrl: 'https://api.example.test/' },
    });
    check('route: scope check programme_not_found', missing.statusCode === 200 && missing.json().verdict === 'programme_not_found', missing.body.slice(0, 160));

    const bad = await app.inject({
      method: 'POST', url: '/api/scope/check',
      headers: { 'x-api-key': 'bs_test' },
      payload: { platform: 'hackerone', handle: 'examplecorp', targetUrl: 'ftp://example.test/' },
    });
    check('route: scope check bad target → 400', bad.statusCode === 400, bad.statusCode);
    await app.close();
  }

  // Swarm wiring: out-of-scope programme → 403 before charge, no scan.
  {
    const db = makeDb('pro');
    const app = Fastify();
    await swarmRoutes(app as never, {
      db, queue: {} as never, provider: { name: 'mock' } as never,
      scopeDataset: scopeDatasetReturning('out_of_scope') as never,
    });
    const r = await app.inject({
      method: 'POST', url: '/api/swarm/scans',
      headers: { 'x-api-key': 'bs_test' },
      payload: {
        targetUrl: 'https://api.example.test/', authorization: authz,
        programme: { platform: 'hackerone', handle: 'examplecorp' },
      },
    });
    check('wiring: swarm out-of-scope → 403', r.statusCode === 403, `${r.statusCode} ${r.body.slice(0, 160)}`);
    check('wiring: rejection happens before charging', db.usage.length === 0 && db.scans.length === 0,
      { usage: db.usage.length, scans: db.scans.length });
    await app.close();
  }

  // Engine wiring: out-of-scope programme → 403 before availability/charge.
  {
    const db = makeDb('pro');
    const app = Fastify();
    await engineRoutes(app as never, {
      db, queue: {} as never, provider: { name: 'mock' } as never,
      scopeDataset: scopeDatasetReturning('out_of_scope') as never,
    });
    const r = await app.inject({
      method: 'POST', url: '/api/engines/scans',
      headers: { 'x-api-key': 'bs_test' },
      payload: {
        engine: 'whatweb', targetUrl: 'https://api.example.test/', authorization: authz,
        programme: { platform: 'hackerone', handle: 'examplecorp' },
      },
    });
    check('wiring: engine out-of-scope → 403', r.statusCode === 403, `${r.statusCode} ${r.body.slice(0, 160)}`);
    check('wiring: engine rejection before charging', db.usage.length === 0 && db.scans.length === 0,
      { usage: db.usage.length, scans: db.scans.length });
    await app.close();
  }

  // Swarm wiring: in-scope verdict recorded on the scan, run proceeds.
  {
    const target = createServer((_req, res) => {
      res.setHeader('content-type', 'text/html');
      res.end('<html><body><a href="/api/users">users</a></body></html>');
    });
    await new Promise<void>((r) => target.listen(0, '127.0.0.1', r));
    const port = (target.address() as { port: number }).port;
    const targetUrl = `http://127.0.0.1:${port}/`;

    const db = makeDb('pro');
    const app = Fastify();
    await swarmRoutes(app as never, {
      db, queue: {} as never, provider: { name: 'mock' } as never,
      scopeDataset: scopeDatasetReturning('in_scope') as never,
    });
    const r = await app.inject({
      method: 'POST', url: '/api/swarm/scans',
      headers: { 'x-api-key': 'bs_test' },
      payload: {
        targetUrl, authorization: authz, allowPrivateTargets: true,
        programme: { platform: 'hackerone', handle: 'examplecorp' },
        specialists: ['recon', 'headers'], maxTokens: 8000, timeoutMinutes: 2,
      },
    });
    const body = r.json();
    check('wiring: in-scope swarm proceeds → 200', r.statusCode === 200, `${r.statusCode} ${r.body.slice(0, 200)}`);
    check('wiring: verdict recorded on scan record', db.scans[0]?.scopeEvidence?.verdict === 'in_scope',
      db.scans[0]?.scopeEvidence);
    check('wiring: verdict echoed in response', body.scopeCheck?.verdict === 'in_scope', body.scopeCheck);
    check('wiring: credits charged on accepted scan', db.usage.some((u: UsageEvent) => u.quantity === 25), db.usage);
    await app.close();
    target.closeAllConnections();
    target.close();
  }
}

async function main() {
  await datasetTests();
  await routeTests();
  await new Promise((r) => setTimeout(r, 100));
  if (failures > 0) { console.error(`${failures} scope test(s) failed`); process.exit(1); }
  console.log('ALL SCOPE TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('scope test crashed', e); process.exit(1); });

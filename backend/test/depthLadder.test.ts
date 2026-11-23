/**
 * Unit tests for the exploit-depth ladder (multiagent/depthLadder.ts).
 * All live probes are mocked, no network, no real target, no LLM.
 *
 * Run:  npx tsx test/depthLadder.test.ts   (from backend/)
 */
import {
  checkStop,
  classifyFinding,
  generateCanary,
  isLadderTestable,
  newLadderState,
  untestedVerification,
  validateFindingWithLadder,
  type DepthProber,
  type DepthProbeResponse,
} from '../src/multiagent/depthLadder.js';
import { generateMarkdownReport } from '../src/reports/markdown.js';
import type { Finding, Scan } from '../src/types.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

const FIXED_NOW = '2026-11-22T16:00:00.000Z';
const baseOpts = { now: () => FIXED_NOW };

function resp(partial: Partial<DepthProbeResponse>): DepthProbeResponse {
  return { ok: true, status: 200, headers: {}, body: '', ...partial };
}

async function main() {
  // ── 1. Canaries: unique, random, alphanumeric, never a script ──
  {
    const a = generateCanary();
    const b = generateCanary();
    check('canary: format bs + 16 hex chars', /^bs[0-9a-f]{16}$/.test(a), a);
    check('canary: unique per call', a !== b, `${a} vs ${b}`);
    check('canary: no script/executable characters', !/[<>"'();=]/.test(a), a);
  }

  // ── 2. Classification ──
  {
    check('classify: xss', classifyFinding({ category: 'xss', title: 'Reflected XSS' }) === 'xss');
    check('classify: idor', classifyFinding({ category: 'idor', title: 'IDOR on /users/42' }) === 'idor');
    check('classify: cors', classifyFinding({ category: 'cors', title: 'CORS misconfig' }) === 'cors');
    check('classify: graphql', classifyFinding({ category: 'graphql', title: 'Introspection enabled' }) === 'graphql');
    check('classify: headers unprobeable', classifyFinding({ category: 'headers', title: 'Missing CSP' }) === 'unprobeable');
    check('classify: secrets unprobeable', classifyFinding({ category: 'secrets', title: 'Leaked key' }) === 'unprobeable');
    check('isLadderTestable: headers false', isLadderTestable({ category: 'headers', title: 'Missing CSP' }) === false);
  }

  // ── 3. XSS: reflected in one param → confirmed; two params → escalated ──
  {
    const reflecting: DepthProber = async (req) => {
      const u = new URL(req.url);
      // Reflect every query-param value (the escalate probe keeps q=hello
      // alongside search=<canary>, so reflecting only q would miss it).
      const values = [...u.searchParams.values()].join(' ');
      return resp({ body: `<html><body>results for ${values}</body></html>` });
    };
    const v = await validateFindingWithLadder(
      { category: 'xss', title: 'Reflected XSS in search', location: 'http://127.0.0.1:9/search?q=hello' },
      reflecting, baseOpts,
    );
    check('xss: reflected in 2 params → verified/escalated', v.status === 'verified' && v.depth === 'escalated', v);
    check('xss: impact derived from depth', v.impact === 'cross-context', v.impact);
    check('xss: canary recorded', !!v.canaryToken && v.evidence.some((e) => e.rung === 'confirm'), v.canaryToken);
    check('xss: two evidence rungs', v.evidence.length === 2, v.evidence.map((e) => e.rung));
  }
  {
    // Only the first param reflects; the second does not → confirmed, not escalated.
    const oneParam: DepthProber = async (req) => {
      const u = new URL(req.url);
      const q = u.searchParams.get('q') ?? '';
      return resp({ body: q ? `<html>results for ${q}</html>` : '<html>no results</html>' });
    };
    const v = await validateFindingWithLadder(
      { category: 'xss', title: 'Reflected XSS in search', location: 'http://127.0.0.1:9/search?q=hello' },
      oneParam, baseOpts,
    );
    check('xss: one param only → verified/confirmed', v.status === 'verified' && v.depth === 'confirmed', v);
    check('xss: single-context impact', v.impact === 'single-context', v.impact);
  }
  {
    const neverReflects: DepthProber = async () => resp({ body: '<html>nothing here</html>' });
    const v = await validateFindingWithLadder(
      { category: 'xss', title: 'Reflected XSS in search', location: 'http://127.0.0.1:9/search?q=hello' },
      neverReflects, baseOpts,
    );
    check('xss: not reflected → hint/unproven', v.status === 'hint' && v.depth === 'unproven', v);
    check('xss: unproven impact not-measured', v.impact === 'not-measured', v.impact);
  }
  {
    // Evidence excerpt is redacted: a PII email next to the canary must not survive.
    const withPii: DepthProber = async (req) => {
      const u = new URL(req.url);
      const q = u.searchParams.get('q') ?? '';
      return resp({ body: `<html>contact victim@example.com, results for ${q}</html>` });
    };
    const v = await validateFindingWithLadder(
      { category: 'xss', title: 'Reflected XSS', location: 'http://127.0.0.1:9/search?q=hello' },
      withPii, baseOpts,
    );
    const allEvidence = v.evidence.map((e) => e.observed).join(' ');
    check('xss: evidence redacts PII next to canary', !allEvidence.includes('victim@example.com') && allEvidence.includes('[REDACTED:email]'), allEvidence);
  }
  {
    // Probe budget: with maxProbes 1 the ladder confirms but cannot escalate.
    let calls = 0;
    const counting: DepthProber = async (req) => {
      calls += 1;
      const u = new URL(req.url);
      const q = u.searchParams.get('q') ?? u.searchParams.get('search') ?? '';
      return resp({ body: `<html>${q}</html>` });
    };
    const v = await validateFindingWithLadder(
      { category: 'xss', title: 'Reflected XSS', location: 'http://127.0.0.1:9/search?q=hello' },
      counting, { ...baseOpts, maxProbes: 1 },
    );
    check('xss: probe budget respected (1 call)', calls === 1, calls);
    check('xss: budget-capped → confirmed, not escalated', v.depth === 'confirmed', v.depth);
  }

  // ── 4. IDOR: neighbour shape match → escalated; values never recorded ──
  {
    const idorTarget: DepthProber = async (req) => {
      const u = new URL(req.url);
      const id = u.pathname.match(/\/(\d+)$/)?.[1];
      if (!id) return resp({ status: 404, ok: false, body: 'not found' });
      // Planted "real" values: the ladder must never record these.
      return resp({ body: JSON.stringify({ id: Number(id), name: `SECRET-VALUE-${id}`, email: 'victim@example.com' }) });
    };
    const v = await validateFindingWithLadder(
      { category: 'idor', title: 'IDOR on /api/users/42', location: 'http://127.0.0.1:9/api/users/42' },
      idorTarget, baseOpts,
    );
    check('idor: two neighbours same shape → verified/escalated', v.status === 'verified' && v.depth === 'escalated', v);
    const allEvidence = JSON.stringify(v.evidence);
    check('idor: no neighbour VALUES in evidence', !allEvidence.includes('SECRET-VALUE') && !allEvidence.includes('victim@example.com'), allEvidence);
    check('idor: evidence records field names only', allEvidence.includes('id, name, email'), allEvidence);
  }
  {
    const lockedDown: DepthProber = async (req) => {
      const u = new URL(req.url);
      if (u.pathname.endsWith('/42')) return resp({ body: JSON.stringify({ id: 42, name: 'mine' }) });
      return resp({ status: 403, ok: false, body: 'forbidden' });
    };
    const v = await validateFindingWithLadder(
      { category: 'idor', title: 'IDOR on /api/users/42', location: 'http://127.0.0.1:9/api/users/42' },
      lockedDown, baseOpts,
    );
    check('idor: neighbour 403 → hint/unproven', v.status === 'hint' && v.depth === 'unproven', v);
  }
  {
    let calls = 0;
    const counting: DepthProber = async (req) => {
      calls += 1;
      return resp({ body: JSON.stringify({ id: 42, name: 'x' }) });
    };
    const v = await validateFindingWithLadder(
      { category: 'idor', title: 'IDOR on /api/users/42', location: 'http://127.0.0.1:9/api/users/42' },
      counting, { ...baseOpts, allowNeighborShapeProbe: false },
    );
    check('idor: neighbour probe disabled → unproven, baseline only', v.depth === 'unproven' && calls === 1, { depth: v.depth, calls });
  }

  // ── 5. CORS: canary origin echoed + credentials → confirmed; data returned → escalated ──
  {
    const corsOpen: DepthProber = async (req) => resp({
      headers: {
        'access-control-allow-origin': req.headers?.['origin'] ?? '',
        'access-control-allow-credentials': 'true',
      },
      body: '{"user":"data"}',
    });
    const v = await validateFindingWithLadder(
      { category: 'cors', title: 'CORS allows any origin with credentials', location: 'http://127.0.0.1:9/api/me' },
      corsOpen, baseOpts,
    );
    check('cors: canary origin echoed + creds + data → verified/escalated', v.status === 'verified' && v.depth === 'escalated', v);
    check('cors: canary origin recorded', !!v.canaryToken && v.canaryToken.startsWith('bs'), v.canaryToken);
  }
  {
    const wildcardNoCreds: DepthProber = async () => resp({
      headers: { 'access-control-allow-origin': '*' },
      body: '{}',
    });
    const v = await validateFindingWithLadder(
      { category: 'cors', title: 'CORS wildcard', location: 'http://127.0.0.1:9/api/me' },
      wildcardNoCreds, baseOpts,
    );
    check('cors: wildcard without credentials → hint/unproven', v.status === 'hint' && v.depth === 'unproven', v);
  }

  // ── 6. GraphQL: read-only query → confirmed; introspection → escalated ──
  {
    const gql: DepthProber = async (req) => {
      if (req.body?.includes('__schema')) {
        return resp({ body: JSON.stringify({ data: { __schema: { queryType: { name: 'Query' }, mutationType: null } } }) });
      }
      if (req.method !== 'POST') return resp({ status: 405, ok: false, body: 'method not allowed' });
      return resp({ body: JSON.stringify({ data: { __typename: 'Query' } }) });
    };
    const v = await validateFindingWithLadder(
      { category: 'graphql', title: 'GraphQL introspection enabled', location: 'http://127.0.0.1:9/graphql' },
      gql, baseOpts,
    );
    check('graphql: typename + introspection → verified/escalated', v.status === 'verified' && v.depth === 'escalated', v);
    check('graphql: only read-only queries sent', v.evidence.every((e) => !/mutation/i.test(e.request) || e.request.includes('mutationType')), v.evidence);
  }
  {
    const gqlClosed: DepthProber = async () => resp({ body: JSON.stringify({ errors: [{ message: 'introspection disabled' }] }) });
    const v = await validateFindingWithLadder(
      { category: 'graphql', title: 'GraphQL introspection enabled', location: 'http://127.0.0.1:9/graphql' },
      gqlClosed, baseOpts,
    );
    check('graphql: no data → hint/unproven', v.status === 'hint' && v.depth === 'unproven', v);
  }

  // ── 7. Stop conditions ──
  {
    const rateLimited: DepthProber = async () => resp({ status: 429, ok: false, body: 'too many requests' });
    const v = await validateFindingWithLadder(
      { category: 'xss', title: 'Reflected XSS', location: 'http://127.0.0.1:9/search?q=hello' },
      rateLimited, baseOpts,
    );
    check('stop: 429 aborts ladder, records stop', v.status === 'hint' && !!v.stopReason?.includes('429'), v.stopReason);
  }
  {
    const captcha: DepthProber = async () => resp({ body: '<html>please complete the captcha challenge</html>' });
    const v = await validateFindingWithLadder(
      { category: 'xss', title: 'Reflected XSS', location: 'http://127.0.0.1:9/search?q=hello' },
      captcha, baseOpts,
    );
    check('stop: CAPTCHA wording aborts ladder', v.status === 'hint' && !!v.stopReason, v.stopReason);
  }
  {
    // 5xx storm policy, exercised directly (3 consecutive server errors).
    const state = newLadderState(6);
    check('stop: 1st 5xx does not stop', checkStop(resp({ status: 500, ok: false, body: 'err' }), state) === null);
    check('stop: 2nd 5xx does not stop', checkStop(resp({ status: 502, ok: false, body: 'err' }), state) === null);
    const third = checkStop(resp({ status: 503, ok: false, body: 'err' }), state);
    check('stop: 3rd consecutive 5xx stops', typeof third === 'string' && third.includes('5xx'), third);
    const okState = newLadderState(6);
    checkStop(resp({ status: 500, ok: false, body: 'err' }), okState);
    check('stop: 200 resets the 5xx counter', checkStop(resp({ status: 200, body: 'ok' }), okState) === null && okState.consecutive5xx === 0);
  }
  {
    // A throwing prober never throws out of the ladder.
    const throwing: DepthProber = async () => { throw new Error('network exploded'); };
    const v = await validateFindingWithLadder(
      { category: 'xss', title: 'Reflected XSS', location: 'http://127.0.0.1:9/search?q=hello' },
      throwing, baseOpts,
    );
    check('stop: throwing prober degrades to hint', v.status === 'hint' && v.depth === 'unproven' && !!v.stopReason, v);
  }

  // ── 8. Unprobeable findings: no probes at all, explicit hint ──
  {
    let calls = 0;
    const counting: DepthProber = async () => { calls += 1; return resp({ body: '' }); };
    const v = await validateFindingWithLadder(
      { category: 'headers', title: 'Missing Content-Security-Policy', location: 'http://127.0.0.1:9/' },
      counting, baseOpts,
    );
    check('unprobeable: zero probes made', calls === 0, calls);
    check('unprobeable: explicit hint with reason', v.status === 'hint' && v.impactSummary.includes('headers'), v.impactSummary);
    const u = untestedVerification('test reason');
    check('untestedVerification: hint/unproven/not-measured', u.status === 'hint' && u.depth === 'unproven' && u.impact === 'not-measured', u);
  }
  {
    // No resolvable URL → hint, no probes.
    let calls = 0;
    const counting: DepthProber = async () => { calls += 1; return resp({ body: '' }); };
    const v = await validateFindingWithLadder(
      { category: 'xss', title: 'Reflected XSS', location: 'not a url at all' },
      counting, baseOpts,
    );
    check('no URL: hint, zero probes', v.status === 'hint' && calls === 0, { status: v.status, calls });
  }

  // ── 9. Report rendering: verified chain section + separate hints ──
  {
    const scan: Scan = {
      id: 'scan-1', userId: 'u1', targetUrl: 'http://127.0.0.1:9/', mode: 'active',
      status: 'completed', scope: { mode: 'subdomain', includeSubdomains: false, excludedHosts: [], excludedPaths: [], maxRequestsPerSecond: 2 },
      techStack: [], progress: { completedSteps: 10, totalSteps: 10 }, createdAt: FIXED_NOW,
    };
    const verifiedFinding: Finding = {
      id: 'f1', scanId: 'scan-1', category: 'xss', title: 'Reflected XSS in search',
      description: 'Canary reflected.', severity: 'high', confidence: 'high',
      trapProbability: 0, honeypotSuspect: false, location: 'http://127.0.0.1:9/search',
      evidence: 'canary reflected', reproSteps: ['visit /search?q=<canary>'], remediation: 'Encode output.',
      references: [], createdAt: FIXED_NOW,
      verification: {
        status: 'verified', depth: 'escalated', impact: 'cross-context',
        impactSummary: 'Measured impact (cross-context): the canary was reflected in two different parameters/contexts.',
        canaryToken: 'bs0123456789abcdef', evidence: [
          { rung: 'confirm', kind: 'xss-reflection', request: 'GET /search?q=<canary>', observed: 'HTTP 200: canary reflected unencoded in text content.', status: 200 },
          { rung: 'escalate', kind: 'xss-second-context', request: 'GET /search?search=<canary>', observed: 'HTTP 200: canary also reflected via a second parameter.', status: 200 },
        ],
        testedAt: FIXED_NOW, method: 'depth-ladder v1 (benign canary, read-only proofs)',
      },
    };
    const hintFinding: Finding = {
      id: 'f2', scanId: 'scan-1', category: 'headers', title: 'Missing Content-Security-Policy',
      description: 'No CSP header.', severity: 'low', confidence: 'high',
      trapProbability: 0, honeypotSuspect: false, location: 'http://127.0.0.1:9/',
      evidence: '', reproSteps: [], remediation: 'Add CSP.',
      references: [], createdAt: FIXED_NOW,
      verification: {
        status: 'hint', depth: 'unproven', impact: 'not-measured',
        impactSummary: 'Impact not measured: no read-only live probe exists for category "headers".',
        evidence: [], testedAt: FIXED_NOW, method: 'depth-ladder v1 (benign canary, read-only proofs)',
      },
    };
    const md = generateMarkdownReport({ scan, findings: [hintFinding, verifiedFinding], generatedBy: 'test' });
    check('report: Verified exploit chains section present', md.includes('## Verified exploit chains'), md.slice(0, 400));
    check('report: chain shows canary proof + escalation + impact', md.includes('Canary proof') && md.includes('Escalation proof') && md.includes('Measured impact'), md);
    check('report: canary token shown', md.includes('bs0123456789abcdef'), md);
    check('report: Hints section separate', md.includes('## Hints (unverified)') && md.includes('Missing Content-Security-Policy'), md);
    check('report: hint labelled as hint', md.includes('Hint — unproven'), md);
    check('report: verified finding carries Verified label', md.includes('Verified — depth: escalated'), md);
  }

  if (failures > 0) { console.error(`${failures} depth-ladder test(s) failed`); process.exit(1); }
  console.log('ALL DEPTH-LADDER TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('depth-ladder test crashed', e); process.exit(1); });

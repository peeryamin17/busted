/**
 * Unit tests for the retester loop (multiagent/retester.ts).
 * All live probes are mocked, no network, no real target, no LLM.
 *
 * Run:  npx tsx test/retester.test.ts   (from backend/)
 */
import { createHash } from 'node:crypto';
import Fastify from 'fastify';
import { MemoryDatabase } from '../src/db/db.js';
import { generateSessionToken, hashSessionToken } from '../src/auth/session.js';
import { retestRoutes } from '../src/routes/retests.js';
import {
  RETEST_METHOD,
  applyRetestVerdict,
  retestFinding,
  type RetestFindingInput,
  type RetestResult,
} from '../src/multiagent/retester.js';
import {
  untestedVerification,
  type DepthProbeResponse,
  type DepthProber,
} from '../src/multiagent/depthLadder.js';
import type { Finding, FindingVerification } from '../src/types.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

const FIXED_NOW = '2026-11-23T12:00:00.000Z';
const TARGET = 'http://127.0.0.1:9';
const XSS_LOCATION = 'http://127.0.0.1:9/search?q=hello';

function resp(partial: Partial<DepthProbeResponse>): DepthProbeResponse {
  return { ok: true, status: 200, headers: {}, body: '', ...partial };
}

function verifiedVerification(): FindingVerification {
  return {
    status: 'verified',
    depth: 'confirmed',
    impact: 'single-context',
    impactSummary: 'Measured impact (single context): a benign canary was reflected unencoded in a response sink (single context).',
    canaryToken: 'bs0123456789abcdef',
    evidence: [
      {
        rung: 'confirm',
        kind: 'xss-reflection',
        request: 'GET /search?q=<canary>',
        observed: 'HTTP 200: canary reflected unencoded in text content.',
        status: 200,
      },
    ],
    testedAt: FIXED_NOW,
    method: 'depth-ladder v1 (benign canary, read-only proofs)',
  };
}

function hintVerification(): FindingVerification {
  return untestedVerification(
    'no read-only live probe exists for category "headers" — the ladder only tests XSS, IDOR, CORS and GraphQL findings live.',
    () => FIXED_NOW,
  );
}

function xssFinding(verification?: FindingVerification): RetestFindingInput {
  return {
    id: 'f-xss',
    category: 'xss',
    title: 'Reflected XSS in search',
    location: XSS_LOCATION,
    ...(verification ? { verification } : {}),
  };
}

function findingRecord(input: RetestFindingInput): Finding {
  return {
    id: input.id,
    scanId: 'scan-1',
    category: input.category,
    title: input.title,
    description: 'Test finding.',
    severity: 'high',
    confidence: 'high',
    trapProbability: 0,
    honeypotSuspect: false,
    location: input.location,
    evidence: '',
    reproSteps: [],
    remediation: 'Fix it.',
    references: [],
    createdAt: FIXED_NOW,
    ...(input.verification ? { verification: input.verification } : {}),
  };
}

/** Reflects every query-param value (the ladder's escalate probe switches params). */
const reflecting: DepthProber = async (req) => {
  const u = new URL(req.url);
  const values = [...u.searchParams.values()].join(' ');
  return resp({ body: `<html><body>results for ${values}</body></html>` });
};

/** Never reflects anything, but the endpoint is alive. */
const neverReflects: DepthProber = async () => resp({ body: '<html>nothing here</html>' });

/** The endpoint is gone entirely. */
const gone: DepthProber = async () => resp({ ok: false, status: 404, body: 'not found' });

async function main() {
  // ── 1. Reproduced: fresh canary still reflects → reproduced ─────────────
  {
    const r = await retestFinding({
      finding: xssFinding(hintVerification()),
      targetUrl: TARGET,
      prober: reflecting,
      now: () => FIXED_NOW,
    });
    check('reproduced: verdict reproduced', r.verdict === 'reproduced', r);
    check('reproduced: depth escalated (two params reflect)', r.depth === 'escalated', r.depth);
    check('reproduced: method is retester v1', r.method === RETEST_METHOD, r.method);
    check('reproduced: fresh canary recorded', !!r.canaryToken && r.canaryToken.startsWith('bs'), r.canaryToken);
    check('reproduced: baseline receipt first, then ladder rungs',
      r.evidence.length === 3 && r.evidence[0]?.kind === 'retest-baseline' && r.evidence[1]?.kind === 'xss-reflection',
      r.evidence.map((e) => e.kind));
    check('reproduced: testedAt from now()', r.testedAt === FIXED_NOW, r.testedAt);
    const updated = applyRetestVerdict(findingRecord(xssFinding(hintVerification())), r);
    check('reproduced: applyRetestVerdict upgrades hint → verified',
      updated.status === 'verified' && updated.depth === 'escalated', updated);
    check('reproduced: applyRetestVerdict carries the retest method',
      updated.method === RETEST_METHOD, updated.method);
  }

  // ── 2. Reproduced again on an already-verified finding ──────────────────
  {
    const r = await retestFinding({
      finding: xssFinding(verifiedVerification()),
      targetUrl: TARGET,
      prober: reflecting,
      now: () => FIXED_NOW,
    });
    check('reproduced (was verified): still reproduced', r.verdict === 'reproduced', r);
    const updated = applyRetestVerdict(findingRecord(xssFinding(verifiedVerification())), r);
    check('reproduced (was verified): stays verified', updated.status === 'verified', updated);
  }

  // ── 3. Fixed: endpoint gone (baseline 404) ─────────────────────────────
  {
    const r = await retestFinding({
      finding: xssFinding(verifiedVerification()),
      targetUrl: TARGET,
      prober: gone,
      now: () => FIXED_NOW,
    });
    check('fixed (404): verdict fixed', r.verdict === 'fixed', r);
    check('fixed (404): depth unproven', r.depth === 'unproven', r.depth);
    check('fixed (404): impactSummary cites the 404',
      r.impactSummary.includes('404'), r.impactSummary);
    check('fixed (404): baseline evidence records the 404',
      r.evidence.some((e) => e.kind === 'retest-baseline' && e.status === 404),
      r.evidence);
    const updated = applyRetestVerdict(findingRecord(xssFinding(verifiedVerification())), r);
    check('fixed (404): applyRetestVerdict sets status fixed',
      updated.status === 'fixed', updated);
    check('fixed (404): fixed verification depth unproven, impact not-measured',
      updated.depth === 'unproven' && updated.impact === 'not-measured', updated);
  }

  // ── 4. Fixed: endpoint alive but the canary no longer reflects ──────────
  {
    const r = await retestFinding({
      finding: xssFinding(verifiedVerification()),
      targetUrl: TARGET,
      prober: neverReflects,
      now: () => FIXED_NOW,
    });
    check('fixed (no reflection): verdict fixed', r.verdict === 'fixed', r);
    check('fixed (no reflection): impactSummary says the canary no longer reproduces',
      r.impactSummary.includes('no longer reproduces'), r.impactSummary);
    const updated = applyRetestVerdict(findingRecord(xssFinding(verifiedVerification())), r);
    check('fixed (no reflection): applyRetestVerdict sets status fixed',
      updated.status === 'fixed', updated);
  }

  // ── 5. Fixed: IDOR neighbour now locked down ────────────────────────────
  {
    const lockedDown: DepthProber = async (req) => {
      const u = new URL(req.url);
      if (u.pathname.endsWith('/42')) {
        return resp({ body: JSON.stringify({ id: 42, name: 'mine' }) });
      }
      return resp({ ok: false, status: 403, body: 'forbidden' });
    };
    const idor: RetestFindingInput = {
      id: 'f-idor',
      category: 'idor',
      title: 'IDOR on /api/users/42',
      location: 'http://127.0.0.1:9/api/users/42',
      verification: verifiedVerification(),
    };
    const r = await retestFinding({ finding: idor, targetUrl: TARGET, prober: lockedDown, now: () => FIXED_NOW });
    check('fixed (idor neighbour 403): verdict fixed', r.verdict === 'fixed', r);
    const updated = applyRetestVerdict(findingRecord(idor), r);
    check('fixed (idor neighbour 403): applyRetestVerdict sets status fixed',
      updated.status === 'fixed', updated);
  }

  // ── 6. Inconclusive: unprobeable category ───────────────────────────────
  {
    const headersFinding: RetestFindingInput = {
      id: 'f-headers',
      category: 'headers',
      title: 'Missing Content-Security-Policy',
      location: 'http://127.0.0.1:9/',
      verification: hintVerification(),
    };
    let calls = 0;
    const counting: DepthProber = async (req) => { calls += 1; return resp({ body: '' }); };
    const r = await retestFinding({ finding: headersFinding, targetUrl: TARGET, prober: counting, now: () => FIXED_NOW });
    check('inconclusive (unprobeable): verdict inconclusive', r.verdict === 'inconclusive', r);
    check('inconclusive (unprobeable): no probes sent', calls === 0, calls);
    check('inconclusive (unprobeable): reason names the category',
      r.impactSummary.includes('headers'), r.impactSummary);
    const rec = findingRecord(headersFinding);
    const updated = applyRetestVerdict(rec, r);
    check('inconclusive: applyRetestVerdict leaves verification untouched (same object)',
      updated === rec.verification, updated);
  }

  // ── 7. Inconclusive: prober throws (rejected promise) ───────────────────
  {
    const throwing: DepthProber = async () => {
      throw new Error('connection reset');
    };
    const r = await retestFinding({
      finding: xssFinding(verifiedVerification()),
      targetUrl: TARGET,
      prober: throwing,
      now: () => FIXED_NOW,
    });
    check('inconclusive (prober throws): verdict inconclusive, never throws', r.verdict === 'inconclusive', r);
    check('inconclusive (prober throws): not fixed', r.verdict !== 'fixed', r.verdict);
    const updated = applyRetestVerdict(findingRecord(xssFinding(verifiedVerification())), r);
    check('inconclusive (prober throws): verification stays verified',
      updated.status === 'verified', updated);
  }

  // ── 8. Inconclusive: prober throws synchronously ────────────────────────
  {
    const syncThrow: DepthProber = () => {
      throw new Error('sync boom');
    };
    let threw = false;
    let r: RetestResult | undefined;
    try {
      r = await retestFinding({
        finding: xssFinding(verifiedVerification()),
        targetUrl: TARGET,
        prober: syncThrow,
        now: () => FIXED_NOW,
      });
    } catch {
      threw = true;
    }
    check('inconclusive (sync throw): retestFinding never throws', !threw && !!r, { threw, r });
    check('inconclusive (sync throw): verdict inconclusive', r?.verdict === 'inconclusive', r);
  }

  // ── 9. Inconclusive: rate-limited (baseline 429) ────────────────────────
  {
    const rateLimited: DepthProber = async () => resp({ ok: false, status: 429, body: 'too many requests' });
    const r = await retestFinding({
      finding: xssFinding(verifiedVerification()),
      targetUrl: TARGET,
      prober: rateLimited,
      now: () => FIXED_NOW,
    });
    check('inconclusive (429): verdict inconclusive', r.verdict === 'inconclusive', r);
    check('inconclusive (429): reason names rate-limit', r.impactSummary.includes('429'), r.impactSummary);
    const updated = applyRetestVerdict(findingRecord(xssFinding(verifiedVerification())), r);
    check('inconclusive (429): verification stays verified', updated.status === 'verified', updated);
  }

  // ── 10. Inconclusive: ladder stops early mid-run (429 on the canary probe) ──
  {
    const stopsMidRun: DepthProber = async (req) => {
      const u = new URL(req.url);
      // The baseline request carries q=hello; the ladder's canary starts with 'bs'.
      const hasCanary = [...u.searchParams.values()].some((v) => v.startsWith('bs'));
      if (hasCanary) return resp({ ok: false, status: 429, body: 'too many requests' });
      return resp({ body: '<html>results for hello</html>' });
    };
    const r = await retestFinding({
      finding: xssFinding(verifiedVerification()),
      targetUrl: TARGET,
      prober: stopsMidRun,
      now: () => FIXED_NOW,
    });
    check('inconclusive (ladder stop): verdict inconclusive', r.verdict === 'inconclusive', r);
    check('inconclusive (ladder stop): reason names the early stop',
      r.impactSummary.includes('stopped early'), r.impactSummary);
  }

  // ── 11. Inconclusive: server erroring (baseline 500) ────────────────────
  {
    const erroring: DepthProber = async () => resp({ ok: false, status: 500, body: 'internal error' });
    const r = await retestFinding({
      finding: xssFinding(verifiedVerification()),
      targetUrl: TARGET,
      prober: erroring,
      now: () => FIXED_NOW,
    });
    check('inconclusive (500): verdict inconclusive, never fixed', r.verdict === 'inconclusive', r);
  }

  // ── 12. Inconclusive: a hint that still does not reproduce ──────────────
  {
    const r = await retestFinding({
      finding: xssFinding(hintVerification()),
      targetUrl: TARGET,
      prober: neverReflects,
      now: () => FIXED_NOW,
    });
    check('inconclusive (hint stays hint): verdict inconclusive', r.verdict === 'inconclusive', r);
    check('inconclusive (hint stays hint): not upgraded to fixed',
      r.verdict !== 'fixed', r.verdict);
    const rec = findingRecord(xssFinding(hintVerification()));
    const updated = applyRetestVerdict(rec, r);
    check('inconclusive (hint stays hint): verification untouched (same object)',
      updated === rec.verification, updated);
  }

  // ── 13. Inconclusive with no prior verification → stays a hint ──────────
  {
    const r = await retestFinding({
      finding: xssFinding(),
      targetUrl: TARGET,
      prober: neverReflects,
      now: () => FIXED_NOW,
    });
    check('inconclusive (no prior verification): verdict inconclusive', r.verdict === 'inconclusive', r);
    const updated = applyRetestVerdict(findingRecord(xssFinding()), r);
    check('inconclusive (no prior verification): applyRetestVerdict returns a hint',
      updated.status === 'hint', updated);
  }

  // ── 14. Location falls back to the target URL ───────────────────────────
  {
    const noLocation: RetestFindingInput = {
      id: 'f-noloc',
      category: 'xss',
      title: 'Reflected XSS in search',
      verification: hintVerification(),
    };
    const r = await retestFinding({
      finding: noLocation,
      targetUrl: XSS_LOCATION,
      prober: reflecting,
      now: () => FIXED_NOW,
    });
    check('fallback: no location → targetUrl is probed, reproduced', r.verdict === 'reproduced', r);
  }

  // ── 15. Method constant ─────────────────────────────────────────────────
  check('method: RETEST_METHOD is the benign-canary read-only method',
    RETEST_METHOD === 'retester v1 (benign canary, read-only)', RETEST_METHOD);

  // ── 16. Routes: auth, ownership, authorization + scope re-checks, persistence ──
  {
    const db = new MemoryDatabase();
    const user = await db.createUser('owner@example.com', createHash('sha256').update('x').digest('hex'));
    const token = generateSessionToken();
    await db.createSession(user.id, hashSessionToken(token), new Date(Date.now() + 3600_000).toISOString());
    const cookie = `bs_session=${token}`;
    const authz = await db.createAuthorization({
      userId: user.id,
      type: 'ownership',
      statement: 'I own this target.',
    });
    const scope = {
      mode: 'subdomain' as const,
      includeSubdomains: false,
      excludedHosts: [] as string[],
      excludedPaths: [] as string[],
      maxRequestsPerSecond: 2,
    };
    const scan = await db.createScan({
      userId: user.id,
      targetUrl: XSS_LOCATION,
      mode: 'active',
      scope,
      authorizationId: authz.id,
    });
    const storedFinding = await db.addFinding({
      scanId: scan.id,
      category: 'xss',
      title: 'Reflected XSS in search',
      description: 'Test finding.',
      severity: 'high',
      confidence: 'high',
      trapProbability: 0,
      honeypotSuspect: false,
      location: XSS_LOCATION,
      evidence: '',
      reproSteps: [],
      remediation: 'Fix it.',
      references: [],
      verification: verifiedVerification(),
    });
    // Injected runner: a fake that always reports the proof fixed, so the
    // route test exercises wiring (auth, re-checks, persistence), not the
    // ladder (covered above).
    const fakeRetest = async (finding: Finding, _targetUrl: string, _userId: string): Promise<RetestResult> => ({
      findingId: finding.id,
      verdict: 'fixed',
      depth: 'unproven',
      impactSummary: 'Retest: the proof no longer reproduces.',
      evidence: [],
      testedAt: FIXED_NOW,
      method: RETEST_METHOD,
    });
    const app = Fastify();
    await app.register(async (instance) => {
      await retestRoutes(instance, { db, runRetest: fakeRetest });
    });
    await app.ready();

    const unauth = await app.inject({ method: 'POST', url: `/api/tasks/${scan.id}/findings/${storedFinding.id}/retest` });
    check('route: POST retest without auth is 401', unauth.statusCode === 401, unauth.statusCode);

    const res = await app.inject({
      method: 'POST',
      url: `/api/tasks/${scan.id}/findings/${storedFinding.id}/retest`,
      headers: { cookie },
    });
    const resBody = res.json() as { verdict: string; verification: { status: string } };
    check('route: POST retest returns the fake verdict', res.statusCode === 200 && resBody.verdict === 'fixed', res.body);
    check('route: POST retest returns the updated verification',
      resBody.verification.status === 'fixed', resBody.verification);
    const storedRetests = await db.listRetests(scan.id);
    check('route: retest row persisted',
      storedRetests.length === 1 && storedRetests[0]?.verdict === 'fixed' && storedRetests[0]?.findingId === storedFinding.id,
      storedRetests);
    const storedFindings = await db.listFindings(scan.id);
    check('route: finding verification updated to fixed in the DB',
      storedFindings[0]?.verification?.status === 'fixed', storedFindings[0]?.verification);

    const list = await app.inject({ method: 'GET', url: `/api/tasks/${scan.id}/retests`, headers: { cookie } });
    const listBody = list.json() as { retests: Array<{ verdict: string }> };
    check('route: GET retests lists the stored retest',
      list.statusCode === 200 && listBody.retests.length === 1 && listBody.retests[0]?.verdict === 'fixed', list.body);

    const other = await db.createUser('other@example.com', 'x');
    const otherToken = generateSessionToken();
    await db.createSession(other.id, hashSessionToken(otherToken), new Date(Date.now() + 3600_000).toISOString());
    const otherPost = await app.inject({
      method: 'POST',
      url: `/api/tasks/${scan.id}/findings/${storedFinding.id}/retest`,
      headers: { cookie: `bs_session=${otherToken}` },
    });
    check('route: POST retest refuses another user (404)', otherPost.statusCode === 404, otherPost.statusCode);
    const otherList = await app.inject({
      method: 'GET',
      url: `/api/tasks/${scan.id}/retests`,
      headers: { cookie: `bs_session=${otherToken}` },
    });
    check('route: GET retests refuses another user (404)', otherList.statusCode === 404, otherList.statusCode);

    const missing = await app.inject({
      method: 'POST',
      url: `/api/tasks/${scan.id}/findings/no-such-finding/retest`,
      headers: { cookie },
    });
    check('route: POST retest for a missing finding is 404', missing.statusCode === 404, missing.statusCode);

    // No authorization record on the scan → retest refused (403).
    const unauthzScan = await db.createScan({
      userId: user.id,
      targetUrl: XSS_LOCATION,
      mode: 'active',
      scope,
    });
    const unauthzFinding = await db.addFinding({
      scanId: unauthzScan.id,
      category: 'xss',
      title: 'Reflected XSS in search',
      description: 'Test finding.',
      severity: 'high',
      confidence: 'high',
      trapProbability: 0,
      honeypotSuspect: false,
      location: XSS_LOCATION,
      evidence: '',
      reproSteps: [],
      remediation: 'Fix it.',
      references: [],
    });
    const refused = await app.inject({
      method: 'POST',
      url: `/api/tasks/${unauthzScan.id}/findings/${unauthzFinding.id}/retest`,
      headers: { cookie },
    });
    check('route: POST retest without an authorization record is 403', refused.statusCode === 403, refused.statusCode);

    // Finding outside the authorised scope → retest refused (403).
    const oosFinding = await db.addFinding({
      scanId: scan.id,
      category: 'xss',
      title: 'Reflected XSS elsewhere',
      description: 'Test finding.',
      severity: 'high',
      confidence: 'high',
      trapProbability: 0,
      honeypotSuspect: false,
      location: 'https://other.example.com/x?q=hello',
      evidence: '',
      reproSteps: [],
      remediation: 'Fix it.',
      references: [],
    });
    const oos = await app.inject({
      method: 'POST',
      url: `/api/tasks/${scan.id}/findings/${oosFinding.id}/retest`,
      headers: { cookie },
    });
    check('route: POST retest for an out-of-scope finding is 403', oos.statusCode === 403, oos.statusCode);

    await app.close();
    await db.close();
  }

  if (failures > 0) { console.error(`${failures} retester test(s) failed`); process.exit(1); }
  console.log('ALL RETESTER TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('retester test crashed', e); process.exit(1); });

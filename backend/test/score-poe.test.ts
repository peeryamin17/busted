/**
 * Tests for the H8/H9 grading fixes (reports/score.ts, multiagent/depthLadder.ts,
 * reports/verification.ts): empty coverage cannot score grade A, and POE 2
 * findings stay hints rather than verified.
 *
 * Run:  npx tsx test/score-poe.test.ts   (from backend/)
 */
import { computeOntologyScore, securityScore } from '../src/reports/score.js';
import { hintFindings, verifiedFindings, verificationLabel } from '../src/reports/verification.js';
import {
  validateFindingWithLadder,
  type DepthProber,
  type DepthProbeResponse,
} from '../src/multiagent/depthLadder.js';
import type { Finding } from '../src/types.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

const FIXED_NOW = '2026-11-22T16:00:00.000Z';

function resp(partial: Partial<DepthProbeResponse>): DepthProbeResponse {
  return { ok: true, status: 200, headers: {}, body: '', ...partial };
}

function findingWithVerification(overrides: Partial<Finding> & {
  verification: NonNullable<Finding['verification']>;
}): Finding {
  return {
    id: 'f1',
    scanId: 'scan-1',
    category: 'xss',
    title: 'Reflected XSS in search',
    description: 'Canary reflected.',
    severity: 'high',
    confidence: 'high',
    trapProbability: 0,
    honeypotSuspect: false,
    location: 'http://127.0.0.1:9/search',
    evidence: 'canary reflected',
    reproSteps: ['visit /search?q=<canary>'],
    remediation: 'Encode output.',
    references: [],
    createdAt: FIXED_NOW,
    ...overrides,
  };
}

async function main() {
  // ── 1. Empty coverage cannot score grade A ──
  {
    const s = securityScore([]);
    check('score: no coverage defaults to passive', s.coverageRatio === 0 && s.coverageLabel === 'Passive Posture Only', s);
    check('score: no coverage caps at INCOMPLETE, never A', s.grade === 'INCOMPLETE', s.grade);
  }
  {
    const s = securityScore([{ severity: 'low' }]);
    check('score: findings without coverage still cannot score A', s.grade !== 'A', s.grade);
  }
  {
    // Explicit active coverage still earns A: the fix targets omitted coverage only.
    const s = securityScore([], {
      mode: 'active',
      endpointsDiscovered: 4,
      endpointsActivelyTested: 4,
      authenticated: true,
    });
    check('score: measured full active coverage can still score A', s.grade === 'A', s.grade);
  }
  {
    const emptyControls = {
      totalMutatingEndpoints: 0,
      protectedMutatingEndpoints: 0,
      totalBaasTargets: 0,
      rlsProtectedBaasTargets: 0,
      totalSessionCookies: 0,
      hardenedSessionCookies: 0,
    };
    const r = computeOntologyScore({
      nodes: [],
      controls: emptyControls,
      coverage: {
        mode: 'active',
        archetypes: [],
        endpointsDiscovered: 4,
        endpointsTested: 4,
        authenticated: true,
      },
    });
    check('ontology: empty controls report hygiene unmeasured (null)', r.matrices.controlHygieneScore === null, r.matrices);
    check('ontology: empty controls cannot score A', r.effectiveGrade !== 'A', r.effectiveGrade);
  }
  {
    // Fully protected controls still earn A: the null gate blocks only unmeasured hygiene.
    const fullControls = {
      totalMutatingEndpoints: 2,
      protectedMutatingEndpoints: 2,
      totalBaasTargets: 1,
      rlsProtectedBaasTargets: 1,
      totalSessionCookies: 1,
      hardenedSessionCookies: 1,
    };
    const r = computeOntologyScore({
      nodes: [],
      controls: fullControls,
      coverage: {
        mode: 'active',
        archetypes: [],
        endpointsDiscovered: 4,
        endpointsTested: 4,
        authenticated: true,
      },
    });
    check('ontology: measured hygiene 100 keeps A reachable', r.matrices.controlHygieneScore === 100 && r.effectiveGrade === 'A', r);
  }

  // ── 2. POE 2 findings stay hints; POE 3+ verifies ──
  {
    const oneParam: DepthProber = async (req) => {
      const u = new URL(req.url);
      const q = u.searchParams.get('q') ?? '';
      return resp({ body: q ? `<html>results for ${q}</html>` : '<html>no results</html>' });
    };
    const v = await validateFindingWithLadder(
      { category: 'xss', title: 'Reflected XSS in search', location: 'http://127.0.0.1:9/search?q=hello' },
      oneParam,
      { now: () => FIXED_NOW },
    );
    check('ladder: single-context reproduction stays hint at POE 2', v.status === 'hint' && v.depth === 'confirmed' && v.poe === 2, v);
  }
  {
    const twoParams: DepthProber = async (req) => {
      const u = new URL(req.url);
      const values = [...u.searchParams.values()].join(' ');
      return resp({ body: `<html><body>results for ${values}</body></html>` });
    };
    const v = await validateFindingWithLadder(
      { category: 'xss', title: 'Reflected XSS in search', location: 'http://127.0.0.1:9/search?q=hello' },
      twoParams,
      { now: () => FIXED_NOW },
    );
    check('ladder: cross-context proof verifies at POE 3', v.status === 'verified' && v.depth === 'escalated' && v.poe === 3, v);
  }
  {
    // A stored record that still says verified at POE 2 must not reach the
    // "Verified exploit chains" listing; it belongs with the hints.
    const legacyPoe2 = findingWithVerification({
      verification: {
        status: 'verified',
        depth: 'confirmed',
        impact: 'single-context',
        impactSummary: 'Canary reflected in one context.',
        evidence: [
          { rung: 'confirm', kind: 'xss-reflection', request: 'GET /search?q=<canary>', observed: 'HTTP 200: canary reflected.', status: 200 },
        ],
        testedAt: FIXED_NOW,
        method: 'depth-ladder v1 (benign canary, read-only proofs)',
      },
    });
    check('reports: POE 2 record stays out of verified findings', verifiedFindings([legacyPoe2]).length === 0, verifiedFindings([legacyPoe2]));
    check('reports: POE 2 record lands with the hints', hintFindings([legacyPoe2]).length === 1, hintFindings([legacyPoe2]));
    check('reports: POE 2 record is labelled a hint, not verified', verificationLabel(legacyPoe2).startsWith('Hint'), verificationLabel(legacyPoe2));
  }
  {
    const poe3 = findingWithVerification({
      verification: {
        status: 'verified',
        depth: 'escalated',
        impact: 'cross-context',
        impactSummary: 'Canary reflected in two contexts.',
        canaryToken: 'bs0123456789abcdef',
        evidence: [
          { rung: 'confirm', kind: 'xss-reflection', request: 'GET /search?q=<canary>', observed: 'HTTP 200: canary reflected.', status: 200 },
          { rung: 'escalate', kind: 'xss-second-context', request: 'GET /search?search=<canary>', observed: 'HTTP 200: canary also reflected.', status: 200 },
        ],
        testedAt: FIXED_NOW,
        method: 'depth-ladder v1 (benign canary, read-only proofs)',
      },
    });
    check('reports: POE 3 verified record stays in verified findings', verifiedFindings([poe3]).length === 1, verifiedFindings([poe3]));
    check('reports: POE 3 verified record keeps its Verified label', verificationLabel(poe3).startsWith('Verified'), verificationLabel(poe3));
  }

  if (failures > 0) { console.error(`${failures} score-poe test(s) failed`); process.exit(1); }
  console.log('ALL SCORE-POE TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('score-poe test crashed', e); process.exit(1); });

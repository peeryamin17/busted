/**
 * Unit tests for the proof gate on the retester: a 'reproduced'
 * verdict upgrades a hint to verified only at POE >= 3 with a verbatim
 * receipt in bound proof. 'fixed' and 'inconclusive' are untouched by the
 * gate. All live probes are mocked, no network, no real target, no LLM.
 *
 * Run:  npx tsx test/retester-gate.test.ts   (from backend/)
 */
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
import type { ProofRecord } from '../src/reports/poe.js';
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

function hintVerification(): FindingVerification {
  return untestedVerification(
    'no read-only live probe exists for category "headers" — the ladder only tests XSS, IDOR, CORS and GraphQL findings live.',
    () => FIXED_NOW,
  );
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
  return resp({
    headers: { 'set-cookie': 'session=abc123', 'content-type': 'text/html' },
    body: `<html><body>results for ${values}</body></html>`,
  });
};

/** Reflects only the first parameter (q), the ladder confirms but never escalates. */
const firstParamOnly: DepthProber = async (req) => {
  const u = new URL(req.url);
  const q = u.searchParams.get('q');
  return resp({ body: q ? `<html><body>results for ${q}</body></html>` : '<html>nothing here</html>' });
};

/** Hand-built 'reproduced' result at POE 3 (escalated, xss-second-context). */
function reproducedResult(overrides: Partial<RetestResult> = {}): RetestResult {
  return {
    findingId: 'f-xss',
    verdict: 'reproduced',
    depth: 'escalated',
    impactSummary: 'Retest reproduced the finding with a fresh benign canary.',
    evidence: [
      {
        rung: 'confirm',
        kind: 'xss-reflection',
        request: 'GET /search?q=<canary>',
        observed: 'HTTP 200: canary reflected unencoded in text content. Excerpt: "searchResultsPage"',
        status: 200,
      },
      {
        rung: 'escalate',
        kind: 'xss-second-context',
        request: 'GET /search?search=<canary>',
        observed: 'HTTP 200: canary also reflected via a second parameter (search). Excerpt: "searchResultsPage"',
        status: 200,
      },
    ],
    canaryToken: 'bs0123456789abcdef',
    testedAt: FIXED_NOW,
    method: RETEST_METHOD,
    ...overrides,
  };
}

async function main() {
  // ── 1. Reproduced, POE 3 + passing receipt → verified ───────────────────
  {
    const r = await retestFinding({
      finding: xssFinding(hintVerification()),
      targetUrl: TARGET,
      prober: reflecting,
      now: () => FIXED_NOW,
    });
    check('gate: reproduced verdict', r.verdict === 'reproduced' && r.depth === 'escalated', r);
    check('gate: retest collects proof bodies (baseline + 2 rungs)',
      (r.proofBodies?.length ?? 0) === 3, r.proofBodies);
    check('gate: retest collects proof records (baseline + 2 rungs)',
      (r.proofRecords?.length ?? 0) === 3, r.proofRecords);
    check('gate: proof record carries status + the canary in its body',
      r.proofRecords?.[1]?.status === 200 &&
        (r.proofRecords?.[1]?.body ?? '').includes(r.canaryToken ?? 'never'),
      r.proofRecords?.[1]);
    check('gate: proof record headers are redacted (set-cookie masked, others kept)',
      r.proofRecords?.[0]?.headers?.['set-cookie'] === '[REDACTED]' &&
        r.proofRecords?.[0]?.headers?.['content-type'] === 'text/html',
      r.proofRecords?.[0]?.headers);
    const updated = applyRetestVerdict(findingRecord(xssFinding(hintVerification())), r);
    check('gate: reproduced POE 3 + receipt → verified',
      updated.status === 'verified' && updated.depth === 'escalated', updated);
    check('gate: verified records poe 3 + receiptChecked true',
      updated.poe === 3 && updated.receiptChecked === true, updated);
  }

  // ── 2. Reproduced, POE 2 → stays hint ──────────────────────────────────
  {
    const r = await retestFinding({
      finding: xssFinding(hintVerification()),
      targetUrl: TARGET,
      prober: firstParamOnly,
      now: () => FIXED_NOW,
    });
    check('gate: single-context retest reproduces at POE 2',
      r.verdict === 'reproduced' && r.depth === 'confirmed', r);
    const held = applyRetestVerdict(findingRecord(xssFinding(hintVerification())), r);
    check('gate: reproduced POE 2 → stays hint',
      held.status === 'hint' && held.depth === 'confirmed', held);
    check('gate: held hint names the failing condition',
      held.impactSummary.includes('Held as a hint by the proof gate') &&
        held.impactSummary.includes('POE 2 is below 3'),
      held.impactSummary);
    check('gate: held hint records poe 2, receipt passed',
      held.poe === 2 && held.receiptChecked === true, held);
  }

  // ── 3. Reproduced, POE 3, receipt fails → stays hint ───────────────────
  {
    const held = applyRetestVerdict(
      findingRecord(xssFinding(hintVerification())),
      reproducedResult(),
      ['<html>nothing here</html>'],
    );
    check('gate: reproduced POE 3 but no receipt → stays hint',
      held.status === 'hint' && held.depth === 'escalated', held);
    check('gate: held hint names the receipt failure',
      held.impactSummary.includes('Held as a hint by the proof gate') &&
        held.impactSummary.includes('no evidence quote appears verbatim'),
      held.impactSummary);
    check('gate: held hint records failed receipt',
      held.poe === 3 && held.receiptChecked === false, held);
  }

  // ── 4. Reproduced, POE 3, receipt via a header record → verified ───────
  {
    const headerRecord: ProofRecord = {
      label: 'cors-confirm',
      url: 'http://127.0.0.1:9/api/me',
      status: 200,
      headers: {
        'access-control-allow-origin': 'https://canary-bs0123456789abcdef.bugseek-test.invalid',
      },
      body: '{}',
    };
    const viaHeader = applyRetestVerdict(
      findingRecord(xssFinding(hintVerification())),
      reproducedResult(),
      undefined,
      [headerRecord],
    );
    check('gate: reproduced POE 3 + receipt in a header record → verified',
      viaHeader.status === 'verified' && viaHeader.receiptChecked === true, viaHeader);
  }

  // ── 5. 'fixed' still moves to fixed without a receipt ──────────────────
  {
    const fixedResult: RetestResult = {
      findingId: 'f-xss',
      verdict: 'fixed',
      depth: 'unproven',
      impactSummary: 'Retest: the proof no longer reproduces.',
      evidence: [],
      testedAt: FIXED_NOW,
      method: RETEST_METHOD,
    };
    const fixed = applyRetestVerdict(
      findingRecord(xssFinding(verifiedVerification())),
      fixedResult,
    );
    check("gate: fixed still moves to fixed without a receipt", fixed.status === 'fixed', fixed);
    check("gate: fixed keeps depth unproven, impact not-measured",
      fixed.depth === 'unproven' && fixed.impact === 'not-measured', fixed);
  }

  // ── 6. 'inconclusive' still changes nothing ────────────────────────────
  {
    const rec = findingRecord(xssFinding(verifiedVerification()));
    const inconclusiveResult: RetestResult = {
      findingId: 'f-xss',
      verdict: 'inconclusive',
      impactSummary: 'Retest inconclusive: the target could not be reached.',
      evidence: [],
      testedAt: FIXED_NOW,
      method: RETEST_METHOD,
    };
    const kept = applyRetestVerdict(rec, inconclusiveResult);
    check('gate: inconclusive leaves verification untouched (same object)',
      kept === rec.verification, kept);
  }

  // ── 7. IDOR: shape proof verifies via the quoted field list ────────────
  // The IDOR proof lives in response shape (field names). The ladder
  // quotes the field list in its evidence, and the proof record renders
  // the same list on its FIELDS line, so the verbatim quote receipt
  // passes on the shape itself, and the gate re-verifies a genuine
  // shape-only reproduction instead of holding it as a hint.
  {
    const idorProber: DepthProber = async () =>
      resp({ body: JSON.stringify({ id: 42, name: 'x', email: 'y' }) });
    const idor: RetestFindingInput = {
      id: 'f-idor',
      category: 'idor',
      title: 'IDOR on /api/users/42',
      location: 'http://127.0.0.1:9/api/users/42',
      verification: hintVerification(),
    };
    const r = await retestFinding({ finding: idor, targetUrl: TARGET, prober: idorProber, now: () => FIXED_NOW });
    check('gate: idor shape reproduction is reproduced at POE 3',
      r.verdict === 'reproduced' && r.depth === 'escalated', r);
    check('gate: idor proof records carry the observed shape',
      r.proofRecords?.some((p) => p.shape?.join(',') === 'id,name,email') ?? false,
      r.proofRecords);
    const verified = applyRetestVerdict(findingRecord(idor), r);
    check('gate: idor reproduction with the field list in proof → verified',
      verified.status === 'verified' && verified.poe === 3 && verified.receiptChecked === true, verified);
  }

  // ── 8. GraphQL: introspection proof verifies via the "__schema" anchor ─
  {
    const gqlProber: DepthProber = async (req) => {
      if (req.body?.includes('__schema')) {
        return resp({ body: JSON.stringify({ data: { __schema: { queryType: { name: 'Query' }, mutationType: null } } }) });
      }
      return resp({ body: JSON.stringify({ data: { __typename: 'Query' } }) });
    };
    const gql: RetestFindingInput = {
      id: 'f-gql',
      category: 'graphql',
      title: 'GraphQL introspection enabled',
      location: 'http://127.0.0.1:9/graphql',
      verification: hintVerification(),
    };
    const r = await retestFinding({ finding: gql, targetUrl: TARGET, prober: gqlProber, now: () => FIXED_NOW });
    check('gate: graphql introspection is reproduced at POE 3',
      r.verdict === 'reproduced' && r.depth === 'escalated', r);
    const verified = applyRetestVerdict(findingRecord(gql), r);
    check('gate: graphql reproduction with the "__schema" anchor in proof → verified',
      verified.status === 'verified' && verified.poe === 3 && verified.receiptChecked === true, verified);
  }

  if (failures > 0) { console.error(`${failures} retester-gate test(s) failed`); process.exit(1); }
  console.log('ALL RETESTER-GATE TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('retester-gate test crashed', e); process.exit(1); });

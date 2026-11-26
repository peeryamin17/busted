/**
 * Unit tests for the severity<->CVSS grading pass (reports/gradeFindings.ts)
 * and the vector scorer (reports/cvss.ts). No network, no DB, no live LLM:
 * the NVD lookup is always an injected fake. Vector scores below are
 * hand-computed from the FIRST v3.1 formula (see the arithmetic in each
 * comment), not fetched from anywhere.
 *
 * Run:  npx tsx test/gradeFindings.test.ts   (from backend/)
 */
import {
  applyContext,
  buildReproduceBlock,
  extractCveId,
  fetchNvdScore,
  gradeFinding,
  gradeFindings,
  gradingNotes,
  isPublicTarget,
  type NvdScoreFetcher,
} from '../src/reports/gradeFindings.js';
import { parseCvssVector, scoreFromVector } from '../src/reports/cvss.js';
import { generateMarkdownReport } from '../src/reports/markdown.js';
import { buildJsonReport } from '../src/reports/json.js';
import type { Finding } from '../src/types.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

// ISS = 1 - 0.44^3 = 0.914816; impact = 6.42 * 0.914816 = 5.873;
// exploit = 8.22 * 0.85 * 0.77 * 0.85 * 0.85 = 3.887; total 9.760 -> 9.8.
const VEC_98 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
// ISS = 0.56; impact = 6.42 * 0.56 = 3.595; exploit 3.887; total 7.482 -> 7.5.
const VEC_75 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N';
// ISS = 1 - 0.78 * 0.78 = 0.3916; impact = 7.52 * (0.3916 - 0.029) = 2.727
// (the 3.25 * (iss - 0.02)^15 term is ~1e-6); exploit =
// 8.22 * 0.85 * 0.77 * 0.85 * 0.62 = 2.835; 1.08 * 5.562 = 6.007 -> 6.1.
const VEC_61 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N';
// ISS = 0.3916; impact = 6.42 * 0.3916 = 2.514; exploit =
// 8.22 * 0.85 * 0.44 * 0.85 * 0.85 = 2.221; total 4.735 -> 4.8.
const VEC_48 = 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N';

const scan = {
  id: 'scan-00000001',
  userId: 'user-1',
  targetUrl: 'https://example.com',
  mode: 'active' as const,
  status: 'completed' as const,
  scope: {
    mode: 'page' as const,
    includeSubdomains: false,
    excludedHosts: [],
    excludedPaths: [],
    maxRequestsPerSecond: 1,
  },
  techStack: [],
  progress: { completedSteps: 1, totalSteps: 1 },
  createdAt: '2026-11-23T10:00:00.000Z',
  finishedAt: '2026-11-23T10:05:00.000Z',
};

function mkFinding(over: Partial<Finding> = {}): Finding {
  return {
    id: 'f-1',
    scanId: scan.id,
    category: 'headers',
    title: 'Missing CSP header',
    description: 'No Content-Security-Policy header present.',
    severity: 'medium',
    confidence: 'high',
    trapProbability: 0,
    honeypotSuspect: false,
    location: 'https://example.com/admin',
    reproSteps: ['Open https://example.com/admin', 'Observe the response has no CSP header'],
    remediation: 'Add a CSP header.',
    references: [],
    createdAt: '2026-11-23T10:01:00.000Z',
    ...over,
  };
}

function verifiedFinding(over: Partial<Finding> = {}): Finding {
  return mkFinding({
    verification: {
      status: 'verified',
      depth: 'escalated',
      impact: 'cross-context',
      impactSummary: 'Canary reflected in a second context.',
      evidence: [],
      testedAt: '2026-11-23T10:02:00.000Z',
      method: 'depth-ladder',
    },
    ...over,
  });
}

async function main() {
  // ── 1. Vector -> score, hand-computed from the v3.1 formula ──
  check('vector: max vector scores 9.8', scoreFromVector(VEC_98) === 9.8, scoreFromVector(VEC_98));
  check('vector: C:H only scores 7.5', scoreFromVector(VEC_75) === 7.5, scoreFromVector(VEC_75));
  check('vector: scope-changed vector scores 6.1', scoreFromVector(VEC_61) === 6.1, scoreFromVector(VEC_61));
  check('vector: high-complexity vector scores 4.8', scoreFromVector(VEC_48) === 4.8, scoreFromVector(VEC_48));
  check('vector: parse returns all eight metrics', (() => {
    const m = parseCvssVector(VEC_98);
    return m !== null && m.av === 'N' && m.ac === 'L' && m.pr === 'N' && m.ui === 'N' && m.s === 'U' && m.c === 'H' && m.i === 'H' && m.a === 'H';
  })());
  check('vector: wrong prefix is null', scoreFromVector('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H') === null);
  check('vector: bad metric value is null', scoreFromVector('CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H') === null);
  check('vector: missing metric is null', scoreFromVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H') === null);
  check('vector: empty string is null', scoreFromVector('') === null);

  // ── 2. Model score disagreeing with its own vector is replaced ──
  {
    const f = gradeFinding(mkFinding({ severity: 'critical', cvssScore: 9.1, cvssVector: VEC_98 }));
    check('score: model 9.1 replaced by computed 9.8', f.cvssScore === 9.8, f.cvssScore);
    check('score: vector kept', f.cvssVector === VEC_98);
    check('score: replacement recorded in reason', (f.gradeReason ?? '').includes('9.1') && (f.gradeReason ?? '').includes('9.8'), f.gradeReason);
    check('score: severity stays critical, no rewrite flag', f.severity === 'critical' && f.severityRewritten !== true);
  }
  {
    const f = gradeFinding(mkFinding({ severity: 'high', cvssScore: 7.5, cvssVector: VEC_75 }));
    check('score: agreeing model score kept', f.cvssScore === 7.5 && f.gradeReason === undefined, f);
  }
  {
    // No vector and no score: falls back to the severity+category estimate.
    const f = gradeFinding(mkFinding({ severity: 'medium' }));
    check('score: estimate fallback fills a score', f.cvssScore === 5.3, f.cvssScore);
    check('score: estimate fallback fills a vector', typeof f.cvssVector === 'string' && f.cvssVector.startsWith('CVSS:3.1/'), f.cvssVector);
    check('score: estimate stays in its band', f.severity === 'medium' && f.severityRewritten !== true);
  }

  // ── 3. Severity rewritten to the score band, flag set, original kept ──
  {
    const f = gradeFinding(mkFinding({ severity: 'low', cvssScore: 2.0, cvssVector: VEC_98 }));
    check('severity: low -> critical on a 9.8 vector', f.severity === 'critical', f.severity);
    check('severity: rewrite flag set', f.severityRewritten === true);
    check('severity: reason names the original', (f.gradeReason ?? '').includes('low -> critical'), f.gradeReason);
  }
  {
    const f = gradeFinding(mkFinding({ severity: 'critical', cvssScore: 9.9, cvssVector: VEC_75 }));
    check('severity: critical -> high on a 7.5 vector', f.severity === 'high', f.severity);
    check('severity: downgrade is flagged too', f.severityRewritten === true);
  }
  {
    const orig = mkFinding({ severity: 'low', cvssVector: VEC_98 });
    gradeFinding(orig);
    check('severity: grading returns a copy, input untouched', orig.severity === 'low' && orig.cvssScore === undefined, orig);
  }

  // ── 4. Context multipliers: direction and clamp ──
  check('context: internet-facing raises 7.5 to 8.6', applyContext(7.5, { internetFacing: true }) === 8.6, applyContext(7.5, { internetFacing: true }));
  check('context: auth-required lowers 7.5 to 6.0', applyContext(7.5, { authRequired: true }) === 6.0, applyContext(7.5, { authRequired: true }));
  check('context: exploit-available raises 7.5 to 9.0', applyContext(7.5, { exploitAvailable: true }) === 9.0, applyContext(7.5, { exploitAvailable: true }));
  check('context: combined multipliers clamp at 10.0', applyContext(9.8, { internetFacing: true, exploitAvailable: true }) === 10, applyContext(9.8, { internetFacing: true, exploitAvailable: true }));
  check('context: no context leaves the score alone', applyContext(7.5, {}) === 7.5);
  {
    const f = gradeFinding(mkFinding({ severity: 'high', cvssVector: VEC_75 }), { context: { authRequired: true } });
    check('context: auth-required drops high to medium', f.severity === 'medium' && f.cvssScore === 6.0, f);
    check('context: context-driven rewrite is flagged', f.severityRewritten === true);
  }
  {
    const f = gradeFinding(mkFinding({ severity: 'high', cvssVector: VEC_98 }), { context: { internetFacing: true, exploitAvailable: true } });
    check('context: clamped score keeps critical', f.severity === 'critical' && f.cvssScore === 10, f);
  }

  // ── 5. NVD cross-check (injected fake fetcher, never live) ──
  const cveFinding = (over: Partial<Finding> = {}) =>
    verifiedFinding({
      severity: 'critical',
      cvssVector: VEC_98,
      references: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
      ...over,
    });
  check('nvd: CVE id extracted from references', extractCveId(cveFinding()) === 'CVE-2021-44228');
  check('nvd: no CVE in finding', extractCveId(mkFinding()) === null);
  {
    const fake: NvdScoreFetcher = async () => 5.0;
    const [f] = await gradeFindings([cveFinding()], { fetchNvdScore: fake });
    check('nvd: mismatch over 2.0 recorded', f.nvdCheck === 'mismatch' && f.nvdScore === 5.0, f);
    check('nvd: mismatch demotes verified to hint', f.verification?.status === 'hint', f.verification);
    check('nvd: demotion reason recorded', (f.gradeReason ?? '').includes('NVD cross-check'), f.gradeReason);
  }
  {
    const fake: NvdScoreFetcher = async () => 9.0;
    const [f] = await gradeFindings([cveFinding()], { fetchNvdScore: fake });
    check('nvd: mismatch within 2.0 is a match', f.nvdCheck === 'match', f);
    check('nvd: small mismatch leaves verified alone', f.verification?.status === 'verified', f.verification);
  }
  {
    const fake: NvdScoreFetcher = async () => null;
    const [f] = await gradeFindings([cveFinding()], { fetchNvdScore: fake });
    check('nvd: no NVD entry is unchecked', f.nvdCheck === 'unchecked', f);
    check('nvd: unchecked never demotes', f.verification?.status === 'verified', f.verification);
  }
  {
    const fake: NvdScoreFetcher = async () => { throw new Error('network down'); };
    const [f] = await gradeFindings([cveFinding()], { fetchNvdScore: fake });
    check('nvd: fetcher throw is unchecked, fail-open', f.nvdCheck === 'unchecked', f);
    check('nvd: throw never demotes', f.verification?.status === 'verified', f.verification);
  }
  {
    let calls = 0;
    const fake: NvdScoreFetcher = async () => { calls++; return 9.8; };
    const [f] = await gradeFindings([mkFinding({ severity: 'critical', cvssVector: VEC_98 })], { fetchNvdScore: fake });
    check('nvd: no CVE means no fetch', calls === 0 && f.nvdCheck === undefined, { calls, nvdCheck: f.nvdCheck });
  }
  {
    // Same CVE on two findings: fetched once, both graded.
    let calls = 0;
    const fake: NvdScoreFetcher = async () => { calls++; return 9.8; };
    const out = await gradeFindings([cveFinding({ id: 'f-a' }), cveFinding({ id: 'f-b' })], { fetchNvdScore: fake });
    check('nvd: shared CVE fetched once per pass', calls === 1, calls);
    check('nvd: both findings checked', out.every((f) => f.nvdCheck === 'match'), out.map((f) => f.nvdCheck));
  }
  {
    // A hint finding stays a hint on mismatch; a fixed finding is untouched.
    const fake: NvdScoreFetcher = async () => 5.0;
    const [hint] = await gradeFindings([mkFinding({ severity: 'critical', cvssVector: VEC_98, references: ['CVE-2021-44228'] })], { fetchNvdScore: fake });
    check('nvd: mismatch without verification object stays a hint', hint.nvdCheck === 'mismatch' && hint.verification === undefined, hint);
  }

  // ── 6. Reproduce block ──
  {
    const block = buildReproduceBlock(mkFinding());
    check('repro: command is a paste-safe curl of the location', block.command === `curl -s -i 'https://example.com/admin'`, block.command);
    check('repro: request is raw HTTP with host', block.request.startsWith('GET /admin HTTP/1.1\nHost: example.com'), block.request);
    check('repro: expected indicator present', block.expected.length > 0 && block.expected.includes('CSP'), block.expected);
  }
  {
    const block = buildReproduceBlock(mkFinding({ location: "https://example.com/a'b", reproSteps: [], evidence: undefined }));
    check('repro: single quote in URL is shell-escaped', block.command === `curl -s -i 'https://example.com/a'\\''b'`, block.command);
  }
  {
    const block = buildReproduceBlock(mkFinding({ location: undefined, reproSteps: [], evidence: undefined }));
    check('repro: no target still yields a block', block.command.length > 0 && block.request.includes('GET / HTTP/1.1'), block);
  }

  // ── 7. Grading notes + renderers ──
  {
    const f = gradeFinding(mkFinding({ severity: 'low', cvssVector: VEC_98 }));
    const notes = gradingNotes(f);
    check('notes: rewrite surfaced', notes.some((n) => n.includes('low -> critical')), notes);
    const md = generateMarkdownReport({ scan, findings: [f], generatedBy: 'test' });
    check('md: re-grade note renders', md.includes('Severity re-graded: severity low -> critical'), md);
    check('md: reproduce block renders command', md.includes(`curl -s -i 'https://example.com/admin'`), md);
    check('md: reproduce block renders raw request', md.includes('GET /admin HTTP/1.1') && md.includes('Host: example.com'), md);
    check('md: reproduce block renders expected indicator', md.includes('Expected: Observe the response has no CSP header'), md);
    const doc = buildJsonReport({ scan, findings: [f], generatedBy: 'test' });
    check('json: graded fields present', doc.findings[0]?.severity === 'critical' && doc.findings[0]?.severityRewritten === true && doc.findings[0]?.cvssScore === 9.8, doc.findings[0]);
    check('json: reproduce block present', doc.findings[0]?.reproduce?.command === `curl -s -i 'https://example.com/admin'`, doc.findings[0]?.reproduce);
  }
  {
    const [f] = await gradeFindings([cveFinding()], { fetchNvdScore: async () => 5.0 });
    const md = generateMarkdownReport({ scan, findings: [f], generatedBy: 'test' });
    check('md: NVD mismatch note renders', md.includes('NVD cross-check: mismatch'), md);
    check('md: demoted finding listed under hints', md.includes('Hints (unverified)'), md);
  }

  // ── 8. Public-target helper ──
  check('target: public host is internet-facing', isPublicTarget('https://example.com') === true);
  check('target: localhost is not', isPublicTarget('http://localhost:3000') === false);
  check('target: loopback is not', isPublicTarget('http://127.0.0.1:8080/x') === false);
  check('target: private LAN is not', isPublicTarget('http://192.168.1.5/') === false);
  check('target: garbage URL is not', isPublicTarget('not a url') === false);

  // The live fetcher exists and is fail-open by construction (no live call
  // is made here: fetchNvdScore is only referenced to keep the import used).
  check('fetcher: live fetcher is exported', typeof fetchNvdScore === 'function');

  if (failures > 0) {
    console.error(`\n${failures} check(s) failed`);
    process.exit(1);
  }
  console.log('\nall gradeFindings checks passed');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

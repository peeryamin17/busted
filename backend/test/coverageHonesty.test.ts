/**
 * Coverage honesty tests (Wave 1 item 6): a zero-finding report must say
 * INCONCLUSIVE when part of the intended surface went unexamined, and
 * must never read as clean. No network, no database.
 *
 * Run:  npx tsx test/coverageHonesty.test.ts   (from backend/)
 */
import { inflateSync } from 'node:zlib';
import Fastify from 'fastify';
import JSZip from 'jszip';
import {
  RISK_CLASSES,
  coverageSummary,
  type CoverageEntry,
} from '../src/coverage/ledger.js';
import {
  coverageVerdict,
  emptyCoverageVerdict,
  zeroFindingsLines,
} from '../src/reports/coverageHonesty.js';
import { generateMarkdownReport } from '../src/reports/markdown.js';
import { generatePdfReport } from '../src/reports/pdf.js';
import { generateDocxReport } from '../src/reports/docx.js';
import { buildJsonReport } from '../src/reports/json.js';
import { renderMarkdownReport } from '../src/multiagent/orchestrator.js';
import { MemoryDatabase } from '../src/db/db.js';
import { MemoryGraphStore } from '../src/graph/store.js';
import { MemoryCoverageStore } from '../src/coverage/ledger.js';
import { generateSessionToken, hashSessionToken } from '../src/auth/session.js';
import { reportRoutes } from '../src/routes/reports.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) {
    failures++;
    console.error(`FAIL: ${name}`, extra ?? '');
  } else {
    console.log(`ok: ${name}`);
  }
}

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

const mkFinding = (over: Record<string, unknown> = {}) => ({
  id: 'f-1',
  scanId: scan.id,
  category: 'headers',
  title: 'Missing CSP header',
  description: 'No Content-Security-Policy header present.',
  severity: 'medium' as const,
  confidence: 'high' as const,
  trapProbability: 0,
  honeypotSuspect: false,
  reproSteps: [],
  remediation: 'Add a CSP header.',
  references: [],
  createdAt: '2026-11-23T10:01:00.000Z',
  ...over,
});

const entriesFor = (classes: string[], outcome: CoverageEntry['outcome'] = 'tested'): CoverageEntry[] =>
  classes.map((riskClass) => ({
    taskId: 'task-1',
    assetValue: 'example.com',
    riskClass,
    outcome,
  }));

const fullSummary = coverageSummary(entriesFor([...RISK_CLASSES]));
const partialSummary = coverageSummary(
  entriesFor(['recon', 'secrets', 'headers', 'cors', 'xss', 'idor']),
);
const lowSummary = coverageSummary(entriesFor(['recon', 'secrets']));

/** PDFKit flate-compresses content and hex-encodes text; undo both. */
async function pdfText(buf: Buffer): Promise<string> {
  const s = buf.toString('latin1');
  const inflated: string[] = [];
  let idx = 0;
  while (true) {
    const start = s.indexOf('stream', idx);
    if (start === -1) break;
    let dataStart = start + 6;
    if (s[dataStart] === '\r') dataStart += 1;
    if (s[dataStart] === '\n') dataStart += 1;
    const end = s.indexOf('endstream', dataStart);
    if (end === -1) break;
    try {
      inflated.push(inflateSync(buf.subarray(dataStart, end)).toString('latin1'));
    } catch {
      /* not a flate stream */
    }
    idx = end + 9;
  }
  const body = inflated.join('\n');
  const hits: { at: number; text: string }[] = [];
  for (const m of body.matchAll(/<([0-9A-Fa-f]+)>/g)) {
    hits.push({ at: m.index ?? 0, text: Buffer.from(m[1], 'hex').toString('latin1') });
  }
  for (const m of body.matchAll(/\((?:\\.|[^\\()])*\)/g)) {
    hits.push({
      at: m.index ?? 0,
      text: m[0].slice(1, -1).replace(/\\([()\\])/g, '$1'),
    });
  }
  return hits.sort((a, b) => a.at - b.at).map((h) => h.text).join('');
}

async function docxText(buf: Buffer): Promise<string> {
  const zip = await JSZip.loadAsync(buf);
  const xml = await zip.file('word/document.xml')?.async('string');
  return xml ?? '';
}

async function main() {
  // --- Verdict tiers ---
  const full = coverageVerdict(fullSummary, 0);
  check('verdict: full coverage is high', full.tier === 'high', full.tier);
  check('verdict: full coverage is not inconclusive', full.inconclusive === false);
  check('verdict: full coverage counts 10 classes', full.testedClasses === 10 && full.applicableClasses === 10);

  const partial = coverageVerdict(partialSummary, 0);
  check('verdict: 6 of 10 tested is partial', partial.tier === 'partial', partial.tier);
  check('verdict: partial + zero findings is inconclusive', partial.inconclusive === true);
  check('verdict: partial lists the untested classes',
    partial.untestedClasses.join(',') === 'auth,graphql,sourcemap,general',
    partial.untestedClasses);

  const low = coverageVerdict(lowSummary, 0);
  check('verdict: 2 of 10 tested is low', low.tier === 'low', low.tier);
  check('verdict: low + zero findings is inconclusive', low.inconclusive === true);

  const none = coverageVerdict(coverageSummary([]), 0);
  check('verdict: no entries at all is none', none.tier === 'none', none.tier);
  check('verdict: no entries + zero findings is inconclusive', none.inconclusive === true);
  check('verdict: no entries leaves all classes untested', none.untestedClasses.length === 10);

  check('verdict: findings present never inconclusive, even at none',
    coverageVerdict(coverageSummary([]), 2).inconclusive === false);
  check('verdict: findings present never inconclusive at partial',
    coverageVerdict(partialSummary, 1).inconclusive === false);

  const naOnly = coverageVerdict(
    coverageSummary([
      ...entriesFor(RISK_CLASSES.slice(0, 9)),
      { taskId: 'task-1', assetValue: 'example.com', riskClass: 'general', outcome: 'not_applicable' },
    ]),
    0,
  );
  check('verdict: not-applicable-only class is out of scope, tier stays high',
    naOnly.tier === 'high' && naOnly.applicableClasses === 9 && naOnly.inconclusive === false,
    naOnly);

  const allNa = coverageVerdict(
    coverageSummary(entriesFor([...RISK_CLASSES], 'not_applicable')),
    0,
  );
  check('verdict: every class ruled out means nothing examined',
    allNa.tier === 'none' && allNa.applicableClasses === 0 && allNa.inconclusive === true,
    allNa);

  const explicitUntested = coverageVerdict(
    coverageSummary([
      ...entriesFor(['recon']),
      { taskId: 'task-1', assetValue: 'example.com', riskClass: 'secrets', outcome: 'untested' },
    ]),
    0,
  );
  check('verdict: explicit untested entry counts as unexamined',
    explicitUntested.tier === 'low' && explicitUntested.untestedClasses.includes('secrets'),
    explicitUntested);

  check('verdict: empty helper matches empty summary',
    emptyCoverageVerdict(0).tier === 'none' && emptyCoverageVerdict(0).inconclusive === true);

  // --- Zero-findings wording ---
  const fullLines = zeroFindingsLines(full);
  check('wording: full coverage keeps the old sentence',
    fullLines.join(' ').includes('No findings were identified during this scan.'));
  check('wording: full coverage shows the tier',
    fullLines.join(' ').includes('Coverage: high'));
  check('wording: full coverage has no INCONCLUSIVE',
    !fullLines.join(' ').includes('INCONCLUSIVE'));

  const partialLines = zeroFindingsLines(partial).join(' ');
  check('wording: partial says INCONCLUSIVE', partialLines.includes('INCONCLUSIVE'));
  check('wording: partial never reads as clean', partialLines.includes('Unexamined is not clean'));
  check('wording: partial names the untested classes',
    partialLines.includes('Auth') && partialLines.includes('GraphQL'));
  check('wording: partial has no standalone old sentence',
    !partialLines.includes('No findings were identified during this scan.'));

  const noneLines = zeroFindingsLines(none).join(' ');
  check('wording: none tier says INCONCLUSIVE with the lowest tier',
    noneLines.includes('INCONCLUSIVE') && noneLines.includes('coverage: none'));

  // --- Markdown / PDF / DOCX generators ---
  const mdFull = generateMarkdownReport({ scan, findings: [], generatedBy: 'test', coverage: fullSummary });
  check('md: full coverage keeps old wording + tier',
    mdFull.includes('No findings were identified during this scan.') &&
      mdFull.includes('Coverage: high') &&
      !mdFull.includes('INCONCLUSIVE'));

  const mdPartial = generateMarkdownReport({ scan, findings: [], generatedBy: 'test', coverage: partialSummary });
  check('md: partial coverage says INCONCLUSIVE',
    mdPartial.includes('INCONCLUSIVE') && mdPartial.includes('Unexamined is not clean'));
  check('md: partial coverage drops the old sentence',
    !mdPartial.includes('No findings were identified during this scan.'));

  const mdNoCoverage = generateMarkdownReport({ scan, findings: [], generatedBy: 'test' });
  check('md: no coverage data is INCONCLUSIVE with the lowest tier',
    mdNoCoverage.includes('INCONCLUSIVE') && mdNoCoverage.includes('coverage: none'));

  const mdWithFindings = generateMarkdownReport({
    scan,
    findings: [mkFinding()],
    generatedBy: 'test',
    coverage: partialSummary,
  });
  check('md: findings present, no INCONCLUSIVE anywhere',
    !mdWithFindings.includes('INCONCLUSIVE'));

  const pdfPartial = await generatePdfReport({ scan, findings: [], generatedBy: 'test', coverage: partialSummary });
  const pdfPartialText = await pdfText(pdfPartial);
  check('pdf: partial coverage says INCONCLUSIVE',
    pdfPartialText.includes('INCONCLUSIVE') && pdfPartialText.includes('Unexamined is not clean'),
    pdfPartialText.slice(0, 300));

  const pdfFull = await generatePdfReport({ scan, findings: [], generatedBy: 'test', coverage: fullSummary });
  const pdfFullText = await pdfText(pdfFull);
  check('pdf: full coverage keeps old wording, no INCONCLUSIVE',
    pdfFullText.includes('No findings were identified during this scan.') &&
      !pdfFullText.includes('INCONCLUSIVE'),
    pdfFullText.slice(0, 300));

  const pdfNoCoverage = await generatePdfReport({ scan, findings: [], generatedBy: 'test' });
  check('pdf: no coverage data is INCONCLUSIVE',
    (await pdfText(pdfNoCoverage)).includes('INCONCLUSIVE'));

  const docxPartial = await generateDocxReport({ scan, findings: [], generatedBy: 'test', coverage: partialSummary });
  const docxPartialText = await docxText(docxPartial);
  check('docx: partial coverage says INCONCLUSIVE',
    docxPartialText.includes('INCONCLUSIVE') && docxPartialText.includes('Unexamined is not clean'));

  const docxFull = await generateDocxReport({ scan, findings: [], generatedBy: 'test', coverage: fullSummary });
  const docxFullText = await docxText(docxFull);
  check('docx: full coverage keeps old wording, no INCONCLUSIVE',
    docxFullText.includes('No findings were identified during this scan.') &&
      !docxFullText.includes('INCONCLUSIVE'));

  const docxNoCoverage = await generateDocxReport({ scan, findings: [], generatedBy: 'test' });
  check('docx: no coverage data is INCONCLUSIVE',
    (await docxText(docxNoCoverage)).includes('INCONCLUSIVE'));

  const docxWithFindings = await generateDocxReport({
    scan,
    findings: [mkFinding()],
    generatedBy: 'test',
    coverage: partialSummary,
  });
  check('docx: findings present, no INCONCLUSIVE anywhere',
    !(await docxText(docxWithFindings)).includes('INCONCLUSIVE'));

  // --- JSON structured field ---
  const jsonPartial = buildJsonReport({ scan, findings: [], generatedBy: 'test', coverage: partialSummary });
  check('json: partial sets the inconclusive flag',
    jsonPartial.coverage.inconclusive === true && jsonPartial.coverage.tier === 'partial',
    jsonPartial.coverage);
  check('json: partial lists untested classes',
    jsonPartial.coverage.untestedClasses.join(',') === 'auth,graphql,sourcemap,general');

  const jsonFull = buildJsonReport({ scan, findings: [], generatedBy: 'test', coverage: fullSummary });
  check('json: full clears the flag',
    jsonFull.coverage.inconclusive === false && jsonFull.coverage.tier === 'high');

  const jsonNoCoverage = buildJsonReport({ scan, findings: [], generatedBy: 'test' });
  check('json: no coverage data flags inconclusive at the lowest tier',
    jsonNoCoverage.coverage.inconclusive === true && jsonNoCoverage.coverage.tier === 'none');

  const jsonWithFindings = buildJsonReport({
    scan,
    findings: [mkFinding()],
    generatedBy: 'test',
    coverage: partialSummary,
  });
  check('json: findings present clears the flag',
    jsonWithFindings.coverage.inconclusive === false);

  // --- Swarm renderer: errors / no tests make zero findings inconclusive ---
  const swarmClean = renderMarkdownReport({
    targetUrl: 'https://example.com',
    findings: [],
    workerReports: [
      {
        specialistId: 'headers', specialistName: 'Headers', summary: 'ok', findings: [],
        testsRun: 3, testsPlanned: 3, escalations: 0, llmCalls: 0,
        tokensUsed: { input: 0, output: 0 }, errors: [], durationMs: 1, notes: [],
      },
    ],
    headSummary: 'done',
    testsRun: 3,
    llmCalls: 0,
    tokensUsed: { input: 0, output: 0 },
    durationMs: 10,
    errors: [],
  });
  check('swarm: clean run keeps the old wording',
    swarmClean.includes('No findings. The swarm found nothing worth reporting') &&
      !swarmClean.includes('INCONCLUSIVE'));

  const swarmErrored = renderMarkdownReport({
    targetUrl: 'https://example.com',
    findings: [],
    workerReports: [
      {
        specialistId: 'headers', specialistName: 'Headers', summary: 'crashed', findings: [],
        testsRun: 0, testsPlanned: 3, escalations: 0, llmCalls: 0,
        tokensUsed: { input: 0, output: 0 }, errors: ['worker crashed'], durationMs: 1, notes: [],
      },
    ],
    headSummary: 'done',
    testsRun: 0,
    llmCalls: 0,
    tokensUsed: { input: 0, output: 0 },
    durationMs: 10,
    errors: ['headers crashed'],
  });
  check('swarm: errored run says INCONCLUSIVE',
    swarmErrored.includes('INCONCLUSIVE') && swarmErrored.includes('Unexamined is not clean'));

  // --- Route: coverage reaches the report through the scan's task ---
  const db = new MemoryDatabase();
  const graph = new MemoryGraphStore();
  const coverage = new MemoryCoverageStore();
  const user = await db.createUser('hunter@example.com', 'x');
  await db.setUserPlan(user.id, 'hunter');

  const mkCompletedScan = async () => {
    const s = await db.createScan({
      userId: user.id,
      targetUrl: 'https://example.com',
      mode: 'active',
      scope: scan.scope,
    });
    await db.updateScan(s.id, { status: 'completed', finishedAt: '2026-11-23T10:05:00.000Z' });
    return s;
  };

  const partialScan = await mkCompletedScan();
  const partialTask = await graph.createTask({
    userId: user.id,
    goalText: 'test',
    targetUrl: 'https://example.com',
    scanId: partialScan.id,
  });
  for (const e of entriesFor(['recon', 'secrets', 'headers', 'cors', 'xss', 'idor'])) {
    await coverage.recordEntry({ ...e, taskId: partialTask.id });
  }

  const fullScan = await mkCompletedScan();
  const fullTask = await graph.createTask({
    userId: user.id,
    goalText: 'test',
    targetUrl: 'https://example.com',
    scanId: fullScan.id,
  });
  for (const e of entriesFor([...RISK_CLASSES])) {
    await coverage.recordEntry({ ...e, taskId: fullTask.id });
  }

  const bareScan = await mkCompletedScan();

  const app = Fastify();
  await app.register(async (instance) => {
    await reportRoutes(instance, { db, queue: {}, provider: {}, graph, coverage } as never);
  });
  await app.ready();
  const token = generateSessionToken();
  await db.createSession(user.id, hashSessionToken(token), new Date(Date.now() + 3600_000).toISOString());
  const cookie = `bs_session=${token}`;

  const partialMd = await app.inject({
    method: 'GET',
    url: `/api/scans/${partialScan.id}/report?format=md`,
    headers: { cookie },
  });
  check('route: partial task coverage makes the md report INCONCLUSIVE',
    partialMd.statusCode === 200 && partialMd.body.includes('INCONCLUSIVE'),
    partialMd.statusCode);

  const fullMd = await app.inject({
    method: 'GET',
    url: `/api/scans/${fullScan.id}/report?format=md`,
    headers: { cookie },
  });
  check('route: full task coverage keeps the old wording',
    fullMd.statusCode === 200 &&
      fullMd.body.includes('No findings were identified during this scan.') &&
      !fullMd.body.includes('INCONCLUSIVE'),
    fullMd.statusCode);

  const bareMd = await app.inject({
    method: 'GET',
    url: `/api/scans/${bareScan.id}/report?format=md`,
    headers: { cookie },
  });
  check('route: scan with no task is INCONCLUSIVE, never clean',
    bareMd.statusCode === 200 && bareMd.body.includes('INCONCLUSIVE'),
    bareMd.statusCode);

  const partialJson = await app.inject({
    method: 'GET',
    url: `/api/scans/${partialScan.id}/report?format=json`,
    headers: { cookie },
  });
  const partialDoc = JSON.parse(partialJson.body);
  check('route: json report carries the inconclusive flag',
    partialJson.statusCode === 200 &&
      partialDoc.coverage.inconclusive === true &&
      partialDoc.coverage.tier === 'partial',
    partialDoc.coverage);

  await app.close();
  await db.close();

  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log('\nAll coverage honesty tests passed.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

/* Code-intake route + analyser tests — no live network, no disk writes:
   archives are built in memory with JSZip, the route runs against the
   in-memory DB with a real session cookie. Covers the ZIP source scan
   (secrets + dangerous APIs), the JAR constant-pool scan (explicitly NOT
   decompilation), auth, size/magic validation, and the White-box report
   section in all three generators. */
import Fastify from 'fastify';
import JSZip from 'jszip';
import { MemoryDatabase } from '../src/db/db.js';
import { codeIntakeRoutes } from '../src/routes/codeIntake.js';
import { analyzeCodeArchive } from '../src/codeIntake/analyzer.js';
import { generateSessionToken, hashSessionToken } from '../src/auth/session.js';
import { generateMarkdownReport } from '../src/reports/markdown.js';
import { generatePdfReport } from '../src/reports/pdf.js';
import { generateDocxReport } from '../src/reports/docx.js';
import { splitWhiteBoxFindings } from '../src/reports/whitebox.js';

let failures = 0;
function check(name: string, ok: boolean, extra?: unknown) {
  if (ok) console.log('PASS', name);
  else {
    failures++;
    console.error('FAIL', name, extra ?? '');
  }
}

async function buildZip(files: Record<string, string | Buffer>): Promise<Buffer> {
  const zip = new JSZip();
  for (const [name, content] of Object.entries(files)) zip.file(name, content);
  return zip.generateAsync({ type: 'nodebuffer' });
}

async function main() {
  process.env['ADMIN_EMAIL'] = 'op@example.com';
  const db = new MemoryDatabase();
  const user = await db.createUser('op@example.com', 'unused-hash');
  const token = generateSessionToken();
  await db.createSession(
    user.id,
    hashSessionToken(token),
    new Date(Date.now() + 3600_000).toISOString(),
  );
  const cookie = `bs_session=${token}`;

  const app = Fastify();
  const deps = { db, queue: {} as never, provider: {} as never, orchestrator: {} as never };
  await codeIntakeRoutes(app as never, deps);

  const post = (url: string, payload: Buffer, headers: Record<string, string> = {}) =>
    app.inject({ method: 'POST', url, payload, headers: { cookie, ...headers } });

  /* ── analyser: ZIP source scan ─────────────────────────────── */
  const zipBuf = await buildZip({
    'src/app.js': `const key = "AKIAABCDEFGHIJ123456";\nconst q = location.search;\nfetch('/api?u=' + q);\neval(userInput);\n`,
    'src/util.py': `import pickle\npickle.loads(data)\n`,
    'README.md': 'nothing secret here\n',
  });
  const zipResult = await analyzeCodeArchive(zipBuf, 'zip', 'repo.zip');
  check('zip: scans js + py, skips md', zipResult.filesScanned === 2 && zipResult.entriesSkipped === 1, zipResult);
  check('zip: finds AWS key', zipResult.findings.some((f) => f.title.includes('AWS access key')), zipResult.findings.map((f) => f.title));
  check('zip: finds eval()', zipResult.findings.some((f) => f.title.includes('eval')), zipResult.findings.map((f) => f.title));
  check('zip: finds pickle.loads', zipResult.findings.some((f) => f.title.includes('pickle')), zipResult.findings.map((f) => f.title));
  check('zip: no secret value in evidence', !zipResult.findings.some((f) => (f.evidence ?? '').includes('AKIAABCDEFGHIJ123456')), zipResult.findings);
  check('zip: method note is honest', zipResult.method.includes('Static regex scan'), zipResult.method);

  /* ── analyser: JAR constant-pool scan ──────────────────────── */
  // A fake .class file: not a real class, just bytes carrying the same
  // constant-pool strings a real class would (the scanner reads strings,
  // it does not parse the class format — that IS the documented limit).
  const fakeClass = Buffer.from(
    'cafebabe junk java/lang/Runtime exec (Ljava/lang/String;)Ljava/lang/Process; ' +
      'jdbc:mysql://db.internal:3306/app?user=root&password=hunter2 ' +
      'AKIAABCDEFGHIJ123456 tail',
    'latin1',
  );
  const jarBuf = await buildZip({
    'com/example/App.class': fakeClass,
    'META-INF/MANIFEST.MF': 'Manifest-Version: 1.0\n',
    'application.properties': 'spring.datasource.password=hunter2secret\n',
  });
  const jarResult = await analyzeCodeArchive(jarBuf, 'jar', 'app.jar');
  check('jar: scans class + manifest + properties', jarResult.filesScanned === 3, jarResult);
  check('jar: flags Runtime reference', jarResult.findings.some((f) => f.title.includes('Runtime')), jarResult.findings.map((f) => f.title));
  check('jar: flags JDBC credentials', jarResult.findings.some((f) => f.title.includes('JDBC')), jarResult.findings.map((f) => f.title));
  check('jar: flags AWS key in class strings', jarResult.findings.some((f) => f.title.includes('AWS access key')), jarResult.findings.map((f) => f.title));
  check('jar: method says NOT decompilation', jarResult.method.includes('NOT decompilation'), jarResult.method);

  /* ── analyser: empty archive rejected ──────────────────────── */
  let emptyThrew = false;
  try {
    await analyzeCodeArchive(await buildZip({}), 'zip', 'empty.zip');
  } catch {
    emptyThrew = true;
  }
  check('analyser: empty archive throws', emptyThrew);

  /* ── route: auth + validation ──────────────────────────────── */
  const anon = await app.inject({
    method: 'POST',
    url: '/api/code-intake?kind=zip&filename=repo.zip',
    payload: zipBuf,
    headers: { 'content-type': 'application/zip' },
  });
  check('route: no session → 401', anon.statusCode === 401, anon.statusCode);

  const notZip = await post('/api/code-intake?kind=zip&filename=x.zip', Buffer.from('hello world'), {
    'content-type': 'application/zip',
  });
  check('route: non-ZIP body → 400', notZip.statusCode === 400, notZip.statusCode);

  const badName = await post('/api/code-intake?kind=zip&filename=../evil.zip', zipBuf, {
    'content-type': 'application/zip',
  });
  check('route: path-traversal filename → 400', badName.statusCode === 400, badName.statusCode);

  /* ── route: happy path ZIP ─────────────────────────────────── */
  const okZip = await post('/api/code-intake?kind=zip&filename=repo.zip', zipBuf, {
    'content-type': 'application/zip',
  });
  check('route: ZIP upload → 200', okZip.statusCode === 200, okZip.statusCode);
  const okZipBody = okZip.json() as { scanId: string; findings: Array<{ category: string; title: string }>; filesScanned: number; score: unknown };
  check('route: findings persisted as whitebox', okZipBody.findings.length >= 3 && okZipBody.findings.every((f) => f.category === 'whitebox'), okZipBody);
  check('route: filesScanned reported', okZipBody.filesScanned === 2, okZipBody);

  /* ── route: happy path JAR ─────────────────────────────────── */
  const okJar = await post('/api/code-intake?kind=jar&filename=app.jar', jarBuf, {
    'content-type': 'application/java-archive',
  });
  check('route: JAR upload → 200', okJar.statusCode === 200, okJar.statusCode);
  const okJarBody = okJar.json() as { findings: Array<{ title: string }>; method: string };
  check('route: JAR method note survives', okJarBody.method.includes('NOT decompilation'), okJarBody.method);

  /* ── reports: White-box section ────────────────────────────── */
  const scan = await db.createScan({
    userId: user.id,
    targetUrl: 'code-intake:repo.zip',
    mode: 'passive',
    scope: { mode: 'page', includeSubdomains: false, excludedHosts: [], excludedPaths: [], maxRequestsPerSecond: 1 },
    techStack: [],
  });
  const wb = await db.addFinding({
    scanId: scan.id,
    category: 'whitebox',
    title: 'AWS access key ID in src/app.js',
    description: 'A hardcoded AWS access key ID was found in uploaded code.',
    severity: 'critical',
    confidence: 'high',
    cvssScore: 9.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N',
    trapProbability: 0,
    honeypotSuspect: false,
    location: 'src/app.js',
    evidence: '[REDACTED:aws-key]',
    reproSteps: [],
    remediation: 'Rotate the key.',
    references: [],
  });
  const live = await db.addFinding({
    scanId: scan.id,
    category: 'headers',
    title: 'Missing security header',
    description: 'X-Content-Type-Options is missing.',
    severity: 'low',
    confidence: 'high',
    trapProbability: 0,
    honeypotSuspect: false,
    reproSteps: [],
    remediation: 'Add the header.',
    references: [],
  });
  const findings = [wb, live];
  const split = splitWhiteBoxFindings(findings);
  check('whitebox: split isolates category', split.whiteBox.length === 1 && split.rest.length === 1, split);

  const md = generateMarkdownReport({ scan, findings, generatedBy: 'test' });
  check('md: White-box section present', md.includes('## White-box analysis'), md.slice(0, 400));
  check('md: method note present', md.includes('constant-pool string scans'), md);
  check('md: white-box finding listed once', md.split('AWS access key ID in src/app.js').length - 1 === 1, md);
  check('md: live finding still in Findings', md.includes('Missing security header'), md);

  const pdf = await generatePdfReport({ scan, findings, generatedBy: 'test' });
  check('pdf: generates non-empty buffer', pdf.length > 1000, pdf.length);

  const docx = await generateDocxReport({ scan, findings, generatedBy: 'test' });
  check('docx: generates non-empty buffer', docx.length > 1000, docx.length);

  console.log(failures === 0 ? 'ALL PASS' : `${failures} FAILURES`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

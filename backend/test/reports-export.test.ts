/* CSV/JSON findings export tests. No live network:
   unit tests for the formula-injection guard and CSV quoting, JSON shape
   against the Markdown report's fields, and route tests (plan gating,
   headers, auth, ownership, completed-only) via Fastify inject with a
   MemoryDatabase and a real session cookie. */
async function main() {
  const { generateCsvReport, escapeCsvCell, csvCell, CSV_HEADERS } = await import(
    '../src/reports/csv.js'
  );
  const { generateJsonReport, buildJsonReport } = await import('../src/reports/json.js');
  const { generateMarkdownReport } = await import('../src/reports/markdown.js');
  const { MemoryDatabase } = await import('../src/db/db.js');
  const { generateSessionToken, hashSessionToken } = await import('../src/auth/session.js');
  const { reportRoutes } = await import('../src/routes/reports.js');
  const Fastify = (await import('fastify')).default;

  let failures = 0;
  const check = (name: string, ok: boolean, extra?: unknown) => {
    console.log(`${ok ? 'PASS' : 'FAIL'} ${name}`);
    if (!ok) {
      failures++;
      if (extra !== undefined) console.log('     →', extra);
    }
  };

  // Minimal RFC 4180 parser, only used to verify CSV round-trips.
  const parseCsv = (text: string): string[][] => {
    const rows: string[][] = [];
    let row: string[] = [];
    let cell = '';
    let inQuotes = false;
    const body = text.replace(/^\uFEFF/, '');
    for (let i = 0; i < body.length; i++) {
      const c = body[i];
      if (inQuotes) {
        if (c === '"') {
          if (body[i + 1] === '"') { cell += '"'; i++; }
          else inQuotes = false;
        } else cell += c;
      } else if (c === '"') inQuotes = true;
      else if (c === ',') { row.push(cell); cell = ''; }
      else if (c === '\r') { /* \r\n handled by \n below */ }
      else if (c === '\n') { row.push(cell); cell = ''; rows.push(row); row = []; }
      else cell += c;
    }
    if (cell !== '' || row.length > 0) { row.push(cell); rows.push(row); }
    return rows;
  };

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

  const mkFinding = (over: Record<string, unknown>) => ({
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

  const input = {
    scan,
    findings: [
      mkFinding({ id: 'f-1', severity: 'medium' }),
      mkFinding({
        id: 'f-2',
        title: '=2+2',
        severity: 'critical',
        cvssScore: 9.1,
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        location: 'https://example.com/admin',
        evidence: 'a,b "quoted"\nnewline',
        references: ['https://example.com/ref', 'https://example.com/ref2'],
        reproSteps: ['step one', 'step two'],
      }),
    ],
    generatedBy: 'test',
  };

  // --- Formula-injection guard ---
  check('formula: = leader is quoted', escapeCsvCell('=2+2') === "'=2+2", escapeCsvCell('=2+2'));
  check('formula: + leader is quoted', escapeCsvCell('+2+2') === "'+2+2");
  check('formula: - leader is quoted', escapeCsvCell('-2+2') === "'-2+2");
  check('formula: @ leader is quoted', escapeCsvCell('@SUM(A1:A2)') === "'@SUM(A1:A2)");
  check('formula: leading tab is quoted', escapeCsvCell('\t=2+2') === "'=2+2");
  check('formula: leading CR is quoted', escapeCsvCell('\r=2+2') === "'=2+2");
  check('formula: leading tab before benign text is quoted', escapeCsvCell('\tfoo') === "'\tfoo");
  check('formula: leading CR before benign text is quoted', escapeCsvCell('\rfoo') === "'\rfoo");
  check('formula: spaces before = are trimmed then quoted', escapeCsvCell('   =cmd') === "'=cmd");
  check('formula: benign digit lead is untouched', escapeCsvCell('12345') === '12345');
  check('formula: benign letter lead is untouched', escapeCsvCell('abc') === 'abc');
  check('formula: empty cell stays empty', escapeCsvCell('') === '');
  check('formula: = mid-string is untouched', escapeCsvCell('a=b') === 'a=b');

  // --- CSV quoting + round-trip ---
  check('quoting: comma forces quotes', csvCell('a,b') === '"a,b"');
  check('quoting: embedded quote is doubled', csvCell('say "hi"') === '"say ""hi"""');
  check('quoting: newline forces quotes', csvCell('line1\nline2') === '"line1\nline2"');
  check('quoting: plain cell is bare', csvCell('plain') === 'plain');

  const csv = generateCsvReport(input);
  check('csv: starts with UTF-8 BOM', csv.charCodeAt(0) === 0xfeff);
  const rows = parseCsv(csv);
  check('csv: header row matches declared headers', rows[0].join(',') === CSV_HEADERS.join(','));
  check('csv: one row per finding plus header', rows.length === 3, rows.length);
  // Sorted by severity: critical (f-2) first.
  const critical = rows[1];
  const titleIdx = CSV_HEADERS.indexOf('title');
  const evidenceIdx = CSV_HEADERS.indexOf('evidence');
  const refsIdx = CSV_HEADERS.indexOf('references');
  const stepsIdx = CSV_HEADERS.indexOf('repro_steps');
  check('csv: critical finding sorts first', critical[CSV_HEADERS.indexOf('id')] === 'f-2');
  check('csv: formula title round-trips guarded', critical[titleIdx] === "'=2+2", critical[titleIdx]);
  check('csv: comma/quote/newline evidence round-trips', critical[evidenceIdx] === 'a,b "quoted"\nnewline');
  check('csv: references joined with "; "', critical[refsIdx] === 'https://example.com/ref; https://example.com/ref2');
  check('csv: repro steps joined with "; "', critical[stepsIdx] === 'step one; step two');
  check('csv: cvss score present', critical[CSV_HEADERS.indexOf('cvss_score')] === '9.1');
  check('csv: raw output has no unguarded formula cell', !/(^|,)="2\+2"/.test(csv) && !/(^|,)=2\+2/.test(csv));

  // --- JSON shape ---
  const jsonText = generateJsonReport(input);
  check('json: pretty-printed (indented)', jsonText.includes('\n  "scan"'));
  const doc = JSON.parse(jsonText);
  check('json: findings array present', Array.isArray(doc.findings) && doc.findings.length === 2);
  check('json: scan metadata present', doc.scan.id === scan.id && doc.scan.targetUrl === 'https://example.com');
  check('json: summary totals match', doc.summary.total === 2 && doc.summary.bySeverity.critical === 1);
  const jf = doc.findings[0];
  check('json: finding fields match Markdown report fields',
    jf.title === '=2+2' && jf.severity === 'critical' && jf.cvssScore === 9.1 &&
    jf.cvssVector === 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' &&
    jf.location === 'https://example.com/admin' && jf.evidence === 'a,b "quoted"\nnewline' &&
    typeof jf.verification === 'string' && jf.verification.length > 0 &&
    jf.honeypotSuspect === false && Array.isArray(jf.references) && Array.isArray(jf.reproSteps));
  check('json: builder and generator agree', JSON.stringify(buildJsonReport(input).findings) === JSON.stringify(doc.findings));

  // Markdown uses the same fields, spot-check the shared surface.
  const md = generateMarkdownReport(input);
  check('md: same title/severity/cvss shown', md.includes('=2+2') && md.includes('CRITICAL') && md.includes('9.1'));

  // --- Routes: plan gating, headers, auth, ownership, completed-only ---
  const db = new MemoryDatabase();
  const freeUser = await db.createUser('free@example.com', 'x');
  const hunterUser = await db.createUser('hunter@example.com', 'x');
  await db.setUserPlan(hunterUser.id, 'hunter');
  const hunterScan = await db.createScan({
    userId: hunterUser.id,
    targetUrl: 'https://example.com',
    mode: 'active',
    scope: scan.scope,
  });
  await db.updateScan(hunterScan.id, { status: 'completed', finishedAt: '2026-11-23T10:05:00.000Z' });
  await db.addFinding(mkFinding({ scanId: hunterScan.id, id: undefined, title: '=2+2' }) as never);
  // Free-plan user needs their own completed scan: json is gated by
  // ownership as well as plan, and the hunter's scan is not theirs.
  const freeScan = await db.createScan({
    userId: freeUser.id,
    targetUrl: 'https://example.com',
    mode: 'passive',
    scope: scan.scope,
  });
  await db.updateScan(freeScan.id, { status: 'completed', finishedAt: '2026-11-23T10:05:00.000Z' });
  await db.addFinding(mkFinding({ scanId: freeScan.id, id: undefined, title: 'Missing CSP header' }) as never);
  const queuedScan = await db.createScan({
    userId: hunterUser.id,
    targetUrl: 'https://example.com',
    mode: 'passive',
    scope: scan.scope,
  });

  const app = Fastify();
  await app.register(async (instance) => {
    await reportRoutes(instance, { db, queue: {}, provider: {} } as never);
  });
  await app.ready();

  const cookieFor = async (userId: string) => {
    const token = generateSessionToken();
    await db.createSession(userId, hashSessionToken(token), new Date(Date.now() + 3600_000).toISOString());
    return `bs_session=${token}`;
  };
  const hunterCookie = await cookieFor(hunterUser.id);
  const freeCookie = await cookieFor(freeUser.id);

  const unauth = await app.inject({ method: 'GET', url: `/api/scans/${hunterScan.id}/report?format=csv` });
  check('route: csv without auth is 401', unauth.statusCode === 401, unauth.statusCode);

  const freeCsv = await app.inject({
    method: 'GET',
    url: `/api/scans/${hunterScan.id}/report?format=csv`,
    headers: { cookie: freeCookie },
  });
  check('route: free plan csv is 403', freeCsv.statusCode === 403, freeCsv.statusCode);

  const csvRes = await app.inject({
    method: 'GET',
    url: `/api/scans/${hunterScan.id}/report?format=csv`,
    headers: { cookie: hunterCookie },
  });
  check('route: hunter csv is 200', csvRes.statusCode === 200, csvRes.statusCode);
  check('route: csv content-type is text/csv', (csvRes.headers['content-type'] ?? '').startsWith('text/csv'), csvRes.headers['content-type']);
  check('route: csv content-disposition is an attachment .csv',
    (csvRes.headers['content-disposition'] ?? '').includes('attachment') &&
    (csvRes.headers['content-disposition'] ?? '').includes('.csv'));
  check('route: csv body starts with BOM and guarded title',
    csvRes.body.charCodeAt(0) === 0xfeff && csvRes.body.includes("'=2+2"), csvRes.body.slice(0, 120));

  const jsonRes = await app.inject({
    method: 'GET',
    url: `/api/scans/${freeScan.id}/report?format=json`,
    headers: { cookie: freeCookie },
  });
  check('route: free plan json is 200 (existing gating)', jsonRes.statusCode === 200, jsonRes.statusCode);
  check('route: json content-type is application/json',
    (jsonRes.headers['content-type'] ?? '').startsWith('application/json'), jsonRes.headers['content-type']);
  check('route: json body is pretty-printed with findings array',
    jsonRes.body.includes('\n  "findings"') && JSON.parse(jsonRes.body).findings.length === 1);

  const badFormat = await app.inject({
    method: 'GET',
    url: `/api/scans/${hunterScan.id}/report?format=xlsx`,
    headers: { cookie: hunterCookie },
  });
  check('route: unknown format is 400', badFormat.statusCode === 400, badFormat.statusCode);

  const queued = await app.inject({
    method: 'GET',
    url: `/api/scans/${queuedScan.id}/report?format=csv`,
    headers: { cookie: hunterCookie },
  });
  check('route: non-completed scan is 409', queued.statusCode === 409, queued.statusCode);

  const missing = await app.inject({
    method: 'GET',
    url: '/api/scans/no-such-scan/report?format=csv',
    headers: { cookie: hunterCookie },
  });
  check('route: unknown scan is 404', missing.statusCode === 404, missing.statusCode);

  await app.close();
  await db.close();

  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log('\nAll report export tests passed.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

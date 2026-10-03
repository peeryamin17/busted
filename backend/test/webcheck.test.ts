/* Web demo patrol tests — no live network, DNS or TLS anywhere:
   the guard gets an injected resolver, the checks module gets crafted
   snapshots, and the routes get a fixture patrol runner. Covers the
   SSRF guard, the redaction rules, the plan gate (withheld finding
   text must not appear ANYWHERE in a free-plan response), auth, the
   authorisation tick, per-user throttling and run ownership. */
async function main() {
  const { MemoryDatabase } = await import('../src/db/db.js');
  const { webCheckRoutes } = await import('../src/routes/webcheck.js');
  const { generateSessionToken, hashSessionToken } = await import('../src/auth/session.js');
  const {
    assertPublicUrl,
    isPrivateAddress,
    resolvePublicHost,
  } = await import('../src/webcheck/guard.js');
  const { analyseWebCheck } = await import('../src/webcheck/checks.js');
  const Fastify = (await import('fastify')).default;

  let failures = 0;
  const check = (name: string, ok: boolean, extra?: unknown) => {
    console.log(`${ok ? 'PASS' : 'FAIL'} ${name}`);
    if (!ok) {
      failures++;
      if (extra !== undefined) console.log('     →', extra);
    }
  };
  const throwsWith = (fn: () => unknown, needle: string) => {
    try {
      fn();
      return false;
    } catch (err) {
      return (err as Error).message.includes(needle);
    }
  };
  const rejectsWith = async (p: Promise<unknown>, needle: string) => {
    try {
      await p;
      return false;
    } catch (err) {
      return (err as Error).message.includes(needle);
    }
  };

  /* ── the SSRF guard ─────────────────────────────────────────── */
  const privates: Array<[string, boolean]> = [
    ['127.0.0.1', true], ['10.1.2.3', true], ['172.16.0.1', true],
    ['172.31.255.255', true], ['172.32.0.1', false], ['192.168.1.1', true],
    ['169.254.10.10', true], ['0.0.0.0', true], ['8.8.8.8', false],
    ['1.1.1.1', false], ['::1', true], ['fe80::1', true], ['febf::1', true],
    ['fc00::1', true], ['fd12::1', true], ['2001:4860:4860::8888', false],
    ['::ffff:127.0.0.1', true], ['::ffff:8.8.8.8', false], ['::ffff:7f00:1', true],
  ];
  for (const [ip, expected] of privates) {
    check(`isPrivateAddress(${ip}) === ${expected}`, isPrivateAddress(ip) === expected);
  }

  check('assertPublicUrl refuses ftp://', throwsWith(() => assertPublicUrl('ftp://example.com'), 'http(s)'));
  check(
    'assertPublicUrl refuses embedded credentials',
    throwsWith(() => assertPublicUrl('https://user:pass@example.com'), 'credentials'),
  );
  check('assertPublicUrl refuses garbage', throwsWith(() => assertPublicUrl('not a url'), 'URL'));
  check('assertPublicUrl accepts https', assertPublicUrl('https://example.com/x').hostname === 'example.com');

  const publicResolver = async () => [{ address: '93.184.216.34', family: 4 }];
  const mixedResolver = async () => [
    { address: '93.184.216.34', family: 4 },
    { address: '10.0.0.9', family: 4 },
  ];
  check(
    'resolvePublicHost accepts an all-public answer set',
    (await resolvePublicHost('example.com', publicResolver)).length === 1,
  );
  check(
    'resolvePublicHost refuses when ANY answer is private',
    await rejectsWith(resolvePublicHost('sneaky.example', mixedResolver), 'private'),
  );
  check(
    'resolvePublicHost refuses a private literal',
    await rejectsWith(resolvePublicHost('192.168.0.1', publicResolver), 'private'),
  );

  /* ── the checks module over crafted snapshots ───────────────── */
  const SECRET_VALUE = 's3cret-cookie-value';
  const AWS_DOCS_KEY = 'AKIAIOSFODNN7EXAMPLE'; // AWS's public documentation example — not a credential
  const { findings, api } = analyseWebCheck({
    page: {
      finalUrl: 'https://shop.example/',
      status: 200,
      headers: { server: 'nginx/1.24.0' },
      setCookie: [
        `session_id=${SECRET_VALUE}; Path=/; Expires=Wed, 01 Jan 2031 00:00:00 GMT`,
      ],
      body: '<html><head><script src="/app.js"></script></head><body><img src="http://cdn.example/x.png"></body></html>',
    },
    probes: {
      env: { path: '/.env', status: 200, body: 'DB_HOST=db.internal\nDB_PASS=hunter2-secret\n' },
      gitHead: { path: '/.git/HEAD', status: 200, body: 'ref: refs/heads/main\n' },
      gitConfig: null,
      backupSql: null,
      svnEntries: null,
      robots: null,
    },
    scripts: [
      {
        url: 'https://shop.example/app.js',
        body: `const K = "${AWS_DOCS_KEY}"; fetch("/api/users"); const gql = "/graphql";`,
      },
    ],
    sourceMaps: [{ scriptUrl: 'https://shop.example/app.js', mapUrl: 'https://shop.example/app.js.map' }],
    apiDocUrl: 'https://shop.example/openapi.json',
    tls: {
      issuer: "Let's Encrypt",
      subject: 'shop.example',
      validTo: null,
      daysLeft: 90,
      authorized: true,
      protocol: 'TLSv1.3',
    },
  });

  const titles = findings.map((f) => f.title).join('\n');
  const findingsJson = JSON.stringify(findings);
  check('critical sorts first', findings[0]?.severity === 'critical', findings[0]);
  check('.env exposure fires as critical', titles.includes('/.env is publicly readable'));
  check('.env evidence names keys only', findingsJson.includes('DB_HOST') && findingsJson.includes('DB_PASS'));
  check('.env value never appears anywhere', !findingsJson.includes('hunter2-secret'));
  check('.git/HEAD exposure fires', titles.includes('Git repository exposed'));
  check('missing CSP fires', titles.includes('No Content-Security-Policy'));
  check('missing HSTS fires', titles.includes('No HSTS header'));
  check('server banner with version fires', titles.includes('advertises the stack'));
  check('session cookie without HttpOnly fires', titles.includes('readable by JavaScript'));
  check('cookie without Secure fires', titles.includes('without Secure'));
  check('cookie without SameSite fires', titles.includes('no SameSite'));
  check('long-lived cookie fires', /lives for \d+ days/.test(titles));
  check('cookie VALUE never appears anywhere', !findingsJson.includes(SECRET_VALUE));
  check('source map finding fires', titles.includes('Source map ships the original source'));
  check('mixed content fires', titles.includes('Mixed content'));
  check('public API doc fires', titles.includes('API documentation is publicly readable'));
  check('AWS key in JS fires by type', titles.includes('AWS access key in shipped JavaScript'));
  check('the matched secret string never appears', !findingsJson.includes(AWS_DOCS_KEY));
  check('API endpoints inventoried', api.endpoints.includes('/api/users'), api);
  check('GraphQL surface noted', api.graphql === true);
  check('openApiDoc noted', api.openApiDoc === true);

  /* ── the routes: gate, auth, tick, throttle, ownership ──────── */
  const db = new MemoryDatabase();
  const deps = { db, queue: {} as never, provider: {} as never };

  const FIXTURE_FINDINGS = [
    { severity: 'critical' as const, category: 'files', title: 'AAA first full finding', detail: 'detail one', confidence: 'high' as const, evidence: 'keys seen: DB_HOST' },
    { severity: 'high' as const, category: 'headers', title: 'BBB second full finding', detail: 'detail two', confidence: 'high' as const },
    { severity: 'medium' as const, category: 'cookies', title: 'CCC WITHHELD TITLE', detail: 'withheld detail', confidence: 'medium' as const },
    { severity: 'low' as const, category: 'tech', title: 'DDD WITHHELD TITLE', detail: 'withheld detail', confidence: 'low' as const },
  ];
  const FIXTURE_INFO = {
    perf: { ttfbMs: 42, totalMs: 120, bytes: 1024, redirectCount: 0, compression: 'gzip', scripts: 1, styles: 1, images: 2, htmlBytes: 900 },
    server: { ip: '93.184.216.34', country: 'United States', city: 'Norwell', region: 'Massachusetts', org: 'Example ISP' },
    domain: { registrar: 'Example Registrar', created: '2020-01-01T00:00:00Z', expires: '2030-01-01T00:00:00Z', daysLeft: 1000, status: ['ok'], nameservers: ['ns1.example'] },
    dns: { a: ['93.184.216.34'], aaaa: [], mx: ['mail.example'], ns: ['ns1.example'], spf: true, dmarc: false, caa: false },
    tls: null,
    api: { endpoints: ['/api/users'], openApiDoc: false, graphql: false },
    robotsTxt: true,
    securityTxt: false,
  };

  const app = Fastify();
  await webCheckRoutes(app as never, deps, {
    patrol: async () => ({
      url: 'https://demo.example/',
      host: 'demo.example',
      findings: FIXTURE_FINDINGS,
      info: FIXTURE_INFO,
    }),
  });

  const makeCookie = async (email: string) => {
    const user = await db.createUser(email, 'hash');
    const token = generateSessionToken();
    await db.createSession(
      user.id,
      hashSessionToken(token),
      new Date(Date.now() + 3_600_000).toISOString(),
    );
    return { user, cookie: `bs_session=${token}` };
  };

  const signedOut = await app.inject({ method: 'POST', url: '/api/webcheck', payload: { url: 'https://demo.example', authorized: true } });
  check('signed-out POST → 401', signedOut.statusCode === 401, signedOut.statusCode);

  const alice = await makeCookie('alice@example.com');

  const noTick = await app.inject({
    method: 'POST',
    url: '/api/webcheck',
    headers: { cookie: alice.cookie },
    payload: { url: 'https://demo.example', authorized: false },
  });
  check('missing authorisation tick → 400', noTick.statusCode === 400, noTick.statusCode);

  const created = await app.inject({
    method: 'POST',
    url: '/api/webcheck',
    headers: { cookie: alice.cookie },
    payload: { url: 'https://demo.example', authorized: true },
  });
  check('happy path → 201', created.statusCode === 201, created.statusCode);
  const view = created.json() as {
    id: string; gated: boolean; counts: Record<string, number>;
    findings: Array<Record<string, unknown>>; info: unknown; locked: unknown[];
  };
  check('free plan is gated', view.gated === true);
  check('counts cover every severity', view.counts.critical === 1 && view.counts.high === 1 && view.counts.medium === 1 && view.counts.low === 1 && view.counts.info === 0, view.counts);
  check('first finding is full', view.findings[0]?.title === 'AAA first full finding');
  check('second finding is full', view.findings[1]?.title === 'BBB second full finding');
  check(
    'third finding is severity+category ONLY',
    view.findings[2]?.severity === 'medium' &&
      view.findings[2]?.category === 'cookies' &&
      !('title' in (view.findings[2] ?? {})) &&
      !('detail' in (view.findings[2] ?? {})) &&
      !('evidence' in (view.findings[2] ?? {})),
    view.findings[2],
  );
  check('withheld titles leak NOWHERE in the response', !created.body.includes('CCC WITHHELD TITLE') && !created.body.includes('DDD WITHHELD TITLE') && !created.body.includes('withheld detail'), 'response body scan');
  check('locked teaser rows present', Array.isArray(view.locked) && view.locked.length === 2);
  check('the full info matrix rides along', Boolean(view.info));

  const stored = await db.listWebChecks(alice.user.id, 5);
  check('the FULL result is what got stored', stored.length === 1 && stored[0]?.findings.length === 4, stored.length);

  const tooSoon = await app.inject({
    method: 'POST',
    url: '/api/webcheck',
    headers: { cookie: alice.cookie },
    payload: { url: 'https://demo.example', authorized: true },
  });
  check('second patrol inside a minute → 429', tooSoon.statusCode === 429, tooSoon.statusCode);

  const mine = await app.inject({ method: 'GET', url: '/api/webcheck', headers: { cookie: alice.cookie } });
  const mineBody = mine.json() as { runs: Array<{ id: string; findingCount: number }> };
  check('my runs list has the run', mine.statusCode === 200 && mineBody.runs.length === 1 && mineBody.runs[0]?.id === view.id, mine.body);
  check('summary counts findings', mineBody.runs[0]?.findingCount === 4);

  const bob = await makeCookie('bob@example.com');
  const bobsList = await app.inject({ method: 'GET', url: '/api/webcheck', headers: { cookie: bob.cookie } });
  check("another user's list is empty", (bobsList.json() as { runs: unknown[] }).runs.length === 0);
  const bobsPeek = await app.inject({ method: 'GET', url: `/api/webcheck/${view.id}`, headers: { cookie: bob.cookie } });
  check("another user cannot open my run → 404", bobsPeek.statusCode === 404, bobsPeek.statusCode);

  await db.setUserPlan(alice.user.id, 'hunter');
  const unlocked = await app.inject({ method: 'GET', url: `/api/webcheck/${view.id}`, headers: { cookie: alice.cookie } });
  const unlockedBody = unlocked.json() as { gated: boolean; findings: Array<Record<string, unknown>> };
  check('paid plan unblurs the STORED run (no re-scan)', unlocked.statusCode === 200 && unlockedBody.gated === false, unlocked.statusCode);
  check('all findings full after upgrade', unlockedBody.findings.every((f) => typeof f.title === 'string'), unlockedBody.findings.length);
  check('previously withheld title now served', unlocked.body.includes('CCC WITHHELD TITLE'));

  /* ── the origin stamp: stored IP + geo, disclosed, non-fatal ── */
  const stampedPatrol = async () => ({
    url: 'https://demo.example/',
    host: 'demo.example',
    findings: FIXTURE_FINDINGS,
    info: FIXTURE_INFO,
  });

  const app2 = Fastify();
  await webCheckRoutes(app2 as never, deps, {
    patrol: stampedPatrol,
    geo: async () => ({ country: 'India', city: 'Srinagar', region: 'Jammu and Kashmir' }),
  });
  const carol = await makeCookie('carol@example.com');
  const stamped = await app2.inject({
    method: 'POST',
    url: '/api/webcheck',
    headers: { cookie: carol.cookie, 'x-forwarded-for': '203.0.113.9, 10.0.0.5' },
    payload: { url: 'https://demo.example', authorized: true },
  });
  check('stamped run → 201', stamped.statusCode === 201, stamped.statusCode);
  const stampedView = stamped.json() as {
    requester: { ip: string | null; geo: { city: string | null; country: string | null } | null };
  };
  check('first forwarded hop is the requester ip', stampedView.requester.ip === '203.0.113.9', stampedView.requester);
  check(
    'geo rides the stamp',
    stampedView.requester.geo?.city === 'Srinagar' && stampedView.requester.geo?.country === 'India',
    stampedView.requester,
  );
  const carolsRuns = await db.listWebChecks(carol.user.id, 5);
  check(
    'the stamp is what got stored',
    carolsRuns[0]?.requesterIp === '203.0.113.9' && carolsRuns[0]?.requesterGeo?.city === 'Srinagar',
    carolsRuns[0],
  );
  const carolsList = await app2.inject({ method: 'GET', url: '/api/webcheck', headers: { cookie: carol.cookie } });
  const carolsListBody = carolsList.json() as { runs: Array<{ requesterIp: string | null; requesterGeo: { city: string | null } | null }> };
  check(
    'history shows the owner their own stamp',
    carolsListBody.runs[0]?.requesterIp === '203.0.113.9' && carolsListBody.runs[0]?.requesterGeo?.city === 'Srinagar',
    carolsListBody.runs[0],
  );
  await app2.close();

  const app3 = Fastify();
  await webCheckRoutes(app3 as never, deps, {
    patrol: stampedPatrol,
    geo: async () => {
      throw new Error('geo service down');
    },
  });
  const dave = await makeCookie('dave@example.com');
  const unstamped = await app3.inject({
    method: 'POST',
    url: '/api/webcheck',
    headers: { cookie: dave.cookie },
    payload: { url: 'https://demo.example', authorized: true },
  });
  check('a dead geo lookup never blocks the run', unstamped.statusCode === 201, unstamped.statusCode);
  const unstampedView = unstamped.json() as { requester: { ip: string | null; geo: unknown } };
  check('ip falls back to the connection address', unstampedView.requester.ip === '127.0.0.1', unstampedView.requester);
  check('geo is null, not invented', unstampedView.requester.geo === null);
  await app3.close();

  /* ── GPS beats IP when the visitor shares it ── */
  const app4 = Fastify();
  await webCheckRoutes(app4 as never, deps, {
    patrol: stampedPatrol,
    geo: async () => {
      throw new Error('ip geo must not be consulted when GPS is shared');
    },
    reverseGeo: async () => ({ city: 'Srinagar', region: 'Jammu and Kashmir', country: 'India' }),
  });
  const erin = await makeCookie('erin@example.com');
  const gpsRun = await app4.inject({
    method: 'POST',
    url: '/api/webcheck',
    headers: { cookie: erin.cookie, 'x-forwarded-for': '203.0.113.9' },
    payload: {
      url: 'https://demo.example',
      authorized: true,
      gps: { lat: 34.0837, lon: 74.7973, accuracy: 18 },
    },
  });
  check('gps run → 201 (ip geo never consulted)', gpsRun.statusCode === 201, gpsRun.statusCode);
  const gpsView = gpsRun.json() as {
    requester: {
      ip: string | null;
      geo: { source?: string; lat?: number; lon?: number; accuracyM?: number; city: string | null } | null;
    };
  };
  check('ip still stamped alongside', gpsView.requester.ip === '203.0.113.9', gpsView.requester);
  check('stamp says gps', gpsView.requester.geo?.source === 'gps', gpsView.requester.geo);
  check(
    'coordinates stored as given',
    gpsView.requester.geo?.lat === 34.0837 && gpsView.requester.geo?.lon === 74.7973 && gpsView.requester.geo?.accuracyM === 18,
    gpsView.requester.geo,
  );
  check('reverse-geocoded city rides along', gpsView.requester.geo?.city === 'Srinagar', gpsView.requester.geo);
  await app4.close();

  const app5 = Fastify();
  await webCheckRoutes(app5 as never, deps, {
    patrol: stampedPatrol,
    geo: async () => ({ country: 'India', city: 'Srinagar', region: 'Jammu and Kashmir' }),
  });
  const frank = await makeCookie('frank@example.com');
  const ipRun = await app5.inject({
    method: 'POST',
    url: '/api/webcheck',
    headers: { cookie: frank.cookie, 'x-forwarded-for': '198.51.100.7' },
    payload: { url: 'https://demo.example', authorized: true },
  });
  const ipView = ipRun.json() as { requester: { geo: { source?: string } | null } };
  check('an unshared run is labelled ip', ipView.requester.geo?.source === 'ip', ipView.requester);
  await app5.close();

  await app.close();
  console.log(failures === 0 ? 'ALL WEBCHECK TESTS PASSED' : `${failures} FAILURES`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

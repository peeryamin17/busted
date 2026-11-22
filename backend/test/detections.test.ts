/* Runtime detection tests (Thread 5, DEFENSIVE) — no live network:
   crafted security events drive the pure rules; the analyzer persists
   through MemoryDatabase; the routes get a real session cookie via
   Fastify inject. Covers every rule (velocity, spray, many-accounts,
   user-agent diversity, API-key anomalies, probe patterns), spray
   hash-equality without plaintext, analyzer dedupe, route auth and
   per-user ownership, and the defensive report section. */
async function main() {
  const { MemoryDatabase } = await import('../src/db/db.js');
  const { generateSessionToken, hashSessionToken } = await import('../src/auth/session.js');
  const {
    analyzeEvents,
    hashAccountId,
    hashAttemptedPassword,
    runAllRules,
  } = await import('../src/detection/index.js');
  const { detectionRoutes } = await import('../src/routes/detections.js');
  const { buildDefensiveSection, defensiveClassesFromFindings } = await import('../src/reports/defensive.js');
  const Fastify = (await import('fastify')).default;
  const { createHash } = await import('node:crypto');

  let failures = 0;
  const check = (name: string, ok: boolean, extra?: unknown) => {
    console.log(`${ok ? 'PASS' : 'FAIL'} ${name}`);
    if (!ok) {
      failures++;
      if (extra !== undefined) console.log('     →', extra);
    }
  };

  const now = new Date('2026-11-22T12:00:00.000Z');
  const at = (minsAgo: number) =>
    new Date(now.getTime() - minsAgo * 60_000).toISOString();
  const userId = 'user-1';
  const ip = '203.0.113.7';

  const failedLogin = (account: string, password: string, minsAgo: number, fromIp = ip) => ({
    userId,
    type: 'failed_login' as const,
    at: at(minsAgo),
    ip: fromIp,
    accountHash: hashAccountId(account),
    passwordHash: hashAttemptedPassword(password),
    userAgent: 'Mozilla/5.0',
  });

  // --- Failed-login velocity: 12 failures from one IP in 10 min. ---
  const velocityEvents = Array.from({ length: 12 }, (_, i) =>
    failedLogin(`victim-${i}@example.com`, `pw-${i}`, 9 - i * 0.5),
  );
  const velocity = runAllRules(velocityEvents, null, { now });
  check(
    'velocity rule fires on 12 failed logins from one IP',
    velocity.some((c) => c.pattern === 'failed-login-velocity' && c.dedupeKey.includes(ip)),
  );
  check(
    'a single failed login fires nothing',
    runAllRules([failedLogin('a@example.com', 'pw', 1)], null, { now }).length === 0,
  );

  // --- Password spray: same password, 6 accounts, one IP. ---
  const sprayEvents = Array.from({ length: 6 }, (_, i) =>
    failedLogin(`user${i}@example.com`, 'Summer2026!', 30 + i),
  );
  const spray = runAllRules(sprayEvents, null, { now });
  check(
    'spray rule fires on one password across 6 accounts',
    spray.some((c) => c.pattern === 'password-spray' && c.severity === 'high'),
  );
  check(
    'spray detection never carries the plaintext password',
    !JSON.stringify(spray).includes('Summer2026!'),
  );
  check(
    'spray detection never carries a plaintext account',
    !JSON.stringify(spray).includes('user0@example.com'),
  );
  // Same password hash, different accounts — equality works on hashes.
  const hashA = hashAttemptedPassword('Summer2026!');
  const hashB = hashAttemptedPassword('Summer2026!');
  check('password hashing is deterministic for equality matching', hashA === hashB);
  check(
    'password hash is not the password',
    hashA !== 'Summer2026!' && !hashA.includes('Summer'),
  );

  // --- Many accounts from few IPs: 11 accounts, 1 IP. ---
  const manyEvents = Array.from({ length: 11 }, (_, i) =>
    failedLogin(`acct${i}@example.com`, `unique-pw-${i}`, 40 + i),
  );
  check(
    'many-accounts rule fires on 11 accounts from 1 IP',
    runAllRules(manyEvents, null, { now }).some((c) => c.pattern === 'many-accounts-few-ips'),
  );

  // --- User-agent diversity: 6 agents, one account. ---
  const uaEvents = Array.from({ length: 6 }, (_, i) => ({
    userId,
    type: 'login' as const,
    at: at(20 + i),
    ip,
    accountHash: hashAccountId('shared@example.com'),
    userAgent: `Agent/${i}`,
  }));
  check(
    'user-agent diversity fires on 6 agents for one account',
    runAllRules(uaEvents, null, { now }).some((c) => c.pattern === 'user-agent-diversity'),
  );

  // --- API-key anomalies: volume spike, new IP, new endpoint. ---
  const keyUses = Array.from({ length: 120 }, (_, i) => ({
    userId,
    type: 'api_key_use' as const,
    at: at(50 - i * 0.4),
    ip: i < 110 ? '198.51.100.1' : '198.51.100.99',
    apiKeyPrefix: 'bs_abc123',
    endpoint: i < 115 ? '/api/scans' : '/api/admin',
  }));
  const baseline = {
    knownIpsByKey: new Map([['bs_abc123', new Set(['198.51.100.1'])]]),
    knownEndpointsByKey: new Map([['bs_abc123', new Set(['/api/scans'])]]),
  };
  const keyFindings = runAllRules(keyUses, baseline, { now });
  check(
    'API-key volume spike fires over threshold',
    keyFindings.some((c) => c.pattern === 'api-key-anomaly' && c.dedupeKey.includes('volume')),
  );
  check(
    'API-key new IP fires against baseline',
    keyFindings.some((c) => c.pattern === 'api-key-anomaly' && c.dedupeKey.includes('new-ip')),
  );
  check(
    'API-key new endpoint fires against baseline',
    keyFindings.some((c) => c.pattern === 'api-key-anomaly' && c.dedupeKey.includes('new-endpoint')),
  );
  check(
    'API-key rules stay quiet without a baseline for new-IP/new-endpoint',
    runAllRules(keyUses, null, { now }).every((c) => !c.dedupeKey.includes('new-')),
  );

  // --- Probe patterns: admin 404s + payload signatures. ---
  const probeEvents = [
    ...['/admin', '/wp-admin', '/phpmyadmin', '/console', '/debug'].map((p, i) => ({
      userId,
      type: 'request' as const,
      at: at(10 + i),
      ip,
      endpoint: p,
      status: 404,
    })),
    ...Array.from({ length: 3 }, (_, i) => ({
      userId,
      type: 'request' as const,
      at: at(5 + i),
      ip,
      endpoint: `/search?q=%3Cscript%3E${i}`,
      status: 200,
    })),
  ];
  const probes = runAllRules(probeEvents, null, { now });
  check(
    'probe rule fires on repeated admin 404s',
    probes.some((c) => c.pattern === 'probe-pattern' && c.dedupeKey.includes('admin')),
  );
  check(
    'probe rule fires on payload signatures in paths',
    probes.some((c) => c.pattern === 'probe-pattern' && c.dedupeKey.includes('signature')),
  );

  // --- Analyzer: persists, dedupes within the hour. ---
  const db = new MemoryDatabase();
  const user = await db.createUser('owner@example.com', createHash('sha256').update('x').digest('hex'));
  const sprayForUser = sprayEvents.map((e) => ({ ...e, userId: user.id }));
  const first = await analyzeEvents(db, user.id, sprayForUser, null, { now });
  check('analyzer persists spray detection', first.created.length === 1);
  const second = await analyzeEvents(db, user.id, sprayForUser, null, { now });
  check('analyzer dedupes the same spray within the hour', second.created.length === 0);
  const stored = await db.listDetections(user.id, 20);
  check('stored detection round-trips through the DB layer', stored.length === 1 && stored[0].pattern === 'password-spray');
  const one = await db.getDetection(user.id, stored[0].id);
  check('getDetection returns the stored row', one !== null && one.id === stored[0].id);
  check('getDetection refuses another user', (await db.getDetection('someone-else', stored[0].id)) === null);

  // --- Routes: auth required, list + one, ownership enforced. ---
  const app = Fastify();
  await app.register(async (instance) => {
    await detectionRoutes(instance, { db, queue: {}, provider: {} } as never);
  });
  await app.ready();

  const unauth = await app.inject({ method: 'GET', url: '/api/detections' });
  check('GET /api/detections without auth is 401', unauth.statusCode === 401, unauth.statusCode);

  const token = generateSessionToken();
  await db.createSession(user.id, hashSessionToken(token), new Date(Date.now() + 3600_000).toISOString());
  const cookie = `bs_session=${token}`;
  const list = await app.inject({ method: 'GET', url: '/api/detections', headers: { cookie } });
  const listBody = list.json() as { detections: Array<{ pattern: string }> };
  check('GET /api/detections lists my detections', list.statusCode === 200 && listBody.detections.length === 1, list.body);
  const other = await db.createUser('other@example.com', 'x');
  const otherToken = generateSessionToken();
  await db.createSession(other.id, hashSessionToken(otherToken), new Date(Date.now() + 3600_000).toISOString());
  const forbidden = await app.inject({
    method: 'GET',
    url: `/api/detections/${stored[0].id}`,
    headers: { cookie: `bs_session=${otherToken}` },
  });
  check('GET /api/detections/:id refuses another user', forbidden.statusCode === 404, forbidden.statusCode);
  const got = await app.inject({
    method: 'GET',
    url: `/api/detections/${stored[0].id}`,
    headers: { cookie },
  });
  check('GET /api/detections/:id returns my detection', got.statusCode === 200 && (got.json() as { pattern: string }).pattern === 'password-spray');

  // --- Defensive report section. ---
  const md = buildDefensiveSection({
    targetUrl: 'https://example.com',
    scannedAt: '2026-11-22T12:00:00.000Z',
    classes: [
      {
        attackClass: 'brute-force',
        detected: 'not-observed',
        blocked: 'not-observed',
        logged: 'unknown',
        alerted: 'unknown',
        summary: '5 canary failed logins produced no throttling signal.',
      },
      {
        attackClass: 'waf-evasion',
        detected: 'observed',
        blocked: 'observed',
        logged: 'unknown',
        alerted: 'unknown',
        summary: 'All encoding classes blocked at the edge.',
      },
    ],
  });
  check('report names the blind spot', md.includes('Blind spot'));
  check('report carries remediation for the gap', md.includes('rate limiting on the login endpoint'));
  check('report is honest about unobservable logging', md.includes('not visible from outside'));
  check('report covers the defended class too', md.includes('WAF / filter evasion'));

  // Derivation: defense findings -> defensive classes (integration wiring).
  // Tags first (extension findings carry them); title prefixes as fallback
  // (backend findings lose tags at ingestion).
  const derived = defensiveClassesFromFindings([
    { title: 'Brute-force defense engaged (rate limiting)', description: 'Rate limiting engaged after 3 failures.', tags: ['defense-verification', 'defense-brute-force', 'defense-engaged'] },
    { title: 'WAF let through 2 encoding class(es): double-encoded, unicode', description: 'Two classes passed.', tags: ['defense-verification', 'defense-waf', 'defense-blind'] },
    { title: 'No brute-force protection observed on login', description: 'Nothing reacted.' },
    { title: 'Key-exposure defense check: no exposed keys found to assess', description: 'Nothing to assess.' },
    { title: 'Brute-force defense check skipped — not authorized', description: 'Skipped.' },
    { title: 'Random unrelated finding', description: 'Not a defense finding.' },
  ]);
  const byClass = new Map(derived.map((c) => [c.attackClass, c]));
  check('derivation covers three classes', derived.length === 3);
  check('derivation: engaged brute force reads Defended', byClass.get('brute-force')?.blocked === 'observed');
  check('derivation: WAF bypass reads seen-but-not-stopped', byClass.get('waf-evasion')?.detected === 'observed' && byClass.get('waf-evasion')?.blocked === 'not-observed');
  check('derivation: clean key-exposure reads Defended', byClass.get('key-exposure')?.blocked === 'observed');
  check('derivation: skipped probe does not outvote an engaged one', byClass.get('brute-force')?.detected === 'observed');
  check('derivation ignores non-defense findings', !byClass.has('exploitation' as never));
  const derivedBlind = defensiveClassesFromFindings([
    { title: 'No brute-force protection observed on login', description: 'Nothing reacted.' },
  ]);
  check('derivation: blind brute force reads Blind spot', derivedBlind[0]?.detected === 'not-observed' && derivedBlind[0]?.blocked === 'not-observed');
  const derivedSkipped = defensiveClassesFromFindings([
    { title: 'Brute-force defense check skipped — not authorized', description: 'Skipped.' },
  ]);
  check('derivation: skipped probe reads Inconclusive', derivedSkipped[0]?.detected === 'unknown' && derivedSkipped[0]?.blocked === 'unknown');
  check('derivation returns [] with no defense findings', defensiveClassesFromFindings([{ title: 'Random finding' }]).length === 0);

  await app.close();
  await db.close();

  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log('\nAll detection tests passed.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

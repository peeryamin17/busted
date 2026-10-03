/* Waitlist test: POST /api/waitlist against the in-memory DB — storage,
   dedupe by normalised email, input validation, and the per-route
   rate limit. No live Postgres needed, same as the other suites. */
async function main() {
  const { MemoryDatabase } = await import('../src/db/db.js');
  const { waitlistRoutes } = await import('../src/routes/waitlist.js');
  const Fastify = (await import('fastify')).default;
  const rateLimit = (await import('@fastify/rate-limit')).default;

  let failures = 0;
  const check = (name: string, ok: boolean, extra?: unknown) => {
    console.log(`${ok ? 'PASS' : 'FAIL'} ${name}`);
    if (!ok) {
      failures++;
      if (extra !== undefined) console.log('     →', extra);
    }
  };

  const db = new MemoryDatabase();
  const deps = { db, queue: {} as never, provider: {} as never };

  /* ── plain route (validation + storage + dedupe) ── */
  const app = Fastify();
  await waitlistRoutes(app as never, deps);

  const first = await app.inject({
    method: 'POST',
    url: '/api/waitlist',
    payload: { email: 'hunter@example.com' },
  });
  const firstBody = first.json() as { ok: boolean; already: boolean };
  check('valid email → 200', first.statusCode === 200, first.statusCode);
  check('first signup → { ok: true, already: false }', firstBody.ok === true && firstBody.already === false, first.body);

  const dupe = await app.inject({
    method: 'POST',
    url: '/api/waitlist',
    payload: { email: 'hunter@example.com' },
  });
  const dupeBody = dupe.json() as { ok: boolean; already: boolean };
  check('duplicate → still 200', dupe.statusCode === 200, dupe.statusCode);
  check('duplicate → already: true', dupeBody.ok === true && dupeBody.already === true, dupe.body);

  const sloppy = await app.inject({
    method: 'POST',
    url: '/api/waitlist',
    payload: { email: '  Hunter@Example.COM  ' },
  });
  check('case/spacing variant counts as the same email', (sloppy.json() as { already: boolean }).already === true, sloppy.body);

  const invalid = await app.inject({
    method: 'POST',
    url: '/api/waitlist',
    payload: { email: 'not-an-email' },
  });
  check('invalid email → 400', invalid.statusCode === 400, invalid.statusCode);
  check('400 carries a JSON error', typeof (invalid.json() as { error?: unknown }).error === 'string', invalid.body);

  const nonString = await app.inject({
    method: 'POST',
    url: '/api/waitlist',
    payload: { email: 42 },
  });
  check('non-string email → 400', nonString.statusCode === 400, nonString.statusCode);

  const missing = await app.inject({ method: 'POST', url: '/api/waitlist', payload: {} });
  check('missing email → 400', missing.statusCode === 400, missing.statusCode);

  await app.close();

  /* ── per-route rate limit (5/min/IP on this route only) ── */
  const limited = Fastify();
  await limited.register(rateLimit, { max: 1000, timeWindow: '1 minute' });
  await waitlistRoutes(limited as never, deps);

  let fifthOk = true;
  for (let i = 1; i <= 5; i++) {
    const res = await limited.inject({
      method: 'POST',
      url: '/api/waitlist',
      payload: { email: `rate-${i}@example.com` },
    });
    if (res.statusCode !== 200) fifthOk = false;
  }
  check('first 5 requests in a minute → 200', fifthOk);
  const sixth = await limited.inject({
    method: 'POST',
    url: '/api/waitlist',
    payload: { email: 'rate-6@example.com' },
  });
  check('6th request in a minute → 429', sixth.statusCode === 429, sixth.statusCode);

  await limited.close();
  console.log(failures === 0 ? 'ALL WAITLIST TESTS PASSED' : `${failures} FAILURES`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

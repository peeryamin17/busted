/**
 * Unit tests for the noise governor (src/egress/noise.ts). No network, no
 * DB, no LLM. Fetches are faked; timing tests use small real delays (the
 * whole file runs in ~3 s).
 *
 * Run:  npx tsx test/noise.test.ts   (from backend/)
 */
import {
  DEFAULT_NOISE_PROFILE,
  NOISE_PROFILES,
  NoiseGovernor,
  coalescedGet,
  fetchWithGovernor,
  parseNoiseProfile,
  parseRetryAfterMs,
  type GovernedFetchInit,
} from '../src/egress/noise.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** A fake fetch that replays a scripted list of responses, counting calls. */
function scriptedFetch(script: Array<Response | Error>) {
  let calls = 0;
  const fn = async (_url: string, _init: GovernedFetchInit): Promise<Response> => {
    const next = script[Math.min(calls, script.length - 1)]!;
    calls++;
    if (next instanceof Error) throw next;
    return next;
  };
  return { fn, calls: () => calls };
}

const ok200 = (body = 'hello') => new Response(body, { status: 200 });
const rateLimited = (retryAfter?: string) =>
  new Response('slow down', {
    status: 429,
    headers: retryAfter === undefined ? {} : { 'retry-after': retryAfter },
  });

async function main() {
  // ── 1. Profile parsing ──
  // Decision: parsing is case-insensitive and trims whitespace; anything
  // unknown, empty or missing falls back to 'balanced'; 'off' only when
  // explicitly requested.
  {
    check('parse: undefined → balanced', parseNoiseProfile(undefined) === 'balanced');
    check('parse: empty → balanced', parseNoiseProfile('') === 'balanced');
    check('parse: whitespace → balanced', parseNoiseProfile('   ') === 'balanced');
    check('parse: unknown → balanced', parseNoiseProfile('turbo') === 'balanced');
    check('parse: off → off', parseNoiseProfile('off') === 'off');
    check('parse: case-insensitive QUIET → quiet', parseNoiseProfile('QUIET') === 'quiet');
    check('parse: trims + lowercases', parseNoiseProfile('  Balanced ') === 'balanced');
    check('parse: AGGRESSIVE → aggressive', parseNoiseProfile('AGGRESSIVE') === 'aggressive');
    check('default profile is balanced', DEFAULT_NOISE_PROFILE === 'balanced');
  }

  // ── 2. Profile table ──
  {
    check('profiles: quiet 2/s burst 4, 1 in flight',
      NOISE_PROFILES.quiet.rps === 2 && NOISE_PROFILES.quiet.burst === 4 && NOISE_PROFILES.quiet.maxInFlight === 1);
    check('profiles: balanced 5/s burst 10, 2 in flight',
      NOISE_PROFILES.balanced.rps === 5 && NOISE_PROFILES.balanced.burst === 10 && NOISE_PROFILES.balanced.maxInFlight === 2);
    check('profiles: aggressive 20/s burst 40, 4 in flight',
      NOISE_PROFILES.aggressive.rps === 20 && NOISE_PROFILES.aggressive.burst === 40 && NOISE_PROFILES.aggressive.maxInFlight === 4);
    check('profiles: off has no jitter', NOISE_PROFILES.off.jitterMs === 0);
    check('profiles: every other profile jitters 0–250ms',
      NOISE_PROFILES.quiet.jitterMs === 250 && NOISE_PROFILES.balanced.jitterMs === 250 && NOISE_PROFILES.aggressive.jitterMs === 250);
  }

  // ── 3. Rate limiting actually waits ──
  // quiet = 2/s with burst 4, so the first four acquires are free; the
  // 5th waits ~500 ms for a refill and the 6th ~500 ms more. Six rapid
  // acquires must therefore take >= ~1 s in total. Random is fixed to 0
  // so jitter cannot fake the wait.
  {
    const gov = new NoiseGovernor('quiet', { random: () => 0 });
    const started = Date.now();
    for (let i = 0; i < 6; i++) {
      await gov.acquire('example.com');
      gov.release('example.com');
    }
    const elapsed = Date.now() - started;
    check('ratelimit: 6 rapid quiet acquires take >= ~1s', elapsed >= 900, `${elapsed}ms`);
    check('ratelimit: ...and finish well under 5s', elapsed < 5000, `${elapsed}ms`);
    check('ratelimit: acquired counter counts all 6',
      gov.getCounters()['example.com']?.acquired === 6, gov.getCounters());
    check('ratelimit: delayed counter counts the waits',
      (gov.getCounters()['example.com']?.delayed ?? 0) >= 2, gov.getCounters());
  }

  // ── 4. Jitter is applied (injected deterministic random) ──
  {
    const max = new NoiseGovernor('balanced', { random: () => 1.0 });
    const t0 = Date.now();
    await max.acquire('example.com');
    max.release('example.com');
    const elapsedMax = Date.now() - t0;
    check('jitter: random=1.0 delays near the 250ms max', elapsedMax >= 200, `${elapsedMax}ms`);
    check('jitter: max-jitter acquire counted as delayed',
      max.getCounters()['example.com']?.delayed === 1, max.getCounters());

    const none = new NoiseGovernor('balanced', { random: () => 0.0 });
    const t1 = Date.now();
    await none.acquire('example.com');
    none.release('example.com');
    const elapsedNone = Date.now() - t1;
    check('jitter: random=0.0 delays ~0ms', elapsedNone < 200, `${elapsedNone}ms`);
    check('jitter: zero-jitter acquire not counted as delayed',
      none.getCounters()['example.com']?.delayed === 0, none.getCounters());
  }

  // ── 5. Per-host in-flight cap, FIFO queue ──
  {
    const gov = new NoiseGovernor('quiet', { random: () => 0 }); // 1 in flight
    await gov.acquire('example.com'); // holds the only slot
    let secondDone = false;
    let thirdDone = false;
    const order: string[] = [];
    const second = gov.acquire('example.com').then(() => { secondDone = true; order.push('second'); });
    const third = gov.acquire('example.com').then(() => { thirdDone = true; order.push('third'); });
    await sleep(60);
    check('inflight: 2nd acquire waits while slot held', secondDone === false);
    check('inflight: 3rd acquire waits while slot held', thirdDone === false);
    gov.release('example.com'); // slot passes to the 2nd waiter
    await second;
    check('inflight: 2nd acquire resolves after release', secondDone === true);
    check('inflight: 3rd still waits (FIFO)', thirdDone === false);
    gov.release('example.com');
    await third;
    check('inflight: 3rd acquire resolves after 2nd releases', thirdDone === true);
    check('inflight: waiters resolve FIFO', order.join(',') === 'second,third', order);
    gov.release('example.com');
  }

  // ── 6. Retry-After parsing ──
  {
    check('retry-after: seconds → ms', parseRetryAfterMs('2') === 2000);
    check('retry-after: 0 → 0', parseRetryAfterMs('0') === 0);
    check('retry-after: capped at 60s', parseRetryAfterMs('3600') === 60000);
    check('retry-after: null → null', parseRetryAfterMs(null) === null);
    check('retry-after: empty → null', parseRetryAfterMs('  ') === null);
    check('retry-after: garbage → null', parseRetryAfterMs('soon') === null);
    const future = new Date(Date.now() + 5000).toUTCString();
    const parsed = parseRetryAfterMs(future);
    check('retry-after: HTTP date → ms until then', parsed !== null && parsed > 3000 && parsed <= 5000, parsed);
    check('retry-after: past date → 0', parseRetryAfterMs(new Date(Date.now() - 5000).toUTCString()) === 0);
  }

  // ── 7. Retry-After backoff: retry once, then stop ──
  {
    const gov = new NoiseGovernor('balanced', { random: () => 0 });
    const fake = scriptedFetch([rateLimited('0'), ok200()]);
    const res = await fetchWithGovernor(gov, 'https://example.com/a', {}, fake.fn);
    check('retry: 429 + Retry-After 0 retried once → 200', res.status === 200);
    check('retry: underlying fetch called twice', fake.calls() === 2, fake.calls());
    check('retry: retriedAfter429 counter is 1',
      gov.getCounters()['example.com']?.retriedAfter429 === 1, gov.getCounters());

    const twice = scriptedFetch([rateLimited('0'), rateLimited('0')]);
    const res2 = await fetchWithGovernor(gov, 'https://example.com/b', {}, twice.fn);
    check('retry: second 429 is NOT retried (returned as-is)', res2.status === 429);
    check('retry: second 429 → exactly 2 calls', twice.calls() === 2, twice.calls());

    const post = scriptedFetch([rateLimited('0'), ok200()]);
    const res3 = await fetchWithGovernor(gov, 'https://example.com/c', { method: 'POST' }, post.fn);
    check('retry: POST 429 is NOT retried', res3.status === 429 && post.calls() === 1, post.calls());

    const noHeader = scriptedFetch([rateLimited(), ok200()]);
    const res4 = await fetchWithGovernor(gov, 'https://example.com/d', {}, noHeader.fn);
    check('retry: 429 without Retry-After is NOT retried', res4.status === 429 && noHeader.calls() === 1, noHeader.calls());

    const garbage = scriptedFetch([rateLimited('soon'), ok200()]);
    const res5 = await fetchWithGovernor(gov, 'https://example.com/e', {}, garbage.fn);
    check('retry: unparseable Retry-After is NOT retried', res5.status === 429 && garbage.calls() === 1, garbage.calls());

    const svc = scriptedFetch([
      new Response('unavailable', { status: 503, headers: { 'retry-after': '0' } }),
      ok200(),
    ]);
    const res6 = await fetchWithGovernor(gov, 'https://example.com/f', {}, svc.fn);
    check('retry: 503 + Retry-After is retried like 429', res6.status === 200 && svc.calls() === 2, svc.calls());

    const opts = scriptedFetch([rateLimited('0'), ok200()]);
    const res7 = await fetchWithGovernor(gov, 'https://example.com/g', { method: 'OPTIONS' }, opts.fn);
    check('retry: OPTIONS 429 is retried (read-only)', res7.status === 200 && opts.calls() === 2, opts.calls());

    const dated = scriptedFetch([
      new Response('slow down', { status: 429, headers: { 'retry-after': new Date().toUTCString() } }),
      ok200(),
    ]);
    const res8 = await fetchWithGovernor(gov, 'https://example.com/h', {}, dated.fn);
    check('retry: HTTP-date Retry-After (now) is honoured', res8.status === 200 && dated.calls() === 2, dated.calls());
  }

  // ── 8. Retry-After timing: a 1 s backoff really waits ──
  {
    const gov = new NoiseGovernor('balanced', { random: () => 0 });
    const fake = scriptedFetch([rateLimited('1'), ok200()]);
    const started = Date.now();
    const res = await fetchWithGovernor(gov, 'https://example.com/slow', {}, fake.fn);
    const elapsed = Date.now() - started;
    check('retry-timing: Retry-After 1 waits >= ~1s', res.status === 200 && elapsed >= 900, `${elapsed}ms`);
    check('retry-timing: ...and finishes well under 5s', elapsed < 5000, `${elapsed}ms`);
  }

  // ── 9. `off` passes through: no retry, no coalescing ──
  {
    const gov = new NoiseGovernor('off');
    const fake = scriptedFetch([rateLimited('0'), ok200()]);
    const res = await fetchWithGovernor(gov, 'https://example.com/off', {}, fake.fn);
    check('off: 429 is NOT retried', res.status === 429 && fake.calls() === 1, fake.calls());

    let calls = 0;
    const fn = async () => { calls++; await sleep(20); return ok200(); };
    const [r1, r2] = await Promise.all([
      coalescedGet(gov, 'https://example.com/off-get', fn),
      coalescedGet(gov, 'https://example.com/off-get', fn),
    ]);
    check('off: identical GETs are NOT coalesced', calls === 2, calls);
    check('off: both callers still get 200', r1.status === 200 && r2.status === 200);
  }

  // ── 10. GET coalescing ──
  {
    const gov = new NoiseGovernor('balanced', { random: () => 0 });
    let calls = 0;
    const fn = async () => { calls++; await sleep(30); return ok200('shared-body'); };
    const [r1, r2] = await Promise.all([
      coalescedGet(gov, 'https://example.com/same', fn),
      coalescedGet(gov, 'https://example.com/same', fn),
    ]);
    check('coalesce: two concurrent identical GETs → one underlying call', calls === 1, calls);
    check('coalesce: both callers get 200', r1.status === 200 && r2.status === 200);
    check('coalesce: both callers can read the body (clone works)',
      (await r1.text()) === 'shared-body' && (await r2.text()) === 'shared-body');
    check('coalesce: waiter counted as coalesced',
      gov.getCounters()['example.com']?.coalesced === 1, gov.getCounters());

    let diffCalls = 0;
    const diffFn = async () => { diffCalls++; await sleep(10); return ok200(); };
    await Promise.all([
      coalescedGet(gov, 'https://example.com/one', diffFn),
      coalescedGet(gov, 'https://example.com/two', diffFn),
    ]);
    check('coalesce: different URLs are NOT coalesced', diffCalls === 2, diffCalls);

    // Sequential identical GETs (no overlap) must not share, no caching.
    let seqCalls = 0;
    const seqFn = async () => { seqCalls++; return ok200(); };
    await coalescedGet(gov, 'https://example.com/seq', seqFn);
    await coalescedGet(gov, 'https://example.com/seq', seqFn);
    check('coalesce: sequential identical GETs are NOT shared', seqCalls === 2, seqCalls);
  }

  // ── 11. A failed shared GET does not poison the next one ──
  {
    const gov = new NoiseGovernor('balanced', { random: () => 0 });
    let calls = 0;
    const flaky = async (): Promise<Response> => {
      calls++;
      await sleep(20);
      if (calls === 1) throw new Error('boom');
      return ok200('recovered');
    };
    const results = await Promise.allSettled([
      coalescedGet(gov, 'https://example.com/flaky', flaky),
      coalescedGet(gov, 'https://example.com/flaky', flaky),
    ]);
    check('coalesce-fail: both waiters reject on a failed shared GET',
      results.every((r) => r.status === 'rejected'), results.map((r) => r.status));
    check('coalesce-fail: failed shared GET ran once', calls === 1, calls);
    const retry = await coalescedGet(gov, 'https://example.com/flaky', flaky);
    check('coalesce-fail: next identical GET refetches and succeeds',
      retry.status === 200 && (await retry.text()) === 'recovered' && calls === 2, calls);
  }

  // ── 12. fetchWithGovernor releases the slot even when fetch throws ──
  {
    const gov = new NoiseGovernor('quiet', { random: () => 0 }); // 1 in flight
    const throwing = scriptedFetch([new Error('network down')]);
    await fetchWithGovernor(gov, 'https://example.com/throw', {}, throwing.fn).catch(() => undefined);
    let acquired = false;
    const pending = gov.acquire('example.com').then(() => { acquired = true; });
    await Promise.race([pending, sleep(500)]);
    check('release: slot freed after a throwing fetch (no deadlock)', acquired === true);
    if (acquired) gov.release('example.com');
    check('release: throwing fetch still counted as acquired',
      gov.getCounters()['example.com']?.acquired === 2, gov.getCounters());
  }

  // ── 13. Counters are per-host and per-instance; logCounters logs ──
  {
    const gov = new NoiseGovernor('balanced', { random: () => 0 });
    await gov.acquire('a.example.com');
    gov.release('a.example.com');
    await gov.acquire('b.example.com');
    gov.release('b.example.com');
    const counters = gov.getCounters();
    check('counters: per-host entries', counters['a.example.com']?.acquired === 1 && counters['b.example.com']?.acquired === 1, counters);
    check('counters: returned copies (mutating them changes nothing)',
      (() => { counters['a.example.com']!.acquired = 99; return gov.getCounters()['a.example.com']?.acquired === 1; })());
    const other = new NoiseGovernor('balanced');
    check('counters: a second governor starts empty', Object.keys(other.getCounters()).length === 0);

    const lines: string[] = [];
    const origInfo = console.info;
    console.info = (...args: unknown[]) => { lines.push(args.join(' ')); };
    try {
      gov.logCounters();
      other.logCounters();
    } finally {
      console.info = origInfo;
    }
    check('logCounters: one [noise] line per host',
      lines.filter((l) => l.startsWith('[noise] a.example.com')).length === 1 &&
      lines.filter((l) => l.startsWith('[noise] b.example.com')).length === 1, lines);
    check('logCounters: empty governor logs a single no-requests line',
      lines.some((l) => l === '[noise] no requests governed'), lines);
  }

  if (failures > 0) { console.error(`${failures} noise test(s) failed`); process.exit(1); }
  console.log('ALL NOISE TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('noise test crashed', e); process.exit(1); });

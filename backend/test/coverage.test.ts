/**
 * Unit tests for the coverage ledger (coverage/ledger.ts) and its route
 * (routes/coverage.ts). No network, no database, the Postgres store is
 * exercised through a stub query function, and the route through Fastify
 * inject with a fake authenticate + fake task lookup.
 *
 * Run:  npx tsx test/coverage.test.ts   (from backend/)
 */
import Fastify from 'fastify';
import {
  MemoryCoverageStore,
  PostgresCoverageStore,
  RISK_CLASSES,
  coverageSummary,
  recordFromFindings,
  riskClassForCategory,
  type CoverageEntry,
} from '../src/coverage/ledger.js';
import { coverageRoutes } from '../src/routes/coverage.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

const TASK = 'task-1';
const OTHER_TASK = 'task-2';

async function main() {
  // ── 1. Memory store: upsert by (taskId, assetId, riskClass) ──
  {
    const store = new MemoryCoverageStore();
    const first = await store.recordEntry({
      taskId: TASK, riskClass: 'xss', outcome: 'untested', reason: 'worker not spawned yet',
    });
    const second = await store.recordEntry({
      taskId: TASK, riskClass: 'xss', outcome: 'tested', evidence: 'probed /search?q=<canary>',
    });
    check('upsert: second entry replaces first', first.id === second.id, { first, second });
    const list = await store.listEntries(TASK);
    check('upsert: exactly one row survives', list.length === 1, list);
    check('upsert: surviving row is the later outcome', list[0]?.outcome === 'tested', list[0]);
    check('upsert: later evidence wins', list[0]?.evidence === 'probed /search?q=<canary>', list[0]);
    const got = await store.getEntry(TASK, null, 'xss');
    check('getEntry: finds the upserted row', got?.outcome === 'tested', got);
    const missing = await store.getEntry(TASK, null, 'idor');
    check('getEntry: null for a class never recorded', missing === null, missing);
  }

  // ── 2. Memory store: per-asset triples are distinct; list is task-scoped ──
  {
    const store = new MemoryCoverageStore();
    await store.recordEntry({ taskId: TASK, assetId: 'asset-a', riskClass: 'xss', outcome: 'finding' });
    await store.recordEntry({ taskId: TASK, assetId: 'asset-b', riskClass: 'xss', outcome: 'tested' });
    await store.recordEntry({ taskId: TASK, riskClass: 'xss', outcome: 'tested' });
    await store.recordEntry({ taskId: OTHER_TASK, riskClass: 'xss', outcome: 'finding' });
    const list = await store.listEntries(TASK);
    check('scoping: same class on two assets + task-level = 3 rows', list.length === 3, list);
    const other = await store.listEntries(OTHER_TASK);
    check('scoping: other task sees only its own rows', other.length === 1 && other[0]?.taskId === OTHER_TASK, other);
    const empty = await store.listEntries('no-such-task');
    check('scoping: unknown task lists nothing', empty.length === 0, empty);
  }

  // ── 3. coverageSummary math ──
  {
    const entries: CoverageEntry[] = [
      { taskId: TASK, assetId: 'a1', riskClass: 'xss', outcome: 'finding' },
      { taskId: TASK, assetId: 'a1', riskClass: 'xss', outcome: 'tested' },
      { taskId: TASK, assetId: 'a2', riskClass: 'headers', outcome: 'tested' },
      { taskId: TASK, riskClass: 'cors', outcome: 'not_applicable', reason: 'no CORS surface' },
      { taskId: TASK, riskClass: 'auth', outcome: 'untested' },
    ];
    const s = coverageSummary(entries);
    check('summary: xss finding counted', s.byClass.xss.finding === 1, s.byClass.xss);
    check('summary: xss tested counted', s.byClass.xss.tested === 1, s.byClass.xss);
    check('summary: headers tested counted', s.byClass.headers.tested === 1, s.byClass.headers);
    check('summary: cors n/a counted', s.byClass.cors.notApplicable === 1, s.byClass.cors);
    check('summary: auth untested counted', s.byClass.auth.untested === 1, s.byClass.auth);
    check('summary: totalEntries', s.totalEntries === 5, s.totalEntries);
    check('summary: testedAssets counts distinct assets', s.testedAssets === 2, s.testedAssets);
  }

  // ── 4. THE CORE RULE: untested by default ──
  {
    const onlyXss: CoverageEntry[] = [
      { taskId: TASK, riskClass: 'xss', outcome: 'finding' },
    ];
    const s = coverageSummary(onlyXss);
    check('untested-by-default: xss is not untested', !s.untestedClasses.includes('xss'), s.untestedClasses);
    const everyOther = RISK_CLASSES.filter((c) => c !== 'xss');
    check(
      'untested-by-default: every other risk class is untested',
      everyOther.every((c) => s.untestedClasses.includes(c)),
      s.untestedClasses,
    );
    check(
      'untested-by-default: untestedClasses covers all but one class',
      s.untestedClasses.length === RISK_CLASSES.length - 1,
      s.untestedClasses,
    );
  }
  {
    // 'not_applicable' and 'untested' entries do NOT count as tested.
    const s = coverageSummary([
      { taskId: TASK, riskClass: 'cors', outcome: 'not_applicable' },
      { taskId: TASK, riskClass: 'auth', outcome: 'untested' },
    ]);
    check('untested-by-default: n/a is not tested', s.untestedClasses.includes('cors'), s.untestedClasses);
    check('untested-by-default: untested entry is not tested', s.untestedClasses.includes('auth'), s.untestedClasses);
  }
  {
    // Empty task: all classes untested, zero counts everywhere.
    const s = coverageSummary([]);
    check('empty task: all classes untested', s.untestedClasses.length === RISK_CLASSES.length, s.untestedClasses);
    check(
      'empty task: every byClass row is zero',
      RISK_CLASSES.every((c) => {
        const b = s.byClass[c];
        return b.tested === 0 && b.untested === 0 && b.finding === 0 && b.notApplicable === 0;
      }),
      s.byClass,
    );
    check('empty task: zero assets, zero entries', s.testedAssets === 0 && s.totalEntries === 0, s);
  }

  // ── 5. recordFromFindings mapping ──
  {
    check('map: xss → xss', riskClassForCategory('xss') === 'xss');
    check('map: secrets → secrets', riskClassForCategory('secrets') === 'secrets');
    check('map: cookies → headers', riskClassForCategory('cookies') === 'headers');
    check('map: dom → xss', riskClassForCategory('dom') === 'xss');
    check('map: tech → recon', riskClassForCategory('tech') === 'recon');
    check('map: source-map → sourcemap', riskClassForCategory('source-map') === 'sourcemap');
    check('map: unknown → general', riskClassForCategory('weird-category') === 'general');
    check('map: case-insensitive', riskClassForCategory('XSS') === 'xss');

    const made = recordFromFindings(TASK, [
      { category: 'xss', location: 'https://example.com/search?q=1' },
      { category: 'xss', location: 'https://example.com/search?q=1' },
      { category: 'xss', location: 'https://example.com/other' },
      { category: 'secrets', location: 'https://example.com/app.js' },
      { category: 'mystery', location: 'https://example.com/' },
      { category: 'headers' },
    ]);
    check('recordFromFindings: dedupes same class+location', made.length === 5, made);
    check(
      'recordFromFindings: all outcomes are finding',
      made.every((e) => e.outcome === 'finding'),
      made,
    );
    check(
      'recordFromFindings: unknown category lands in general',
      made.some((e) => e.riskClass === 'general' && e.assetValue === 'https://example.com/'),
      made,
    );
    check(
      'recordFromFindings: location becomes assetValue',
      made.some((e) => e.riskClass === 'secrets' && e.assetValue === 'https://example.com/app.js'),
      made,
    );
    check(
      'recordFromFindings: location-less finding is task-level',
      made.some((e) => e.riskClass === 'headers' && e.assetValue === undefined),
      made,
    );
    const s = coverageSummary(made);
    check('recordFromFindings: summary sees the finding classes as tested', !s.untestedClasses.includes('xss') && !s.untestedClasses.includes('secrets'), s.untestedClasses);
  }

  // ── 6. Postgres store over a stub query fn (no live DB) ──
  {
    const seen: { sql: string; params: unknown[] }[] = [];
    const store = new PostgresCoverageStore(async (sql, params) => {
      seen.push({ sql, params });
      if (sql.includes('insert into coverage_ledger')) {
        return {
          rows: [{
            id: 'row-1', task_id: TASK, asset_id: null, asset_value: null,
            risk_class: 'xss', outcome: 'tested', evidence: 'probe', reason: null,
            created_at: new Date('2026-11-23T20:00:00.000Z'),
          }],
        };
      }
      if (sql.includes('where task_id = $1 and asset_id is not distinct from')) {
        return { rows: [] };
      }
      return {
        rows: [{
          id: 'row-1', task_id: TASK, asset_id: null, asset_value: null,
          risk_class: 'xss', outcome: 'tested', evidence: 'probe', reason: null,
          created_at: '2026-11-23T20:00:00.000Z',
        }],
      };
    });
    const saved = await store.recordEntry({ taskId: TASK, riskClass: 'xss', outcome: 'tested', evidence: 'probe' });
    check('pg store: upsert maps snake_case → camelCase', saved.taskId === TASK && saved.riskClass === 'xss' && saved.outcome === 'tested' && saved.createdAt === '2026-11-23T20:00:00.000Z', saved);
    check('pg store: upsert SQL uses ON CONFLICT', seen[0]?.sql.includes('on conflict'), seen[0]?.sql);
    check('pg store: upsert passes params in column order', seen[0]?.params[0] === TASK && seen[0]?.params[3] === 'xss', seen[0]?.params);
    const listed = await store.listEntries(TASK);
    check('pg store: listEntries maps rows', listed.length === 1 && listed[0]?.evidence === 'probe', listed);
    const missing = await store.getEntry(TASK, null, 'idor');
    check('pg store: getEntry returns null on no rows', missing === null, missing);
  }

  // ── 7. Route: auth required, ownership enforced, summary returned ──
  {
    const store = new MemoryCoverageStore();
    await store.recordEntry({ taskId: TASK, riskClass: 'xss', outcome: 'finding', assetValue: 'https://example.com/search' });
    await store.recordEntry({ taskId: TASK, riskClass: 'headers', outcome: 'tested' });

    const appAuthed = Fastify();
    await appAuthed.register(async (instance) => {
      await coverageRoutes(instance, {
        coverage: store,
        getTask: async (id, userId) =>
          id === TASK && userId === 'u1' ? { id, userId } : null,
        authenticate: async (request) => {
          request.user = { id: 'u1', email: 'u1@example.com', plan: 'free', viaApiKey: false };
        },
      });
    });

    const ok = await appAuthed.inject({ method: 'GET', url: `/api/tasks/${TASK}/coverage` });
    const okBody = ok.json() as { taskId: string; summary: { untestedClasses: string[]; totalEntries: number }; entries: unknown[] };
    check('route: 200 for the owning user', ok.statusCode === 200, ok.statusCode);
    check('route: returns taskId + summary + entries', okBody.taskId === TASK && okBody.entries.length === 2 && okBody.summary.totalEntries === 2, okBody);
    check('route: summary marks untested classes', okBody.summary.untestedClasses.includes('idor') && !okBody.summary.untestedClasses.includes('xss'), okBody.summary.untestedClasses);

    const notMine = await appAuthed.inject({ method: 'GET', url: '/api/tasks/someone-elses-task/coverage' });
    check('route: 404 for a task that is not the caller’s', notMine.statusCode === 404, notMine.statusCode);

    const appNoAuth = Fastify();
    await appNoAuth.register(async (instance) => {
      await coverageRoutes(instance, {
        coverage: store,
        getTask: async (id, userId) => ({ id, userId }),
        // No authenticate passed: the route must fail closed.
      });
    });
    const denied = await appNoAuth.inject({ method: 'GET', url: `/api/tasks/${TASK}/coverage` });
    check('route: 401 when no authenticate is wired', denied.statusCode === 401, denied.statusCode);

    const appAnon = Fastify();
    await appAnon.register(async (instance) => {
      await coverageRoutes(instance, {
        coverage: store,
        getTask: async (id, userId) => ({ id, userId }),
        authenticate: async () => { /* sets no user */ },
      });
    });
    const anon = await appAnon.inject({ method: 'GET', url: `/api/tasks/${TASK}/coverage` });
    check('route: 401 when authenticate sets no user', anon.statusCode === 401, anon.statusCode);
  }

  if (failures > 0) { console.error(`${failures} coverage test(s) failed`); process.exit(1); }
  console.log('ALL COVERAGE TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('coverage test crashed', e); process.exit(1); });

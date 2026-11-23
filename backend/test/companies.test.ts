/**
 * Unit tests for companies + task↔company links + company routes
 * (src/companies/store.ts, src/companies/tasks.ts,
 * src/routes/companies.ts). No network, no DB.
 *
 * Run:  npx tsx test/companies.test.ts   (from backend/)
 */
import Fastify from 'fastify';
import {
  MemoryCompanyStore,
  PostgresCompanyStore,
  type CompanyQueryFn,
} from '../src/companies/store.js';
import {
  MemoryTaskCompanyStore,
  PostgresTaskCompanyStore,
  linkTaskToCompany,
  tasksForCompany,
  type TaskCompanyQueryFn,
} from '../src/companies/tasks.js';
import { MemoryGraphStore } from '../src/graph/store.js';
import { companyRoutes } from '../src/routes/companies.js';
import type { Database } from '../src/db/db.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

const USER = 'user-1';
const OTHER = 'user-2';

async function main() {
  // ── 1. Company CRUD ──
  {
    const store = new MemoryCompanyStore();
    const c = await store.create({
      userId: USER,
      name: ' Acme Corp ',
      scope: { domains: ['acme.com', ' API.Acme.com ', 'acme.com'], notes: '  Main client  ' },
    });
    check('company: create trims the name', c.name === 'Acme Corp', c);
    check('company: scope domains lowercased + deduped', JSON.stringify(c.scope.domains) === JSON.stringify(['acme.com', 'api.acme.com']), c.scope);
    check('company: scope notes trimmed', c.scope.notes === 'Main client', c.scope);
    check('company: records user + time', c.userId === USER && typeof c.createdAt === 'string', c);

    const listed = await store.list(USER);
    check('company: list returns the company', listed.length === 1 && listed[0]?.id === c.id, listed);
    check('company: list is empty for another user', (await store.list(OTHER)).length === 0);

    const got = await store.get(c.id, USER);
    check('company: get by id + user', got?.id === c.id, got);
    check('company: get returns null for another user', (await store.get(c.id, OTHER)) === null);

    const renamed = await store.rename({ id: c.id, userId: USER, name: 'Acme Ltd' });
    check('company: rename changes the name', renamed?.name === 'Acme Ltd', renamed);
    check('company: rename of another user’s company → null', (await store.rename({ id: c.id, userId: OTHER, name: 'Nope' })) === null);

    const removed = await store.remove(c.id, USER);
    check('company: remove returns the deleted row', removed?.id === c.id, removed);
    check('company: removed company no longer lists', (await store.list(USER)).length === 0);
    check('company: remove again → null', (await store.remove(c.id, USER)) === null);
  }

  // ── 2. One company per (user, name) ──
  {
    const store = new MemoryCompanyStore();
    await store.create({ userId: USER, name: 'Dup Co' });
    let threw = false;
    try {
      await store.create({ userId: USER, name: 'dup co' });
    } catch (e) {
      threw = (e as Error).message === 'company_name_exists';
    }
    check('company: duplicate name rejected (case-insensitive)', threw);
    // Same name under a different user is a different company.
    const other = await store.create({ userId: OTHER, name: 'Dup Co' });
    check('company: same name allowed for another user', other.userId === OTHER, other);

    const second = await store.create({ userId: USER, name: 'Second Co' });
    let threwRename = false;
    try {
      await store.rename({ id: second.id, userId: USER, name: 'Dup Co' });
    } catch (e) {
      threwRename = (e as Error).message === 'company_name_exists';
    }
    check('company: rename onto an existing name rejected', threwRename);

    let threwEmpty = false;
    try {
      await store.create({ userId: USER, name: '   ' });
    } catch (e) {
      threwEmpty = (e as Error).message === 'company_name_required';
    }
    check('company: blank name rejected', threwEmpty);
  }

  // ── 3. Task linking validates task existence + ownership ──
  {
    const graph = new MemoryGraphStore();
    const links = new MemoryTaskCompanyStore();
    const companies = new MemoryCompanyStore();
    const mine = await graph.createTask({ userId: USER, goalText: 'Test acme', targetUrl: 'https://acme.com' });
    const theirs = await graph.createTask({ userId: OTHER, goalText: 'Test other', targetUrl: 'https://other.com' });
    const company = await companies.create({ userId: USER, name: 'Link Co' });
    const getTask = (id: string) => graph.getTask(id);

    const { link, created } = await linkTaskToCompany(links, getTask, mine.id, company.id, USER);
    check('link: links an owned task', link.taskId === mine.id && link.companyId === company.id && created === true, link);
    const again = await linkTaskToCompany(links, getTask, mine.id, company.id, USER);
    check('link: re-linking is a no-op, not a duplicate', again.created === false && again.link.taskId === mine.id, again);
    check('link: tasksForCompany lists the task once', JSON.stringify(await tasksForCompany(links, company.id, USER)) === JSON.stringify([mine.id]));

    let threwMissing = false;
    try {
      await linkTaskToCompany(links, getTask, 'no-such-task', company.id, USER);
    } catch (e) {
      threwMissing = (e as Error).message === 'task_not_found';
    }
    check('link: unknown task refused', threwMissing);

    let threwOwned = false;
    try {
      await linkTaskToCompany(links, getTask, theirs.id, company.id, USER);
    } catch (e) {
      threwOwned = (e as Error).message === 'task_not_owned';
    }
    check('link: another user’s task refused', threwOwned);

    check('link: companiesForTask lists the company', JSON.stringify(await links.companiesForTask(mine.id, USER)) === JSON.stringify([company.id]));
    check('link: hasTasks true while linked', await links.hasTasks(company.id, USER));
    check('link: unlink removes the link', await links.unlink(mine.id, company.id, USER));
    check('link: hasTasks false after unlink', !(await links.hasTasks(company.id, USER)));
  }

  // ── 4. Remove refuses while tasks are linked ──
  {
    const graph = new MemoryGraphStore();
    const links = new MemoryTaskCompanyStore();
    const companies = new MemoryCompanyStore();
    const task = await graph.createTask({ userId: USER, goalText: 'Test', targetUrl: 'https://example.com' });
    const company = await companies.create({ userId: USER, name: 'Guarded Co' });
    await linkTaskToCompany(links, (id) => graph.getTask(id), task.id, company.id, USER);

    let threw = false;
    try {
      await companies.remove(company.id, USER, (id) => links.hasTasks(id, USER));
    } catch (e) {
      threw = (e as Error).message === 'company_has_linked_tasks';
    }
    check('company: remove refused while tasks linked', threw);
    check('company: refused company still exists', (await companies.get(company.id, USER)) !== null);

    await links.unlink(task.id, company.id, USER);
    const removed = await companies.remove(company.id, USER, (id) => links.hasTasks(id, USER));
    check('company: remove succeeds once unlinked', removed?.id === company.id, removed);
  }

  // ── 5. Postgres stores: SQL shape via a stub query function ──
  {
    const seen: { sql: string; params: unknown[] }[] = [];
    const query: CompanyQueryFn = async (sql, params) => {
      seen.push({ sql, params });
      if (/SELECT id FROM companies/.test(sql)) return { rows: [] };
      if (/INSERT INTO companies/.test(sql)) {
        return { rows: [{ id: 'c1', user_id: params[0], name: params[1], scope: params[2], created_at: new Date().toISOString() }] };
      }
      return { rows: [] };
    };
    const pg = new PostgresCompanyStore(query);
    const created = await pg.create({ userId: USER, name: 'Pg Co', scope: { domains: ['pg.example.com'] } });
    check('pg company: create maps the row', created.name === 'Pg Co' && created.scope.domains[0] === 'pg.example.com', created);
    check('pg company: duplicate pre-check runs first', /SELECT id FROM companies/.test(seen[0]?.sql ?? ''), seen[0]);
    check('pg company: insert passes user, name, scope json', seen[1]?.params[0] === USER && seen[1]?.params[1] === 'Pg Co', seen[1]);

    const linkSeen: { sql: string; params: unknown[] }[] = [];
    const linkQuery: TaskCompanyQueryFn = async (sql, params) => {
      linkSeen.push({ sql, params });
      if (/INSERT INTO task_companies/.test(sql)) {
        return { rows: [{ task_id: params[0], company_id: params[1], user_id: params[2], linked_at: new Date().toISOString() }] };
      }
      return { rows: [] };
    };
    const pgLinks = new PostgresTaskCompanyStore(linkQuery);
    const { link, created: linkCreated } = await pgLinks.link('t1', 'c1', USER);
    check('pg link: insert returns the link', link.taskId === 't1' && link.companyId === 'c1' && linkCreated === true, link);
    check('pg link: insert is idempotent via ON CONFLICT', /ON CONFLICT \(task_id, company_id\) DO NOTHING/.test(linkSeen[0]?.sql ?? ''), linkSeen[0]?.sql);
  }

  // ── 6. Routes: full flow over Fastify inject ──
  {
    const graph = new MemoryGraphStore();
    const companies = new MemoryCompanyStore();
    const links = new MemoryTaskCompanyStore();
    const task = await graph.createTask({ userId: USER, goalText: 'Assess acme', targetUrl: 'https://acme.com' });
    const othersCompany = await companies.create({ userId: OTHER, name: 'Not Mine' });

    const app = Fastify();
    await app.register(async (instance) => {
      await companyRoutes(instance, {
        db: {} as unknown as Database,
        companies,
        links,
        graph,
        authenticate: async (request) => {
          request.user = { id: USER, email: 'u1@example.com', plan: 'free', viaApiKey: false };
        },
      });
    });

    const createdRes = await app.inject({
      method: 'POST',
      url: '/api/companies',
      payload: { name: 'Route Co', scope: { domains: ['route.example.com'] } },
    });
    check('route: POST creates a company (201)', createdRes.statusCode === 201, createdRes.statusCode);
    const createdBody = createdRes.json() as { company: { id: string; name: string } };
    const companyId = createdBody.company.id;
    check('route: created company has the name', createdBody.company.name === 'Route Co', createdBody);

    const dupRes = await app.inject({
      method: 'POST',
      url: '/api/companies',
      payload: { name: 'route co' },
    });
    check('route: duplicate name → 409', dupRes.statusCode === 409, dupRes.statusCode);

    const listRes = await app.inject({ method: 'GET', url: '/api/companies' });
    const listBody = listRes.json() as { companies: { id: string }[] };
    check('route: GET lists only my companies', listRes.statusCode === 200 && listBody.companies.length === 1 && listBody.companies[0]?.id === companyId, listBody);

    const patchRes = await app.inject({
      method: 'PATCH',
      url: `/api/companies/${companyId}`,
      payload: { name: 'Route Co Renamed' },
    });
    check('route: PATCH renames (200)', patchRes.statusCode === 200 && (patchRes.json() as { company: { name: string } }).company.name === 'Route Co Renamed', patchRes.statusCode);

    const linkRes = await app.inject({
      method: 'POST',
      url: `/api/companies/${companyId}/tasks`,
      payload: { taskId: task.id },
    });
    check('route: POST link a task (201)', linkRes.statusCode === 201, { status: linkRes.statusCode, body: linkRes.body });

    const tasksRes = await app.inject({ method: 'GET', url: `/api/companies/${companyId}/tasks` });
    const tasksBody = tasksRes.json() as { tasks: { id: string }[] };
    check('route: GET tasks lists the linked task', tasksRes.statusCode === 200 && tasksBody.tasks.length === 1 && tasksBody.tasks[0]?.id === task.id, tasksBody);

    const deleteBlocked = await app.inject({ method: 'DELETE', url: `/api/companies/${companyId}` });
    check('route: DELETE refused while tasks linked (409)', deleteBlocked.statusCode === 409, deleteBlocked.statusCode);

    const linkAgain = await app.inject({
      method: 'POST',
      url: `/api/companies/${companyId}/tasks`,
      payload: { taskId: task.id },
    });
    check('route: re-linking the same task is idempotent (200)', linkAgain.statusCode === 200, linkAgain.statusCode);

    const othersTasks = await app.inject({ method: 'GET', url: `/api/companies/${othersCompany.id}/tasks` });
    check('route: another user’s company reads as 404', othersTasks.statusCode === 404, othersTasks.statusCode);

    const linkMissing = await app.inject({
      method: 'POST',
      url: `/api/companies/${companyId}/tasks`,
      payload: { taskId: 'no-such-task' },
    });
    check('route: linking an unknown task → 404', linkMissing.statusCode === 404, linkMissing.statusCode);

    await links.unlink(task.id, companyId, USER);
    const deleteOk = await app.inject({ method: 'DELETE', url: `/api/companies/${companyId}` });
    check('route: DELETE succeeds once unlinked (200)', deleteOk.statusCode === 200, deleteOk.statusCode);
    const deleteGone = await app.inject({ method: 'DELETE', url: `/api/companies/${companyId}` });
    check('route: DELETE of a gone company → 404', deleteGone.statusCode === 404, deleteGone.statusCode);
  }

  if (failures > 0) { console.error(`${failures} company test(s) failed`); process.exit(1); }
  console.log('ALL COMPANY TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('companies test crashed', e); process.exit(1); });

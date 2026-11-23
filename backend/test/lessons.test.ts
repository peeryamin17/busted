/**
 * Unit tests for cross-task lesson extraction (src/lessons/extract.ts),
 * the lesson store (src/lessons/store.ts) and the lesson routes
 * (src/routes/lessons.ts).
 * No network, no DB, no LLM.
 *
 * Run:  npx tsx test/lessons.test.ts   (from backend/)
 */
import Fastify from 'fastify';
import { MemoryDatabase } from '../src/db/db.js';
import { generateSessionToken, hashSessionToken } from '../src/auth/session.js';
import { MemoryGraphStore } from '../src/graph/store.js';
import { extractLessons } from '../src/lessons/extract.js';
import { MemoryLessonStore } from '../src/lessons/store.js';
import { lessonsRoutes } from '../src/routes/lessons.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

const TASK = {
  id: '11111111-1111-1111-1111-111111111111',
  userId: 'user-1',
  status: 'done',
  goalText: 'Assess example.com',
  targetUrl: 'https://example.com',
};

async function main() {
  // ── 1. Extraction: worked / failed / pattern from a completed task ──
  {
    const lessons = extractLessons({
      task: TASK,
      todolist: [
        { id: 't1', text: 'Enumerate subdomains', status: 'done' },
        { id: 't2', text: 'Probe GraphQL endpoint', status: 'skipped' },
        { id: 't3', text: 'Check headers', status: 'done' },
        { id: 't4', text: 'Fuzz login form', status: 'pending' },
      ],
      findings: [
        { category: 'xss', title: 'Reflected XSS in search', verified: true, severity: 'high' },
        { category: 'xss', title: 'Stored XSS in comments', verified: false, severity: 'medium' },
        { category: 'headers', title: 'Missing CSP', verified: false, severity: 'low' },
      ],
      retests: [
        { findingId: 'f-1', verdict: 'reproduced' },
        { findingId: 'f-2', verdict: 'inconclusive' },
      ],
      coverage: [
        { taskId: TASK.id, riskClass: 'xss', outcome: 'finding' },
        { taskId: TASK.id, riskClass: 'xss', outcome: 'finding' },
        { taskId: TASK.id, riskClass: 'headers', outcome: 'tested' },
      ],
    });
    const worked = lessons.filter((l) => l.kind === 'worked');
    const failed = lessons.filter((l) => l.kind === 'failed');
    const patterns = lessons.filter((l) => l.kind === 'pattern');
    check('extract: done steps + verified finding become worked', worked.length === 3, worked);
    check('extract: worked lesson names the completed step', worked.some((l) => l.title.includes('Enumerate subdomains')));
    check('extract: worked lesson names the verified finding', worked.some((l) => l.title.includes('Reflected XSS')));
    check('extract: skipped step + inconclusive retest become failed', failed.length === 2, failed);
    check('extract: pending steps produce no lesson', !lessons.some((l) => l.title.includes('Fuzz login')));
    check('extract: reproduced retest produces no lesson', !lessons.some((l) => l.title.includes('f-1')));
    check('extract: unverified finding is not worked', !worked.some((l) => l.title.includes('Stored XSS')));
    check('extract: repeated category becomes a pattern', patterns.some((l) => l.title.includes('Repeated xss findings (2)')), patterns);
    check('extract: repeated coverage class becomes a pattern', patterns.some((l) => l.title.includes('Repeated xss coverage hits (2)')), patterns);
    check('extract: every lesson carries evidence', lessons.every((l) => l.evidence.length > 0));
    check('extract: single-occurrence category is not a pattern', !patterns.some((l) => l.title.includes('headers')));
  }

  // ── 2. Extraction refuses an unfinished task ──
  {
    let threw = false;
    try {
      extractLessons({ task: { ...TASK, status: 'running' }, todolist: [], findings: [] });
    } catch (e) {
      threw = /task_not_completed/.test((e as Error).message);
    }
    check('extract: running task rejected', threw);
  }

  // ── 3. Secrets are redacted out of lesson detail ──
  {
    const secretKey = 'AKIAIOSFODNN7EXAMPLE';
    const lessons = extractLessons({
      task: TASK,
      todolist: [
        { id: 't1', text: `Found key ${secretKey} in a JS bundle`, status: 'done' },
      ],
      findings: [
        { category: 'secrets', title: `Leaked key ${secretKey}`, verified: true },
      ],
    });
    check('redact: secret key is not in any lesson title or detail',
      lessons.every((l) => !l.title.includes(secretKey) && !l.detail.includes(secretKey)), lessons);
    check('redact: redaction marker present instead', lessons.some((l) => l.detail.includes('[REDACTED')));
    const pw = extractLessons({
      task: TASK,
      todolist: [{ id: 't1', text: 'Login with password "hunter2-secret-value" worked', status: 'done' }],
      findings: [],
    });
    check('redact: password value scrubbed from detail', !pw[0].detail.includes('hunter2-secret-value'), pw);
  }

  // ── 4. Store: record/list + shadow mode gate ──
  {
    const store = new MemoryLessonStore();
    check('store: default mode is shadow', (await store.getMode('user-1')) === 'shadow');
    const recorded = await store.record({
      taskId: TASK.id, userId: 'user-1', kind: 'worked',
      title: 'Completed step: Enumerate subdomains', detail: 'd', evidence: ['todolist:t1'],
    });
    check('store: record assigns an id', typeof recorded.id === 'string' && recorded.id.length > 0);
    const listed = await store.listByUser('user-1');
    check('store: list shows the stored lesson', listed.length === 1 && listed[0].title.includes('Enumerate'), listed);
    check('store: other user sees nothing', (await store.listByUser('user-2')).length === 0);
    check('store: task filter narrows the list', (await store.listByUser('user-1', { taskId: 'nope' })).length === 0);
    check('store: lessonsForPrompt returns [] in shadow mode even with lessons stored',
      (await store.lessonsForPrompt('user-1')).length === 0);
    await store.setMode('user-1', 'off');
    check('store: mode can be set to off', (await store.getMode('user-1')) === 'off');
    check('store: lessonsForPrompt still returns [] when off',
      (await store.lessonsForPrompt('user-1')).length === 0);
    let threw = false;
    try {
      await store.setMode('user-1', 'inject' as never);
    } catch (e) {
      threw = /invalid_lesson_mode/.test((e as Error).message);
    }
    check('store: inject mode rejected at the store', threw);
  }

  // ── 5. Routes: extract, list, mode get/set, inject rejected ──
  {
    const db = new MemoryDatabase();
    const user = await db.createUser('user@example.com', 'unused-hash');
    const token = generateSessionToken();
    await db.createSession(user.id, hashSessionToken(token), new Date(Date.now() + 3600_000).toISOString());
    const cookie = `bs_session=${token}`;
    const graph = new MemoryGraphStore();
    const lessons = new MemoryLessonStore();
    const task = await graph.createTask({ userId: user.id, goalText: 'Assess example.com', targetUrl: 'https://example.com' });
    await graph.setTaskTodolist(task.id, [
      { id: 't1', text: 'Enumerate subdomains', status: 'done' },
      { id: 't2', text: 'Probe GraphQL endpoint', status: 'skipped' },
    ]);

    const app = Fastify();
    await lessonsRoutes(app as never, { db, graph, lessons });

    const unauth = await app.inject({ method: 'GET', url: '/api/lessons' });
    check('route: unauthenticated lessons list → 401', unauth.statusCode === 401);

    const tooEarly = await app.inject({
      method: 'POST', url: `/api/tasks/${task.id}/lessons/extract`, headers: { cookie },
    });
    check('route: extract from a running task → 409', tooEarly.statusCode === 409, tooEarly.body);

    await graph.updateTaskStatus(task.id, 'done');
    const extracted = await app.inject({
      method: 'POST', url: `/api/tasks/${task.id}/lessons/extract`, headers: { cookie },
    });
    const extractBody = JSON.parse(extracted.body) as { lessons: Array<{ kind: string; title: string }>; mode: string };
    check('route: extract from a done task → 200', extracted.statusCode === 200, extracted.body);
    check('route: extract stored 2 lessons (1 worked, 1 failed)',
      extractBody.lessons.length === 2 &&
      extractBody.lessons.some((l) => l.kind === 'worked') &&
      extractBody.lessons.some((l) => l.kind === 'failed'), extractBody);
    check('route: extract reports shadow mode', extractBody.mode === 'shadow');

    const listed = await app.inject({ method: 'GET', url: '/api/lessons', headers: { cookie } });
    const listBody = JSON.parse(listed.body) as { lessons: Array<{ title: string }>; mode: string };
    check('route: lesson list shows stored lessons', listBody.lessons.length === 2, listBody);
    const filtered = await app.inject({
      method: 'GET', url: `/api/lessons?taskId=${task.id}`, headers: { cookie },
    });
    check('route: lesson list filters by task', (JSON.parse(filtered.body) as { lessons: unknown[] }).lessons.length === 2);

    const modeGet = await app.inject({ method: 'GET', url: '/api/lessons/mode', headers: { cookie } });
    check('route: mode defaults to shadow', (JSON.parse(modeGet.body) as { mode: string }).mode === 'shadow');

    const inject = await app.inject({
      method: 'POST', url: '/api/lessons/mode', headers: { cookie },
      payload: { mode: 'inject' },
    });
    check("route: mode endpoint rejects 'inject'", inject.statusCode === 400, inject.body);
    const modeAfter = await app.inject({ method: 'GET', url: '/api/lessons/mode', headers: { cookie } });
    check("route: mode is still shadow after rejected 'inject'", (JSON.parse(modeAfter.body) as { mode: string }).mode === 'shadow');

    const off = await app.inject({
      method: 'POST', url: '/api/lessons/mode', headers: { cookie },
      payload: { mode: 'off' },
    });
    check("route: mode can be set to 'off'", off.statusCode === 200 && (JSON.parse(off.body) as { mode: string }).mode === 'off');

    const unknownTask = await app.inject({
      method: 'POST', url: '/api/tasks/00000000-0000-0000-0000-000000000000/lessons/extract', headers: { cookie },
    });
    check('route: extract for unknown task → 404', unknownTask.statusCode === 404);
  }

  if (failures > 0) { console.error(`${failures} lesson test(s) failed`); process.exit(1); }
  console.log('ALL LESSON TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('lessons test crashed', e); process.exit(1); });

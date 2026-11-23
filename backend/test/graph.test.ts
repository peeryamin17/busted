/**
 * Tests for the task + exploration-graph piece (graph/store.ts,
 * routes/tasks.ts). No network, no live Postgres: the memory store is
 * exercised directly, the Postgres store runs against a stub query
 * function (mapping + SQL shape only), and the routes run through
 * Fastify inject with a real session cookie.
 *
 * Run:  npx tsx test/graph.test.ts   (from backend/)
 *
 * NOTE on style: the repo's tests do not use node:test, they are plain
 * main() scripts with a check() helper (see depthLadder.test.ts). This
 * file follows that convention so it runs with the same runner.
 */
import { MemoryGraphStore, PostgresGraphStore, type GraphQueryFn } from '../src/graph/store.js';
import type { TaskStatus } from '../src/graph/types.js';

let failures = 0;
function check(name: string, ok: boolean, extra?: unknown) {
  if (ok) console.log('PASS', name);
  else {
    failures++;
    console.error('FAIL', name, extra ?? '');
  }
}

async function main() {
  const { MemoryDatabase } = await import('../src/db/db.js');
  const { generateSessionToken, hashSessionToken } = await import('../src/auth/session.js');
  const { tasksRoutes } = await import('../src/routes/tasks.js');
  const Fastify = (await import('fastify')).default;

  const USER_A = 'user-a';
  const USER_B = 'user-b';

  // ── 1. Memory store: task create / get / list ──────────────────────────
  const store = new MemoryGraphStore();
  const task = await store.createTask({
    userId: USER_A,
    goalText: 'Find XSS on the checkout flow',
    targetUrl: 'https://example.com/',
    scope: { mode: 'subdomain', includeSubdomains: false },
  });
  check('create: starts running', task.status === 'running', task.status);
  check('create: todolist starts empty', task.todolist.length === 0);
  check('create: scope round-trips', (task.scope as { mode?: string })?.mode === 'subdomain', task.scope);
  check('create: finishedAt starts null', task.finishedAt === null);

  const fetched = await store.getTask(task.id);
  check('get: returns the created task', fetched?.id === task.id && fetched?.goalText === 'Find XSS on the checkout flow');
  check('get: unknown id is null', (await store.getTask('no-such-id')) === null);

  const second = await store.createTask({ userId: USER_A, goalText: 'Second goal', targetUrl: 'https://example.com/2' });
  const other = await store.createTask({ userId: USER_B, goalText: 'Other user goal', targetUrl: 'https://example.com/3' });
  const mine = await store.listTasks(USER_A);
  check('list: newest first', mine[0]?.id === second.id && mine[1]?.id === task.id, mine.map((t) => t.id));
  check('list: only my tasks', mine.length === 2 && mine.every((t) => t.userId === USER_A));
  check('list: other user sees only theirs', (await store.listTasks(USER_B)).length === 1);

  // ── 2. Status transition matrix ────────────────────────────────────────
  const allowed: Array<[TaskStatus, TaskStatus]> = [
    ['running', 'paused'],
    ['paused', 'running'],
    ['running', 'done'],
    ['running', 'timeout'],
    ['running', 'failed'],
    ['paused', 'done'],
    ['paused', 'timeout'],
    ['paused', 'failed'],
  ];
  for (const [from, to] of allowed) {
    const t = await store.createTask({ userId: USER_A, goalText: `t ${from}->${to}`, targetUrl: 'https://example.com/' });
    if (from === 'paused') await store.updateTaskStatus(t.id, 'paused');
    const moved = await store.updateTaskStatus(t.id, to);
    check(`transition: ${from} -> ${to} allowed`, moved?.status === to, moved?.status);
    if (to === 'done' || to === 'timeout' || to === 'failed') {
      check(`transition: ${from} -> ${to} stamps finishedAt`, !!moved?.finishedAt, moved?.finishedAt);
    }
  }
  const rejected: Array<[TaskStatus, TaskStatus]> = [
    ['running', 'running'],
    ['paused', 'paused'],
    ['done', 'running'],
    ['done', 'paused'],
    ['done', 'done'],
    ['failed', 'running'],
    ['timeout', 'running'],
    ['timeout', 'done'],
  ];
  for (const [from, to] of rejected) {
    const t = await store.createTask({ userId: USER_A, goalText: `t ${from}->${to} rejected`, targetUrl: 'https://example.com/' });
    if (from === 'paused') await store.updateTaskStatus(t.id, 'paused');
    if (from === 'done' || from === 'failed' || from === 'timeout') {
      await store.updateTaskStatus(t.id, from);
    }
    let threw = false;
    try {
      await store.updateTaskStatus(t.id, to);
    } catch (e) {
      threw = (e as Error).message === `invalid_task_transition: ${from} -> ${to}`;
    }
    check(`transition: ${from} -> ${to} rejected`, threw);
  }
  check('transition: unknown task is null', (await store.updateTaskStatus('no-such-id', 'paused')) === null);

  // ── 3. Graph round-trip: nodes / edges / anchors / assets ─────────────
  const goal = await store.addNode({ taskId: task.id, kind: 'goal', label: task.goalText, detail: task.targetUrl });
  const intent = await store.addNode({ taskId: task.id, kind: 'intent', label: 'Probe checkout params', status: 'open' });
  const fact = await store.addNode({ taskId: task.id, kind: 'fact', label: 'Checkout reflects q param' });
  const finding = await store.addNode({ taskId: task.id, kind: 'finding', label: 'Reflected XSS in q' });
  const edge1 = await store.addEdge({ taskId: task.id, fromNodeId: goal.id, toNodeId: intent.id, rel: 'spawns' });
  const edge2 = await store.addEdge({ taskId: task.id, fromNodeId: intent.id, toNodeId: fact.id, rel: 'yields' });
  const edge3 = await store.addEdge({ taskId: task.id, fromNodeId: fact.id, toNodeId: finding.id, rel: 'proves' });
  const asset = await store.addAsset({ taskId: task.id, kind: 'endpoint', value: 'GET /checkout?q=', host: 'example.com' });
  const anchor = await store.addAnchor({ taskId: task.id, nodeId: finding.id, assetId: asset.id });

  const full = await store.getTaskGraph(task.id);
  check('graph: task + all parts round-trip', !!full && full.nodes.length === 4 && full.edges.length === 3 && full.anchors.length === 1 && full.assets.length === 1, full);
  check('graph: nodes keep insertion order', full?.nodes[0]?.id === goal.id && full?.nodes[3]?.id === finding.id);
  check('graph: edge rels preserved', full?.edges.map((e) => e.rel).join(',') === 'spawns,yields,proves');
  check('graph: anchor joins finding to asset', full?.anchors[0]?.id === anchor.id && full?.anchors[0]?.nodeId === finding.id && full?.anchors[0]?.assetId === asset.id);
  check('graph: unknown task is null', (await store.getTaskGraph('no-such-id')) === null);
  check('graph: edge endpoints are the stored ids', edge1.fromNodeId === goal.id && edge3.toNodeId === finding.id);

  // Validation at the store boundary: bad kinds/rels and cross-task links.
  let badKind = false;
  try {
    await store.addNode({ taskId: task.id, kind: 'attack' as never, label: 'x' });
  } catch {
    badKind = true;
  }
  check('graph: unknown node kind rejected', badKind);
  let badRel = false;
  try {
    await store.addEdge({ taskId: task.id, fromNodeId: goal.id, toNodeId: intent.id, rel: 'eats' as never });
  } catch {
    badRel = true;
  }
  check('graph: unknown edge rel rejected', badRel);
  let crossTaskEdge = false;
  try {
    // `other` is USER_B's task; goal/intent belong to USER_A's task.
    await store.addEdge({ taskId: other.id, fromNodeId: goal.id, toNodeId: intent.id, rel: 'spawns' });
  } catch {
    crossTaskEdge = true;
  }
  check('graph: edge cannot bridge two tasks', crossTaskEdge);
  let crossTaskAnchor = false;
  try {
    await store.addAnchor({ taskId: other.id, nodeId: finding.id, assetId: asset.id });
  } catch {
    crossTaskAnchor = true;
  }
  check('graph: anchor cannot bridge two tasks', crossTaskAnchor);
  let nodeOnMissingTask = false;
  try {
    await store.addNode({ taskId: 'no-such-id', kind: 'fact', label: 'x' });
  } catch {
    nodeOnMissingTask = true;
  }
  check('graph: node on missing task rejected', nodeOnMissingTask);

  // ── 4. Postgres store against a stub query (mapping + SQL shape) ──────
  const calls: Array<{ sql: string; params: unknown[] }> = [];
  const taskRow = {
    id: 'task-pg-1',
    user_id: USER_A,
    goal_text: 'PG goal',
    target_url: 'https://example.com/',
    scope: { mode: 'page' },
    status: 'running',
    scan_id: null,
    authorization_id: null,
    todolist: [],
    created_at: new Date('2026-11-23T10:00:00.000Z'),
    updated_at: new Date('2026-11-23T10:00:00.000Z'),
    finished_at: null,
  };
  const stubQuery: GraphQueryFn = async (sql, params) => {
    calls.push({ sql, params });
    if (sql.includes('INSERT INTO tasks')) return { rows: [{ ...taskRow, id: 'task-pg-new' }] };
    if (sql.includes('SELECT * FROM tasks WHERE id')) return { rows: [{ ...taskRow }] };
    if (sql.includes('SELECT * FROM tasks WHERE user_id')) return { rows: [{ ...taskRow }] };
    if (sql.includes('UPDATE tasks SET status')) {
      return { rows: [{ ...taskRow, status: params[0], finished_at: new Date('2026-11-23T11:00:00.000Z') }] };
    }
    if (sql.includes('SELECT id, task_id FROM exploration_nodes WHERE id = $1 OR id = $2')) {
      return { rows: [{ id: 'n1', task_id: 'task-pg-1' }, { id: 'n2', task_id: 'task-pg-1' }] };
    }
    if (sql.includes('INSERT INTO exploration_edges')) {
      return { rows: [{ id: 'e1', task_id: 'task-pg-1', from_node_id: 'n1', to_node_id: 'n2', rel: 'spawns', created_at: new Date('2026-11-23T10:05:00.000Z') }] };
    }
    if (sql.includes('SELECT * FROM exploration_nodes')) return { rows: [] };
    if (sql.includes('SELECT * FROM exploration_edges')) return { rows: [] };
    if (sql.includes('SELECT * FROM exploration_anchors')) return { rows: [] };
    if (sql.includes('SELECT * FROM assets')) return { rows: [] };
    return { rows: [] };
  };
  const pg = new PostgresGraphStore(stubQuery);
  const pgTask = await pg.createTask({ userId: USER_A, goalText: 'PG goal', targetUrl: 'https://example.com/' });
  check('pg: create maps the RETURNING row', pgTask.id === 'task-pg-new' && pgTask.status === 'running', pgTask);
  const createCall = calls.find((c) => c.sql.includes('INSERT INTO tasks'));
  check('pg: create uses $ params (no interpolation)', !!createCall && createCall.sql.includes('$1') && !createCall.sql.includes(USER_A));
  const pgFetched = await pg.getTask('task-pg-1');
  check('pg: Date rows map to ISO strings', pgFetched?.createdAt === '2026-11-23T10:00:00.000Z', pgFetched?.createdAt);
  check('pg: jsonb scope maps to an object', (pgFetched?.scope as { mode?: string })?.mode === 'page', pgFetched?.scope);
  const pgListed = await pg.listTasks(USER_A);
  check('pg: list maps rows', pgListed.length === 1 && pgListed[0]?.id === 'task-pg-1');
  const pgPaused = await pg.updateTaskStatus('task-pg-1', 'paused');
  check('pg: pause maps the updated row', pgPaused?.status === 'paused', pgPaused?.status);
  const pgEdge = await pg.addEdge({ taskId: 'task-pg-1', fromNodeId: 'n1', toNodeId: 'n2', rel: 'spawns' });
  check('pg: edge insert maps the RETURNING row', pgEdge.id === 'e1' && pgEdge.rel === 'spawns');
  let pgBadTransition = false;
  try {
    // Stubbed current status is 'running'; running -> running is invalid.
    await pg.updateTaskStatus('task-pg-1', 'running');
  } catch (e) {
    pgBadTransition = (e as Error).message === 'invalid_task_transition: running -> running';
  }
  check('pg: invalid transition rejected before any UPDATE', pgBadTransition);

  // ── 5. Routes: auth, create + goal node, isolation, pause/resume ──────
  const db = new MemoryDatabase();
  const routeStore = new MemoryGraphStore();
  const app = Fastify();
  await app.register(async (instance) => {
    await tasksRoutes(instance, { db, graph: routeStore });
  });
  await app.ready();

  const unauth = await app.inject({ method: 'GET', url: '/api/tasks' });
  check('route: GET /api/tasks without auth is 401', unauth.statusCode === 401, unauth.statusCode);

  const userA = await db.createUser('a@example.com', 'x');
  const userB = await db.createUser('b@example.com', 'x');
  const tokenA = generateSessionToken();
  await db.createSession(userA.id, hashSessionToken(tokenA), new Date(Date.now() + 3600_000).toISOString());
  const tokenB = generateSessionToken();
  await db.createSession(userB.id, hashSessionToken(tokenB), new Date(Date.now() + 3600_000).toISOString());
  const cookieA = `bs_session=${tokenA}`;
  const cookieB = `bs_session=${tokenB}`;

  const badGoal = await app.inject({
    method: 'POST',
    url: '/api/tasks',
    headers: { cookie: cookieA },
    payload: { goalText: '', targetUrl: 'https://example.com/' },
  });
  check('route: empty goalText is 400', badGoal.statusCode === 400, badGoal.statusCode);
  const badUrl = await app.inject({
    method: 'POST',
    url: '/api/tasks',
    headers: { cookie: cookieA },
    payload: { goalText: 'goal', targetUrl: 'ftp://example.com/' },
  });
  check('route: non-http targetUrl is 400', badUrl.statusCode === 400, badUrl.statusCode);
  const badAuthz = await app.inject({
    method: 'POST',
    url: '/api/tasks',
    headers: { cookie: cookieA },
    payload: { goalText: 'goal', targetUrl: 'https://example.com/', authorizationId: '00000000-0000-0000-0000-000000000000' },
  });
  check('route: unknown authorizationId is 400', badAuthz.statusCode === 400, badAuthz.statusCode);

  const created = await app.inject({
    method: 'POST',
    url: '/api/tasks',
    headers: { cookie: cookieA },
    payload: { goalText: 'Find XSS on checkout', targetUrl: 'https://example.com/checkout' },
  });
  const createdBody = created.json() as { task: { id: string; status: string } };
  check('route: POST /api/tasks is 201 with a running task', created.statusCode === 201 && createdBody.task.status === 'running', created.body);
  const taskId = createdBody.task.id;

  const detail = await app.inject({ method: 'GET', url: `/api/tasks/${taskId}`, headers: { cookie: cookieA } });
  const detailBody = detail.json() as { task: { id: string }; nodes: Array<{ kind: string; label: string }>; edges: unknown[] };
  check('route: GET detail returns task + graph', detail.statusCode === 200 && detailBody.task.id === taskId, detail.body);
  check('route: create seeds one goal node', detailBody.nodes.length === 1 && detailBody.nodes[0]?.kind === 'goal' && detailBody.nodes[0]?.label === 'Find XSS on checkout', detailBody.nodes);

  const listA = await app.inject({ method: 'GET', url: '/api/tasks', headers: { cookie: cookieA } });
  const listABody = listA.json() as { tasks: Array<{ id: string }> };
  check('route: list shows my task', listA.statusCode === 200 && listABody.tasks.some((t) => t.id === taskId));
  const listB = await app.inject({ method: 'GET', url: '/api/tasks', headers: { cookie: cookieB } });
  const listBBody = listB.json() as { tasks: Array<{ id: string }> };
  check('route: list hides another user’s task', listB.statusCode === 200 && !listBBody.tasks.some((t) => t.id === taskId), listBBody.tasks);
  const crossDetail = await app.inject({ method: 'GET', url: `/api/tasks/${taskId}`, headers: { cookie: cookieB } });
  check('route: another user’s task reads as 404', crossDetail.statusCode === 404, crossDetail.statusCode);
  const crossPause = await app.inject({ method: 'POST', url: `/api/tasks/${taskId}/pause`, headers: { cookie: cookieB } });
  check('route: another user cannot pause my task', crossPause.statusCode === 404, crossPause.statusCode);

  const paused = await app.inject({ method: 'POST', url: `/api/tasks/${taskId}/pause`, headers: { cookie: cookieA } });
  const pausedBody = paused.json() as { task: { status: string } };
  check('route: pause moves running -> paused', paused.statusCode === 200 && pausedBody.task.status === 'paused', paused.body);
  const pauseAgain = await app.inject({ method: 'POST', url: `/api/tasks/${taskId}/pause`, headers: { cookie: cookieA } });
  check('route: pausing a paused task is 409', pauseAgain.statusCode === 409, pauseAgain.statusCode);
  const resumed = await app.inject({ method: 'POST', url: `/api/tasks/${taskId}/resume`, headers: { cookie: cookieA } });
  const resumedBody = resumed.json() as { task: { status: string } };
  check('route: resume moves paused -> running', resumed.statusCode === 200 && resumedBody.task.status === 'running', resumed.body);
  const resumeAgain = await app.inject({ method: 'POST', url: `/api/tasks/${taskId}/resume`, headers: { cookie: cookieA } });
  check('route: resuming a running task is 409', resumeAgain.statusCode === 409, resumeAgain.statusCode);
  const missing = await app.inject({ method: 'POST', url: '/api/tasks/no-such-id/pause', headers: { cookie: cookieA } });
  check('route: pausing a missing task is 404', missing.statusCode === 404, missing.statusCode);

  await app.close();

  if (failures > 0) {
    console.error(`${failures} graph test(s) failed`);
    process.exit(1);
  }
  console.log('ALL GRAPH TESTS PASSED');
  process.exit(0);
}

main().catch((e) => {
  console.error('graph test crashed', e);
  process.exit(1);
});

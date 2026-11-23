/**
 * Unit tests for frozen-context Q&A (`/btw`) + its routes
 * (src/sidequestions/ask.ts, src/sidequestions/store.ts,
 * src/routes/sidequestions.ts). No network, no DB, the provider is
 * a fake returning canned text.
 *
 * Run:  npx tsx test/sidequestions.test.ts   (from backend/)
 */
import Fastify from 'fastify';
import {
  SNAPSHOT_MAX_CHARS,
  SNAPSHOT_TRUNCATION_MARKER,
  askSideQuestion,
  buildSnapshot,
  recordSideQuestion,
} from '../src/sidequestions/ask.js';
import { MemorySideQuestionStore } from '../src/sidequestions/store.js';
import { MemoryGraphStore } from '../src/graph/store.js';
import { sideQuestionRoutes } from '../src/routes/sidequestions.js';
import type { Database } from '../src/db/db.js';
import { makeCompletion, type LLMProvider } from '../src/llm/provider.js';
import type { TaskRecord } from '../src/graph/types.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

const USER = 'user-1';

function makeTask(overrides: Partial<TaskRecord> = {}): TaskRecord {
  return {
    id: '11111111-1111-1111-1111-111111111111',
    userId: USER,
    goalText: 'Assess example.com for XSS and IDOR',
    targetUrl: 'https://example.com',
    scope: null,
    status: 'running',
    scanId: null,
    authorizationId: null,
    todolist: [{ id: 't1', text: 'Probe search for reflected XSS', status: 'done' }],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    finishedAt: null,
    ...overrides,
  };
}

/** Fake provider: canned answer, counts invocations. */
function makeFakeProvider(answer = 'Canned answer from the snapshot.'): { provider: LLMProvider; calls: { count: number; lastReq?: unknown } } {
  const calls: { count: number; lastReq?: unknown } = { count: 0 };
  const provider: LLMProvider = {
    name: 'fake-test',
    async complete(req) {
      calls.count++;
      calls.lastReq = req;
      return makeCompletion(answer, { inputTokens: 10, outputTokens: 5 });
    },
  };
  return { provider, calls };
}

async function main() {
  // ── 1. Snapshot: goal, intents, facts, findings with severity ──
  {
    const task = makeTask();
    const snapshot = buildSnapshot({
      task,
      nodes: [
        { id: 'n1', taskId: task.id, kind: 'intent', label: 'Probe search endpoint', detail: null, status: 'done', createdAt: task.createdAt },
        { id: 'n2', taskId: task.id, kind: 'fact', label: 'Search reflects the q parameter', detail: 'seen in response body', status: null, createdAt: task.createdAt },
        { id: 'n3', taskId: task.id, kind: 'hint', label: 'Check the admin panel next', detail: null, status: null, createdAt: task.createdAt },
      ],
      findings: [
        { title: 'Reflected XSS in search', severity: 'high', category: 'xss', location: 'https://example.com/search?q=', description: 'The q parameter is reflected without encoding.' },
        { title: 'Missing security header', severity: 'low', category: 'headers', location: 'https://example.com', description: 'No Content-Security-Policy header.' },
      ],
      coverage: { tested: ['xss', 'headers'], untested: ['idor', 'sqli'] },
    });
    check('snapshot: carries the goal', snapshot.includes('Assess example.com for XSS and IDOR'), snapshot);
    check('snapshot: carries the target', snapshot.includes('https://example.com'), snapshot);
    check('snapshot: carries intent + fact + note nodes', snapshot.includes('Probe search endpoint') && snapshot.includes('Search reflects the q parameter') && snapshot.includes('Check the admin panel next'), snapshot);
    check('snapshot: findings carry severity', snapshot.includes('[high] Reflected XSS in search') && snapshot.includes('[low] Missing security header'), snapshot);
    check('snapshot: coverage marks untested classes', snapshot.includes('idor') && snapshot.includes('Untested'), snapshot);
    check('snapshot: small snapshot is not truncated', !snapshot.includes(SNAPSHOT_TRUNCATION_MARKER), snapshot);
    check('snapshot: within the cap', snapshot.length <= SNAPSHOT_MAX_CHARS, snapshot.length);
  }

  // ── 2. Snapshot bounding: huge finding list truncates, secrets never survive ──
  {
    const task = makeTask();
    const findings = Array.from({ length: 200 }, (_, i) => ({
      title: `Finding ${i} — verbose title padded out to eat snapshot budget quickly`,
      severity: i % 10 === 0 ? 'critical' : 'medium',
      category: 'xss',
      location: 'https://example.com/search',
      description:
        `This finding description is deliberately long so the list blows past the snapshot cap. ` +
        `Leaked credential seen in the page: sk_live_abcdefghijklmnop1234 and AKIAIOSFODNN7EXAMPLE — ` +
        `these must never reach the snapshot. `.repeat(3),
    }));
    const snapshot = buildSnapshot({ task, findings });
    check('snapshot: huge list stays within the 8000-char cap', snapshot.length <= SNAPSHOT_MAX_CHARS, snapshot.length);
    check('snapshot: truncation is marked, never silent', snapshot.includes(SNAPSHOT_TRUNCATION_MARKER), snapshot.slice(-200));
    check('snapshot: not all findings shown', snapshot.includes('of 200') && !snapshot.includes('Finding 199'), snapshot.slice(0, 400));
    check('snapshot: fake Stripe-style key is absent', !snapshot.includes('sk_live_abcdefghijklmnop1234'), snapshot);
    check('snapshot: fake AWS key is absent', !snapshot.includes('AKIAIOSFODNN7EXAMPLE'), snapshot);
    check('snapshot: redaction markers replace the secrets', snapshot.includes('[REDACTED:'), snapshot);
    // A finding shown in full is never cut mid-block: every shown
    // finding line ends before the marker, and the marker is the last line.
    const lines = snapshot.trim().split('\n');
    check('snapshot: truncation marker is the last line', lines[lines.length - 1]?.startsWith(SNAPSHOT_TRUNCATION_MARKER) ?? false, lines.slice(-2));
  }

  // ── 3. askSideQuestion: exactly one LLM call, frozen-snapshot prompt ──
  {
    const { provider, calls } = makeFakeProvider();
    const snapshot = buildSnapshot({ task: makeTask(), findings: [] });
    const result = await askSideQuestion({ provider, snapshot, question: 'What did the search probe find?' });
    check('ask: exactly one provider call', calls.count === 1, calls.count);
    check('ask: returns the canned answer', result.answer === 'Canned answer from the snapshot.', result);
    check('ask: returns the provider name as model', result.model === 'fake-test', result);
    check('ask: snapshotChars matches the snapshot', result.snapshotChars === snapshot.length, result);
    check('ask: tokens sum input + output', result.tokens === 15, result);
    const req = calls.lastReq as { messages: { role: string; content: string }[]; temperature: number };
    check('ask: system prompt says the context is frozen', req.messages[0]?.content.includes('FROZEN SNAPSHOT'), req.messages[0]);
    check('ask: system prompt forbids inventing findings', req.messages[0]?.content.includes('Do not invent findings'), req.messages[0]);
    check('ask: temperature is 0.2', req.temperature === 0.2, req.temperature);
    check('ask: user message carries snapshot + question', req.messages[1]?.content.includes(snapshot.slice(0, 50)) && req.messages[1]?.content.includes('What did the search probe find?'), req.messages[1]?.content.slice(0, 120));
  }

  // ── 4. Question validation ──
  {
    const { provider } = makeFakeProvider();
    let threwEmpty = false;
    try {
      await askSideQuestion({ provider, snapshot: 'snap', question: '   ' });
    } catch (e) {
      threwEmpty = (e as Error).message === 'side_question_empty';
    }
    check('ask: empty question rejected', threwEmpty);
    let threwLong = false;
    try {
      await askSideQuestion({ provider, snapshot: 'snap', question: 'x'.repeat(2001) });
    } catch (e) {
      threwLong = (e as Error).message === 'side_question_too_long';
    }
    check('ask: oversize question rejected', threwLong);
    // Exactly 2000 chars is allowed.
    const ok = await askSideQuestion({ provider, snapshot: 'snap', question: 'x'.repeat(2000) });
    check('ask: 2000-char question allowed', ok.answer.length > 0, ok);
  }

  // ── 5. Record + list, scoped per task ──
  {
    const store = new MemorySideQuestionStore();
    const taskA = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    const taskB = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
    await recordSideQuestion(store, { taskId: taskA, userId: USER, question: 'First?', answer: 'One.', snapshotChars: 100 });
    await recordSideQuestion(store, { taskId: taskA, userId: USER, question: 'Second?', answer: 'Two.', snapshotChars: 120 });
    await recordSideQuestion(store, { taskId: taskB, userId: USER, question: 'Other task?', answer: 'Three.', snapshotChars: 90 });
    const listedA = await store.listForTask(taskA, USER);
    check('store: lists Q&As for the task', listedA.length === 2, listedA);
    check('store: both questions present', listedA.some((q) => q.question === 'First?') && listedA.some((q) => q.question === 'Second?'), listedA);
    check('store: other task’s Q&A not listed', (await store.listForTask(taskB, USER)).length === 1);
    check('store: other user sees nothing', (await store.listForTask(taskA, 'user-2')).length === 0);
    check('store: record carries snapshot size', listedA.every((q) => q.snapshotChars > 0), listedA);

    let threw = false;
    try {
      await recordSideQuestion(store, { taskId: taskA, userId: USER, question: ' ', answer: 'x', snapshotChars: 1 });
    } catch (e) {
      threw = (e as Error).message === 'side_question_empty';
    }
    check('store: recording an empty question rejected', threw);
  }

  // ── 6. Routes: ask, list, 404s, 400s ──
  {
    const graph = new MemoryGraphStore();
    const questions = new MemorySideQuestionStore();
    const task = await graph.createTask({ userId: USER, goalText: 'Assess example.com', targetUrl: 'https://example.com' });
    await graph.addNode({ taskId: task.id, kind: 'fact', label: 'Search reflects q' });
    const { provider, calls } = makeFakeProvider('The search probe found a reflection.');

    const app = Fastify();
    await app.register(async (instance) => {
      await sideQuestionRoutes(instance, {
        db: {} as unknown as Database,
        graph,
        provider,
        questions,
        listFindings: async () => [
          {
            id: 'f1',
            scanId: 's1',
            category: 'xss',
            title: 'Reflected XSS in search',
            description: 'q is reflected without encoding.',
            severity: 'high',
            confidence: 'high',
            trapProbability: 0,
            honeypotSuspect: false,
            location: 'https://example.com/search',
            reproSteps: [],
            remediation: 'Encode output.',
            references: [],
            createdAt: new Date().toISOString(),
          },
        ],
        authenticate: async (request) => {
          request.user = { id: USER, email: 'u1@example.com', plan: 'free', viaApiKey: false };
        },
      });
    });

    const askRes = await app.inject({
      method: 'POST',
      url: `/api/tasks/${task.id}/btw`,
      payload: { question: 'What did the search probe find?' },
    });
    check('route: POST asks and records (200)', askRes.statusCode === 200, { status: askRes.statusCode, body: askRes.body });
    const askBody = askRes.json() as { answer: string; model: string; tokens: number; snapshotChars: number; question: string };
    check('route: answer + model + tokens returned', askBody.answer === 'The search probe found a reflection.' && askBody.model === 'fake-test' && askBody.tokens === 15, askBody);
    check('route: snapshotChars recorded', askBody.snapshotChars > 0, askBody);
    check('route: exactly one LLM call for the ask', calls.count === 1, calls.count);

    const listRes = await app.inject({ method: 'GET', url: `/api/tasks/${task.id}/btw` });
    const listBody = listRes.json() as { taskId: string; questions: { question: string }[] };
    check('route: GET lists the recorded Q&A', listRes.statusCode === 200 && listBody.questions.length === 1 && listBody.questions[0]?.question === 'What did the search probe find?', listBody);

    const emptyRes = await app.inject({
      method: 'POST',
      url: `/api/tasks/${task.id}/btw`,
      payload: { question: '   ' },
    });
    check('route: empty question → 400', emptyRes.statusCode === 400, emptyRes.statusCode);
    const longRes = await app.inject({
      method: 'POST',
      url: `/api/tasks/${task.id}/btw`,
      payload: { question: 'x'.repeat(2001) },
    });
    check('route: oversize question → 400', longRes.statusCode === 400, longRes.statusCode);
    check('route: rejected questions made no LLM call', calls.count === 1, calls.count);

    const notMinePost = await app.inject({
      method: 'POST',
      url: '/api/tasks/someone-elses-task/btw',
      payload: { question: 'Hello?' },
    });
    check('route: another user’s task → 404 on POST', notMinePost.statusCode === 404, notMinePost.statusCode);
    const notMineGet = await app.inject({ method: 'GET', url: '/api/tasks/someone-elses-task/btw' });
    check('route: another user’s task → 404 on GET', notMineGet.statusCode === 404, notMineGet.statusCode);
    check('route: 404s made no LLM call', calls.count === 1, calls.count);
  }

  if (failures > 0) { console.error(`${failures} side-question test(s) failed`); process.exit(1); }
  console.log('ALL SIDE-QUESTION TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('sidequestions test crashed', e); process.exit(1); });

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import type { Database } from '../db/db.js';
import type { GraphStore } from '../graph/store.js';
import type { TaskRecord } from '../graph/types.js';
import type { Finding } from '../types.js';
import type { LLMProvider } from '../llm/provider.js';
import {
  askSideQuestion,
  buildSnapshot,
  recordSideQuestion,
  type SnapshotFinding,
} from '../sidequestions/ask.js';
import type { SideQuestionStore } from '../sidequestions/store.js';

/**
 * Side-question routes.
 *
 *   POST /api/tasks/:id/btw - ask one question about a task, answered
 *        from a frozen snapshot of its context (one provider call, no
 *        tools); the Q&A is recorded against the task.
 *   GET  /api/tasks/:id/btw - the task's recorded Q&As, newest first.
 *
 * Member-authenticated; the task must belong to the caller, another
 * user's task reads as 404. The question must be non-empty and at most
 * 2000 characters. The provider, graph store, and question store are
 * injected deps, so tests can pass a fake provider and a memory graph
 * store. Auth is optional only for tests; when omitted the route fails
 * closed with 401. Registered in server.ts, not here.
 */

export interface SideQuestionRouteDeps {
  db: Database;
  graph: GraphStore;
  provider: LLMProvider;
  questions: SideQuestionStore;
  /**
   * Findings for a task, for the snapshot. Defaults to the task's
   * scan findings via db; inject a fake in tests.
   */
  listFindings?: (task: TaskRecord) => Promise<Finding[]>;
  authenticate?: (request: FastifyRequest, reply: FastifyReply) => Promise<void> | void;
}

const askSchema = z.object({
  question: z.string(),
});

function toSnapshotFinding(f: Finding): SnapshotFinding {
  return {
    title: f.title,
    severity: f.severity,
    category: f.category,
    location: f.location,
    description: f.description,
  };
}

export async function sideQuestionRoutes(app: FastifyInstance, deps: SideQuestionRouteDeps): Promise<void> {
  const { db, graph, provider, questions } = deps;
  const authenticate =
    deps.authenticate ??
    buildAuthenticate(db);
  const listFindings =
    deps.listFindings ??
    (async (task: TaskRecord): Promise<Finding[]> => {
      if (!task.scanId) return [];
      return db.listFindings(task.scanId).catch(() => []);
    });

  app.post('/api/tasks/:id/btw', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const body = askSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    const question = body.data.question.trim();
    if (!question) {
      return reply.status(400).send({ error: 'Question must not be empty' });
    }
    if (question.length > 2000) {
      return reply.status(400).send({ error: 'Question must be at most 2000 characters' });
    }
    const task = await graph.getTask(id);
    if (!task || task.userId !== user.id) {
      return reply.status(404).send({ error: 'Task not found' });
    }
    const [nodes, findings] = await Promise.all([
      graph.listNodes(id),
      listFindings(task),
    ]);
    const snapshot = buildSnapshot({
      task,
      nodes,
      findings: findings.map(toSnapshotFinding),
    });
    let result;
    try {
      result = await askSideQuestion({ provider, snapshot, question });
    } catch (err) {
      return reply.status(502).send({ error: `Side question failed: ${(err as Error).message}` });
    }
    const record = await recordSideQuestion(questions, {
      taskId: id,
      userId: user.id,
      question,
      answer: result.answer,
      snapshotChars: result.snapshotChars,
    });
    return reply.send({
      ...record,
      model: result.model,
      tokens: result.tokens,
    });
  });

  app.get('/api/tasks/:id/btw', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const task = await graph.getTask(id);
    if (!task || task.userId !== user.id) {
      return reply.status(404).send({ error: 'Task not found' });
    }
    const list = await questions.listForTask(id, user.id);
    return { taskId: id, questions: list };
  });
}

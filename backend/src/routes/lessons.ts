import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import type { Database } from '../db/db.js';
import type { GraphStore } from '../graph/store.js';
import { extractLessons } from '../lessons/extract.js';
import { assertLessonMode, type LessonStore } from '../lessons/store.js';

/**
 * Lesson routes.
 *
 *   POST /api/tasks/:id/lessons/extract - extract rule-based lessons
 *     from a completed task and store them (shadow mode)
 *   GET  /api/lessons                   - my stored lessons (filter by taskId)
 *   GET  /api/lessons/mode             - my lesson mode (shadow | off)
 *   POST /api/lessons/mode             - set my lesson mode (shadow | off)
 *
 * Member-authenticated; scoped to the caller, another user's task reads
 * as 404. Lessons are stored for review and never reach agent prompts:
 * there is no 'inject' mode, and lessonsForPrompt returns [] always.
 * Promotion to active prompt use needs the operator's say-so and a code
 * change. Registered in server.ts, not here.
 */

export interface LessonRouteDeps {
  db: Database;
  graph: GraphStore;
  lessons: LessonStore;
}

const modeSchema = z.object({
  mode: z.string(),
});

export async function lessonsRoutes(app: FastifyInstance, deps: LessonRouteDeps): Promise<void> {
  const { db, graph, lessons } = deps;
  const authenticate = buildAuthenticate(db);

  app.post('/api/tasks/:id/lessons/extract', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const task = await graph.getTask(id);
    if (!task || task.userId !== user.id) {
      return reply.status(404).send({ error: 'Task not found' });
    }
    if (task.status !== 'done' && task.status !== 'timeout' && task.status !== 'failed') {
      return reply
        .status(409)
        .send({ error: `Cannot extract lessons from a ${task.status} task` });
    }
    // Findings come from the task's scan (when it has one); retests
    // are listed per task. A task with no scan simply has no findings
    // to learn from, the todolist still yields lessons.
    const findings = task.scanId ? await db.listFindings(task.scanId) : [];
    const retests = await db.listRetests(task.id);
    const extracted = extractLessons({
      task: {
        id: task.id,
        userId: task.userId,
        status: task.status,
        goalText: task.goalText,
        targetUrl: task.targetUrl,
      },
      todolist: task.todolist,
      findings: findings.map((f) => ({
        category: f.category,
        title: f.title,
        verified: f.verification?.status === 'verified',
        severity: f.severity,
      })),
      retests: retests.map((r) => ({ findingId: r.findingId, verdict: r.verdict })),
    });
    const stored = [];
    for (const lesson of extracted) {
      stored.push(
        await lessons.record({
          taskId: lesson.taskId,
          userId: lesson.userId,
          kind: lesson.kind,
          title: lesson.title,
          detail: lesson.detail,
          evidence: lesson.evidence,
        }),
      );
    }
    return reply.send({ lessons: stored, mode: await lessons.getMode(user.id) });
  });

  app.get('/api/lessons', { preHandler: authenticate }, async (request) => {
    const user = requireUser(request);
    const query = request.query as { taskId?: string };
    const stored = await lessons.listByUser(user.id, { taskId: query.taskId });
    return { lessons: stored, mode: await lessons.getMode(user.id) };
  });

  app.get('/api/lessons/mode', { preHandler: authenticate }, async (request) => {
    const user = requireUser(request);
    return { mode: await lessons.getMode(user.id) };
  });

  app.post('/api/lessons/mode', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const body = modeSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    try {
      assertLessonMode(body.data.mode);
    } catch (err) {
      // 'inject' (and anything else) is rejected here: there is no
      // inject mode in this pass, by design, shadow is the default
      // and the only active mode.
      return reply.status(400).send({ error: (err as Error).message });
    }
    const mode = await lessons.setMode(user.id, body.data.mode);
    return reply.send({ mode });
  });
}

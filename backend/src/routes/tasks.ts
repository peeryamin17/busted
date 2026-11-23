import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import type { Database } from '../db/db.js';
import type { GraphStore } from '../graph/store.js';
import type { TaskStatus } from '../graph/types.js';

/**
 * Task routes.
 *
 *   POST /api/tasks            - create a task (goal + target) + its goal node
 *   GET  /api/tasks            - my tasks, newest first
 *   GET  /api/tasks/:id        - one task + its full exploration graph
 *   POST /api/tasks/:id/pause  - running → paused
 *   POST /api/tasks/:id/resume - paused → running
 *
 * Member-authenticated; scoped to the caller, another user's task reads
 * as 404. Registered in server.ts, not here.
 */

export interface TaskRouteDeps {
  db: Database;
  graph: GraphStore;
}

const createTaskSchema = z.object({
  goalText: z.string().min(1).max(5000),
  targetUrl: z.string().min(1).max(2000),
  scope: z.record(z.string(), z.unknown()).optional(),
  authorizationId: z.string().uuid().optional(),
});

function validHttpUrl(raw: string): URL | null {
  try {
    const url = new URL(raw);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    return url;
  } catch {
    return null;
  }
}

export async function tasksRoutes(app: FastifyInstance, deps: TaskRouteDeps): Promise<void> {
  const { db, graph } = deps;
  const authenticate = buildAuthenticate(db);

  app.post('/api/tasks', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const body = createTaskSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    const target = validHttpUrl(body.data.targetUrl);
    if (!target) {
      return reply.status(400).send({ error: 'targetUrl must be an http(s) URL' });
    }
    // An authorization id, when given, must be one of the caller's own
    // records, a stray id from another account is a 400, not a link.
    if (body.data.authorizationId) {
      const authz = await db.getAuthorization(body.data.authorizationId);
      if (!authz || authz.userId !== user.id) {
        return reply.status(400).send({ error: 'Unknown authorization' });
      }
    }
    const task = await graph.createTask({
      userId: user.id,
      goalText: body.data.goalText.trim(),
      targetUrl: target.toString(),
      scope: body.data.scope ?? null,
      authorizationId: body.data.authorizationId ?? null,
    });
    // Every task starts with its goal node, the root of the graph the
    // planner will grow intents, facts and findings from.
    await graph.addNode({
      taskId: task.id,
      kind: 'goal',
      label: task.goalText,
      detail: task.targetUrl,
    });
    return reply.status(201).send({ task });
  });

  app.get('/api/tasks', { preHandler: authenticate }, async (request) => {
    const user = requireUser(request);
    const tasks = await graph.listTasks(user.id);
    return { tasks };
  });

  app.get('/api/tasks/:id', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const task = await graph.getTask(id);
    if (!task || task.userId !== user.id) {
      return reply.status(404).send({ error: 'Task not found' });
    }
    const full = await graph.getTaskGraph(id);
    // getTaskGraph returns null only when the task vanished between the
    // two reads; the task just read is the honest fallback.
    return full ?? { task, nodes: [], edges: [], anchors: [], assets: [] };
  });

  for (const [action, to] of [['pause', 'paused'], ['resume', 'running']] as const) {
    app.post(`/api/tasks/:id/${action}`, { preHandler: authenticate }, async (request, reply) => {
      const user = requireUser(request);
      const { id } = request.params as { id: string };
      const task = await graph.getTask(id);
      if (!task || task.userId !== user.id) {
        return reply.status(404).send({ error: 'Task not found' });
      }
      try {
        const updated = await graph.updateTaskStatus(id, to as TaskStatus);
        return reply.send({ task: updated });
      } catch (err) {
        const message = (err as Error).message;
        if (message.startsWith('invalid_task_transition')) {
          return reply.status(409).send({ error: `Cannot ${action} a ${task.status} task` });
        }
        throw err;
      }
    });
  }
}

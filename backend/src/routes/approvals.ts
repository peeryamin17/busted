import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import { isAdminEmail } from '../auth/session.js';
import type { Database } from '../db/db.js';
import type { GraphStore } from '../graph/store.js';
import type { ApprovalStore } from '../approvals/store.js';
import type { ApprovalRuleStore } from '../approvals/rules.js';
import { assertRuleDecision, assertRulePattern } from '../approvals/rules.js';
import { decide } from '../approvals/service.js';

/**
 * Approval routes.
 *
 *   GET  /api/tasks/:id/approvals
 *        - this task's approvals, pending first, then newest first.
 *   POST /api/tasks/:id/approvals/:approvalId/decide {decision}
 *        - allow or deny one pending approval; decidedBy is the caller.
 *        A denied step is recorded as 'denied' here; the swarm caller
 *        records the step itself as skipped and never auto-retries it.
 *   POST /api/tasks/:id/approvals/batch-decide {ids, decision}
 *        - decide each pending one; per-id results, partial success
 *        allowed (an already-decided id reports its error, not a 500).
 *   POST /api/tasks/:id/approvals/rules {pattern, decision, ...}
 *        - create a standing allow / ask / deny rule, scoped to this
 *        task (or to all of the caller's tasks with scope 'all'); an
 *        allow rule created with alwaysAllow is the "always allow this
 *        kind" rule the UI posts from the decide action.
 *
 * Member-authenticated; scoped to the caller, another user's task reads
 * as 404. Registered in server.ts, not here.
 */

export interface ApprovalRouteDeps {
  db: Database;
  graph: GraphStore;
  approvals: ApprovalStore;
  rules: ApprovalRuleStore;
}

const decideSchema = z.object({
  decision: z.enum(['allow', 'deny']),
});

const batchDecideSchema = z.object({
  ids: z.array(z.string().min(1)).min(1).max(100),
  decision: z.enum(['allow', 'deny']),
});

const createRuleSchema = z.object({
  pattern: z.object({
    kind: z.enum(['tool', 'target-host', 'category']),
    value: z.string().min(1).max(500),
  }),
  decision: z.enum(['allow', 'ask', 'deny']),
  alwaysAllow: z.boolean().optional(),
  scope: z.enum(['task', 'all']).optional(),
});

export async function approvalsRoutes(app: FastifyInstance, deps: ApprovalRouteDeps): Promise<void> {
  const { db, graph, approvals, rules } = deps;
  const authenticate = buildAuthenticate(db);

  /** The task must exist and belong to the caller (or the caller is admin). */
  async function resolveTask(taskId: string, userId: string, userEmail: string) {
    const task = await graph.getTask(taskId).catch(() => null);
    if (!task || (task.userId !== userId && !isAdminEmail(userEmail))) return null;
    return task;
  }

  app.get('/api/tasks/:id/approvals', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const task = await resolveTask(id, user.id, user.email);
    if (!task) {
      return reply.status(404).send({ error: 'Task not found' });
    }
    const rows = await approvals.listForTask(id);
    return { taskId: id, approvals: rows };
  });

  app.post(
    '/api/tasks/:id/approvals/:approvalId/decide',
    { preHandler: authenticate },
    async (request, reply) => {
      const user = requireUser(request);
      const { id, approvalId } = request.params as { id: string; approvalId: string };
      const body = decideSchema.safeParse(request.body);
      if (!body.success) {
        return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
      }
      const task = await resolveTask(id, user.id, user.email);
      if (!task) {
        return reply.status(404).send({ error: 'Task not found' });
      }
      const approval = await approvals.get(approvalId);
      if (!approval || approval.taskId !== id) {
        return reply.status(404).send({ error: 'Approval not found' });
      }
      try {
        const decided = await decide(approvals, approvalId, body.data.decision, user.id);
        return reply.send({ approval: decided });
      } catch (err) {
        const message = (err as Error).message;
        if (message.startsWith('approval_not_pending')) {
          return reply.status(409).send({ error: `Approval already ${approval.status}` });
        }
        throw err;
      }
    },
  );

  app.post(
    '/api/tasks/:id/approvals/batch-decide',
    { preHandler: authenticate },
    async (request, reply) => {
      const user = requireUser(request);
      const { id } = request.params as { id: string };
      const body = batchDecideSchema.safeParse(request.body);
      if (!body.success) {
        return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
      }
      const task = await resolveTask(id, user.id, user.email);
      if (!task) {
        return reply.status(404).send({ error: 'Task not found' });
      }
      // Only ids that belong to this task are decided; anything else is
      // reported per-id instead of leaking whether it exists elsewhere.
      const results = [];
      for (const approvalId of body.data.ids) {
        const approval = await approvals.get(approvalId);
        if (!approval || approval.taskId !== id) {
          results.push({ id: approvalId, ok: false, error: 'approval_not_found' });
          continue;
        }
        try {
          const decided = await decide(approvals, approvalId, body.data.decision, user.id);
          results.push({ id: approvalId, ok: true, approval: decided });
        } catch (err) {
          results.push({ id: approvalId, ok: false, error: (err as Error).message });
        }
      }
      return reply.send({ results });
    },
  );

  app.post('/api/tasks/:id/approvals/rules', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const body = createRuleSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    const task = await resolveTask(id, user.id, user.email);
    if (!task) {
      return reply.status(404).send({ error: 'Task not found' });
    }
    try {
      assertRulePattern(body.data.pattern);
      assertRuleDecision(body.data.decision);
    } catch (err) {
      return reply.status(400).send({ error: (err as Error).message });
    }
    const rule = await rules.createRule({
      userId: user.id,
      taskId: body.data.scope === 'all' ? null : id,
      pattern: body.data.pattern,
      decision: body.data.decision,
      alwaysAllow: body.data.alwaysAllow ?? false,
    });
    return reply.status(201).send({ rule });
  });
}

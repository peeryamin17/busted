import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import { isAdminEmail } from '../auth/session.js';
import type { Database } from '../db/db.js';
import type { GraphStore } from '../graph/store.js';
import {
  TARGET_RULE_ACTIONS,
  TARGET_RULE_KINDS,
  validatePinHost,
  validatePinPort,
  type PinStore,
} from '../guardrails/pins.js';

/**
 * Target-pin and rule routes.
 *
 *   GET    /api/tasks/:id/pins                  - active pins for the task
 *   POST   /api/tasks/:id/pins {host, port?}    - pin a target (the human
 *                                                 approval action)
 *   DELETE /api/tasks/:id/pins/:host[?port=]    - deactivate a pin
 *   GET    /api/tasks/:id/target-rules          - my rules (user-wide +
 *                                                 this task's)
 *   POST   /api/tasks/:id/target-rules {kind, pattern, action}
 *   DELETE /api/tasks/:id/target-rules/:ruleId  - deactivate a rule
 *
 * Member-authenticated; scoped to the caller, another user's task reads
 * as 404; ADMIN_EMAIL may act on any task. Pins and rules are append-only
 * history: deletes deactivate, they never remove a row. The route is
 * thin: validation and ownership here, all pin/rule logic in
 * guardrails/pins.ts. Registered in server.ts, not here.
 */

export interface PinRouteDeps {
  db: Database;
  graph: GraphStore;
  pins: PinStore;
}

const createPinSchema = z.object({
  host: z.string().min(1).max(253),
  port: z.number().int().min(1).max(65535).optional().nullable(),
});

const createRuleSchema = z.object({
  kind: z.enum(TARGET_RULE_KINDS as [string, ...string[]]),
  pattern: z.string().min(1).max(2000),
  action: z.enum(TARGET_RULE_ACTIONS as [string, ...string[]]),
});

export async function pinsRoutes(app: FastifyInstance, deps: PinRouteDeps): Promise<void> {
  const { db, graph, pins } = deps;
  const authenticate = buildAuthenticate(db);

  /** The task must exist and belong to the caller (or the caller is admin). */
  async function loadOwnedTask(taskId: string, user: { id: string; email: string }) {
    const task = await graph.getTask(taskId);
    if (!task || (task.userId !== user.id && !isAdminEmail(user.email))) return null;
    return task;
  }

  app.get('/api/tasks/:id/pins', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const task = await loadOwnedTask(id, user);
    if (!task) return reply.status(404).send({ error: 'Task not found' });
    const query = request.query as { includeInactive?: string };
    const list = await pins.listPins(id, { includeInactive: query.includeInactive === 'true' });
    return { pins: list };
  });

  app.post('/api/tasks/:id/pins', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const task = await loadOwnedTask(id, user);
    if (!task) return reply.status(404).send({ error: 'Task not found' });
    const body = createPinSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    try {
      const pin = await pins.addPin({
        taskId: id,
        host: validatePinHost(body.data.host),
        port: validatePinPort(body.data.port),
        pinnedBy: user.id,
      });
      return reply.status(201).send({ pin });
    } catch (err) {
      return reply.status(400).send({ error: (err as Error).message });
    }
  });

  app.delete('/api/tasks/:id/pins/:host', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id, host } = request.params as { id: string; host: string };
    const task = await loadOwnedTask(id, user);
    if (!task) return reply.status(404).send({ error: 'Task not found' });
    const query = request.query as { port?: string };
    const port = query.port === undefined ? null : Number(query.port);
    if (port !== null && (!Number.isInteger(port) || port < 1 || port > 65535)) {
      return reply.status(400).send({ error: 'port must be an integer between 1 and 65535' });
    }
    try {
      const pin = await pins.deactivatePin(id, host, port);
      if (!pin) return reply.status(404).send({ error: 'No active pin for that host' });
      return { pin };
    } catch (err) {
      return reply.status(400).send({ error: (err as Error).message });
    }
  });

  app.get('/api/tasks/:id/target-rules', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const task = await loadOwnedTask(id, user);
    if (!task) return reply.status(404).send({ error: 'Task not found' });
    const rules = await pins.listRules(user.id, id);
    return { rules };
  });

  app.post('/api/tasks/:id/target-rules', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const task = await loadOwnedTask(id, user);
    if (!task) return reply.status(404).send({ error: 'Task not found' });
    const body = createRuleSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    try {
      const rule = await pins.addRule({
        userId: user.id,
        taskId: id,
        kind: body.data.kind as (typeof TARGET_RULE_KINDS)[number],
        pattern: body.data.pattern,
        action: body.data.action as (typeof TARGET_RULE_ACTIONS)[number],
        createdBy: user.id,
      });
      return reply.status(201).send({ rule });
    } catch (err) {
      // Invalid CIDR (and any other pattern validation) is a 400.
      return reply.status(400).send({ error: (err as Error).message });
    }
  });

  app.delete('/api/tasks/:id/target-rules/:ruleId', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id, ruleId } = request.params as { id: string; ruleId: string };
    const task = await loadOwnedTask(id, user);
    if (!task) return reply.status(404).send({ error: 'Task not found' });
    const rule = await pins.removeRule(ruleId, user.id);
    if (!rule) return reply.status(404).send({ error: 'Rule not found' });
    return { rule };
  });
}

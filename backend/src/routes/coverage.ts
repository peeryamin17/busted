import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { requireUser } from '../middleware/auth.js';
import {
  type CoverageEntry,
  type CoverageStore,
  coverageSummary,
} from '../coverage/ledger.js';

/**
 * Coverage routes.
 *
 *   GET /api/tasks/:id/coverage - this task's ledger entries + summary.
 *
 * Member-authenticated; the task must belong to the caller. A task with
 * no entries at all is a valid answer: every risk class comes back
 * untested, never clean. Auth is optional only for tests; when omitted
 * the route fails closed with 401. Registered in server.ts, not here.
 */

export interface CoverageRouteDeps {
  coverage: CoverageStore;
  getTask: (id: string, userId: string) => Promise<{ id: string; userId: string } | null>;
  authenticate?: (request: FastifyRequest, reply: FastifyReply) => Promise<void> | void;
}

function publicView(e: CoverageEntry): Record<string, unknown> {
  return {
    ...(e.id !== undefined ? { id: e.id } : {}),
    taskId: e.taskId,
    ...(e.assetId !== undefined ? { assetId: e.assetId } : {}),
    ...(e.assetValue !== undefined ? { assetValue: e.assetValue } : {}),
    riskClass: e.riskClass,
    outcome: e.outcome,
    ...(e.evidence !== undefined ? { evidence: e.evidence } : {}),
    ...(e.reason !== undefined ? { reason: e.reason } : {}),
    ...(e.createdAt !== undefined ? { createdAt: e.createdAt } : {}),
  };
}

export async function coverageRoutes(
  app: FastifyInstance,
  deps: CoverageRouteDeps,
): Promise<void> {
  const { coverage, getTask } = deps;
  const authenticate =
    deps.authenticate ??
    (async () => {
      throw Object.assign(new Error('Authentication required'), { statusCode: 401 });
    });

  app.get('/api/tasks/:id/coverage', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const task = await getTask(id, user.id);
    if (!task) {
      return reply.status(404).send({ error: 'No such task' });
    }
    const entries = await coverage.listEntries(id);
    return {
      taskId: id,
      summary: coverageSummary(entries),
      entries: entries.map(publicView),
    };
  });
}

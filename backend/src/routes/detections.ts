import type { FastifyInstance } from 'fastify';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import { analyzeEvents } from '../detection/analyze.js';
import { listSecurityEvents } from '../detection/events.js';
import type { DetectionRecord } from '../detection/types.js';
import type { RouteDeps } from './health.js';

/**
 * Runtime-detection routes (Thread 5, DEFENSIVE).
 *
 *   GET /api/detections, my detections, newest first.
 *   GET /api/detections/:id, one of my detections.
 *
 * Member-authenticated (session cookie / API key / Bearer, same as the
 * other member routes). Read-only: detections are produced by the rule
 * engine (backend/src/detection/), never by clients. A user only ever
 * sees their own detections, the queries are scoped by user id.
 *
 * Registration: `detectionRoutes` is registered in server.ts next to the
 * other route registrations. Analysis is on-demand: listing runs the rules
 * over the events recorded so far (there is no scheduler yet), so the
 * panel is live as soon as intake records anything.
 */

function publicView(d: DetectionRecord): Record<string, unknown> {
  return {
    id: d.id,
    pattern: d.pattern,
    severity: d.severity,
    title: d.title,
    detail: d.detail,
    ...(d.evidence !== undefined ? { evidence: d.evidence } : {}),
    createdAt: d.createdAt,
  };
}

export async function detectionRoutes(
  app: FastifyInstance,
  deps: RouteDeps,
): Promise<void> {
  const { db } = deps;
  const authenticate = buildAuthenticate(db);

  app.get('/api/detections', { preHandler: authenticate }, async (request) => {
    const user = requireUser(request);
    const query = request.query as { limit?: string };
    const parsed = Number.parseInt(query.limit ?? '20', 10);
    const limit = Number.isFinite(parsed) ? Math.max(1, Math.min(100, parsed)) : 20;
    // On-demand analysis (no scheduler yet): run the rules over the events
    // recorded for this user, then list. With no events the honest answer
    // is an empty list, not a clean bill of health.
    await analyzeEvents(db, user.id, listSecurityEvents(user.id)).catch(() => undefined);
    const detections = await db.listDetections(user.id, limit);
    return { detections: detections.map(publicView) };
  });

  app.get('/api/detections/:id', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const rec = await db.getDetection(user.id, id);
    if (!rec) {
      return reply.status(404).send({ error: 'No such detection' });
    }
    return publicView(rec);
  });
}

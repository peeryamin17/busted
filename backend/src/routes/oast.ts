import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import type { RouteDeps } from './health.js';
import { generateCanary, oastConfigured, oastDomain } from '../oast/canary.js';
import { recordCallback, callbacksForScan } from '../oast/store.js';

/**
 * OAST (out-of-band security testing) routes — Phase 3 scaffolding.
 *
 *   POST /api/oast/callback   — the OAST listener posts observed DNS/HTTP hits.
 *                               Auth: shared service secret (x-oast-token).
 *   GET  /api/oast/callbacks  — user-authenticated; callbacks for a scan id,
 *                               so the UI/CLI can surface "blind hit observed".
 *   POST /api/oast/canary     — user-authenticated; mint a canary for a scan.
 *
 * The listener itself (wildcard DNS + HTTP server) is separate always-on
 * infrastructure — see docs/oast.md. Until OAST_DOMAIN / OAST_INGEST_TOKEN are
 * configured these routes exist but do nothing useful.
 */

const callbackSchema = z.object({
  canary: z.string().min(1).max(253),
  kind: z.enum(['dns', 'http']),
  sourceIp: z.string().max(64).optional(),
  path: z.string().max(500).optional(),
  userAgent: z.string().max(300).optional(),
  observedAt: z.string().datetime().optional(),
});

export async function oastRoutes(app: FastifyInstance, deps: RouteDeps): Promise<void> {
  const { db } = deps;
  const authenticate = buildAuthenticate(db);
  const ingestToken = process.env['OAST_INGEST_TOKEN'];

  // Listener → server ingest. Shared secret, not user auth (the listener is infra).
  app.post('/api/oast/callback', async (request, reply) => {
    if (!ingestToken) {
      return reply.status(503).send({ error: 'OAST ingest not configured (OAST_INGEST_TOKEN unset)' });
    }
    const token = request.headers['x-oast-token'];
    if (token !== ingestToken) {
      return reply.status(401).send({ error: 'unauthorized' });
    }
    const parsed = callbackSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.status(400).send({ error: 'invalid callback body' });
    }
    const cb = recordCallback(parsed.data);
    return { ok: true, recorded: cb.observedAt };
  });

  app.post('/api/oast/canary', { preHandler: authenticate }, async (request, reply) => {
    requireUser(request);
    const body = z.object({ scanId: z.string().min(1).max(64) }).safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: 'scanId required' });
    }
    return {
      canary: generateCanary(body.data.scanId),
      domain: oastDomain(),
      live: oastConfigured(),
      note: oastConfigured()
        ? 'Embed this hostname in blind payloads; hits appear under GET /api/oast/callbacks.'
        : 'OAST_DOMAIN is not configured — this canary is inert until the listener infra exists (docs/oast.md).',
    };
  });

  app.get('/api/oast/callbacks', { preHandler: authenticate }, async (request, reply) => {
    requireUser(request);
    const q = z.object({ scanId: z.string().min(1).max(64) }).safeParse(request.query);
    if (!q.success) {
      return reply.status(400).send({ error: 'scanId query param required' });
    }
    const hits = callbacksForScan(q.data.scanId);
    return {
      scanId: q.data.scanId,
      live: oastConfigured(),
      callbacks: hits,
      blindHit: hits.length > 0,
    };
  });
}

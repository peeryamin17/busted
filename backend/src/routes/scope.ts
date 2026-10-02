import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate } from '../middleware/auth.js';
import { normalizeTargetUrl } from '../guardrails/scope.js';
import type { RouteDeps } from './health.js';
import { sharedScopeDataset, type ScopeDataset } from '../scope/dataset.js';

/**
 * Programme scope routes.
 *
 *   GET  /api/scope/programmes?platform=hackerone&q=acme — find a public
 *        programme by handle or name.
 *   POST /api/scope/check { platform, handle, targetUrl } — is this target
 *        inside the programme's published scope? Always answers with a
 *        verdict (in_scope / out_of_scope / programme_not_found / unknown);
 *        the only hard failures are bad input and a fully unavailable
 *        dataset on the search endpoint.
 *
 * Scope data comes from the community bounty-targets-data mirror and is
 * cached by ScopeDataset. Verdicts are evidence, never authorisation.
 */

const searchQuerySchema = z.object({
  platform: z.enum(['hackerone', 'bugcrowd']).optional(),
  q: z.string().max(200).optional().default(''),
});

const checkSchema = z.object({
  platform: z.enum(['hackerone', 'bugcrowd']),
  handle: z.string().min(1).max(200),
  targetUrl: z.string().min(1).max(2000),
});

export async function scopeRoutes(
  app: FastifyInstance,
  deps: RouteDeps & { scopeDataset?: ScopeDataset },
): Promise<void> {
  const { db } = deps;
  const dataset = deps.scopeDataset ?? sharedScopeDataset;
  const authenticate = buildAuthenticate(db);

  app.get(
    '/api/scope/programmes',
    { preHandler: authenticate },
    async (request, reply) => {
      const parsed = searchQuerySchema.safeParse(request.query);
      if (!parsed.success) {
        return reply
          .status(400)
          .send({ error: parsed.error.issues[0]?.message ?? 'Invalid query' });
      }
      const programmes = await dataset.search(
        parsed.data.platform,
        parsed.data.q,
      );
      if (!programmes) {
        return reply.status(503).send({
          error:
            'Programme scope data is unavailable just now — try again shortly.',
        });
      }
      return { programmes };
    },
  );

  app.post(
    '/api/scope/check',
    { preHandler: authenticate },
    async (request, reply) => {
      const parsed = checkSchema.safeParse(request.body);
      if (!parsed.success) {
        return reply
          .status(400)
          .send({ error: parsed.error.issues[0]?.message ?? 'Invalid input' });
      }
      let target: URL;
      try {
        target = normalizeTargetUrl(parsed.data.targetUrl);
      } catch (err) {
        return reply.status(400).send({ error: (err as Error).message });
      }
      const result = await dataset.checkScope(
        parsed.data.platform,
        parsed.data.handle,
        target.toString(),
      );
      return result;
    },
  );
}

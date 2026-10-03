import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { RouteDeps } from './health.js';

const waitlistSchema = z.object({
  email: z.string().trim().toLowerCase().email('That email address looks incomplete').max(254),
});

/**
 * POST /api/waitlist — the "Coming soon" list from the site's drop
 * section. Public on purpose (it is a pre-launch signup), validated
 * and normalised here, deduped by the unique email constraint. There
 * is deliberately no way to read the list back over the API.
 */
export async function waitlistRoutes(app: FastifyInstance, deps: RouteDeps): Promise<void> {
  const { db } = deps;

  app.post(
    '/api/waitlist',
    { config: { rateLimit: { max: 5, timeWindow: '1 minute' } } },
    async (request, reply) => {
      const body = waitlistSchema.safeParse(request.body);
      if (!body.success) {
        return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
      }
      const { already } = await db.addWaitlistEmail(body.data.email);
      return reply.send({ ok: true, already });
    }
  );
}

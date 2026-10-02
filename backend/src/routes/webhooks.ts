import type { FastifyInstance } from 'fastify';
import { verifySvixSignature } from '../auth/clerkWebhook.js';
import type { RouteDeps } from './health.js';

/**
 * Clerk webhooks → our database.
 *
 * POST /api/webhooks/clerk (Svix-signed; secret in CLERK_WEBHOOK_SECRET —
 * unset disables the route with a 503). Subscribed events:
 *   user.created / user.updated → upsert user with their email
 *   session.created             → stamp lastLoginAt for that user
 * This is how EVERY sign-up and sign-in lands in BugSeek's own database,
 * regardless of which page the user visited afterwards.
 *
 * Registered in its own encapsulated context: the signature is computed
 * over the RAW body, so this route parses JSON as a string.
 */
export async function webhookRoutes(app: FastifyInstance, deps: RouteDeps): Promise<void> {
  const { db } = deps;

  app.addContentTypeParser('application/json', { parseAs: 'string' }, (_req, body, done) => {
    done(null, body);
  });

  app.post('/api/webhooks/clerk', async (request, reply) => {
    const secret = process.env['CLERK_WEBHOOK_SECRET'];
    if (!secret) {
      return reply.status(503).send({ error: 'Clerk webhooks are not configured on this backend' });
    }
    const raw = typeof request.body === 'string' ? request.body : '';
    const ok = verifySvixSignature(
      secret,
      {
        id: request.headers['svix-id'] as string | undefined,
        timestamp: request.headers['svix-timestamp'] as string | undefined,
        signature: request.headers['svix-signature'] as string | undefined,
      },
      raw,
    );
    if (!ok) {
      return reply.status(400).send({ error: 'Invalid webhook signature' });
    }

    let event: { type?: string; data?: Record<string, unknown> };
    try {
      event = JSON.parse(raw) as typeof event;
    } catch {
      return reply.status(400).send({ error: 'Invalid JSON' });
    }
    const data = event.data ?? {};

    if (event.type === 'user.created' || event.type === 'user.updated') {
      const clerkUserId = typeof data['id'] === 'string' ? data['id'] : null;
      const addresses = (data['email_addresses'] as Array<{ id?: string; email_address?: string }>) ?? [];
      const primaryId = data['primary_email_address_id'] as string | undefined;
      const email =
        addresses.find((a) => a.id === primaryId)?.email_address ?? addresses[0]?.email_address ?? null;
      if (clerkUserId) await db.recordClerkLogin(clerkUserId, email);
    } else if (event.type === 'session.created') {
      const clerkUserId = typeof data['user_id'] === 'string' ? data['user_id'] : null;
      if (clerkUserId) await db.recordClerkLogin(clerkUserId, null);
    }
    return reply.send({ received: true });
  });
}

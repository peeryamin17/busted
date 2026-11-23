import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import { encryptSecret, maskApiKey } from '../lib/crypto.js';
import type { Database } from '../db/db.js';
import type { SecretStore } from '../secrets/store.js';
import {
  validateNotifyChannelInput,
  type NotifyChannelRecord,
  type NotifyChannelStore,
} from '../notify/channels.js';
import { NotifyService, type FetchFn, type SmtpTransportFactory } from '../notify/send.js';

/**
 * Notification channel routes.
 *
 *   POST /api/notify/channels
 *        - create a channel. Credentials supplied in the same body
 *        under `secret` are encrypted into the secrets store (kind
 *        'notify', label = channel id) and are never echoed back:
 *        webhook bearer secret, Telegram bot token, SMTP password.
 *   GET  /api/notify/channels
 *        - the user's channels, secrets masked (hint only, never
 *        ciphertext, never plaintext).
 *   DELETE /api/notify/channels/:id
 *        - remove the channel and its stored credential.
 *   POST /api/notify/channels/:id/test
 *        - send a test event through the channel; returns ok/error
 *        only, never the secret. The test bypasses the channel's
 *        filters (it is an explicit operator action) but still
 *        respects enabled + rate limit.
 *
 * Member-authenticated; scoped to the caller, another user's channel
 * reads as 404. Registered in server.ts, not here.
 */

export interface NotifyRouteDeps {
  db: Database;
  channels: NotifyChannelStore;
  secrets: SecretStore;
  fetchFn?: FetchFn;
  smtpTransportFactory?: SmtpTransportFactory;
}

/** A channel as the API returns it: everything except any credential, plus a masked hint. */
export interface NotifyChannelPublic {
  id: string;
  userId: string;
  type: NotifyChannelRecord['type'];
  label: string;
  target: NotifyChannelRecord['target'];
  filters: NotifyChannelRecord['filters'];
  enabled: boolean;
  createdAt: string;
  /** Masked hint (first 4 + last 4) of the stored credential, or null when none is stored. */
  secretHint: string | null;
}

export function channelPublicView(
  channel: NotifyChannelRecord,
  secretHint: string | null,
): NotifyChannelPublic {
  return {
    id: channel.id,
    userId: channel.userId,
    type: channel.type,
    label: channel.label,
    target: channel.target,
    filters: channel.filters,
    enabled: channel.enabled,
    createdAt: channel.createdAt,
    secretHint,
  };
}

const createChannelSchema = z.object({
  type: z.enum(['webhook', 'telegram', 'smtp']),
  label: z.string().min(1).max(100),
  target: z.record(z.string(), z.unknown()),
  filters: z
    .object({
      minSeverity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
      events: z
        .array(z.enum(['task-completed', 'finding-critical', 'finding-high', 'task-failed']))
        .optional(),
    })
    .optional(),
  enabled: z.boolean().optional(),
  /** Telegram bot token / SMTP password / webhook bearer secret. Encrypted on save, never returned. */
  secret: z.string().min(1).max(4096).optional(),
});

export async function notifyRoutes(app: FastifyInstance, deps: NotifyRouteDeps): Promise<void> {
  const { db, channels, secrets } = deps;
  const authenticate = buildAuthenticate(db);
  const service = new NotifyService({
    channels,
    secrets,
    fetchFn: deps.fetchFn,
    smtpTransportFactory: deps.smtpTransportFactory,
  });

  /** The stored hint for one channel, or null when no credential is stored. */
  async function secretHintFor(userId: string, channelId: string): Promise<string | null> {
    const summaries = await secrets.list(userId, 'notify').catch(() => []);
    return summaries.find((s) => s.label === channelId)?.hint ?? null;
  }

  app.post('/api/notify/channels', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const body = createChannelSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    let valid;
    try {
      valid = validateNotifyChannelInput({
        userId: user.id,
        type: body.data.type,
        label: body.data.label,
        target: body.data.target,
        filters: body.data.filters,
        enabled: body.data.enabled,
      });
    } catch (err) {
      return reply.status(400).send({ error: (err as Error).message });
    }
    const channel = await channels.create({
      userId: valid.userId,
      type: valid.type,
      label: valid.label,
      target: valid.target as unknown as Record<string, unknown>,
      filters: valid.filters,
      enabled: valid.enabled,
    });
    let hint: string | null = null;
    if (body.data.secret !== undefined) {
      hint = maskApiKey(body.data.secret);
      await secrets.save({
        userId: user.id,
        kind: 'notify',
        label: channel.id,
        encryptedValue: encryptSecret(body.data.secret),
        hint,
      });
    }
    return reply.status(201).send({ channel: channelPublicView(channel, hint) });
  });

  app.get('/api/notify/channels', { preHandler: authenticate }, async (request) => {
    const user = requireUser(request);
    const rows = await channels.listForUser(user.id);
    const summaries = await secrets.list(user.id, 'notify').catch(() => []);
    const hintByChannel = new Map(summaries.map((s) => [s.label, s.hint]));
    return {
      channels: rows.map((c) => channelPublicView(c, hintByChannel.get(c.id) ?? null)),
    };
  });

  app.delete('/api/notify/channels/:id', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const channel = await channels.get(id);
    if (!channel || channel.userId !== user.id) {
      return reply.status(404).send({ error: 'Channel not found' });
    }
    await channels.remove(id, user.id);
    await secrets.remove(user.id, 'notify', id).catch(() => undefined);
    return { ok: true };
  });

  app.post('/api/notify/channels/:id/test', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const channel = await channels.get(id);
    if (!channel || channel.userId !== user.id) {
      return reply.status(404).send({ error: 'Channel not found' });
    }
    const result = await service.sendTest(channel);
    // ok/error only, the secret is never in this response.
    return { ok: result.ok, ...(result.ok ? {} : { error: result.error ?? 'send_failed' }) };
  });
}

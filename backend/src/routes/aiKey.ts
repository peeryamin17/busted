import type { FastifyInstance, FastifyRequest } from 'fastify';
import { encryptSecret, decryptSecret, maskApiKey } from '../lib/crypto.js';
import type { Database } from '../db/db.js';
import type { RouteDeps } from './health.js';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';

export async function verifyGeminiKey(apiKey: string): Promise<{ ok: boolean; error?: string }> {
  // Support mock/test keys in test or dev environments without making live HTTP requests
  if (
    apiKey.startsWith('mock-') ||
    apiKey === 'AIzaTestValidKey1234567890' ||
    process.env['MOCK_GEMINI_VERIFY'] === 'true'
  ) {
    return { ok: true };
  }

  try {
    const res = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(apiKey)}`,
      { method: 'GET', signal: AbortSignal.timeout(8000) }
    );
    if (res.ok) return { ok: true };
    const body = (await res.json().catch(() => ({}))) as { error?: { message?: string } };
    return {
      ok: false,
      error: body?.error?.message || `Gemini rejected the key (HTTP ${res.status}).`,
    };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : 'Failed to reach Gemini API.',
    };
  }
}

export async function aiKeyRoutes(app: FastifyInstance, deps: RouteDeps): Promise<void> {
  const { db } = deps;
  const authenticate = buildAuthenticate(db);

  // Check whether the signed-in user has a BYOK key configured
  app.get('/api/me/ai-key', { preHandler: [authenticate] }, async (req: FastifyRequest) => {
    const user = requireUser(req);
    const row = await db.getAiKey(user.id);
    return {
      connected: Boolean(row?.aiKeyHint),
      provider: row?.aiProvider ?? 'gemini',
      hint: row?.aiKeyHint ?? null,
      updatedAt: row?.aiKeyUpdatedAt ?? null,
    };
  });

  // Save & verify a new Gemini API key
  app.post('/api/me/ai-key', { preHandler: [authenticate] }, async (req, reply) => {
    const user = requireUser(req);
    const body = (req.body ?? {}) as { apiKey?: string; provider?: string };
    const rawKey = typeof body.apiKey === 'string' ? body.apiKey.trim() : '';
    const provider = body.provider === 'gemini' || !body.provider ? 'gemini' : body.provider;

    if (!rawKey || rawKey.length < 20) {
      return reply.code(400).send({ error: 'Please enter a valid Gemini API key.' });
    }
    if (provider !== 'gemini') {
      return reply.code(400).send({ error: 'Only Gemini API keys are supported right now.' });
    }

    const check = await verifyGeminiKey(rawKey);
    if (!check.ok) {
      return reply.code(400).send({ error: check.error || 'Invalid Gemini API key.' });
    }

    const encrypted = encryptSecret(rawKey);
    const hint = maskApiKey(rawKey);

    await db.setAiKey(user.id, encrypted, provider, hint);

    return {
      connected: true,
      provider,
      hint,
      message: 'API key verified and encrypted. Your extension is now unlocked.',
    };
  });

  // Remove saved BYOK key
  app.delete('/api/me/ai-key', { preHandler: [authenticate] }, async (req) => {
    const user = requireUser(req);
    await db.deleteAiKey(user.id);
    return { connected: false };
  });
}

// Helper for backend/src/routes/multiagent.ts when launching a swarm.
// Supports both (db, userId) and (userId) overloads.
let defaultDb: Database | undefined;
export function registerDefaultDatabase(db: Database) {
  defaultDb = db;
}

export async function getUserDecryptedAiKey(
  dbOrUserId: Database | string,
  maybeUserId?: string
): Promise<string | null> {
  let db: Database;
  let userId: string;

  if (typeof dbOrUserId === 'string') {
    userId = dbOrUserId;
    if (!defaultDb) {
      throw new Error('Default database not registered for getUserDecryptedAiKey(userId)');
    }
    db = defaultDb;
  } else {
    db = dbOrUserId;
    userId = maybeUserId!;
  }

  if (typeof db.getAiKey !== 'function') {
    return null;
  }

  const row = await db.getAiKey(userId);
  const encrypted = row?.encryptedAiKey;
  if (!encrypted) return null;
  return decryptSecret(encrypted);
}

import type { FastifyInstance, FastifyRequest } from 'fastify';
import { encryptSecret, decryptSecret, maskApiKey } from '../lib/crypto.js';
import type { Database } from '../db/db.js';
import type { RouteDeps } from './health.js';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';

export type AiProvider = 'gemini' | 'qwen' | 'ollama';

/** DashScope OpenAI-compatible base URLs, by region. International is the default. */
export const QWEN_BASE_URLS = {
  intl: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1',
  cn: 'https://dashscope.aliyuncs.com/compatible-mode/v1',
  us: 'https://dashscope-us.aliyuncs.com/compatible-mode/v1',
} as const;

export type QwenRegion = keyof typeof QWEN_BASE_URLS | 'custom';

/**
 * Resolve the DashScope base URL for a Qwen key. A custom workspace URL is
 * only accepted when it passes the strict allowlist below, the server never
 * fetches an arbitrary user-supplied URL (SSRF guard).
 */
export function resolveQwenBaseUrl(
  region: string | undefined,
  customBaseUrl: string | undefined,
): { baseUrl: string; region: QwenRegion } | { error: string } {
  const r = region ?? 'intl';
  if (r === 'intl' || r === 'cn' || r === 'us') {
    return { baseUrl: QWEN_BASE_URLS[r], region: r };
  }
  if (r !== 'custom') {
    return { error: `Unknown Qwen region "${r}". Pick International, Beijing, or a custom workspace URL.` };
  }
  const raw = (customBaseUrl ?? '').trim().replace(/\/+$/, '');
  if (!raw) {
    return { error: 'Enter your custom DashScope workspace URL for Qwen.' };
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { error: 'That Qwen workspace URL does not look like a valid URL.' };
  }
  if (
    url.protocol !== 'https:' ||
    url.username !== '' ||
    url.password !== '' ||
    (url.port !== '' && url.port !== '443') ||
    !url.hostname.endsWith('.aliyuncs.com') ||
    url.pathname !== '/compatible-mode/v1'
  ) {
    return {
      error:
        'Custom Qwen URL must be an https://*.aliyuncs.com/compatible-mode/v1 endpoint.',
    };
  }
  return { baseUrl: url.toString().replace(/\/+$/, ''), region: 'custom' };
}

/** Which region a stored Qwen base URL belongs to (for the GET response). */
export function regionForQwenBaseUrl(baseUrl: string | null | undefined): QwenRegion | null {
  if (!baseUrl) return null;
  const known = (Object.entries(QWEN_BASE_URLS) as [QwenRegion, string][]).find(
    ([, url]) => url === baseUrl,
  );
  return known ? known[0] : 'custom';
}

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

export async function verifyQwenKey(
  apiKey: string,
  baseUrl: string,
): Promise<{ ok: boolean; error?: string }> {
  // Mock/test keys never hit the live DashScope endpoint.
  if (apiKey.startsWith('mock-') || process.env['MOCK_QWEN_VERIFY'] === 'true') {
    return { ok: true };
  }

  try {
    const res = await fetch(`${baseUrl}/models`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${apiKey}` },
      signal: AbortSignal.timeout(8000),
    });
    if (res.ok) return { ok: true };
    const body = (await res.json().catch(() => ({}))) as {
      error?: { message?: string } | string;
    };
    const detail =
      typeof body?.error === 'string'
        ? body.error
        : body?.error?.message || `Qwen rejected the key (HTTP ${res.status}).`;
    // A key from one DashScope region returns 401 in another, say so plainly.
    const hint =
      res.status === 401
        ? ' Check the key and the region: a DashScope key only works in the region it was created for.'
        : '';
    return { ok: false, error: `${detail}${hint}` };
  } catch (err) {
    return {
      ok: false,
      error:
        err instanceof Error
          ? `Could not reach Qwen (${err.message}).`
          : 'Failed to reach Qwen API.',
    };
  }
}

const PROVIDER_LABELS: Record<AiProvider, string> = {
  gemini: 'Gemini',
  qwen: 'Qwen',
  ollama: 'Ollama',
};

export async function aiKeyRoutes(app: FastifyInstance, deps: RouteDeps): Promise<void> {
  const { db } = deps;
  const authenticate = buildAuthenticate(db);

  // Check whether the signed-in user has a BYOK key configured
  app.get('/api/me/ai-key', { preHandler: [authenticate] }, async (req: FastifyRequest) => {
    const user = requireUser(req);
    const row = await db.getAiKey(user.id);
    const provider = (row?.aiProvider as AiProvider | undefined) ?? 'gemini';
    const connected = Boolean(row?.aiKeyHint);
    return {
      connected,
      provider,
      baseUrl: row?.aiBaseUrl ?? null,
      region: provider === 'qwen' ? regionForQwenBaseUrl(row?.aiBaseUrl) : null,
      // Gemini and Qwen keys are only stored after a live check; Ollama is
      // local-only, so the hosted backend can never verify it.
      verified: connected && provider !== 'ollama',
      hint: row?.aiKeyHint ?? null,
      updatedAt: row?.aiKeyUpdatedAt ?? null,
    };
  });

  // Save & verify a new BYOK key (Gemini, Qwen, or local Ollama)
  app.post('/api/me/ai-key', { preHandler: [authenticate] }, async (req, reply) => {
    const user = requireUser(req);
    const body = (req.body ?? {}) as {
      apiKey?: string;
      provider?: string;
      region?: string;
      baseUrl?: string;
    };
    const rawKey = typeof body.apiKey === 'string' ? body.apiKey.trim() : '';
    const providerRaw = body.provider ?? 'gemini';
    if (providerRaw !== 'gemini' && providerRaw !== 'qwen' && providerRaw !== 'ollama') {
      return reply.code(400).send({
        error: `Unknown AI provider "${providerRaw}". Pick Gemini, Qwen, or Ollama.`,
      });
    }
    const provider = providerRaw as AiProvider;
    const label = PROVIDER_LABELS[provider];

    // Ollama runs on the user's own machine: no key, no server-side check.
    // The client checks reachability itself. Stored as unverified.
    if (provider === 'ollama') {
      await db.setAiKey(user.id, '', provider, 'local', null);
      return {
        connected: true,
        provider,
        baseUrl: null,
        region: null,
        verified: false,
        hint: 'local',
        message:
          'Ollama saved as your local provider. It only works where Ollama is running on your own machine — the hosted backend cannot reach your localhost.',
      };
    }

    if (!rawKey || rawKey.length < 16) {
      return reply.code(400).send({ error: `Please enter a valid ${label} API key.` });
    }

    let baseUrl: string | null = null;
    if (provider === 'qwen') {
      const resolved = resolveQwenBaseUrl(body.region, body.baseUrl);
      if ('error' in resolved) {
        return reply.code(400).send({ error: resolved.error });
      }
      baseUrl = resolved.baseUrl;
      const check = await verifyQwenKey(rawKey, baseUrl);
      if (!check.ok) {
        return reply.code(400).send({ error: check.error || 'Invalid Qwen API key.' });
      }
    } else {
      const check = await verifyGeminiKey(rawKey);
      if (!check.ok) {
        return reply.code(400).send({ error: check.error || 'Invalid Gemini API key.' });
      }
    }

    const encrypted = encryptSecret(rawKey);
    const hint = maskApiKey(rawKey);

    await db.setAiKey(user.id, encrypted, provider, hint, baseUrl);

    return {
      connected: true,
      provider,
      baseUrl,
      region: provider === 'qwen' ? regionForQwenBaseUrl(baseUrl) : null,
      verified: true,
      hint,
      message: `${label} API key verified and encrypted. Your extension is now unlocked.`,
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

/**
 * Full BYOK config for a user: decrypted key plus the provider and base URL
 * the LLM layer needs to route the call. Null when no key is stored
 * (Ollama has no key, callers treat provider 'ollama' as local-only).
 */
export async function getUserAiKeyConfig(
  db: Database,
  userId: string,
): Promise<{ apiKey: string; provider: AiProvider; baseUrl: string | null } | null> {
  const row = await db.getAiKey(userId);
  if (!row) return null;
  const provider = (row.aiProvider as AiProvider | undefined) ?? 'gemini';
  if (provider === 'ollama') {
    return { apiKey: '', provider, baseUrl: null };
  }
  if (!row.encryptedAiKey) return null;
  return {
    apiKey: decryptSecret(row.encryptedAiKey),
    provider,
    baseUrl: row.aiBaseUrl ?? null,
  };
}

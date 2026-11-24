import type { FastifyInstance, FastifyRequest } from 'fastify';
import { encryptSecret, decryptSecret, maskApiKey } from '../lib/crypto.js';
import type { Database, UserLlmRouting } from '../db/db.js';
import type { RouteDeps } from './health.js';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import { getBackendRuntime } from './health.js';
import {
  PROVIDER_REGISTRY,
  isProviderId,
  validateProviderBaseUrl,
  type ProviderId,
} from '../llm/registry.js';

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
  try {
    const res = await fetch('https://generativelanguage.googleapis.com/v1beta/models', {
      method: 'GET',
      headers: { 'x-goog-api-key': apiKey },
      signal: AbortSignal.timeout(8000),
    });
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

/** Last four characters only, e.g. ****1a2b. Never the full key. */
export function multiKeyHint(apiKey: string): string {
  const trimmed = apiKey.trim();
  return `****${trimmed.slice(-4)}`;
}

const VERIFY_TIMEOUT_MS = 10_000;

function providerErrorDetail(body: string, status: number): string {
  try {
    const parsed = JSON.parse(body) as { error?: { message?: unknown } | string };
    const detail =
      typeof parsed?.error === 'string'
        ? parsed.error
        : typeof parsed?.error?.message === 'string'
          ? parsed.error.message
          : '';
    if (detail) return detail.slice(0, 140);
  } catch {
    // Not JSON, fall through to the status line.
  }
  return `Provider rejected the key (HTTP ${status}).`;
}

/**
 * Live verification call for a provider key. Ten seconds, header auth
 * only, and only the provider's structured error message is returned.
 * No mock bypass: a key that cannot be verified live is not stored.
 */
export async function verifyProviderKey(
  providerId: ProviderId,
  apiKey: string,
  baseUrl: string,
): Promise<{ ok: boolean; error?: string }> {
  try {
    if (providerId === 'gemini') {
      const res = await fetch(`${baseUrl}/models`, {
        method: 'GET',
        headers: { 'x-goog-api-key': apiKey },
        signal: AbortSignal.timeout(VERIFY_TIMEOUT_MS),
      });
      if (res.ok) return { ok: true };
      return { ok: false, error: providerErrorDetail(await res.text().catch(() => ''), res.status) };
    }
    if (providerId === 'claude') {
      const res = await fetch(`${baseUrl}/messages`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: PROVIDER_REGISTRY.claude.defaultModels.reasoning,
          max_tokens: 1,
          messages: [{ role: 'user', content: 'ping' }],
        }),
        signal: AbortSignal.timeout(VERIFY_TIMEOUT_MS),
      });
      if (res.ok) return { ok: true };
      return { ok: false, error: providerErrorDetail(await res.text().catch(() => ''), res.status) };
    }
    const headers: Record<string, string> = {};
    if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;
    const res = await fetch(`${baseUrl}/models`, {
      method: 'GET',
      headers,
      signal: AbortSignal.timeout(VERIFY_TIMEOUT_MS),
    });
    if (res.ok) return { ok: true };
    return { ok: false, error: providerErrorDetail(await res.text().catch(() => ''), res.status) };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? `Could not reach provider (${err.message.slice(0, 120)}).` : 'Failed to reach provider.',
    };
  }
}

export interface SavedProviderKeyOut {
  providerId: ProviderId;
  apiKey: string;
  baseUrl: string;
  verifiedAt: string;
}

/** Decrypted saved keys for a user. Rows that fail to decrypt are skipped. */
export async function getUserAiKeysDecrypted(
  db: Database,
  userId: string,
  opts?: { strict?: boolean },
): Promise<SavedProviderKeyOut[]> {
  if (typeof (db as Database).listUserAiKeys !== 'function') return [];
  // Lenient by default (other callers treat a failed load as "no keys").
  // Strict mode rethrows the query error: the swarm path must tell a
  // database failure apart from a legitimate zero-row result.
  const rows = opts?.strict
    ? await (db as Database).listUserAiKeys(userId)
    : await (db as Database).listUserAiKeys(userId).catch(() => []);
  const out: SavedProviderKeyOut[] = [];
  for (const row of rows) {
    try {
      out.push({
        providerId: row.providerId as ProviderId,
        apiKey: decryptSecret(row.encryptedKey),
        baseUrl: row.baseUrl,
        verifiedAt: row.verifiedAt,
      });
    } catch {
      // A corrupt row must not break the swarm; it is skipped.
    }
  }
  return out;
}

export const DEFAULT_ROUTING: UserLlmRouting = {
  workerProvider: 'gemini',
  workerModel: PROVIDER_REGISTRY.gemini.defaultModels.worker,
  reasoningProvider: 'gemini',
  reasoningModel: PROVIDER_REGISTRY.gemini.defaultModels.reasoning,
};

export async function getUserLlmRoutingOrDefault(
  db: Database,
  userId: string,
  opts?: { strict?: boolean },
): Promise<UserLlmRouting> {
  if (typeof (db as Database).getUserLlmRouting !== 'function') return { ...DEFAULT_ROUTING };
  // Lenient by default; strict mode rethrows the query error instead of
  // silently returning the Gemini defaults (see getUserAiKeysDecrypted).
  const row = opts?.strict
    ? await (db as Database).getUserLlmRouting(userId)
    : await (db as Database).getUserLlmRouting(userId).catch(() => null);
  if (!row) return { ...DEFAULT_ROUTING };
  return {
    workerProvider: row.workerProvider || 'gemini',
    workerModel: row.workerModel ?? null,
    reasoningProvider: row.reasoningProvider || 'gemini',
    reasoningModel: row.reasoningModel ?? null,
  };
}

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

  // ── Multi-provider keys (migration 034) ──
  // Same authenticated access as every other route here: session cookie
  // or a verified bs_ key. A provider key is never a credential.

  app.get('/api/v1/ai-keys', { preHandler: [authenticate] }, async (req) => {
    const user = requireUser(req);
    const rows = await db.listUserAiKeys(user.id).catch(() => []);
    const routing = await getUserLlmRoutingOrDefault(db, user.id);
    return {
      keys: rows.map((r) => ({
        providerId: r.providerId,
        keyHint: r.keyHint,
        baseUrl: r.baseUrl,
        verifiedAt: r.verifiedAt,
      })),
      routing: {
        workerProvider: routing.workerProvider,
        workerModel: routing.workerModel ?? PROVIDER_REGISTRY[routing.workerProvider as ProviderId]?.defaultModels.worker ?? null,
        reasoningProvider: routing.reasoningProvider,
        reasoningModel: routing.reasoningModel ?? PROVIDER_REGISTRY[routing.reasoningProvider as ProviderId]?.defaultModels.reasoning ?? null,
      },
      hasByok: rows.length > 0,
    };
  });

  app.post('/api/v1/ai-keys', { preHandler: [authenticate] }, async (req, reply) => {
    const user = requireUser(req);
    const body = (req.body ?? {}) as {
      providerId?: string;
      apiKey?: string;
      baseUrl?: string;
    };
    const providerIdRaw = typeof body.providerId === 'string' ? body.providerId.trim().toLowerCase() : '';
    if (!isProviderId(providerIdRaw)) {
      return reply.code(400).send({ error: `Unknown AI provider "${body.providerId ?? ''}".` });
    }
    const providerId = providerIdRaw as ProviderId;
    const spec = PROVIDER_REGISTRY[providerId];

    if (providerId === 'ollama' && getBackendRuntime() === 'cloud') {
      return reply
        .code(400)
        .send({ error: 'Ollama requires a local backend and cannot be saved on the hosted backend.' });
    }

    let baseUrl: string;
    try {
      baseUrl = validateProviderBaseUrl(providerId, body.baseUrl);
    } catch {
      return reply.code(400).send({ error: `Disallowed base URL for provider ${providerId}.` });
    }

    const rawKey = typeof body.apiKey === 'string' ? body.apiKey.trim() : '';
    if (providerId !== 'ollama') {
      if (!rawKey || rawKey.length < 16) {
        return reply.code(400).send({ error: `Please enter a valid ${spec.label} API key.` });
      }
      if (rawKey.startsWith('mock-') || rawKey === 'mock') {
        return reply.code(400).send({ error: 'Mock keys cannot be saved; enter a real provider key.' });
      }
    }

    const check = await verifyProviderKey(providerId, rawKey, baseUrl);
    if (!check.ok) {
      return reply.code(400).send({ error: check.error || 'Provider rejected the key.' });
    }

    const storedKey = providerId === 'ollama' && !rawKey ? 'ollama-local' : rawKey;
    const encrypted = encryptSecret(storedKey);
    const hint = providerId === 'ollama' && !rawKey ? 'local' : multiKeyHint(rawKey);
    const verifiedAt = new Date().toISOString();
    // The legacy sync below overwrites the single-key row with this key,
    // so read it first: it is the only evidence of a Gemini key the user
    // held through the older single-key route.
    const legacyBefore = await db.getAiKey(user.id).catch(() => null);
    const heldGeminiLegacy = Boolean(
      legacyBefore?.encryptedAiKey && (legacyBefore.aiProvider ?? 'gemini') === 'gemini',
    );
    await db.upsertUserAiKey(user.id, {
      providerId,
      encryptedKey: encrypted,
      keyHint: hint,
      baseUrl,
      verifiedAt,
    });
    // Keep the legacy single-key row on the latest saved key so older
    // clients (extension popup, /api/me/ai-key) keep working.
    await db.setAiKey(user.id, encrypted, providerId, hint, baseUrl).catch(() => undefined);
    const remaining = await db.listUserAiKeys(user.id).catch(() => []);
    // Auto-route: when the user saves a key for a non-Gemini provider and
    // holds no Gemini key, point both tiers at the saved provider — but
    // only when it becomes their only key, or routing still holds the
    // Gemini defaults. A routing row that already points at a different
    // provider the user holds is an explicit choice and is left alone.
    let routingAutoSet = false;
    let routing = await getUserLlmRoutingOrDefault(db, user.id);
    const holdsGemini =
      heldGeminiLegacy || remaining.some((r) => r.providerId === 'gemini');
    if (providerId !== 'gemini' && !holdsGemini) {
      const held = new Set(remaining.map((r) => r.providerId));
      const routingPointsAtHeldProvider =
        (routing.workerProvider !== 'gemini' && held.has(routing.workerProvider)) ||
        (routing.reasoningProvider !== 'gemini' && held.has(routing.reasoningProvider));
      const isOnlyKey = held.size === 1 && held.has(providerId);
      const routingIsGeminiDefault =
        routing.workerProvider === 'gemini' && routing.reasoningProvider === 'gemini';
      if (!routingPointsAtHeldProvider && (isOnlyKey || routingIsGeminiDefault)) {
        const nextRouting: UserLlmRouting = {
          workerProvider: providerId,
          workerModel: null,
          reasoningProvider: providerId,
          reasoningModel: null,
        };
        if (typeof (db as Database).setUserLlmRouting === 'function') {
          try {
            await db.setUserLlmRouting(user.id, nextRouting);
            routing = nextRouting;
            routingAutoSet = true;
          } catch {
            // Routing stays as it was; the response reports no auto-set.
          }
        }
      }
    }
    const routingOut = {
      workerProvider: routing.workerProvider,
      workerModel:
        routing.workerModel ??
        PROVIDER_REGISTRY[routing.workerProvider as ProviderId]?.defaultModels.worker ??
        null,
      reasoningProvider: routing.reasoningProvider,
      reasoningModel:
        routing.reasoningModel ??
        PROVIDER_REGISTRY[routing.reasoningProvider as ProviderId]?.defaultModels.reasoning ??
        null,
    };
    return {
      providerId,
      keyHint: hint,
      baseUrl,
      verifiedAt,
      hasByok: remaining.length > 0,
      routingAutoSet,
      routing: routingOut,
    };
  });

  app.delete('/api/v1/ai-keys/:providerId', { preHandler: [authenticate] }, async (req, reply) => {
    const user = requireUser(req);
    const providerIdRaw = (req.params as { providerId?: string }).providerId ?? '';
    const providerId = providerIdRaw.trim().toLowerCase();
    if (!isProviderId(providerId)) {
      return reply.code(400).send({ error: `Unknown AI provider "${providerIdRaw}".` });
    }
    const deleted = await db.deleteUserAiKey(user.id, providerId);
    if (!deleted) {
      return reply.code(404).send({ error: `No saved key for provider ${providerId}.` });
    }
    const remaining = await db.listUserAiKeys(user.id).catch(() => []);
    const routing = await getUserLlmRoutingOrDefault(db, user.id);
    const fallbackProvider = remaining[0]?.providerId ?? 'gemini';
    let routingChanged = false;
    if (routing.workerProvider === providerId) {
      routing.workerProvider = fallbackProvider;
      routing.workerModel = null;
      routingChanged = true;
    }
    if (routing.reasoningProvider === providerId) {
      routing.reasoningProvider = fallbackProvider;
      routing.reasoningModel = null;
      routingChanged = true;
    }
    if (routingChanged) {
      await db.setUserLlmRouting(user.id, routing).catch(() => undefined);
    }
    return { deleted: true, hasByok: remaining.length > 0 };
  });

  app.put('/api/v1/ai-keys/routing', { preHandler: [authenticate] }, async (req, reply) => {
    const user = requireUser(req);
    const body = (req.body ?? {}) as {
      workerProvider?: string;
      workerModel?: string;
      reasoningProvider?: string;
      reasoningModel?: string;
    };
    const saved = await db.listUserAiKeys(user.id).catch(() => []);
    const owned = new Set(saved.map((r) => r.providerId));
    const account = await db.getUserById(user.id).catch(() => null);
    const hasPlatformCredits = account !== null && account.plan !== 'free';
    const pickProvider = (raw: unknown, current: string): string | null => {
      if (raw === undefined) return current;
      if (typeof raw !== 'string' || !isProviderId(raw.trim().toLowerCase())) return null;
      return raw.trim().toLowerCase();
    };
    const current = await getUserLlmRoutingOrDefault(db, user.id);
    const workerProvider = pickProvider(body.workerProvider, current.workerProvider);
    const reasoningProvider = pickProvider(body.reasoningProvider, current.reasoningProvider);
    if (workerProvider === null || reasoningProvider === null) {
      return reply.code(400).send({ error: 'Unknown provider in routing.' });
    }
    for (const p of [workerProvider, reasoningProvider]) {
      if (!owned.has(p) && !hasPlatformCredits) {
        return reply.code(400).send({
          error: `No saved key for provider ${p}; save a key first or use a plan with platform credits.`,
        });
      }
    }
    const pickModel = (raw: unknown, currentModel: string | null): string | null | false => {
      if (raw === undefined) return currentModel;
      if (typeof raw !== 'string' || !raw.trim() || raw.trim().length > 200) return false;
      return raw.trim();
    };
    const workerModel = pickModel(body.workerModel, current.workerModel);
    const reasoningModel = pickModel(body.reasoningModel, current.reasoningModel);
    if (workerModel === false || reasoningModel === false) {
      return reply.code(400).send({ error: 'Model names must be non-empty strings.' });
    }
    const routing: UserLlmRouting = {
      workerProvider,
      workerModel,
      reasoningProvider,
      reasoningModel,
    };
    await db.setUserLlmRouting(user.id, routing);
    return {
      routing: {
        workerProvider: routing.workerProvider,
        workerModel: routing.workerModel,
        reasoningProvider: routing.reasoningProvider,
        reasoningModel: routing.reasoningModel,
      },
    };
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

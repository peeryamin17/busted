import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import type { Database } from '../db/db.js';
import type { SecretStore } from '../secrets/store.js';
import { decryptSecret, encryptSecret, maskApiKey } from '../lib/crypto.js';
import {
  DEFAULT_SEARCH_PROVIDER,
  SEARCH_PROVIDER_INFO,
  SearchRateLimiter,
  frameSearchResults,
  isSearchProviderName,
  providerNeedsKey,
  search,
  type SearchFetch,
  type SearchProviderName,
} from '../search/providers.js';
import {
  resolveDefaultProvider,
  type SearchSettingsStore,
} from '../search/config.js';

/**
 * Web-search routes.
 *
 *   GET    /api/search/providers
 *          - every provider: whether it can search, whether it needs a
 *            key, and whether the caller has one saved (hint only).
 *   GET    /api/search/settings
 *          - the caller's default provider.
 *   POST   /api/search/provider {provider}
 *          - set the default provider (deepseek rejected: not a search
 *            provider).
 *   POST   /api/search/key {provider, apiKey}
 *          - save a provider key: AES-256-GCM encrypted into the
 *            generic secrets store (kind 'search', label = provider).
 *            DuckDuckGo takes no key. Returns the masked hint only.
 *   DELETE /api/search/key/:provider
 *          - delete a saved provider key.
 *   POST   /api/search {query, provider?, limit?}
 *          - run a search (provider defaults to the caller's saved
 *            default, else 'duckduckgo'). Rate-limited: 10 searches
 *            per minute per user, in-process. Returns the results plus
 *            a framed copy wrapped in the untrusted-output boundary.
 *            Results are untrusted web content, never instructions.
 *   POST   /api/search/test {provider?}
 *          - validate a saved key with a one-word probe query; returns
 *            the result count only, never result contents or the key.
 *
 * Member-authenticated. Search is a read-only information tool: it
 * touches no target and never bypasses scope or approvals.
 * Registered in server.ts, not here.
 */

export interface SearchRouteDeps {
  db: Database;
  secrets: SecretStore;
  settings: SearchSettingsStore;
  /** Injected fetch (tests); defaults to global fetch inside providers. */
  fetchImpl?: SearchFetch;
  /** Injected limiter (tests); defaults to a shared 10/min instance. */
  rateLimiter?: SearchRateLimiter;
}

const saveKeySchema = z.object({
  provider: z.string().min(1).max(50),
  apiKey: z.string().min(8).max(500),
});

const setProviderSchema = z.object({
  provider: z.string().min(1).max(50),
});

const searchBodySchema = z.object({
  query: z.string().min(1).max(500),
  provider: z.string().min(1).max(50).optional(),
  limit: z.number().int().min(1).max(10).optional(),
});

const testBodySchema = z.object({
  provider: z.string().min(1).max(50).optional(),
});

const PROBE_QUERY = 'test';

export async function searchRoutes(app: FastifyInstance, deps: SearchRouteDeps): Promise<void> {
  const { db, secrets, settings } = deps;
  const authenticate = buildAuthenticate(db);
  const limiter = deps.rateLimiter ?? new SearchRateLimiter();

  /** Decrypt the caller's saved key for a provider, or null when none is saved. */
  async function loadApiKey(userId: string, provider: SearchProviderName): Promise<string | null> {
    const rec = await secrets.get(userId, 'search', provider);
    if (!rec) return null;
    try {
      return decryptSecret(rec.encryptedValue);
    } catch {
      return null;
    }
  }

  function parseProvider(raw: string): SearchProviderName | null {
    return isSearchProviderName(raw) ? raw : null;
  }

  app.get('/api/search/providers', { preHandler: authenticate }, async (request) => {
    const user = requireUser(request);
    const saved = await secrets.list(user.id, 'search');
    const hasKey = new Set(saved.map((s) => s.label));
    return {
      providers: SEARCH_PROVIDER_INFO.map((info) => ({
        name: info.name,
        isSearchProvider: info.isSearchProvider,
        needsKey: info.needsKey,
        description: info.description,
        hasKey: hasKey.has(info.name),
      })),
    };
  });

  app.get('/api/search/settings', { preHandler: authenticate }, async (request) => {
    const user = requireUser(request);
    const provider = await resolveDefaultProvider(settings, user.id);
    return { provider };
  });

  app.post('/api/search/provider', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const body = setProviderSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    const provider = parseProvider(body.data.provider);
    if (!provider) {
      return reply.status(400).send({ error: `Unknown search provider: ${body.data.provider}` });
    }
    try {
      const saved = await settings.set(user.id, provider);
      return { provider: saved.provider };
    } catch (err) {
      return reply.status(400).send({ error: (err as Error).message });
    }
  });

  app.post('/api/search/key', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const body = saveKeySchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    const provider = parseProvider(body.data.provider);
    if (!provider) {
      return reply.status(400).send({ error: `Unknown search provider: ${body.data.provider}` });
    }
    if (!providerNeedsKey(provider)) {
      return reply
        .status(400)
        .send({ error: `${provider} does not take an API key.` });
    }
    const apiKey = body.data.apiKey.trim();
    const saved = await secrets.save({
      userId: user.id,
      kind: 'search',
      label: provider,
      encryptedValue: encryptSecret(apiKey),
      hint: maskApiKey(apiKey),
    });
    return { provider, hint: saved.hint };
  });

  app.delete('/api/search/key/:provider', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { provider: raw } = request.params as { provider: string };
    const provider = parseProvider(raw);
    if (!provider) {
      return reply.status(400).send({ error: `Unknown search provider: ${raw}` });
    }
    const removed = await secrets.remove(user.id, 'search', provider);
    return { provider, removed };
  });

  app.post('/api/search', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const body = searchBodySchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    const provider = body.data.provider ? parseProvider(body.data.provider) : null;
    if (body.data.provider && !provider) {
      return reply.status(400).send({ error: `Unknown search provider: ${body.data.provider}` });
    }
    const effective = provider ?? (await resolveDefaultProvider(settings, user.id));
    if (!limiter.tryAcquire(user.id)) {
      return reply.status(429).send({ error: 'Search rate limit exceeded: max 10 searches per minute.' });
    }
    try {
      const apiKey = providerNeedsKey(effective) ? await loadApiKey(user.id, effective) : null;
      const { results } = await search(body.data.query, {
        provider: effective,
        limit: body.data.limit,
        fetchImpl: deps.fetchImpl,
        apiKey,
      });
      const { framed, nonce } = frameSearchResults(results, effective);
      return { provider: effective, results, framed, nonce };
    } catch (err) {
      const message = (err as Error).message;
      if (message.startsWith('search_provider_not_supported')) {
        return reply.status(400).send({ error: message });
      }
      if (message.startsWith('search_key_required')) {
        return reply.status(400).send({ error: `No ${effective} API key saved. Save one first.` });
      }
      if (message.startsWith('search_query_')) {
        return reply.status(400).send({ error: message });
      }
      return reply.status(502).send({ error: message });
    }
  });

  app.post('/api/search/test', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const body = testBodySchema.safeParse(request.body ?? {});
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    const provider = body.data.provider ? parseProvider(body.data.provider) : null;
    if (body.data.provider && !provider) {
      return reply.status(400).send({ error: `Unknown search provider: ${body.data.provider}` });
    }
    const effective = provider ?? (await resolveDefaultProvider(settings, user.id));
    if (!limiter.tryAcquire(user.id)) {
      return reply.status(429).send({ error: 'Search rate limit exceeded: max 10 searches per minute.' });
    }
    try {
      const apiKey = providerNeedsKey(effective) ? await loadApiKey(user.id, effective) : null;
      const { results } = await search(PROBE_QUERY, {
        provider: effective,
        limit: 1,
        fetchImpl: deps.fetchImpl,
        apiKey,
      });
      return { provider: effective, ok: true, resultCount: results.length };
    } catch (err) {
      const message = (err as Error).message;
      if (message.startsWith('search_key_required')) {
        return reply.status(400).send({ error: `No ${effective} API key saved. Save one first.` });
      }
      return reply.status(502).send({ error: message });
    }
  });
}

export { DEFAULT_SEARCH_PROVIDER };

import { config } from '../config.js';
import type { LLMCompletion, LLMCompletionRequest, LLMMessage, LLMProvider } from './provider.js';
import { ClaudeProvider } from './claude.js';
import { GeminiProvider } from './gemini.js';
import { MockProvider } from './mock.js';
import { QwenProvider } from './qwen.js';
import { OpenAiCompatProvider, finiteInt, type OpenAiCompatProviderId } from './openaiCompat.js';
import { PROVIDER_REGISTRY, type ModelTier, type ProviderId } from './registry.js';

export { PROVIDER_REGISTRY, validateProviderBaseUrl, type ProviderId, type ModelTier } from './registry.js';
export { OpenAiCompatProvider, finiteInt, sanitizedProviderError } from './openaiCompat.js';

/**
 * Select the LLM provider from config (env LLM_PROVIDER).
 *
 * Default is `gemini` (Google AI). If LLM_PROVIDER=gemini but GEMINI_API_KEY
 * is not set, we fall back to the mock provider with a warning so `npm run
 * dev` keeps working with zero infrastructure and zero cost. Set the key to
 * use live models. The same fallback applies to LLM_PROVIDER=qwen.
 */
export function createLLMProvider(apiKey?: string): LLMProvider {
  switch (config.llmProvider) {
    case 'gemini': {
      const key = apiKey || config.geminiApiKey;
      if (!key) {
        // SECURITY: never serve deterministic fake findings as real ones in
        // production. In dev/test the mock keeps zero-cost local runs working.
        if (process.env['NODE_ENV'] === 'production') {
          throw new Error(
            'LLM_PROVIDER=gemini but GEMINI_API_KEY is not set (refusing to fall back to the mock provider in production)'
          );
        }
        console.warn(
          '[llm] LLM_PROVIDER=gemini but GEMINI_API_KEY is not set — falling back to the mock provider (no network, no cost)'
        );
        return new MockProvider();
      }
      return new GeminiProvider(key);
    }
    case 'qwen': {
      const key = apiKey || config.qwenApiKey;
      if (!key) {
        if (process.env['NODE_ENV'] === 'production') {
          throw new Error(
            'LLM_PROVIDER=qwen but QWEN_API_KEY is not set (refusing to fall back to the mock provider in production)'
          );
        }
        console.warn(
          '[llm] LLM_PROVIDER=qwen but QWEN_API_KEY is not set — falling back to the mock provider (no network, no cost)'
        );
        return new MockProvider();
      }
      return new QwenProvider(key);
    }
    case 'claude':
      return new ClaudeProvider();
    case 'mock':
    default:
      return new MockProvider();
  }
}

export interface ProviderModelOverrides {
  workerModel?: string;
  reasoningModel?: string;
}

/**
 * Construct a provider for a specific user-supplied (BYOK) key, by provider
 * name. Used by routes that know which provider the user's stored key
 * belongs to (the stored ai_provider column), rather than the server-wide
 * LLM_PROVIDER default.
 *
 * - 'gemini': Google AI key → GeminiProvider.
 * - 'qwen': DashScope key → QwenProvider against the configured (or given)
 *   DashScope base URL.
 * - 'claude': Anthropic key → ClaudeProvider.
 * - 'kimi' / 'glm' / 'deepseek' / 'openrouter': OpenAI-compatible adapter.
 * - 'ollama': local Ollama server, OpenAI-compatible adapter against the
 *   local endpoint with a keyless sentinel (Ollama ignores the Bearer
 *   token). Only used by local paths; never a hosted provider.
 * - anything else: falls back to Gemini (the historical BYOK default).
 */
export function createProviderForUser(
  provider: string,
  apiKey: string,
  baseUrl?: string,
  models?: ProviderModelOverrides,
): LLMProvider {
  const id = provider.toLowerCase();
  switch (id) {
    case 'qwen':
      return new QwenProvider(
        apiKey,
        baseUrl,
        models?.workerModel,
        models?.reasoningModel,
        models?.reasoningModel,
      );
    case 'claude':
      return new ClaudeProvider(apiKey, models?.reasoningModel, models?.workerModel);
    case 'kimi':
    case 'glm':
    case 'deepseek':
    case 'openrouter':
      return new OpenAiCompatProvider(
        id as OpenAiCompatProviderId,
        apiKey,
        baseUrl,
        models?.workerModel,
        models?.reasoningModel,
      );
    case 'ollama':
      return new OpenAiCompatProvider(
        'ollama',
        apiKey || 'ollama-local',
        baseUrl ?? 'http://127.0.0.1:11434/v1',
        models?.workerModel,
        models?.reasoningModel,
      );
    case 'gemini':
    default:
      return new GeminiProvider(apiKey, models?.workerModel, models?.reasoningModel);
  }
}

/** The mock provider is only ever a stand-in when explicitly opted into outside production. */
export function mockAllowed(): boolean {
  return process.env['BUGSEEK_ALLOW_MOCK_LLM'] === '1' && process.env['NODE_ENV'] !== 'production';
}

export interface PoolEntry {
  providerId: ProviderId | 'mock';
  provider: LLMProvider;
  workerModel?: string;
  reasoningModel?: string;
}

export interface PoolOptions {
  now?: () => number;
  /** Per-tier preferred provider; see PoolRouting. Failover still tries the other saved providers. */
  routing?: PoolRouting | null;
}

/** Cooldown after consecutive failures: 10s, 20s, 40s, then 120s. */
export const POOL_COOLDOWN_STEPS_MS = [10_000, 20_000, 40_000, 120_000];

/**
 * Tier-aware pool over a user's verified providers. Entries are tried in
 * EMA-latency order, with the tier's routing provider first and the other
 * saved providers as failover; a 429, 5xx or timeout cools that provider
 * down and the call falls through to the next entry. A 400 fails fast: the
 * request itself is bad and no provider would accept it.
 */
export class LlmProviderPool implements LLMProvider {
  readonly name = 'pool';
  private readonly entries: PoolEntry[];
  private readonly now: () => number;
  private readonly routing: PoolRouting | null;
  private failures = new Map<string, number>();
  private cooledUntil = new Map<string, number>();
  private emaLatency = new Map<string, number>();

  constructor(entries: PoolEntry[], opts?: PoolOptions) {
    if (!entries || entries.length === 0) {
      throw new Error('LlmProviderPool requires at least one provider');
    }
    this.entries = [...entries];
    this.now = opts?.now ?? Date.now;
    this.routing = opts?.routing ?? null;
  }

  isCoolingDown(providerId: string): boolean {
    return (this.cooledUntil.get(providerId) ?? 0) > this.now();
  }

  cooldownRemainingMs(providerId: string): number {
    return Math.max(0, (this.cooledUntil.get(providerId) ?? 0) - this.now());
  }

  /** LLMProvider interface: 'routine'/'code' map onto the pool tiers. */
  async complete(req: LLMCompletionRequest): Promise<LLMCompletion> {
    const tier: ModelTier = req.tier === 'reasoning' || req.tier === 'code' ? 'reasoning' : 'worker';
    return this.completeTier(tier, req.messages, {
      maxTokens: req.maxTokens,
      temperature: req.temperature,
      signal: req.signal,
    });
  }

  async completeTier(
    tier: ModelTier,
    messages: LLMMessage[],
    opts?: { maxTokens?: number; temperature?: number; signal?: AbortSignal },
  ): Promise<LLMCompletion> {
    // The tier's routing provider goes first; the other saved providers
    // follow as failover. Within each group entries stay in EMA-latency
    // order. When only one provider is saved it serves both tiers whatever
    // the routing defaults say.
    const preferredId = (
      tier === 'reasoning' ? this.routing?.reasoningProvider : this.routing?.workerProvider
    )
      ?.toLowerCase()
      .trim();
    const byEma = (a: PoolEntry, b: PoolEntry) =>
      (this.emaLatency.get(a.providerId) ?? 0) - (this.emaLatency.get(b.providerId) ?? 0);
    const ordered = this.entries
      .filter((e) => !this.isCoolingDown(e.providerId))
      .sort((a, b) => {
        const aPref = preferredId ? a.providerId.toLowerCase() === preferredId : false;
        const bPref = preferredId ? b.providerId.toLowerCase() === preferredId : false;
        if (aPref !== bPref) return aPref ? -1 : 1;
        return byEma(a, b);
      });
    if (ordered.length === 0) {
      throw new Error('All LLM providers are cooling down after failures');
    }
    let lastError: unknown = null;
    for (const entry of ordered) {
      const started = this.now();
      try {
        const completion = await entry.provider.complete({
          messages,
          maxTokens: opts?.maxTokens,
          temperature: opts?.temperature,
          tier: tier === 'reasoning' ? 'reasoning' : 'routine',
          ...(opts?.signal ? { signal: opts.signal } : {}),
        });
        const elapsed = Math.max(0, this.now() - started);
        const prev = this.emaLatency.get(entry.providerId);
        this.emaLatency.set(entry.providerId, prev === undefined ? elapsed : Math.round(prev * 0.7 + elapsed * 0.3));
        this.failures.delete(entry.providerId);
        this.cooledUntil.delete(entry.providerId);
        completion.usage = {
          ...completion.usage,
          inputTokens: finiteInt(completion.usage.inputTokens),
          outputTokens: finiteInt(completion.usage.outputTokens),
        };
        if (!completion.providerId) completion.providerId = entry.providerId;
        if (!completion.model) {
          completion.model =
            tier === 'reasoning'
              ? (entry.reasoningModel ?? PROVIDER_REGISTRY[entry.providerId as ProviderId]?.defaultModels.reasoning)
              : (entry.workerModel ?? PROVIDER_REGISTRY[entry.providerId as ProviderId]?.defaultModels.worker);
        }
        return completion;
      } catch (err) {
        lastError = err;
        const status = (err as { status?: unknown })?.status;
        if (status === 400) throw err;
        const count = (this.failures.get(entry.providerId) ?? 0) + 1;
        this.failures.set(entry.providerId, count);
        const step = POOL_COOLDOWN_STEPS_MS[Math.min(count - 1, POOL_COOLDOWN_STEPS_MS.length - 1)];
        this.cooledUntil.set(entry.providerId, this.now() + step);
      }
    }
    throw lastError ?? new Error('All LLM providers failed');
  }
}

export interface SavedProviderKey {
  providerId: string;
  apiKey: string;
  baseUrl: string | null;
}

export interface PoolRouting {
  workerProvider?: string | null;
  workerModel?: string | null;
  reasoningProvider?: string | null;
  reasoningModel?: string | null;
}

/**
 * Build a pool strictly from the user's verified saved keys. The routing
 * models apply to the matching tier provider; every other provider uses
 * its registry default models. Null when the user saved no keys: the
 * caller then falls back to the legacy single-key / platform path.
 */
export function buildPoolFromKeys(
  keys: SavedProviderKey[],
  routing?: PoolRouting | null,
): LlmProviderPool | null {
  if (!keys || keys.length === 0) return null;
  const entries: PoolEntry[] = [];
  for (const key of keys) {
    const id = key.providerId.toLowerCase();
    if (!(id in PROVIDER_REGISTRY)) continue;
    const providerId = id as ProviderId;
    const spec = PROVIDER_REGISTRY[providerId];
    const overrides: ProviderModelOverrides = {
      workerModel:
        routing?.workerProvider === providerId && routing.workerModel
          ? routing.workerModel
          : spec.defaultModels.worker,
      reasoningModel:
        routing?.reasoningProvider === providerId && routing.reasoningModel
          ? routing.reasoningModel
          : spec.defaultModels.reasoning,
    };
    entries.push({
      providerId,
      provider: createProviderForUser(providerId, key.apiKey, key.baseUrl ?? undefined, overrides),
      workerModel: overrides.workerModel,
      reasoningModel: overrides.reasoningModel,
    });
  }
  if (entries.length === 0) return null;
  return new LlmProviderPool(entries, { routing: routing ?? null });
}

/** Pool with a mock entry, only when mockAllowed() says so. Never silent. */
export function createMockPool(): LlmProviderPool | null {
  if (!mockAllowed()) return null;
  return new LlmProviderPool([{ providerId: 'mock', provider: new MockProvider() }]);
}

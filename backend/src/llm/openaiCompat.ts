import {
  makeCompletion,
  type LLMCompletion,
  type LLMCompletionRequest,
  type LLMProvider,
} from './provider.js';
import { PROVIDER_REGISTRY, validateProviderBaseUrl, type ProviderId } from './registry.js';

export type OpenAiCompatProviderId = 'qwen' | 'kimi' | 'glm' | 'deepseek' | 'openrouter' | 'ollama';

export const OPENAI_COMPAT_TIMEOUT_MS = 45_000;

export function finiteInt(value: unknown): number {
  const n = Number(value);
  return Number.isFinite(n) ? Math.trunc(n) : 0;
}

export function safeErrorCode(status: number): string {
  if (status === 429) return 'rate_limited';
  if (status === 401 || status === 403) return 'invalid_key';
  if (status === 404) return 'model_not_found';
  return 'provider_error';
}

export function sanitizedProviderError(provider: string, status: number): Error {
  const err = new Error(`${provider} API error ${status}: ${safeErrorCode(status)}`);
  (err as unknown as { status: number }).status = status;
  return err;
}

function errorCodeOf(err: unknown): string | undefined {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === 'string' ? code : undefined;
}

/**
 * Single OpenAI-compatible chat completions adapter. One code path for
 * every provider that speaks the /chat/completions dialect, so timeout,
 * error sanitising and token accounting cannot drift per provider.
 */
export class OpenAiCompatProvider implements LLMProvider {
  readonly name: string;
  readonly providerId: OpenAiCompatProviderId;
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly workerModel: string;
  private readonly reasoningModel: string;

  constructor(
    providerId: OpenAiCompatProviderId,
    apiKey: string,
    baseUrl?: string,
    workerModel?: string,
    reasoningModel?: string,
  ) {
    const spec = PROVIDER_REGISTRY[providerId];
    if (!apiKey || !apiKey.trim()) {
      throw new Error(`${spec.label} API key is required`);
    }
    this.providerId = providerId;
    this.name = providerId;
    this.apiKey = apiKey.trim();
    this.baseUrl = validateProviderBaseUrl(providerId, baseUrl);
    this.workerModel = (workerModel ?? spec.defaultModels.worker).trim();
    this.reasoningModel = (reasoningModel ?? spec.defaultModels.reasoning).trim();
  }

  modelForTier(tier: 'worker' | 'reasoning'): string {
    return tier === 'reasoning' ? this.reasoningModel : this.workerModel;
  }

  async complete(req: LLMCompletionRequest): Promise<LLMCompletion> {
    const tier = req.tier === 'reasoning' || req.tier === 'code' ? 'reasoning' : 'worker';
    const model = this.modelForTier(tier);
    const signal = req.signal ?? AbortSignal.timeout(OPENAI_COMPAT_TIMEOUT_MS);
    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify({
          model,
          messages: req.messages.map((m) => ({ role: m.role, content: m.content })),
          temperature: req.temperature ?? 0.2,
          max_tokens: req.maxTokens ?? 2000,
        }),
        signal,
      });
    } catch (err) {
      if (errorCodeOf(err) === 'ERR_CANCELED') throw err;
      const name = (err as { name?: string })?.name ?? '';
      if (name === 'TimeoutError' || name === 'AbortError') throw err;
      throw err;
    }
    if (!res.ok) {
      await res.text().catch(() => '');
      throw sanitizedProviderError(this.providerId, res.status);
    }
    const data = (await res.json()) as {
      choices?: Array<{ message?: { content?: unknown }; finish_reason?: string }>;
      usage?: {
        prompt_tokens?: unknown;
        completion_tokens?: unknown;
        prompt_tokens_details?: { cached_tokens?: unknown };
      };
    };
    const text = data?.choices?.[0]?.message?.content;
    if (!text || typeof text !== 'string') {
      throw new Error(
        `${this.providerId} returned no text content (finish_reason: ${data?.choices?.[0]?.finish_reason ?? 'unknown'})`,
      );
    }
    const usage = data?.usage ?? {};
    const cached = finiteInt(usage.prompt_tokens_details?.cached_tokens);
    const completion = makeCompletion(text, {
      inputTokens: finiteInt(usage.prompt_tokens),
      outputTokens: finiteInt(usage.completion_tokens),
      ...(cached > 0 ? { cacheReadTokens: cached } : {}),
    });
    completion.providerId = this.providerId;
    completion.model = model;
    return completion;
  }
}

export type { ProviderId };

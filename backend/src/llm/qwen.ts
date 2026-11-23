import { config } from '../config.js';
import { redactText } from '../guardrails/redact.js';
import {
  makeCompletion,
  type LLMCompletion,
  type LLMCompletionRequest,
  type LLMProvider,
} from './provider.js';

/**
 * Patterns matching specialized non-text models (embeddings, TTS, audio,
 * image, vision-only, omni-modal, rerankers, transcription) that cannot
 * serve a plain text chat completion. Mirrors gemini.ts's
 * isTextGenerationModel style, extended for the DashScope catalog.
 */
const NON_TEXT_MODEL_PATTERNS = [
  /embedding/i,
  /tts/i,
  /audio/i,
  /image/i,
  /rerank/i,
  /transcri/i,
  /omni/i,
  /whisper/i,
  /(^|[-_.])vl([-_.]|$)/i,
];

/**
 * Returns true if the model name indicates a text-generation capable LLM,
 * and false for specialized media/audio/embedding models.
 */
export function isTextGenerationModel(name: string): boolean {
  if (!name || typeof name !== 'string') return false;
  const lower = name.toLowerCase();
  return !NON_TEXT_MODEL_PATTERNS.some((pattern) => pattern.test(lower));
}

/**
 * True when an error is a fetch abort / timeout (AbortSignal.timeout fires
 * a DOMException named TimeoutError). Treated as "this model is hanging",
 * not as a fatal call failure, so the cascade can try the next candidate.
 */
export function isTimeoutError(err: unknown): boolean {
  const name = (err as any)?.name ?? '';
  const message = String((err as any)?.message ?? '');
  return name === 'TimeoutError' || name === 'AbortError' || /timed out|aborted/i.test(message);
}

/**
 * Qwen (Alibaba DashScope, OpenAI-compatible) implementation.
 *
 * REST endpoint: {baseUrl}/chat/completions (OpenAI-compatible mode)
 * Auth: Authorization: Bearer <key>. The key is read ONLY from the
 * QWEN_API_KEY env var or user BYOK, never hardcoded, never logged.
 *
 * Region matters: a key issued for one DashScope region returns 401 on
 * another region's base URL. Defaults to the international endpoint;
 * override with QWEN_BASE_URL (Beijing / US endpoints).
 *   intl:    https://dashscope-intl.aliyuncs.com/compatible-mode/v1
 *   Beijing: https://dashscope.aliyuncs.com/compatible-mode/v1
 *   US:      https://dashscope-us.aliyuncs.com/compatible-mode/v1
 *
 * Tiered routing (cost control, the user is a cost-sensitive student):
 * - tier 'routine'   → QWEN_ROUTINE_MODEL   (default qwen3.8-flash: cheap, fast)
 * - tier 'reasoning' → QWEN_REASONING_MODEL (default qwen3.7-plus: strong reasoning)
 * - tier 'code'      → QWEN_CODE_MODEL      (default qwen3.7-plus, then
 *   qwen3-coder-flash when discovery shows it, then qwen3.8-max)
 * - escalation: the hardest calls cascade past the plus-class model to
 *   qwen3.8-max when the plus candidate fails.
 *
 * Dynamic Model Discovery & Multi-Candidate Fallback (mirrors gemini.ts):
 * GET {baseUrl}/models lists the models this key can use; non-text models
 * are filtered out. If discovery returns nothing, a static fallback
 * catalog is used. Candidates are tried in priority order; a timeout or
 * a 404/unknown-model error cascades to the next candidate, 401/403 fail
 * fast, and the first working model is locked in per tier.
 */
export class QwenProvider implements LLMProvider {
  readonly name = 'qwen';
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly routineModel: string;
  private readonly reasoningModel: string;
  private readonly codeModel: string;

  private static cachedModels = new Map<string, string[]>();
  private activeRoutineModel?: string;
  private activeReasoningModel?: string;
  private activeCodeModel?: string;

  constructor(
    apiKey?: string,
    baseUrl?: string,
    routineModel?: string,
    reasoningModel?: string,
    codeModel?: string
  ) {
    const key = apiKey ?? config.qwenApiKey;
    if (!key) {
      throw new Error('QWEN_API_KEY is required for the Qwen provider');
    }
    this.apiKey = key.trim();
    this.baseUrl = (baseUrl ?? config.qwenBaseUrl).trim().replace(/\/+$/, '');
    this.routineModel = (routineModel ?? config.qwenRoutineModel).trim();
    this.reasoningModel = (reasoningModel ?? config.qwenReasoningModel).trim();
    this.codeModel = (codeModel ?? config.qwenCodeModel).trim();
  }

  /**
   * Resets the static model discovery cache.
   */
  static resetModelCache(): void {
    QwenProvider.cachedModels.clear();
  }

  /**
   * Cache key: discovery results depend on both the key and the region
   * (base URL), so both are part of the cache key.
   */
  private cacheKey(): string {
    return `${this.baseUrl}\n${this.apiKey}`;
  }

  /**
   * Dynamically query GET {baseUrl}/models for this API key to discover
   * which text chat models are available. Result is cached in memory per
   * key + base URL. Returns [] on any failure, callers fall back to the
   * static catalog.
   */
  async getAvailableModels(): Promise<string[]> {
    const key = this.cacheKey();
    const cached = QwenProvider.cachedModels.get(key);
    if (cached && cached.length > 0) return cached;

    try {
      const res = await fetch(`${this.baseUrl}/models`, {
        headers: { Authorization: `Bearer ${this.apiKey}` },
        signal: AbortSignal.timeout(8000),
      });

      if (res.ok) {
        const body = (await res.json()) as any;
        const models = (body.data ?? [])
          .map((m: any) => (typeof m?.id === 'string' ? m.id : ''))
          .filter((id: string) => id.length > 0 && isTextGenerationModel(id));

        if (models.length > 0) {
          QwenProvider.cachedModels.set(key, models);
          return models;
        }
      }
    } catch {
      // Ignore network / timeout issues during discovery and proceed to fallbacks
    }
    return [];
  }

  /**
   * Static fallback catalog, used only when discovery returns nothing.
   * NOTE: qwen3-coder-plus was retired 10 Oct 2026 (replaced by
   * qwen3.7-plus), it is deliberately NOT in this list. qwen3-coder-flash
   * is only used when discovery proves it exists for this key.
   */
  static fallbackCatalog(): string[] {
    return ['qwen3.8-flash', 'qwen3.7-plus', 'qwen3.8-max', 'qwen-plus', 'qwen-max', 'qwen-turbo'];
  }

  /**
   * Determine prioritized list of candidate models for the requested tier.
   * A locked-in working model short-circuits to a single candidate.
   */
  getCandidateModels(
    tier: 'routine' | 'reasoning' | 'code',
    available: string[]
  ): string[] {
    const active =
      tier === 'reasoning'
        ? this.activeReasoningModel
        : tier === 'code'
          ? this.activeCodeModel
          : this.activeRoutineModel;
    if (active && isTextGenerationModel(active)) {
      return [active];
    }

    const priorityPool =
      tier === 'reasoning'
        ? [
            this.reasoningModel,
            'qwen3.7-plus',
            'qwen3.8-max',
            'qwen-plus',
            'qwen-max',
          ]
        : tier === 'code'
          ? [
              this.codeModel,
              'qwen3.7-plus',
              // qwen3-coder-flash only if discovery shows it exists.
              ...(available.includes('qwen3-coder-flash') ? ['qwen3-coder-flash'] : []),
              'qwen3.8-max',
              'qwen-plus',
            ]
          : [
              this.routineModel,
              'qwen3.8-flash',
              'qwen-turbo',
              'qwen-plus',
              'qwen3.7-plus',
            ];

    const safeAvailable = available.filter(isTextGenerationModel);

    if (safeAvailable.length > 0) {
      const candidates: string[] = [];
      // 1. Exact priority matches present in discovered available models
      for (const p of priorityPool) {
        if (safeAvailable.includes(p) && !candidates.includes(p) && isTextGenerationModel(p)) {
          candidates.push(p);
        }
      }
      // 2. Any available models matching the tier's preferred keyword
      const keyword = tier === 'routine' ? 'flash' : tier === 'code' ? 'coder' : 'plus';
      for (const m of safeAvailable) {
        if (m.includes(keyword) && !candidates.includes(m) && isTextGenerationModel(m)) {
          candidates.push(m);
        }
      }
      // 3. Any other available text models
      for (const m of safeAvailable) {
        if (!candidates.includes(m) && isTextGenerationModel(m)) {
          candidates.push(m);
        }
      }
      if (candidates.length > 0) return candidates;
    }

    // Fallback: deduplicated, text-only priority pool (plus the static
    // catalog for tiers whose pool is short).
    const pool = [...priorityPool, ...QwenProvider.fallbackCatalog()];
    return Array.from(new Set(pool.filter(isTextGenerationModel)));
  }

  async complete(req: LLMCompletionRequest): Promise<LLMCompletion> {
    const tier = req.tier ?? 'routine';

    const body: Record<string, unknown> = {
      messages: req.messages.map((m) => ({ role: m.role, content: m.content })),
      temperature: req.temperature ?? 0.2,
      max_tokens: req.maxTokens ?? 2000,
    };

    const available = await this.getAvailableModels();
    const candidates = this.getCandidateModels(tier, available);

    let lastError: any = null;
    for (const model of candidates) {
      const url = `${this.baseUrl}/chat/completions`;
      const attemptStarted = Date.now();
      try {
        const data = await this.postWithRetry(url, { ...body, model });

        // Success! Remember this working model for future calls
        if (tier === 'reasoning') {
          this.activeReasoningModel = model;
        } else if (tier === 'code') {
          this.activeCodeModel = model;
        } else {
          this.activeRoutineModel = model;
        }

        return this.parseResponse(data);
      } catch (err: any) {
        lastError = err;
        const status = err?.status;
        const message = String(err?.message ?? '');
        const elapsedMs = Date.now() - attemptStarted;
        const isTimeout = isTimeoutError(err);
        const isNotFoundOrIncompatible =
          status === 404 ||
          /not found|does not exist|model .* not (exist|available|supported)|invalid model/i.test(
            message
          );

        if (isTimeout || isNotFoundOrIncompatible) {
          console.warn(
            `[qwen] Model "${model}" ${
              isTimeout ? `timed out after ${elapsedMs}ms` : `is unavailable (${status})`
            }: ${message.slice(0, 140)} — trying next candidate...`
          );
          // Clear active model if it failed
          if (tier === 'reasoning' && this.activeReasoningModel === model) {
            this.activeReasoningModel = undefined;
          } else if (tier === 'code' && this.activeCodeModel === model) {
            this.activeCodeModel = undefined;
          } else if (tier === 'routine' && this.activeRoutineModel === model) {
            this.activeRoutineModel = undefined;
          }
          continue; // try next candidate model
        }

        console.warn(`[qwen] Model "${model}" failed after ${elapsedMs}ms: ${message.slice(0, 140)}`);
        // For non-compatibility errors (401 auth, 403 quota, schema), fail fast
        throw err;
      }
    }

    throw lastError ?? new Error(`All candidate Qwen models failed for tier "${tier}"`);
  }

  private parseResponse(data: any): LLMCompletion {
    const choice = data?.choices?.[0];
    const text = choice?.message?.content;
    if (!text || typeof text !== 'string') {
      throw new Error(
        `Qwen returned no text content (finish_reason: ${choice?.finish_reason ?? 'unknown'})`
      );
    }
    const usage = data?.usage ?? {};
    const inTokens = Number(usage.prompt_tokens ?? 0);
    const outTokens = Number(usage.completion_tokens ?? 0);
    const cachedTokens = Number(usage.prompt_tokens_details?.cached_tokens ?? NaN);
    return makeCompletion(text, {
      inputTokens: Number.isFinite(inTokens) ? inTokens : 0,
      outputTokens: Number.isFinite(outTokens) ? outTokens : 0,
      ...(Number.isFinite(cachedTokens) && cachedTokens > 0
        ? { cacheReadTokens: cachedTokens }
        : {}),
    });
  }

  /**
   * POST with one retry on transient statuses (429 / 5xx), exponential backoff.
   * Keeps paid calls minimal: at most 2 attempts per candidate model.
   */
  private async postWithRetry(url: string, body: Record<string, unknown>): Promise<any> {
    let lastError: Error | null = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      if (attempt > 0) {
        await new Promise((r) => setTimeout(r, 1000 * Math.pow(2, attempt - 1)));
      }
      let res: Response;
      try {
        res = await fetch(url, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            Authorization: `Bearer ${this.apiKey}`,
          },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(30_000),
        });
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        lastError = error;
        // A fetch abort (TimeoutError) means this model is hanging.
        // Retrying the same endpoint would burn the worker's budget, so fail
        // fast and let complete() cascade to the next candidate.
        if (isTimeoutError(error)) throw error;
        continue;
      }
      if (res.ok) {
        return (await res.json()) as any;
      }
      const rawPayload = await res.text().catch(() => '');
      // Never surface the raw provider body: it can echo key material
      // or request details. Same treatment as Gemini (key= stripped,
      // then the shared redactor scrubs secret shapes and truncates).
      const sanitizedPayload = redactText(
        rawPayload.replace(/([?&]key=)[^&"'\s]+/gi, '$1REDACTED'),
        300,
      );
      const err = new Error(`Qwen API error ${res.status}: ${sanitizedPayload}`);
      (err as any).status = res.status;
      lastError = err;
      if (res.status !== 429 && res.status < 500) break; // non-transient, don't retry
    }
    throw lastError ?? new Error('Qwen request failed');
  }
}

/**
 * Cross-provider failover: tries providers in order and falls through to
 * the next one on any provider-side failure (timeout, 401/403, 429, 5xx,
 * transport error). NEVER falls through on a 400/invalid-request error,
 * that means the request itself is bad and no provider would accept it.
 * Used so a BYOK Qwen failure falls back to the server Gemini key.
 */
export class FailoverProvider implements LLMProvider {
  readonly name: string;
  private readonly providers: LLMProvider[];

  constructor(providers: LLMProvider[]) {
    if (!providers || providers.length === 0) {
      throw new Error('FailoverProvider requires at least one provider');
    }
    this.providers = [...providers];
    this.name = `failover:${this.providers.map((p) => p.name).join('+')}`;
  }

  async complete(req: LLMCompletionRequest): Promise<LLMCompletion> {
    let lastError: any = null;
    for (const provider of this.providers) {
      const attemptStarted = Date.now();
      try {
        return await provider.complete(req);
      } catch (err: any) {
        lastError = err;
        const status = err?.status;
        const message = String(err?.message ?? '');
        const elapsedMs = Date.now() - attemptStarted;

        // A 400 means the request itself is invalid, no provider will
        // accept it, so do not burn the next provider's budget on it.
        if (status === 400 || /invalid[_ ]request/i.test(message)) {
          throw err;
        }

        console.warn(
          `[failover] provider "${provider.name}" failed after ${elapsedMs}ms (status ${status ?? 'n/a'}): ${message.slice(0, 140)} — trying next provider...`
        );
      }
    }
    throw lastError ?? new Error('All failover providers failed');
  }
}

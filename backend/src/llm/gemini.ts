import { createHash } from 'node:crypto';
import { config } from '../config.js';
import { makeCompletion, type LLMCompletion, type LLMCompletionRequest, type LLMProvider } from './provider.js';
import { finiteInt, safeErrorCode } from './openaiCompat.js';

const MODEL_CACHE_TTL_MS = 15 * 60_000;
const CASCADE_TIMEOUT_MS = 45_000;

/** Provider error bodies are never surfaced raw: only the structured message field, redacted and short. */
export function sanitizedGeminiError(status: number, rawBody: string): Error {
  let detail = '';
  try {
    const parsed = JSON.parse(rawBody) as { error?: { message?: unknown } };
    if (typeof parsed?.error?.message === 'string') detail = parsed.error.message;
  } catch {
    detail = '';
  }
  const clean = detail.replace(/([?&]key=)[^&"'\s]+/gi, '$1REDACTED').slice(0, 140);
  const err = new Error(
    clean ? `Gemini API error ${status}: ${clean}` : `Gemini API error ${status}: ${safeErrorCode(status)}`,
  );
  (err as unknown as { status: number }).status = status;
  return err;
}

/**
 * Patterns matching specialized non-text models (TTS, audio-only, embeddings,
 * image generation, live websocket sessions) that cannot generate text output.
 */
const NON_TEXT_MODEL_PATTERNS = [
  /tts/i,
  /audio/i,
  /embedding/i,
  /imagen/i,
  /live/i,
  /aqa/i,
  /whisper/i,
  /transcribe/i,
];

/**
 * Returns true if the model name indicates a text-generation capable LLM,
 * and false for specialized media/audio/TTS models (e.g. gemini-2.5-flash-preview-tts).
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
 * Google Gemini (AI Studio Developer API) implementation, the DEFAULT provider.
 *
 * REST endpoint: https://generativelanguage.googleapis.com/{version}/models/{model}:generateContent
 * Auth: `x-goog-api-key` header only. The key never goes in a URL query
 * string, it would land in server and proxy logs.
 * The API key is read ONLY from the GEMINI_API_KEY env var or user BYOK, never hardcoded,
 * and always redacted from errors/logs.
 *
 * Tiered routing (cost control, the user is a cost-sensitive student):
 * - tier 'routine'   → GEMINI_ROUTINE_MODEL   (default gemini-2.0-flash: cheap, ultra-fast)
 * - tier 'reasoning' → GEMINI_REASONING_MODEL (default gemini-2.0-flash / gemini-1.5-pro: strong reasoning)
 *
 * Dynamic Model Discovery & Multi-Candidate Fallback:
 * Dynamically queries `ModelService.ListModels` to discover the exact models supported
 * by the user's specific API key for `generateContent`. Filters out non-text models
 * (such as `-tts` or `-audio` variants). If a model 404s or returns 400 for unsupported
 * modalities, cascades through text-capable candidates ('gemini-2.0-flash', 'gemini-2.5-flash', etc.)
 * across v1beta and v1 endpoints, locking in the first working model for subsequent calls.
 */
export class GeminiProvider implements LLMProvider {
  readonly name = 'gemini';
  private readonly apiKey: string;
  private readonly routineModel: string;
  private readonly reasoningModel: string;

  private static cachedModels = new Map<string, { models: string[]; expiresAt: number }>();
  private activeRoutineModel?: string;
  private activeReasoningModel?: string;

  constructor(apiKey?: string, routineModel?: string, reasoningModel?: string) {
    const key = apiKey ?? config.geminiApiKey;
    if (!key) {
      throw new Error('GEMINI_API_KEY is required for the Gemini provider');
    }
    this.apiKey = key.trim();
    this.routineModel = (routineModel ?? config.geminiRoutineModel).trim();
    this.reasoningModel = (reasoningModel ?? config.geminiReasoningModel).trim();
  }

  /**
   * Resets the static model discovery cache.
   */
  static resetModelCache(): void {
    GeminiProvider.cachedModels.clear();
  }

  /**
   * Dynamically query ModelService.ListModels for this API key to discover which
   * models support `generateContent` for text. Result is cached in memory per API key.
   */
  /** Cache key is a hash of the key, never the key itself, and entries expire after 15 minutes. */
  private cacheKey(): string {
    return createHash('sha256').update(this.apiKey).digest('hex');
  }

  async getAvailableModels(): Promise<string[]> {
    const key = this.cacheKey();
    const cached = GeminiProvider.cachedModels.get(key);
    if (cached && cached.expiresAt > Date.now() && cached.models.length > 0) return cached.models;
    if (cached) GeminiProvider.cachedModels.delete(key);

    try {
      const url = 'https://generativelanguage.googleapis.com/v1beta/models';
      const res = await fetch(url, {
        headers: {
          'x-goog-api-key': this.apiKey,
        },
        signal: AbortSignal.timeout(8000),
      });

      if (res.ok) {
        const body = (await res.json()) as any;
        const models = (body.models ?? [])
          .filter(
            (m: any) =>
              Array.isArray(m.supportedGenerationMethods) &&
              m.supportedGenerationMethods.includes('generateContent') &&
              typeof m.name === 'string' &&
              isTextGenerationModel(m.name)
          )
          .map((m: any) => m.name.replace(/^models\//, ''));

        if (models.length > 0) {
          GeminiProvider.cachedModels.set(key, { models, expiresAt: Date.now() + MODEL_CACHE_TTL_MS });
          return models;
        }
      }
    } catch {
      // Ignore network / timeout issues during discovery and proceed to fallbacks
    }
    return [];
  }

  /**
   * Determine prioritized list of candidate models for the requested tier.
   * Guarantees all candidates are valid text-generation models.
   * Tier 'code' has no separate Gemini pool, it maps onto the reasoning
   * pool (the strongest general models handle code review too).
   */
  getCandidateModels(tier: 'routine' | 'reasoning' | 'code', available: string[]): string[] {
    const effectiveTier: 'routine' | 'reasoning' = tier === 'reasoning' || tier === 'code' ? 'reasoning' : 'routine';
    const active = effectiveTier === 'reasoning' ? this.activeReasoningModel : this.activeRoutineModel;
    if (active && isTextGenerationModel(active)) {
      return [active];
    }

    let configured = effectiveTier === 'reasoning' ? this.reasoningModel : this.routineModel;
    // Normalize legacy model strings. gemini-3.8-flash is real (Google's
    // free-tier model for new projects) and must not be rewritten.
    if (configured.includes('3.5-flash')) {
      configured = 'gemini-2.0-flash';
    } else if (configured.includes('3.1-pro')) {
      configured = 'gemini-2.0-flash';
    }

    const priorityPool =
      effectiveTier === 'reasoning'
        ? [
            configured,
            'gemini-2.5-pro',
            'gemini-2.5-pro-preview',
            'gemini-2.5-flash',
            'gemini-2.5-flash-preview',
            'gemini-2.0-flash',
            'gemini-1.5-pro',
            'gemini-1.5-pro-latest',
            'gemini-1.5-pro-001',
            'gemini-1.5-pro-002',
            'gemini-1.5-flash-latest',
            'gemini-1.5-flash',
            'gemini-pro',
          ]
        : [
            configured,
            'gemini-2.5-flash',
            'gemini-2.5-flash-preview',
            'gemini-2.0-flash',
            'gemini-2.0-flash-lite',
            'gemini-2.0-flash-lite-preview',
            'gemini-1.5-flash-latest',
            'gemini-1.5-flash',
            'gemini-1.5-flash-001',
            'gemini-1.5-flash-002',
            'gemini-1.5-flash-8b',
            'gemini-2.0-flash-exp',
            'gemini-1.5-pro-latest',
            'gemini-1.5-pro',
            'gemini-pro',
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
      // 2. Any available models matching the tier's preferred keyword ('flash' or 'pro')
      const keyword = effectiveTier === 'reasoning' ? 'pro' : 'flash';
      for (const m of safeAvailable) {
        if (m.includes(keyword) && !candidates.includes(m) && isTextGenerationModel(m)) {
          candidates.push(m);
        }
      }
      // 3. Any other available text models supporting generateContent
      for (const m of safeAvailable) {
        if (!candidates.includes(m) && isTextGenerationModel(m)) {
          candidates.push(m);
        }
      }
      if (candidates.length > 0) return candidates;
    }

    // Fallback: return deduplicated, text-only priority pool
    return Array.from(new Set(priorityPool.filter(isTextGenerationModel)));
  }

  /**
   * Worker-model fallback for a failed reasoning model: the configured
   * routine model when it differs from the failed one, else the standard
   * flash model. Null when no distinct fallback exists (the reasoning
   * model already is flash), so the caller fails loudly instead.
   */
  private downgradeModel(failedModel: string): string | null {
    let routine = this.routineModel;
    if (routine.includes('3.5-flash')) routine = 'gemini-2.0-flash';
    if (isTextGenerationModel(routine) && routine !== failedModel) return routine;
    if (failedModel !== 'gemini-2.5-flash') return 'gemini-2.5-flash';
    return null;
  }

  async complete(req: LLMCompletionRequest): Promise<LLMCompletion> {
    // Tier 'code' shares the reasoning pool (see getCandidateModels), so
    // normalize it here to keep the active-model lock-in consistent.
    const tier: 'routine' | 'reasoning' = req.tier === 'reasoning' || req.tier === 'code' ? 'reasoning' : 'routine';
    const system = req.messages
      .filter((m) => m.role === 'system')
      .map((m) => m.content)
      .join('\n\n');
    const contents = req.messages
      .filter((m) => m.role !== 'system')
      .map((m) => ({
        role: m.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: m.content }],
      }));

    if (contents.length === 0) {
      contents.push({
        role: 'user',
        parts: [{ text: system || 'Execute request' }],
      });
    }

    const body: Record<string, unknown> = {
      contents,
      generationConfig: {
        maxOutputTokens: req.maxTokens ?? 2000,
        temperature: req.temperature ?? 0.2,
      },
    };
    if (system) {
      body['systemInstruction'] = { parts: [{ text: system }] };
    }

    const available = await this.getAvailableModels();
    const candidates = this.getCandidateModels(tier, available);

    // One shared controller caps the whole cascade under 45s; every
    // attempt shares its signal, so a hung model cannot outlive the
    // worker timeout by stacking per-attempt timeouts.
    const controller = new AbortController();
    const cascadeTimer = setTimeout(() => controller.abort(), CASCADE_TIMEOUT_MS);
    let lastError: any = null;
    // At most one reasoning → worker model downgrade per call, and only
    // for 429/5xx: a busy reasoning model falls back to the cheaper flash
    // model instead of hard-failing the call on the first 503.
    let downgraded = false;
    try {
    for (let i = 0; i < candidates.length; i++) {
      const model = candidates[i];
      if (controller.signal.aborted) {
        lastError = new Error('Gemini cascade timed out after 45s');
        break;
      }
      // Try v1beta first, then v1 if 404/incompatible
      const versions = ['v1beta', 'v1'];
      for (const ver of versions) {
        const url = `https://generativelanguage.googleapis.com/${ver}/models/${encodeURIComponent(model)}:generateContent`;
        const attemptStarted = Date.now();
        try {
          const data = await this.postWithRetry(url, body, controller.signal);

          // Success! Remember this working model for future calls
          if (tier === 'reasoning') {
            this.activeReasoningModel = model;
          } else {
            this.activeRoutineModel = model;
          }

          return this.parseResponse(data, model);
        } catch (err: any) {
          lastError = err;
          const status = err?.status;
          const message = String(err?.message ?? '');
          const elapsedMs = Date.now() - attemptStarted;
          const isTimeout = isTimeoutError(err);
          const isNotFoundOrIncompatible =
            status === 404 ||
            message.includes('not found') ||
            message.includes('is not supported for generateContent') ||
            message.includes('response modalities') ||
            message.includes('not supported by the model') ||
            (status === 400 && (message.includes('INVALID_ARGUMENT') || message.includes('modalities')));

          if (isTimeout || isNotFoundOrIncompatible) {
            console.warn(
              `[gemini] Model "${model}" on ${ver} ${isTimeout ? `timed out after ${elapsedMs}ms` : `is incompatible (${status})`}: ${message.slice(0, 140)} — trying next candidate...`
            );
            // Clear active model if it failed
            if (tier === 'reasoning' && this.activeReasoningModel === model) {
              this.activeReasoningModel = undefined;
            } else if (tier === 'routine' && this.activeRoutineModel === model) {
              this.activeRoutineModel = undefined;
            }
            continue; // try next API version or next candidate model
          }

          console.warn(`[gemini] Model "${model}" on ${ver} failed after ${elapsedMs}ms: ${message.slice(0, 140)}`);
          // Reasoning tier only: a 429/5xx (e.g. a 503 overload) on the
          // reasoning model falls back to the worker (flash) model once,
          // with jittered backoff, instead of failing the call outright.
          // The worker tier never escalates: flash is already the fallback.
          const isOverloaded = status === 429 || (typeof status === 'number' && status >= 500);
          if (tier === 'reasoning' && !downgraded && isOverloaded) {
            const fallback = this.downgradeModel(model);
            if (fallback && fallback !== model) {
              downgraded = true;
              if (this.activeReasoningModel === model) this.activeReasoningModel = undefined;
              console.warn(
                `[gemini] Reasoning model "${model}" returned ${status} — falling back to "${fallback}" after jittered backoff...`,
              );
              await new Promise((r) => setTimeout(r, 200 + Math.random() * 600));
              if (!controller.signal.aborted) {
                // Flash is usually already further down the candidate list;
                // pull it forward so it is tried next, not after the other
                // pro-class candidates.
                const existingIdx = candidates.indexOf(fallback);
                if (existingIdx !== -1) candidates.splice(existingIdx, 1);
                candidates.splice(i + 1, 0, fallback);
                break; // leave the version loop; the outer loop tries the fallback next
              }
            }
          }
          // For non-compatibility errors (401 auth, 403 quota, schema, safety block), fail fast
          throw err;
        }
      }
    }

    throw lastError ?? new Error(`All candidate Gemini models failed for tier "${tier}"`);
    } finally {
      clearTimeout(cascadeTimer);
    }
  }

  private parseResponse(data: any, model?: string): LLMCompletion {
    const blockReason = data?.promptFeedback?.blockReason;
    if (blockReason) {
      throw new Error(`Gemini request blocked (safety): ${blockReason}`);
    }
    const candidate = data?.candidates?.[0];
    if (!candidate) {
      throw new Error(
        `Gemini returned no candidates (finishReason: ${data?.candidates?.[0]?.finishReason ?? 'unknown'})`
      );
    }
    const parts: Array<{ text?: string; thought?: boolean }> = candidate.content?.parts ?? [];
    const text = parts
      .filter((p) => typeof p.text === 'string' && !p.thought)
      .map((p) => p.text as string)
      .join('');
    if (!text) {
      throw new Error(
        `Gemini returned an empty response (finishReason: ${candidate.finishReason ?? 'unknown'})`
      );
    }
    const inTokens = finiteInt(data?.usageMetadata?.promptTokenCount);
    const outTokens = finiteInt(data?.usageMetadata?.candidatesTokenCount);
    const completion = makeCompletion(text, {
      inputTokens: inTokens,
      outputTokens: outTokens,
    });
    completion.providerId = 'gemini';
    if (model) completion.model = model;
    return completion;
  }

  /**
   * POST with one retry on transient statuses (429 / 5xx), exponential backoff.
   * Keeps paid calls minimal: at most 2 attempts per completion.
   */
  private async postWithRetry(
    url: string,
    body: Record<string, unknown>,
    signal?: AbortSignal,
  ): Promise<any> {
    let lastError: Error | null = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      if (attempt > 0) {
        await new Promise((r) => setTimeout(r, 1000 * Math.pow(2, attempt - 1)));
      }
      if (signal?.aborted) {
        throw new DOMException('The operation timed out.', 'TimeoutError');
      }
      let res: Response;
      try {
        res = await fetch(url, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-goog-api-key': this.apiKey,
          },
          body: JSON.stringify(body),
          signal: signal ?? AbortSignal.timeout(30_000),
        });
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        lastError = error;
        // A fetch abort (TimeoutError) means this model+version is hanging.
        // Retrying the same endpoint would burn the worker's budget, so fail
        // fast and let complete() cascade to the next version/candidate.
        if (isTimeoutError(error)) throw error;
        continue;
      }
      if (res.ok) {
        return (await res.json()) as any;
      }
      const rawPayload = await res.text().catch(() => '');
      const err = sanitizedGeminiError(res.status, rawPayload);
      lastError = err;
      if (res.status !== 429 && res.status < 500) break; // non-transient, don't retry
    }
    throw lastError ?? new Error('Gemini request failed');
  }
}

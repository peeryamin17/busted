import { config } from '../config.js';
import { makeCompletion, type LLMCompletion, type LLMCompletionRequest, type LLMProvider } from './provider.js';

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
 * Google Gemini (AI Studio Developer API) implementation — the DEFAULT provider.
 *
 * REST endpoint: https://generativelanguage.googleapis.com/{version}/models/{model}:generateContent
 * Auth: Both `x-goog-api-key` header and `?key=` query parameter for maximum proxy compatibility.
 * The API key is read ONLY from the GEMINI_API_KEY env var or user BYOK — never hardcoded,
 * and always redacted from errors/logs.
 *
 * Tiered routing (cost control — the user is a cost-sensitive student):
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

  private static cachedModels = new Map<string, string[]>();
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
  async getAvailableModels(): Promise<string[]> {
    const cached = GeminiProvider.cachedModels.get(this.apiKey);
    if (cached && cached.length > 0) return cached;

    try {
      const url = `https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(this.apiKey)}`;
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
          GeminiProvider.cachedModels.set(this.apiKey, models);
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
   */
  getCandidateModels(tier: 'routine' | 'reasoning', available: string[]): string[] {
    const active = tier === 'reasoning' ? this.activeReasoningModel : this.activeRoutineModel;
    if (active && isTextGenerationModel(active)) {
      return [active];
    }

    let configured = tier === 'reasoning' ? this.reasoningModel : this.routineModel;
    // Normalize legacy or nonexistent model strings
    if (configured.includes('3.8-flash') || configured.includes('3.5-flash')) {
      configured = 'gemini-2.0-flash';
    } else if (configured.includes('3.1-pro')) {
      configured = 'gemini-2.0-flash';
    }

    const priorityPool =
      tier === 'reasoning'
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
      const keyword = tier === 'reasoning' ? 'pro' : 'flash';
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

  async complete(req: LLMCompletionRequest): Promise<LLMCompletion> {
    const tier = req.tier ?? 'routine';
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

    let lastError: any = null;
    for (const model of candidates) {
      // Try v1beta first, then v1 if 404/incompatible
      const versions = ['v1beta', 'v1'];
      for (const ver of versions) {
        const url = `https://generativelanguage.googleapis.com/${ver}/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(this.apiKey)}`;
        try {
          const data = await this.postWithRetry(url, body);

          // Success! Remember this working model for future calls
          if (tier === 'reasoning') {
            this.activeReasoningModel = model;
          } else {
            this.activeRoutineModel = model;
          }

          return this.parseResponse(data);
        } catch (err: any) {
          lastError = err;
          const status = err?.status;
          const message = String(err?.message ?? '');
          const isNotFoundOrIncompatible =
            status === 404 ||
            message.includes('not found') ||
            message.includes('is not supported for generateContent') ||
            message.includes('response modalities') ||
            message.includes('not supported by the model') ||
            (status === 400 && (message.includes('INVALID_ARGUMENT') || message.includes('modalities')));

          if (isNotFoundOrIncompatible) {
            console.warn(
              `[gemini] Model "${model}" on ${ver} is incompatible (${status}): ${message.slice(0, 140)}. Trying next candidate...`
            );
            // Clear active model if it failed
            if (tier === 'reasoning' && this.activeReasoningModel === model) {
              this.activeReasoningModel = undefined;
            } else if (tier === 'routine' && this.activeRoutineModel === model) {
              this.activeRoutineModel = undefined;
            }
            continue; // try next API version or next candidate model
          }

          // For non-compatibility errors (401 auth, 403 quota, schema, safety block), fail fast
          throw err;
        }
      }
    }

    throw lastError ?? new Error(`All candidate Gemini models failed for tier "${tier}"`);
  }

  private parseResponse(data: any): LLMCompletion {
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
    const inTokens = Number(data?.usageMetadata?.promptTokenCount ?? 0);
    const outTokens = Number(data?.usageMetadata?.candidatesTokenCount ?? 0);
    return makeCompletion(text, {
      inputTokens: Number.isFinite(inTokens) ? inTokens : 0,
      outputTokens: Number.isFinite(outTokens) ? outTokens : 0,
    });
  }

  /**
   * POST with one retry on transient statuses (429 / 5xx), exponential backoff.
   * Keeps paid calls minimal: at most 2 attempts per completion.
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
            'x-goog-api-key': this.apiKey,
          },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(30_000),
        });
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
        continue;
      }
      if (res.ok) {
        return (await res.json()) as any;
      }
      const rawPayload = await res.text().catch(() => '');
      const sanitizedPayload = rawPayload.replace(/([?&]key=)[^&"'\s]+/gi, '$1REDACTED');
      const err = new Error(`Gemini API error ${res.status}: ${sanitizedPayload.slice(0, 300)}`);
      (err as any).status = res.status;
      lastError = err;
      if (res.status !== 429 && res.status < 500) break; // non-transient — don't retry
    }
    throw lastError ?? new Error('Gemini request failed');
  }
}

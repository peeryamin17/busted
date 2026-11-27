import { config } from '../config.js';
import { makeCompletion, type LLMCompletion, type LLMCompletionRequest, type LLMProvider } from './provider.js';
import { finiteInt, safeErrorCode } from './openaiCompat.js';
import { PROVIDER_REGISTRY, noFreeDefaultError } from './registry.js';

/**
 * Claude (Anthropic Messages API) implementation.
 * The API key is read ONLY from the ANTHROPIC_API_KEY env var, never
 * hardcoded, never logged. config.ts throws at boot if the key is missing
 * while LLM_PROVIDER=claude.
 */
export class ClaudeProvider implements LLMProvider {
  readonly name = 'claude';
  private readonly apiKey: string;
  private readonly workerModel: string;
  private readonly reasoningModel: string;

  constructor(apiKey?: string, reasoningModel?: string, workerModel?: string, opts?: { allowConfigModels?: boolean }) {
    const key = apiKey ?? config.anthropicApiKey;
    if (!key) {
      throw new Error('ANTHROPIC_API_KEY is required for the Claude provider');
    }
    this.apiKey = key;
    // BYOK keys never fall back to the paid config model: with no free
    // registry default and no explicit model, fail loudly instead. The
    // platform-key path opts into the config model explicitly.
    const reasoning =
      (reasoningModel ??
        (opts?.allowConfigModels ? config.anthropicModel : PROVIDER_REGISTRY.claude.defaultModels.reasoning)
      )?.trim() || null;
    if (!reasoning) throw noFreeDefaultError('claude', 'reasoning');
    this.reasoningModel = reasoning;
    const worker = (workerModel ?? PROVIDER_REGISTRY.claude.defaultModels.worker)?.trim() || null;
    if (!worker) throw noFreeDefaultError('claude', 'worker');
    this.workerModel = worker;
  }

  modelForTier(tier: 'worker' | 'reasoning'): string {
    return tier === 'reasoning' ? this.reasoningModel : this.workerModel;
  }

  async complete(req: LLMCompletionRequest): Promise<LLMCompletion> {
    const tier = req.tier === 'reasoning' || req.tier === 'code' ? 'reasoning' : 'worker';
    const model = this.modelForTier(tier);
    const system = req.messages
      .filter((m) => m.role === 'system')
      .map((m) => m.content)
      .join('\n\n');
    const messages = req.messages
      .filter((m) => m.role !== 'system')
      .map((m) => ({ role: m.role, content: m.content }));

    let res: Response;
    try {
      res = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-api-key': this.apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model,
          max_tokens: req.maxTokens ?? 2000,
          temperature: req.temperature ?? 0.2,
          system: system || undefined,
          messages,
        }),
        signal: req.signal ?? AbortSignal.timeout(45_000),
      });
    } catch (err) {
      throw err instanceof Error ? err : new Error(String(err));
    }

    if (!res.ok) {
      const raw = await res.text().catch(() => '');
      let detail = '';
      try {
        const parsed = JSON.parse(raw) as { error?: { message?: unknown } };
        if (typeof parsed?.error?.message === 'string') detail = parsed.error.message;
      } catch {
        detail = '';
      }
      const clean = detail.slice(0, 140);
      const err = new Error(
        clean
          ? `Anthropic API error ${res.status}: ${clean}`
          : `Anthropic API error ${res.status}: ${safeErrorCode(res.status)}`,
      );
      (err as unknown as { status: number }).status = res.status;
      throw err;
    }
    const data = (await res.json()) as {
      content: Array<{ type: string; text?: string }>;
      usage: { input_tokens: unknown; output_tokens: unknown };
    };
    const text = data.content
      .filter((b) => b.type === 'text' && b.text)
      .map((b) => b.text as string)
      .join('');
    const completion = makeCompletion(text, {
      inputTokens: finiteInt(data.usage.input_tokens),
      outputTokens: finiteInt(data.usage.output_tokens),
    });
    completion.providerId = 'claude';
    completion.model = model;
    return completion;
  }
}

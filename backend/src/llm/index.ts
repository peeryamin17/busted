import { config } from '../config.js';
import type { LLMProvider } from './provider.js';
import { ClaudeProvider } from './claude.js';
import { GeminiProvider } from './gemini.js';
import { MockProvider } from './mock.js';
import { QwenProvider } from './qwen.js';

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

/**
 * Construct a provider for a specific user-supplied (BYOK) key, by provider
 * name. Used by routes that know which provider the user's stored key
 * belongs to (the stored ai_provider column), rather than the server-wide
 * LLM_PROVIDER default.
 *
 * - 'gemini': Google AI key → GeminiProvider.
 * - 'qwen': DashScope key → QwenProvider against the configured (or given)
 *   DashScope base URL.
 * - 'ollama': local Ollama server, a QwenProvider pointed at the local
 *   OpenAI-compatible endpoint with a keyless sentinel (Ollama ignores the
 *   Bearer token). Only used by local paths; never a hosted provider.
 * - anything else: falls back to Gemini (the historical BYOK default).
 */
export function createProviderForUser(
  provider: string,
  apiKey: string,
  baseUrl?: string
): LLMProvider {
  switch (provider.toLowerCase()) {
    case 'qwen':
      return new QwenProvider(apiKey, baseUrl);
    case 'ollama':
      return new QwenProvider(
        'ollama-local',
        baseUrl ?? 'http://localhost:11434/v1'
      );
    case 'gemini':
    default:
      return new GeminiProvider(apiKey);
  }
}

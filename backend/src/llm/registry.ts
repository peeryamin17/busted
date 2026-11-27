export type ProviderId =
  | 'gemini'
  | 'claude'
  | 'qwen'
  | 'kimi'
  | 'glm'
  | 'deepseek'
  | 'openrouter'
  | 'openai'
  | 'ollama'
  | 'omniroute';

export type ModelTier = 'worker' | 'reasoning';

export interface ProviderSpec {
  id: ProviderId;
  label: string;
  protocol: 'openai_compat' | 'gemini' | 'anthropic';
  mode: 'hosted' | 'local';
  defaultBaseUrl: string;
  allowedBaseUrlPatterns: RegExp[];
  defaultModels: Record<ModelTier, string>;
  /** No fixed host: the caller must supply a public base URL at save time. */
  requiresCustomBaseUrl?: boolean;
}

export const PROVIDER_REGISTRY: Record<ProviderId, ProviderSpec> = {
  gemini: {
    id: 'gemini',
    label: 'Google Gemini',
    protocol: 'gemini',
    mode: 'hosted',
    defaultBaseUrl: 'https://generativelanguage.googleapis.com/v1beta',
    allowedBaseUrlPatterns: [/^https:\/\/generativelanguage\.googleapis\.com\/v1beta$/],
    defaultModels: { worker: 'gemini-2.5-flash', reasoning: 'gemini-2.5-pro' },
  },
  claude: {
    id: 'claude',
    label: 'Anthropic Claude',
    protocol: 'anthropic',
    mode: 'hosted',
    defaultBaseUrl: 'https://api.anthropic.com/v1',
    allowedBaseUrlPatterns: [/^https:\/\/api\.anthropic\.com\/v1$/],
    defaultModels: { worker: 'claude-haiku-4-5', reasoning: 'claude-sonnet-4-5' },
  },
  qwen: {
    id: 'qwen',
    label: 'Qwen (DashScope)',
    protocol: 'openai_compat',
    mode: 'hosted',
    defaultBaseUrl: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1',
    allowedBaseUrlPatterns: [
      /^https:\/\/[a-z0-9-]+\.aliyuncs\.com\/compatible-mode\/v1$/,
      // Model Studio workspace endpoints: <workspace-id>.<region>.maas.aliyuncs.com
      /^https:\/\/[a-z0-9-]+\.[a-z0-9-]+\.maas\.aliyuncs\.com\/compatible-mode\/v1$/,
    ],
    defaultModels: { worker: 'qwen3.7-plus', reasoning: 'qwen4-max' },
  },
  kimi: {
    id: 'kimi',
    label: 'Kimi (Moonshot)',
    protocol: 'openai_compat',
    mode: 'hosted',
    defaultBaseUrl: 'https://api.moonshot.ai/v1',
    allowedBaseUrlPatterns: [/^https:\/\/api\.moonshot\.(ai|cn)\/v1$/],
    defaultModels: { worker: 'moonshot-v1-32k', reasoning: 'kimi-k2-0711-preview' },
  },
  glm: {
    id: 'glm',
    label: 'GLM (Zhipu)',
    protocol: 'openai_compat',
    mode: 'hosted',
    defaultBaseUrl: 'https://open.bigmodel.cn/api/paas/v4',
    allowedBaseUrlPatterns: [/^https:\/\/open\.bigmodel\.cn\/api\/paas\/v4$/],
    defaultModels: { worker: 'glm-4-air', reasoning: 'glm-4-plus' },
  },
  deepseek: {
    id: 'deepseek',
    label: 'DeepSeek',
    protocol: 'openai_compat',
    mode: 'hosted',
    defaultBaseUrl: 'https://api.deepseek.com/v1',
    allowedBaseUrlPatterns: [/^https:\/\/api\.deepseek\.com(\/v1)?$/],
    defaultModels: { worker: 'deepseek-chat', reasoning: 'deepseek-reasoner' },
  },
  openrouter: {
    id: 'openrouter',
    label: 'OpenRouter',
    protocol: 'openai_compat',
    mode: 'hosted',
    defaultBaseUrl: 'https://openrouter.ai/api/v1',
    allowedBaseUrlPatterns: [/^https:\/\/openrouter\.ai\/api\/v1$/],
    defaultModels: { worker: 'deepseek/deepseek-chat', reasoning: 'anthropic/claude-sonnet-4.5' },
  },
  openai: {
    id: 'openai',
    label: 'OpenAI',
    protocol: 'openai_compat',
    mode: 'hosted',
    defaultBaseUrl: 'https://api.openai.com/v1',
    allowedBaseUrlPatterns: [/^https:\/\/api\.openai\.com\/v1$/],
    defaultModels: { worker: 'gpt-6-luna', reasoning: 'gpt-6.2-astra' },
  },
  ollama: {
    id: 'ollama',
    label: 'Ollama (Local)',
    protocol: 'openai_compat',
    mode: 'local',
    defaultBaseUrl: 'http://127.0.0.1:11434/v1',
    allowedBaseUrlPatterns: [/^http:\/\/(127\.0\.0\.1|localhost):11434(\/v1)?$/],
    defaultModels: { worker: 'qwen2.5:14b', reasoning: 'deepseek-r1:14b' },
  },
  omniroute: {
    id: 'omniroute',
    label: 'OmniRoute',
    protocol: 'openai_compat',
    mode: 'hosted',
    defaultBaseUrl: '',
    allowedBaseUrlPatterns: [],
    defaultModels: { worker: 'auto', reasoning: 'auto/coding' },
    requiresCustomBaseUrl: true,
  },
};

export function isProviderId(value: string): value is ProviderId {
  return value in PROVIDER_REGISTRY;
}

/**
 * Region-aware default models for a provider. Qwen reasoning varies by
 * DashScope region: the international endpoint gets qwen3.8-max, every
 * other endpoint (Beijing, US, custom workspaces) gets qwen4-max, which
 * is also the registry default when no base URL is known. All other
 * providers return their registry defaultModels unchanged.
 */
export function defaultModelsFor(
  providerId: ProviderId,
  baseUrl?: string | null,
): Record<ModelTier, string> {
  const spec = PROVIDER_REGISTRY[providerId];
  if (providerId === 'qwen') {
    const reasoning =
      baseUrl && baseUrl.includes('dashscope-intl') ? 'qwen3.8-max' : 'qwen4-max';
    return { worker: 'qwen3.7-plus', reasoning };
  }
  return { ...spec.defaultModels };
}

export function validateProviderBaseUrl(providerId: ProviderId, url?: string): string {
  const spec = PROVIDER_REGISTRY[providerId];
  if (spec.requiresCustomBaseUrl) {
    // No fixed host, so no pattern to match: the URL must be supplied and
    // must be https. Scheme and public-host checks happen at save time,
    // where DNS can run; the adapter trusts the stored URL from there.
    const candidate = (url ?? '').trim().replace(/\/$/, '');
    if (!candidate) {
      throw new Error(`Provider ${providerId} needs a base URL; there is no default to fall back to`);
    }
    let parsed: URL;
    try {
      parsed = new URL(candidate);
    } catch {
      throw new Error(`Disallowed base URL for provider ${providerId}`);
    }
    if (parsed.protocol !== 'https:') {
      throw new Error(`Disallowed base URL for provider ${providerId}`);
    }
    return candidate;
  }
  const candidate = (url?.trim() || spec.defaultBaseUrl).replace(/\/$/, '');
  const ok = spec.allowedBaseUrlPatterns.some((re) => re.test(candidate));
  if (!ok) {
    throw new Error(`Disallowed base URL for provider ${providerId}`);
  }
  return candidate;
}

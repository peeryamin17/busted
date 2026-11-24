export type ProviderId =
  | 'gemini'
  | 'claude'
  | 'qwen'
  | 'kimi'
  | 'glm'
  | 'deepseek'
  | 'openrouter'
  | 'ollama';

export type ModelTier = 'worker' | 'reasoning';

export interface LlmProviderCapability {
  id: ProviderId;
  label: string;
  mode: 'hosted' | 'local';
  available: boolean;
  reason?: string;
  defaultModels: Record<ModelTier, string>;
}

export type EngineId = 'httpx' | 'katana' | 'nuclei' | 'whatweb' | 'nikto';

export interface EngineCapability {
  id: EngineId;
  available: boolean;
  reason?: string;
}

export interface CapabilitiesResponse {
  version: string;
  runtime: 'cloud' | 'local';
  llmProviders: LlmProviderCapability[];
  engines: EngineCapability[];
}

export interface SavedAiKey {
  providerId: ProviderId;
  keyHint: string;
  baseUrl: string;
  verifiedAt: string;
}

export interface LlmRouting {
  workerProvider: string;
  workerModel: string | null;
  reasoningProvider: string;
  reasoningModel: string | null;
}

export interface AiKeysListResponse {
  keys: SavedAiKey[];
  routing: LlmRouting;
  hasByok: boolean;
}

export interface SaveAiKeyPayload {
  providerId: ProviderId;
  apiKey: string;
  baseUrl?: string;
}

export interface SaveAiKeyResult {
  providerId: ProviderId;
  keyHint: string;
  baseUrl: string;
  verifiedAt: string;
  hasByok: boolean;
  routingAutoSet: boolean;
  routing: LlmRouting;
}

export interface DeleteAiKeyResult {
  deleted: boolean;
  hasByok: boolean;
}

export interface UpdateRoutingPayload {
  workerProvider: string;
  workerModel: string;
  reasoningProvider: string;
  reasoningModel: string;
}

export type ApiResult<T> =
  | { ok: true; data: T }
  | { ok: false; status: number; error: string };

export type QwenRegion = 'intl' | 'cn' | 'custom';

export const QWEN_BASE_URLS = {
  intl: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1',
  cn: 'https://dashscope.aliyuncs.com/compatible-mode/v1',
} as const;

export function resolveQwenBaseUrl(region: QwenRegion, customUrl: string): string | null {
  if (region === 'intl' || region === 'cn') return QWEN_BASE_URLS[region];
  const raw = customUrl.trim().replace(/\/+$/, '');
  return raw.length > 0 ? raw : null;
}

export function ollamaCapability(caps: CapabilitiesResponse): LlmProviderCapability | undefined {
  return caps.llmProviders.find((p) => p.id === 'ollama');
}

/**
 * One-line save failure for the error slot under the Save key button:
 * the exact HTTP status plus the backend's own message, so a failed
 * save never looks like a silent success.
 */
export function formatSaveKeyError(status: number, message: string): string {
  return status > 0
    ? `Save failed (HTTP ${status}): ${message}`
    : `Save failed: ${message}`;
}

/** Short display name for a provider label ("Qwen (DashScope)" -> "Qwen"). */
export function shortProviderLabel(label: string): string {
  const short = label.replace(/\s*\(.*\)$/, '').trim();
  return short.length > 0 ? short : label;
}

/**
 * Status badge text for the active routing, e.g.
 * "Active: Qwen · worker qwen3.7-plus · reasoning qwen4-max".
 * Models are the effective values from the routing (GET or the POST
 * save response), never placeholders or registry defaults shown as
 * if they were the current configuration.
 */
export function formatRoutingBadge(
  routing: LlmRouting,
  labelFor: (providerId: string) => string,
): string {
  const workerModel = routing.workerModel ?? '';
  const reasoningModel = routing.reasoningModel ?? '';
  const workerLabel = labelFor(routing.workerProvider);
  if (routing.workerProvider === routing.reasoningProvider) {
    return `Active: ${workerLabel} · worker ${workerModel} · reasoning ${reasoningModel}`;
  }
  const reasoningLabel = labelFor(routing.reasoningProvider);
  return (
    `Active: worker ${workerLabel} ${workerModel} · ` +
    `reasoning ${reasoningLabel} ${reasoningModel}`
  );
}

export function hostedProviders(caps: CapabilitiesResponse): LlmProviderCapability[] {
  return caps.llmProviders.filter((p) => p.mode === 'hosted' && p.available);
}

export function modelOptionsFor(
  provider: LlmProviderCapability,
  currentModel: string | null,
): string[] {
  const options = [provider.defaultModels.worker, provider.defaultModels.reasoning];
  if (currentModel && !options.includes(currentModel)) options.push(currentModel);
  return options;
}

async function readError(res: Response): Promise<string> {
  const data = (await res.json().catch(() => null)) as { error?: unknown } | null;
  if (data && typeof data.error === 'string' && data.error.length > 0) return data.error;
  return `Request failed (HTTP ${res.status})`;
}

async function callApi<T>(
  fetchImpl: typeof fetch,
  path: string,
  init: RequestInit,
): Promise<ApiResult<T>> {
  let res: Response;
  try {
    res = await fetchImpl(path, {
      credentials: 'include',
      signal: AbortSignal.timeout(15_000),
      ...init,
    });
  } catch (err) {
    return {
      ok: false,
      status: 0,
      error: err instanceof Error ? err.message : 'Could not reach the backend.',
    };
  }
  if (!res.ok) {
    return { ok: false, status: res.status, error: await readError(res) };
  }
  const data = (await res.json().catch(() => null)) as T;
  return { ok: true, data };
}

export function fetchCapabilities(
  fetchImpl: typeof fetch = globalThis.fetch,
): Promise<ApiResult<CapabilitiesResponse>> {
  return callApi<CapabilitiesResponse>(fetchImpl, '/api/v1/capabilities', {});
}

export function listAiKeys(
  fetchImpl: typeof fetch = globalThis.fetch,
): Promise<ApiResult<AiKeysListResponse>> {
  return callApi<AiKeysListResponse>(fetchImpl, '/api/v1/ai-keys', {});
}

export function saveAiKey(
  payload: SaveAiKeyPayload,
  fetchImpl: typeof fetch = globalThis.fetch,
): Promise<ApiResult<SaveAiKeyResult>> {
  return callApi<SaveAiKeyResult>(fetchImpl, '/api/v1/ai-keys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export function deleteAiKey(
  providerId: ProviderId,
  fetchImpl: typeof fetch = globalThis.fetch,
): Promise<ApiResult<DeleteAiKeyResult>> {
  return callApi<DeleteAiKeyResult>(
    fetchImpl,
    `/api/v1/ai-keys/${encodeURIComponent(providerId)}`,
    { method: 'DELETE' },
  );
}

export function updateRouting(
  payload: UpdateRoutingPayload,
  fetchImpl: typeof fetch = globalThis.fetch,
): Promise<ApiResult<{ routing: LlmRouting }>> {
  return callApi<{ routing: LlmRouting }>(fetchImpl, '/api/v1/ai-keys/routing', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

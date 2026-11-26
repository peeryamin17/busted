export type ProviderId =
  | 'gemini'
  | 'claude'
  | 'qwen'
  | 'kimi'
  | 'glm'
  | 'deepseek'
  | 'openrouter'
  | 'ollama';

export interface SavedAiKey {
  providerId: ProviderId;
  keyHint: string;
  baseUrl: string;
  verifiedAt: string;
}

export interface AiKeysListResponse {
  keys: SavedAiKey[];
  hasByok: boolean;
}

export type ApiResult<T> =
  | { ok: true; data: T }
  | { ok: false; status: number; error: string };

function providerLabel(providerId: ProviderId): string {
  return providerId.charAt(0).toUpperCase() + providerId.slice(1);
}

/**
 * One-line status for the AI keys line on the member site.
 * `null` means the check is still loading or failed, so the line
 * stays neutral and never claims keys exist (or don't) before it
 * knows. Otherwise it names the saved providers, if any.
 */
export function formatKeyStatus(keys: SavedAiKey[] | null): string {
  if (keys === null) return 'AI keys live in your extension';
  if (keys.length === 0) return 'No key saved yet';
  const labels = keys.map((key) => providerLabel(key.providerId)).join(', ');
  return `AI keys live in your extension — ${labels} ${keys.length === 1 ? 'key' : 'keys'} saved`;
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

export function listAiKeys(
  fetchImpl: typeof fetch = globalThis.fetch,
): Promise<ApiResult<AiKeysListResponse>> {
  return callApi<AiKeysListResponse>(fetchImpl, '/api/v1/ai-keys', {});
}

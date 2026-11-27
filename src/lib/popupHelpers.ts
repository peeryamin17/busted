/**
 * Pure popup helpers, kept free of top-level document or chrome calls
 * so they can be imported under Node (tests) as well as by the popup.
 */
export async function restoreTabScanIfMatching<T extends { targetUrl: string }>(
  tabId: number,
  currentTabUrl: string,
  renderScanResult: (scan: T) => void,
  storageKey = `scan:${tabId}`,
): Promise<void> {
  const stored = await chrome.storage.local.get([storageKey]);
  const prev = stored[storageKey] as T | undefined;
  if (!prev?.targetUrl) return;

  try {
    const prevOrigin = new URL(prev.targetUrl).origin;
    const currOrigin = new URL(currentTabUrl).origin;
    if (prevOrigin === currOrigin) {
      renderScanResult(prev);
      return;
    }
  } catch {
    // Invalid URL, discard cached entry
  }

  await chrome.storage.local.remove(storageKey);
}

export async function onProviderKeySaved(
  syncFn: () => Promise<void>,
  refreshAccountUi: () => Promise<void>,
  setStatus: (msg: string) => void,
): Promise<void> {
  await syncFn();
  await refreshAccountUi();
  setStatus('Provider key verified and synced.');
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

/** Localhost, loopback, or private-network host. The cloud backend cannot reach those. */
function isLocalOrPrivateHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (host === '::' || host === '::1' || host === '0.0.0.0') return true;
  const parts = host.split('.');
  if (parts.length === 4 && parts.every((p) => /^\d+$/.test(p) && Number(p) <= 255)) {
    const [a, b] = parts.map(Number);
    if (a === 127) return true;
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    return false;
  }
  // IPv6 unique-local (fc00::/7) and link-local (fe80::/10).
  return (
    host.startsWith('fc') ||
    host.startsWith('fd') ||
    host.startsWith('fe8') ||
    host.startsWith('fe9') ||
    host.startsWith('fea') ||
    host.startsWith('feb')
  );
}

/**
 * OmniRoute base URL check. The gateway runs on the user's own server,
 * so the URL must be a public https endpoint. Mirrors the server-side
 * rule, so a bad URL fails in the popup instead of after the round trip.
 */
export function resolveOmniRouteBaseUrl(
  customUrl: string | undefined,
): { baseUrl: string } | { error: string } {
  const raw = (customUrl ?? '').trim().replace(/\/+$/, '');
  if (!raw) return { error: 'Enter the public URL of your OmniRoute instance.' };
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { error: 'That OmniRoute URL does not look like a valid URL.' };
  }
  if (url.protocol !== 'https:' || url.username !== '' || url.password !== '') {
    return { error: 'OmniRoute URL must be a public https:// endpoint.' };
  }
  if (isLocalOrPrivateHost(url.hostname)) {
    return {
      error:
        'OmniRoute URL must be a public address. The cloud backend cannot reach localhost or a private network.',
    };
  }
  return { baseUrl: url.toString().replace(/\/+$/, '') };
}

/** Short display name for a provider label ("Qwen (DashScope)" -> "Qwen"). */
export function shortProviderLabel(label: string): string {
  const short = label.replace(/\s*\(.*\)$/, '').trim();
  return short.length > 0 ? short : label;
}

export interface RoutingBadgeInput {
  workerProvider: string;
  workerModel?: string | null;
  reasoningProvider: string;
  reasoningModel?: string | null;
}

/**
 * Status badge text for the active routing, e.g.
 * "Active: Qwen · worker qwen3.7-plus · reasoning qwen4-max".
 * A tier with no model picked reads "— pick a model" instead of
 * a blank gap. Models are the effective values from the routing
 * (GET or the POST save response), never placeholders or registry
 * defaults shown as if they were the current configuration.
 */
export function formatRoutingBadge(
  routing: RoutingBadgeInput,
  labelFor: (providerId: string) => string,
): string {
  const workerModel = routing.workerModel || '— pick a model';
  const reasoningModel = routing.reasoningModel || '— pick a model';
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

/** Local Ollama triage toggle. A plain preference, it never touches operator status. */
const LOCAL_OLLAMA_STORAGE_KEY = 'bugseek:localOllama';

export async function getLocalOllamaEnabled(): Promise<boolean> {
  try {
    const stored = await chrome.storage.local.get(LOCAL_OLLAMA_STORAGE_KEY);
    return stored[LOCAL_OLLAMA_STORAGE_KEY] === true;
  } catch {
    return false;
  }
}

export async function setLocalOllamaEnabled(enabled: boolean): Promise<void> {
  try {
    await chrome.storage.local.set({ [LOCAL_OLLAMA_STORAGE_KEY]: enabled });
  } catch {
    /* storage unavailable, the toggle stays off */
  }
}

/** Finite token count as a short display string. Never NaN, 0 minimum. */
export function formatTokenCount(value: unknown): string {
  let total = 0;
  if (typeof value === 'number' && Number.isFinite(value)) {
    total = value;
  } else if (value && typeof value === 'object') {
    const v = value as { total?: unknown; input?: unknown; output?: unknown };
    const t = Number(v.total);
    if (Number.isFinite(t) && t > 0) {
      total = t;
    } else {
      const i = Number(v.input);
      const o = Number(v.output);
      total = (Number.isFinite(i) ? i : 0) + (Number.isFinite(o) ? o : 0);
    }
  }
  total = Math.max(0, Math.floor(total));
  return total > 0 ? `${(total / 1000).toFixed(1)}k tokens` : '0k tokens';
}

export interface WorkerTelemetryInput {
  providerId?: string | null;
  model?: string | null;
  tokensUsed?: unknown;
}

/** One telemetry line for a run record. Empty when the record carries no telemetry. */
export function formatWorkerTelemetry(report: WorkerTelemetryInput): string {
  const parts: string[] = [];
  if (report.providerId) parts.push(report.providerId);
  if (report.model) parts.push(report.model);
  if (report.tokensUsed !== undefined && report.tokensUsed !== null) {
    parts.push(formatTokenCount(report.tokensUsed));
  }
  return parts.join(' · ');
}

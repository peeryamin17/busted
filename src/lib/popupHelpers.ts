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
  try {
    await syncFn();
    await refreshAccountUi();
    setStatus('Provider key verified and synced.');
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    await refreshAccountUi();
    setStatus(`Saved locally; backend sync failed (${detail}).`);
  }
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

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

export async function verifyGeminiApiKey(
  rawKey: string,
): Promise<{ valid: boolean; error?: string }> {
  const key = rawKey.trim();
  if (!key) return { valid: false, error: 'Enter a Gemini API key.' };

  const res = await fetch('https://generativelanguage.googleapis.com/v1beta/models', {
    method: 'GET',
    headers: {
      'x-goog-api-key': key,
    },
    signal: AbortSignal.timeout(10_000),
  });

  if (!res.ok) {
    return { valid: false, error: `Gemini rejected key (HTTP ${res.status}).` };
  }
  return { valid: true };
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

/**
 * BugSeek AI background service worker (Manifest V3).
 *
 * Responsibilities:
 *  - Capture main-frame response headers via webRequest (passive).
 *  - Orchestrate a scan when the popup requests one:
 *      content script DOM data -> cookie audit -> secret scan of
 *      inline + same-origin external JS -> header checks -> tech
 *      fingerprinting -> aggregated, severity-sorted findings.
 *
 * Phase 1 performs NO active testing: no payload injection, no fuzzing,
 * no authentication attempts. The only network reads are the page's own
 * public resources.
 */
import type { DomScanData, Finding, ScanMessage, ScanResult } from './lib/types';
import { SEVERITY_ORDER } from './lib/types';
import { scanSecrets, scanSecretKeyNames, type ScriptSource } from './scanners/secretScanner';
import { attachTrailsToFindings, buildTrails, sightingsFromFindings } from './scanners/keyTrail';
import { fetchSourceMaps, scanSourceMaps } from './scanners/sourceMapScanner';
import { scanDeepSurface } from './scanners/deepSurface';
import { auditCookies } from './scanners/cookieAuditor';
import { checkHeaders } from './scanners/headerChecker';
import { analyzeDom } from './scanners/domAnalyzer';
import { fingerprintTech } from './lib/fingerprint';
import { scanPageBundles } from './scanners/jsBundleScanner';
import { analyzeScriptsCrossFile } from './sast/crossFileTaint';
import { analyzeRecoveredSources } from './sast/sourceMapRecovery';
import { scanWasmModules } from './sast/wasmScan';
import { crossFileLinksToFindings, taintFlowsToFindings } from './sast/findings';
import { STORAGE_KEYS } from './lib/config';
import { runActiveScan } from './active/activeRunner';
import type { RateLimiter } from './lib/rateLimiter';
import { getMainFrameHeaders, recordMainFrameHeaders } from './active/traffic';
import { setBackendApiKey } from './lib/apiClient';

const MAX_EXTERNAL_SCRIPTS = 12;
const MAX_SCRIPT_BYTES = 1_500_000;
const FETCH_TIMEOUT_MS = 8000;

/** Latest observed main-frame response headers per tab (passive). */
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const headers: Record<string, string> = {};
    for (const h of details.responseHeaders ?? []) {
      if (h.name) headers[h.name.toLowerCase()] = h.value ?? '';
    }
    recordMainFrameHeaders(details.tabId, headers);
    return undefined;
  },
  { urls: ['<all_urls>'], types: ['main_frame'] },
  ['responseHeaders'],
);

chrome.tabs.onRemoved.addListener((tabId) => {
  // Tab-scoped traffic state is cleaned up inside traffic.ts.
});

chrome.runtime.onMessage.addListener(
  (msg: ScanMessage | { type: string; apiKey?: string }, _sender, sendResponse) => {
    if (msg.type === 'RUN_SCAN') {
      // Fire-and-forget: progress + result are pushed back as messages.
      void runScan((msg as ScanMessage & { tabId: number }).tabId);
    } else if (msg.type === 'RUN_ACTIVE_SCAN') {
      // Active testing: gated on the authorization record (checked in the runner).
      const m = msg as ScanMessage & { tabId: number; deepInspect?: boolean };
      void runActive(m.tabId, m.deepInspect ?? false);
    } else if (msg.type === 'BUGSEEK_SET_API_KEY') {
      // Website connect hand-off (see connectRelay.ts): the signed-in
      // user clicked "Connect the extension" on our own site. Store the
      // key as the backend key; format-checked before it lands.
      const keyMsg = msg as { type: string; apiKey?: string };
      const apiKey = typeof keyMsg.apiKey === 'string' ? keyMsg.apiKey.trim() : '';
      if (!apiKey.startsWith('bs_')) {
        sendResponse({ ok: false });
        return false;
      }
      void setBackendApiKey(apiKey).then(() => sendResponse({ ok: true }));
      return true;
    }
    return false;
  },
);

function sendProgress(step: string): void {
  chrome.runtime
    .sendMessage({ type: 'SCAN_PROGRESS', step } satisfies ScanMessage)
    .catch(() => {
      /* popup may be closed; ignore */
    });
}

async function runScan(tabId: number): Promise<void> {
  const started = Date.now();
  try {
    const tab = await chrome.tabs.get(tabId);
    const url = tab.url ?? '';
    if (!/^https?:\/\//i.test(url)) {
      throw new Error(
        'BugSeek can only scan regular web pages (http/https). Open a website and try again.',
      );
    }

    sendProgress('Collecting page structure…');
    const dom = await collectDom(tabId);

    sendProgress('Auditing cookies…');
    const cookieFindings = await auditCookies(url);

    sendProgress('Scanning JavaScript for exposed secrets…');
    const externalCode = await fetchSameOriginScripts(dom.externalScripts, url);
    const scriptSources: ScriptSource[] = [
      ...dom.inlineScripts.map((code, i) => ({
        label: `inline <script> #${i + 1} on ${shortHost(url)}`,
        code,
      })),
      ...externalCode,
    ];
    const secretFindings: Finding[] = scanSecrets(scriptSources);

    // Secret-shaped key NAMES in web storage / cookies (names only, values
    // are never read). Correlate every secret finding into a per-key trail.
    try {
      let cookieNames: string[] = [];
      try {
        cookieNames = (await chrome.cookies.getAll({ url })).map((c) => c.name);
      } catch {
        /* cookie read unavailable, storage names still checked */
      }
      secretFindings.push(...scanSecretKeyNames(dom.storage, cookieNames, url));
      // No traffic observations in a passive scan (tab capture runs only
      // during active scans), so trails here link discovery/storage
      // sightings; traffic steps join when a caller supplies observations.
      const trails = buildTrails(sightingsFromFindings(secretFindings), []);
      attachTrailsToFindings(secretFindings, trails);
    } catch {
      /* trail/key-name enrichment is best-effort; pattern findings stand */
    }

    sendProgress('Checking for exposed source maps…');
    const exposedMaps = await fetchSourceMaps(
      externalCode.map((s) => ({ url: s.label, code: s.code })),
      url,
    );
    const sourceMapFindings: Finding[] = scanSourceMaps(exposedMaps);

    sendProgress('Running white-box taint analysis…');
    let whiteBoxFindings: Finding[] = [];
    try {
      whiteBoxFindings = await runWhiteBoxAnalysis(scriptSources, exposedMaps, dom.wasmUrls ?? [], url);
    } catch {
      /* white-box analysis is best-effort; other findings still stand */
    }

    sendProgress('Checking security headers…');
    const headers = getMainFrameHeaders(tabId) ?? (await fetchHeadersFallback(url));
    const headerFindings = checkHeaders(headers, url.startsWith('https://'));

    sendProgress('Fingerprinting technology…');
    const tech = fingerprintTech(headers, dom);

    sendProgress('Analyzing page structure…');
    const domFindings = analyzeDom(dom);

    sendProgress('Scanning JS bundles for API endpoints & SPA routes…');
    let bundleFindings: Finding[] = [];
    try {
      const bundleScan = await scanPageBundles(new URL(url).origin, dom.externalScripts, dom.inlineScripts);
      if (bundleScan.endpoints.length > 0 || bundleScan.spaRoutes.length > 0) {
        bundleFindings.push({
          id: `jsbundle-${Date.now()}`,
          category: 'api',
          title: `Discovered ${bundleScan.endpoints.length} API endpoint${bundleScan.endpoints.length === 1 ? '' : 's'} and ${bundleScan.spaRoutes.length} SPA route${bundleScan.spaRoutes.length === 1 ? '' : 's'} in JS bundles`,
          description: `Client-side script inspection discovered ${bundleScan.endpoints.length} hidden API endpoints and ${bundleScan.spaRoutes.length} SPA routes (${bundleScan.scriptsScanned} scripts / ${Math.round(bundleScan.bytesScanned / 1024)} KB scanned).`,
          severity: 'info',
          confidence: 'high',
          location: url,
          evidence: `Sample endpoints: ${bundleScan.endpoints.slice(0, 5).map((e) => e.path).join(', ')}${bundleScan.spaRoutes.length > 0 ? ` | Routes: ${bundleScan.spaRoutes.slice(0, 5).join(', ')}` : ''}`,
          remediation: 'Verify endpoint access controls and ensure administrative or sensitive routes are protected by server-side authorization checks.',
        });
      }
    } catch {
      /* non-fatal fallback */
    }

    sendProgress('Mapping cookies, storage, payments & integrations…');
    const deepFindings = await scanDeepSurface(dom);

    const findings = [
      ...secretFindings,
      ...sourceMapFindings,
      ...whiteBoxFindings,
      ...cookieFindings,
      ...headerFindings,
      ...domFindings,
      ...bundleFindings,
      ...deepFindings,
    ].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

    const result: ScanResult = {
      targetUrl: url,
      scannedAt: new Date().toISOString(),
      durationMs: Date.now() - started,
      tech,
      findings,
    };

    await chrome.storage.local.set({ [`scan:${tabId}`]: result, lastResult: result });
    await chrome.runtime
      .sendMessage({ type: 'SCAN_DONE', result } satisfies ScanMessage)
      .catch(() => {
        /* popup may be closed; result is in storage */
      });
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    await chrome.runtime
      .sendMessage({ type: 'SCAN_ERROR', error } satisfies ScanMessage)
      .catch(() => {
        /* popup may be closed */
      });
  }
}

/**
 * White-box analysis over already-fetched code only (passive, no new
 * requests except same-origin .wasm fetches, size-capped):
 *  1. cross-file taint analysis over inline + external scripts
 *     (single-file flows, cross-bundle flows, shared-helper links);
 *  2. taint analysis on original sources recovered from exposed maps;
 *  3. WebAssembly module inventory + embedded-string scan.
 */
async function runWhiteBoxAnalysis(
  scriptSources: ScriptSource[],
  exposedMaps: import('./scanners/sourceMapScanner').ExposedSourceMap[],
  wasmUrls: string[],
  pageUrl: string,
): Promise<Finding[]> {
  const findings: Finding[] = [];

  const scripts = scriptSources.map((s) => ({ url: s.label, code: s.code }));
  const { flows, links } = analyzeScriptsCrossFile(scripts);
  findings.push(...taintFlowsToFindings(flows));
  findings.push(...crossFileLinksToFindings(links));

  const recovered = analyzeRecoveredSources(exposedMaps);
  findings.push(...taintFlowsToFindings(recovered.flows));
  if (recovered.sourcesAnalysed.length > 0) {
    findings.push({
      id: `whitebox-recovered-${Date.now()}`,
      category: 'whitebox',
      title: `Taint analysis ran on ${recovered.sourcesAnalysed.length} recovered original source file(s)`,
      description:
        `Exposed source maps embedded original sources; the taint engine analysed the recovered originals instead of the minified bundles. ` +
        `Line numbers in those findings refer to the original files, not the minified code (no mapping back is performed).` +
        (recovered.skipped.length > 0 ? ` Skipped: ${recovered.skipped.slice(0, 3).join('; ')}` : ''),
      severity: 'info',
      confidence: 'high',
      location: pageUrl,
      evidence: recovered.sourcesAnalysed.slice(0, 5).join(', '),
      remediation: 'Remove .map files from production deployments (see the source-map findings) so original sources are not recoverable.',
    });
  }

  const { findings: wasmFindings } = await scanWasmModules(wasmUrls, pageUrl);
  findings.push(...wasmFindings);

  return findings;
}

async function collectDom(tabId: number): Promise<DomScanData> {
  let res: { ok: boolean; data?: DomScanData; error?: string };
  try {
    res = (await chrome.tabs.sendMessage(tabId, {
      type: 'COLLECT_DOM',
    } satisfies ScanMessage)) as typeof res;
  } catch {
    throw new Error(
      'Could not reach the page. Reload the tab (the extension must be installed before the page loads) and scan again.',
    );
  }
  if (!res?.ok || !res.data) {
    throw new Error(res?.error ?? 'The page did not return scan data.');
  }
  return res.data;
}

/**
 * Fetch first-party (same-origin) external scripts for secret scanning.
 * Third-party CDN bundles are skipped in Phase 1 to keep scans fast and
 * focused on code the site owner controls.
 */
async function fetchSameOriginScripts(
  srcs: string[],
  pageUrl: string,
): Promise<ScriptSource[]> {
  const pageOrigin = new URL(pageUrl).origin;
  const targets = srcs
    .filter((s) => {
      try {
        return new URL(s).origin === pageOrigin;
      } catch {
        return false;
      }
    })
    .slice(0, MAX_EXTERNAL_SCRIPTS);

  const results: ScriptSource[] = [];
  await Promise.all(
    targets.map(async (src) => {
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
        const res = await fetch(src, { signal: ctrl.signal });
        clearTimeout(timer);
        if (!res.ok) return;
        const text = await res.text();
        if (!text || text.length > MAX_SCRIPT_BYTES) return;
        results.push({ label: src, code: text });
      } catch {
        /* skip unreachable scripts */
      }
    }),
  );
  return results;
}

/** Fallback: read headers with a HEAD request if the navigation predates the extension. */
async function fetchHeadersFallback(url: string): Promise<Record<string, string>> {
  const headers: Record<string, string> = {};
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    const res = await fetch(url, { method: 'HEAD', signal: ctrl.signal });
    clearTimeout(timer);
    res.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
  } catch {
    /* leave empty; checkHeaders() reports the gap */
  }
  return headers;
}

function shortHost(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

/**
 * Active testing scan (Phase 2). Authorization + scope are enforced inside
 * runActiveScan; every request is rate-limited via ActiveHttpClient.
 */
async function runActive(tabId: number, deepInspect: boolean): Promise<void> {
  try {
    const result = await runActiveScan(
      tabId,
      (step, limiter: RateLimiter) => {
      const stats = limiter.getStats();
      chrome.runtime
        .sendMessage({
          type: 'ACTIVE_PROGRESS',
          step,
          requestsMade: stats.requestsMade,
          rateLimitMs: stats.gapMs,
          nextRequestInMs: stats.nextRequestInMs,
        } satisfies ScanMessage)
        .catch(() => {
          /* popup may be closed; ignore */
        });
      },
      { deepInspect },
    );

    await chrome.storage.local.set({
      [`${STORAGE_KEYS.activeScanPrefix}${tabId}`]: result,
      [STORAGE_KEYS.lastActiveResult]: result,
    });
    await chrome.runtime
      .sendMessage({ type: 'ACTIVE_DONE', result } satisfies ScanMessage)
      .catch(() => {
        /* popup may be closed; result is in storage */
      });
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    await chrome.runtime
      .sendMessage({ type: 'ACTIVE_ERROR', error } satisfies ScanMessage)
      .catch(() => {
        /* popup may be closed */
      });
  }
}

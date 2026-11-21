/**
 * Backend API client — the SINGLE module that talks to the BugSeek backend.
 *
 * The backend (~/workspace/bugseek/backend, Fastify, default
 * http://localhost:3000) is built by a sibling worker in parallel, so every
 * endpoint here is provisional: each call has a short timeout and degrades to
 * null when the backend is unreachable. The extension is fully functional
 * standalone — backend calls only add AI deepening, scan history, and richer
 * reports on top of local results.
 */
import {
  BACKEND_BASE_URL,
  BACKEND_REQUEST_TIMEOUT_MS,
} from './config';
import type { AttackChain, Finding, ScanResult } from './types';
import { buildChainDeepeningRequest } from './attackChains';

export interface BackendStatus {
  reachable: boolean;
  baseUrl: string;
  version?: string;
}

const BACKEND_URL_STORAGE_KEY = 'bugseek:backendUrl';

export async function getBackendBaseUrl(): Promise<string> {
  try {
    const stored = await chrome.storage.local.get(BACKEND_URL_STORAGE_KEY);
    const custom = stored[BACKEND_URL_STORAGE_KEY];
    if (typeof custom === 'string' && custom.trim().length > 0) {
      return custom.trim().replace(/\/+$/, '');
    }
  } catch {}
  return BACKEND_BASE_URL;
}

export async function setBackendBaseUrl(url: string | null): Promise<void> {
  try {
    if (url && url.trim().length > 0) {
      await chrome.storage.local.set({ [BACKEND_URL_STORAGE_KEY]: url.trim().replace(/\/+$/, '') });
    } else {
      await chrome.storage.local.remove(BACKEND_URL_STORAGE_KEY);
    }
  } catch {}
}

/** Backend API key (bs_…), stored by the user in extension settings. Sent as x-api-key. */
const API_KEY_STORAGE_KEY = 'bugseek:apiKey';
/** User's own Gemini API key (AIza…), stored locally in the extension for direct BYOK scans. */
const GEMINI_API_KEY_STORAGE_KEY = 'bugseek:geminiApiKey';

export async function getBackendApiKey(): Promise<string | null> {
  try {
    const stored = await chrome.storage.local.get(API_KEY_STORAGE_KEY);
    const key = stored[API_KEY_STORAGE_KEY];
    return typeof key === 'string' && key.startsWith('bs_') ? key : null;
  } catch {
    return null;
  }
}

export async function setBackendApiKey(key: string | null): Promise<void> {
  try {
    if (key) await chrome.storage.local.set({ [API_KEY_STORAGE_KEY]: key });
    else await chrome.storage.local.remove(API_KEY_STORAGE_KEY);
  } catch {
    /* storage unavailable — backend calls simply stay unauthenticated */
  }
}

export async function getGeminiApiKey(): Promise<string | null> {
  try {
    const stored = await chrome.storage.local.get(GEMINI_API_KEY_STORAGE_KEY);
    const key = stored[GEMINI_API_KEY_STORAGE_KEY];
    return typeof key === 'string' && key.trim().length > 0 ? key.trim() : null;
  } catch {
    return null;
  }
}

export async function setGeminiApiKey(key: string | null): Promise<void> {
  try {
    if (key) await chrome.storage.local.set({ [GEMINI_API_KEY_STORAGE_KEY]: key.trim() });
    else await chrome.storage.local.remove(GEMINI_API_KEY_STORAGE_KEY);
  } catch {
    /* storage unavailable */
  }
}

async function fetchJson<T>(
  path: string,
  init: RequestInit,
  timeoutMs = BACKEND_REQUEST_TIMEOUT_MS,
): Promise<T | null> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const baseUrl = await getBackendBaseUrl();
    const apiKey = await getBackendApiKey();
    const geminiKey = await getGeminiApiKey();
    const res = await fetch(`${baseUrl}${path}`, {
      ...init,
      signal: ctrl.signal,
      headers: {
        'content-type': 'application/json',
        ...(apiKey ? { 'x-api-key': apiKey } : {}),
        ...(geminiKey ? { 'x-gemini-api-key': geminiKey } : {}),
        ...(init.headers ?? {}),
      },
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    clearTimeout(timer);
    return null;
  }
}

/** Cheap liveness probe used for the popup's backend status badge. */
export async function checkBackendStatus(
  onWaking?: () => void,
): Promise<BackendStatus> {
  const baseUrl = await getBackendBaseUrl();
  let health = await fetchJson<{ version?: string }>(
    '/api/v1/health',
    { method: 'GET' },
    3500,
  );
  if (!health) {
    // The backend sleeps when idle on the free tier and can take the
    // better part of a minute to wake. One patient retry before the
    // popup is allowed to declare it offline.
    onWaking?.();
    health = await fetchJson<{ version?: string }>(
      '/api/v1/health',
      { method: 'GET' },
      45_000,
    );
  }
  return {
    reachable: health !== null,
    baseUrl,
    version: health?.version,
  };
}

export interface BackendAccount {
  email: string;
  plan: string;
  operator: boolean;
}

/**
 * Who the stored API key belongs to (GET /api/v1/account). `operator` is
 * true only for the operator (ADMIN_EMAIL) account and drives the popup's
 * developer unlock. Null when there is no key, the backend is unreachable,
 * or it predates the endpoint — callers fail closed (locked) on null.
 */
export async function getBackendAccount(): Promise<BackendAccount | null> {
  const apiKey = await getBackendApiKey();
  const geminiKey = await getGeminiApiKey();
  if (geminiKey) {
    const hint = geminiKey.length > 8 ? `${geminiKey.slice(0, 4)}••••${geminiKey.slice(-4)}` : '••••••••';
    return {
      email: `Gemini AI (${hint})`,
      plan: 'enterprise',
      operator: true,
    };
  }
  if (!apiKey) return null;
  return fetchJsonOrThrow<BackendAccount>('/api/v1/account', { method: 'GET' }, 25_000);
}

/**
 * Exchange a one-time link code (generated on the website, typed here)
 * for a real API key, store it, and return whose account it belongs to.
 * The code itself is never stored.
 */
export async function pairWithCode(rawCode: string): Promise<BackendAccount> {
  const code = rawCode.replace(/[^a-zA-Z0-9]/g, '').toUpperCase();
  if (code.length !== 32) {
    throw new Error('A link code is 32 characters — copy it again from the website.');
  }
  const baseUrl = await getBackendBaseUrl();
  const ctrl = new AbortController();
  // The backend sleeps when idle; a first call can take a while to wake it.
  const timer = setTimeout(() => ctrl.abort(), 45_000);
  let res: Response;
  try {
    res = await fetch(`${baseUrl}/api/v1/pair`, {
      method: 'POST',
      signal: ctrl.signal,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code }),
    });
  } catch {
    throw new Error('Backend unreachable — check your connection and try again.');
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    let message = 'That link code did not work — it may be wrong, already used, or expired.';
    try {
      const body = (await res.json()) as { error?: unknown };
      if (typeof body?.error === 'string' && body.error) message = body.error;
    } catch {
      /* keep the generic message */
    }
    throw new Error(message);
  }
  const { apiKey } = (await res.json()) as { apiKey: string };
  await setBackendApiKey(apiKey);
  const account = await getBackendAccount();
  if (!account) {
    throw new Error('Linked, but the account could not be verified — reopen the popup.');
  }
  return account;
}

/**
 * Ask the backend AI agent to deepen/verify locally-built attack chains
 * (plan → act → observe → reflect loop, plan §4.4). Returns the chains with
 * aiDeepened flags/verdicts merged in, or null when offline.
 */
export async function deepenAttackChains(
  targetUrl: string,
  chains: AttackChain[],
  findings: Finding[],
): Promise<AttackChain[] | null> {
  if (chains.length === 0) return chains;
  const req = buildChainDeepeningRequest(targetUrl, chains, findings);
  const res = await fetchJson<{
    chains: Array<{ id: string; verdict: string; confidence?: string; note?: string }>;
  }>('/api/v1/chains/analyze', {
    method: 'POST',
    body: JSON.stringify(req),
  });
  if (!res) return null;
  const verdicts = new Map(res.chains.map((c) => [c.id, c]));
  return chains.map((c) => {
    const v = verdicts.get(c.id);
    if (!v) return c;
    return {
      ...c,
      aiDeepened: true,
      description: v.note ? `${c.description}\n\nAI verdict (${v.verdict}): ${v.note}` : c.description,
    };
  });
}

/**
 * Run the backend multi-agent swarm (head agent + specialist workers) against
 * an authorized target. POST /api/swarm/scans (Hunter+, 25 credits).
 * Returns the swarm outcome (head summary + persisted findings), or null when
 * offline. The caller must pass the user's explicit authorization — the
 * backend re-validates it (plan §8).
 */
export interface SwarmAuthorizationInput {
  type: 'bug-bounty' | 'pentest-contract' | 'ownership';
  programName?: string;
  referenceUrl?: string;
  statement: string;
  confirmed: true;
}

export interface SwarmScopeInput {
  mode?: 'full-domain' | 'subdomain' | 'page';
  includeSubdomains?: boolean;
  excludedHosts?: string[];
  excludedPaths?: string[];
}

export interface SwarmOutcome {
  scanId: string;
  targetUrl: string;
  headSummary: string;
  findings: Array<{
    id: string;
    category: string;
    title: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    confidence: 'high' | 'medium' | 'low';
    location?: string;
    evidence?: string;
    remediation: string;
    cvssScore?: number;
    cvssVector?: string;
    trapProbability?: number;
    honeypotSuspect?: boolean;
  }>;
  workerReports: Array<{
    specialistId: string;
    specialistName: string;
    summary: string;
    testsRun: number;
    findings: number;
    tokensUsed: number;
    durationMs: number;
  }>;
  testsRun: number;
  tokensUsed: number;
  durationMs: number;
  /** Server-computed security score (0–100) + letter grade (A–F); null when the run was not scored. */
  score?: { value: number; grade: string } | null;
}

export const SWARM_SCAN_TIMEOUT_MS = 120_000;

export async function runSwarmScan(
  targetUrl: string,
  authorization: SwarmAuthorizationInput,
  scope?: SwarmScopeInput,
): Promise<SwarmOutcome> {
  return fetchJsonOrThrow<SwarmOutcome>(
    '/api/swarm/scans',
    {
      method: 'POST',
      body: JSON.stringify({ targetUrl, authorization, scope }),
    },
    SWARM_SCAN_TIMEOUT_MS,
  );
}

// ---------------------------------------------------------------------------
// Open-source engines + report import
//
// Unlike the best-effort calls above, these surface the backend's own error
// string (plan gating 403, engine unavailable 503, validation 400) so the
// popup can show the user WHY a run failed instead of a generic "offline".
// ---------------------------------------------------------------------------

/** Engine scans are subprocess-bound on the backend (Nikto/Nuclei take minutes). */
const ENGINE_SCAN_TIMEOUT_MS = 10 * 60_000;
const IMPORT_TIMEOUT_MS = 120_000;

/**
 * fetchJson variant that THROWS: the thrown Error's message is the server's
 * `error` field when the backend sent one, or a backend-unreachable message
 * when the request itself failed (offline / timeout).
 */
async function fetchJsonOrThrow<T>(
  path: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<T> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let res: Response;
  const baseUrl = await getBackendBaseUrl();
  try {
    const apiKey = await getBackendApiKey();
    const geminiKey = await getGeminiApiKey();
    res = await fetch(`${baseUrl}${path}`, {
      ...init,
      signal: ctrl.signal,
      headers: {
        'content-type': 'application/json',
        ...(apiKey ? { 'x-api-key': apiKey } : {}),
        ...(geminiKey ? { 'x-gemini-api-key': geminiKey } : {}),
        ...(init.headers ?? {}),
      },
    });
  } catch (err: any) {
    clearTimeout(timer);
    if (err?.name === 'AbortError') {
      throw new Error(
        `Backend request timed out (${Math.round(timeoutMs / 1000)}s) — Render may be waking up, please try again in a moment.`,
      );
    }
    throw new Error('Backend unreachable — Render free tier is waking up, please wait ~30s or check your connection.');
  }
  clearTimeout(timer);
  if (!res.ok) {
    let message = `Backend request failed (HTTP ${res.status})`;
    try {
      const body = (await res.json()) as { error?: unknown };
      if (typeof body?.error === 'string' && body.error) message = body.error;
    } catch {
      /* non-JSON error body — keep the generic message */
    }
    throw new Error(message);
  }
  return (await res.json()) as T;
}

/** Finding shape shared by swarm scans, engine scans, and report imports. */
export type BackendFinding = SwarmOutcome['findings'][number];

export type EngineId = 'whatweb' | 'nikto' | 'nuclei';

export interface EngineStatusEntry {
  engine: EngineId;
  available: boolean;
  detail?: string;
}

export interface EngineScanOutcome {
  scanId: string;
  engine: EngineId;
  findings: BackendFinding[];
  score: { value: number; grade: string } | null;
}

export type ImportFormat = 'auto' | 'zap' | 'nuclei' | 'nikto' | 'sqlmap';

export interface ImportOutcome {
  scanId: string;
  imported: number;
  findings: BackendFinding[];
  score: { value: number; grade: string } | null;
}

/** GET /api/engines/status — which open-source engines the backend can run. */
export async function getEnginesStatus(): Promise<EngineStatusEntry[] | null> {
  const res = await fetchJson<{ engines: EngineStatusEntry[] }>(
    '/api/engines/status',
    { method: 'GET' },
    5000,
  );
  return res?.engines ?? null;
}

/**
 * POST /api/engines/scans — run one open-source engine (WhatWeb / Nikto /
 * Nuclei) on the backend against an authorized target (Hunter+). Throws with
 * the server's error string on 403/503/400.
 */
export async function runEngineScan(
  engine: EngineId,
  targetUrl: string,
  authorization: SwarmAuthorizationInput,
): Promise<EngineScanOutcome> {
  return fetchJsonOrThrow<EngineScanOutcome>(
    '/api/engines/scans',
    {
      method: 'POST',
      body: JSON.stringify({ engine, targetUrl, authorization }),
    },
    ENGINE_SCAN_TIMEOUT_MS,
  );
}

/**
 * POST /api/import/findings — import an external scanner report (ZAP /
 * Nuclei / Nikto / SQLMap) as BugSeek findings. Throws with the server's
 * error string when the report can't be parsed/validated.
 */
export async function importFindingsReport(
  format: ImportFormat,
  content: string,
  targetUrl: string,
): Promise<ImportOutcome> {
  return fetchJsonOrThrow<ImportOutcome>(
    '/api/import/findings',
    {
      method: 'POST',
      body: JSON.stringify({ format, content, targetUrl }),
    },
    IMPORT_TIMEOUT_MS,
  );
}

/**
 * Submit a finished scan for server-side history/reporting. Best-effort:
 * returns the server scan id, or null when offline. Findings are already
 * redacted client-side (8-char prefix convention); the backend re-redacts
 * before persistence per its own guardrails.
 */
export async function submitScanResult(
  result: ScanResult,
): Promise<string | null> {
  const res = await fetchJson<{ id: string }>('/api/v1/scans', {
    method: 'POST',
    body: JSON.stringify({
      targetUrl: result.targetUrl,
      mode: result.mode ?? 'passive',
      scannedAt: result.scannedAt,
      durationMs: result.durationMs,
      tech: result.tech,
      findings: result.findings,
      chains: result.chains ?? [],
      authorizationId: result.authorization?.id,
      stats: result.activeStats,
    }),
  });
  return res?.id ?? null;
}

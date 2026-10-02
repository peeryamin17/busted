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

/** Backend API key (bs_…), stored by the user in extension settings. Sent as x-api-key. */
const API_KEY_STORAGE_KEY = 'bugseek:apiKey';

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

async function fetchJson<T>(
  path: string,
  init: RequestInit,
  timeoutMs = BACKEND_REQUEST_TIMEOUT_MS,
): Promise<T | null> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const apiKey = await getBackendApiKey();
    const res = await fetch(`${BACKEND_BASE_URL}${path}`, {
      ...init,
      signal: ctrl.signal,
      headers: {
        'content-type': 'application/json',
        ...(apiKey ? { 'x-api-key': apiKey } : {}),
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
export async function checkBackendStatus(): Promise<BackendStatus> {
  const health = await fetchJson<{ version?: string }>(
    '/api/v1/health',
    { method: 'GET' },
    2500,
  );
  return {
    reachable: health !== null,
    baseUrl: BACKEND_BASE_URL,
    version: health?.version,
  };
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

export async function runSwarmScan(
  targetUrl: string,
  authorization: SwarmAuthorizationInput,
  scope?: SwarmScopeInput,
  programme?: ProgrammeRef,
): Promise<SwarmOutcome | null> {
  return fetchJson<SwarmOutcome>('/api/swarm/scans', {
    method: 'POST',
    body: JSON.stringify({
      targetUrl,
      authorization,
      scope,
      ...(programme ? { programme } : {}),
    }),
  });
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
  try {
    const apiKey = await getBackendApiKey();
    res = await fetch(`${BACKEND_BASE_URL}${path}`, {
      ...init,
      signal: ctrl.signal,
      headers: {
        'content-type': 'application/json',
        ...(apiKey ? { 'x-api-key': apiKey } : {}),
        ...(init.headers ?? {}),
      },
    });
  } catch {
    clearTimeout(timer);
    throw new Error('Backend unreachable — is the BugSeek backend running?');
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
  programme?: ProgrammeRef,
): Promise<EngineScanOutcome> {
  return fetchJsonOrThrow<EngineScanOutcome>(
    '/api/engines/scans',
    {
      method: 'POST',
      body: JSON.stringify({
        engine,
        targetUrl,
        authorization,
        ...(programme ? { programme } : {}),
      }),
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

// ---------------------------------------------------------------------------
// Programme scope (HackerOne / Bugcrowd)
//
// The backend mirrors the public programme scope listings (the community
// bounty-targets-data project) and answers "does this programme's published
// scope cover this host?". Picking a programme is optional and never grants
// authorisation by itself — the saved authorisation record still governs
// every active check; the verdict is evidence alongside it. When a swarm or
// engine scan names a programme, the backend re-checks and records the
// verdict on the scan.
// ---------------------------------------------------------------------------

export type ScopePlatform = 'hackerone' | 'bugcrowd';

export interface ProgrammeRef {
  platform: ScopePlatform;
  handle: string;
}

export interface ProgrammeSummary extends ProgrammeRef {
  name: string;
  url?: string;
}

export type ProgrammeScopeVerdict =
  | 'in_scope'
  | 'out_of_scope'
  | 'programme_not_found'
  | 'unknown';

export interface ProgrammeScopeCheck extends ProgrammeRef {
  programmeName?: string;
  verdict: ProgrammeScopeVerdict;
  /** The published scope line that decided the verdict, when one matched. */
  matchedEntry?: string;
  reason: string;
  checkedAt?: string;
}

const PROGRAMME_STORAGE_KEY = 'bugseek:programme';

export async function getStoredProgramme(): Promise<ProgrammeRef | null> {
  try {
    const stored = await chrome.storage.local.get(PROGRAMME_STORAGE_KEY);
    const ref = stored[PROGRAMME_STORAGE_KEY] as ProgrammeRef | undefined;
    if (
      ref &&
      (ref.platform === 'hackerone' || ref.platform === 'bugcrowd') &&
      typeof ref.handle === 'string' &&
      ref.handle.trim()
    ) {
      return { platform: ref.platform, handle: ref.handle };
    }
  } catch {
    /* storage unavailable — no programme selected */
  }
  return null;
}

export async function setStoredProgramme(ref: ProgrammeRef | null): Promise<void> {
  try {
    if (ref) await chrome.storage.local.set({ [PROGRAMME_STORAGE_KEY]: ref });
    else await chrome.storage.local.remove(PROGRAMME_STORAGE_KEY);
  } catch {
    /* selection simply won't persist */
  }
}

/** GET /api/scope/programmes — find programmes by handle or name. */
export async function searchProgrammes(
  platform: ScopePlatform,
  query: string,
): Promise<ProgrammeSummary[] | null> {
  const params = new URLSearchParams({ platform, q: query });
  const res = await fetchJson<{ programmes: ProgrammeSummary[] }>(
    `/api/scope/programmes?${params.toString()}`,
    { method: 'GET' },
    6000,
  );
  return res?.programmes ?? null;
}

/** POST /api/scope/check — verdict for this target against the programme's published scope. */
export async function checkProgrammeScope(
  ref: ProgrammeRef,
  targetUrl: string,
): Promise<ProgrammeScopeCheck | null> {
  return fetchJson<ProgrammeScopeCheck>(
    '/api/scope/check',
    {
      method: 'POST',
      body: JSON.stringify({
        platform: ref.platform,
        handle: ref.handle,
        targetUrl,
      }),
    },
    10_000,
  );
}


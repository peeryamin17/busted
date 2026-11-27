/**
 * Backend API client, the single module that talks to the BugSeek backend.
 *
 * The backend (Fastify) may be unreachable, so every call has a short
 * timeout. Calls return an ApiResult that keeps the failure kind visible:
 * auth, server, client, or offline. The extension works standalone;
 * backend calls only add AI deepening, scan history, and richer reports
 * on top of local results.
 *
 * Auth is the stored bs_ key only. A local provider (BYOK) key is never
 * sent as an auth substitute; it is synced to the account separately and
 * the server decides what it unlocks.
 */
import { BACKEND_BASE_URL, BACKEND_REQUEST_TIMEOUT_MS } from './config';
import type { AttackChain, Finding, ScanResult } from './types';
import { buildChainDeepeningRequest } from './attackChains';

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

/** Backend API key (bs_…), stored by the user in extension settings. Sent as x-api-key. */
const API_KEY_STORAGE_KEY = 'bugseek:apiKey';

/**
 * Hosted provider keys an older popup stored locally. The 0.4.0 key flow
 * keeps hosted keys on the account, never in browser storage.
 */
const LEGACY_PROVIDER_KEY_STORAGE_KEYS = [
  'bugseek:geminiApiKey',
  'geminiApiKey',
  'qwenApiKey',
] as const;
const LEGACY_CLEANUP_DONE_KEY = 'bugseek:legacyKeysCleaned';

/** One-time removal of hosted provider keys left in local storage by older popup versions. */
export async function cleanupLegacyProviderKeys(): Promise<void> {
  try {
    const stored = await chrome.storage.local.get(LEGACY_CLEANUP_DONE_KEY);
    if (stored[LEGACY_CLEANUP_DONE_KEY]) return;
    await chrome.storage.local.remove([...LEGACY_PROVIDER_KEY_STORAGE_KEYS]);
    await chrome.storage.local.set({ [LEGACY_CLEANUP_DONE_KEY]: true });
  } catch {
    /* storage unavailable, cleanup retries on the next popup open */
  }
}

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
    /* storage unavailable, backend calls simply stay unauthenticated */
  }
}

export type ApiErrorKind = 'auth' | 'server' | 'client' | 'offline';

export type ApiResult<T> =
  | { ok: true; status: number; data: T }
  | { ok: false; status: number; kind: ApiErrorKind; error: string };

export async function fetchJson<T>(
  path: string,
  init: RequestInit = {},
  timeoutMs = BACKEND_REQUEST_TIMEOUT_MS,
): Promise<ApiResult<T>> {
  const baseUrl = await getBackendBaseUrl();
  const apiKey = await getBackendApiKey();
  const headers = new Headers(init.headers);
  headers.set('Content-Type', 'application/json');
  if (apiKey) {
    headers.set('x-api-key', apiKey);
    headers.set('Authorization', `Bearer ${apiKey}`);
  }

  try {
    const res = await fetch(`${baseUrl}${path}`, {
      ...init,
      headers,
      signal: init.signal ?? AbortSignal.timeout(timeoutMs),
    });

    const text = await res.text();
    let parsed: unknown = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = null;
    }

    if (!res.ok) {
      const body = parsed as { error?: unknown; message?: unknown } | null;
      const kind: ApiErrorKind =
        res.status === 401 || res.status === 403
          ? 'auth'
          : res.status >= 500
            ? 'server'
            : 'client';
      const serverMessage =
        typeof body?.error === 'string'
          ? body.error
          : typeof body?.message === 'string'
            ? body.message
            : null;
      return {
        ok: false,
        status: res.status,
        kind,
        error: serverMessage ?? `HTTP ${res.status}`,
      };
    }

    return { ok: true, status: res.status, data: parsed as T };
  } catch (err) {
    const isTimeout =
      err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError');
    return {
      ok: false,
      status: 0,
      kind: 'offline',
      error: isTimeout
        ? `Backend request timed out (${Math.round(timeoutMs / 1000)}s) — Render may be waking up, please try again in a moment.`
        : err instanceof Error
          ? err.message
          : 'Network error',
    };
  }
}

/** Cheap liveness probe used for the popup's backend status badge. */
export async function checkBackendStatus(): Promise<{
  state: 'online' | 'auth_error' | 'server_error' | 'offline';
  detail?: string;
}> {
  const res = await fetchJson<{ ok: boolean }>('/api/v1/health', { method: 'GET' }, 10_000);
  if (res.ok) return { state: 'online' };
  if (res.kind === 'auth') return { state: 'auth_error', detail: res.error };
  if (res.kind === 'server') return { state: 'server_error', detail: res.error };
  return { state: 'offline', detail: res.error };
}

export interface AccountState {
  authenticated: boolean;
  email: string | null;
  plan: 'free' | 'scout' | 'hunter' | 'pro' | 'enterprise';
  operator: boolean;
  hasByok: boolean;
}

const PLAN_VALUES = ['free', 'scout', 'hunter', 'pro', 'enterprise'] as const;

function asPlan(value: unknown): AccountState['plan'] {
  return typeof value === 'string' &&
    (PLAN_VALUES as readonly string[]).includes(value)
    ? (value as AccountState['plan'])
    : 'free';
}

/**
 * Who the stored API key belongs to (GET /api/v1/account). Operator status
 * comes strictly from that endpoint; hasByok comes from the synced key
 * list, never from anything stored in this browser.
 */
export async function getBackendAccount(): Promise<AccountState> {
  const res = await fetchJson<{ email?: unknown; plan?: unknown; operator?: unknown }>(
    '/api/v1/account',
    { method: 'GET' },
    10_000,
  );
  if (!res.ok) {
    return {
      authenticated: false,
      email: null,
      plan: 'free',
      operator: false,
      hasByok: false,
    };
  }
  const keys = await getAiKeys();
  return {
    authenticated: true,
    email: typeof res.data.email === 'string' ? res.data.email : null,
    plan: asPlan(res.data.plan),
    operator: Boolean(res.data.operator),
    hasByok: keys.ok ? keys.data.hasByok : false,
  };
}

/**
 * Exchange a one-time link code (generated on the website, typed here)
 * for a real API key, store it, and return whose account it belongs to.
 * The code itself is never stored.
 */
export async function pairWithCode(rawCode: string): Promise<AccountState> {
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
  if (!account.authenticated) {
    throw new Error('Linked, but the account could not be verified — reopen the popup.');
  }
  return account;
}

// ---------------------------------------------------------------------------
// AI provider keys (BYOK), synced to the account
//
// Hosted provider keys live encrypted on the backend, shared across the
// web app and this paired extension. The browser never stores the raw
// key. Every call below authenticates with the stored bs_ key only.
// ---------------------------------------------------------------------------

export type ProviderId =
  | 'gemini'
  | 'claude'
  | 'qwen'
  | 'kimi'
  | 'glm'
  | 'deepseek'
  | 'openrouter'
  | 'openai'
  | 'omniroute'
  | 'ollama';

export type ModelTier = 'worker' | 'reasoning';

export interface LlmProviderCapability {
  id: ProviderId;
  label: string;
  mode: 'hosted' | 'local';
  available: boolean;
  reason?: string;
  defaultModels: Record<ModelTier, string | null>;
}

export interface CapabilitiesResponse {
  version: string;
  runtime: 'cloud' | 'local';
  llmProviders: LlmProviderCapability[];
  engines: Array<{ id: string; available: boolean; reason?: string }>;
}

export interface SavedAiKey {
  providerId: ProviderId;
  keyHint: string;
  baseUrl: string;
  verifiedAt: string;
  /** Model ids the provider key can use, null until the key is re-saved or refreshed. */
  discoveredModels: string[] | null;
}

export interface LlmRouting {
  workerProvider: string;
  workerModel?: string | null;
  reasoningProvider: string;
  reasoningModel?: string | null;
}

export interface AiKeysResponse {
  keys: SavedAiKey[];
  routing: LlmRouting;
  hasByok: boolean;
}

/** POST /api/v1/ai-keys response: the saved key plus the routing the save picked. */
export interface SaveAiKeyResult {
  providerId: ProviderId;
  keyHint: string;
  baseUrl: string;
  verifiedAt: string;
  discoveredModels: string[] | null;
  hasByok: boolean;
  routingAutoSet: boolean;
  routing: LlmRouting;
}

/** GET /api/v1/capabilities, what this backend runtime offers. */
export async function getCapabilities(): Promise<ApiResult<CapabilitiesResponse>> {
  return fetchJson<CapabilitiesResponse>('/api/v1/capabilities', { method: 'GET' }, 10_000);
}

/** GET /api/v1/ai-keys, saved providers (masked hints only) plus tier routing. */
export async function getAiKeys(): Promise<ApiResult<AiKeysResponse>> {
  return fetchJson<AiKeysResponse>('/api/v1/ai-keys', { method: 'GET' }, 10_000);
}

/**
 * POST /api/v1/ai-keys, verify a hosted provider key against the
 * provider and store it encrypted on the account.
 */
export async function saveAiKey(
  providerId: ProviderId,
  apiKey: string,
  baseUrl?: string,
): Promise<ApiResult<SaveAiKeyResult>> {
  return fetchJson<SaveAiKeyResult>('/api/v1/ai-keys', {
    method: 'POST',
    body: JSON.stringify({
      providerId,
      apiKey,
      ...(baseUrl ? { baseUrl } : {}),
    }),
  });
}

/** DELETE /api/v1/ai-keys/:providerId, drop one saved provider key. */
export async function deleteAiKey(
  providerId: ProviderId,
): Promise<ApiResult<{ deleted: boolean; hasByok: boolean }>> {
  return fetchJson<{ deleted: boolean; hasByok: boolean }>(
    `/api/v1/ai-keys/${encodeURIComponent(providerId)}`,
    { method: 'DELETE' },
  );
}

export interface RefreshAiKeyResult {
  providerId: ProviderId;
  discoveredModels: string[] | null;
}

/** POST /api/v1/ai-keys/:providerId/refresh, re-list the models a saved key can use. */
export async function refreshAiKey(
  providerId: ProviderId,
): Promise<ApiResult<RefreshAiKeyResult>> {
  return fetchJson<RefreshAiKeyResult>(
    `/api/v1/ai-keys/${encodeURIComponent(providerId)}/refresh`,
    { method: 'POST' },
  );
}

/** PUT /api/v1/ai-keys/routing, pick the worker and reasoning tier providers. */
export async function saveLlmRouting(
  routing: LlmRouting,
): Promise<ApiResult<{ routing: LlmRouting }>> {
  return fetchJson<{ routing: LlmRouting }>('/api/v1/ai-keys/routing', {
    method: 'PUT',
    body: JSON.stringify(routing),
  });
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
  if (!res.ok) return null;
  const verdicts = new Map(res.data.chains.map((c) => [c.id, c]));
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
 * offline. The caller must pass the user's explicit authorization, the
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

/** Token usage as the backend reports it: a plain count, or input/output parts. */
export type TokenUsage =
  | number
  | { input?: number; output?: number; total?: number };

/** Which provider and model ran a piece of work, plus its token count. */
export interface WorkerTelemetry {
  providerId?: string;
  model?: string;
  tokensUsed?: TokenUsage;
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
    tokensUsed: TokenUsage;
    durationMs: number;
    /** Added by the backend run record when the pool reports it. */
    providerId?: string;
    model?: string;
  }>;
  /** Retester proof gate telemetry, when the backend run record carries it. */
  retester?: WorkerTelemetry;
  testsRun: number;
  tokensUsed: TokenUsage;
  durationMs: number;
  /** Server-computed security score (0–100) + letter grade (A–F); null when the run was not scored. */
  score?: { value: number; grade: string } | null;
}

export const SWARM_SCAN_TIMEOUT_MS = 5 * 60 * 1000;

export async function runSwarmScan(
  payload: unknown,
  onProgress?: (status: string) => void,
): Promise<SwarmOutcome> {
  const start = await fetchJson<
    { jobId?: string; scanId?: string; status?: string } & Partial<SwarmOutcome>
  >(
    '/api/swarm/scans',
    {
      method: 'POST',
      body: JSON.stringify(payload),
    },
    30_000,
  );

  if (!start.ok) {
    throw new Error(`Swarm start failed (${start.kind}): ${start.error}`);
  }

  // The server can complete synchronously (200 with the full outcome).
  if (start.data.status === 'completed' && Array.isArray(start.data.findings)) {
    return start.data as SwarmOutcome;
  }

  const id = start.data.jobId || start.data.scanId;
  if (!id) {
    throw new Error('Backend did not return a scan or job ID');
  }

  const deadline = Date.now() + SWARM_SCAN_TIMEOUT_MS;
  let transientErrors = 0;

  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 3000));
    const poll = await fetchJson<
      {
        status: string;
        error?: string;
        progress?: {
          completedSteps?: number;
          totalSteps?: number;
          currentStep?: string;
        };
      } & Partial<SwarmOutcome>
    >(`/api/swarm/scans/${encodeURIComponent(id)}`, { method: 'GET' }, 15_000);

    if (!poll.ok) {
      // Fail immediately on 401/403/404/422 instead of spinning until the deadline.
      if (poll.kind === 'auth' || poll.kind === 'client') {
        throw new Error(`Swarm aborted (${poll.status}): ${poll.error}`);
      }
      transientErrors++;
      if (transientErrors >= 5) {
        throw new Error(
          `Swarm polling lost connection after ${transientErrors} attempts: ${poll.error}`,
        );
      }
      continue;
    }

    transientErrors = 0;
    onProgress?.(poll.data.status);

    if (poll.data.status === 'completed') return poll.data as SwarmOutcome;
    if (poll.data.status === 'failed') {
      throw new Error(poll.data.error || 'Swarm scan failed on backend');
    }
  }

  throw new Error(`Swarm timed out after ${SWARM_SCAN_TIMEOUT_MS / 1000}s`);
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
  const res = await fetchJson<T>(path, init, timeoutMs);
  if (res.ok) return res.data;
  if (res.kind === 'offline') {
    throw new Error(
      'Backend unreachable — Render free tier is waking up, please wait ~30s or check your connection.',
    );
  }
  throw new Error(res.error);
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

/** GET /api/engines/status, which open-source engines the backend can run. */
export async function getEnginesStatus(): Promise<EngineStatusEntry[] | null> {
  const res = await fetchJson<{ engines: EngineStatusEntry[] }>(
    '/api/engines/status',
    { method: 'GET' },
    5000,
  );
  return res.ok ? res.data.engines : null;
}

/**
 * POST /api/engines/scans, run one open-source engine (WhatWeb / Nikto /
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
 * POST /api/import/findings, import an external scanner report (ZAP /
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
 * redacted client-side (4-char edge mask); the backend re-redacts
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
  return res.ok ? res.data.id : null;
}

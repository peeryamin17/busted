import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { execFile } from 'node:child_process';
import type { FastifyInstance } from 'fastify';
import type { Database } from '../db/db.js';
import type { JobQueue } from '../queue/queue.js';
import type { LLMProvider } from '../llm/provider.js';
import type { GraphStore } from '../graph/store.js';
import type { CoverageStore } from '../coverage/ledger.js';
import type { EvidenceStore } from '../evidence/snapshots.js';
import type { ApprovalStore } from '../approvals/store.js';
import type { ApprovalRuleStore } from '../approvals/rules.js';
import type { PinStore } from '../guardrails/pins.js';
import { PROVIDER_REGISTRY, type ModelTier, type ProviderId } from '../llm/registry.js';

export interface RouteDeps {
  db: Database;
  queue: JobQueue;
  provider: LLMProvider;
  /** stores, present when the app built them (server.ts). */
  graph?: GraphStore;
  coverage?: CoverageStore;
  evidence?: EvidenceStore;
  /** stores, approval queue, rules, target pins. */
  approvals?: ApprovalStore;
  approvalRules?: ApprovalRuleStore;
  pins?: PinStore;
  /**
   * hook, called best-effort when a swarm run completes
   * (server.ts wires it to the notification fan-out). A throwing or
   * slow hook must never break the scan response, so the caller wraps
   * it in a no-throw guard.
   */
  onSwarmCompleted?: (input: {
    userId: string;
    scanId: string;
    taskId: string | null;
    targetUrl: string;
    findings: Array<{ severity: string; title: string; category: string }>;
  }) => Promise<void>;
}

/**
 * Backend version, read from backend/package.json (walked up from this
 * file, so it resolves in both the src and compiled layouts) instead of
 * a hardcoded string, so the health endpoints cannot drift from the
 * release again. Falls back to 0.0.0 when the file cannot be found.
 */
export const APP_VERSION: string = (() => {
  let dir = __dirname;
  for (let i = 0; i < 6; i++) {
    try {
      const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as {
        name?: string;
        version?: string;
      };
      if (pkg.name === 'bugseek-ai-backend' && typeof pkg.version === 'string') {
        return pkg.version;
      }
    } catch {
      // Not this directory, keep walking up.
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return '0.0.0';
})();

export type BackendRuntime = 'cloud' | 'local';

/** Cloud when hosted (Render or production), unless explicitly run local. */
export function getBackendRuntime(): BackendRuntime {
  if (process.env['BUGSEEK_LOCAL_RUNTIME'] === '1') return 'local';
  if (process.env['RENDER'] === 'true' || process.env['NODE_ENV'] === 'production') return 'cloud';
  return 'local';
}

export type EngineId = 'httpx' | 'katana' | 'nuclei' | 'whatweb' | 'nikto';

export interface EngineStatus {
  id: EngineId;
  available: boolean;
  reason?: string;
}

export interface CapabilitiesResponse {
  version: string;
  runtime: BackendRuntime;
  llmProviders: Array<{
    id: ProviderId;
    label: string;
    mode: 'hosted' | 'local';
    available: boolean;
    reason?: string;
    defaultModels: Record<ModelTier, string>;
  }>;
  engines: EngineStatus[];
}

const ENGINE_IDS: EngineId[] = ['httpx', 'katana', 'nuclei', 'whatweb', 'nikto'];

function probeEngine(id: EngineId): Promise<EngineStatus> {
  return new Promise((resolve) => {
    execFile('which', [id], { timeout: 5000 }, (err) => {
      if (err) resolve({ id, available: false, reason: 'not installed' });
      else resolve({ id, available: true });
    });
  });
}

/**
 * Local engine binaries are probed once at boot, never per request.
 * The promise starts here at import time; routes await the same promise.
 */
const engineProbe: Promise<EngineStatus[]> = Promise.all(ENGINE_IDS.map(probeEngine));

export function getEngineStatus(): Promise<EngineStatus[]> {
  return engineProbe;
}

export function buildCapabilitiesResponse(engines: EngineStatus[]): CapabilitiesResponse {
  const runtime = getBackendRuntime();
  return {
    version: APP_VERSION,
    runtime,
    llmProviders: (Object.values(PROVIDER_REGISTRY) as Array<(typeof PROVIDER_REGISTRY)[ProviderId]>).map(
      (spec) => ({
        id: spec.id,
        label: spec.label,
        mode: spec.mode,
        available: spec.mode === 'local' ? runtime === 'local' : true,
        ...(spec.id === 'ollama' && runtime === 'cloud'
          ? { reason: 'Requires local backend' }
          : {}),
        defaultModels: spec.defaultModels,
      }),
    ),
    engines,
  };
}

export async function healthRoutes(app: FastifyInstance, deps: RouteDeps): Promise<void> {
  app.get('/health', async () => ({
    status: 'ok',
    version: APP_VERSION,
    db: deps.db.kind,
    queue: deps.queue.kind,
    llm: deps.provider.name,
    time: new Date().toISOString(),
  }));

  app.get('/api/v1/capabilities', async () => {
    const engines = await getEngineStatus();
    return buildCapabilitiesResponse(engines);
  });
}

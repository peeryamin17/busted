import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
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

export async function healthRoutes(app: FastifyInstance, deps: RouteDeps): Promise<void> {
  app.get('/health', async () => ({
    status: 'ok',
    version: APP_VERSION,
    db: deps.db.kind,
    queue: deps.queue.kind,
    llm: deps.provider.name,
    time: new Date().toISOString(),
  }));
}

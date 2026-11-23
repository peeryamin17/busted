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

export async function healthRoutes(app: FastifyInstance, deps: RouteDeps): Promise<void> {
  app.get('/health', async () => ({
    status: 'ok',
    version: '0.2.0',
    db: deps.db.kind,
    queue: deps.queue.kind,
    llm: deps.provider.name,
    time: new Date().toISOString(),
  }));
}

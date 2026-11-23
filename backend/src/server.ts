import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import type { AppConfig } from './config.js';
import type { Database } from './db/db.js';
import type { JobQueue } from './queue/queue.js';
import type { LLMProvider } from './llm/provider.js';
import { ScanOrchestrator } from './orchestrator/orchestrator.js';
import { healthRoutes } from './routes/health.js';
import { authRoutes } from './routes/auth.js';
import { googleAuthRoutes } from './routes/googleAuth.js';
import { aiKeyRoutes, registerDefaultDatabase } from './routes/aiKey.js';
import { scanRoutes, type ScanRouteDeps } from './routes/scans.js';
import { reportRoutes } from './routes/reports.js';
import { oastRoutes } from './routes/oast.js';
import { engineRoutes } from './routes/engines.js';
import { codeIntakeRoutes } from './routes/codeIntake.js';
import { detectionRoutes } from './routes/detections.js';
import { swarmRoutes } from './routes/multiagent.js';
import { tasksRoutes } from './routes/tasks.js';
import { coverageRoutes } from './routes/coverage.js';
import { retestRoutes } from './routes/retests.js';
import { v1CompatRoutes } from './routes/v1compat.js';
import { waitlistRoutes } from './routes/waitlist.js';
import { webCheckRoutes } from './routes/webcheck.js';
import { MemoryGraphStore, PostgresGraphStore, type GraphStore } from './graph/store.js';
import { MemoryCoverageStore, PostgresCoverageStore, type CoverageStore } from './coverage/ledger.js';
import { MemoryEvidenceStore, PostgresEvidenceStore, type EvidenceStore } from './evidence/snapshots.js';
import { createToolContext } from './agent/tools.js';
import { createDepthProber } from './multiagent/depthLadder.js';
import { retestFinding } from './multiagent/retester.js';
import { buildAuthenticate } from './middleware/auth.js';
import type { Finding, ScopePolicy } from './types.js';

export interface ServerDeps {
  config: AppConfig;
  db: Database;
  queue: JobQueue;
  provider: LLMProvider;
  orchestrator: ScanOrchestrator;
}

export function buildApp(deps: ServerDeps): FastifyInstance {
  const app = Fastify({ logger: false });

  app.register(cors, { origin: deps.config.corsOrigins, credentials: true });
  app.register(rateLimit, {
    max: deps.config.apiRateLimitPerMin,
    timeWindow: '1 minute',
  });

  // Friendly JSON error shape for thrown guardrail errors.
  app.setErrorHandler((err: Error & { statusCode?: number }, _request, reply) => {
    const status = err.statusCode ?? 500;
    if (status >= 500) {
      console.error('[api] internal error:', err);
    }
    reply.status(status).send({ error: err.message ?? 'Internal server error' });
  });

  registerDefaultDatabase(deps.db);

  const routeDeps: ScanRouteDeps = {
    db: deps.db,
    queue: deps.queue,
    provider: deps.provider,
    orchestrator: deps.orchestrator,
  };

  // ── stores (tasks / exploration graph, coverage, evidence) ──
  // Memory mode keeps everything in-process; Postgres mode runs the same
  // stores over the pool. A store failure must never take the API down:
  // the swarm route treats task creation as best-effort.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const pool = (deps.db as any).getPool ? (deps.db as any).getPool() : null;
  const graph: GraphStore =
    deps.db.kind === 'postgres' && pool
      ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new PostgresGraphStore((sql, params) => (pool as any).query(sql, params))
      : new MemoryGraphStore();
  const coverage: CoverageStore =
    deps.db.kind === 'postgres' && pool
      ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new PostgresCoverageStore((sql, params) => (pool as any).query(sql, params))
      : new MemoryCoverageStore();
  const evidence: EvidenceStore =
    deps.db.kind === 'postgres' && pool
      ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new PostgresEvidenceStore((sql, params) => (pool as any).query(sql, params))
      : new MemoryEvidenceStore();

  /**
   * Production retest runner: rebuilds the guarded tool context from the
   * task's own target + scope (same enforcement as the swarm, scope,
   * rate limit, SSRF on every request) and re-runs the finding's proof
   * with a fresh benign canary. Never throws: retestFinding degrades
   * every failure to 'inconclusive'.
   */
  const runRetest = async (
    finding: Finding,
    targetUrl: string,
    _userId: string,
    scope?: ScopePolicy,
  ) => {
    const target = new URL(targetUrl);
    const toolCtx = createToolContext(
      target,
      scope ?? {
        mode: 'subdomain',
        includeSubdomains: false,
        excludedHosts: [],
        excludedPaths: [],
        maxRequestsPerSecond: 2,
      },
      false,
    );
    return retestFinding({ finding, targetUrl, prober: createDepthProber(toolCtx) });
  };

  app.register(async (instance) => {
    await healthRoutes(instance, routeDeps);
    await authRoutes(instance, routeDeps);
    await googleAuthRoutes(instance, routeDeps);
    await aiKeyRoutes(instance, routeDeps);
    await scanRoutes(instance, routeDeps);
    await swarmRoutes(instance, { ...routeDeps, graph, coverage, evidence });
    await tasksRoutes(instance, { db: deps.db, graph });
    await coverageRoutes(instance, {
      coverage,
      getTask: async (id, userId) => {
        const t = await graph.getTask(id).catch(() => null);
        return t && t.userId === userId ? { id: t.id, userId: t.userId } : null;
      },
      authenticate: buildAuthenticate(deps.db),
    });
    await retestRoutes(instance, { db: deps.db, graph, runRetest });
    await v1CompatRoutes(instance, routeDeps);
    await reportRoutes(instance, routeDeps);
    await oastRoutes(instance, routeDeps);
    await engineRoutes(instance, routeDeps);
    await codeIntakeRoutes(instance, routeDeps);
    await detectionRoutes(instance, routeDeps);
    await waitlistRoutes(instance, routeDeps);
    await webCheckRoutes(instance, routeDeps);
  });

  return app;
}

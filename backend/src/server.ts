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
import { approvalsRoutes } from './routes/approvals.js';
import { pinsRoutes } from './routes/pins.js';
import { v1CompatRoutes } from './routes/v1compat.js';
import { waitlistRoutes } from './routes/waitlist.js';
import { webCheckRoutes } from './routes/webcheck.js';
import { skillsRoutes } from './routes/skills.js';
import { mcpRoutes } from './routes/mcp.js';
import { searchRoutes } from './routes/search.js';
import { notifyRoutes } from './routes/notify.js';
import { workspaceRoutes } from './routes/workspace.js';
import { companyRoutes } from './routes/companies.js';
import { sideQuestionRoutes } from './routes/sidequestions.js';
import { asmRoutes } from './routes/asm.js';
import { lessonsRoutes } from './routes/lessons.js';
import { MemorySecretStore, PostgresSecretStore, type SecretStore } from './secrets/store.js';
import { SkillRegistry } from './skills/registry.js';
import { defaultSkillsDir } from './skills/loader.js';
import { MemorySkillGapStore, PostgresSkillGapStore, type SkillGapStore } from './skills/gaps.js';
import { MemoryMcpServerStore, PostgresMcpServerStore, type McpServerStore } from './mcp/servers.js';
import { McpToolRegistry, mcpRegistry } from './mcp/registry.js';
import { MemorySearchSettingsStore, PostgresSearchSettingsStore, type SearchSettingsStore } from './search/config.js';
import { MemoryNotifyChannelStore, PostgresNotifyChannelStore, type NotifyChannelStore } from './notify/channels.js';
import { NotifyService } from './notify/send.js';
import { MemoryWorkspaceMetaStore, PostgresWorkspaceMetaStore, type WorkspaceMetaStore } from './workspace/meta.js';
import { WorkspaceFiles } from './workspace/files.js';
import { MemoryCompanyStore, PostgresCompanyStore, type CompanyStore } from './companies/store.js';
import { MemoryTaskCompanyStore, PostgresTaskCompanyStore, type TaskCompanyLinkStore } from './companies/tasks.js';
import { MemorySideQuestionStore, PostgresSideQuestionStore, type SideQuestionStore } from './sidequestions/store.js';
import { MemoryLessonStore, PostgresLessonStore, type LessonStore } from './lessons/store.js';
import { MemoryGraphStore, PostgresGraphStore, type GraphStore } from './graph/store.js';
import { MemoryCoverageStore, PostgresCoverageStore, type CoverageStore } from './coverage/ledger.js';
import { MemoryEvidenceStore, PostgresEvidenceStore, type EvidenceStore } from './evidence/snapshots.js';
import { MemoryApprovalStore, PostgresApprovalStore, type ApprovalStore } from './approvals/store.js';
import { MemoryApprovalRuleStore, PostgresApprovalRuleStore, type ApprovalRuleStore } from './approvals/rules.js';
import { MemoryPinStore, PostgresPinStore, type PinStore } from './guardrails/pins.js';
import {
  CorroborationPolicy,
  isOracleKind,
  MemoryCorroborationCounterStore,
  PostgresCorroborationCounterStore,
  type CorroborationCounterStore,
} from './multiagent/corroboration.js';
import { createToolContext } from './agent/tools.js';
import { classifyFinding, createDepthProber } from './multiagent/depthLadder.js';
import { buildPinCheck } from './multiagent/head.js';
import { NoiseGovernor } from './egress/noise.js';
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

  // ── stores (approval queue + rules, target pins) ──
  // Same pattern as the stores above: memory mode in-process,
  // Postgres mode over the pool.
  const approvals: ApprovalStore =
    deps.db.kind === 'postgres' && pool
      ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new PostgresApprovalStore((sql, params) => (pool as any).query(sql, params))
      : new MemoryApprovalStore();
  const approvalRules: ApprovalRuleStore =
    deps.db.kind === 'postgres' && pool
      ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new PostgresApprovalRuleStore((sql, params) => (pool as any).query(sql, params))
      : new MemoryApprovalRuleStore();
  const pins: PinStore =
    deps.db.kind === 'postgres' && pool
      ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new PostgresPinStore((sql, params) => (pool as any).query(sql, params))
      : new MemoryPinStore();
  const corroboration: CorroborationCounterStore =
    deps.db.kind === 'postgres' && pool
      ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new PostgresCorroborationCounterStore((sql, params) => (pool as any).query(sql, params))
      : new MemoryCorroborationCounterStore();

  // ── stores (skills, MCP, search, notifications, workspace,
  // companies, side questions, lessons) ──
  // Same pattern as the stores above: memory mode in-process,
  // Postgres mode over the pool. Secrets (search keys, MCP and channel
  // credentials) live in the encrypted user_secrets table (migration
  // 024); every other store holds metadata only, never a
  // plaintext secret.
  const secrets: SecretStore =
    deps.db.kind === 'postgres' && pool
      ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new PostgresSecretStore((sql, params) => (pool as any).query(sql, params))
      : new MemorySecretStore();
  const skillGaps: SkillGapStore =
    deps.db.kind === 'postgres' && pool
      ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new PostgresSkillGapStore((sql, params) => (pool as any).query(sql, params))
      : new MemorySkillGapStore();
  const mcpServers: McpServerStore =
    deps.db.kind === 'postgres' && pool
      ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new PostgresMcpServerStore((sql, params) => (pool as any).query(sql, params))
      : new MemoryMcpServerStore();
  const searchSettings: SearchSettingsStore =
    deps.db.kind === 'postgres' && pool
      ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new PostgresSearchSettingsStore((sql, params) => (pool as any).query(sql, params))
      : new MemorySearchSettingsStore();
  const notifyChannels: NotifyChannelStore =
    deps.db.kind === 'postgres' && pool
      ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new PostgresNotifyChannelStore((sql, params) => (pool as any).query(sql, params))
      : new MemoryNotifyChannelStore();
  const workspaceMeta: WorkspaceMetaStore =
    deps.db.kind === 'postgres' && pool
      ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new PostgresWorkspaceMetaStore((sql, params) => (pool as any).query(sql, params))
      : new MemoryWorkspaceMetaStore();
  const companies: CompanyStore =
    deps.db.kind === 'postgres' && pool
      ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new PostgresCompanyStore((sql, params) => (pool as any).query(sql, params))
      : new MemoryCompanyStore();
  const taskCompanies: TaskCompanyLinkStore =
    deps.db.kind === 'postgres' && pool
      ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new PostgresTaskCompanyStore((sql, params) => (pool as any).query(sql, params))
      : new MemoryTaskCompanyStore();
  const sideQuestions: SideQuestionStore =
    deps.db.kind === 'postgres' && pool
      ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new PostgresSideQuestionStore((sql, params) => (pool as any).query(sql, params))
      : new MemorySideQuestionStore();
  const lessons: LessonStore =
    deps.db.kind === 'postgres' && pool
      ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new PostgresLessonStore((sql, params) => (pool as any).query(sql, params))
      : new MemoryLessonStore();

  // Skill registry: load the starter packs from backend/skills/ once
  // at boot (best-effort, a missing directory must never stop the
  // server; the registry simply starts empty and the routes report it).
  const skillRegistry = new SkillRegistry();
  skillRegistry
    .loadFromDirectory(defaultSkillsDir())
    .then((loaded) => {
      if (loaded.length > 0) console.log(`[skills] loaded ${loaded.length} starter packs`);
    })
    .catch((err: unknown) => {
      console.error('[skills] starter packs failed to load:', (err as Error).message);
    });

  // Notification fan-out for swarm completion: one task-completed
  // event plus one event per critical/high finding (capped at 5).
  // Channel filters decide what the user actually receives; every
  // send is best-effort and a failing channel never breaks the scan.
  const notifyService = new NotifyService({ channels: notifyChannels, secrets });
  const onSwarmCompleted = async (input: {
    userId: string;
    scanId: string;
    taskId: string | null;
    targetUrl: string;
    findings: Array<{ severity: string; title: string; category: string }>;
  }): Promise<void> => {
    const url = 'https://bugseek-ai.vercel.app/app';
    const topSeverity = input.findings.some((f) => f.severity === 'critical')
      ? 'critical'
      : input.findings.some((f) => f.severity === 'high')
        ? 'high'
        : 'info';
    await notifyService
      .notifyEvent(input.userId, {
        kind: 'task-completed',
        taskId: input.taskId ?? input.scanId,
        title: `Swarm finished: ${input.targetUrl} (${input.findings.length} findings)`,
        severity: topSeverity,
        url,
      })
      .catch(() => undefined);
    const top = input.findings
      .filter((f) => f.severity === 'critical' || f.severity === 'high')
      .slice(0, 5);
    for (const f of top) {
      await notifyService
        .notifyEvent(input.userId, {
          kind: f.severity === 'critical' ? 'finding-critical' : 'finding-high',
          taskId: input.taskId ?? input.scanId,
          title: `${f.severity.toUpperCase()}: ${f.title}`,
          severity: f.severity === 'critical' ? 'critical' : 'high',
          url,
        })
        .catch(() => undefined);
    }
  };

  /**
   * Production retest runner: rebuilds the guarded tool context from the
   * task's own target + scope (same enforcement as the swarm, scope,
   * rate limit, SSRF on every request) and re-runs the finding's proof
   * with a fresh benign canary. Never throws: retestFinding degrades
   * every failure to 'inconclusive'. The pin gate allows only the
   * authorised target host, and the noise governor paces the probes;
   * retests never touch private targets.
   */
  const runRetest = async (
    finding: Finding,
    targetUrl: string,
    _userId: string,
    scope?: ScopePolicy,
    taskId?: string,
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
      {
        pinCheck: buildPinCheck(target),
        noise: new NoiseGovernor('balanced'),
      },
    );
    // Oracle cap: a retest of an oracle-kind finding spends one oracle run
    // from the same per-campaign counter the head uses, so retests cannot
    // bypass the cap. At the cap the oracle rung is skipped, no probe sent,
    // and the retest reads inconclusive, never fixed.
    let skipOracle = false;
    if (taskId && isOracleKind(classifyFinding(finding))) {
      const findingRef = `${finding.title} @ ${finding.location ?? targetUrl}`.slice(0, 500);
      const oracle = await new CorroborationPolicy(corroboration)
        .tryOracleRun(taskId, findingRef)
        .catch(() => ({ allowed: true, skippedForCap: false }));
      skipOracle = !oracle.allowed;
    }
    return retestFinding({ finding, targetUrl, prober: createDepthProber(toolCtx), skipOracle });
  };

  // The legacy scan paths run supervised too: the orchestrator builds a
  // Phase C task for active scans and gates every default tool through
  // it (see orchestrator.ts runActive/runPassive).
  deps.orchestrator.setPhaseCStores({ graph, coverage, evidence, approvals, approvalRules, pins, corroboration });

  app.register(async (instance) => {
    await healthRoutes(instance, routeDeps);
    await authRoutes(instance, routeDeps);
    await googleAuthRoutes(instance, routeDeps);
    await aiKeyRoutes(instance, routeDeps);
    await scanRoutes(instance, routeDeps);
    await swarmRoutes(instance, { ...routeDeps, graph, coverage, evidence, approvals, approvalRules, pins, corroboration, onSwarmCompleted });
    await tasksRoutes(instance, { db: deps.db, graph });
    await approvalsRoutes(instance, { db: deps.db, graph, approvals, rules: approvalRules });
    await pinsRoutes(instance, { db: deps.db, graph, pins });
    await skillsRoutes(instance, { db: deps.db, registry: skillRegistry, gaps: skillGaps });
    await mcpRoutes(instance, { db: deps.db, servers: mcpServers, secrets, registry: mcpRegistry });
    await searchRoutes(instance, { db: deps.db, secrets, settings: searchSettings });
    await notifyRoutes(instance, { db: deps.db, channels: notifyChannels, secrets });
    await workspaceRoutes(instance, { db: deps.db, meta: workspaceMeta, files: new WorkspaceFiles() });
    await companyRoutes(instance, { db: deps.db, companies, links: taskCompanies, graph });
    await sideQuestionRoutes(instance, { db: deps.db, graph, provider: deps.provider, questions: sideQuestions });
    await asmRoutes(instance, { db: deps.db, graph });
    await lessonsRoutes(instance, { db: deps.db, graph, lessons });
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
    await reportRoutes(instance, { ...routeDeps, graph, coverage });
    await oastRoutes(instance, routeDeps);
    await engineRoutes(instance, routeDeps);
    await codeIntakeRoutes(instance, routeDeps);
    await detectionRoutes(instance, routeDeps);
    await waitlistRoutes(instance, routeDeps);
    await webCheckRoutes(instance, routeDeps);
  });

  return app;
}

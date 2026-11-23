import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import { isAdminEmail } from '../auth/session.js';
import { PLAN_QUOTAS, SCAN_CREDIT_COST, monthStartIso } from '../auth/usage.js';
import { verifyAndRecordAuthorization } from '../guardrails/authorization.js';
import { normalizeTargetUrl } from '../guardrails/scope.js';
import { redactFindingEvidence } from '../guardrails/redact.js';
import { estimateCvss } from '../reports/cvss.js';
import { securityScore } from '../reports/score.js';
import { suggestFixes } from '../reports/remediation.js';
import { createLLMProvider, createProviderForUser } from '../llm/index.js';
import { FailoverProvider } from '../llm/qwen.js';
import { GeminiProvider } from '../llm/gemini.js';
import { config } from '../config.js';
import { getUserDecryptedAiKey, resolveQwenBaseUrl } from './aiKey.js';
import type { RouteDeps } from './health.js';
import { runMultiAgentScan } from '../multiagent/orchestrator.js';
import type { SwarmTaskContext } from '../multiagent/types.js';
import { recordFromFindings } from '../coverage/ledger.js';
import { BugSeekOSDK } from '../ontology/osdk.js';
import { ingestSurfaceToOntology } from '../ontology/ingest.js';
import { ingestUniversalOntology } from '../ontology/universalIngest.js';
import type { Confidence, PlanTier, Severity } from '../types.js';

// In-memory cache for fast polling lookups of recent swarm outcomes
const swarmScanResults = new Map<string, any>();
const swarmScanErrors = new Map<string, string>();

/**
 * Multi-agent "super agent" swarm routes.
 *
 * POST /api/swarm/scans — run the head agent + specialist workers against an
 * authorized target. Runs inline (bounded by maxDurationMs); for production
 * use at scale this should be moved onto the scan job queue.
 *
 * The scan goes through the same lifecycle as ordinary scans: an explicit
 * authorization record is REQUIRED (plan §8), credits are charged (25 per
 * active swarm scan), findings are persisted, and the scan is marked
 * completed/failed.
 *
 * LEGAL GUARDRAIL: the caller must be authorized to test the target
 * (bug-bounty program, pentest contract, or ownership). The swarm enforces
 * scope, rate limits and SSRF guards on every request; all probes are
 * non-destructive.
 */

const scopeSchema = z.object({
  mode: z.enum(['full-domain', 'subdomain', 'page']).optional(),
  includeSubdomains: z.boolean().optional(),
  excludedHosts: z.array(z.string().max(253)).max(50).optional(),
  excludedPaths: z.array(z.string().max(500)).max(50).optional(),
});

const swarmScanSchema = z.object({
  targetUrl: z.string().min(1).max(2000),
  authorization: z.unknown(), // REQUIRED — validated by verifyAndRecordAuthorization (plan §8)
  scope: scopeSchema.optional(),
  surfaceSnapshot: z.any().optional(),
  maxWorkers: z.number().int().min(1).max(8).optional(),
  concurrency: z.number().int().min(1).max(4).optional(),
  requestsPerSecond: z.number().min(0.1).max(5).optional(),
  maxTokens: z.number().int().min(1000).max(500_000).optional(),
  timeoutMinutes: z.number().min(1).max(20).optional(),
  allowPrivateTargets: z.boolean().optional(),
  sync: z.boolean().optional(),
  async: z.boolean().optional(),
  specialists: z
    .array(z.enum(['recon', 'secrets', 'headers', 'cors', 'xss', 'idor', 'auth', 'graphql', 'sourcemap']))
    .max(9)
    .optional(),
  /** Plain-language goal for the run. */
  goalText: z.string().min(1).max(5000).optional(),
});

export async function swarmRoutes(app: FastifyInstance, deps: RouteDeps): Promise<void> {
  const { db } = deps;
  const authenticate = buildAuthenticate(db);

  app.post('/api/swarm/scans', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const body = swarmScanSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    const d = body.data;
    const isOp = isAdminEmail(user.email);
    const plan: PlanTier = isOp ? 'enterprise' : user.plan;
    const quota = PLAN_QUOTAS[plan];

    const headerGeminiKey =
      typeof request.headers['x-gemini-api-key'] === 'string' &&
      request.headers['x-gemini-api-key'].trim().length >= 16
        ? request.headers['x-gemini-api-key'].trim()
        : undefined;

    const headerQwenKey =
      typeof request.headers['x-qwen-api-key'] === 'string' &&
      request.headers['x-qwen-api-key'].trim().length >= 16
        ? request.headers['x-qwen-api-key'].trim()
        : undefined;

    const userKey = headerGeminiKey || (await getUserDecryptedAiKey(db, user.id));
    // The stored BYOK key's provider (ai_provider column) decides whether
    // the decrypted key is a Gemini key or a DashScope (Qwen) key. A
    // per-request x-qwen-api-key header wins over the stored key.
    const storedAiKey = await db.getAiKey(user.id).catch(() => null);
    const storedProvider = storedAiKey?.aiProvider ?? 'gemini';
    const qwenKey =
      headerQwenKey ?? (!headerGeminiKey && storedProvider === 'qwen' ? userKey : undefined);
    // The popup sends the Qwen base URL (region / workspace) alongside a
    // local Qwen key. It is re-validated against the DashScope allowlist;
    // a bad value is ignored with a warning (the provider then fails fast
    // and failover decides) rather than killing the scan.
    const headerQwenBaseUrl =
      typeof request.headers['x-qwen-base-url'] === 'string' &&
      request.headers['x-qwen-base-url'].trim().length > 0
        ? request.headers['x-qwen-base-url'].trim()
        : undefined;
    let qwenBaseUrl = storedAiKey?.aiBaseUrl ?? undefined;
    if (headerQwenBaseUrl) {
      const resolved = resolveQwenBaseUrl('custom', headerQwenBaseUrl);
      if ('baseUrl' in resolved) qwenBaseUrl = resolved.baseUrl;
      else app.log.warn(`[swarm] ignoring invalid x-qwen-base-url header: ${resolved.error}`);
    }
    const hasByok = Boolean(userKey || headerQwenKey);

    // 1. Feature gating: swarm = active testing → Hunter+ or BYOK AI key.
    if (!isOp && !hasByok && !quota.activeTesting) {
      return reply.status(403).send({
        error: 'Active testing requires the Hunter plan or higher, or a connected AI provider key (BYOK)',
      });
    }

    // 2. Target validation (SSRF guard: public hosts only unless explicitly allowed).
    let target: URL;
    try {
      target = normalizeTargetUrl(d.targetUrl);
    } catch (err) {
      return reply.status(400).send({ error: (err as Error).message });
    }

    // 3. Authorization record (plan §8 — REQUIRED for active testing).
    let authorizationId: string;
    try {
      const record = await verifyAndRecordAuthorization(db, user.id, d.authorization);
      authorizationId = record.id;
    } catch (err) {
      const status = (err as { statusCode?: number }).statusCode ?? 400;
      return reply.status(status).send({ error: (err as Error).message });
    }

    // 4. Credit quota: a swarm scan is an active scan → 25 credits (waived when user brings their own key).
    const creditCost = hasByok ? 0 : SCAN_CREDIT_COST.active;
    if (creditCost > 0) {
      try {
        const used = await db.sumUsageSince(user.id, 'scan', monthStartIso());
        if (!isOp && used + creditCost > quota.creditsPerMonth) {
          return reply.status(429).send({
            error: `Monthly credit quota exceeded (${used}/${quota.creditsPerMonth} credits used on the ${plan} plan; this scan costs ${creditCost})`,
          });
        }
      } catch (err) {
        return reply.status(500).send({ error: (err as Error).message });
      }
    }

    // 5. Create the scan record + charge credits if applicable.
    const scope = {
      mode: d.scope?.mode ?? 'subdomain',
      includeSubdomains: d.scope?.includeSubdomains ?? false,
      excludedHosts: d.scope?.excludedHosts ?? [],
      excludedPaths: d.scope?.excludedPaths ?? [],
      maxRequestsPerSecond: Math.min(5, Math.max(0.1, d.requestsPerSecond ?? 2)),
    } as const;
    const scan = await db.createScan({
      userId: user.id,
      targetUrl: target.toString(),
      mode: 'active',
      scope: { ...scope },
      authorizationId,
      techStack: [],
    });
    if (creditCost > 0) {
      await db.recordUsage(user.id, 'scan', creditCost, scan.id);
    }

    // 5b. task: the swarm run becomes a first-class task with an
    // exploration graph, coverage ledger and evidence store. Best-effort:
    // a task-store failure never blocks the scan.
    const goalText =
      d.goalText?.trim() || `Test ${target.toString()} for security vulnerabilities`;
    let taskId: string | null = null;
    let taskCtx: SwarmTaskContext | undefined;
    if (deps.graph && deps.coverage && deps.evidence) {
      try {
        const task = await deps.graph.createTask({
          userId: user.id,
          goalText,
          targetUrl: target.toString(),
          scope: { ...scope },
          scanId: scan.id,
          authorizationId,
        });
        taskId = task.id;
        taskCtx = { taskId: task.id, graph: deps.graph, coverage: deps.coverage, evidence: deps.evidence };
      } catch (err) {
        app.log.warn({ err }, 'task creation failed; swarm continues without a task');
      }
    }

    let provider;
    if (qwenKey) {
      // BYOK Qwen is the primary provider; a DashScope failure (wrong
      // region 401, 429, timeout, 5xx) falls through to the server Gemini
      // key when one is configured, so the swarm survives a provider outage.
      const qwen = createProviderForUser('qwen', qwenKey, qwenBaseUrl);
      provider = config.geminiApiKey
        ? new FailoverProvider([qwen, new GeminiProvider(config.geminiApiKey)])
        : qwen;
    } else if (userKey) {
      provider = createLLMProvider(userKey);
    } else {
      provider = deps.provider ?? createLLMProvider();
    }

    // Ingest SurfaceSnapshot into immutable ontology graph + evidence blobs if Postgres pool is available
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const pool = (db as any).getPool ? (db as any).getPool() : (db as any).pool;
    let osdk: BugSeekOSDK | undefined;
    if (pool) {
      osdk = new BugSeekOSDK(pool);
      if (d.surfaceSnapshot) {
        if (
          d.surfaceSnapshot.baasTargets ||
          d.surfaceSnapshot.htmlForms ||
          d.surfaceSnapshot.clientSecrets ||
          d.surfaceSnapshot.detectedLibraries
        ) {
          await ingestUniversalOntology(pool, scan.id, d.surfaceSnapshot).catch((err) => {
            app.log.warn({ err }, 'Failed to ingest universal ontology snapshot');
          });
        }
        if (d.surfaceSnapshot.observedApis) {
          await ingestSurfaceToOntology(pool, scan.id, d.surfaceSnapshot).catch((err) => {
            app.log.warn({ err }, 'Failed to ingest surface snapshot to ontology');
          });
        }
      }
    }

    const isSync =
      d.sync === true ||
      request.headers['x-sync'] === 'true' ||
      (request.query as Record<string, string>)?.sync === 'true';

    const runSwarmJob = async () => {
      await db
        .updateScan(scan.id, {
          status: 'running',
          startedAt: new Date().toISOString(),
          progress: { completedSteps: 1, totalSteps: 10, currentStep: 'Swarm specialists running' },
        })
        .catch(() => undefined);

      try {
        const outcome = await runMultiAgentScan({
          targetUrl: target.toString(),
          scope: {
            mode: scope.mode,
            includeSubdomains: scope.includeSubdomains,
            excludedHosts: [...scope.excludedHosts],
            excludedPaths: [...scope.excludedPaths],
          },
          limits: {
            maxWorkers: d.maxWorkers,
            maxConcurrency: d.concurrency,
            maxTotalTokens: d.maxTokens,
            maxDurationMs: d.timeoutMinutes ? d.timeoutMinutes * 60_000 : undefined,
            requestsPerSecond: d.requestsPerSecond,
            allowPrivateTargets: d.allowPrivateTargets,
          },
          specialists: d.specialists,
          provider,
          osdk,
          scanId: scan.id,
          goalText,
          task: taskCtx,
          discoveredEndpoints: Array.isArray(d.surfaceSnapshot?.observedApis)
            ? d.surfaceSnapshot.observedApis.map((a: any) => `${a.method || 'GET'}:${a.path}`)
            : [],
        });
        // AI remediation suggestions for high/critical findings (Phase 3, best-effort).
        const fixes = await suggestFixes(outcome.findings, provider);
        // Server-side re-redaction + CVSS before persisting (same contract as scan findings).
        const findings = outcome.findings.map((f, idx) => {
          const cvss = estimateCvss(f.severity as Severity, f.category);
          const suggestedFix = fixes.get(idx);
          return redactFindingEvidence({
            ...f,
            severity: f.severity as Severity,
            confidence: (f.confidence ?? 'low') as Confidence,
            cvssScore: cvss.score,
            cvssVector: cvss.vector,
            ...(suggestedFix ? { suggestedFix } : {}),
          });
        });
        await db.addFindings(
          findings.map((f) => ({
            scanId: scan.id,
            category: f.category,
            title: f.title,
            description: f.description,
            severity: f.severity,
            confidence: f.confidence,
            location: f.location,
            evidence: f.evidence,
            remediation: f.remediation ?? '',
            cvssScore: f.cvssScore,
            cvssVector: f.cvssVector,
            trapProbability: f.trapProbability,
            honeypotSuspect: f.honeypotSuspect,
            reproSteps: f.reproSteps,
            references: f.references,
            // Depth-ladder verification (Thread 4): without this line the
            // ladder's verdicts never reach the DB, and /api/scans/:id/report
            // (which reads findings from the DB) shows no verified chains.
            verification: f.verification,
          })),
        );
        // persist the ladder's content-addressed proof snapshots
        // against the finding DB ids (matched by title + location), and
        // record 'finding' coverage entries from the findings.
        if (taskCtx) {
          const persisted = await db.listFindings(scan.id);
          const byKey = new Map(persisted.map((p) => [`${p.title}|${p.location ?? ''}`, p]));
          for (const f of outcome.findings) {
            const snaps = f.proofSnapshots;
            if (!snaps || snaps.length === 0) continue;
            const match = byKey.get(`${f.title}|${f.location ?? ''}`);
            if (!match) continue;
            for (const s of snaps) {
              await taskCtx.evidence
                .put(s, { findingId: match.id, taskId: taskCtx.taskId })
                .catch(() => undefined);
            }
          }
          const entries = recordFromFindings(
            taskCtx.taskId,
            outcome.findings.map((f) => ({ category: f.category, location: f.location })),
          );
          for (const e of entries) {
            await taskCtx.coverage.recordEntry(e).catch(() => undefined);
          }
        }
        if (outcome.testsRun === 0 && outcome.findings.length === 0) {
          const firstErr = outcome.errors?.[0] || 'All specialists failed to execute tests';
          throw new Error(`Swarm scan aborted: 0 tests were executed. ${firstErr}`);
        }
        const score = securityScore(findings, {
          mode: 'swarm',
          endpointsDiscovered: Math.max(1, outcome.testsRun),
          endpointsActivelyTested: outcome.testsRun,
          authenticated: false,
        });
        await db.updateScan(scan.id, {
          status: 'completed',
          finishedAt: new Date().toISOString(),
          progress: { completedSteps: 10, totalSteps: 10, currentStep: 'Swarm scan completed' },
        });
        if (taskCtx) {
          await taskCtx.graph.updateTaskStatus(taskCtx.taskId, 'done').catch(() => undefined);
        }

        const fullResult = {
          jobId: scan.id,
          scanId: scan.id,
          taskId,
          status: 'completed' as const,
          targetUrl: outcome.targetUrl,
          headSummary: outcome.headSummary,
          score,
          findings,
          workerReports: outcome.workerReports.map((r) => ({
            specialistId: r.specialistId,
            specialistName: r.specialistName,
            summary: r.summary,
            findings: r.findings.length,
            testsRun: r.testsRun,
            testsPlanned: r.testsPlanned,
            llmCalls: r.llmCalls,
            tokensUsed: r.tokensUsed,
            errors: r.errors,
            durationMs: r.durationMs,
          })),
          testsRun: outcome.testsRun,
          llmCalls: outcome.llmCalls,
          tokensUsed: {
            input: Number.isFinite(outcome.tokensUsed?.input) ? outcome.tokensUsed.input : 0,
            output: Number.isFinite(outcome.tokensUsed?.output) ? outcome.tokensUsed.output : 0,
            total:
              (Number.isFinite(outcome.tokensUsed?.input) ? outcome.tokensUsed.input : 0) +
              (Number.isFinite(outcome.tokensUsed?.output) ? outcome.tokensUsed.output : 0),
          },
          durationMs: outcome.durationMs,
          errors: outcome.errors,
        };
        swarmScanResults.set(scan.id, fullResult);
        return fullResult;
      } catch (err) {
        const errorMsg = (err as Error).message || 'Swarm job failed';
        await db
          .updateScan(scan.id, {
            status: 'failed',
            finishedAt: new Date().toISOString(),
            error: errorMsg,
          })
          .catch(() => undefined);
        if (taskCtx) {
          await taskCtx.graph.updateTaskStatus(taskCtx.taskId, 'failed').catch(() => undefined);
        }
        swarmScanErrors.set(scan.id, errorMsg);
        throw err;
      }
    };

    if (isSync) {
      try {
        const result = await runSwarmJob();
        return reply.status(200).send(result);
      } catch (err) {
        const status = (err as { statusCode?: number }).statusCode ?? 500;
        return reply.status(status).send({ error: (err as Error).message });
      }
    }

    // Fire-and-forget background worker execution for 202 Accepted
    void runSwarmJob().catch((err) => {
      app.log.error({ err, scanId: scan.id }, 'Swarm job failed');
    });

    return reply.status(202).send({
      jobId: scan.id,
      scanId: scan.id,
      taskId,
      status: 'queued',
      targetUrl: target.toString(),
    });
  });

  // ── Lightweight polling status endpoint for background swarm scans ──────────
  app.get('/api/swarm/scans/:id', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const scan = await db.getScan(id);
    if (!scan || (scan.userId !== user.id && !isAdminEmail(user.email))) {
      return reply.status(404).send({ error: 'Job not found' });
    }

    if (scan.status === 'completed') {
      const cached = swarmScanResults.get(id);
      if (cached) {
        return reply.send(cached);
      }
      const findings = await db.listFindings(id);
      return reply.send({
        jobId: scan.id,
        scanId: scan.id,
        status: 'completed',
        targetUrl: scan.targetUrl,
        headSummary: 'Swarm scan completed.',
        findings,
        workerReports: [],
        score: securityScore(findings, {
          mode: 'swarm',
          endpointsDiscovered: Math.max(1, findings.length),
          endpointsActivelyTested: findings.length,
          authenticated: false,
        }),
        testsRun: findings.length,
        llmCalls: 0,
        tokensUsed: 0,
        durationMs: 0,
      });
    }

    if (scan.status === 'failed') {
      return reply.send({
        jobId: scan.id,
        scanId: scan.id,
        status: 'failed',
        error: scan.error || swarmScanErrors.get(id) || 'Swarm job failed',
      });
    }

    return reply.send({
      jobId: scan.id,
      scanId: scan.id,
      status: scan.status,
      progress: scan.progress,
    });
  });
}

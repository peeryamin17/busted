import type { FastifyInstance } from 'fastify';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import { isAdminEmail } from '../auth/session.js';
import { isUrlInScope, normalizeTargetUrl } from '../guardrails/scope.js';
import type { Database } from '../db/db.js';
import type { GraphStore } from '../graph/store.js';
import {
  applyRetestVerdict,
  type RetestResult,
} from '../multiagent/retester.js';
import type { Finding, Scan, ScopePolicy } from '../types.js';

/**
 * Retest routes.
 *
 * POST /api/tasks/:id/findings/:findingId/retest - re-run one finding's own
 * proof with a fresh benign canary and record the verdict
 * (reproduced / fixed / inconclusive). GET /api/tasks/:id/retests - the
 * task's retest history, newest first.
 *
 * The finding must belong to the caller's scan/task; the scan's
 * authorization record must still exist and belong to the scan's owner
 * (a retest is active testing, so a missing authorization is a hard
 * stop); and the finding's location must still be inside the scan's
 * authorised scope. All verdict logic lives in multiagent/retester.ts,
 * and the probing is the injected runRetest runner.
 * Registered in server.ts, not here.
 */

export interface RetestRouteDeps {
  db: Database;
  /**
   * The tasks store. When present, a task id resolves through
   * the tasks table to its scan; when absent (tests, older wiring) the
   * task id is treated as a scan id, as before.
   */
  graph?: GraphStore;
  /**
   * Runs one retest for a finding the caller owns. Injected so tests can
   * pass a fake; the production runner (wired in server.ts) builds a
   * DepthProber for the task via `createDepthProber(toolExecutionContext)`
   *, the context built from the task's target + scope exactly as the swarm
   * route builds it, and calls `retestFinding({ finding, targetUrl,
   * prober })`. The runner must never throw: `retestFinding` already
   * degrades every failure to 'inconclusive'. The optional 4th argument
   * is the scan's scope policy, so the runner can enforce it.
   */
  runRetest: (
    finding: Finding,
    targetUrl: string,
    userId: string,
    scope?: ScopePolicy,
  ) => Promise<RetestResult>;
}

export async function retestRoutes(app: FastifyInstance, deps: RetestRouteDeps): Promise<void> {
  const { db, graph, runRetest } = deps;
  const authenticate = buildAuthenticate(db);

  /**
   * Resolve a task id to the scan that carries its target, scope and
   * authorization. With the tasks table, the task row points at
   * its scan; without a graph store the task id is a scan id (the
   * pre-tasks fallback, kept for tests).
   */
  async function resolveTask(taskId: string): Promise<Scan | null> {
    if (graph) {
      const task = await graph.getTask(taskId).catch(() => null);
      if (!task) return null;
      if (!task.scanId) return null;
      return db.getScan(task.scanId);
    }
    return db.getScan(taskId);
  }

  app.post(
    '/api/tasks/:id/findings/:findingId/retest',
    { preHandler: authenticate },
    async (request, reply) => {
      const user = requireUser(request);
      const { id, findingId } = request.params as { id: string; findingId: string };
      const scan = await resolveTask(id);
      if (!scan || (scan.userId !== user.id && !isAdminEmail(user.email))) {
        return reply.status(404).send({ error: 'Task not found' });
      }
      const findings = await db.listFindings(scan.id);
      const finding = findings.find((f) => f.id === findingId);
      if (!finding) {
        return reply.status(404).send({ error: 'Finding not found' });
      }

      // Re-check authorisation: the scan's authorization record must still
      // exist and belong to the scan's owner. Same bar as the swarm route,
      // active testing without a live authorization record is refused.
      if (!scan.authorizationId) {
        return reply.status(403).send({
          error: 'Retest refused: the scan has no authorization record for active testing',
        });
      }
      const authorization = await db.getAuthorization(scan.authorizationId).catch(() => null);
      if (!authorization || authorization.userId !== scan.userId) {
        return reply.status(403).send({
          error: 'Retest refused: the scan authorization record is missing',
        });
      }

      // Re-check scope: the finding's location (else the scan target) must
      // still be inside the scan's authorised scope.
      let target: URL;
      try {
        target = normalizeTargetUrl(scan.targetUrl);
      } catch (err) {
        return reply.status(400).send({ error: (err as Error).message });
      }
      const scopeCheck = isUrlInScope(finding.location ?? scan.targetUrl, target, scan.scope);
      if (!scopeCheck.allowed) {
        return reply.status(403).send({
          error: `Retest refused: ${scopeCheck.reason ?? 'finding is outside the authorised scope'}`,
        });
      }

      let result: RetestResult;
      try {
        result = await runRetest(finding, scan.targetUrl, user.id, scan.scope);
      } catch (err) {
        return reply.status(500).send({ error: (err as Error).message });
      }

      const verification = applyRetestVerdict(finding, result);
      await db.recordRetest({
        taskId: id,
        findingId: finding.id,
        scanId: scan.id,
        verdict: result.verdict,
        depth: result.depth ?? null,
        evidence: result.evidence,
        impactSummary: result.impactSummary,
        testedAt: result.testedAt,
        method: result.method,
      });
      const updated = await db.updateFindingVerification(finding.id, verification);
      return reply.send({ ...result, verification: updated?.verification ?? verification });
    },
  );

  app.get('/api/tasks/:id/retests', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const scan = await resolveTask(id);
    if (!scan || (scan.userId !== user.id && !isAdminEmail(user.email))) {
      return reply.status(404).send({ error: 'Task not found' });
    }
    const retests = await db.listRetests(id);
    return { taskId: id, retests };
  });
}

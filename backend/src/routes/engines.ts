import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import { PLAN_QUOTAS, monthStartIso } from '../auth/usage.js';
import { verifyAndRecordAuthorization } from '../guardrails/authorization.js';
import { normalizeTargetUrl } from '../guardrails/scope.js';
import { redactFindingEvidence } from '../guardrails/redact.js';
import { estimateCvss } from '../reports/cvss.js';
import { securityScore } from '../reports/score.js';
import type { RouteDeps } from './health.js';
import { parseImport, type ImportedFinding } from '../engines/importers.js';
import { engineStatus, runEngine, type EngineId } from '../engines/runner.js';
import {
  assertProgrammeScope,
  sharedScopeDataset,
  type ScopeDataset,
} from '../scope/dataset.js';
import type { Confidence, ScopeCheckResult, Severity } from '../types.js';

/**
 * Open-source engine routes (Phase 5).
 *
 *   GET  /api/engines/status    — which bundled engines exist on this host.
 *   POST /api/engines/scans     — run WhatWeb/Nikto/Nuclei against an
 *                                 AUTHORISED target (Hunter plan, recorded
 *                                 authorisation, 10 credits — engines burn
 *                                 no LLM tokens but are premium compute).
 *   POST /api/import/findings   — import a ZAP/Nuclei/Nikto/SQLMap report
 *                                 file's contents; normalised, deduped,
 *                                 CVSS-scored, persisted as a scan.
 *
 * Imported findings are labelled with their source tool in the finding
 * itself — provenance is never laundered into "BugSeek found this".
 */

const ENGINE_CREDIT_COST = 10;

const importSchema = z.object({
  format: z.enum(['auto', 'zap', 'nuclei', 'nikto', 'sqlmap']).default('auto'),
  content: z.string().min(2).max(12_000_000),
  targetUrl: z.string().min(1).max(2000),
});

const engineScanSchema = z.object({
  engine: z.enum(['whatweb', 'nikto', 'nuclei']),
  targetUrl: z.string().min(1).max(2000),
  authorization: z.unknown(), // REQUIRED — validated by verifyAndRecordAuthorization
  // OPTIONAL programme reference: when a HackerOne/Bugcrowd programme is
  // named, its published scope is checked before charging (see
  // docs/scope-validation.md). Never a substitute for authorization.
  programme: z
    .object({
      platform: z.enum(['hackerone', 'bugcrowd']),
      handle: z.string().min(1).max(200),
    })
    .optional(),
});

type Db = RouteDeps['db'];

async function persistFindings(
  db: Db,
  scanId: string,
  imported: ImportedFinding[],
): Promise<Array<Record<string, unknown>>> {
  const saved: Array<Record<string, unknown>> = [];
  for (const f of imported) {
    const cvss = estimateCvss(f.severity as Severity, f.category);
    const rec = await db.addFinding(
      redactFindingEvidence({
        scanId,
        category: f.category,
        title: `[${f.source.split(' (')[0]}] ${f.title}`,
        description: `${f.description}\n\nImported from ${f.source} — verify before reporting; imported findings are not trap-screened.`,
        severity: f.severity as Severity,
        confidence: f.confidence as Confidence,
        cvssScore: cvss.score,
        cvssVector: cvss.vector,
        trapProbability: 0,
        honeypotSuspect: false,
        location: f.location,
        evidence: f.evidence,
        reproSteps: [],
        remediation: f.remediation,
        references: f.references,
      }),
    );
    saved.push({
      id: rec.id,
      category: rec.category,
      title: rec.title,
      description: rec.description,
      severity: rec.severity,
      confidence: rec.confidence,
      location: rec.location,
      evidence: rec.evidence,
      remediation: rec.remediation,
      cvssScore: rec.cvssScore,
      cvssVector: rec.cvssVector,
      trapProbability: rec.trapProbability,
      honeypotSuspect: rec.honeypotSuspect,
    });
  }
  return saved;
}

export async function engineRoutes(
  app: FastifyInstance,
  deps: RouteDeps & { scopeDataset?: ScopeDataset },
): Promise<void> {
  const { db } = deps;
  const authenticate = buildAuthenticate(db);

  app.get('/api/engines/status', { preHandler: authenticate }, async () => {
    return { engines: await engineStatus() };
  });

  app.post('/api/import/findings', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const body = importSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    let imported: ImportedFinding[];
    try {
      imported = parseImport(body.data.format, body.data.content);
    } catch (err) {
      return reply.status(400).send({ error: `Could not parse report: ${(err as Error).message}` });
    }
    const scan = await db.createScan({
      userId: user.id,
      targetUrl: body.data.targetUrl,
      mode: 'passive',
      scope: { mode: 'page', includeSubdomains: false, excludedHosts: [], excludedPaths: [], maxRequestsPerSecond: 1 },
      techStack: [],
    });
    const findings = await persistFindings(db, scan.id, imported);
    await db.updateScan(scan.id, { status: 'completed' });
    return reply.send({
      scanId: scan.id,
      imported: findings.length,
      findings,
      score: securityScore(
        imported.map((f) => ({ severity: f.severity, confidence: f.confidence, honeypotSuspect: false })),
      ),
    });
  });

  app.post('/api/engines/scans', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const body = engineScanSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    const d = body.data;
    const quota = PLAN_QUOTAS[user.plan];
    if (!quota.activeTesting) {
      return reply.status(403).send({ error: 'Active testing requires the Hunter plan or higher' });
    }

    let target: URL;
    try {
      target = normalizeTargetUrl(d.targetUrl);
    } catch (err) {
      return reply.status(400).send({ error: (err as Error).message });
    }

    let authorizationId: string;
    try {
      const record = await verifyAndRecordAuthorization(db, user.id, d.authorization);
      authorizationId = record.id;
    } catch (err) {
      const status = (err as { statusCode?: number }).statusCode ?? 400;
      return reply.status(status).send({ error: (err as Error).message });
    }

    // Optional programme scope check: a programme that places this target
    // outside its published scope stops the scan before any charge; other
    // verdicts are recorded on the scan as authorisation evidence.
    let scopeEvidence: ScopeCheckResult | undefined;
    if (d.programme) {
      try {
        scopeEvidence = await assertProgrammeScope(
          deps.scopeDataset ?? sharedScopeDataset,
          d.programme.platform,
          d.programme.handle,
          target.toString(),
        );
      } catch (err) {
        const status = (err as { statusCode?: number }).statusCode ?? 400;
        return reply.status(status).send({ error: (err as Error).message });
      }
    }

    // Availability BEFORE charging anyone.
    const status = (await engineStatus()).find((e) => e.engine === (d.engine as EngineId));
    if (!status?.available) {
      return reply.status(503).send({ error: `Engine ${d.engine} is not available on this backend (${status?.detail ?? 'not installed'})` });
    }

    const used = await db.sumUsageSince(user.id, 'scan', monthStartIso());
    if (used + ENGINE_CREDIT_COST > quota.creditsPerMonth) {
      return reply.status(429).send({
        error: `Monthly credit quota exceeded (${used}/${quota.creditsPerMonth} credits used on the ${user.plan} plan; this scan costs ${ENGINE_CREDIT_COST})`,
      });
    }

    const scan = await db.createScan({
      userId: user.id,
      targetUrl: target.toString(),
      mode: 'active',
      scope: { mode: 'subdomain', includeSubdomains: false, excludedHosts: [], excludedPaths: [], maxRequestsPerSecond: 2 },
      authorizationId,
      scopeEvidence,
      techStack: [],
    });
    await db.recordUsage(user.id, 'scan', ENGINE_CREDIT_COST, scan.id);

    try {
      const imported = await runEngine(d.engine as EngineId, target.toString());
      const findings = await persistFindings(db, scan.id, imported);
      await db.updateScan(scan.id, { status: 'completed' });
      return reply.send({
        scanId: scan.id,
        engine: d.engine,
        ...(scopeEvidence ? { scopeCheck: scopeEvidence } : {}),
        findings,
        score: securityScore(
          imported.map((f) => ({ severity: f.severity, confidence: f.confidence, honeypotSuspect: false })),
        ),
      });
    } catch (err) {
      await db.updateScan(scan.id, { status: 'failed' }).catch(() => undefined);
      const statusCode = (err as { statusCode?: number }).statusCode ?? 500;
      return reply.status(statusCode).send({ error: (err as Error).message });
    }
  });
}

import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import { securityScore } from '../reports/score.js';
import { runWebPatrol, type PatrolOutcome } from '../webcheck/run.js';
import { fetchRequesterGeo } from '../webcheck/info.js';
import type { GeoStamp, WebCheckRecord, WebFinding } from '../webcheck/types.js';
import type { PlanTier, Severity } from '../types.js';
import type { RouteDeps } from './health.js';

/**
 * Web demo patrol routes.
 *
 *   POST /api/webcheck      — run a passive patrol on a site the user
 *                             owns (the `authorized` tick is the licence
 *                             to probe it), store the FULL result,
 *                             answer with the plan-gated view.
 *   GET  /api/webcheck      — my runs, newest first, summaries only.
 *   GET  /api/webcheck/:id  — one of my runs, plan-gated view.
 *
 * THE GATE IS THE PRODUCT: the stored result is complete, but free
 * plans see the first two findings in full and only {severity,
 * category} for the rest — withheld titles/details never leave the
 * server. Upgrading unblurs the stored run; nothing re-scans.
 */

export type PatrolRunner = (url: string) => Promise<PatrolOutcome>;

export interface WebCheckRouteOptions {
  /** Test seam: replace the live patrol with a fixture runner. */
  patrol?: PatrolRunner;
  /**
   * Test seam: resolve the requester's coarse location for the run's
   * origin stamp. Production reads the visitor's address off the
   * wire; a slow or failed lookup never blocks the patrol.
   */
  geo?: (ip: string) => Promise<GeoStamp | null>;
}

const LOCKED = [
  {
    label: 'Active checks',
    count: 9,
    note: 'These run inside the Chrome extension, in your browser.',
  },
  {
    label: 'Open-source engines (Nuclei · Nikto · ZAP)',
    count: null,
    note: 'Engine room opens with the Hunter plan.',
  },
] as const;

const createSchema = z.object({
  url: z.string().min(1, 'Paste the site to patrol').max(2048),
  authorized: z.boolean(),
});

function fullFinding(f: WebFinding): Record<string, unknown> {
  const out: Record<string, unknown> = {
    severity: f.severity,
    category: f.category,
    title: f.title,
    detail: f.detail,
    confidence: f.confidence,
  };
  if (f.evidence !== undefined) out.evidence = f.evidence;
  return out;
}

export function gatedView(rec: WebCheckRecord, plan: PlanTier): Record<string, unknown> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of rec.findings) counts[f.severity]++;

  const gated = plan === 'free';
  return {
    id: rec.id,
    url: rec.url,
    host: rec.host,
    createdAt: rec.createdAt,
    score: rec.score,
    grade: rec.grade,
    counts,
    gated,
    findings: gated
      ? rec.findings.map((f, i) =>
          i < 2 ? fullFinding(f) : { severity: f.severity, category: f.category },
        )
      : rec.findings.map(fullFinding),
    info: rec.info,
    /** The origin stamp stored with this run (the owner's own — shown back to them). */
    requester: { ip: rec.requesterIp, geo: rec.requesterGeo },
    locked: LOCKED,
  };
}

export async function webCheckRoutes(
  app: FastifyInstance,
  deps: RouteDeps,
  opts: WebCheckRouteOptions = {},
): Promise<void> {
  const { db } = deps;
  const authenticate = buildAuthenticate(db);
  const patrol: PatrolRunner = opts.patrol ?? ((url) => runWebPatrol(url));

  // One patrol a minute per user (the fleet is small and targets
  // deserve a breather). Checked in-route, keyed by the account —
  // the plugin's IP limit below is just the outer fence.
  const lastRunAt = new Map<string, number>();
  const RUN_INTERVAL_MS = 60_000;

  app.post(
    '/api/webcheck',
    {
      preHandler: authenticate,
      config: { rateLimit: { max: 1, timeWindow: '1 minute' } },
    },
    async (request, reply) => {
      const user = requireUser(request);
      const body = createSchema.safeParse(request.body);
      if (!body.success) {
        return reply
          .status(400)
          .send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
      }
      if (body.data.authorized !== true) {
        return reply.status(400).send({
          error: 'Tick the box first — the patrol only visits sites you own or may test.',
        });
      }

      const now = Date.now();
      const last = lastRunAt.get(user.id) ?? 0;
      if (now - last < RUN_INTERVAL_MS) {
        return reply
          .status(429)
          .send({ error: 'One patrol a minute — let the last one sink in.' });
      }
      lastRunAt.set(user.id, now);

      try {
        const outcome = await patrol(body.data.url);
        // Stamp the run with who asked and roughly where from
        // (disclosed on the form). Behind Vercel → Render the
        // visitor's address is the first forwarded hop; request.ip
        // is the fallback. Geo is best-effort.
        const xff = request.headers['x-forwarded-for'];
        const firstHop = (Array.isArray(xff) ? xff[0] : xff)?.split(',')[0]?.trim();
        const requesterIp = firstHop || request.ip || null;
        let requesterGeo: GeoStamp | null = null;
        if (requesterIp) {
          try {
            requesterGeo = await (opts.geo ?? fetchRequesterGeo)(requesterIp);
          } catch {
            requesterGeo = null;
          }
        }
        const scored = securityScore(outcome.findings);
        const rec = await db.insertWebCheck({
          userId: user.id,
          url: outcome.url,
          host: outcome.host,
          authorized: true,
          score: scored.value,
          grade: scored.grade,
          findings: outcome.findings,
          info: outcome.info,
          requesterIp,
          requesterGeo,
        });
        return reply.status(201).send(gatedView(rec, user.plan));
      } catch (err) {
        const status = (err as { statusCode?: number }).statusCode ?? 500;
        if (status >= 500 && status !== 502) {
          console.error('[webcheck] patrol failed:', err);
        }
        return reply
          .status(status)
          .send({ error: (err as Error).message ?? 'The patrol failed' });
      }
    },
  );

  app.get('/api/webcheck', { preHandler: authenticate }, async (request) => {
    const user = requireUser(request);
    const runs = await db.listWebChecks(user.id, 20);
    return {
      runs: runs.map((r) => ({
        id: r.id,
        url: r.url,
        host: r.host,
        score: r.score,
        grade: r.grade,
        findingCount: r.findings.length,
        requesterIp: r.requesterIp,
        requesterGeo: r.requesterGeo,
        createdAt: r.createdAt,
      })),
    };
  });

  app.get(
    '/api/webcheck/:id',
    { preHandler: authenticate },
    async (request, reply) => {
      const user = requireUser(request);
      const { id } = request.params as { id: string };
      const rec = await db.getWebCheck(user.id, id);
      if (!rec) {
        return reply.status(404).send({ error: 'No such patrol run' });
      }
      return gatedView(rec, user.plan);
    },
  );
}

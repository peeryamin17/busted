import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import { securityScore } from '../reports/score.js';
import { runWebPatrol, type PatrolOutcome } from '../webcheck/run.js';
import { fetchRequesterGeo, fetchReverseGeo } from '../webcheck/info.js';
import type { GeoStamp, RequesterOrigin, WebCheckRecord, WebFinding } from '../webcheck/types.js';
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
  /** Test seam: place names for device coordinates, when GPS was shared. */
  reverseGeo?: (
    lat: number,
    lon: number,
  ) => Promise<{ city: string | null; region: string | null; country: string | null } | null>;
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

/** Free accounts get a lifetime handful of patrols; plans patrol freely. */
const FREE_PATROL_LIMIT = 10;
/** Free accounts keep their newest few runs readable; the rest sit in the vault. */
const FREE_HISTORY_OPEN = 3;

interface PatrolUsage {
  used: number;
  limit: number | null;
  left: number | null;
}

function usageFor(plan: PlanTier, used: number): PatrolUsage {
  const limit = plan === 'free' ? FREE_PATROL_LIMIT : null;
  return { used, limit, left: limit === null ? null : Math.max(0, limit - used) };
}

const createSchema = z.object({
  url: z.string().min(1, 'Paste the site to patrol').max(2048),
  authorized: z.boolean(),
  /**
   * The device's position, present only when the visitor allowed the
   * browser's location prompt. Coordinates are taken as given; they
   * outrank the IP-based stamp on the run.
   */
  gps: z
    .object({
      lat: z.number().min(-90).max(90),
      lon: z.number().min(-180).max(180),
      accuracy: z.number().nonnegative().max(1_000_000).optional(),
    })
    .optional(),
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
    /** The trust verdict ("is it a trap?") — separate from the score, always. */
    trust: rec.info.trust ?? null,
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

      /* The free handful is for keeps: ten patrols a lifetime, counted
         from the stored runs. Refuse BEFORE the throttle stamps or a
         single probe flies — a plan is the only way past this door. */
      const usedBefore = await db.countWebChecks(user.id);
      if (user.plan === 'free' && usedBefore >= FREE_PATROL_LIMIT) {
        return reply.status(403).send({
          error:
            "You've used your 10 free patrols — a plan unlocks unlimited patrols and your full history.",
          code: 'quota_exceeded',
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
        // Stamp the run with who asked and where from — BOTH halves,
        // side by side (disclosed on the form): the address and its
        // coarse location always, and the device's own position when
        // the visitor shared it. Both lookups are best-effort.
        const xff = request.headers['x-forwarded-for'];
        const firstHop = (Array.isArray(xff) ? xff[0] : xff)?.split(',')[0]?.trim();
        const requesterIp = firstHop || request.ip || null;
        let ipGeo: GeoStamp | null = null;
        if (requesterIp) {
          try {
            ipGeo = await (opts.geo ?? fetchRequesterGeo)(requesterIp);
          } catch {
            ipGeo = null;
          }
        }
        let gpsStamp: RequesterOrigin['gps'] = null;
        const gps = body.data.gps;
        if (gps) {
          let place: { city: string | null; region: string | null; country: string | null } | null =
            null;
          try {
            place = await (opts.reverseGeo ?? fetchReverseGeo)(gps.lat, gps.lon);
          } catch {
            place = null;
          }
          gpsStamp = {
            country: place?.country ?? null,
            city: place?.city ?? null,
            region: place?.region ?? null,
            lat: gps.lat,
            lon: gps.lon,
            ...(gps.accuracy !== undefined ? { accuracyM: gps.accuracy } : {}),
          };
        }
        const requesterGeo: RequesterOrigin | null =
          ipGeo || gpsStamp ? { ip: ipGeo, gps: gpsStamp } : null;
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
        return reply
          .status(201)
          .send({ ...gatedView(rec, user.plan), usage: usageFor(user.plan, usedBefore + 1) });
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
    const runs = await db.listWebCheckSummaries(user.id, 20);
    const used = await db.countWebChecks(user.id);
    return {
      usage: usageFor(user.plan, used),
      runs: runs.map((r, i) => {
        /* History vault: past the newest few, a free account keeps the
           fact of a run — its host and date — and none of its contents. */
        if (user.plan === 'free' && i >= FREE_HISTORY_OPEN) {
          return { id: r.id, host: r.host, createdAt: r.createdAt, locked: true };
        }
        return {
          id: r.id,
          url: r.url,
          host: r.host,
          score: r.score,
          grade: r.grade,
          findingCount: r.findingCount,
          trustVerdict: r.trustVerdict,
          requesterIp: r.requesterIp,
          requesterGeo: r.requesterGeo,
          createdAt: r.createdAt,
        };
      }),
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
      /* The vault door: a free account reopens only its newest few
         runs; anything older is a plan's to unlock. */
      if (user.plan === 'free') {
        const open = await db.listWebCheckSummaries(user.id, FREE_HISTORY_OPEN);
        if (!open.some((r) => r.id === rec.id)) {
          return reply.status(403).send({
            error: 'That patrol rests in the vault — a plan unlocks your full history.',
            code: 'history_locked',
          });
        }
      }
      return gatedView(rec, user.plan);
    },
  );
}

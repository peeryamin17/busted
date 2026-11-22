/**
 * Analyzer (Thread 5, DEFENSIVE) — runs the rules and persists what fires.
 *
 * Dedupe: a candidate is only persisted when no detection with the same
 * dedupe key exists from the last hour (a spray that keeps going does
 * not spam the panel with a new row every run). Analysis is on-demand —
 * the coordinator wires it to run after login/API-key/request intake, or
 * on a schedule. It never runs by itself here.
 */
import type { Database } from '../db/db.js';
import { runAllRules, type RuleOptions } from './rules.js';
import type { ApiKeyBaseline, DetectionRecord, SecurityEvent } from './types.js';

export interface AnalyzeOptions extends RuleOptions {
  /** Dedupe window for repeat firings of the same pattern + entity. */
  dedupeWindowMs?: number;
}

const DEFAULT_DEDUPE_MS = 60 * 60_000;

/**
 * Run all rules over `events` for `userId` and persist new detections.
 * Returns the detections created by this run (possibly empty). When the
 * event list is empty the honest answer is "nothing to analyse", not a
 * clean bill of health.
 */
export async function analyzeEvents(
  db: Database,
  userId: string,
  events: SecurityEvent[],
  baseline: ApiKeyBaseline | null = null,
  opts: AnalyzeOptions = {},
): Promise<{ created: DetectionRecord[]; analyzedEvents: number }> {
  const candidates = runAllRules(events, baseline, opts);
  const dedupeMs = opts.dedupeWindowMs ?? DEFAULT_DEDUPE_MS;
  const recent = await db.listDetections(userId, 200);
  const recentSince = Date.now() - dedupeMs;
  const seen = new Set(
    recent
      .filter((d) => Date.parse(d.createdAt) >= recentSince)
      .map((d) => d.dedupeKey),
  );

  const created: DetectionRecord[] = [];
  for (const c of candidates) {
    if (seen.has(c.dedupeKey)) continue;
    seen.add(c.dedupeKey);
    created.push(
      await db.recordDetection({
        userId,
        pattern: c.pattern,
        severity: c.severity,
        title: c.title,
        detail: c.detail,
        evidence: c.evidence,
        dedupeKey: c.dedupeKey,
      }),
    );
  }
  return { created, analyzedEvents: events.length };
}

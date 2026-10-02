import type { Confidence, Severity } from '../types.js';

/**
 * Aggregate security score (Phase 4) — one 0–100 number + letter grade for
 * a scan, derived from its findings so the UI can lead with a verdict.
 *
 * Heuristic by design, and deliberately conservative:
 *  - suspected honeypots NEVER lower the score (unverified by definition);
 *  - low-confidence findings count less than confirmed ones;
 *  - a single critical shouldn't zero a site, but three should hurt.
 */
const SEVERITY_COST: Record<Severity, number> = {
  critical: 25,
  high: 12,
  medium: 5,
  low: 2,
  info: 0.5,
};

const CONFIDENCE_WEIGHT: Record<Confidence, number> = {
  high: 1,
  medium: 0.7,
  low: 0.4,
};

export interface SecurityScore {
  value: number; // 0..100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  deductions: number;
}

export function securityScore(
  findings: Array<{
    severity: Severity;
    confidence?: Confidence;
    honeypotSuspect?: boolean;
  }>,
): SecurityScore {
  let deductions = 0;
  for (const f of findings) {
    if (f.honeypotSuspect) continue;
    deductions += SEVERITY_COST[f.severity] * CONFIDENCE_WEIGHT[f.confidence ?? 'low'];
  }
  const value = Math.max(0, Math.round(100 - deductions));
  const grade: SecurityScore['grade'] =
    value >= 90 ? 'A' : value >= 75 ? 'B' : value >= 60 ? 'C' : value >= 40 ? 'D' : 'F';
  return { value, grade, deductions: Math.round(deductions * 10) / 10 };
}

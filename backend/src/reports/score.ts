import type { Confidence } from '../types.js';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface ScoreableFinding {
  severity: Severity;
  confidence?: number;       // 0..1 (default 0.85)
  trapProbability?: number;  // 0..1 (default 0)
  verdict?: 'confirmed' | 'downgraded' | 'dropped' | 'honeypot_trap';
}

export interface CoverageMetrics {
  mode: 'passive' | 'active' | 'swarm';
  endpointsDiscovered: number;
  endpointsActivelyTested: number;
  authenticated: boolean;
}

export interface SecurityScoreReport {
  postureScore: number;            // 0..100
  coverageRatio: number;           // 0..1
  effectiveGrade: 'A' | 'B' | 'C' | 'D' | 'F' | 'INCOMPLETE';
  coverageLabel: string;
  riskIndex: number;
  warnings: string[];
}

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 45,
  high: 24,
  medium: 11,
  low: 3,
  info: 0,
};

const DECAY_LAMBDA = 0.018;

export function computeSecurityScore(
  findings: ScoreableFinding[],
  coverage: CoverageMetrics
): SecurityScoreReport {
  let riskIndex = 0;

  for (const f of findings) {
    if (f.verdict === 'dropped' || f.verdict === 'honeypot_trap') continue;
    const w = SEVERITY_WEIGHT[f.severity] ?? 0;
    const confidence = Math.min(1, Math.max(0, f.confidence ?? 0.85));
    const trapDiscount = 1 - Math.min(1, Math.max(0, f.trapProbability ?? 0));
    riskIndex += w * confidence * trapDiscount;
  }

  const postureScore = Math.max(
    0,
    Math.min(100, Math.round(100 * Math.exp(-DECAY_LAMBDA * riskIndex)))
  );

  const coverageRatio =
    coverage.mode === 'passive'
      ? 0
      : coverage.endpointsDiscovered === 0
        ? coverage.endpointsActivelyTested > 0
          ? 0.5
          : 0
        : Math.min(1, coverage.endpointsActivelyTested / coverage.endpointsDiscovered);

  const warnings: string[] = [];
  if (coverage.mode === 'passive') {
    warnings.push('Passive scan only: API endpoints and business logic were not tested.');
  } else if (coverageRatio < 0.25) {
    warnings.push(
      `Low active coverage (${coverage.endpointsActivelyTested}/${coverage.endpointsDiscovered} discovered endpoints tested).`
    );
  }
  if (!coverage.authenticated) {
    warnings.push('Unauthenticated scan: post-login IDOR and access-control surfaces were not evaluated.');
  }

  // Never award an A/B grade when coverage is insufficient
  let effectiveGrade: SecurityScoreReport['effectiveGrade'];
  if (coverage.mode === 'passive' || coverageRatio < 0.25) {
    effectiveGrade = postureScore < 60 ? 'D' : 'INCOMPLETE';
  } else if (postureScore >= 90) {
    effectiveGrade = 'A';
  } else if (postureScore >= 80) {
    effectiveGrade = 'B';
  } else if (postureScore >= 65) {
    effectiveGrade = 'C';
  } else if (postureScore >= 45) {
    effectiveGrade = 'D';
  } else {
    effectiveGrade = 'F';
  }

  const coverageLabel =
    coverage.mode === 'passive'
      ? 'Passive Posture Only'
      : `Active Coverage: ${Math.round(coverageRatio * 100)}% (${coverage.endpointsActivelyTested}/${coverage.endpointsDiscovered})`;

  return {
    postureScore,
    coverageRatio: Number(coverageRatio.toFixed(3)),
    effectiveGrade,
    coverageLabel,
    riskIndex: Number(riskIndex.toFixed(2)),
    warnings,
  };
}

export interface SecurityScore extends SecurityScoreReport {
  value: number; // 0..100
  grade: 'A' | 'B' | 'C' | 'D' | 'F' | 'INCOMPLETE';
  deductions: number;
}

export function securityScore(
  findings: Array<{
    severity: Severity;
    confidence?: Confidence | number;
    honeypotSuspect?: boolean;
    trapProbability?: number;
    verdict?: 'confirmed' | 'downgraded' | 'dropped' | 'honeypot_trap';
  }>,
  coverage?: Partial<CoverageMetrics>,
): SecurityScore {
  const scoreableFindings: ScoreableFinding[] = findings.map((f) => {
    let confNum = 0.85;
    if (typeof f.confidence === 'number') {
      confNum = f.confidence;
    } else if (f.confidence === 'high') {
      confNum = 1.0;
    } else if (f.confidence === 'medium') {
      confNum = 0.7;
    } else if (f.confidence === 'low') {
      confNum = 0.4;
    }
    const trapProb = f.trapProbability ?? (f.honeypotSuspect ? 1 : 0);
    return {
      severity: f.severity,
      confidence: confNum,
      trapProbability: trapProb,
      verdict: f.honeypotSuspect ? 'honeypot_trap' : f.verdict,
    };
  });

  const cov: CoverageMetrics = {
    mode: coverage?.mode ?? 'active',
    endpointsDiscovered: coverage?.endpointsDiscovered ?? Math.max(1, findings.length),
    endpointsActivelyTested: coverage?.endpointsActivelyTested ?? Math.max(1, findings.length),
    authenticated: coverage?.authenticated ?? false,
  };

  const report = computeSecurityScore(scoreableFindings, cov);

  return {
    value: report.postureScore,
    grade: report.effectiveGrade,
    deductions: report.riskIndex,
    ...report,
  };
}

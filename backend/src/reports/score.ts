import type { Confidence } from '../types.js';
import type { StackArchetype } from '../ontology/universalIngest.js';
import type { GraphDelta } from '../ontology/osdk.js';

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

// ─────────────────────────────────────────────────────────────────────────────
// Universal Ontology 4-Matrix Posture Model
// ─────────────────────────────────────────────────────────────────────────────

export type OntologyRiskCategory =
  | 'CLIENT_SECRET_EXPOSURE'
  | 'DIRECT_BAAS_WITHOUT_RLS'
  | 'UNPROTECTED_STATE_MUTATION'
  | 'FORM_MISSING_CSRF'
  | 'INSECURE_SESSION_COOKIE'
  | 'OUTDATED_LIBRARY_CVE'
  | 'MISSING_SECURITY_HEADER';

export interface ScoredOntologyNode {
  nodeId: string;
  riskCategory: OntologyRiskCategory;
  blastRadiusCount: number;    // From osdk.getBlastRadius().length
  provenanceVerified: boolean; // From osdk.verifyProvenance()
  confidence?: number;         // 0..1 (default 0.9 for deterministic graph hits)
  trapProbability?: number;    // 0..1 (default 0)
}

export interface ControlMatrixInput {
  totalMutatingEndpoints: number;
  protectedMutatingEndpoints: number;
  totalBaasTargets: number;
  rlsProtectedBaasTargets: number;
  totalSessionCookies: number;
  hardenedSessionCookies: number;
}

export interface CoverageMatrixInput {
  mode: 'passive' | 'active' | 'swarm';
  archetypes: StackArchetype[];
  endpointsDiscovered: number;
  endpointsTested: number;
  authenticated: boolean;
}

export interface OntologyScoreReport {
  postureScore: number; // 0..100
  effectiveGrade: 'A' | 'B' | 'C' | 'D' | 'F' | 'INCOMPLETE';
  matrices: {
    ontologyRiskIndex: number;
    controlHygieneScore: number; // 0..100
    driftPenalty: number;
    coverageRatio: number;       // 0..1
  };
  breakdownByCategory: Record<string, { count: number; weightedRisk: number }>;
  archetypes: StackArchetype[];
  warnings: string[];
}

const CATEGORY_WEIGHTS: Record<OntologyRiskCategory, number> = {
  CLIENT_SECRET_EXPOSURE: 50,
  DIRECT_BAAS_WITHOUT_RLS: 40,
  UNPROTECTED_STATE_MUTATION: 22,
  FORM_MISSING_CSRF: 18,
  OUTDATED_LIBRARY_CVE: 15,
  INSECURE_SESSION_COOKIE: 10,
  MISSING_SECURITY_HEADER: 5,
};

const BLAST_ALPHA = 0.25;
const DRIFT_CONTROL_PENALTY = 12;
const ONTOLOGY_DECAY_LAMBDA = 0.015;

function computeControlHygiene(ctrl: ControlMatrixInput): number {
  const ratios: number[] = [];

  if (ctrl.totalMutatingEndpoints > 0) {
    ratios.push(ctrl.protectedMutatingEndpoints / ctrl.totalMutatingEndpoints);
  }
  if (ctrl.totalBaasTargets > 0) {
    ratios.push(ctrl.rlsProtectedBaasTargets / ctrl.totalBaasTargets);
  }
  if (ctrl.totalSessionCookies > 0) {
    ratios.push(ctrl.hardenedSessionCookies / ctrl.totalSessionCookies);
  }

  if (ratios.length === 0) return 100;
  const mean = ratios.reduce((acc, v) => acc + v, 0) / ratios.length;
  return Math.round(mean * 100);
}

export function computeOntologyScore(params: {
  nodes: ScoredOntologyNode[];
  controls: ControlMatrixInput;
  coverage: CoverageMatrixInput;
  delta?: GraphDelta | null;
}): OntologyScoreReport {
  const { nodes, controls, coverage, delta } = params;
  const breakdown: Record<string, { count: number; weightedRisk: number }> = {};
  const warnings: string[] = [];

  let ontologyRiskIndex = 0;
  let unverifiedDropped = 0;

  // 1. Ontology Risk Matrix (Blast-Radius & Provenance Weighted)
  for (const node of nodes) {
    if (!node.provenanceVerified) {
      unverifiedDropped++;
      continue;
    }

    const baseWeight = CATEGORY_WEIGHTS[node.riskCategory] ?? 10;
    const blastMultiplier = 1 + BLAST_ALPHA * Math.log(1 + Math.max(0, node.blastRadiusCount));
    const confidence = Math.min(1, Math.max(0, node.confidence ?? 0.9));
    const trapDiscount = 1 - Math.min(1, Math.max(0, node.trapProbability ?? 0));

    const weighted = baseWeight * blastMultiplier * confidence * trapDiscount;
    ontologyRiskIndex += weighted;

    if (!breakdown[node.riskCategory]) {
      breakdown[node.riskCategory] = { count: 0, weightedRisk: 0 };
    }
    breakdown[node.riskCategory].count += 1;
    breakdown[node.riskCategory].weightedRisk = Number(
      (breakdown[node.riskCategory].weightedRisk + weighted).toFixed(2)
    );
  }

  if (unverifiedDropped > 0) {
    warnings.push(
      `Dropped ${unverifiedDropped} finding(s) that failed cryptographic provenance verification.`
    );
  }

  // 2. Temporal Drift Matrix
  const removedControlsCount = delta?.removedControls.length ?? 0;
  const driftPenalty = removedControlsCount * DRIFT_CONTROL_PENALTY;
  if (removedControlsCount > 0) {
    warnings.push(
      `Security regression detected: ${removedControlsCount} control(s) removed since baseline scan.`
    );
  }

  // 3. Control Hygiene Matrix
  const controlHygieneScore = computeControlHygiene(controls);

  // 4. Composite Posture Score
  const totalRisk = ontologyRiskIndex + driftPenalty;
  const postureScore = Math.max(
    0,
    Math.min(100, Math.round(100 * Math.exp(-ONTOLOGY_DECAY_LAMBDA * totalRisk)))
  );

  // 5. Coverage Gate
  const coverageRatio =
    coverage.mode === 'passive'
      ? 0
      : coverage.endpointsDiscovered === 0
        ? coverage.endpointsTested > 0
          ? 0.5
          : 0
        : Math.min(1, coverage.endpointsTested / coverage.endpointsDiscovered);

  if (coverage.mode === 'passive') {
    warnings.push('Passive scan only: active state-graph and API mutation checks did not run.');
  } else if (coverageRatio < 0.25) {
    warnings.push(
      `Low surface coverage (${coverage.endpointsTested}/${coverage.endpointsDiscovered} endpoints tested).`
    );
  }
  if (!coverage.authenticated) {
    warnings.push('Unauthenticated scan: role-based access control and post-login surfaces were not evaluated.');
  }

  let effectiveGrade: OntologyScoreReport['effectiveGrade'];
  if (coverage.mode === 'passive' || coverageRatio < 0.25) {
    effectiveGrade = postureScore < 60 ? 'D' : 'INCOMPLETE';
  } else if (postureScore >= 90 && controlHygieneScore >= 85) {
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

  return {
    postureScore,
    effectiveGrade,
    matrices: {
      ontologyRiskIndex: Number(ontologyRiskIndex.toFixed(2)),
      controlHygieneScore,
      driftPenalty,
      coverageRatio: Number(coverageRatio.toFixed(3)),
    },
    breakdownByCategory: breakdown,
    archetypes: coverage.archetypes,
    warnings,
  };
}

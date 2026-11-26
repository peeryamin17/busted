import type { Finding, ReproduceBlock, Scan } from '../types.js';
import { SEVERITY_ORDER } from '../types.js';
import { verificationLabel } from './verification.js';
import type { ReportInput } from './markdown.js';
import {
  coverageVerdict,
  emptyCoverageVerdict,
  type CoverageTier,
} from './coverageHonesty.js';

/**
 * JSON findings export, the same findings the Markdown report shows,
 * as a structured document: scan metadata, a severity summary, and the
 * findings array. Pretty-printed (2 spaces) so it is readable as a file.
 * No new finding fields are invented; every field comes from Finding/Scan.
 */

export interface JsonFinding {
  id: string;
  title: string;
  category: string;
  severity: string;
  cvssScore?: number;
  cvssVector?: string;
  severityRewritten?: boolean;
  gradeReason?: string;
  nvdCheck?: string;
  nvdScore?: number;
  reproduce?: ReproduceBlock;
  confidence: string;
  verification: string;
  location?: string;
  description: string;
  evidence?: string;
  remediation: string;
  suggestedFix?: string;
  honeypotSuspect: boolean;
  trapProbability: number;
  references: string[];
  reproSteps: string[];
  createdAt: string;
}

export interface JsonReport {
  format: 'bugseek-findings-v1';
  generatedBy: string;
  generatedAt: string;
  scan: {
    id: string;
    targetUrl: string;
    mode: string;
    status: string;
    createdAt: string;
    finishedAt?: string;
    authorizationId?: string;
  };
  summary: { total: number; bySeverity: Record<string, number> };
  /**
   * Coverage honesty: how much of the intended surface was examined.
   * inconclusive is true only when the report has zero findings and the
   * surface was not fully examined. Absent coverage data counts as none.
   */
  coverage: {
    tier: CoverageTier;
    inconclusive: boolean;
    testedClasses: number;
    applicableClasses: number;
    untestedClasses: string[];
    testedAssets: number;
  };
  findings: JsonFinding[];
}

function toJsonFinding(f: Finding): JsonFinding {
  return {
    id: f.id,
    title: f.title,
    category: f.category,
    severity: f.severity,
    ...(f.cvssScore != null ? { cvssScore: f.cvssScore } : {}),
    ...(f.cvssVector ? { cvssVector: f.cvssVector } : {}),
    ...(f.severityRewritten ? { severityRewritten: true } : {}),
    ...(f.gradeReason ? { gradeReason: f.gradeReason } : {}),
    ...(f.nvdCheck ? { nvdCheck: f.nvdCheck } : {}),
    ...(f.nvdScore != null ? { nvdScore: f.nvdScore } : {}),
    ...(f.reproduce ? { reproduce: f.reproduce } : {}),
    confidence: f.confidence,
    verification: verificationLabel(f),
    ...(f.location ? { location: f.location } : {}),
    description: f.description,
    ...(f.evidence ? { evidence: f.evidence } : {}),
    remediation: f.remediation,
    ...(f.suggestedFix ? { suggestedFix: f.suggestedFix } : {}),
    honeypotSuspect: f.honeypotSuspect,
    trapProbability: f.trapProbability,
    references: [...f.references],
    reproSteps: [...f.reproSteps],
    createdAt: f.createdAt,
  };
}

/** Build the JSON report document (object form, for callers that re-serialise). */
export function buildJsonReport(input: ReportInput): JsonReport {
  const { scan, findings } = input;
  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );
  const bySeverity: Record<string, number> = {};
  for (const f of sorted) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  const verdict = input.coverage
    ? coverageVerdict(input.coverage, sorted.length)
    : emptyCoverageVerdict(sorted.length);
  return {
    format: 'bugseek-findings-v1',
    generatedBy: input.generatedBy,
    generatedAt: new Date().toISOString(),
    scan: {
      id: scan.id,
      targetUrl: scan.targetUrl,
      mode: scan.mode,
      status: scan.status,
      createdAt: scan.createdAt,
      ...(scan.finishedAt ? { finishedAt: scan.finishedAt } : {}),
      ...(scan.authorizationId ? { authorizationId: scan.authorizationId } : {}),
    },
    summary: { total: sorted.length, bySeverity },
    coverage: {
      tier: verdict.tier,
      inconclusive: verdict.inconclusive,
      testedClasses: verdict.testedClasses,
      applicableClasses: verdict.applicableClasses,
      untestedClasses: verdict.untestedClasses,
      testedAssets: verdict.testedAssets,
    },
    findings: sorted.map(toJsonFinding),
  };
}

/** Pretty-printed JSON export of a scan's findings. */
export function generateJsonReport(input: ReportInput): string {
  return JSON.stringify(buildJsonReport(input), null, 2) + '\n';
}

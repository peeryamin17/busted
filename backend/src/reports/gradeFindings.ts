import { estimateCvss, scoreFromVector, severityLabel } from './cvss.js';
import type { Finding, ReproduceBlock } from '../types.js';

// Grading pass over findings, run before any report is rendered (see
// routes/reports.ts). It recomputes severity from CVSS, never trusts a
// model-supplied score over its own vector, applies context multipliers,
// cross-checks CVEs against NVD, and builds a copy-pasteable reproduce
// block. Pure grading: no probes, no mutation of stored findings.

export const NVD_MISMATCH_THRESHOLD = 2.0;

export const CONTEXT_MULTIPLIERS = {
  internetFacing: 1.15,
  authRequired: 0.8,
  exploitAvailable: 1.2,
} as const;

export interface GradeContext {
  internetFacing?: boolean;
  authRequired?: boolean;
  exploitAvailable?: boolean;
}

/** Returns the NVD published base score, or null when unreachable / no entry. */
export type NvdScoreFetcher = (cveId: string) => Promise<number | null>;

export interface GradeOptions {
  context?: GradeContext;
  fetchNvdScore?: NvdScoreFetcher;
}

const CVE_RE = /CVE-\d{4}-\d{4,7}/i;

/** First CVE id mentioned in the finding's references, title or description. */
export function extractCveId(f: Finding): string | null {
  for (const text of [...f.references, f.title, f.description]) {
    const m = text.match(CVE_RE);
    if (m) return m[0].toUpperCase();
  }
  return null;
}

/** True when the target host is a public address, not localhost / private. */
export function isPublicTarget(targetUrl: string): boolean {
  try {
    const host = new URL(targetUrl).hostname.toLowerCase();
    if (host === 'localhost' || host === '[::1]') return false;
    if (/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host)) return false;
    return true;
  } catch {
    return false;
  }
}

/** Apply the context multipliers to a base score, clamped to 0.0-10.0. */
export function applyContext(base: number, ctx: GradeContext): number {
  let score = base;
  if (ctx.internetFacing) score *= CONTEXT_MULTIPLIERS.internetFacing;
  if (ctx.authRequired) score *= CONTEXT_MULTIPLIERS.authRequired;
  if (ctx.exploitAvailable) score *= CONTEXT_MULTIPLIERS.exploitAvailable;
  return Math.min(10, Math.max(0, Math.round(score * 10) / 10));
}

function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

function firstUrl(texts: string[]): string | undefined {
  for (const text of texts) {
    const m = text.match(/https?:\/\/[^\s'")\]]+/);
    if (m) return m[0];
  }
  return undefined;
}

/** Build the reproduce block: paste-safe command, raw HTTP request, expected indicator. */
export function buildReproduceBlock(f: Finding): ReproduceBlock {
  const target =
    (f.location?.startsWith('http') ? f.location : undefined) ??
    firstUrl([...f.reproSteps, f.evidence ?? '']) ??
    f.location ??
    '';
  const command = target ? `curl -s -i ${shellQuote(target)}` : 'curl -s -i <target-url>';
  let request: string;
  try {
    const u = new URL(target);
    request = `GET ${u.pathname}${u.search} HTTP/1.1\nHost: ${u.host}\nAccept: */*\nConnection: close`;
  } catch {
    request = `GET / HTTP/1.1\nHost: ${target || 'target'}\nAccept: */*\nConnection: close`;
  }
  const expected =
    f.reproSteps.length > 0
      ? f.reproSteps[f.reproSteps.length - 1]
      : f.evidence
        ? f.evidence.split('\n')[0].slice(0, 120)
        : 'Response shows the reported behaviour';
  return { command, request, expected };
}

/** Grade one finding: recompute CVSS, rewrite severity to its band, build the reproduce block. */
export function gradeFinding(f: Finding, opts: GradeOptions = {}): Finding {
  const out: Finding = { ...f };
  const notes: string[] = [];
  let base: number | null = null;
  let fromVector = false;
  if (f.cvssVector) {
    const computed = scoreFromVector(f.cvssVector);
    if (computed !== null) {
      base = computed;
      fromVector = true;
    }
  }
  if (base === null && f.cvssScore != null) base = f.cvssScore;
  if (base === null) {
    const est = estimateCvss(f.severity, f.category);
    base = est.score;
    if (!out.cvssVector) out.cvssVector = est.vector;
  }
  if (fromVector && f.cvssScore != null && Math.round(f.cvssScore * 10) !== Math.round(base * 10)) {
    notes.push(
      `CVSS score ${f.cvssScore.toFixed(1)} disagreed with its vector (computed ${base.toFixed(1)}); score replaced`,
    );
  }
  const adjusted = applyContext(base, opts.context ?? {});
  const band = severityLabel(adjusted);
  out.cvssScore = adjusted;
  if (band !== f.severity) {
    out.severity = band;
    out.severityRewritten = true;
    notes.push(`severity ${f.severity} -> ${band} (CVSS ${adjusted.toFixed(1)})`);
  }
  if (notes.length > 0) out.gradeReason = notes.join('; ');
  out.reproduce = buildReproduceBlock(f);
  return out;
}

/** Base score used for the NVD comparison: from the vector when present, else the recorded score. */
function baseForNvd(f: Finding): number | null {
  if (f.cvssVector) {
    const computed = scoreFromVector(f.cvssVector);
    if (computed !== null) return computed;
  }
  return f.cvssScore ?? null;
}

/**
 * Grade every finding, then cross-check CVEs against NVD. A mismatch over
 * the threshold demotes a verified finding to hint; anything the fetcher
 * cannot answer (no entry, unreachable, throws) is recorded unchecked and
 * never demotes. Findings without a CVE are untouched by this step.
 */
export async function gradeFindings(findings: Finding[], opts: GradeOptions = {}): Promise<Finding[]> {
  const graded = findings.map((f) => gradeFinding(f, opts));
  if (!opts.fetchNvdScore) return graded;
  const cache = new Map<string, number | null>();
  for (const f of graded) {
    const cve = extractCveId(f);
    if (!cve) continue;
    let nvd: number | null;
    if (cache.has(cve)) {
      nvd = cache.get(cve) ?? null;
    } else {
      try {
        nvd = await opts.fetchNvdScore(cve);
      } catch {
        nvd = null;
      }
      cache.set(cve, nvd);
    }
    if (nvd === null) {
      f.nvdCheck = 'unchecked';
      continue;
    }
    f.nvdScore = nvd;
    const base = baseForNvd(f);
    const diff = base === null ? 0 : Math.abs(base - nvd);
    if (diff > NVD_MISMATCH_THRESHOLD) {
      f.nvdCheck = 'mismatch';
      if (f.verification?.status === 'verified') {
        f.verification = { ...f.verification, status: 'hint' };
      }
      const note =
        `NVD cross-check: NVD scores ${cve} ${nvd.toFixed(1)} vs computed ${(base ?? 0).toFixed(1)} ` +
        `(diff ${diff.toFixed(1)} > ${NVD_MISMATCH_THRESHOLD.toFixed(1)}); finding demoted to hint`;
      f.gradeReason = f.gradeReason ? `${f.gradeReason}; ${note}` : note;
    } else {
      f.nvdCheck = 'match';
    }
  }
  return graded;
}

/** One-liners for the report renderers: what the grading pass changed, if anything. */
export function gradingNotes(f: Finding): string[] {
  const notes: string[] = [];
  const reason = f.gradeReason ?? '';
  const sevMatch = reason.match(/severity \w+ -> \w+ \(CVSS [\d.]+\)/);
  const rest = reason
    .replace(sevMatch?.[0] ?? '\u0000', '')
    .replace(/NVD cross-check:.*?finding demoted to hint/, '')
    .split(';')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .join('; ');
  if (f.severityRewritten) {
    notes.push(
      `Severity re-graded: ${sevMatch?.[0] ?? 'CVSS band disagreed with recorded severity'}`,
    );
  }
  if (rest.length > 0) notes.push(`Grading note: ${rest}`);
  if (f.nvdCheck === 'mismatch') {
    notes.push(
      `NVD cross-check: mismatch (NVD ${f.nvdScore?.toFixed(1) ?? 'n/a'}) — treated as unverified hint`,
    );
  } else if (f.nvdCheck === 'unchecked') {
    notes.push('NVD cross-check: unchecked (NVD unreachable or no entry for this CVE)');
  } else if (f.nvdCheck === 'match') {
    notes.push(`NVD cross-check: matches published score (${f.nvdScore?.toFixed(1)})`);
  }
  return notes;
}

/** Live NVD lookup, fail-open: any failure returns null (unchecked, never demotes). */
export async function fetchNvdScore(cveId: string): Promise<number | null> {
  let res: Response;
  try {
    res = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`,
      { signal: AbortSignal.timeout(5000), headers: { Accept: 'application/json' } },
    );
  } catch {
    return null;
  }
  if (!res.ok) return null;
  let doc: unknown;
  try {
    doc = await res.json();
  } catch {
    return null;
  }
  const cve = (doc as { vulnerabilities?: Array<{ cve?: unknown }> })?.vulnerabilities?.[0]?.cve as
    | { metrics?: { cvssMetricV31?: Array<{ cvssData?: { baseScore?: number } }>; cvssMetricV30?: Array<{ cvssData?: { baseScore?: number } }> } }
    | undefined;
  const v31 = cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore;
  if (typeof v31 === 'number') return v31;
  const v30 = cve?.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore;
  return typeof v30 === 'number' ? v30 : null;
}

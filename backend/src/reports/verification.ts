import { assignPoe, type OracleVerdict } from './poe.js';
import type { Finding } from '../types.js';

/**
 * Shared "Verified exploit chain" rendering helpers for the Markdown, PDF
 * and DOCX report generators. All three reports show the same contract:
 *
 * - Verified findings (ladder status 'verified') appear under
 *   "Verified exploit chain" as vulnerability → canary proof → escalation
 *   proof → measured impact, with the redacted evidence for each rung.
 * - Hint findings (status 'hint', or no verification object on findings
 *   from older scans) appear separately, labelled as hints, and are never
 *   presented as confirmed.
 *
 * 'Verified' here means reproduced with a benign canary and read-only
 * proofs. It is not proof of exploitability to full impact, the ladder
 * never executes an attack chain.
 */

/**
 * Three-valued verdict for one finding, from what it carries: 'fixed'
 * is refuted (a clean re-run proved the proof no longer reproduces);
 * 'verified' at POE 3+ is confirmed unless the gate recorded a failed
 * receipt (receiptChecked false); anything else is inconclusive,
 * including a finding the gate never ran (receiptChecked unset) with a
 * status below verified. An inconclusive finding is never verified.
 */
export function verificationVerdict(f: Finding): OracleVerdict {
  const v = f.verification;
  if (!v) return 'inconclusive';
  if (v.status === 'fixed') return 'refuted';
  if (v.status === 'verified' && assignPoe(f).poe >= 3 && v.receiptChecked !== false) {
    return 'confirmed';
  }
  return 'inconclusive';
}

/**
 * A finding counts as verified only at POE 3 or higher (see reports/poe.ts).
 * A record that still carries status 'verified' from before the POE gate,
 * or with a POE below 3, is a hint, not a verified chain.
 */
export function isVerifiedFinding(f: Finding): boolean {
  return verificationVerdict(f) === 'confirmed';
}

export function verifiedFindings(findings: Finding[]): Finding[] {
  return findings.filter(isVerifiedFinding);
}

export function fixedFindings(findings: Finding[]): Finding[] {
  return findings.filter((f) => f.verification?.status === 'fixed');
}

export function hintFindings(findings: Finding[]): Finding[] {
  return findings.filter(
    (f) => !isVerifiedFinding(f) && f.verification?.status !== 'fixed',
  );
}

export function verificationLabel(f: Finding): string {
  const v = f.verification;
  const poe = assignPoe(f).poe;
  if (!v) {
    return `Hint — not verified (no depth-ladder result; treat as unconfirmed), POE ${poe}`;
  }
  if (verificationVerdict(f) === 'confirmed') {
    return (
      `Verified — depth: ${v.depth}, measured impact: ${v.impact}` +
      (v.canaryToken ? `, canary: ${v.canaryToken}` : '') +
      `, POE ${poe}`
    );
  }
  if (v.status === 'fixed') {
    return `Fixed — a retest confirmed the proof no longer reproduces (${v.impactSummary}), POE ${poe}`;
  }
  return `Hint — unproven (${v.impactSummary}), POE ${poe}`;
}

/** One line per rung of the verified chain, in ladder order. */
export function chainLines(f: Finding): string[] {
  const v = f.verification;
  if (!v) return [];
  const lines: string[] = [
    `Vulnerability: ${f.title} (${f.severity}, ${f.location ?? 'location not recorded'})`,
  ];
  for (const e of v.evidence) {
    const rung = e.rung === 'confirm' ? 'Canary proof' : 'Escalation proof';
    lines.push(
      `${rung} [${e.kind}]: ${e.request} → ${e.observed}`,
    );
  }
  if (v.evidence.length === 0) {
    lines.push('Canary proof: (no rung evidence recorded)');
  }
  lines.push(`Measured impact: ${v.impactSummary}`);
  if (v.stopReason) lines.push(`Ladder stopped early: ${v.stopReason}`);
  return lines;
}

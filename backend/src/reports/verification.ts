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
 * proofs. It is not proof of exploitability to full impact — the ladder
 * never executes an attack chain.
 */

export function verifiedFindings(findings: Finding[]): Finding[] {
  return findings.filter((f) => f.verification?.status === 'verified');
}

export function hintFindings(findings: Finding[]): Finding[] {
  return findings.filter((f) => f.verification?.status !== 'verified');
}

export function verificationLabel(f: Finding): string {
  const v = f.verification;
  if (!v) return 'Hint — not verified (no depth-ladder result; treat as unconfirmed)';
  if (v.status === 'verified') {
    return (
      `Verified — depth: ${v.depth}, measured impact: ${v.impact}` +
      (v.canaryToken ? `, canary: ${v.canaryToken}` : '')
    );
  }
  return `Hint — unproven (${v.impactSummary})`;
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

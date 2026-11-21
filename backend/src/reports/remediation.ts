import type { LLMProvider } from '../llm/provider.js';
import type { Finding } from '../types.js';

/**
 *
 *
 * For medium/high/critical findings, provides a CONCRETE "Fix-in-IDE" prompt
 * with vulnerable pattern → fixed pattern snippets for developers to paste
 * directly into their AI-assisted IDE (Cursor, Claude Code, GitHub Copilot).
 *
 * Bounds: at most MAX_FIXES findings per scan.
 * Best-effort: a failed suggestion never fails the scan.
 */

const MAX_FIXES = 10;

type FixInput = Pick<
  Finding,
  | 'title'
  | 'description'
  | 'severity'
  | 'confidence'
  | 'location'
  | 'evidence'
  | 'remediation'
  | 'honeypotSuspect'
>;

/**
 * Builds a concrete "Fix-in-IDE" prompt suitable for an engineer to hand
 * to an IDE-based coding agent (Cursor, Claude Code, Copilot, Gemini CLI).
 */
export function buildFixInIdePrompt(finding: {
  title: string;
  category?: string;
  severity: string;
  confidence?: string;
  location?: string;
  evidence?: string;
  description?: string;
  remediation?: string;
}): string {
  return [
    `// BugSeek AI — Fix-in-IDE Remediation Prompt`,
    `// Vulnerability: ${finding.title}`,
    `// Severity: ${finding.severity.toUpperCase()}${finding.confidence ? ` (Confidence: ${finding.confidence})` : ''}`,
    `// Target / Location: ${finding.location ?? 'unknown'}`,
    ...(finding.evidence ? [`// Evidence: ${finding.evidence}`] : []),
    ...(finding.remediation ? [`// Recommended fix: ${finding.remediation}`] : []),
    ``,
    `TASK FOR AI CODING ASSISTANT:`,
    `1. Locate the file and code handler implementing ${finding.location ?? finding.title}.`,
    `2. Apply the necessary defensive controls to remediate this vulnerability.`,
    `3. Add or update unit/integration tests to verify the fix and prevent regressions.`,
  ].join('\n');
}

export async function suggestFixes(
  findings: FixInput[],
  provider: LLMProvider,
): Promise<Map<number, string>> {
  const out = new Map<number, string>();

  const candidates = findings
    .map((f, i) => ({ f, i }))
    .filter(
      ({ f }) =>
        (f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium') &&
        !f.honeypotSuspect,
    )
    .slice(0, MAX_FIXES);

  if (provider.name === 'mock') {
    for (const { f, i } of candidates) {
      out.set(i, buildFixInIdePrompt(f));
    }
    return out;
  }

  for (const { f, i } of candidates) {
    try {
      const completion = await provider.complete({
        messages: [
          {
            role: 'system',
            content:
              'You are a senior application-security engineer writing fix guidance for developers. Be concrete and brief.',
          },
          {
            role: 'user',
            content:
              `Finding: ${f.title}\n` +
              `Severity: ${f.severity} (confidence: ${f.confidence})\n` +
              `Location: ${f.location ?? 'unknown'}\n` +
              `Description: ${f.description}\n` +
              `Redacted evidence: ${f.evidence ?? 'n/a'}\n` +
              `Current advice: ${f.remediation}\n\n` +
              `Write a CONCRETE suggested code fix: show the vulnerable pattern and the fixed pattern ` +
              `as a short before/after snippet (max 12 lines total), naming the exact API, header, or ` +
              `config to use. Do not repeat generic advice. Plain text only, no markdown fences, no preamble.`,
          },
        ],
        maxTokens: 500,
        temperature: 0.1,
        tier: 'reasoning',
      });
      const text = completion.text.trim();
      const prompt = buildFixInIdePrompt(f) + (text ? `\n\n// Suggested Code Fix:\n${text}` : '');
      out.set(i, prompt.slice(0, 3000));
    } catch {
      out.set(i, buildFixInIdePrompt(f));
    }
  }
  return out;
}

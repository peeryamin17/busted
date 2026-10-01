import type { LLMProvider } from '../llm/provider.js';
import type { Finding } from '../types.js';

/**
 * Phase 3 — AI remediation suggestions (developer persona).
 *
 * For high/critical findings, asks the cheap 'routine' tier for a CONCRETE
 * suggested code fix (vulnerable pattern → fixed pattern, short snippet).
 * Suggestions are explicitly labeled AI-generated and unverified in every
 * report format — a confidently wrong auto-fix is worse than none.
 *
 * Bounds: at most MAX_FIXES findings per scan; skipped entirely when the
 * provider is the mock (no point suggesting fixes for synthetic findings).
 * Best-effort: a failed suggestion never fails the scan.
 */

const MAX_FIXES = 5;

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

export async function suggestFixes(
  findings: FixInput[],
  provider: LLMProvider,
): Promise<Map<number, string>> {
  const out = new Map<number, string>();
  if (provider.name === 'mock') return out;

  const candidates = findings
    .map((f, i) => ({ f, i }))
    .filter(
      ({ f }) =>
        (f.severity === 'high' || f.severity === 'critical') && !f.honeypotSuspect,
    )
    .slice(0, MAX_FIXES);

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
        maxTokens: 400,
        temperature: 0.2,
        tier: 'routine',
      });
      const text = completion.text.trim();
      if (text) out.set(i, text.slice(0, 2000));
    } catch {
      /* best-effort — a missing suggestion never fails the scan */
    }
  }
  return out;
}

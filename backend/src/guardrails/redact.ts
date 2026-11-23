/**
 * LEGAL GUARDRAIL, no exfiltration or storage of sensitive data (product plan §8).
 *
 * BugSeek must never exfiltrate, store, or transmit sensitive data found during
 * testing (PII, credentials, financial data). Findings reference the
 * vulnerability; they do not reproduce the sensitive data itself.
 *
 * EVERY finding is passed through `redactEvidence()` before persistence,
 * both for agent-produced findings and for findings submitted by the extension
 * via POST /api/scans/:id/findings. Evidence snippets are truncated so a
 * partial match can never leak a full secret.
 */

interface RedactionPattern {
  kind: string;
  re: RegExp;
}

const PATTERNS: RedactionPattern[] = [
  { kind: 'aws-key', re: /AKIA[0-9A-Z]{16}/g },
  { kind: 'private-key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,200}?-----END [A-Z ]*PRIVATE KEY-----/g },
  { kind: 'bearer-token', re: /bearer\s+[A-Za-z0-9\-._~+/=]{16,}/gi },
  { kind: 'jwt', re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { kind: 'api-key', re: /\b(sk|pk|rk|whsec)_(live|test)_[A-Za-z0-9]{16,}/g },
  { kind: 'generic-secret', re: /(?<=(password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret)\s*["':=]\s*["']?)[^"'&\s;]{8,}/gi },
  { kind: 'card-number', re: /\b(?:\d[ -]*?){13,19}\b/g },
  { kind: 'email', re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { kind: 'phone', re: /(?<!\d)(\+?\d[\d -]{7,}\d)(?!\d)/g },
];

export const MAX_EVIDENCE_LENGTH = 500;

/**
 * BugSeek's own benign canary tokens (`bs` + 16 hex chars, see
 * multiagent/depthLadder.ts `generateCanary`). They are markers, never
 * secrets, ours, safe to show, and the verbatim receipt check depends
 * on them surviving redaction: for XSS the canary reflected in bound
 * proof IS the receipt.
 */
const CANARY_RE = /\bbs[0-9a-f]{16}\b/g;

/**
 * Mask secrets/PII in a free-text snippet and truncate it. Idempotent.
 *
 * Canaries are lifted out before the patterns run and restored after:
 * a canary's digit runs otherwise match the phone / card-number
 * patterns and get mangled (e.g. `bs6a12ded794735159` → 
 * `bs6a12ded[REDACTED:phone]`), which breaks the receipt check
 * non-deterministically, only canaries whose hex happens to contain a
 * long digit run are hit, so the failure looks flaky when it is not.
 */
export function redactText(input: string, maxLength: number = MAX_EVIDENCE_LENGTH): string {
  const canaries: string[] = [];
  let out = input.replace(CANARY_RE, (m) => {
    canaries.push(m);
    return `\u0000CANARY${canaries.length - 1}\u0000`;
  });
  for (const p of PATTERNS) {
    out = out.replace(p.re, `[REDACTED:${p.kind}]`);
  }
  if (canaries.length > 0) {
    // The NUL delimiters are part of the match: a literal "CANARY5" in
    // the original text must never be mistaken for a placeholder.
    out = out.replace(/\u0000CANARY(\d+)\u0000/g, (_, i) => canaries[Number(i)] ?? '');
  }
  if (out.length > maxLength) {
    out = out.slice(0, maxLength) + '…[truncated]';
  }
  return out;
}

/**
 * Sanitize a finding's free-text fields before persistence.
 * Evidence, location, title AND description are scrubbed: LLM-written text
 * can echo secrets (e.g. quoting a leaked key in a description), and the
 * module's contract is that EVERY finding is redacted before storage.
 * Returns a redacted copy; never mutates the input.
 */
export function redactFindingEvidence<T extends { evidence?: string; location?: string }>(
  finding: T
): T {
  const out: Record<string, unknown> = {
    ...finding,
    evidence: finding.evidence ? redactText(finding.evidence) : finding.evidence,
    location: finding.location ? redactText(finding.location, 300) : finding.location,
  };
  // Free-text fields that LLMs (or extension clients) fill in, scrub too.
  for (const key of ['title', 'description', 'remediation', 'suggestedFix', 'note'] as const) {
    const v = (finding as Record<string, unknown>)[key];
    if (typeof v === 'string' && v) {
      out[key] = redactText(v, key === 'title' ? 300 : 5000);
    }
  }
  return out as T;
}

/** Drop Set-Cookie values / Authorization headers from logged header maps. */
export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    const lk = k.toLowerCase();
    if (lk === 'set-cookie' || lk === 'cookie' || lk === 'authorization' || lk === 'proxy-authorization') {
      out[k] = '[REDACTED]';
    } else {
      out[k] = v;
    }
  }
  return out;
}

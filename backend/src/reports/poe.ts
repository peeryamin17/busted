import type { DepthEvidence, FindingVerification } from '../types.js';

/**
 * POE (proof-of-exploitation) levels 0-4, the credibility core of a
 * finding. A finding must EARN "verified": the level is derived only from
 * what the depth ladder actually observed, never from a model guess, and
 * the top level is never assigned by code at all.
 *
 *   0, unverified claim: no live proof (ladder unproven, or no
 *       verification recorded at all).
 *   1, error/timing variation only. Reserved for that signal; the depth
 *       ladder's confirm rung always demonstrates structural reproduction,
 *       so no ladder outcome maps to 1 today. Kept in the scale so a
 *       future error/timing-only prober has a level to land on.
 *   2, structural manipulation reproduced: a benign canary was reflected
 *       / echoed / shape-matched in a single context (ladder "confirmed",
 *       or "escalated" with no cross-context evidence).
 *   3, actual data extracted / cross-context reproduction: escalation
 *       evidence shows data was returned or a second independent context
 *       reproduced the behaviour. L3 is the minimum for "verified".
 *   4, critical impact (admin credentials, code execution, data theft).
 *       NEVER auto-assigned by code: only a human reviewer may assign it.
 *       The ladder's probes are read-only and benign-canary by
 *       construction, so they cannot, by design, prove critical impact;
 *       letting code claim L4 would be exactly the false confidence the
 *       fake-100 bug taught us to refuse.
 *
 * This module reimplements the *rule* (POE ≥ 3 + a verbatim quote in bound
 * proof evidence) in BugSeek's own code.
 */

export type PoeLevel = 0 | 1 | 2 | 3 | 4;

/** Minimum length of an evidence quote for the receipt check. */
export const MIN_QUOTE_LENGTH = 8;

/** Max quotes extracted from one finding's evidence (bounded output). */
export const MAX_QUOTES = 10;

/**
 * Escalation evidence kinds that prove data was returned or a second
 * independent context reproduced the behaviour, i.e. the ladder's
 * "escalated" depth is backed by cross-context proof, not just a second
 * probe of the same shape. These are the exact `kind` strings the depth
 * ladder records in DepthEvidence (see multiagent/depthLadder.ts).
 */
export const DATA_ESCALATION_KINDS: ReadonlySet<string> = new Set([
  'graphql-introspection', // read-only introspection returned the schema
  'cors-credentialed-read', // credentialed cross-origin GET returned data
  'idor-second-neighbor-shape', // a second neighbour record matched by shape
  'xss-second-context', // canary reflected via a second parameter/context
]);

export interface PoeResult {
  poe: PoeLevel;
  rationale: string;
}

/**
 * Map a finding's depth-ladder verification to a POE level.
 *
 * - no verification / depth 'unproven' → 0
 * - depth 'confirmed' → 2 (single-context reproduction)
 * - depth 'escalated' → 3 ONLY when an escalation evidence kind shows
 *   data or a second context; escalated without such a kind → 2
 * - 4 is never returned: see the module comment above.
 *
 * `evidenceKinds` optionally overrides the kinds read from
 * `finding.verification.evidence` (the coordinator passes the kinds of
 * the evidence actually bound to snapshots when they differ from the
 * ladder's in-memory list). When omitted, kinds come from the finding.
 */
export function assignPoe(
  finding: { verification?: FindingVerification },
  evidenceKinds?: string[],
): PoeResult {
  const v = finding.verification;
  if (!v) {
    return {
      poe: 0,
      rationale:
        'No depth-ladder verification recorded — the claim has no live proof.',
    };
  }
  if (v.depth === 'unproven') {
    return {
      poe: 0,
      rationale:
        'Ladder depth unproven: the claimed vulnerability could not be reproduced with a benign canary probe.',
    };
  }
  if (v.depth === 'confirmed') {
    return {
      poe: 2,
      rationale:
        'Ladder depth confirmed: a benign canary reproduced the behaviour in a single context (structural manipulation, no cross-context proof).',
    };
  }
  // Escalated: L3 only with a data/second-context evidence kind.
  const kinds =
    evidenceKinds ?? v.evidence.map((e) => e.kind);
  const dataKind = kinds.find((k) => DATA_ESCALATION_KINDS.has(k));
  if (dataKind) {
    return {
      poe: 3,
      rationale: `Ladder depth escalated with cross-context proof (${dataKind}): data was returned or a second independent context reproduced the behaviour.`,
    };
  }
  return {
    poe: 2,
    rationale:
      'Ladder depth escalated, but no escalation evidence kind shows data returned or a second independent context — treated as single-context reproduction (POE 2).',
  };
}

/**
 * Pull quoted substrings (text inside double quotes in the `observed`
 * field of each evidence entry) of at least MIN_QUOTE_LENGTH characters,
 * deduped in first-seen order, capped at MAX_QUOTES. Quotes shorter than
 * the minimum are ignored, a 3-character fragment is not a receipt.
 */
export function extractQuotes(evidence: DepthEvidence[]): string[] {
  const seen = new Set<string>();
  const quotes: string[] = [];
  for (const entry of evidence) {
    const matches = entry.observed.matchAll(/"([^"]+)"/g);
    for (const m of matches) {
      const quote = m[1];
      if (quote.length < MIN_QUOTE_LENGTH) continue;
      if (seen.has(quote)) continue;
      seen.add(quote);
      quotes.push(quote);
      if (quotes.length >= MAX_QUOTES) return quotes;
    }
  }
  return quotes;
}

export interface ReceiptResult {
  pass: boolean;
  matchedQuote?: string;
}

/**
 * The receipt check: pass iff at least one quote appears VERBATIM (exact
 * substring) in at least one proof body. An empty quotes list always
 * fails — there is no receipt without a quote to match.
 */
export function receiptCheck(
  quotes: string[],
  proofBodies: string[],
): ReceiptResult {
  if (quotes.length === 0 || proofBodies.length === 0) {
    return { pass: false };
  }
  for (const quote of quotes) {
    for (const body of proofBodies) {
      if (body.includes(quote)) {
        return { pass: true, matchedQuote: quote };
      }
    }
  }
  return { pass: false };
}

export interface VerifiedResult {
  verified: boolean;
  poe: PoeLevel;
  receipt: boolean;
  reason: string;
}

/**
 * A finding is "verified" only when ALL three hold:
 *   1. POE >= 3 (cross-context proof, the ladder's escalated depth with
 *      a data/second-context evidence kind),
 *   2. the receipt check passes (a verbatim evidence quote appears in a
 *      bound proof body),
 *   3. the ladder itself marked the finding 'verified'.
 *
 * `proofBodies` are the bodies of the bound proof/verification evidence
 * snapshots for this finding (see evidence/snapshots.ts), the live text
 * the quote must appear in verbatim.
 */
export function isVerified(
  finding: { verification?: FindingVerification },
  proofBodies: string[],
): VerifiedResult {
  const { poe, rationale } = assignPoe(finding);
  const v = finding.verification;
  const quotes = v ? extractQuotes(v.evidence) : [];
  const receipt = receiptCheck(quotes, proofBodies);
  const statusOk = v?.status === 'verified';

  if (poe >= 3 && receipt.pass && statusOk) {
    return {
      verified: true,
      poe,
      receipt: true,
      reason:
        `Verified: POE ${poe} — ${rationale} Receipt check passed on quote ` +
        `"${receipt.matchedQuote}".`,
    };
  }
  const failures: string[] = [];
  if (poe < 3) failures.push(`POE ${poe} is below 3 (${rationale})`);
  if (!receipt.pass) {
    failures.push(
      quotes.length === 0
        ? 'no evidence quote of 8+ characters to check a receipt against'
        : 'no evidence quote appears verbatim in any bound proof body',
    );
  }
  if (!statusOk) {
    failures.push(
      v
        ? `ladder status is '${v.status}', not 'verified'`
        : 'no ladder verification recorded',
    );
  }
  return {
    verified: false,
    poe,
    receipt: receipt.pass,
    reason: `Not verified: ${failures.join('; ')}.`,
  };
}

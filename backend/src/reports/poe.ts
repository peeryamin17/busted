import type { DepthEvidence, FindingVerification, VerificationStatus } from '../types.js';

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

/**
 * Three-valued oracle verdict: what the proof gate actually knows.
 * 'inconclusive' is the zero value. No proof, a probe error, or a
 * receipt miss all land here, never a pass or a fail: a probe error
 * can neither confirm nor condemn a finding. 'refuted' needs positive
 * evidence the proof no longer reproduces (a clean re-run that fails),
 * never a missing or errored probe. OOB never disproves: when the OOB
 * oracle lands, an absent callback is inconclusive, not refuted.
 */
export type OracleVerdict = 'confirmed' | 'inconclusive' | 'refuted';

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
  'differential-sqli-second-context', // boolean SQLi signal via a second parameter
  'differential-ssti-second-context', // SSTI signal via a second parameter
  'timing-second-context', // timing signal via a second parameter, latency scaling with delay
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
 * One bound proof observation: a single probe response, as the receipt
 * check searches it. `body` is the (redacted) response body; `status` and
 * `headers` carry what the body alone cannot prove (a CORS echo lives in
 * `access-control-allow-origin`, not in the body); `shape` is the list of
 * top-level JSON field names observed in the response, in observed order
 * (for IDOR/GraphQL: the exact field names of the returned object,
 * values are never recorded, only the names).
 *
 * Headers stored here must already be redacted (see
 * guardrails/redact.ts `redactHeaders`): the receipt check renders them
 * verbatim into the canonical proof text.
 */
export interface ProofRecord {
  label: string;
  url: string;
  status?: number;
  headers?: Record<string, string>;
  body: string;
  shape?: string[];
}

/**
 * The single canonical rendering of a proof record, the ONLY surface the
 * receipt check searches. Deterministic: header lines are sorted by
 * (lowercased) name, so the same record always renders the same text.
 * Shape renders as one `FIELDS` line (omitted when no field names were
 * observed).
 */
export function canonicalProofText(record: ProofRecord): string {
  const lines: string[] = [];
  if (record.status !== undefined) lines.push(`STATUS ${record.status}`);
  const headers = record.headers ?? {};
  for (const name of Object.keys(headers).sort()) {
    lines.push(`HEADER ${name.toLowerCase()}: ${headers[name]}`);
  }
  lines.push(record.body);
  if (record.shape && record.shape.length > 0) {
    // Comma-space join: the field list renders exactly as the ladder
    // records it in evidence prose ("id, name, email"), so a quoted
    // field list from evidence can receipt against this line verbatim.
    lines.push(`FIELDS ${record.shape.join(', ')}`);
  }
  return lines.join('\n');
}

/**
 * The receipt check over proof records: pass iff at least one quote
 * appears VERBATIM (exact substring) in at least one record's canonical
 * proof text. Same rules as the body-only check, an empty quotes list
 * or an empty records list always fails; there is no receipt without a
 * quote to match or proof to match it against.
 */
export function receiptCheckRecords(
  quotes: string[],
  records: ProofRecord[],
): ReceiptResult {
  if (quotes.length === 0 || records.length === 0) {
    return { pass: false };
  }
  for (const quote of quotes) {
    for (const record of records) {
      if (canonicalProofText(record).includes(quote)) {
        return { pass: true, matchedQuote: quote };
      }
    }
  }
  return { pass: false };
}

/**
 * The receipt check: pass iff at least one quote appears VERBATIM (exact
 * substring) in at least one proof body. An empty quotes list always
 * fails, there is no receipt without a quote to match. This is the
 * body-only special case of `receiptCheckRecords`: a body with no
 * status, headers or shape renders as just the body, so the two checks
 * agree exactly.
 */
export function receiptCheck(
  quotes: string[],
  proofBodies: string[],
): ReceiptResult {
  return receiptCheckRecords(
    quotes,
    proofBodies.map((body) => ({ label: '', url: '', body })),
  );
}

export interface ShapeReceiptResult {
  pass: boolean;
  matchedFields: string[];
}

/**
 * The shape receipt: pass iff EVERY expected field name appears EXACTLY
 * (case-sensitive, whole-field equality, not a substring, not a prefix)
 * in at least one record's `shape` list. A record with field
 * `identity` does NOT satisfy an expected field `id`. An empty expected
 * list always fails, a shape receipt needs a field set to check.
 *
 * This is the receipt for IDOR (a neighbour record's field names) and
 * GraphQL (schema field names): the "quote" is the field set, and the
 * check is exact membership, not fuzzy matching.
 */
export function shapeReceiptCheck(
  expectedFields: string[],
  records: ProofRecord[],
): ShapeReceiptResult {
  const observed = new Set<string>();
  for (const record of records) {
    for (const field of record.shape ?? []) observed.add(field);
  }
  const matchedFields = expectedFields.filter((f) => observed.has(f));
  return {
    pass:
      expectedFields.length > 0 &&
      matchedFields.length === expectedFields.length,
    matchedFields,
  };
}

export interface VerifiedResult {
  verified: boolean;
  verdict: OracleVerdict;
  poe: PoeLevel;
  receipt: boolean;
  reason: string;
}

/** Collapse the gate outcome to the three-valued verdict. */
function toVerdict(verified: boolean, status?: VerificationStatus): OracleVerdict {
  if (verified) return 'confirmed';
  if (status === 'fixed') return 'refuted';
  return 'inconclusive';
}

/**
 * A finding is "verified" only when ALL three hold:
 *   1. POE >= 3 (cross-context proof, the ladder's escalated depth with
 *      a data/second-context evidence kind),
 *   2. the receipt check passes (a verbatim evidence quote appears in
 *      bound proof),
 *   3. the ladder itself marked the finding 'verified'.
 *
 * `proofBodies` are the bodies of the bound proof/verification evidence
 * snapshots for this finding (see evidence/snapshots.ts), the live text
 * the quote must appear in verbatim. When `proofRecords` is supplied,
 * the receipt is checked against the records' canonical proof text
 * instead (headers + shape included, the only surface that can prove a
 * CORS echo or an IDOR/GraphQL field set); when omitted, behaviour is
 * exactly the body-only check. The verdict is three-valued: confirmed
 * only when verified, refuted only for a 'fixed' finding, inconclusive
 * for every other failure (including a probe error or a receipt miss).
 */
export function isVerified(
  finding: { verification?: FindingVerification },
  proofBodies: string[],
  proofRecords?: ProofRecord[],
): VerifiedResult {
  const { poe, rationale } = assignPoe(finding);
  const v = finding.verification;
  // The canary itself is a receipt quote: a benign canary reflected
  // verbatim in bound proof is the proof for XSS, where the evidence
  // carries no double-quoted strings. (head gate did this
  // explicitly; the records gate must not drop it.)
  const quotes = v
    ? [...extractQuotes(v.evidence), ...(v.canaryToken ? [v.canaryToken] : [])]
    : [];
  const receipt =
    proofRecords !== undefined
      ? receiptCheckRecords(quotes, proofRecords)
      : receiptCheck(quotes, proofBodies);
  const statusOk = v?.status === 'verified';

  if (poe >= 3 && receipt.pass && statusOk) {
    return {
      verified: true,
      verdict: 'confirmed',
      poe,
      receipt: true,
      reason:
        `Verified: POE ${poe} — ${rationale} Receipt check passed on quote ` +
        `"${receipt.matchedQuote}"` +
        (proofRecords !== undefined
          ? ' in a bound proof record.'
          : ' in a bound proof body.'),
    };
  }
  const failures: string[] = [];
  if (poe < 3) failures.push(`POE ${poe} is below 3 (${rationale})`);
  if (!receipt.pass) {
    failures.push(
      quotes.length === 0
        ? 'no evidence quote of 8+ characters to check a receipt against'
        : proofRecords !== undefined
          ? 'no evidence quote appears verbatim in any bound proof record'
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
    verdict: toVerdict(false, v?.status),
    poe,
    receipt: receipt.pass,
    reason: `Not verified: ${failures.join('; ')}.`,
  };
}

/**
 * The records version of `isVerified`: POE ≥ 3 AND a verbatim quote in a
 * bound proof record AND ladder status 'verified', plus, when
 * `expectedFields` is given, the shape receipt must ALSO pass (every
 * expected field name exactly present in some record's shape). The
 * reason names which surface passed, so a held-as-hint finding says
 * exactly what was missing. The verdict is three-valued: confirmed only
 * when verified, refuted only for a 'fixed' finding, inconclusive for
 * every other failure (including a probe error or a receipt miss).
 */
export function verifyWithRecords(
  finding: { verification?: FindingVerification },
  records: ProofRecord[],
  expectedFields?: string[],
): VerifiedResult {
  const { poe, rationale } = assignPoe(finding);
  const v = finding.verification;
  // Same canary-as-quote rule as isVerified above: the canary reflected
  // verbatim is the receipt for XSS.
  const quotes = v
    ? [...extractQuotes(v.evidence), ...(v.canaryToken ? [v.canaryToken] : [])]
    : [];
  const receipt = receiptCheckRecords(quotes, records);
  const shape =
    expectedFields !== undefined
      ? shapeReceiptCheck(expectedFields, records)
      : null;
  const statusOk = v?.status === 'verified';

  if (poe >= 3 && receipt.pass && (shape === null || shape.pass) && statusOk) {
    const surfaces = [`verbatim quote "${receipt.matchedQuote}" in a bound proof record`];
    if (shape !== null) {
      surfaces.push(`shape receipt for fields ${shape.matchedFields.join(', ')}`);
    }
    return {
      verified: true,
      verdict: 'confirmed',
      poe,
      receipt: true,
      reason:
        `Verified: POE ${poe} — ${rationale} Receipt passed on ` +
        `${surfaces.join(' and ')}.`,
    };
  }
  const failures: string[] = [];
  if (poe < 3) failures.push(`POE ${poe} is below 3 (${rationale})`);
  if (!receipt.pass) {
    failures.push(
      quotes.length === 0
        ? 'no evidence quote of 8+ characters to check a receipt against'
        : 'no evidence quote appears verbatim in any bound proof record',
    );
  }
  if (shape !== null && !shape.pass) {
    const missing = (expectedFields ?? []).filter(
      (f) => !shape.matchedFields.includes(f),
    );
    failures.push(
      `shape receipt failed: expected field(s) ${missing.join(', ')} not observed exactly in any bound proof record`,
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
    verdict: toVerdict(false, v?.status),
    poe,
    receipt: receipt.pass,
    reason: `Not verified: ${failures.join('; ')}.`,
  };
}

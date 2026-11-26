import type { OracleVerdict } from '../reports/poe.js';

// Differential-response oracle: an attack request vs a control request
// over the same endpoint, compared after payload normalisation. A
// difference after normalisation means the payload changed server
// behaviour, not that an id or timestamp rotated.
//
// Canary shapes only. Every producer below emits an inert payload:
// boolean SQLi compares two truth values (no data extraction, no
// stacked queries), SSTI evaluates one arithmetic expression (no
// template breakout, no code execution), XSS echoes one unique marker
// (no script execution). Anything else is refused before sending.

export type DifferentialKind = 'sqli-boolean' | 'ssti' | 'xss-marker';

/** Token-Jaccard similarity at or above this means no signal. */
export const SIMILARITY_THRESHOLD = 0.95;

export interface CanaryPair {
  kind: DifferentialKind;
  control: string;
  attack: string;
  /** Expected evaluated result for SSTI, the marker for XSS, else null. */
  expectedSignal: string | null;
}

export function buildCanaryPair(kind: DifferentialKind, canary: string): CanaryPair {
  if (kind === 'sqli-boolean') {
    return { kind, control: '1 AND 1=1', attack: '1 AND 1=2', expectedSignal: null };
  }
  if (kind === 'ssti') {
    return { kind, control: '7*7', attack: '{{7*7}}', expectedSignal: '49' };
  }
  return { kind, control: 'plainmarker', attack: canary, expectedSignal: canary };
}

// Payloads that must never be sent: data extraction, mutation, stacked
// queries, template breakout, code execution, script execution.
const FORBIDDEN_PAYLOAD_RE =
  /\b(union|select|insert|update|delete|drop|alter|create|truncate|exec|execute|into|from|where)\b|;|--|[/][*]|[*][/]|\b(alert|eval|fetch|XMLHttpRequest)\s*\(|document\.|window\.|on\w+\s*=|<script|__class__|__subclasses__|config\b|self\.|os\.|subprocess|import\s+\w|request\.|{{[^}]*[._a-zA-Z][^}]*[a-zA-Z][^}]*}}/i;

// A BOLA-shaped target: a path naming another user's object. The oracle
// never probes those, it refuses them.
const BOLA_PATH_RE = /\/(users?|accounts?|orders?|profiles?|customers?|invoices?)\/\d+/i;
const BOLA_PARAM_RE = /(^|[?&])(userId|user_id|objectId|object_id|ownerId)=\d+/i;

export function isForbiddenPayload(payload: string): boolean {
  // SSTI arithmetic is the one {{ }} shape allowed, and only exactly that.
  if (payload === '{{7*7}}') return false;
  return FORBIDDEN_PAYLOAD_RE.test(payload);
}

export function isBolaShapedUrl(url: string): boolean {
  return BOLA_PATH_RE.test(url) || BOLA_PARAM_RE.test(url);
}

export interface OracleInputCheck {
  allowed: boolean;
  reason?: string;
}

/** Guardrail gate: refuse BOLA targets and forbidden payloads, never probe them. */
export function checkOracleInput(url: string, payloads: string[]): OracleInputCheck {
  if (isBolaShapedUrl(url)) {
    return { allowed: false, reason: 'BOLA-shaped target (another user object id) — refused, not probed' };
  }
  for (const p of payloads) {
    if (isForbiddenPayload(p)) {
      return { allowed: false, reason: `forbidden payload refused before sending: ${p.slice(0, 80)}` };
    }
  }
  return { allowed: true };
}

// Normalisation: strip volatile values that rotate between requests so
// they cannot count as a behavioural difference.
const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const ISO_TS_RE = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?/g;
const EPOCH_RE = /\b(1[6-9]\d{8}|1[6-9]\d{11})\b/g;
const LONG_HEX_RE = /\b[0-9a-f]{16,}\b/gi;
const VOLATILE_KV_RE =
  /("(?:requestId|request_id|traceId|trace_id|csrf|_csrf|xsrf|sessionId|session_id|token|nonce)"\s*:\s*")[^"]*(")/gi;

export function normalizeResponse(body: string, stripValues: string[] = []): string {
  let out = body;
  for (const v of stripValues) {
    if (v) out = out.split(v).join('');
  }
  out = out
    .replace(UUID_RE, '')
    .replace(ISO_TS_RE, '')
    .replace(EPOCH_RE, '')
    .replace(LONG_HEX_RE, '')
    .replace(VOLATILE_KV_RE, '$1$2');
  return out;
}

export function tokenize(normalized: string): Set<string> {
  const tokens = normalized
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 0);
  return new Set(tokens);
}

export function jaccardSimilarity(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 1;
  let shared = 0;
  for (const t of a) if (b.has(t)) shared += 1;
  return shared / (a.size + b.size - shared);
}

export interface DifferentialComparison {
  similarity: number;
  signal: boolean;
  verdict: OracleVerdict;
  reason: string;
}

/**
 * Compare a control response against an attack response. Both payload
 * strings are stripped from both bodies first, so a server that merely
 * echoes its input cannot produce a signal, and a canary that appears
 * in both responses cannot count as a difference either. Similarity at
 * or above 0.95 is inconclusive (no signal), never a confirmation. A
 * probe error is handled by the caller and also lands inconclusive.
 */
export function compareResponses(
  controlBody: string,
  attackBody: string,
  controlPayload: string,
  attackPayload: string,
): DifferentialComparison {
  const strip = [controlPayload, attackPayload];
  const control = tokenize(normalizeResponse(controlBody, strip));
  const attack = tokenize(normalizeResponse(attackBody, strip));
  const similarity = jaccardSimilarity(control, attack);
  if (similarity >= SIMILARITY_THRESHOLD) {
    return {
      similarity,
      signal: false,
      verdict: 'inconclusive',
      reason: `responses identical after normalisation (Jaccard ${similarity.toFixed(3)} >= ${SIMILARITY_THRESHOLD}) — no signal`,
    };
  }
  return {
    similarity,
    signal: true,
    verdict: 'confirmed',
    reason: `responses differ after normalisation (Jaccard ${similarity.toFixed(3)} < ${SIMILARITY_THRESHOLD}) — payload changed server behaviour`,
  };
}

/**
 * Per-kind signal check on top of the Jaccard comparison. SSTI: the
 * evaluated result (49) appears in the attack response but the raw
 * expression does not. XSS marker: the canary appears in the attack
 * response and not in the control. SQLi has no extra signal, the
 * Jaccard comparison is the whole verdict.
 */
export function kindSignal(
  kind: DifferentialKind,
  pair: CanaryPair,
  controlBody: string,
  attackBody: string,
): boolean {
  if (kind === 'ssti') {
    return attackBody.includes('49') && !attackBody.includes('{{7*7}}');
  }
  if (kind === 'xss-marker') {
    return attackBody.includes(pair.attack) && !controlBody.includes(pair.attack);
  }
  return false;
}

export interface DifferentialOutcome extends DifferentialComparison {
  kindSignal: boolean;
}

/** Full verdict for one control/attack pair: Jaccard or kind signal. */
export function evaluatePair(
  kind: DifferentialKind,
  pair: CanaryPair,
  controlBody: string,
  attackBody: string,
): DifferentialOutcome {
  const compared = compareResponses(controlBody, attackBody, pair.control, pair.attack);
  const signal = kindSignal(kind, pair, controlBody, attackBody);
  if (signal && compared.verdict !== 'confirmed') {
    return {
      ...compared,
      signal: true,
      verdict: 'confirmed',
      kindSignal: true,
      reason: `kind signal observed (${kind}): ${
        kind === 'ssti' ? 'arithmetic result 49 in attack response, raw expression absent' : 'canary marker in attack response, absent in control'
      }`,
    };
  }
  return { ...compared, kindSignal: signal };
}

/**
 * Deterministic risk score (0-100) for a proposed action, used to rank
 * approval requests next to the judge verdict. Pure function: no LLM,
 * no I/O, no randomness.
 *
 * Design: an additive score from explicit weights, plus floors for the
 * cases that must never look safe. Every weight is >= 0 and every floor
 * is a max(), so adding a risk factor can never lower the score
 * (monotonicity), and the result is always clamped to 0-100.
 *
 * Band thresholds: low < 30, medium 30-59, high 60-79, critical >= 80.
 */

export type ActionClass =
  | 'read-only-fetch'
  | 'form-submit'
  | 'auth-probe'
  | 'graphql-query'
  | 'code-intake'
  | 'brute-force-canary'
  | 'destructive'
  | 'other';

export type ScopePosition = 'primary' | 'subdomain' | 'edge' | 'out-of-scope';

export interface RiskInput {
  /** What kind of action is proposed. Unknown classes score as 'other'. */
  actionClass: ActionClass | string;
  /** Full URL being touched, if any, used to infer auth endpoints. */
  url?: string;
  /** Hostname of the primary authorised target, for host comparison. */
  targetHost?: string;
  /** Hostname the action touches, if different from the target. */
  host?: string;
  /** Where the target sits relative to the authorised scope. */
  scopePosition?: ScopePosition;
  /** True when the URL is an auth/login/admin/session endpoint. */
  isAuthEndpoint?: boolean;
  /** True when the action sends, reads or replays credentials/session data. */
  touchesCredentials?: boolean;
  /** True when the host is newly discovered and not pinned as a target. */
  isNewHost?: boolean;
  /** True when the action mutates server state (writes, deletes, submits). */
  mutates?: boolean;
}

export type RiskBand = 'low' | 'medium' | 'high' | 'critical';

export interface RiskResult {
  score: number;
  band: RiskBand;
  /** Human-readable factors that produced the score (shown in the UI). */
  reasons: string[];
}

/**
 * Base score per action class, the inherent risk of the action itself,
 * before target or scope are considered.
 * - read-only fetch: 10, a plain GET that changes nothing.
 * - graphql-query: 20, read-only, but queries can reach deep resolvers.
 * - code-intake: 30, uploads code for analysis; no live request, but
 *   the payload is attacker-shaped input to our own pipeline.
 * - form-submit: 35, a state-changing submit, kept benign-canary sized.
 * - auth-probe: 55, probes the login/session surface by definition.
 * - brute-force-canary: 60, guardrailed canary logins still hammer auth.
 * - destructive: 70, deletes / irreversible writes; floored at 70 below.
 * - other/unknown: 30, unknown actions default to medium, never low.
 */
const BASE_SCORES: Record<string, number> = {
  'read-only-fetch': 10,
  'graphql-query': 20,
  'code-intake': 30,
  'form-submit': 35,
  'auth-probe': 55,
  'brute-force-canary': 60,
  destructive: 70,
  other: 30,
};

/** Extra risk when the target is an auth/login/admin/session endpoint. */
const AUTH_ENDPOINT_WEIGHT = 25;
/** Extra risk when the action touches credentials or session data. */
const CREDENTIALS_WEIGHT = 25;
/** Extra risk when the action mutates server state. */
const MUTATES_WEIGHT = 20;
/** Extra risk for a subdomain of the primary target. */
const SUBDOMAIN_WEIGHT = 10;
/** Extra risk for an edge host (in scope but not the primary target). */
const EDGE_WEIGHT = 20;
/** Extra risk for an unpinned, newly discovered host. */
const NEW_HOST_WEIGHT = 30;
/** Extra risk for anything outside the authorised scope. */
const OUT_OF_SCOPE_WEIGHT = 55;

/** Auth probes and credential-touching actions never score below 70. */
const AUTH_FLOOR = 70;
/** Destructive / mutating actions never score below 70. */
const DESTRUCTIVE_FLOOR = 70;
/** Out-of-scope actions and unpinned new hosts never score below 80. */
const OUT_OF_SCOPE_FLOOR = 80;

const AUTH_PATH_SEGMENTS = [
  'admin',
  'login',
  'signin',
  'sign-in',
  'auth',
  'session',
  'token',
  'oauth',
  'password',
  'reset',
];

function urlLooksLikeAuthEndpoint(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  const haystack = `${parsed.pathname}/${parsed.search}`.toLowerCase();
  return AUTH_PATH_SEGMENTS.some((seg) => haystack.includes(`/${seg}`) || haystack.includes(`${seg}=`));
}

function hostOf(url: string): string | undefined {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

export function bandForScore(score: number): RiskBand {
  if (score < 30) return 'low';
  if (score < 60) return 'medium';
  if (score < 80) return 'high';
  return 'critical';
}

export function riskScore(input: RiskInput): RiskResult {
  const reasons: string[] = [];
  let score = 0;

  // ── Base: the action class ────────────────────────────────────────
  const actionClass = input.actionClass in BASE_SCORES ? input.actionClass : 'other';
  const base = BASE_SCORES[actionClass] ?? BASE_SCORES['other']!;
  score += base;
  reasons.push(
    actionClass === 'read-only-fetch'
      ? 'Read-only fetch — retrieves data without changing server state.'
      : actionClass === 'destructive'
        ? 'Destructive action — deletes data or makes irreversible changes.'
        : actionClass === 'auth-probe'
          ? 'Auth probe — exercises the login/session surface.'
          : actionClass === 'brute-force-canary'
            ? 'Brute-force canary — repeated login attempts, even though guardrailed.'
            : actionClass === 'form-submit'
              ? 'Form submit — sends data that changes server state.'
              : actionClass === 'graphql-query'
                ? 'GraphQL query — read-only, but can reach deep resolvers.'
                : actionClass === 'code-intake'
                  ? 'Code intake — uploads code for analysis.'
                  : 'Unknown action class — scored as medium by default.'
  );

  // ── Target sensitivity ────────────────────────────────────────────
  const url = input.url ?? '';
  const isAuth =
    input.isAuthEndpoint ?? (url ? urlLooksLikeAuthEndpoint(url) : false);
  if (isAuth) {
    score += AUTH_ENDPOINT_WEIGHT;
    reasons.push('Targets an auth/login/admin/session endpoint.');
  }
  if (input.touchesCredentials) {
    score += CREDENTIALS_WEIGHT;
    reasons.push('Touches credentials or session data.');
  }
  if (input.mutates) {
    score += MUTATES_WEIGHT;
    reasons.push('Mutates server state.');
  }

  // ── Scope position ────────────────────────────────────────────────
  let scopePosition = input.scopePosition;
  if (!scopePosition) {
    const host = (input.host ?? (url ? hostOf(url) : undefined) ?? '').toLowerCase();
    const target = (input.targetHost ?? '').toLowerCase();
    if (host && target) {
      if (host === target) scopePosition = 'primary';
      else if (host.endsWith(`.${target}`)) scopePosition = 'subdomain';
      else scopePosition = 'edge';
    } else {
      scopePosition = 'primary';
    }
  }
  if (scopePosition === 'subdomain') {
    score += SUBDOMAIN_WEIGHT;
    reasons.push('Target is a subdomain of the primary host, not the primary host itself.');
  } else if (scopePosition === 'edge') {
    score += EDGE_WEIGHT;
    reasons.push('Target is an edge host — in scope, but not the primary target.');
  } else if (scopePosition === 'out-of-scope') {
    score += OUT_OF_SCOPE_WEIGHT;
    reasons.push('Target is outside the authorised scope.');
  } else {
    reasons.push('Target is the primary in-scope host.');
  }

  // ── New / unpinned host ───────────────────────────────────────────
  if (input.isNewHost) {
    score += NEW_HOST_WEIGHT;
    reasons.push('Target host is newly discovered and not pinned as an authorised target.');
  }

  // ── Floors (max(), never lower the score) ────────────────────────
  if (scopePosition === 'out-of-scope' || input.isNewHost) {
    score = Math.max(score, OUT_OF_SCOPE_FLOOR);
    if (scopePosition === 'out-of-scope' || input.isNewHost) {
      reasons.push('Floored at 80: out-of-scope or unpinned-host actions are always critical.');
    }
  }
  if (actionClass === 'auth-probe' || input.touchesCredentials) {
    score = Math.max(score, AUTH_FLOOR);
    reasons.push('Floored at 70: auth probes and credential-touching actions are always high risk or above.');
  }
  if (actionClass === 'destructive' || input.mutates) {
    score = Math.max(score, DESTRUCTIVE_FLOOR);
    reasons.push('Floored at 70: destructive/mutating actions are always high risk or above.');
  }

  score = Math.min(100, Math.max(0, Math.round(score)));
  return { score, band: bandForScore(score), reasons };
}

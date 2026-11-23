/**
 * Defense verification probes. One question per attack class, for a
 * website owner: did my site notice the attack, block it, log it,
 * alert on it, or was it blind? These verify defenses, they do not
 * attack. Every probe is safe by construction:
 *
 *  - Key exposure: format hints only, from the bloodhound's findings.
 *    No found key is ever validated against a provider API.
 *  - Brute force: at most 5 failed logins with a canary username that
 *    cannot be a real account (`bugseek-canary-<random>@invalid`).
 *  - Exploitation / WAF: benign canary payloads, inert marker strings
 *    sent as data, response read as text only. Never loaded in a tab,
 *    never rendered, never executed. Reflected raw means "let through".
 *  - Request smuggling: conditions only. Fetch cannot set
 *    Transfer-Encoding, so no smuggled request can be built from here.
 *    We check response/header handling for ambiguity and report the
 *    rest as a server-config review. Live smuggling tests belong on
 *    isolated staging, never shared infrastructure.
 *  - Post-exploitation / lateral movement: static mapping only.
 *    Internal and debug endpoints are inventoried with read-only GETs
 *    (status + content type). SSRF and cloud-metadata reachability are
 *    tested only via a canary callback to a BugSeek-owned endpoint,
 *    yes/no, no data fetched. 169.254.169.254 is never requested.
 *    Env vars come from static sources only (error messages, bundles,
 *    source maps), key names only, values never captured. BaaS key scope
 *    is assessed only for the client's own keys, supplied at their
 *    explicit direction.
 *  - OAST: with no listener configured, the SSRF canary is not sent
 *    and the finding says so.
 *
 * Gating: the base authorization record gates the whole module, every
 * request goes through ActiveHttpClient (scope + rate limiting). The
 * brute-force probe additionally needs the `allowAuthProbes` grant.
 * Probes that need a login form are skipped when no form is found.
 *
 * Limits, stated in every finding that touches them: from outside, an
 * extension can observe blocking (status codes, block pages, CAPTCHAs)
 * and sometimes reflection. It cannot observe whether the server logged
 * the attempt or alerted anyone, so "logged" and "alerted" are always
 * "unknown, not observable from outside" unless the client wires in
 * the backend runtime detection layer (backend/src/detection/).
 */
import { scoreFinding } from '../lib/cvss';
import { SECRET_PATTERNS } from '../lib/regexes';
import type { AuthorizationRecord, DomScanData, Finding } from '../lib/types';
import type { ActiveHttpClient } from './httpClient';
import { redactedSnippet } from './httpClient';
import { detectLoginForms } from './authChecker';

/**
 * The OAST listener lives on the backend (backend/src/oast/, scaffolding
 * only until OAST_DOMAIN points at real infrastructure). The extension
 * cannot check that itself, so "configured" here means the coordinator
 * supplied a BugSeek-owned canary URL for this scan. No canary URL means
 * no listener to call back to, and the SSRF probe reports statically.
 */
function oastListenerConfigured(canaryUrl: string | null | undefined): boolean {
  return Boolean(canaryUrl);
}

let findingSeq = 0;

function nextId(): string {
  findingSeq++;
  return `defense-${findingSeq}`;
}

function cvssFields(presetKey: string): Pick<
  Finding, 'cvssScore' | 'cvssVector' | 'cvssJustification' | 'references'
> {
  const s = scoreFinding(presetKey);
  return {
    cvssScore: s.score,
    cvssVector: s.vector,
    cvssJustification: s.justification,
    references: s.references,
  };
}

function randToken(prefix: string): string {
  return `${prefix}${Math.random().toString(36).slice(2, 8)}${Date.now().toString(36).slice(-4)}`;
}const CAPTCHA_HINT_RE = /captcha|recaptcha|challenge|verify you are human/i;
const LOCKOUT_HINT_RE = /locked|too many attempts|try again later|temporarily blocked/i;
const WAF_BLOCK_RE =
  /request blocked|blocked by|access denied|forbidden|not acceptable|waf|cloudflare|akamai|incapsula|imperva|modsecurity|suspicious (request|activity)|security policy/i;

/** One per-class verdict. `logged`/`alerted` are unobservable from outside. */
export type DefenseSignal = 'observed' | 'not-observed' | 'unknown';

export interface DefenseVerdict {
  attackClass:
    | 'key-exposure'
    | 'brute-force'
    | 'exploitation'
    | 'waf-evasion'
    | 'request-smuggling'
    | 'post-exploitation'
    | 'lateral-movement';
  /** Did a defense engage visibly (block / rate-limit / CAPTCHA / 403)? */
  blocked: DefenseSignal;
  /** Did the site visibly react at all (any non-200-normal response)? */
  detected: DefenseSignal;
  /** Not observable from outside, always 'unknown' here. */
  logged: DefenseSignal;
  /** Not observable from outside, always 'unknown' here. */
  alerted: DefenseSignal;
  /** Plain-language summary of what was (and was not) seen. */
  summary: string;
}

export interface DiscoveredEndpointInput {
  path: string;
  status?: number;
  params?: string[];
}

export interface OwnKeySelfCheckInput {
  /** Provider id as the client knows it, e.g. 'stripe', 'supabase'. */
  provider: string;
  /** Redacted fingerprint only, never a key value. */
  fingerprint: string;
  /** Scopes/restrictions the client says the key has, if they know them. */
  declaredScopes?: string[];
}

export interface CapturedResponseInput {
  url: string;
  bodyText: string;
}

export interface DefenseProbeInput {
  /** Bloodhound secret findings (secretScanner / keyTrail output). */
  secretFindings?: Finding[];
  /** Endpoints discovered by apiDiscovery (paths + params). */
  apiEndpoints?: DiscoveredEndpointInput[];
  /** Response bodies already captured during the scan (deep inspect / traffic). */
  responseBodies?: CapturedResponseInput[];
  /**
   * A BugSeek-owned OAST canary URL for the SSRF callback test, supplied
   * by the backend when a listener exists. Omit (or pass null) when there
   * is no listener, the SSRF probe is then reported statically.
   */
  oastCanaryUrl?: string | null;
  /** The client's OWN keys, supplied at their explicit direction, for a scope self-check. */
  ownKeys?: OwnKeySelfCheckInput[];
  /** True when the target is the client's isolated staging (smuggling note). */
  isStaging?: boolean;
}

export interface DefenseProbeResult {
  findings: Finding[];
  verdicts: DefenseVerdict[];
  /** Requests spent by the probes (accountability). */
  requestCount: number;
}

const UNKNOWN_OUTSIDE =
  'Not observable from outside: whether the attempt was logged or raised an alert can only be confirmed from server-side logs or the BugSeek runtime detection layer.';

function baseFinding(partial: Omit<Finding, 'id' | 'category' | 'mode' | 'tags'> & {
  category: Finding['category'];
  tags: string[];
}): Finding {
  return {
    id: nextId(),
    mode: 'active',
    ...partial,
  };
}

/* ------------------------------------------------------------------ */
/* 1. Key exposure, format-hint assessment of bloodhound findings.    */
/* ------------------------------------------------------------------ */

/**
 * Which key types support scoping / short lifetimes, by FORMAT only.
 * This is public provider knowledge, not a live check: nothing here
 * contacts any provider, and no found key is ever used for anything.
 */
const KEY_SCOPE_NOTES: Record<string, { scoping: string; rotation: string }> = {
  'github-token': {
    scoping:
      'GitHub fine-grained PATs support repository/org scoping; classic PATs are account-wide. Format alone cannot tell which kind this is.',
    rotation: 'Revoke at github.com/settings/tokens and reissue with least privilege.',
  },
  'stripe-live-key': {
    scoping:
      'Stripe secret keys are account-wide and cannot be scoped — they must live server-side only. Restricted keys can limit permissions.',
    rotation: 'Roll the key in the Stripe dashboard and replace it with a restricted key.',
  },
  'google-api-key': {
    scoping:
      'Google API keys support HTTP-referrer and per-API restrictions in Cloud Console — a key with no restrictions is fully exposed.',
    rotation: 'Restrict the key, then rotate it.',
  },
  'openai-api-key': {
    scoping:
      'OpenAI keys can be scoped to a project with usage limits; a key with no project scoping bills the whole account.',
    rotation: 'Revoke at platform.openai.com and reissue project-scoped.',
  },
  'aws-access-key': {
    scoping:
      'AWS access keys are scoped by the IAM policy attached to their user/role — the format says nothing about how broad that policy is.',
    rotation: 'Rotate in IAM and audit the attached policy for least privilege.',
  },
  'aws-session-token': {
    scoping:
      'AWS session tokens are temporary by construction — they expire on their own, which bounds the exposure window.',
    rotation: 'Revoke the session that issued the token; the token itself cannot be rotated.',
  },
  jwt: {
    scoping:
      'A JWT is short-lived only if its exp claim says so. This module holds only the redacted fingerprint, never the token, so expiry cannot be checked here.',
    rotation: 'Invalidate server-side (deny-list / key rotation) if the token is live.',
  },
};

const GENERIC_KEY_NOTE = {
  scoping:
    'No provider-specific scoping information is known for this key type from its format alone.',
  rotation: 'Rotate the credential and confirm the new value is never shipped to the browser.',
};

/** Key-type guidance + leak-in-response/source-map checks. No live validation. */
export function assessKeyExposure(input: DefenseProbeInput): {
  findings: Finding[];
  verdict: DefenseVerdict;
} {
  const findings: Finding[] = [];
  const secrets = (input.secretFindings ?? []).filter(
    (f) => f.category === 'secrets' || f.tags?.includes('secret'),
  );

  if (secrets.length === 0) {
    findings.push(baseFinding({
      category: 'secrets',
      tags: ['defense-verification', 'defense-key-exposure'],
      title: 'Key-exposure defense check: no exposed keys found to assess',
      description:
        'The bloodhound found no secrets in the scanned surface, so there is nothing to assess for scoping, rotation, or leak paths. ' +
        'This is a clean result for this scan, not proof no key exists elsewhere.',
      severity: 'info',
      confidence: 'high',
      confirmed: true,
      remediation: 'No action needed for this scan. Re-run after each deploy, since keys leak through new bundles.',
      ...cvssFields('api:endpoint-discovered'),
      requestCount: 0,
    }));
  }

  for (const secret of secrets.slice(0, 5)) {
    const provider = secret.secretProvider ?? 'unknown';
    const note = KEY_SCOPE_NOTES[provider] ?? GENERIC_KEY_NOTE;
    const inSourceMap = /sourcemap|source[ -]?map|\.map\b/i.test(
      `${secret.location ?? ''} ${(secret.trail ?? []).join(' ')}`,
    );
    findings.push(baseFinding({
      category: 'secrets',
      tags: ['defense-verification', 'defense-key-exposure', 'key-scope-review'],
      title:
        `Exposed key (${secret.secretProvider ?? 'unidentified'}) — ` +
        `${inSourceMap ? 'leaking via source map; ' : ''}scope/rotation review (format hints only)`,
      description:
        `Bloodhound finding "${secret.title}" (${secret.fingerprint ?? 'no fingerprint'}). ` +
        `${note.scoping} ${inSourceMap ? 'The key is reachable through a source map, which means it ships to every visitor. ' : ''}` +
        'This assessment is format/context only: the key was NEVER validated against any provider API, so its live status and real permissions are unknown.',
      severity: inSourceMap ? 'high' : secret.severity,
      confidence: 'medium',
      confirmed: false,
      location: secret.location,
      evidence: secret.fingerprint ? `fingerprint: ${secret.fingerprint} (value never stored)` : undefined,
      remediation:
        `${note.rotation} Scope the replacement to the minimum permissions the client needs, set an expiry where the provider supports it, ` +
        'and add a pre-deploy secret scan so the next key never ships.',
      ...cvssFields('secrets:response-body'),
      requestCount: 0,
    }));
  }

  // Keys leaking in error messages / captured responses (static scan of
  // bodies already captured, no new requests, key names / fingerprints only).
  for (const body of input.responseBodies ?? []) {
    for (const pattern of SECRET_PATTERNS) {
      pattern.regex.lastIndex = 0;
      const match = body.bodyText.match(pattern.regex);
      pattern.regex.lastIndex = 0;
      if (!match) continue;
      findings.push(baseFinding({
        category: 'secrets',
        tags: ['defense-verification', 'defense-key-exposure', 'key-in-response'],
        title: `Secret-shaped value in a response body (${pattern.name})`,
        description:
          `A ${pattern.name} pattern matched inside the response from ${body.url}. ` +
          'Keys in responses leak to anyone who can reach the endpoint — including error pages, which are often public. ' +
          'Only the pattern name is reported; the matched value was never copied.',
        severity: pattern.severity,
        confidence: 'medium',
        confirmed: false,
        location: body.url,
        evidence: `pattern: ${pattern.id} (matched value redacted, never stored)`,
        remediation:
          'Stop returning credential material in responses and error pages. Rotate the credential, then strip secrets from error handling and logging.',
        ...cvssFields('secrets:response-body'),
        requestCount: 0,
      }));
      break; // one finding per body is enough, the pattern list is long
    }
  }

  const verdict: DefenseVerdict = {
    attackClass: 'key-exposure',
    blocked: secrets.length === 0 ? 'observed' : 'not-observed',
    detected: secrets.length === 0 ? 'observed' : 'not-observed',
    logged: 'unknown',
    alerted: 'unknown',
    summary:
      secrets.length === 0
        ? 'No exposed keys were found in the scanned surface, so there was nothing for key defenses to catch.'
        : `${secrets.length} exposed key(s) were found in client-reachable code. A key that ships to the browser has already passed every defense — ` +
          `scope and rotation are damage control, not prevention. ${UNKNOWN_OUTSIDE}`,
  };
  return { findings, verdict };
}

/* ------------------------------------------------------------------ */
/* 2. Brute-force defense, ≤5 canary-username failed logins.          */
/* ------------------------------------------------------------------ */

export const MAX_DEFENSE_LOGIN_ATTEMPTS = 5;

export async function probeBruteForceDefense(
  http: ActiveHttpClient,
  authz: AuthorizationRecord,
  tabUrl: string,
  dom: DomScanData,
): Promise<{ findings: Finding[]; verdict: DefenseVerdict; requestCount: number }> {
  const findings: Finding[] = [];
  const noDefenseVerdict = (summary: string): DefenseVerdict => ({
    attackClass: 'brute-force',
    blocked: 'not-observed',
    detected: 'not-observed',
    logged: 'unknown',
    alerted: 'unknown',
    summary,
  });

  if (!authz.allowAuthProbes) {
    findings.push(baseFinding({
      category: 'auth',
      tags: ['defense-verification', 'defense-brute-force', 'defense-probes-skipped'],
      title: 'Brute-force defense check skipped — not authorized',
      description:
        'No login-form testing grant is present in the authorization record, so the canary-login probe was not run. ' +
        'The auth checker reports the same gate for its own probes.',
      severity: 'info',
      confidence: 'high',
      confirmed: true,
      remediation: 'Re-authorize with "allow login-form testing" to enable the check.',
      ...cvssFields('api:endpoint-discovered'),
      requestCount: 0,
    }));
    return {
      findings,
      verdict: {
        attackClass: 'brute-force',
        blocked: 'unknown',
        detected: 'unknown',
        logged: 'unknown',
        alerted: 'unknown',
        summary: 'Skipped: login-form testing was not authorized for this scan.',
      },
      requestCount: 0,
    };
  }

  const forms = detectLoginForms(dom, tabUrl);
  if (forms.length === 0) {
    findings.push(baseFinding({
      category: 'auth',
      tags: ['defense-verification', 'defense-brute-force'],
      title: 'Brute-force defense check not applicable — no login form found',
      description: 'Login-form testing is authorized, but no password form was found on the scanned page.',
      severity: 'info',
      confidence: 'high',
      confirmed: true,
      remediation: 'Point the scanner at the login page directly to test authentication defenses.',
      ...cvssFields('api:endpoint-discovered'),
      requestCount: 0,
    }));
    return {
      findings,
      verdict: {
        attackClass: 'brute-force',
        blocked: 'unknown',
        detected: 'unknown',
        logged: 'unknown',
        alerted: 'unknown',
        summary: 'Not applicable: no login form was found on the scanned page.',
      },
      requestCount: 0,
    };
  }

  const form = forms[0];
  const canaryUser = `bugseek-canary-${randToken('')}@invalid`;
  const engaged: string[] = [];
  let attempts = 0;
  for (let i = 0; i < MAX_DEFENSE_LOGIN_ATTEMPTS; i++) {
    attempts++;
    const body = new URLSearchParams();
    body.set(form.usernameField, canaryUser);
    body.set(form.passwordField, `wrong-password-${randToken('')}`);
    for (const [k, v] of form.extraFields) body.set(k, v);
    try {
      const res = await http.post(form.actionUrl, body.toString());
      if (res.status === 429) engaged.push('HTTP 429 rate limiting');
      if (res.headers['retry-after']) engaged.push('Retry-After header');
      if (CAPTCHA_HINT_RE.test(res.bodyText.slice(0, 4000))) engaged.push('CAPTCHA/challenge presented');
      if (LOCKOUT_HINT_RE.test(res.bodyText.slice(0, 4000))) engaged.push('lockout messaging');
    } catch {
      break;
    }
    if (engaged.length > 0) break; // defense seen, stop, never more than needed
  }

  if (engaged.length > 0) {
    findings.push(baseFinding({
      category: 'auth',
      tags: ['defense-verification', 'defense-brute-force', 'defense-engaged'],
      title: `Brute-force defense engaged (${engaged.join(', ')})`,
      description:
        `${attempts} failed login(s) with the canary account ${canaryUser} triggered: ${engaged.join('; ')}. ` +
        'The canary username cannot be a real account, so no real user was touched. Good posture for this control. ' +
        UNKNOWN_OUTSIDE,
      severity: 'info',
      confidence: 'high',
      confirmed: true,
      location: form.actionUrl,
      evidence: redactedSnippet(engaged.join('; '), 200),
      remediation: 'No action needed. Keep the lockout/CAPTCHA thresholds and monitor failed-login velocity.',
      ...cvssFields('api:endpoint-discovered'),
      requestCount: attempts,
    }));
    return {
      findings,
      verdict: {
        attackClass: 'brute-force',
        blocked: 'observed',
        detected: 'observed',
        logged: 'unknown',
        alerted: 'unknown',
        summary: `Defense engaged after ${attempts} canary failed login(s): ${engaged.join(', ')}. ${UNKNOWN_OUTSIDE}`,
      },
      requestCount: attempts,
    };
  }

  findings.push(baseFinding({
    category: 'auth',
    tags: ['defense-verification', 'defense-brute-force', 'defense-blind'],
    title: 'No brute-force protection observed on login',
    description:
      `${attempts} sequential failed logins with a canary account produced no rate limiting (429), Retry-After, CAPTCHA, or lockout signals. ` +
      'The site appears blind to repeated failed logins. This is a missing-control observation, not an exploited flaw — ' +
      'credential guessing was not attempted beyond these probes. ' +
      UNKNOWN_OUTSIDE,
    severity: 'low',
    confidence: 'medium',
    confirmed: false,
    location: form.actionUrl,
    evidence: `${attempts} failed logins → 200 responses, no throttling signals`,
    remediation:
      'Add progressive delays, account lockout or CAPTCHA after failed attempts, rate limiting on the login endpoint, and alerting on failed-login velocity.',
    ...cvssFields('auth:brute-force-indicators'),
    reproSteps: [
      `Submit ${attempts} failed logins to ${form.actionUrl} with a nonexistent account.`,
      'Observe the absence of 429 / Retry-After / CAPTCHA / lockout responses.',
    ],
    requestCount: attempts,
  }));
  return {
    findings,
    verdict: noDefenseVerdict(
      `${attempts} canary failed logins produced no throttling, CAPTCHA, or lockout signal — the login endpoint looks unprotected. ${UNKNOWN_OUTSIDE}`,
    ),
    requestCount: attempts,
  };
}

/* ------------------------------------------------------------------ */
/* 3. Exploitation defense, benign canary payloads, text-only read.   */
/* ------------------------------------------------------------------ */

interface CanaryProbeOutcome {
  label: string;
  url: string;
  status: number;
  outcome: 'blocked' | 'let-through-raw' | 'let-through-encoded' | 'inconclusive';
  note: string;
}

function classifyCanaryResponse(
  status: number,
  body: string,
  canary: string,
): CanaryProbeOutcome['outcome'] {
  const head = body.slice(0, 4000);
  if (
    status === 403 ||
    status === 406 ||
    status === 501 ||
    (status >= 400 && status < 500 && WAF_BLOCK_RE.test(head))
  ) {
    return 'blocked';
  }
  if (status === 429) return 'blocked'; // rate limiting is also a defense engaging
  if (!body.includes(canary)) return 'let-through-encoded'; // dropped, encoded, or normalised away
  // Reflected verbatim, but check whether it was HTML-encoded.
  const idx = body.indexOf(canary);
  const around = body.slice(Math.max(0, idx - 120), idx + canary.length + 120);
  if (/&lt;|&gt;|&quot;|&#x?[0-9a-f]+;/i.test(around)) return 'let-through-encoded';
  return 'let-through-raw';
}

/** Benign marker payloads: inert canary strings, never executed, never rendered. */
export async function probeExploitationDefense(
  http: ActiveHttpClient,
  tabUrl: string,
): Promise<{ findings: Finding[]; verdict: DefenseVerdict; requestCount: number }> {
  const findings: Finding[] = [];
  const outcomes: CanaryProbeOutcome[] = [];
  let requests = 0;

  const probe = async (label: string, url: string, canary: string) => {
    try {
      requests++;
      const res = await http.get(url);
      const outcome = classifyCanaryResponse(res.status, res.bodyText, canary);
      outcomes.push({
        label,
        url: new URL(url).pathname,
        status: res.status,
        outcome,
        note:
          outcome === 'blocked'
            ? `HTTP ${res.status} / block page — defense engaged`
            : outcome === 'let-through-raw'
              ? `HTTP ${res.status} — marker reflected verbatim (not executed; response read as text only)`
              : outcome === 'let-through-encoded'
                ? `HTTP ${res.status} — marker encoded, dropped, or normalised`
                : `HTTP ${res.status} — inconclusive`,
      });
    } catch {
      outcomes.push({ label, url, status: 0, outcome: 'inconclusive', note: 'request failed' });
    }
  };

  // 1. Plain reflection: unique canary in a query parameter.
  const canary1 = randToken('bsdef');
  const u1 = new URL(tabUrl);
  u1.searchParams.set('bugseek_probe', canary1);
  await probe('reflected input (plain canary)', u1.toString(), canary1);

  // 2. Error-page reflection: canary in a path that 404s.
  const canary2 = randToken('bsdef');
  const u2 = new URL(tabUrl);
  u2.pathname = `${u2.pathname.replace(/\/$/, '')}/bugseek-defense-${canary2}`;
  u2.search = '';
  await probe('error-page reflection (404 path)', u2.toString(), canary2);

  // 3. Suspicious-pattern marker: a classic attack SHAPE carrying only the
  //    inert canary as its content. Sent as data, read as text, never rendered.
  const canary3 = randToken('bsdef');
  const u3 = new URL(tabUrl);
  u3.searchParams.set('bugseek_probe', `<script>${canary3}</script>`);
  await probe('suspicious-pattern marker (script-shaped canary)', u3.toString(), canary3);

  const blocked = outcomes.filter((o) => o.outcome === 'blocked');
  const raw = outcomes.filter((o) => o.outcome === 'let-through-raw');
  const summaryLines = outcomes.map((o) => `${o.label}: ${o.note}`).join(' | ');

  if (raw.length === 0) {
    findings.push(baseFinding({
      category: 'xss',
      tags: ['defense-verification', 'defense-exploitation', 'defense-engaged'],
      title: 'Exploitation canaries contained — no payload class passed through raw',
      description:
        `Benign canary markers were sent in three classes (${outcomes.map((o) => o.label).join('; ')}). ${summaryLines}. ` +
        'Nothing was executed: responses were read as text only and probe URLs were never rendered. ' +
        UNKNOWN_OUTSIDE,
      severity: 'info',
      confidence: 'high',
      confirmed: true,
      location: tabUrl,
      evidence: redactedSnippet(summaryLines, 400),
      remediation: 'No action needed for these classes. Keep output encoding and WAF rules in place.',
      ...cvssFields('xss:review-hint'),
      requestCount: requests,
    }));
  } else {
    findings.push(baseFinding({
      category: 'xss',
      tags: ['defense-verification', 'defense-exploitation', 'defense-blind'],
      title: `${raw.length} canary payload class(es) passed the defenses unencoded`,
      description:
        `Benign canary markers were reflected verbatim in: ${raw.map((o) => o.label).join(', ')}. ` +
        `Full picture — ${summaryLines}. The markers are inert (a random token, no executable content) and were never executed; ` +
        'raw reflection of attacker-controlled input is the condition an exploit needs, so these classes deserve a closer look. ' +
        UNKNOWN_OUTSIDE,
      severity: 'low',
      confidence: 'medium',
      confirmed: false,
      location: tabUrl,
      evidence: redactedSnippet(raw.map((o) => `${o.label} → HTTP ${o.status}`).join('; '), 300),
      remediation:
        'Ensure output encoding / CSP on every reflection point, and add WAF rules for the payload classes that passed through raw.',
      ...cvssFields('xss:review-hint'),
      requestCount: requests,
    }));
  }

  return {
    findings,
    verdict: {
      attackClass: 'exploitation',
      blocked: blocked.length > 0 ? 'observed' : raw.length > 0 ? 'not-observed' : 'unknown',
      detected: blocked.length > 0 || raw.length > 0 ? 'observed' : 'unknown',
      logged: 'unknown',
      alerted: 'unknown',
      summary: `${summaryLines}. ${UNKNOWN_OUTSIDE}`,
    },
    requestCount: requests,
  };
}

/* ------------------------------------------------------------------ */
/* 4. Post-exploitation paths, STATIC mapping, read-only GETs.         */
/* ------------------------------------------------------------------ */

const INTERNAL_PATHS = [
  '/admin',
  '/api/admin',
  '/api/internal',
  '/api/debug',
  '/debug',
  '/actuator',
  '/actuator/env',
  '/api/v1/admin',
] as const;

export async function probePostExploitationExposure(
  http: ActiveHttpClient,
  tabUrl: string,
): Promise<{ findings: Finding[]; verdict: DefenseVerdict; requestCount: number }> {
  const findings: Finding[] = [];
  const origin = new URL(tabUrl).origin;
  const exposed: string[] = [];
  const defended: string[] = [];
  const absent: string[] = [];
  let requests = 0;

  for (const path of INTERNAL_PATHS) {
    try {
      requests++;
      const res = await http.get(`${origin}${path}`);
      if (res.status === 200) exposed.push(`${path} (200, ${res.contentType || 'unknown type'})`);
      else if (res.status === 401 || res.status === 403) defended.push(`${path} (${res.status})`);
      else absent.push(`${path} (${res.status})`);
    } catch {
      absent.push(`${path} (unreachable)`);
    }
  }

  if (exposed.length > 0) {
    findings.push(baseFinding({
      category: 'api',
      tags: ['defense-verification', 'defense-post-exploitation', 'defense-blind'],
      title: `${exposed.length} internal/debug endpoint(s) reachable without authentication`,
      description:
        `Read-only GETs found these internal or debug paths responding 200: ${exposed.join('; ')}. ` +
        'No session was used, no auth was bypassed, and no data was read beyond the status and content type — ' +
        'this is a static exposure map, not a pivot. Anything reachable here is reachable by an attacker who gets one foothold. ' +
        `Defended (401/403): ${defended.length > 0 ? defended.join(', ') : 'none observed'}. ` +
        `Not present: ${absent.length > 0 ? absent.join(', ') : 'none'}.`,
      severity: 'medium',
      confidence: 'medium',
      confirmed: true,
      location: origin,
      evidence: redactedSnippet(exposed.join('; '), 300),
      remediation:
        'Put internal/debug endpoints behind authentication and network restrictions (allow-list, VPN, or removal from production). ' +
        'Actuator/env endpoints must never be internet-reachable.',
      ...cvssFields('api:sensitive-endpoint'),
      requestCount: requests,
    }));
  } else {
    findings.push(baseFinding({
      category: 'api',
      tags: ['defense-verification', 'defense-post-exploitation', 'defense-engaged'],
      title: 'No internal/debug endpoints reachable — post-exploitation surface looks closed',
      description:
        `Read-only GETs to ${INTERNAL_PATHS.length} internal/debug paths returned no 200s. ` +
        `Defended (401/403): ${defended.length > 0 ? defended.join(', ') : 'none'}. ` +
        `Not present: ${absent.join(', ')}. This maps the front door only — internal network topology was not probed.`,
      severity: 'info',
      confidence: 'medium',
      confirmed: true,
      location: origin,
      remediation: 'No action needed. Keep internal endpoints off the public surface.',
      ...cvssFields('api:endpoint-discovered'),
      requestCount: requests,
    }));
  }

  return {
    findings,
    verdict: {
      attackClass: 'post-exploitation',
      blocked: exposed.length === 0 ? 'observed' : 'not-observed',
      detected: exposed.length === 0 ? 'observed' : 'not-observed',
      logged: 'unknown',
      alerted: 'unknown',
      summary:
        exposed.length === 0
          ? 'No internal/debug endpoint answered 200 to an unauthenticated read-only GET.'
          : `${exposed.length} internal/debug path(s) are reachable unauthenticated: ${exposed.join('; ')}. ${UNKNOWN_OUTSIDE}`,
    },
    requestCount: requests,
  };
}

/* ------------------------------------------------------------------ */
/* 5. WAF effectiveness, inert canaries across encoding classes.      */
/*    DECLINED offensive equivalent: adaptive WAF/filter evasion       */
/*    (fuzzing loop mutating payloads until one slips through).         */
/*    This is the defensive flip: ONE inert canary per encoding class, */
/*    recorded as blocked / let-through, so the client can tune rules.  */
/* ------------------------------------------------------------------ */

interface WafClassOutcome {
  encodingClass: string;
  status: number;
  outcome: 'blocked' | 'let-through' | 'inconclusive';
  note: string;
}

const WAF_BLOCK_STATUSES = new Set([400, 403, 406, 418, 419, 501, 503]);

function classifyWafResponse(status: number, body: string, canary: string): WafClassOutcome['outcome'] {
  const head = body.slice(0, 4000);
  if (WAF_BLOCK_STATUSES.has(status) && (WAF_BLOCK_RE.test(head) || status === 403 || status === 406)) {
    return 'blocked';
  }
  if (status === 429) return 'blocked'; // throttling engaging counts as a defense
  if (status >= 200 && status < 400) return 'let-through';
  if (status === 404) return 'let-through'; // request reached the app (not blocked at the edge)
  if (body.includes(canary)) return 'let-through';
  return 'inconclusive';
}

export async function probeWafEffectiveness(
  http: ActiveHttpClient,
  tabUrl: string,
): Promise<{ findings: Finding[]; verdict: DefenseVerdict; requestCount: number }> {
  const findings: Finding[] = [];
  const outcomes: WafClassOutcome[] = [];
  let requests = 0;

  // One inert canary per encoding class. Each payload is a classic WAF-test
  // SHAPE (angle brackets, quote, traversal, expression syntax) whose only
  // content is the random canary token, no executable code, no exfiltration
  // channel, and the response is read as text only, never rendered.
  const canary = randToken('bswaf');
  const base = new URL(tabUrl);
  base.search = '';
  const classes: Array<{ encodingClass: string; value: string; raw?: boolean }> = [
    { encodingClass: 'plain', value: `<script>${canary}</script>` },
    { encodingClass: 'url-encoded', value: `%3Cscript%3E${canary}%3C%2Fscript%3E` },
    { encodingClass: 'double-encoded', value: `%253Cscript%253E${canary}%253C%252Fscript%253E` },
    { encodingClass: 'unicode', value: `%u003cscript%u003e${canary}%u003c%u002fscript%u003e` },
    { encodingClass: 'polyglot-shape', value: `"'${canary}--><svg>${canary}</svg>` },
    { encodingClass: 'traversal-shape', value: `../../${canary}` },
  ];

  for (const c of classes) {
    const u = new URL(base.toString());
    // Build the query string by hand so the encoding class survives intact
    // (URLSearchParams would normalise it away).
    u.search = `bugseek_waf_probe=${c.value}`;
    try {
      requests++;
      const res = await http.get(u.toString());
      const outcome = classifyWafResponse(res.status, res.bodyText, canary);
      outcomes.push({
        encodingClass: c.encodingClass,
        status: res.status,
        outcome,
        note:
          outcome === 'blocked'
            ? `HTTP ${res.status} — blocked at the edge / by a filter`
            : outcome === 'let-through'
              ? `HTTP ${res.status} — reached the application`
              : `HTTP ${res.status} — inconclusive`,
      });
    } catch {
      outcomes.push({ encodingClass: c.encodingClass, status: 0, outcome: 'inconclusive', note: 'request failed' });
    }
  }

  const blocked = outcomes.filter((o) => o.outcome === 'blocked');
  const passed = outcomes.filter((o) => o.outcome === 'let-through');
  const table = outcomes.map((o) => `${o.encodingClass}: ${o.note}`).join(' | ');

  if (passed.length === 0) {
    findings.push(baseFinding({
      category: 'api',
      tags: ['defense-verification', 'defense-waf', 'defense-engaged'],
      title: 'WAF/filter blocked every encoding class tested',
      description:
        `Inert canary payloads in ${classes.length} encoding classes (plain, URL-encoded, double-encoded, Unicode, polyglot shape, traversal shape) ` +
        `were all blocked before reaching the application. ${table}. This is a single canary per class, not a fuzzing loop — ` +
        'it proves these shapes are caught, not that no bypass exists. ' + UNKNOWN_OUTSIDE,
      severity: 'info',
      confidence: 'medium',
      confirmed: true,
      location: tabUrl,
      evidence: redactedSnippet(table, 400),
      remediation: 'No action needed for these classes. Re-run after every WAF rule change.',
      ...cvssFields('api:endpoint-discovered'),
      requestCount: requests,
    }));
  } else {
    findings.push(baseFinding({
      category: 'api',
      tags: ['defense-verification', 'defense-waf', 'defense-blind'],
      title: `WAF let through ${passed.length} encoding class(es): ${passed.map((o) => o.encodingClass).join(', ')}`,
      description:
        `Inert canary payloads reached the application in these encoding classes: ${passed.map((o) => `${o.encodingClass} (HTTP ${o.status})`).join('; ')}. ` +
        `Blocked: ${blocked.length > 0 ? blocked.map((o) => o.encodingClass).join(', ') : 'none'}. Full picture — ${table}. ` +
        'Each payload carried only a random canary token (no executable content) and responses were read as text only, so nothing was exploited — ' +
        'these are the classes to tune rules for. ' + UNKNOWN_OUTSIDE,
      severity: 'medium',
      confidence: 'medium',
      confirmed: false,
      location: tabUrl,
      evidence: redactedSnippet(passed.map((o) => `${o.encodingClass} → HTTP ${o.status}`).join('; '), 300),
      remediation:
        'Add or tighten WAF rules for the encoding classes that passed (normalise double/Unicode encoding at the edge, block traversal shapes on non-file routes), ' +
        'then re-run this probe to confirm the tune.',
      ...cvssFields('api:sensitive-endpoint'),
      requestCount: requests,
    }));
  }

  return {
    findings,
    verdict: {
      attackClass: 'waf-evasion',
      blocked: blocked.length === classes.length ? 'observed' : passed.length > 0 ? 'not-observed' : 'unknown',
      detected: blocked.length > 0 || passed.length > 0 ? 'observed' : 'unknown',
      logged: 'unknown',
      alerted: 'unknown',
      summary: `${table}. ${UNKNOWN_OUTSIDE}`,
    },
    requestCount: requests,
  };
}

/**
 * Request-smuggling CONDITIONS check, analysis only, no desync attempt.
 *
 * The browser fetch API forbids setting Transfer-Encoding, so a smuggled
 * request cannot be constructed from this extension at all. What CAN be
 * checked: whether responses carry ambiguous framing signals (duplicate
 * Content-Length, Transfer-Encoding + Content-Length together, chunked
 * framing oddities) and whether the server rejects a TE-bearing request.
 * A live smuggling test belongs on the client's isolated staging with a
 * purpose-built tool, never against shared production infrastructure,
 * and this finding says exactly that.
 */
export async function probeRequestSmugglingConditions(
  http: ActiveHttpClient,
  tabUrl: string,
  isStaging = false,
): Promise<{ findings: Finding[]; verdict: DefenseVerdict; requestCount: number }> {
  const findings: Finding[] = [];
  let requests = 0;
  const signals: string[] = [];

  try {
    requests++;
    const res = await http.get(tabUrl);
    // Duplicate / ambiguous framing headers on the RESPONSE side.
    const rawCl = res.headers['content-length'];
    if (res.headers['transfer-encoding'] && rawCl) {
      signals.push('response carries both Transfer-Encoding and Content-Length');
    }
    if (res.headers['transfer-encoding']?.toLowerCase().includes('chunked') && res.status === 200) {
      signals.push('response uses chunked transfer encoding (normal for dynamic responses — review framing only if paired with ambiguity)');
    }
  } catch {
    signals.push('baseline request failed — conditions could not be assessed');
  }

  // Attempting to set Transfer-Encoding via fetch is a no-op (forbidden
  // header): the browser strips it. We record that fact rather than
  // pretending a TE probe was sent.
  findings.push(baseFinding({
    category: 'api',
    tags: ['defense-verification', 'defense-waf', 'defense-smuggling-conditions'],
    title:
      signals.length > 0 && !signals[0].startsWith('baseline')
        ? 'Request-smuggling conditions: ambiguous framing signals present'
        : 'Request-smuggling conditions: no ambiguous framing signals observed',
    description:
      'Smuggling was checked for CONDITIONS ONLY — no smuggled request was sent and none can be built from a browser extension ' +
      '(fetch forbids the Transfer-Encoding header, and a desync attempt against shared infrastructure could poison other users’ requests). ' +
      `${signals.length > 0 ? `Signals: ${signals.join('; ')}.` : 'The baseline response showed no duplicate Content-Length / Transfer-Encoding ambiguity.'} ` +
      (isStaging
        ? 'This target is marked as isolated staging: a purpose-built smuggling test (e.g. a dedicated scanner against this staging host) is the correct next step.'
        : 'A live smuggling test must only ever run against the client’s isolated staging, never shared production.'),
    severity: signals.length > 0 && !signals[0].startsWith('baseline') ? 'low' : 'info',
    confidence: 'medium',
    confirmed: false,
    location: tabUrl,
    evidence: redactedSnippet(signals.join('; ') || 'no ambiguous framing headers', 300),
    remediation:
      'Reject requests carrying both Content-Length and Transfer-Encoding, and duplicate Content-Length headers, at the edge (load balancer / reverse proxy). ' +
      'Test smuggling only on isolated staging with a dedicated tool.',
    ...cvssFields('api:endpoint-discovered'),
    requestCount: requests,
  }));

  return {
    findings,
    verdict: {
      attackClass: 'request-smuggling',
      blocked: 'unknown',
      detected: signals.length > 0 ? 'observed' : 'not-observed',
      logged: 'unknown',
      alerted: 'unknown',
      summary:
        'Conditions-only check: no smuggled request was sent. ' +
        (signals.length > 0 ? `Signals: ${signals.join('; ')}.` : 'No ambiguous framing signals in the baseline response.') +
        ' A live test belongs on isolated staging only.',
    },
    requestCount: requests,
  };
}

/* ------------------------------------------------------------------ */
/* 6. Lateral-movement exposure mapping, static blast-radius map.     */
/*    DECLINED offensive equivalent: automated lateral movement &      */
/*    exfiltration (SSRF/RCE/leaked BaaS keys to enumerate metadata,   */
/*    dump env vars, map internal topology). This is the defensive     */
/*    flip: map what an attacker COULD reach, without executing it.    */
/* ------------------------------------------------------------------ */

const SSRF_PARAM_RE = /^(url|uri|fetch|proxy|redirect|next|callback|webhook|image|file|path|target|dest|continue)$/i;
const METADATA_HOST_RE = /169\.254\.169\.254|metadata\.google\.internal|metadata\.google|instance-data/i;
const ENV_NAME_RE = /^([A-Z][A-Z0-9_]{2,})\s*=/gm;

export async function probeLateralMovementExposure(
  http: ActiveHttpClient,
  tabUrl: string,
  dom: DomScanData,
  input: DefenseProbeInput,
): Promise<{ findings: Finding[]; verdict: DefenseVerdict; requestCount: number }> {
  const findings: Finding[] = [];
  let requests = 0;

  // --- a. SSRF sink surface (static): which discovered endpoints/params
  //        look like server-side fetch sinks. ---
  const sinkParams: string[] = [];
  for (const ep of input.apiEndpoints ?? []) {
    for (const p of ep.params ?? []) {
      if (SSRF_PARAM_RE.test(p)) sinkParams.push(`${ep.path} → param "${p}"`);
    }
  }
  const tabParams = [...new URL(tabUrl).searchParams.keys()].filter((p) => SSRF_PARAM_RE.test(p));
  for (const p of tabParams) sinkParams.push(`${new URL(tabUrl).pathname} → param "${p}"`);

  // --- b. SSRF canary: ONLY to a BugSeek-owned endpoint, ONLY when a
  //        listener exists. The question is yes/no ("did the server make
  //        the outbound request at all"), no data is fetched. The callback
  //        itself is observed server-side (backend OAST store); the
  //        extension can only dispatch the canary and report that it did.
  const canaryUrl = input.oastCanaryUrl ?? null;
  const listenerConfigured = oastListenerConfigured(canaryUrl);
  let canaryDispatched = false;
  if (sinkParams.length > 0 && listenerConfigured && canaryUrl) {
    // One GET, one sink param, canary URL as the value. No metadata
    // address, no internal host, only the BugSeek-owned canary.
    const first = (input.apiEndpoints ?? []).find((ep) =>
      (ep.params ?? []).some((p) => SSRF_PARAM_RE.test(p)),
    );
    const param = first?.params?.find((p) => SSRF_PARAM_RE.test(p)) ?? tabParams[0];
    if (param && first) {
      try {
        requests++;
        const u = new URL(first.path.startsWith('http') ? first.path : `${new URL(tabUrl).origin}${first.path}`);
        u.searchParams.set(param, canaryUrl);
        await http.get(u.toString());
        canaryDispatched = true;
      } catch {
        /* dispatch failure is itself a data point, recorded below */
      }
    }
  }

  if (sinkParams.length === 0) {
    findings.push(baseFinding({
      category: 'api',
      tags: ['defense-verification', 'defense-lateral-movement', 'defense-ssrf-surface'],
      title: 'Lateral-movement map: no server-side-fetch (SSRF) sink surface found',
      description:
        'No discovered endpoint or page parameter looks like a server-side fetch sink (url/redirect/proxy/callback-style params). ' +
        'Without a sink, an SSRF-based lateral move has nowhere to start from the observed surface. ' +
        'This maps the discovered surface only — undiscovered endpoints were not probed.',
      severity: 'info',
      confidence: 'medium',
      confirmed: true,
      location: tabUrl,
      remediation: 'No action needed for this surface. Keep URL-accepting parameters off public endpoints, or allow-list their destinations.',
      ...cvssFields('api:endpoint-discovered'),
      requestCount: requests,
    }));
  } else if (canaryDispatched) {
    findings.push(baseFinding({
      category: 'api',
      tags: ['defense-verification', 'defense-lateral-movement', 'defense-ssrf-surface'],
      title: `SSRF sink surface found (${sinkParams.length} param(s)) — canary dispatched, awaiting server-side correlation`,
      description:
        `Server-side-fetch-style parameters found: ${sinkParams.slice(0, 5).join('; ')}. ` +
        'One canary request was sent carrying ONLY the BugSeek-owned callback URL (no metadata address, no internal host, no data fetched). ' +
        'Whether the server actually made the outbound request is decided server-side by checking the OAST callback store for this canary — ' +
        'a hit means the server will fetch attacker-supplied URLs; no hit means the sink is inert or filtered. ' +
        'This finding is pending that correlation; check the backend OAST callbacks for the verdict.',
      severity: 'medium',
      confidence: 'medium',
      confirmed: false,
      location: tabUrl,
      evidence: redactedSnippet(sinkParams.slice(0, 5).join('; '), 300),
      remediation:
        'Allow-list the destinations of every URL-accepting parameter, block link-local/metadata ranges (169.254.0.0/16, 10/8, 172.16/12, 192.168/16) at the egress proxy, and require authentication on fetch endpoints.',
      ...cvssFields('api:sensitive-endpoint'),
      requestCount: requests,
    }));
  } else {
    findings.push(baseFinding({
      category: 'api',
      tags: ['defense-verification', 'defense-lateral-movement', 'defense-ssrf-surface'],
      title: `SSRF sink surface found (${sinkParams.length} param(s)) — canary NOT sent (no OAST listener)`,
      description:
        `Server-side-fetch-style parameters found: ${sinkParams.slice(0, 5).join('; ')}. ` +
        'The SSRF canary was NOT sent: no OAST listener is configured (scaffolding only), so there is nowhere for a callback to land. ' +
        'The exposure is therefore reported statically: an attacker who controls one of these parameters can ask the server to fetch arbitrary URLs, ' +
        'including cloud metadata — unless egress filtering blocks it, which this probe cannot verify without a listener. ' +
        'Stand up the OAST listener (see docs/oast.md) to turn this into a yes/no test.',
      severity: 'medium',
      confidence: 'medium',
      confirmed: false,
      location: tabUrl,
      evidence: redactedSnippet(sinkParams.slice(0, 5).join('; '), 300),
      remediation:
        'Allow-list fetch destinations, block link-local/metadata ranges at the egress proxy, and stand up the OAST listener so the canary test can run.',
      ...cvssFields('api:sensitive-endpoint'),
      requestCount: requests,
    }));
  }

  // --- c. Metadata-endpoint reachability: canary ONLY, never fetched. ---
  // The metadata address is never requested by this module, directly, via
  // a parameter, or via a redirect. Reachability is inferred only from (i)
  // whether an SSRF sink exists (above) and (ii) whether any captured
  // response mentions metadata hosts (static text search below).
  const metadataMentioned = (input.responseBodies ?? []).some((b) => METADATA_HOST_RE.test(b.bodyText));
  findings.push(baseFinding({
    category: 'api',
    tags: ['defense-verification', 'defense-lateral-movement', 'defense-metadata'],
    title: metadataMentioned
      ? 'Cloud metadata host referenced in captured responses — review reachability'
      : 'Cloud metadata endpoint (169.254.169.254) never requested — reachability assessed statically',
    description:
      'The metadata endpoint was NOT fetched by this probe, directly or indirectly: fetching it would be the attack itself. ' +
      (metadataMentioned
        ? 'Captured responses DO mention a metadata host, which means server-side code paths reference it — confirm egress filtering blocks it.'
        : 'Static assessment only: reachability depends on whether an SSRF sink exists (see the SSRF finding) and whether egress filtering blocks link-local ranges. ') +
      'A canary-only test (server asked to fetch the BugSeek canary, never metadata) is the safe way to settle this once the OAST listener exists.',
    severity: metadataMentioned ? 'medium' : 'info',
    confidence: 'medium',
    confirmed: false,
    location: tabUrl,
    remediation:
      'Block 169.254.169.254 and the link-local range at the egress proxy / firewall, and require IMDSv2 with hop limits on cloud instances.',
    ...cvssFields('api:sensitive-endpoint'),
    requestCount: 0,
  }));

  // --- d. Environment-variable exposure via STATIC sources only. ---
  const envNames = new Set<string>();
  const sources: string[] = [];
  const staticTexts: Array<{ label: string; text: string }> = [
    ...((input.responseBodies ?? []).map((b) => ({ label: `response ${b.url}`, text: b.bodyText }))),
    ...((input.secretFindings ?? []).map((f) => ({ label: `finding ${f.title}`, text: `${f.title} ${f.description ?? ''}` }))),
    ...((dom.inlineScripts ?? []).map((s, i) => ({ label: `inline script #${i + 1}`, text: s }))),
  ];
  for (const { label, text } of staticTexts) {
    for (const m of text.matchAll(ENV_NAME_RE)) {
      const name = m[1];
      if (/(KEY|SECRET|TOKEN|PASSWORD|DATABASE|DB_|AWS_|STRIPE|SMTP|MAIL_|PRIVATE|CREDENTIAL)/.test(name)) {
        envNames.add(name);
        if (!sources.includes(label)) sources.push(label);
      }
    }
    if (envNames.size >= 12) break;
  }
  if (envNames.size > 0) {
    findings.push(baseFinding({
      category: 'secrets',
      tags: ['defense-verification', 'defense-lateral-movement', 'defense-env-exposure'],
      title: `Environment variable names exposed in static sources (${envNames.size} found)`,
      description:
        `Variable NAMES (never values) found in ${sources.slice(0, 3).join('; ')}: ${[...envNames].slice(0, 12).join(', ')}. ` +
        'Names alone tell an attacker exactly which credentials to hunt for and confirm the stack. ' +
        'Nothing was dumped: no environment was read, no process was inspected — this is static text already shipped to the browser.',
      severity: 'medium',
      confidence: 'medium',
      confirmed: true,
      location: tabUrl,
      evidence: `exposed variable names: ${[...envNames].slice(0, 12).join(', ')} (values never captured)`,
      remediation:
        'Strip env dumps from error pages, bundles, and source maps. Rotate any credential whose name appears here and confirm it is not also exposed by value.',
      ...cvssFields('secrets:response-body'),
      requestCount: 0,
    }));
  }

  // --- e. BaaS key scope, ONLY the client's own keys, at their direction. ---
  const ownKeys = input.ownKeys ?? [];
  if (ownKeys.length === 0) {
    findings.push(baseFinding({
      category: 'secrets',
      tags: ['defense-verification', 'defense-lateral-movement', 'defense-baask-scope'],
      title: 'BaaS key scope self-check not run — no own keys supplied',
      description:
        'No client-owned keys were supplied for the scope self-check, so nothing was assessed. ' +
        'This check runs ONLY on keys the client supplies at their explicit direction; found or leaked keys are never scope-checked against any provider.',
      severity: 'info',
      confidence: 'high',
      confirmed: true,
      remediation: 'To run the self-check, supply your own keys (fingerprints only) with their declared scopes and re-run.',
      ...cvssFields('api:endpoint-discovered'),
      requestCount: 0,
    }));
  } else {
    for (const k of ownKeys.slice(0, 5)) {
      findings.push(baseFinding({
        category: 'secrets',
        tags: ['defense-verification', 'defense-lateral-movement', 'defense-baask-scope'],
        title: `Own-key scope self-check (${k.provider}, ${k.fingerprint})`,
        description:
          `Client-supplied own key (${k.provider}, fingerprint ${k.fingerprint}). ` +
          `Declared scopes: ${k.declaredScopes?.length ? k.declaredScopes.join(', ') : 'not declared by the client'}. ` +
          'Assessed from the client’s own declaration only — no provider was contacted and no permission was probed live. ' +
          'If the declared scope is broader than the client needs (e.g. full database read/write for a frontend key), narrow it: use row-level security, anon-vs-service-role separation, and per-environment keys.',
        severity: k.declaredScopes?.length ? 'info' : 'low',
        confidence: 'medium',
        confirmed: false,
        location: tabUrl,
        evidence: `fingerprint: ${k.fingerprint} (value never supplied or stored)`,
        remediation:
          'Narrow the key to the minimum scope the client needs, split anon and service-role keys, and rotate any key whose scope cannot be narrowed.',
        ...cvssFields('api:endpoint-discovered'),
        requestCount: 0,
      }));
    }
  }

  const sinkCount = sinkParams.length;
  return {
    findings,
    verdict: {
      attackClass: 'lateral-movement',
      blocked: sinkCount === 0 && envNames.size === 0 ? 'observed' : 'not-observed',
      detected: sinkCount > 0 || envNames.size > 0 ? 'observed' : 'not-observed',
      logged: 'unknown',
      alerted: 'unknown',
      summary:
        `Blast-radius map (static, nothing executed): ${sinkCount} SSRF sink param(s); ` +
        `${canaryDispatched ? 'SSRF canary dispatched — server-side correlation pending' : listenerConfigured ? 'SSRF canary not dispatched (no sink to send it through)' : 'SSRF canary not sent — no OAST listener'}; ` +
        `metadata endpoint never fetched; ${envNames.size} env-var name(s) exposed in static sources; ` +
        `${ownKeys.length} own key(s) scope-checked. ${UNKNOWN_OUTSIDE}`,
    },
    requestCount: requests,
  };
}

/* ------------------------------------------------------------------ */
/* Entry point (coordinator wires this into the active runner).        */
/* ------------------------------------------------------------------ */

export async function runDefenseProbes(
  http: ActiveHttpClient,
  authz: AuthorizationRecord,
  tabUrl: string,
  dom: DomScanData,
  input: DefenseProbeInput = {},
): Promise<DefenseProbeResult> {
  const findings: Finding[] = [];
  const verdicts: DefenseVerdict[] = [];
  let requestCount = 0;

  const key = assessKeyExposure(input);
  findings.push(...key.findings);
  verdicts.push(key.verdict);

  const brute = await probeBruteForceDefense(http, authz, tabUrl, dom);
  findings.push(...brute.findings);
  verdicts.push(brute.verdict);
  requestCount += brute.requestCount;

  const exploit = await probeExploitationDefense(http, tabUrl);
  findings.push(...exploit.findings);
  verdicts.push(exploit.verdict);
  requestCount += exploit.requestCount;

  const post = await probePostExploitationExposure(http, tabUrl);
  findings.push(...post.findings);
  verdicts.push(post.verdict);
  requestCount += post.requestCount;

  const waf = await probeWafEffectiveness(http, tabUrl);
  findings.push(...waf.findings);
  verdicts.push(waf.verdict);
  requestCount += waf.requestCount;

  const smuggling = await probeRequestSmugglingConditions(http, tabUrl, input.isStaging ?? false);
  findings.push(...smuggling.findings);
  verdicts.push(smuggling.verdict);
  requestCount += smuggling.requestCount;

  const lateral = await probeLateralMovementExposure(http, tabUrl, dom, input);
  findings.push(...lateral.findings);
  verdicts.push(lateral.verdict);
  requestCount += lateral.requestCount;

  return { findings, verdicts, requestCount };
}

/* ── Defensive section for the extension's one-click Markdown report ──
 * Mirrors backend/src/reports/defensive.ts (the extension cannot import
 * backend code). Derives classes from finding tags, extension findings
 * carry them; the backend derives from titles as a fallback because tags
 * do not survive scan ingestion. `logged`/`alerted` are always unknown
 * from outside; only server-side logs or the runtime detection layer can
 * confirm them. Returns [] when no defense-verification findings exist.
 */

const DEFENSE_CLASS_BY_TAG: Record<string, DefenseVerdict['attackClass']> = {
  'defense-key-exposure': 'key-exposure',
  'defense-brute-force': 'brute-force',
  'defense-exploitation': 'exploitation',
  'defense-waf': 'waf-evasion',
  'defense-smuggling-conditions': 'request-smuggling',
  'defense-post-exploitation': 'post-exploitation',
  'defense-lateral-movement': 'lateral-movement',
};

const DEFENSE_CLASS_LABELS: Record<DefenseVerdict['attackClass'], string> = {
  'key-exposure': 'Key exposure',
  'brute-force': 'Brute force / credential stuffing',
  exploitation: 'Exploitation attempts (benign canaries)',
  'waf-evasion': 'WAF / filter evasion (encoding classes)',
  'request-smuggling': 'Request smuggling (conditions check)',
  'post-exploitation': 'Post-exploitation paths (internal/debug endpoints)',
  'lateral-movement': 'Lateral movement (SSRF / metadata / env exposure)',
};

const DEFENSE_FIXES: Record<DefenseVerdict['attackClass'], string[]> = {
  'key-exposure': [
    'Rotate every exposed key and scope the replacement to least privilege.',
    'Add a pre-deploy secret scan so keys never ship in bundles or source maps again.',
  ],
  'brute-force': [
    'Enable rate limiting on the login endpoint and progressive delays after failed attempts.',
    'Add account lockout or CAPTCHA after a small number of failures.',
  ],
  exploitation: [
    'Ensure output encoding on every reflection point and keep CSP enforced.',
    'Add WAF rules for the payload classes that passed through unencoded.',
  ],
  'waf-evasion': [
    'Normalise double-encoded and Unicode input at the edge before rule matching.',
    'Add rules for the encoding classes that passed, then re-run the probe to confirm the tune.',
  ],
  'request-smuggling': [
    'Reject requests carrying both Content-Length and Transfer-Encoding, and duplicate Content-Length headers, at the edge.',
    'Test smuggling only on isolated staging with a dedicated tool — never shared production.',
  ],
  'post-exploitation': [
    'Put internal/debug endpoints behind authentication and network restrictions (allow-list, VPN, or removal from production).',
    'Actuator/env endpoints must never be internet-reachable.',
  ],
  'lateral-movement': [
    'Allow-list the destinations of every URL-accepting parameter.',
    'Block link-local/metadata ranges (169.254.0.0/16, 10/8, 172.16/12, 192.168/16) at the egress proxy.',
  ],
};

function defenseSignalWord(s: DefenseSignal): string {
  if (s === 'observed') return 'Yes';
  if (s === 'not-observed') return 'No';
  return 'Unknown';
}

function defenseClassVerdict(v: DefenseVerdict): string {
  if (v.blocked === 'observed') return 'Defended — the attack class was blocked';
  if (v.detected === 'observed' && v.blocked === 'not-observed') {
    return 'Seen but not stopped — the site reacted without blocking';
  }
  if (v.detected === 'not-observed' && v.blocked === 'not-observed') {
    return 'Blind spot — no defense was observed for this class';
  }
  return 'Inconclusive — not enough signal to judge this class';
}

/** Render the defensive aftermath section as Markdown lines, or [] when absent. */
export function defensiveSectionLines(findings: Finding[]): string[] {
  const byClass = new Map<DefenseVerdict['attackClass'], Finding[]>();
  for (const f of findings) {
    const tags = f.tags ?? [];
    if (!tags.includes('defense-verification')) continue;
    for (const t of tags) {
      const cls = DEFENSE_CLASS_BY_TAG[t];
      if (cls) {
        const list = byClass.get(cls) ?? [];
        list.push(f);
        byClass.set(cls, list);
        break;
      }
    }
  }
  if (byClass.size === 0) return [];

  const verdicts: DefenseVerdict[] = [];
  for (const [attackClass, list] of byClass) {
    const tags = list.flatMap((f) => f.tags ?? []);
    const titles = list.map((f) => f.title).join(' ');
    const engaged = tags.includes('defense-engaged') || /engaged|blocked every|contained/i.test(titles);
    const bypassed = /let through|passed the defenses/i.test(titles);
    const notTested = /skipped|not applicable|not run/i.test(titles);
    const clean =
      !engaged && !bypassed && !notTested && /no .* found|no .* reachable|no .* to assess|no .* signals observed/i.test(titles);
    let detected: DefenseSignal;
    let blocked: DefenseSignal;
    if (engaged && !bypassed) {
      detected = 'observed';
      blocked = 'observed';
    } else if (bypassed) {
      detected = 'observed';
      blocked = 'not-observed';
    } else if (notTested) {
      detected = 'unknown';
      blocked = 'unknown';
    } else if (clean) {
      detected = 'not-observed';
      blocked = 'observed';
    } else if (/reachable without authentication|exposed|surface found|response body|signals present/i.test(titles)) {
      detected = 'not-observed';
      blocked = 'not-observed';
    } else {
      detected = 'observed';
      blocked = 'not-observed';
    }
    const summarySource = list.find((f) => f.description)?.description ?? list[0]?.title ?? '';
    verdicts.push({
      attackClass,
      detected,
      blocked,
      logged: 'unknown',
      alerted: 'unknown',
      summary: summarySource.length > 300 ? `${summarySource.slice(0, 297)}…` : summarySource,
    });
  }

  const lines: string[] = [
    '## Did your site notice? — defensive aftermath',
    '',
    'Each attack class below was tested with safe, authorized probes (inert canaries, at most 5 canary ' +
      'logins, read-only GETs — nothing was exploited). "Logged" and "alerted" can only be confirmed ' +
      'from server-side logs or the BugSeek runtime detection layer; "Unknown" there means "not visible ' +
      'from outside", not "did not happen".',
    '',
    '| Attack class | Detected | Blocked | Logged | Alerted | Verdict |',
    '|---|---|---|---|---|---|',
  ];
  const gaps: DefenseVerdict[] = [];
  for (const v of verdicts) {
    lines.push(
      `| ${DEFENSE_CLASS_LABELS[v.attackClass]} | ${defenseSignalWord(v.detected)} | ${defenseSignalWord(v.blocked)} | ` +
        `${defenseSignalWord(v.logged)} | ${defenseSignalWord(v.alerted)} | ${defenseClassVerdict(v)} |`,
    );
    if (v.blocked === 'not-observed' || v.detected === 'not-observed') gaps.push(v);
  }
  lines.push('');
  for (const v of verdicts) {
    lines.push(`### ${DEFENSE_CLASS_LABELS[v.attackClass]}`, '');
    lines.push(`${v.summary}`, '');
  }
  if (gaps.length > 0) {
    lines.push('### What to fix first', '');
    for (const v of gaps) {
      lines.push(`**${DEFENSE_CLASS_LABELS[v.attackClass]}** — ${defenseClassVerdict(v)}.`);
      for (const fix of DEFENSE_FIXES[v.attackClass]) lines.push(`- ${fix}`);
      lines.push('');
    }
  } else {
    lines.push(
      '### What to fix first',
      '',
      'No blind spots were observed in this run: every tested class was blocked or produced no exposure. ' +
        'Re-run after each deploy and each WAF rule change — defenses rot silently.',
      '',
    );
  }
  return lines;
}

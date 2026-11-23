/**
 * Guardrailed brute-force testing, extension-side.
 *
 * Does: well-known default credentials for the detected tech (Tomcat /
 * Jenkins / WordPress / router / generic) plus a short weak-password
 * list (<= 15 entries) against ONE username only. Reports whether a
 * default credential worked, whether brute-force protection was
 * observed, and the lockout risk of continued guessing.
 *
 * Never: credential stuffing with breached lists, spraying across
 * accounts, high-throughput guessing, OTP/session-token guessing, or
 * any rate-limit evasion. Every attempt goes through ActiveHttpClient
 * (scope check + rate limiter) and is spaced >= 2s apart. Stops at
 * once on 429, CAPTCHA, a lockout message, Retry-After, or repeated 403s.
 *
 * Gating: only when the authorization record carries the separate
 * `allowAuthProbes` grant. A working password is never recorded,
 * a success is reported by username only.
 */
import { scoreFinding } from '../lib/cvss';
import type { AuthorizationRecord, DomScanData, Finding } from '../lib/types';
import type { ActiveHttpClient } from './httpClient';
import {
  DEFAULT_CREDENTIALS as AUTH_CHECKER_DEFAULTS,
  detectLoginForms,
  looksLikeSuccess,
} from './authChecker';
import {
  buildAttemptPlan,
  type AttemptPlanEntry,
  type LoginTech,
} from './bruteForceLists';

let findingSeq = 0;

/** Hard cap on login attempts per scan (DoS / lockout guardrail). */
const MAX_BRUTE_FORCE_ATTEMPTS = 20;
/** Minimum spacing between attempts inside this module, ms (on top of the
 *  shared rate limiter, so effective pace is ~1 attempt per 2 seconds). */
const MIN_ATTEMPT_GAP_MS = 2000;
/** Consecutive 403s that count as a lockout signal. */
const MAX_CONSECUTIVE_403 = 2;

function nextId(): string {
  findingSeq++;
  return `bruteforce-${findingSeq}`;
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

const CAPTCHA_HINT_RE = /captcha|recaptcha|challenge|verify you are human/i;
const LOCKOUT_HINT_RE =
  /account (is )?locked|too many (failed )?attempts|try again later|temporarily (blocked|locked|suspended)|account suspended/i;

/** Best-effort technology guess from the login form and page signals. */
function detectLoginTech(dom: DomScanData, formActionUrl: string): LoginTech {
  const action = formActionUrl.toLowerCase();
  const haystack = [
    action,
    dom.externalScripts.join(' '),
    dom.metaTags.map((m) => `${m.name} ${m.content}`).join(' '),
    dom.globals.join(' '),
  ]
    .join(' ')
    .toLowerCase();
  if (
    action.includes('wp-login') ||
    haystack.includes('wp-content') ||
    haystack.includes('wp-includes') ||
    haystack.includes('wordpress')
  ) {
    return 'wordpress';
  }
  if (
    action.includes('/manager/html') ||
    haystack.includes('tomcat') ||
    haystack.includes('apache tomcat')
  ) {
    return 'tomcat';
  }
  if (haystack.includes('jenkins') || action.includes('/jenkins/')) {
    return 'jenkins';
  }
  if (
    action.includes('login.cgi') ||
    action.includes('/goform/') ||
    /router|gateway/.test(action)
  ) {
    return 'router';
  }
  return 'generic';
}

/** "tomcat defaults (4 pairs), weak passwords (11 pairs)", for the summary. */
function summarizeAttempted(plan: AttemptPlanEntry[]): string {
  const counts = new Map<string, number>();
  for (const e of plan) counts.set(e.list, (counts.get(e.list) ?? 0) + 1);
  return [...counts.entries()]
    .map(([list, n]) => `${list} (${n} ${n === 1 ? 'pair' : 'pairs'})`)
    .join(', ');
}

export interface BruteForceResult {
  findings: Finding[];
}

export async function testBruteForce(
  http: ActiveHttpClient,
  authz: AuthorizationRecord,
  tabUrl: string,
  dom: DomScanData,
): Promise<BruteForceResult> {
  const findings: Finding[] = [];
  const before = http.limiter.getStats().requestsMade;

  const loginForms = detectLoginForms(dom, tabUrl);

  // --- Gate: the separate login-form testing grant (same as authChecker). ---
  if (!authz.allowAuthProbes) {
    if (loginForms.length > 0) {
      findings.push({
        id: nextId(),
        category: 'auth',
        mode: 'active',
        tags: ['auth', 'bruteforce-skipped'],
        title: 'Brute-force testing skipped: no authorization record',
        description:
          'Login forms were found, but guardrailed brute-force testing was skipped because the authorization record ' +
          'does not include the separate login-form testing grant. Re-authorize with "allow login-form testing" to enable it. ' +
          'No login attempts were made.',
        severity: 'info',
        confidence: 'high',
        confirmed: true,
        remediation: 'No action needed unless deeper auth testing is in scope.',
        ...cvssFields('api:endpoint-discovered'),
        requestCount: 0,
      });
    }
    return { findings };
  }

  if (loginForms.length === 0) {
    findings.push({
      id: nextId(),
      category: 'auth',
      mode: 'active',
      tags: ['auth', 'bruteforce-not-applicable'],
      title: 'No login forms detected — brute-force testing not applicable',
      description:
        'The authorization record permits login-form testing, but no password forms were found on the scanned page. ' +
        'No login attempts were made.',
      severity: 'info',
      confidence: 'high',
      confirmed: true,
      remediation: 'Point the scanner at the login page directly to test authentication.',
      ...cvssFields('api:endpoint-discovered'),
      requestCount: 0,
    });
    return { findings };
  }

  // --- Guardrailed attempt loop. ---
  const form = loginForms[0];
  const tech = detectLoginTech(dom, form.actionUrl);
  const plan = buildAttemptPlan(tech, AUTH_CHECKER_DEFAULTS, MAX_BRUTE_FORCE_ATTEMPTS);

  const sleep = (ms: number): Promise<void> =>
    new Promise((resolve) => setTimeout(resolve, ms));

  let attempts = 0;
  let succeededUser: string | null = null;
  let succeededList: string | null = null;
  let stopCondition: string | null = null;
  const protectionSignals: string[] = [];
  let consecutive403 = 0;
  let lastAttemptAt = 0;

  for (const entry of plan) {
    // Extra spacing on top of the shared limiter: ~1 attempt per 2s max.
    if (attempts > 0) {
      const sinceLast = Date.now() - lastAttemptAt;
      if (sinceLast < MIN_ATTEMPT_GAP_MS) {
        await sleep(MIN_ATTEMPT_GAP_MS - sinceLast);
      }
    }
    const body = new URLSearchParams();
    body.set(form.usernameField, entry.username);
    body.set(form.passwordField, entry.password);
    for (const [k, v] of form.extraFields) body.set(k, v);

    let res: Awaited<ReturnType<typeof http.post>>;
    try {
      res = await http.post(form.actionUrl, body.toString());
    } catch {
      stopCondition = 'request error / timeout — stopped';
      break;
    }
    lastAttemptAt = Date.now();
    attempts++;

    if (looksLikeSuccess(res)) {
      // Username only, the working password is never recorded.
      succeededUser = entry.username;
      succeededList = entry.list;
      stopCondition = 'credential accepted — stopped immediately';
      break;
    }

    // Lockout-aware: stop IMMEDIATELY on any defensive signal.
    const snippet = res.bodyText.slice(0, 4000);
    if (res.status === 429) {
      protectionSignals.push('HTTP 429 rate limiting');
      stopCondition = 'HTTP 429 rate limiting';
      break;
    }
    if (res.headers['retry-after']) {
      protectionSignals.push('Retry-After header');
      stopCondition = 'Retry-After header';
      break;
    }
    if (CAPTCHA_HINT_RE.test(snippet)) {
      protectionSignals.push('CAPTCHA/challenge presented');
      stopCondition = 'CAPTCHA/challenge presented';
      break;
    }
    if (LOCKOUT_HINT_RE.test(snippet)) {
      protectionSignals.push('account lockout message');
      stopCondition = 'account lockout message';
      break;
    }
    if (res.status === 403) {
      consecutive403++;
      if (consecutive403 >= MAX_CONSECUTIVE_403) {
        protectionSignals.push(`repeated HTTP 403 responses (${consecutive403} in a row)`);
        stopCondition = `repeated HTTP 403 responses (${consecutive403} in a row)`;
        break;
      }
    } else {
      consecutive403 = 0;
    }
  }

  const spent = http.limiter.getStats().requestsMade - before;
  const attemptedPlan = plan.slice(0, attempts);
  const protectionObserved = protectionSignals.length > 0;

  // --- Success finding (username only, never the password). ---
  if (succeededUser) {
    findings.push({
      id: nextId(),
      category: 'auth',
      mode: 'active',
      tags: ['auth', 'bruteforce', 'default-creds'],
      title: `Default credential accepted for user "${succeededUser}" (password redacted)`,
      description:
        `The login form accepted a credential from the ${succeededList} list on attempt ${attempts} of ${plan.length} ` +
        `(explicitly authorized, guardrailed test). The working password is never recorded — only the username is reported. ` +
        'This is a complete authentication bypass for that account. Per honeypot analysis, trivially-easy successes are also scored for trap probability.',
      severity: 'critical',
      confidence: 'high',
      confirmed: true,
      location: form.actionUrl,
      evidence: `accepted username "${succeededUser}" via ${succeededList} list, attempt ${attempts} (password value redacted)`,
      remediation:
        'Force a password change on first boot, disable or remove default accounts, and enforce unique per-installation credentials.',
      ...cvssFields('auth:default-credentials'),
      reproSteps: [
        `Open the login form at ${form.actionUrl}.`,
        `Submit username "${succeededUser}" with the documented default password for ${tech}.`,
        'Observe successful authentication (session established / redirected past login).',
      ],
      requestCount: attempts,
    });
  }

  // --- Summary finding: what was tested, protection, lockout risk, stop. ---
  const lockoutRisk = succeededUser
    ? 'Not applicable — a credential was accepted before any lockout signal; rotate the compromised credential and then verify lockout controls with failed-login tests.'
    : protectionObserved
      ? `HIGH if guessing had continued — the target began defending the endpoint after ${attempts} attempt(s) (${protectionSignals.join('; ')}), and testing stopped immediately per the guardrail. Continued guessing would risk locking the account.`
      : attempts >= MAX_BRUTE_FORCE_ATTEMPTS
        ? `Low for this test (${attempts} failed attempts produced no lockout), but the absence of any throttling means an attacker faces no friction — treat as missing brute-force protection. The test stopped at the ${MAX_BRUTE_FORCE_ATTEMPTS}-attempt hard cap.`
        : `Low for this test (${attempts} failed attempts produced no lockout), but the absence of any throttling means an attacker faces no friction — treat as missing brute-force protection.`;

  findings.push({
    id: nextId(),
    category: 'auth',
    mode: 'active',
    tags: [
      'auth',
      'bruteforce',
      protectionObserved ? 'bruteforce-protected' : 'no-bruteforce-protection',
    ],
    title: succeededUser
      ? `Brute-force test stopped — credential accepted after ${attempts} attempt(s)`
      : stopCondition && stopCondition !== 'credential accepted — stopped immediately'
        ? `Brute-force test stopped early after ${attempts} attempt(s) — ${stopCondition}`
        : `Brute-force test complete: ${attempts} attempt(s), no credential accepted`,
    description:
      `Guardrailed test against ${form.actionUrl} (detected stack: ${tech}). ` +
      `Tested ${attempts} attempt(s): ${attemptedPlan.length > 0 ? summarizeAttempted(attemptedPlan) : 'none'}. ` +
      (protectionObserved
        ? `Brute-force protection observed: ${protectionSignals.join('; ')}. `
        : 'No brute-force protection signals observed (no 429, CAPTCHA, Retry-After, or lockout message). ') +
      `Lockout risk assessment: ${lockoutRisk} ` +
      (stopCondition
        ? `Stop condition: ${stopCondition}.`
        : 'Stop condition: list exhausted — all planned attempts completed.'),
    severity: succeededUser || protectionObserved ? 'info' : 'low',
    confidence: 'high',
    confirmed: true,
    location: form.actionUrl,
    evidence:
      `attempts=${attempts} (${attemptedPlan.length > 0 ? summarizeAttempted(attemptedPlan) : 'none'}); ` +
      `stop=${stopCondition ?? 'list exhausted'}; ` +
      `protection=${protectionObserved ? protectionSignals.join('; ') : 'none observed'}`,
    remediation: protectionObserved
      ? 'No action needed. Keep lockout / throttling controls and monitor for credential-stuffing.'
      : 'Add progressive delays, account lockout or CAPTCHA after failed attempts, and rate limiting on the login endpoint. Remove or rotate any default credentials.',
    ...cvssFields(
      protectionObserved || succeededUser
        ? 'api:endpoint-discovered'
        : 'auth:brute-force-indicators',
    ),
    requestCount: Math.max(spent, attempts),
  });

  return { findings };
}

/**
 * Detection rules (Thread 5, DEFENSIVE), pure functions over events.
 *
 * Every rule takes an explicit window and threshold so tests can drive
 * them with crafted events and no clock. Rules return candidates; the
 * analyzer persists them. Nothing here reads the database or the clock.
 *
 * Thresholds are deliberately conservative (few false positives over
 * early warning): a single failed login is normal, ten in ten minutes
 * from one IP is not.
 */
import type {
  ApiKeyBaseline,
  DetectionCandidate,
  SecurityEvent,
} from './types.js';

export interface RuleOptions {
  /** Window end (usually "now"); windows look backwards from here. */
  now?: Date;
  /** Failed logins from one IP inside the window that fire the rule. */
  loginVelocityThreshold?: number;
  /** Failed logins for one account inside the window that fire the rule. */
  accountVelocityThreshold?: number;
  /** Distinct accounts sharing one password hash that fire the spray rule. */
  sprayAccountThreshold?: number;
  /** Distinct accounts from few IPs that fire the many-accounts rule. */
  manyAccountsThreshold?: number;
  /** Distinct user agents for one account that fire the diversity rule. */
  userAgentThreshold?: number;
  /** API-key uses in one hour that count as a volume spike. */
  apiKeyVolumeThreshold?: number;
  /** Distinct admin-path 404s from one IP that fire the probe rule. */
  probePathThreshold?: number;
  /** Requests carrying a known payload signature that fire the probe rule. */
  probeSignatureThreshold?: number;
}

const DEFAULTS: Required<RuleOptions> = {
  now: new Date(),
  loginVelocityThreshold: 10,
  accountVelocityThreshold: 5,
  sprayAccountThreshold: 5,
  manyAccountsThreshold: 10,
  userAgentThreshold: 5,
  apiKeyVolumeThreshold: 100,
  probePathThreshold: 5,
  probeSignatureThreshold: 3,
};

function inWindow(e: SecurityEvent, sinceMs: number): boolean {
  return Date.parse(e.at) >= sinceMs;
}

function groupBy<T>(items: T[], key: (t: T) => string | undefined): Map<string, T[]> {
  const out = new Map<string, T[]>();
  for (const item of items) {
    const k = key(item);
    if (k === undefined) continue;
    const list = out.get(k) ?? [];
    list.push(item);
    out.set(k, list);
  }
  return out;
}

/** Failed-login velocity, per IP and per account (10-minute window). */
export function failedLoginVelocityRule(
  events: SecurityEvent[],
  opts: RuleOptions = {},
): DetectionCandidate[] {
  const o = { ...DEFAULTS, ...opts, now: opts.now ?? DEFAULTS.now };
  const since = o.now.getTime() - 10 * 60_000;
  const failed = events.filter((e) => e.type === 'failed_login' && inWindow(e, since));
  const out: DetectionCandidate[] = [];

  for (const [ip, list] of groupBy(failed, (e) => e.ip)) {
    if (list.length >= o.loginVelocityThreshold) {
      out.push({
        pattern: 'failed-login-velocity',
        severity: list.length >= 25 ? 'high' : 'medium',
        title: `Failed-login velocity from ${ip}`,
        detail:
          `${list.length} failed logins from one IP in 10 minutes ` +
          `(threshold ${o.loginVelocityThreshold}). A steady drip is normal; this rate looks like guessing.`,
        evidence: `failed logins: ${list.length} in 10 min from ${ip}`,
        dedupeKey: `failed-login-velocity:ip:${ip}`,
      });
    }
  }
  for (const [account, list] of groupBy(failed, (e) => e.accountHash)) {
    if (list.length >= o.accountVelocityThreshold) {
      out.push({
        pattern: 'failed-login-velocity',
        severity: list.length >= 15 ? 'high' : 'medium',
        title: 'Failed-login velocity against one account',
        detail:
          `${list.length} failed logins against one account in 10 minutes ` +
          `(threshold ${o.accountVelocityThreshold}). The account may be targeted — or locked out by the time the owner notices.`,
        evidence: `failed logins: ${list.length} in 10 min for one account (hash ${account.slice(0, 12)}…)`,
        dedupeKey: `failed-login-velocity:account:${account}`,
      });
    }
  }
  return out;
}

/**
 * Password spray: one password hash across many accounts from one IP.
 * Detected by HASH EQUALITY only, plaintext passwords are never stored
 * or compared (see events.ts).
 */
export function passwordSprayRule(
  events: SecurityEvent[],
  opts: RuleOptions = {},
): DetectionCandidate[] {
  const o = { ...DEFAULTS, ...opts, now: opts.now ?? DEFAULTS.now };
  const since = o.now.getTime() - 60 * 60_000;
  const failed = events.filter(
    (e) => e.type === 'failed_login' && e.passwordHash && e.ip && inWindow(e, since),
  );
  const out: DetectionCandidate[] = [];
  for (const [ip, list] of groupBy(failed, (e) => e.ip)) {
    for (const [passwordHash, attempts] of groupBy(list, (e) => e.passwordHash)) {
      const accounts = new Set(attempts.map((e) => e.accountHash).filter(Boolean));
      if (accounts.size >= o.sprayAccountThreshold) {
        out.push({
          pattern: 'password-spray',
          severity: 'high',
          title: `Password-spray pattern from ${ip}`,
          detail:
            `The same attempted password (hash ${passwordHash.slice(0, 12)}…) was tried against ` +
            `${accounts.size} different accounts from one IP in the last hour. That is the signature of credential spraying, not a forgetful user.`,
          evidence: `one password hash × ${accounts.size} accounts from ${ip} in 1 h`,
          dedupeKey: `password-spray:${ip}:${passwordHash.slice(0, 16)}`,
        });
      }
    }
  }
  return out;
}

/** Many accounts attempted from few IPs (credential-stuffing shape). */
export function manyAccountsFewIpsRule(
  events: SecurityEvent[],
  opts: RuleOptions = {},
): DetectionCandidate[] {
  const o = { ...DEFAULTS, ...opts, now: opts.now ?? DEFAULTS.now };
  const since = o.now.getTime() - 60 * 60_000;
  const failed = events.filter((e) => e.type === 'failed_login' && e.accountHash && inWindow(e, since));
  const accounts = new Set(failed.map((e) => e.accountHash));
  const ips = new Set(failed.map((e) => e.ip).filter(Boolean));
  if (accounts.size >= o.manyAccountsThreshold && ips.size > 0 && ips.size <= 2) {
    return [
      {
        pattern: 'many-accounts-few-ips',
        severity: 'high',
        title: `${accounts.size} accounts probed from ${ips.size} IP(s)`,
        detail:
          `${accounts.size} different accounts saw failed logins from just ${ips.size} IP address(es) in the last hour. ` +
          'One user does not forget that many passwords — this looks like a credential list being worked through.',
        evidence: `${accounts.size} accounts × ${ips.size} IP(s) in 1 h`,
        dedupeKey: `many-accounts-few-ips:${[...ips].sort().join(',')}`,
      },
    ];
  }
  return [];
}

/** Unusual user-agent diversity for one account (session/account sharing or automation). */
export function userAgentDiversityRule(
  events: SecurityEvent[],
  opts: RuleOptions = {},
): DetectionCandidate[] {
  const o = { ...DEFAULTS, ...opts, now: opts.now ?? DEFAULTS.now };
  const since = o.now.getTime() - 60 * 60_000;
  const logins = events.filter(
    (e) => (e.type === 'login' || e.type === 'failed_login') && e.accountHash && e.userAgent && inWindow(e, since),
  );
  const out: DetectionCandidate[] = [];
  for (const [account, list] of groupBy(logins, (e) => e.accountHash)) {
    const agents = new Set(list.map((e) => e.userAgent));
    if (agents.size >= o.userAgentThreshold) {
      out.push({
        pattern: 'user-agent-diversity',
        severity: 'medium',
        title: 'Unusual user-agent diversity for one account',
        detail:
          `One account was seen with ${agents.size} distinct user agents in the last hour ` +
          `(threshold ${o.userAgentThreshold}). Either the credentials are shared, or something automated is cycling agents.`,
        evidence: `${agents.size} user agents for one account (hash ${account.slice(0, 12)}…) in 1 h`,
        dedupeKey: `user-agent-diversity:${account}`,
      });
    }
  }
  return out;
}

/**
 * API-key usage anomalies: a key used from a new IP, a volume spike, or
 * endpoints the key never used before. "New" is judged against the
 * baseline passed in; without a baseline only the volume check runs.
 */
export function apiKeyAnomalyRule(
  events: SecurityEvent[],
  baseline: ApiKeyBaseline | null,
  opts: RuleOptions = {},
): DetectionCandidate[] {
  const o = { ...DEFAULTS, ...opts, now: opts.now ?? DEFAULTS.now };
  const since = o.now.getTime() - 60 * 60_000;
  const uses = events.filter((e) => e.type === 'api_key_use' && e.apiKeyPrefix && inWindow(e, since));
  const out: DetectionCandidate[] = [];
  for (const [prefix, list] of groupBy(uses, (e) => e.apiKeyPrefix)) {
    if (list.length >= o.apiKeyVolumeThreshold) {
      out.push({
        pattern: 'api-key-anomaly',
        severity: 'medium',
        title: `Volume spike for API key ${prefix}`,
        detail:
          `Key ${prefix} was used ${list.length} times in the last hour (threshold ${o.apiKeyVolumeThreshold}). ` +
          'A spike can be legitimate traffic — or a leaked key being exercised.',
        evidence: `${list.length} uses in 1 h for key ${prefix}`,
        dedupeKey: `api-key-anomaly:volume:${prefix}`,
      });
    }
    if (baseline) {
      const knownIps = baseline.knownIpsByKey.get(prefix) ?? new Set<string>();
      const newIps = [...new Set(list.map((e) => e.ip).filter((ip): ip is string => Boolean(ip)))].filter(
        (ip) => !knownIps.has(ip),
      );
      if (knownIps.size > 0 && newIps.length > 0) {
        out.push({
          pattern: 'api-key-anomaly',
          severity: 'medium',
          title: `API key ${prefix} used from a new IP`,
          detail:
            `Key ${prefix} appeared from ${newIps.join(', ')}, address(es) it has never used before. ` +
            'If the owner did not travel or redeploy, treat the key as possibly leaked.',
          evidence: `new IP(s) for key ${prefix}: ${newIps.join(', ')}`,
          dedupeKey: `api-key-anomaly:new-ip:${prefix}:${newIps.sort().join(',')}`,
        });
      }
      const knownEndpoints = baseline.knownEndpointsByKey.get(prefix) ?? new Set<string>();
      const newEndpoints = [
        ...new Set(list.map((e) => e.endpoint).filter((ep): ep is string => Boolean(ep))),
      ].filter((ep) => !knownEndpoints.has(ep));
      if (knownEndpoints.size > 0 && newEndpoints.length > 0) {
        out.push({
          pattern: 'api-key-anomaly',
          severity: 'low',
          title: `API key ${prefix} used new endpoints`,
          detail:
            `Key ${prefix} called endpoint(s) it never used before: ${newEndpoints.join(', ')}. ` +
            'New endpoints can be a feature launch — or a key being explored for what it can reach.',
          evidence: `new endpoint(s) for key ${prefix}: ${newEndpoints.join(', ')}`,
          dedupeKey: `api-key-anomaly:new-endpoint:${prefix}:${newEndpoints.sort().join(',')}`,
        });
      }
    }
  }
  return out;
}

const ADMIN_PATH_RE = /\/(admin|wp-admin|phpmyadmin|console|dashboard|config|debug|actuator|\.env|login|signin)/i;
const PAYLOAD_SIGNATURE_RE =
  /(<script|union(\s|\+|%20)+select|\.\.\/|\.\.\\|%2e%2e|select(\s|\+|%20)+.+(\s|\+|%20)+from|\$\{|\{\{|\bOR\b(\s|\+|%20)+1=1)/i;

/** Probe patterns: repeated 404s on admin paths, known payload signatures in requests. */
export function probePatternRule(
  events: SecurityEvent[],
  opts: RuleOptions = {},
): DetectionCandidate[] {
  const o = { ...DEFAULTS, ...opts, now: opts.now ?? DEFAULTS.now };
  const since = o.now.getTime() - 60 * 60_000;
  const requests = events.filter((e) => e.type === 'request' && e.endpoint && e.ip && inWindow(e, since));
  const out: DetectionCandidate[] = [];

  for (const [ip, list] of groupBy(requests, (e) => e.ip)) {
    const admin404s = new Set(
      list.filter((e) => e.status === 404 && ADMIN_PATH_RE.test(e.endpoint ?? '')).map((e) => e.endpoint),
    );
    if (admin404s.size >= o.probePathThreshold) {
      out.push({
        pattern: 'probe-pattern',
        severity: 'medium',
        title: `Admin-path probing from ${ip}`,
        detail:
          `${admin404s.size} distinct admin-ish paths returned 404 for one IP in the last hour ` +
          `(${[...admin404s].slice(0, 5).join(', ')}${admin404s.size > 5 ? ', …' : ''}). Somebody is mapping the admin surface.`,
        evidence: `${admin404s.size} distinct admin paths → 404 from ${ip} in 1 h`,
        dedupeKey: `probe-pattern:admin:${ip}`,
      });
    }
    const sigHits = list.filter((e) => {
      // Paths arrive URL-encoded (%3Cscript%3E); decode before matching
      // so encoded payload shapes are caught too. Undecodable input is
      // tested as-is rather than dropped.
      let decoded = e.endpoint ?? '';
      try {
        decoded = decodeURIComponent(decoded);
      } catch {
        /* keep raw */
      }
      return PAYLOAD_SIGNATURE_RE.test(decoded);
    });
    if (sigHits.length >= o.probeSignatureThreshold) {
      out.push({
        pattern: 'probe-pattern',
        severity: 'high',
        title: `Known payload signatures in requests from ${ip}`,
        detail:
          `${sigHits.length} request(s) from one IP carried known attack-payload shapes in the path ` +
          `(script tags, SQL fragments, traversal, template expressions). Paths only — no query values were inspected.`,
        evidence: `${sigHits.length} signature-matching requests from ${ip} in 1 h`,
        dedupeKey: `probe-pattern:signature:${ip}`,
      });
    }
  }
  return out;
}

/** Run every rule over the events. Pure, no I/O. */
export function runAllRules(
  events: SecurityEvent[],
  baseline: ApiKeyBaseline | null = null,
  opts: RuleOptions = {},
): DetectionCandidate[] {
  return [
    ...failedLoginVelocityRule(events, opts),
    ...passwordSprayRule(events, opts),
    ...manyAccountsFewIpsRule(events, opts),
    ...userAgentDiversityRule(events, opts),
    ...apiKeyAnomalyRule(events, baseline, opts),
    ...probePatternRule(events, opts),
  ];
}

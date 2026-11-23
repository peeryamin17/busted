/**
 * Runtime detection layer: types. The layer watches BugSeek's own backend
 * first: it runs rules over security events the backend records (failed
 * logins, API-key uses, requests) and persists detections the site owner
 * can read back. Rule-based only: no new services, no new spend, no model
 * calls.
 *
 * Passwords are never stored, not even hashed without a pepper (see
 * events.ts). Account identifiers are stored as SHA-256 hashes; equality
 * is all the spray rules need. IPs in detections are the attacker's
 * address hitting the owner's backend, operational data the owner needs
 * to block them.
 */

export type DetectionPattern =
  | 'failed-login-velocity'
  | 'password-spray'
  | 'many-accounts-few-ips'
  | 'user-agent-diversity'
  | 'api-key-anomaly'
  | 'probe-pattern';

export type DetectionSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** One persisted detection (a rule firing, not a raw event). */
export interface DetectionRecord {
  id: string;
  userId: string;
  pattern: DetectionPattern;
  severity: DetectionSeverity;
  title: string;
  detail: string;
  /** Redacted evidence: counts, paths, key prefixes, IPs, never secrets. */
  evidence?: string;
  /** Dedupe key: pattern + the entity it fired on (IP / account hash / key prefix). */
  dedupeKey: string;
  createdAt: string; // ISO
}

export type SecurityEventType = 'failed_login' | 'login' | 'api_key_use' | 'request';

/**
 * One security event fed to the rules. Only the fields a rule needs;
 * values are never carried (paths only, key prefixes only, hashes only).
 */
export interface SecurityEvent {
  /** Owner whose backend produced the event (dogfood: the BugSeek user). */
  userId: string;
  type: SecurityEventType;
  at: string; // ISO
  /** Source address of the request. */
  ip?: string;
  /** SHA-256 hash of the account identifier (username/email), never the value. */
  accountHash?: string;
  /** Peppered SHA-256 of the attempted password, equality only, never plaintext. */
  passwordHash?: string;
  userAgent?: string;
  /** API-key prefix only (e.g. `bs_abc123`), never the key. */
  apiKeyPrefix?: string;
  /** Request path only, no query string, no values. */
  endpoint?: string;
  status?: number;
}

/** Baselines the API-key rules compare against (built from past events). */
export interface ApiKeyBaseline {
  /** IPs each key prefix has been seen from before. */
  knownIpsByKey: Map<string, Set<string>>;
  /** Endpoints each key prefix has used before. */
  knownEndpointsByKey: Map<string, Set<string>>;
}

/** A rule firing before persistence (no id / timestamps yet). */
export interface DetectionCandidate {
  pattern: DetectionPattern;
  severity: DetectionSeverity;
  title: string;
  detail: string;
  evidence?: string;
  dedupeKey: string;
}

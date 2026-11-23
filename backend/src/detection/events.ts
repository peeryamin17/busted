/**
 * Security-event intake: a bounded in-memory ring buffer plus hashing
 * helpers, for the rules to run on. When the process restarts the buffer
 * is gone.
 *
 * Wiring: call recordSecurityEvent from the login-failure paths, from
 * API-key auth, and from a request hook for 404/probe traffic. Until
 * wired, the rules run over whatever events exist, which may be none,
 * and analyzeEvents says so rather than inventing detections.
 *
 * Account identifiers and attempted passwords are stored as SHA-256
 * hashes with a server-side pepper (DETECTION_PEPPER, else a random
 * per-process pepper). A peppered hash of a weak password is still
 * dictionary-reversible in principle, so the buffer is treated as
 * sensitive: bounded, in-memory only, never logged, never returned
 * by any API. The rules need equality only.
 */
import { createHash, randomBytes } from 'node:crypto';
import type { SecurityEvent } from './types.js';

const PEPPER =
  process.env['DETECTION_PEPPER'] ?? randomBytes(16).toString('hex');

function sha256(value: string): string {
  return createHash('sha256').update(`${PEPPER}:${value}`).digest('hex');
}

/** Hash an account identifier (username/email) for equality-only matching. */
export function hashAccountId(accountId: string): string {
  return sha256(`account:${accountId.trim().toLowerCase()}`);
}

/** Hash an attempted password for spray detection. Plaintext is never kept. */
export function hashAttemptedPassword(password: string): string {
  return sha256(`password:${password}`);
}

const MAX_EVENTS = 10_000;
const events: SecurityEvent[] = [];

/** Append an event; oldest events drop off past the bound. */
export function recordSecurityEvent(event: SecurityEvent): void {
  events.push(event);
  if (events.length > MAX_EVENTS) events.splice(0, events.length - MAX_EVENTS);
}

/** Events for one owner, newest last, optionally since an ISO timestamp. */
export function listSecurityEvents(userId: string, sinceIso?: string): SecurityEvent[] {
  return events.filter(
    (e) => e.userId === userId && (sinceIso === undefined || e.at >= sinceIso),
  );
}

/** Test seam: clear the in-memory buffer. */
export function clearSecurityEvents(): void {
  events.length = 0;
}

/** Current buffer size (for the "no events yet" honest-empty state). */
export function securityEventCount(userId?: string): number {
  return userId === undefined
    ? events.length
    : events.filter((e) => e.userId === userId).length;
}

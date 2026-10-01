/**
 * In-memory OAST callback store — Phase 3 scaffolding.
 *
 * The production OAST listener (separate always-on infra, see docs/oast.md)
 * POSTs observed DNS/HTTP hits to /api/oast/callback; they land here keyed by
 * canary hostname. CallbacksForScan correlates them back to a scan via the
 * scan-id prefix embedded in the canary.
 *
 * Production TODO: replace with a proper table (oast_callbacks) so hits
 * survive restarts and are queryable per user.
 */

export interface OastCallback {
  canary: string;
  kind: 'dns' | 'http';
  /** IP that resolved/requested the canary (the target's egress, not the user). */
  sourceIp?: string;
  path?: string;
  userAgent?: string;
  observedAt: string; // ISO
}

const callbacks: OastCallback[] = [];
const MAX_STORED = 10_000;

export function recordCallback(cb: Omit<OastCallback, 'observedAt'> & { observedAt?: string }): OastCallback {
  const full: OastCallback = {
    ...cb,
    observedAt: cb.observedAt ?? new Date().toISOString(),
  };
  callbacks.push(full);
  if (callbacks.length > MAX_STORED) callbacks.splice(0, callbacks.length - MAX_STORED);
  return full;
}

/** All callbacks whose canary starts with this scan's id prefix. */
export function callbacksForScan(scanId: string): OastCallback[] {
  const prefix = scanId.replace(/[^a-z0-9]/gi, '').slice(0, 8).toLowerCase();
  if (!prefix) return [];
  return callbacks.filter((c) => c.canary.toLowerCase().startsWith(prefix + '-'));
}

export function callbacksForCanary(canary: string): OastCallback[] {
  return callbacks.filter((c) => c.canary === canary);
}

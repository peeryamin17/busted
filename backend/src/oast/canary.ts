import { randomBytes } from 'node:crypto';

/**
 * OAST (out-of-band security testing) canary hostnames — Phase 3 scaffolding.
 *
 * A canary is a unique hostname per scan, e.g. `a1b2c3d4-9f8e.oast.example.com`.
 * Blind-payload probes embed the canary; if the target's backend ever resolves
 * or requests it, the OAST listener records the callback and it becomes a
 * high-severity finding ("blind XSS/SSRF confirmed out-of-band").
 *
 * INFRA TODO: OAST_DOMAIN must point at infrastructure you operate (wildcard
 * DNS + DNS/HTTP listeners — see docs/oast.md). Until then canaries generate
 * fine but are inert: nothing listens for them.
 */

export function oastDomain(): string {
  return process.env['OAST_DOMAIN'] ?? 'oast.example.invalid';
}

/** Unique canary hostname for a scan. The scan id prefix enables correlation. */
export function generateCanary(scanId: string): string {
  const short =
    scanId.replace(/[^a-z0-9]/gi, '').slice(0, 8).toLowerCase() || 'scan';
  const rand = randomBytes(4).toString('hex');
  return `${short}-${rand}.${oastDomain()}`;
}

/** True when OAST_DOMAIN looks like real, operator-owned infrastructure. */
export function oastConfigured(): boolean {
  const d = oastDomain();
  return d !== 'oast.example.invalid' && d.includes('.');
}

/**
 * Key-trail correlation (API-key bloodhound).
 *
 * When the same key fingerprint shows up in more than one place, a JS
 * bundle, a source map, a storage key, a request, this links the
 * sightings into one ordered "trail" per fingerprint, so a report shows
 * where a key lives and where it travels instead of N disconnected
 * findings. Trails carry the redacted fingerprint only
 * (`provider:first4…last4`); the full value is never stored, logged,
 * or rendered here.
 *
 * Limits: traffic correlation is name-based only. The traffic log
 * records parameter names, never values, and no request headers, so a
 * traffic step means "a key-shaped parameter/header name was sent to a
 * host where this fingerprint was also seen", not "this exact key was
 * observed in transit". Every traffic step says so and carries
 * `valueMatched: false`. Header and WebSocket observations can only
 * arrive as explicit `TrafficKeyUse` inputs from a caller that
 * actually observed them; none exists yet, so trails currently hold
 * discovery/storage steps plus query-param steps. No found key is ever
 * validated against a provider API.
 */
import type { Finding } from '../lib/types';

export type TrailChannel = 'query-param' | 'header' | 'websocket' | 'cookie' | 'storage';

/** One place a key fingerprint was seen at rest (code, map, or storage). */
export interface KeySighting {
  /** Redacted fingerprint: `provider:first4…last4`. Never a full value. */
  fingerprint: string;
  provider: string;
  location: string;
  kind: 'discovered' | 'stored';
  entropyScore?: number;
}

/** One observed use of a key-shaped name in traffic (names only, never values). */
export interface TrafficKeyUse {
  url: string;
  host: string;
  path: string;
  method: string;
  channel: TrailChannel;
  /** The parameter / header / field NAME that carried it, e.g. `api_key`. */
  name: string;
  timeStamp?: number;
}

export interface TrailStep {
  text: string;
  channel: TrailChannel | 'discovered' | 'stored';
  /**
   * Always false for traffic steps: the traffic log never records values,
   * so a value-level match is impossible by design. True only for a
   * discovery/storage step, where the fingerprint itself was computed
   * from the found value.
   */
  valueMatched: boolean;
}

export interface KeyTrail {
  fingerprint: string;
  provider: string;
  entropyScore?: number;
  steps: TrailStep[];
  /** Distinct locations, in first-seen order. */
  locations: string[];
}

/** Parameter / header names that suggest a credential is being carried. */
export const KEY_LIKE_NAME_RE =
  /^(api[_-]?key|apikey|access[_-]?token|id[_-]?token|auth|authorization|token|secret|x-api-key|x-auth-token|session|sid)$/i;

/**
 * Convert stored traffic entries into key-use observations. Only entries
 * whose parameter NAMES look key-shaped produce an observation; values
 * were never recorded, so none is consulted here.
 *
 * Accepts the structural shape of TrafficEntry (url/host/path/paramNames)
 * rather than importing the active traffic module.
 */
export function trafficUsesFromEntries(
  entries: Array<{ url: string; host: string; path: string; method: string; paramNames: string[]; timeStamp?: number }>,
): TrafficKeyUse[] {
  const uses: TrafficKeyUse[] = [];
  for (const e of entries) {
    for (const name of e.paramNames ?? []) {
      if (!KEY_LIKE_NAME_RE.test(name)) continue;
      uses.push({
        url: e.url,
        host: e.host,
        path: e.path,
        method: e.method,
        channel: 'query-param',
        name,
        timeStamp: e.timeStamp,
      });
    }
  }
  return uses;
}

/** Best-effort host extraction from a finding location (URL or free-text label). */
export function hostOfLocation(location: string): string {
  try {
    return new URL(location).hostname;
  } catch {
    const m = location.match(/([a-z0-9][a-z0-9.-]+\.[a-z]{2,})/i);
    return m ? m[1].toLowerCase() : '';
  }
}

/**
 * Build one trail per fingerprint. Discovery/storage sightings come first
 * (in the order supplied); a traffic use joins a trail only when its host
 * matches a host where that fingerprint was seen at rest, same-site
 * correlation, so a key found on example.com is never linked to an
 * `api_key` param sent to an unrelated host.
 */
export function buildTrails(sightings: KeySighting[], trafficUses: TrafficKeyUse[] = []): KeyTrail[] {
  const byFingerprint = new Map<string, KeyTrail>();

  for (const s of sightings) {
    let trail = byFingerprint.get(s.fingerprint);
    if (!trail) {
      trail = { fingerprint: s.fingerprint, provider: s.provider, steps: [], locations: [] };
      byFingerprint.set(s.fingerprint, trail);
    }
    if (s.entropyScore !== undefined && trail.entropyScore === undefined) {
      trail.entropyScore = s.entropyScore;
    }
    const text =
      s.kind === 'stored' ? `stored at ${s.location}` : `discovered in ${s.location}`;
    if (!trail.steps.some((st) => st.text === text)) {
      trail.steps.push({ text, channel: s.kind, valueMatched: true });
    }
    if (!trail.locations.includes(s.location)) trail.locations.push(s.location);
  }

  const seenTraffic = new Set<string>();
  for (const use of trafficUses) {
    const dedupeKey = `${use.channel}:${use.name}:${use.url}`;
    if (seenTraffic.has(dedupeKey)) continue;
    seenTraffic.add(dedupeKey);

    for (const trail of byFingerprint.values()) {
      const hosts = trail.locations.map(hostOfLocation).filter(Boolean);
      if (hosts.length > 0 && !hosts.includes(use.host.toLowerCase())) continue;
      // A trail with no parseable host cannot be attributed to any traffic.
      if (hosts.length === 0) continue;
      const where = `${use.method} ${use.host}${use.path}`;
      const text =
        use.channel === 'query-param'
          ? `sent as query param "${use.name}" to ${where} (name-based correlation — the key value was never observed in transit)`
          : use.channel === 'header'
            ? `sent in "${use.name}" header to ${where} (name-based correlation — the key value was never observed in transit)`
            : use.channel === 'websocket'
              ? `sent in WebSocket message field "${use.name}" to ${where} (name-based correlation — the key value was never observed in transit)`
              : `sent via ${use.channel} "${use.name}" to ${where} (name-based correlation — the key value was never observed in transit)`;
      if (!trail.steps.some((st) => st.text === text)) {
        trail.steps.push({ text, channel: use.channel, valueMatched: false });
      }
    }
  }

  return [...byFingerprint.values()];
}

/** Pull sightings out of secret findings (findings without a fingerprint are skipped). */
export function sightingsFromFindings(findings: Finding[]): KeySighting[] {
  return findings
    .filter((f): f is Finding & { fingerprint: string } => typeof f.fingerprint === 'string')
    .map((f) => ({
      fingerprint: f.fingerprint,
      provider: f.secretProvider ?? 'unknown',
      location: f.location ?? 'unknown location',
      kind: (f.location ?? '').includes('key "') || (f.location ?? '').includes('cookie "')
        ? ('stored' as const)
        : ('discovered' as const),
      entropyScore: f.entropyScore,
    }));
}

/**
 * Attach each trail's ordered steps to the findings that share its
 * fingerprint (as `finding.trail`, the string list the report renders).
 * Findings with no trail keep the single-step trail the scanners set.
 */
export function attachTrailsToFindings(findings: Finding[], trails: KeyTrail[]): void {
  const byFingerprint = new Map(trails.map((t) => [t.fingerprint, t]));
  for (const f of findings) {
    if (!f.fingerprint) continue;
    const trail = byFingerprint.get(f.fingerprint);
    if (!trail || trail.steps.length <= 1) continue;
    f.trail = trail.steps.map((s) => s.text);
    if (f.entropyScore === undefined && trail.entropyScore !== undefined) {
      f.entropyScore = trail.entropyScore;
    }
  }
}

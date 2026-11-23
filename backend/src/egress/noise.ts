import { TokenBucketRateLimiter } from '../guardrails/ratelimit.js';

/**
 * Noise governor, named per-host egress profiles for active testing.
 *
 * Active probing should be polite: a scan that hammers one host looks like
 * (and can act like) a denial-of-service attempt, trips rate limits, and
 * burns the findings on 429s. The governor sits in the guardedFetch path
 * and paces each host independently:
 *
 *   - per-host token buckets (one TokenBucketRateLimiter per hostname),
 *   - per-host in-flight caps (FIFO semaphore, so bursts queue instead of
 *     piling onto the target),
 *   - jitter between acquiring a token and sending, so workers do not
 *     synchronise into lock-step request waves,
 *   - Retry-After backoff: a 429/503 with a Retry-After header is honoured
 *     once for read-only methods, never for writes,
 *   - GET coalescing: identical in-flight GETs share one underlying fetch.
 *
 * Counters are per governor instance (one instance per task run), never
 * global, so a run's `[noise]` summary describes exactly that run.
 *
 * The `off` profile passes through completely: no token wait, no jitter,
 * no in-flight cap, no Retry-After retry, no coalescing. Scope checks,
 * the SSRF guard and the shared global rate limiter live outside this
 * module and are unaffected by the profile.
 */

export type NoiseProfileName = 'off' | 'quiet' | 'balanced' | 'aggressive';

export interface NoiseProfile {
  /** Sustained requests per second, per host. 0 for `off` (no bucket). */
  rps: number;
  /** Token bucket capacity, per host. */
  burst: number;
  /** Max requests in flight to one host at the same time. */
  maxInFlight: number;
  /** Upper bound of the random pre-send jitter, in ms. */
  jitterMs: number;
}

export const NOISE_PROFILES: Record<NoiseProfileName, NoiseProfile> = {
  off: { rps: 0, burst: 0, maxInFlight: Infinity, jitterMs: 0 },
  quiet: { rps: 2, burst: 4, maxInFlight: 1, jitterMs: 250 },
  balanced: { rps: 5, burst: 10, maxInFlight: 2, jitterMs: 250 },
  aggressive: { rps: 20, burst: 40, maxInFlight: 4, jitterMs: 250 },
};

/** Default for active testing. */
export const DEFAULT_NOISE_PROFILE: NoiseProfileName = 'balanced';

/**
 * Parse a profile name from a request parameter. Case-insensitive, trims
 * surrounding whitespace. Anything unknown, empty or missing falls back to
 * 'balanced'; 'off' is only honoured when explicitly requested.
 */
export function parseNoiseProfile(value: string | undefined): NoiseProfileName {
  const v = value?.trim().toLowerCase();
  if (v === 'off' || v === 'quiet' || v === 'balanced' || v === 'aggressive') return v;
  return 'balanced';
}

export interface NoiseHostCounters {
  /** Calls that acquired a token + slot (or passed through under `off`). */
  acquired: number;
  /** Acquires where the governor made the caller wait (token, slot, jitter). */
  delayed: number;
  /** Callers that shared an in-flight GET instead of sending their own. */
  coalesced: number;
  /** Requests retried once after honouring a Retry-After header. */
  retriedAfter429: number;
}

function emptyCounters(): NoiseHostCounters {
  return { acquired: 0, delayed: 0, coalesced: 0, retriedAfter429: 0 };
}

export interface NoiseGovernorOptions {
  /** Random source in [0, 1) for jitter; inject a fixed value in tests. */
  random?: () => number;
  /** Sleep implementation; inject a fake clock in tests. */
  sleep?: (ms: number) => Promise<void>;
}

/** Methods that may be retried after a 429/503: read-only probes only. */
const RETRYABLE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/** Longest Retry-After backoff honoured, in ms (60 s). */
export const MAX_RETRY_AFTER_MS = 60_000;

/**
 * Parse a Retry-After header value to a delay in ms, capped at 60 s.
 * Accepts delay-seconds ("120") or an HTTP date. Returns null when the
 * header is absent, empty or unparseable, callers treat that as "do not
 * retry" rather than guessing a delay.
 */
export function parseRetryAfterMs(value: string | null): number | null {
  if (value === null) return null;
  const v = value.trim();
  if (v === '') return null;
  if (/^\d+$/.test(v)) return Math.min(Number(v) * 1000, MAX_RETRY_AFTER_MS);
  const at = Date.parse(v);
  if (Number.isNaN(at)) return null;
  return Math.min(Math.max(at - Date.now(), 0), MAX_RETRY_AFTER_MS);
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return 'unknown';
  }
}

interface SlotState {
  inFlight: number;
  /** FIFO queue of waiters; each resolver hands the slot straight over. */
  queue: Array<() => void>;
}

export class NoiseGovernor {
  readonly profileName: NoiseProfileName;
  readonly profile: NoiseProfile;
  private readonly buckets = new Map<string, TokenBucketRateLimiter>();
  private readonly slots = new Map<string, SlotState>();
  private readonly inflightGets = new Map<string, Promise<Response>>();
  private readonly counters = new Map<string, NoiseHostCounters>();
  private readonly random: () => number;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(profile: NoiseProfileName = 'balanced', opts: NoiseGovernorOptions = {}) {
    this.profileName = profile;
    this.profile = NOISE_PROFILES[profile];
    this.random = opts.random ?? Math.random;
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  }

  private counterFor(host: string): NoiseHostCounters {
    let c = this.counters.get(host);
    if (!c) {
      c = emptyCounters();
      this.counters.set(host, c);
    }
    return c;
  }

  private bucketFor(host: string): TokenBucketRateLimiter {
    let b = this.buckets.get(host);
    if (!b) {
      b = new TokenBucketRateLimiter(this.profile.rps, this.profile.burst);
      this.buckets.set(host, b);
    }
    return b;
  }

  private slotFor(host: string): SlotState {
    let s = this.slots.get(host);
    if (!s) {
      s = { inFlight: 0, queue: [] };
      this.slots.set(host, s);
    }
    return s;
  }

  /**
   * Wait for a token from the host's bucket and a free in-flight slot, then
   * apply jitter before the caller sends. Under `off` this returns at once.
   * Every successful acquire MUST be matched by a `release(host)` in a
   * `finally` block, or the host's slot leaks and later requests queue
   * forever.
   */
  async acquire(host: string): Promise<void> {
    const c = this.counterFor(host);
    c.acquired++;
    if (this.profileName === 'off') return;

    const slotWaited = await this.takeSlot(host);
    // The token bucket's minimum sleep is 10 ms, so a real token wait is
    // comfortably above this threshold; a same-millisecond straddle is not
    // counted as a delay.
    const beforeToken = Date.now();
    await this.bucketFor(host).take();
    const tokenWaited = Date.now() - beforeToken > 5;

    const jitterMs = Math.floor(this.random() * this.profile.jitterMs);
    if (jitterMs > 0) await this.sleep(jitterMs);

    if (slotWaited || tokenWaited || jitterMs > 0) c.delayed++;
  }

  /**
   * Free one in-flight slot for the host. If requests are queued, the slot
   * passes directly to the head of the queue (FIFO); otherwise the
   * in-flight count drops. Safe to call for a host with no state.
   */
  release(host: string): void {
    if (this.profileName === 'off') return;
    const s = this.slots.get(host);
    if (!s) return;
    const next = s.queue.shift();
    if (next) {
      next();
      return;
    }
    s.inFlight = Math.max(0, s.inFlight - 1);
  }

  /** Take an in-flight slot, queueing FIFO when the host is at its cap. */
  private takeSlot(host: string): Promise<boolean> {
    const s = this.slotFor(host);
    if (s.inFlight < this.profile.maxInFlight) {
      s.inFlight++;
      return Promise.resolve(false);
    }
    return new Promise<boolean>((resolve) => {
      s.queue.push(() => resolve(true));
    });
  }

  /**
   * One governed request: acquire a token + slot for the request's host,
   * run `doFetch`, honour a Retry-After retry once for read-only methods,
   * and release the slot in a `finally` (even when the fetch throws).
   * The retry reuses the same slot and token, it is part of the same
   * logical request, not a second request. No coalescing here: that lives
   * in `coalescedGet`, applied once per logical request on the original
   * URL, so redirect hops are never coalesced against each other.
   */
  async fetch(
    url: string,
    init: GovernedFetchInit,
    doFetch: (url: string, init: GovernedFetchInit) => Promise<Response>,
  ): Promise<Response> {
    const method = (init?.method ?? 'GET').toUpperCase();
    const host = hostOf(url);
    await this.acquire(host);
    try {
      let res = await doFetch(url, init ?? {});
      if (
        this.profileName !== 'off' &&
        (res.status === 429 || res.status === 503) &&
        RETRYABLE_METHODS.has(method)
      ) {
        const delayMs = parseRetryAfterMs(res.headers.get('retry-after'));
        if (delayMs !== null) {
          // Drain the 429/503 body so the connection can be reused, then
          // back off and retry exactly once. A second 429/503 is returned
          // as-is, the target has said no twice, so stop asking.
          await res.arrayBuffer().catch(() => undefined);
          this.counterFor(host).retriedAfter429++;
          await this.sleep(delayMs);
          res = await doFetch(url, init ?? {});
        }
      }
      return res;
    } finally {
      this.release(host);
    }
  }

  /**
   * GET coalescing: while `fn()` is still in flight for this exact URL
   * string, further callers share its promise instead of running `fn()`
   * again. Each caller gets its own `Response.clone()`, so every consumer
   * can read the body independently. Only identical URL strings coalesce;
   * sequential (non-overlapping) calls never share, and a failed shared
   * fetch rejects all waiters and clears the entry, failures are never
   * cached and never poison the next identical GET.
   */
  async coalescedGet(url: string, fn: () => Promise<Response>): Promise<Response> {
    if (this.profileName === 'off') return fn();
    const existing = this.inflightGets.get(url);
    if (existing) {
      this.counterFor(hostOf(url)).coalesced++;
      return (await existing).clone();
    }
    const shared = fn();
    this.inflightGets.set(url, shared);
    try {
      return (await shared).clone();
    } finally {
      if (this.inflightGets.get(url) === shared) this.inflightGets.delete(url);
    }
  }

  /** Per-host counters for this governor instance (copies, not live refs). */
  getCounters(): Record<string, NoiseHostCounters> {
    const out: Record<string, NoiseHostCounters> = {};
    for (const [host, c] of this.counters) out[host] = { ...c };
    return out;
  }

  /** One `[noise]` summary line per host, for the end of a task run. */
  logCounters(): void {
    if (this.counters.size === 0) {
      console.info('[noise] no requests governed');
      return;
    }
    for (const [host, c] of this.counters) {
      console.info(
        `[noise] ${host}: acquired=${c.acquired} delayed=${c.delayed} ` +
          `coalesced=${c.coalesced} retriedAfter429=${c.retriedAfter429}`,
      );
    }
  }
}

export interface GovernedFetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

/**
 * Standalone hook for the guardedFetch integration: one governed request
 * (token + slot + jitter + a single Retry-After retry). Prefer this over
 * calling `acquire`/`release` directly, the `finally` is already handled.
 */
export async function fetchWithGovernor(
  governor: NoiseGovernor,
  url: string,
  init: GovernedFetchInit,
  doFetch: (url: string, init: GovernedFetchInit) => Promise<Response>,
): Promise<Response> {
  return governor.fetch(url, init, doFetch);
}

/**
 * Standalone hook for GET coalescing at the guardedFetch entry point.
 * Key on the ORIGINAL url string only, never on a redirect hop.
 */
export async function coalescedGet(
  governor: NoiseGovernor,
  url: string,
  fn: () => Promise<Response>,
): Promise<Response> {
  return governor.coalescedGet(url, fn);
}

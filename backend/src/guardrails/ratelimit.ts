import { createHash } from 'node:crypto';

/**
 * LEGAL GUARDRAIL — rate limiting on ALL active requests (product plan §8).
 *
 * The tool should never send enough requests to impact the target's
 * availability. Every active-testing tool acquires a token before sending a
 * request. Default is AGENT_REQUESTS_PER_SECOND (2/s); configurable per scan
 * via the scope policy.
 */
export class TokenBucketRateLimiter {
  private tokens: number;
  private lastRefill: number;

  constructor(
    private readonly requestsPerSecond: number,
    private readonly burst: number = 1
  ) {
    if (requestsPerSecond <= 0) throw new Error('requestsPerSecond must be > 0');
    this.tokens = burst;
    this.lastRefill = Date.now();
  }

  private refill(): void {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    this.tokens = Math.min(this.burst, this.tokens + elapsed * this.requestsPerSecond);
    this.lastRefill = now;
  }

  /** Resolves when a token is available. Never rejects. */
  async take(): Promise<void> {
    for (;;) {
      this.refill();
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      const waitMs = Math.ceil((1 - this.tokens) / this.requestsPerSecond * 1000);
      await new Promise((r) => setTimeout(r, Math.max(waitMs, 10)));
    }
  }
}

/**
 * LEGAL GUARDRAIL, failed API-key authentication attempts (login equivalent).
 *
 * Counts FAILED `bs_` API-key authentications only. Successful
 * authentications are never throttled: the extension polls legitimately, and
 * breaking that would be a regression. After `maxFailures` failures from one
 * bucket inside `windowMs`, further attempts with a `bs_` key are rejected
 * with 429 until the window passes.
 *
 * Two buckets are tracked per failure, so neither rotation axis escapes the
 * limit on its own: one per client IP, and one per key fingerprint (SHA-256
 * prefix of the presented key, never the key itself).
 *
 * In-memory and per-process, like the existing queue behaviour: on Render
 * each instance keeps its own counters, so the limit is per instance, not
 * global. That is acceptable for a login-equivalent abuse brake, not a
 * billing-grade quota.
 */
export class FailedAuthRateLimiter {
  private readonly attempts = new Map<string, number[]>();

  constructor(
    private readonly maxFailures: number = 10,
    private readonly windowMs: number = 60_000,
    private readonly now: () => number = Date.now,
  ) {
    if (maxFailures <= 0) throw new Error('maxFailures must be > 0');
    if (windowMs <= 0) throw new Error('windowMs must be > 0');
  }

  private prune(key: string): number[] {
    const cutoff = this.now() - this.windowMs;
    const kept = (this.attempts.get(key) ?? []).filter((t) => t > cutoff);
    if (kept.length === 0) this.attempts.delete(key);
    else this.attempts.set(key, kept);
    return kept;
  }

  /** True once `maxFailures` failures landed in this bucket inside the window. */
  isLimited(key: string): boolean {
    return this.prune(key).length >= this.maxFailures;
  }

  /** Whole seconds until the oldest failure in this bucket ages out (0 if not limited). */
  retryAfterSeconds(key: string): number {
    const kept = this.prune(key);
    if (kept.length < this.maxFailures) return 0;
    return Math.max(1, Math.ceil((kept[0]! + this.windowMs - this.now()) / 1000));
  }

  /** Record one failed authentication in this bucket. */
  recordFailure(key: string): void {
    const kept = this.prune(key);
    kept.push(this.now());
    this.attempts.set(key, kept);
  }

  /** A success clears the bucket: a legitimate user who mistyped, then got the key right, is not punished. */
  recordSuccess(key: string): void {
    this.attempts.delete(key);
  }

  /** Test/support hook: drop every bucket. */
  reset(): void {
    this.attempts.clear();
  }
}

/** Shared limiter for the `bs_` API-key path (10 failures / 60 s per bucket). */
export const apiKeyAuthFailures = new FailedAuthRateLimiter();

/**
 * Client IP, following the convention already used in src/routes/webcheck.ts:
 * the first hop of `X-Forwarded-For` when present, else Fastify's
 * `request.ip` (the socket peer, no `trustProxy` is configured in
 * src/server.ts, so Fastify itself never trusts the header). No new
 * proxy-trust behaviour is introduced here; a spoofed first hop can only
 * burn that spoofed address's own budget, never anyone else's.
 */
export function clientIp(request: {
  ip?: string;
  headers: Record<string, string | string[] | undefined>;
}): string {
  const xff = request.headers['x-forwarded-for'];
  const firstHop = (Array.isArray(xff) ? xff[0] : xff)?.split(',')[0]?.trim();
  return firstHop || request.ip || 'unknown';
}

/** Short, non-reversible fingerprint of a presented API key (SHA-256 hex, first 16 chars). */
export function apiKeyFingerprint(apiKey: string): string {
  return createHash('sha256').update(apiKey).digest('hex').slice(0, 16);
}

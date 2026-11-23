import type { Database } from '../db/db.js';
import type { PlanTier } from '../types.js';

/**
 * Plan tiers per the product plan (§6.1) and business plan (§3, credit-metered).
 * Quotas are enforced at scan creation; feature gating (active testing, API
 * access, report formats) is enforced on the relevant endpoints.
 *
 * Credits are the billing unit: 1 credit = one passive recon scan,
 * 25 credits = one guided active agent scan. This protects margin, an
 * active scan costs ~65x a passive one in LLM spend (business plan §3.1).
 */
export interface PlanQuota {
  creditsPerMonth: number; // Infinity = unlimited
  activeTesting: boolean;
  apiAccess: boolean;
  reportFormats: Array<'md' | 'json' | 'pdf' | 'docx' | 'csv'>;
}

/** Credits consumed by one scan of the given mode. */
export const SCAN_CREDIT_COST = { passive: 1, active: 25 } as const;

export const PLAN_QUOTAS: Record<PlanTier, PlanQuota> = {
  free: {
    creditsPerMonth: 50,
    activeTesting: false,
    apiAccess: false,
    reportFormats: ['md', 'json'],
  },
  hunter: {
    creditsPerMonth: 300,
    activeTesting: true,
    apiAccess: false,
    reportFormats: ['md', 'json', 'pdf', 'docx', 'csv'],
  },
  pro: {
    creditsPerMonth: 1500,
    activeTesting: true,
    apiAccess: true,
    reportFormats: ['md', 'json', 'pdf', 'docx', 'csv'],
  },
  enterprise: {
    creditsPerMonth: Number.POSITIVE_INFINITY,
    activeTesting: true,
    apiAccess: true,
    reportFormats: ['md', 'json', 'pdf', 'docx', 'csv'],
  },
};

export function monthStartIso(now: Date = new Date()): string {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)).toISOString();
}

// ── Per-call LLM token accounting ───────────────────
// One row per LLM call in llm_usage: provider-native token counts
// (input/output plus the cache-read/cache-write split), latency, and
// ok/error status, keyed by provider + model + tier. No price tables:
// cost is tracked in provider-native tokens only.
//
// The opt-in wire trace (LLM_WIRE_TRACE=1) stores redacted request /
// response bodies in llm_wire_traces, bounded per attempt and capped at
// 8 attempts retained per user (oldest deleted on insert).

/** Max wire-trace body size per attempt (1 MiB). */
export const LLM_WIRE_TRACE_MAX_BYTES = 1024 * 1024;
/** Max wire-trace attempts retained per user. */
export const LLM_WIRE_TRACE_MAX_ATTEMPTS = 8;

export interface LlmUsageEntry {
  userId?: string | null;
  provider: string;
  model: string;
  tier?: 'routine' | 'reasoning' | 'code';
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens?: number;
  cacheWriteTokens?: number;
  latencyMs?: number;
  status?: 'ok' | 'error';
  trace?: { request?: string; response?: string };
}

/** Strip key material from a wire body before it is ever stored. */
export function redactWireBody(body: string): string {
  let out = body;
  // Authorization / x-api-key headers, JSON or raw header-line form.
  out = out.replace(/"authorization"\s*:\s*"[^"]*"/gi, '"authorization": "[REDACTED]"');
  out = out.replace(/"x-api-key"\s*:\s*"[^"]*"/gi, '"x-api-key": "[REDACTED]"');
  out = out.replace(/^(authorization\s*:\s*).*$/gim, '$1[REDACTED]');
  out = out.replace(/^(x-api-key\s*:\s*).*$/gim, '$1[REDACTED]');
  // Bearer tokens anywhere else in the body.
  out = out.replace(/Bearer\s+[A-Za-z0-9\-._~+/=]{8,}/gi, 'Bearer [REDACTED]');
  // Google API keys (AIza…) and the current AQ.-prefixed AI Studio auth
  // keys, GitHub / Slack / GitLab tokens, OpenAI project keys, and bare
  // AWS secrets (40 mixed-case base64 chars, no key name next to them).
  out = out.replace(/AIza[0-9A-Za-z\-_]{20,}/g, '[REDACTED:google-api-key]');
  out = out.replace(/\bAQ\.[A-Za-z0-9_\-]{20,}\b/g, '[REDACTED:google-auth-key]');
  out = out.replace(/\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g, '[REDACTED:github-token]');
  out = out.replace(/\bxox[baprs]-[0-9A-Za-z-]{10,}/g, '[REDACTED:slack-token]');
  out = out.replace(/\bgl(?:pat|dt|rt)-[A-Za-z0-9\-_]{20}\b/g, '[REDACTED:gitlab-token]');
  out = out.replace(/\bsk-proj-[A-Za-z0-9\-_]{20,}\b/g, '[REDACTED:api-key]');
  // OpenAI-style keys (sk-…, sk_live_…).
  out = out.replace(/\bsk_(live|test)_[A-Za-z0-9]{16,}/g, '[REDACTED:api-key]');
  out = out.replace(/\bsk-(?:proj-|live-|test-)?[A-Za-z0-9\-_]{16,}/g, '[REDACTED:api-key]');
  // Bare AWS secrets last: the sk- shapes above must go first, or this
  // pattern would match only the body of a sk- key and leave its prefix.
  out = out.replace(
    /(?<![A-Za-z0-9/+=])(?=[A-Za-z0-9/+=]*[A-Z])(?=[A-Za-z0-9/+=]*[a-z])(?=[A-Za-z0-9/+=]*[0-9])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    '[REDACTED:aws-secret]',
  );
  return out;
}

/** Bound a wire body to the per-attempt byte cap (redaction runs first). */
export function boundWireBody(body: string): string {
  const redacted = redactWireBody(body);
  if (Buffer.byteLength(redacted, 'utf8') <= LLM_WIRE_TRACE_MAX_BYTES) return redacted;
  return (
    Buffer.from(redacted, 'utf8').subarray(0, LLM_WIRE_TRACE_MAX_BYTES).toString('utf8') +
    '…[truncated]'
  );
}

function cleanCount(n: number | undefined): number {
  return Number.isFinite(n) && (n as number) >= 0 ? Math.floor(n as number) : 0;
}

/**
 * Record one LLM call's usage. No-op-safe and no-throw: a missing trace
 * flag drops the trace, and any db failure is logged and swallowed,
 * accounting must never break a scan.
 */
export async function recordLlmUsage(db: Database, entry: LlmUsageEntry): Promise<void> {
  try {
    const rec = await db.insertLlmUsage({
      userId: entry.userId ?? null,
      provider: entry.provider,
      model: entry.model,
      tier: entry.tier,
      inputTokens: cleanCount(entry.inputTokens),
      outputTokens: cleanCount(entry.outputTokens),
      cacheReadTokens: cleanCount(entry.cacheReadTokens),
      cacheWriteTokens: cleanCount(entry.cacheWriteTokens),
      latencyMs:
        Number.isFinite(entry.latencyMs) && (entry.latencyMs as number) >= 0
          ? Math.floor(entry.latencyMs as number)
          : undefined,
      status: entry.status ?? 'ok',
    });
    if (entry.trace && process.env.LLM_WIRE_TRACE === '1') {
      const request =
        entry.trace.request === undefined ? undefined : boundWireBody(entry.trace.request);
      const response =
        entry.trace.response === undefined ? undefined : boundWireBody(entry.trace.response);
      if (request !== undefined || response !== undefined) {
        await db.insertLlmWireTrace({
          llmUsageId: rec.id,
          userId: entry.userId ?? null,
          requestBody: request ?? null,
          responseBody: response ?? null,
        });
      }
    }
  } catch (err) {
    console.warn(
      '[usage] failed to record LLM usage:',
      err instanceof Error ? err.message : String(err),
    );
  }
}

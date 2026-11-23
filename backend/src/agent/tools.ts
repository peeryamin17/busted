import http from 'node:http';
import https from 'node:https';
import type { ScopePolicy } from '../types.js';
import {
  assertUrlAllowed,
  resolvePublicAddresses,
  type ResolvedHostAddress,
} from '../guardrails/scope.js';
import { pinnedLookup } from '../webcheck/fetch.js';
import { TokenBucketRateLimiter } from '../guardrails/ratelimit.js';
import { redactHeaders, redactText } from '../guardrails/redact.js';
import { assessmentHeaders } from '../guardrails/identityHeader.js';
import {
  coalescedGet,
  fetchWithGovernor,
  type GovernedFetchInit,
  type NoiseGovernor,
} from '../egress/noise.js';

/**
 * Agent tool interface. Every tool that touches the network goes through
 * `guardedFetch`, which enforces (in order):
 *   1. scope check, never test outside the user-defined scope (plan §8)
 *   2. rate limit, never DoS-like (plan §8)
 *   3. SSRF guard, never touch private/internal addresses (plan §8)
 *
 * Tools only READ responses; payloads are benign canaries (reflection checks),
 * never destructive input. Sensitive values are redacted before they reach
 * the agent's observations or any persisted finding.
 */

export interface ToolExecutionContext {
  target: URL;
  scope: ScopePolicy;
  rateLimiter: TokenBucketRateLimiter;
  allowPrivateTargets: boolean;
  fetchTimeoutMs: number;
  /**
   * Task that owns this run, carried only so the assessment-identity
   * header can name it. Absent for one-off / pre-task callers.
   */
  taskId?: string;
  /**
   * Target-pin gate for this task, built once by the caller from the
   * task's pins + rules. Absent = no pin enforcement (pre-Phase-C
   * callers, e.g. one-off active tests with no task).
   */
  pinCheck?: (url: URL) => { decision: 'allowed' | 'ask' | 'blocked'; reason: string };
  /**
   * Noise governor for this task run. Absent = ungoverned,
   * as before, the global rate limiter still applies.
   */
  noise?: NoiseGovernor;
}

export interface ToolResult {
  ok: boolean;
  status?: number;
  finalUrl?: string;
  /** Redacted response headers. */
  headers?: Record<string, string>;
  /** Redacted, truncated body snippet. */
  bodySnippet?: string;
  timingMs?: number;
  /** Structured observations for the agent / reflection step. */
  data?: Record<string, unknown>;
  error?: string;
  honeypotSignals?: string[];
}

export interface AgentTool {
  name: string;
  description: string;
  run(args: Record<string, unknown>, ctx: ToolExecutionContext): Promise<ToolResult>;
}

export function createToolContext(
  target: URL,
  scope: ScopePolicy,
  allowPrivateTargets: boolean,
  opts?: {
    taskId?: string;
    pinCheck?: ToolExecutionContext['pinCheck'];
    noise?: NoiseGovernor;
  },
): ToolExecutionContext {
  return {
    target,
    scope,
    rateLimiter: new TokenBucketRateLimiter(scope.maxRequestsPerSecond),
    allowPrivateTargets,
    fetchTimeoutMs: 15_000,
    ...(opts?.taskId ? { taskId: opts.taskId } : {}),
    ...(opts?.pinCheck ? { pinCheck: opts.pinCheck } : {}),
    ...(opts?.noise ? { noise: opts.noise } : {}),
  };
}

interface GuardedFetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

const MAX_REDIRECT_HOPS = 5;
/** Cap on response bytes read into memory (DoS guard, see audit). */
export const MAX_BODY_BYTES = 1_000_000;

/**
 * One HTTP(S) request over node:http, connecting only to an address the
 * SSRF guard already approved (pinned lookup). The global fetch cannot
 * take a custom lookup, so a checked hostname could rebind between the
 * check and the connect; this transport closes that window. Returns a
 * real Response (body capped at MAX_BODY_BYTES) with url set to the
 * hop URL, so callers see the same shape fetch gave them.
 */
async function pinnedRequest(
  url: URL,
  addresses: ResolvedHostAddress[],
  init: GovernedFetchInit,
  timeoutMs: number,
): Promise<Response> {
  const isHttps = url.protocol === 'https:';
  const lib = isHttps ? https : http;
  const body = init.body !== undefined ? Buffer.from(init.body, 'utf8') : null;
  const headers: Record<string, string> = { ...(init.headers ?? {}) };
  if (body) headers['content-length'] = String(body.length);
  return new Promise((resolve, reject) => {
    const req = lib.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port ? Number(url.port) : isHttps ? 443 : 80,
        path: `${url.pathname}${url.search}`,
        method: init.method ?? 'GET',
        agent: false,
        lookup: pinnedLookup(addresses),
        headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let total = 0;
        let done = false;
        const finish = () => {
          if (done) return;
          done = true;
          const headersOut: Record<string, string> = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (typeof v === 'string') headersOut[k.toLowerCase()] = v;
            else if (Array.isArray(v)) headersOut[k.toLowerCase()] = v.join(', ');
          }
          const out = new Response(
            res.statusCode === 204 || res.statusCode === 304
              ? null
              : Buffer.concat(chunks),
            {
              status: res.statusCode ?? 0,
              headers: headersOut,
            },
          );
          Object.defineProperty(out, 'url', { value: url.toString() });
          resolve(out);
        };
        res.on('data', (chunk: Buffer) => {
          total += chunk.length;
          if (total <= MAX_BODY_BYTES) {
            chunks.push(chunk);
          } else if (Buffer.concat(chunks).length < MAX_BODY_BYTES) {
            const room = MAX_BODY_BYTES - Buffer.concat(chunks).length;
            if (room > 0) chunks.push(chunk.subarray(0, room));
          }
          if (total >= MAX_BODY_BYTES) {
            res.destroy();
            finish();
          }
        });
        res.on('end', finish);
        res.on('error', () => finish());
      },
    );
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`Timed out after ${Math.round(timeoutMs / 1000)}s`));
    });
    req.on('error', reject);
    req.end(body ?? undefined);
  });
}

export async function guardedFetch(
  urlStr: string,
  ctx: ToolExecutionContext,
  init: GuardedFetchInit = {}
): Promise<Response> {
  const run = async (): Promise<Response> => {
    let current = urlStr;
    for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
      // 1. Scope enforcement, throws if out of scope (checked on EVERY hop).
      const url = assertUrlAllowed(current, ctx.target, ctx.scope);
      // 1b. Target-pin gate, a host nobody approved is never fetched.
      // Checked before the rate limiter so a refused host burns no token.
      if (ctx.pinCheck) {
        const pin = ctx.pinCheck(url);
        if (pin.decision === 'blocked') {
          throw Object.assign(new Error(`Target blocked: ${pin.reason}`), { statusCode: 403 });
        }
        if (pin.decision === 'ask') {
          throw Object.assign(new Error(`Target needs human approval: ${pin.reason}`), { statusCode: 409 });
        }
      }
      // 2. Rate limiting, wait for a token (never burst/DoS).
      await ctx.rateLimiter.take();
      // 3. SSRF guard, refuse private/internal hosts (re-resolved every hop,
      //    so a redirect to a DNS-rebinding or privately-resolving host is caught).
      // The approved addresses are pinned for the connect, so the host
      // cannot pass the check and then rebind to a private address.
      const addresses = await resolvePublicAddresses(url.hostname, ctx.allowPrivateTargets);

      // 4. Noise governor (per hop): per-host token + in-flight slot +
      //    jitter, plus one Retry-After retry for this hop only. The
      //    assessment-identity header is merged LAST so a caller-supplied
      //    header can never strip it, guardedFetch is active-testing
      //    traffic only, which is exactly what the header is for.
      const doHop = (u: string, hopInit: GovernedFetchInit): Promise<Response> =>
        pinnedRequest(
          new URL(u),
          addresses,
          {
            method: hopInit.method ?? 'GET',
            headers: {
              'user-agent': 'BugSeekAI/0.2 (authorized security scan)',
              ...(hopInit.headers ?? {}),
              ...assessmentHeaders(ctx.taskId),
            },
            body: hop === 0 ? hopInit.body : undefined,
          },
          ctx.fetchTimeoutMs,
        );
      const hopInit: GovernedFetchInit = {
        method: init.method ?? 'GET',
        ...(init.headers ? { headers: init.headers } : {}),
        ...(hop === 0 && init.body !== undefined ? { body: init.body } : {}),
      };
      const res = ctx.noise
        ? await fetchWithGovernor(ctx.noise, url.toString(), hopInit, doHop)
        : await doHop(url.toString(), hopInit);

      const location = res.headers.get('location');
      const isRedirect = res.status >= 300 && res.status < 400 && location;
      if (!isRedirect) return res;
      // Drain the redirect response body before following.
      await res.arrayBuffer().catch(() => undefined);
      if (hop === MAX_REDIRECT_HOPS) {
        throw Object.assign(new Error('Too many redirects (SSRF/scope guardrail)'), { statusCode: 400 });
      }
      current = new URL(location, url).toString();
    }
    throw Object.assign(new Error('Too many redirects (SSRF/scope guardrail)'), { statusCode: 400 });
  };

  // GET coalescing wraps the WHOLE redirect loop and keys on the
  // ORIGINAL url string only, redirect hops are never coalesced
  // against each other. GET only; anything else runs unshared.
  if (ctx.noise && (init.method ?? 'GET').toUpperCase() === 'GET') {
    return coalescedGet(ctx.noise, urlStr, run);
  }
  return run();
}

export async function readResult(res: Response, ctx: ToolExecutionContext): Promise<ToolResult> {
  const started = Date.now();
  const text = await readBodyCapped(res).catch(() => '');
  const headers: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    headers[k] = v;
  });
  return {
    ok: true,
    status: res.status,
    finalUrl: res.url,
    headers: redactHeaders(headers),
    bodySnippet: redactText(text, 2000),
    timingMs: Date.now() - started,
    honeypotSignals: detectTrapSignals(text),
  };
}

/**
 * Read a response body with a hard byte cap. A malicious target can otherwise
 * stream unbounded bytes and OOM the worker (timeout bounds time, not bytes).
 */
async function readBodyCapped(res: Response): Promise<string> {
  if (!res.body) return res.text().catch(() => '');
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) break;
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
    // Cancel the remainder so the socket doesn't keep streaming.
    await res.body.cancel().catch(() => undefined);
  }
  const buf = Buffer.concat(chunks);
  return buf.toString('utf8');
}

function fail(error: unknown): ToolResult {
  const msg = error instanceof Error ? error.message : String(error);
  return { ok: false, error: msg.slice(0, 300), honeypotSignals: [] };
}

/**
 * Honeypot/trap signal detection (plan §4.5): known canary-token patterns,
 * honeypot software banners, and suspiciously "perfect" fake errors.
 */
const TRAP_PATTERNS: Array<{ re: RegExp; signal: string }> = [
  { re: /thinkstcanary|canarytoken/i, signal: 'canary-token pattern in response (Thinkst Canary)' },
  { re: /cowrie|honeyd|kippo|dionaea/i, signal: 'known honeypot software banner' },
  { re: /honeypot/i, signal: 'literal "honeypot" string in response' },
];

export function detectTrapSignals(body: string): string[] {
  const signals: string[] = [];
  for (const p of TRAP_PATTERNS) {
    if (p.re.test(body)) signals.push(p.signal);
  }
  return signals;
}

/** Parse Set-Cookie headers (Node's getSetCookie) into attribute maps. */
function parseSetCookies(res: Response): Array<Record<string, string>> {
  const raw = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
  return raw.map((c) => {
    const parts = c.split(';').map((s) => s.trim());
    const attrs: Record<string, string> = {};
    for (const p of parts) {
      const [k, ...rest] = p.split('=');
      attrs[(k ?? '').toLowerCase()] = rest.join('=');
    }
    return attrs;
  });
}

const REQUIRED_HEADERS = [
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
];

export function defaultTools(): AgentTool[] {
  const fetchUrl: AgentTool = {
    name: 'fetch_url',
    description: 'Fetch a URL (GET/POST) and return status, headers, and a redacted body snippet.',
    async run(args, ctx) {
      try {
        const url = args['url'] as string;
        const res = await guardedFetch(url, ctx, {
          method: (args['method'] as string) ?? 'GET',
          body: args['body'] as string | undefined,
        });
        const result = await readResult(res, ctx);
        const server = res.headers.get('server');
        const poweredBy = res.headers.get('x-powered-by');
        result.data = {
          serverDisclosure: server ?? poweredBy ?? null,
          contentType: res.headers.get('content-type'),
        };
        return result;
      } catch (e) {
        return fail(e);
      }
    },
  };

  const checkSecurityHeaders: AgentTool = {
    name: 'check_security_headers',
    description: 'Fetch a URL and report which OWASP-recommended security headers are missing.',
    async run(args, ctx) {
      try {
        const res = await guardedFetch(args['url'] as string, ctx);
        const result = await readResult(res, ctx);
        const present = new Set<string>();
        res.headers.forEach((_v, k) => present.add(k.toLowerCase()));
        const missing = REQUIRED_HEADERS.filter((h) => !present.has(h));
        result.data = { missing, presentCount: present.size };
        return result;
      } catch (e) {
        return fail(e);
      }
    },
  };

  const probeCors: AgentTool = {
    name: 'probe_cors',
    description:
      'Probe CORS misconfiguration by sending a cross-origin request from an attacker-controlled origin.',
    async run(args, ctx) {
      const evilOrigin = 'https://evil.bugseek-test.invalid';
      try {
        // Preflight
        const pre = await guardedFetch(args['url'] as string, ctx, {
          method: 'OPTIONS',
          headers: { origin: evilOrigin, 'access-control-request-method': 'GET' },
        });
        // Actual request with attacker origin
        const res = await guardedFetch(args['url'] as string, ctx, {
          headers: { origin: evilOrigin },
        });
        const result = await readResult(res, ctx);
        const acao = res.headers.get('access-control-allow-origin');
        const acac = res.headers.get('access-control-allow-credentials');
        const reflected = acao === evilOrigin || acao === '*';
        result.data = {
          evilOrigin,
          allowOrigin: acao,
          allowCredentials: acac,
          preflightStatus: pre.status,
          vulnerable: reflected && acac?.toLowerCase() === 'true',
          wildcard: acao === '*',
        };
        return result;
      } catch (e) {
        return fail(e);
      }
    },
  };

  const probeReflectedXss: AgentTool = {
    name: 'probe_reflected_xss',
    description:
      'Test for reflected XSS using a BENIGN alphanumeric canary (no script payload). ' +
      'Reports whether the canary is reflected unencoded in the response.',
    async run(args, ctx) {
      try {
        const param = (args['param'] as string) ?? 'q';
        const canary = `bsx${Date.now().toString(36)}canary`;
        const base = new URL(args['url'] as string);
        base.searchParams.set(param, canary);
        const res = await guardedFetch(base.toString(), ctx);
        const text = await res.text().catch(() => '');
        const reflectedRaw = text.includes(canary);
        const reflectedEncoded =
          text.includes(encodeURIComponent(canary)) || text.includes(canary.replace(/&/g, '&amp;'));
        const result: ToolResult = {
          ok: true,
          status: res.status,
          finalUrl: res.url,
          bodySnippet: redactText(text, 2000),
          honeypotSignals: detectTrapSignals(text),
          data: {
            param,
            canary,
            reflectedUnencoded: reflectedRaw && !reflectedEncoded ? true : reflectedRaw,
            reflectedAtAll: reflectedRaw,
          },
        };
        return result;
      } catch (e) {
        return fail(e);
      }
    },
  };

  const inspectCookies: AgentTool = {
    name: 'inspect_cookies',
    description: 'Fetch a URL and audit Set-Cookie flags (Secure, HttpOnly, SameSite).',
    async run(args, ctx) {
      try {
        const res = await guardedFetch(args['url'] as string, ctx);
        const result = await readResult(res, ctx);
        const cookies = parseSetCookies(res);
        const issues: string[] = [];
        for (const c of cookies) {
          const name = Object.keys(c)[0] ?? 'unknown';
          if (!('secure' in c)) issues.push(`cookie "${name}" missing Secure flag`);
          if (!('httponly' in c)) issues.push(`cookie "${name}" missing HttpOnly flag`);
          if (!('samesite' in c)) issues.push(`cookie "${name}" missing SameSite attribute`);
          if (c['samesite']?.toLowerCase() === 'none' && !('secure' in c)) {
            issues.push(`cookie "${name}" uses SameSite=None without Secure`);
          }
        }
        result.data = { cookieCount: cookies.length, issues };
        return result;
      } catch (e) {
        return fail(e);
      }
    },
  };

  return [fetchUrl, checkSecurityHeaders, probeCors, probeReflectedXss, inspectCookies];
}

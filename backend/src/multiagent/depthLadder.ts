import { randomBytes } from 'node:crypto';
import {
  guardedFetch,
  type ToolExecutionContext,
} from '../agent/tools.js';
import { redactHeaders, redactText } from '../guardrails/redact.js';
import type {
  DepthEvidence,
  DepthImpact,
  DepthLevel,
  FindingVerification,
} from '../types.js';

/**
 * Exploit-depth ladder, extends the head agent's PoC validator pass
 * (head.ts Phase 4.5) with live, benign-canary proof.
 *
 * The ladder VALIDATES findings the specialists already produced. It never
 * invents findings, never executes an attack chain, and never performs a
 * state-changing request:
 *
 *   CONFIRM, a benign canary proves the vulnerability is real
 *               (XSS: unique canary reflected; IDOR: a neighbour record
 *               reachable with the same shape; CORS: a canary origin is
 *               echoed with credentials allowed; GraphQL: a read-only
 *               `{ __typename }` query returns data).
 *   ESCALATE, blast radius, READ-ONLY proofs only (second reflection
 *               context, second neighbour record, credentialed cross-origin
 *               GET returning data, read-only introspection).
 *   MEASURE, impact is derived from the OBSERVED depth, not a model
 *               guess, and recorded with the evidence for each rung.
 *
 * HARD RULES, enforced here (not just documented):
 * - Canaries are unique random tokens, alphanumeric only. They are markers,
 *   never scripts: no alert(), no document.cookie, no exfiltration payload.
 * - Read-only proofs only. The only non-GET request the ladder makes is a
 *   GraphQL query (`{ __typename }` / introspection), a read-only query,
 *   never a mutation. No POST/PUT/DELETE/PATCH anywhere else.
 * - Never modify/delete data. Never record another record's VALUES: IDOR
 *   escalation compares HTTP status + JSON FIELD NAMES + content length
 *   only. Evidence excerpts are redacted and truncated.
 * - Stop conditions: the ladder aborts immediately on a rate-limit /
 *   lockout signal (429, lockout wording, CAPTCHA challenge), a 5xx storm
 *   (3 consecutive server errors), or a scope/SSRF guardrail refusal, and
 *   records the stop reason on the finding.
 *
 * SCOPE LIMITS (operator ceiling): no exploitation to code execution, no
 * data extraction, no state mutation, no post-exploitation chaining, no
 * privilege-escalation execution, no pivoting to internal services or cloud
 * metadata endpoints, no database dumping, no session hijacking. Attack
 * chains stay at the level of reasoning/narrative (head.ts chainWith)
 * without executing the chain.
 */

export type LadderKind = 'xss' | 'idor' | 'cors' | 'graphql' | 'unprobeable';

/** Minimal shape the ladder needs, satisfied by WorkerFinding and Finding. */
export interface LadderFindingInput {
  category: string;
  title: string;
  location?: string;
  evidence?: string;
}

export interface DepthProbeRequest {
  method: 'GET' | 'OPTIONS' | 'POST';
  url: string;
  headers?: Record<string, string>;
  /** Only ever a read-only GraphQL query body. Never a mutation. */
  body?: string;
  /** Short label for the evidence trail, e.g. 'xss-confirm'. */
  label: string;
}

export interface DepthProbeResponse {
  ok: boolean;
  status?: number;
  headers?: Record<string, string>;
  /** Raw body (capped). The ladder excerpts/redacts before storing. */
  body: string;
  /**
   * Top-level JSON field names observed in the body, in observed order
   * (values never recorded, names only). Populated by the live prober
   * for JSON responses; callers use it to build proof records for
   * IDOR/GraphQL shape receipts.
   */
  shape?: string[];
  error?: string;
}

export type DepthProber = (req: DepthProbeRequest) => Promise<DepthProbeResponse>;

export interface LadderOptions {
  /** Absolute target URL, used to resolve relative finding locations. */
  targetUrl?: string;
  /** Max HTTP probes per finding (default 6). Hard cap, the ladder is cheap. */
  maxProbes?: number;
  /**
   * Allow the IDOR escalation probe (neighbour record reached, compared by
   * status + JSON field names only, values never recorded). Default true.
   * Disable it and IDOR findings can only be confirmed, never escalated.
   */
  allowNeighborShapeProbe?: boolean;
  /**
   * Called with every probe response so the caller can snapshot the proof
   * and run the verbatim-receipt check. The hook
   * receives the raw capped body (the caller redacts before persisting
   * anything) plus the response status, the REDACTED response headers
   * (cookie/authorization values already masked) and, for JSON
   * responses, the observed top-level field names as `shape`, so the
   * caller can build proof records for header/shape receipts. The hook
   * never affects the ladder outcome: a throwing hook is swallowed.
   */
  onProbe?: (probe: {
    label: string;
    url: string;
    body: string;
    status?: number;
    headers?: Record<string, string>;
    shape?: string[];
  }) => void;
  now?: () => string;
}

const LADDER_METHOD = 'depth-ladder v1 (benign canary, read-only proofs)';
const MAX_PROBES_DEFAULT = 6;
const MAX_BODY_BYTES = 200_000;
const SERVER_ERROR_STOP = 3;

/** A benign canary: unique, random, alphanumeric, a marker, never a payload. */
export function generateCanary(): string {
  return `bs${randomBytes(8).toString('hex')}`;
}

export function isLadderTestable(finding: LadderFindingInput): boolean {
  return classifyFinding(finding) !== 'unprobeable';
}

export function classifyFinding(finding: LadderFindingInput): LadderKind {
  const hay = `${finding.category} ${finding.title}`.toLowerCase();
  if (/\bxss\b|cross-site scripting/.test(hay)) return 'xss';
  if (/\bidor\b|insecure direct object/.test(hay)) return 'idor';
  if (/\bcors\b|cross-origin resource sharing/.test(hay)) return 'cors';
  if (/\bgraphql\b/.test(hay)) return 'graphql';
  return 'unprobeable';
}

/** A verification for a finding the ladder did not (or could not) test live. */
export function untestedVerification(reason: string, now: () => string = () => new Date().toISOString()): FindingVerification {
  return {
    status: 'hint',
    depth: 'unproven',
    impact: 'not-measured',
    impactSummary:
      `Impact not measured: ${reason} Treat as an unconfirmed hint, not a confirmed finding.`,
    evidence: [],
    testedAt: now(),
    method: LADDER_METHOD,
  };
}

/**
 * Live prober built on guardedFetch, so every ladder request goes through
 * the same enforcement as specialist tools: scope check → rate limit →
 * SSRF guard, on every request (including redirects).
 */
export function createDepthProber(ctx: ToolExecutionContext): DepthProber {
  return async (req) => {
    try {
      const res = await guardedFetch(req.url, ctx, {
        method: req.method,
        headers: req.headers,
        body: req.body,
      });
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => {
        headers[k.toLowerCase()] = v;
      });
      const body = await readCapped(res);
      const shape = jsonFieldNames(body) ?? undefined;
      return {
        ok: res.status < 500,
        status: res.status,
        headers: redactHeaders(headers),
        body,
        ...(shape ? { shape } : {}),
      };
    } catch (e) {
      return { ok: false, body: '', error: (e as Error).message.slice(0, 200) };
    }
  };
}

async function readCapped(res: Response): Promise<string> {
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
    await res.body.cancel().catch(() => undefined);
  }
  return Buffer.concat(chunks).toString('utf8');
}

// ── Helpers ────────────────────────────────────────────────────────────────

function resolveUrl(finding: LadderFindingInput, targetUrl?: string): URL | null {
  const candidates = [finding.location, targetUrl].filter(Boolean) as string[];
  for (const c of candidates) {
    try {
      const u = new URL(c);
      if (u.protocol === 'http:' || u.protocol === 'https:') return u;
    } catch {
      // Not absolute, try resolving a path against the target origin.
      if (targetUrl && c.startsWith('/')) {
        try {
          return new URL(c, targetUrl);
        } catch {
          /* fall through */
        }
      }
    }
  }
  return null;
}

/** Short redacted excerpt centred on the canary match (never a full body). */
function excerptAround(body: string, token: string, radius = 80): string {
  const idx = body.indexOf(token);
  const snippet =
    idx >= 0
      ? body.slice(Math.max(0, idx - radius), Math.min(body.length, idx + token.length + radius))
      : body.slice(0, 160);
  return redactText(snippet, 300);
}

/** JSON field names only, values are never recorded, by design. Exported so callers (retester) can derive a probe's shape from its body. */
export function jsonFieldNames(body: string): string[] | null {
  try {
    const parsed: unknown = JSON.parse(body);
    const obj = Array.isArray(parsed) ? parsed[0] : parsed;
    if (obj && typeof obj === 'object') {
      return Object.keys(obj as Record<string, unknown>).slice(0, 30);
    }
  } catch {
    /* not JSON */
  }
  return null;
}

function sameShape(a: string[] | null, b: string[] | null): boolean {
  if (!a || !b || a.length === 0 || b.length === 0) return false;
  return a.length === b.length && a.every((f, i) => f === b[i]);
}

const LOCKOUT_RE = /lockout|locked out|account locked|too many (attempts|requests)|captcha|challenge/i;

interface LadderState {
  probesUsed: number;
  maxProbes: number;
  consecutive5xx: number;
  stopReason?: string;
  evidence: DepthEvidence[];
}

/** Fresh stop state for one finding (exported for unit tests). */
export function newLadderState(maxProbes: number): LadderState {
  return { probesUsed: 0, maxProbes, consecutive5xx: 0, evidence: [] };
}

/**
 * Stop policy, applied to EVERY probe response: returns a stop reason, or
 * null to continue. Exported so tests can exercise it directly.
 */
export function checkStop(res: DepthProbeResponse, state: LadderState): string | null {
  if (res.status === 429) return 'rate-limited (HTTP 429) — ladder aborted';
  if (res.status === 403 && res.body && LOCKOUT_RE.test(res.body)) {
    return 'lockout signal (HTTP 403 with lockout wording) — ladder aborted';
  }
  if (res.body && LOCKOUT_RE.test(res.body.slice(0, 2000))) {
    return 'challenge/lockout wording in response — ladder aborted';
  }
  if (res.status !== undefined && res.status >= 500) {
    state.consecutive5xx += 1;
    if (state.consecutive5xx >= SERVER_ERROR_STOP) {
      return `repeated server errors (${state.consecutive5xx} consecutive 5xx) — ladder aborted`;
    }
  } else {
    state.consecutive5xx = 0;
  }
  if (res.error && /scope|ssrf|private|forbidden host/i.test(res.error)) {
    return `guardrail refused request (${res.error}) — ladder aborted`;
  }
  return null;
}

function impactFor(depth: DepthLevel, kind: LadderKind): { impact: DepthImpact; summary: string } {
  if (depth === 'unproven') {
    return {
      impact: 'not-measured',
      summary:
        'Impact not measured: the claimed vulnerability could not be reproduced with a benign canary probe. Treat as an unconfirmed hint, not a confirmed finding.',
    };
  }
  if (depth === 'confirmed') {
    const what =
      kind === 'xss'
        ? 'a benign canary was reflected unencoded in a response sink (single context)'
        : kind === 'idor'
          ? 'a neighbour record was reachable with the same response shape (values never recorded)'
          : kind === 'cors'
            ? 'a canary cross-origin request was accepted with credentials allowed'
            : kind === 'graphql'
              ? 'a read-only query returned data from the GraphQL endpoint'
              : 'a benign canary probe reproduced the claimed behaviour';
    return {
      impact: 'single-context',
      summary: `Measured impact (single context): ${what}. Cross-context blast radius was not proven — the finding is confirmed, not escalated.`,
    };
  }
  const what =
    kind === 'xss'
      ? 'the canary was reflected in two different parameters/contexts'
      : kind === 'idor'
        ? 'two different neighbour records were reachable with the same response shape (values never recorded)'
        : kind === 'cors'
          ? 'a credentialed cross-origin request actually returned data to a canary origin'
          : kind === 'graphql'
            ? 'read-only introspection returned the full schema'
            : 'the behaviour reproduced across more than one context';
  return {
    impact: 'cross-context',
    summary: `Measured impact (cross-context): ${what}. This is the observed blast radius — it proves reach, not exploitability to code execution or data theft, which the ladder never attempts.`,
  };
}

// ── Per-kind rungs ─────────────────────────────────────────────────────────

async function runXss(
  finding: LadderFindingInput,
  url: URL,
  canary: string,
  probe: DepthProber,
  state: LadderState,
): Promise<DepthLevel> {
  // Confirm: reflect the canary through the parameter the finding names
  // (query param in the location URL, else a name mentioned in evidence,
  // else the conventional 'q'). Alphanumeric canary, reflection is
  // unambiguous, and nothing executes.
  const params = [...url.searchParams.keys()];
  const mentioned = (finding.evidence ?? '').match(/param(?:eter)?\s*["']?([A-Za-z0-9_]+)/i)?.[1];
  const firstParam = params[0] ?? mentioned ?? 'q';
  const confirmUrl = new URL(url.toString());
  confirmUrl.searchParams.set(firstParam, canary);
  if (state.probesUsed >= state.maxProbes) return 'unproven';
  state.probesUsed += 1;
  const res = await probe({
    method: 'GET',
    url: confirmUrl.toString(),
    label: 'xss-confirm',
  });
  const stop = checkStop(res, state);
  if (stop) {
    state.stopReason = stop;
    return 'unproven';
  }
  if (!res.ok || res.status !== 200 || !res.body.includes(canary)) return 'unproven';
  // Sink context: inside an HTML tag/attribute, or plain text?
  const at = res.body.indexOf(canary);
  const before = res.body.slice(Math.max(0, at - 200), at);
  const lastOpen = before.lastIndexOf('<');
  const lastClose = before.lastIndexOf('>');
  const context = lastOpen > lastClose ? 'inside an HTML tag/attribute' : 'in text content';
  state.evidence.push({
    rung: 'confirm',
    kind: 'xss-reflection',
    request: `GET ${confirmUrl.pathname}${confirmUrl.search} (${firstParam}=<canary>)`,
    observed: `HTTP ${res.status}: canary reflected unencoded ${context}. Excerpt: ${excerptAround(res.body, canary)}`,
    status: res.status,
  });
  // Escalate: same canary reflected through a second parameter, proves
  // the reflection is not tied to one input.
  const secondParam =
    ['q', 'search', 'query', 'name', 'keyword'].find((p) => p !== firstParam) ?? 'search';
  const escUrl = new URL(url.toString());
  escUrl.searchParams.set(secondParam, canary);
  if (state.probesUsed >= state.maxProbes) return 'confirmed';
  state.probesUsed += 1;
  const esc = await probe({ method: 'GET', url: escUrl.toString(), label: 'xss-escalate' });
  const stop2 = checkStop(esc, state);
  if (stop2) {
    state.stopReason = stop2;
    return 'confirmed';
  }
  if (esc.ok && esc.status === 200 && esc.body.includes(canary)) {
    state.evidence.push({
      rung: 'escalate',
      kind: 'xss-second-context',
      request: `GET ${escUrl.pathname}${escUrl.search} (${secondParam}=<canary>)`,
      observed: `HTTP ${esc.status}: canary also reflected via a second parameter (${secondParam}). Excerpt: ${excerptAround(esc.body, canary)}`,
      status: esc.status,
    });
    return 'escalated';
  }
  return 'confirmed';
}

const NUMERIC_ID_RE = /\/(\d{1,10})(?=\/|$|[?#])/;

async function runIdor(
  finding: LadderFindingInput,
  url: URL,
  _canary: string,
  probe: DepthProber,
  state: LadderState,
  allowNeighborShapeProbe: boolean,
): Promise<DepthLevel> {
  const m = url.pathname.match(NUMERIC_ID_RE);
  if (!m) return 'unproven';
  const id = Number(m[1]);
  const replaceId = (next: number): string => {
    const u = new URL(url.toString());
    u.pathname = u.pathname.replace(`/${m[1]}`, `/${String(next)}`);
    return u.toString();
  };
  // Baseline: the claimed object itself must be retrievable, else there is
  // nothing to validate. Only status + field names are recorded.
  if (state.probesUsed >= state.maxProbes) return 'unproven';
  state.probesUsed += 1;
  const base = await probe({ method: 'GET', url: url.toString(), label: 'idor-baseline' });
  const stop = checkStop(base, state);
  if (stop) {
    state.stopReason = stop;
    return 'unproven';
  }
  if (!base.ok || base.status !== 200) return 'unproven';
  const baseFields = jsonFieldNames(base.body);
  if (!baseFields) return 'unproven';
  // Confirm: a neighbour record (id+1) returns the same shape. This is the
  // IDOR proof, but only shape is compared. Values are NEVER recorded, so
  // no other user's data is read, stored, or exfiltrated. Ideally the
  // neighbour is a seeded canary record; without one, shape + status is the
  // honest limit of what a read-only probe can prove.
  if (!allowNeighborShapeProbe) return 'unproven';
  if (state.probesUsed >= state.maxProbes) return 'unproven';
  state.probesUsed += 1;
  const n1 = await probe({ method: 'GET', url: replaceId(id + 1), label: 'idor-confirm' });
  const stop1 = checkStop(n1, state);
  if (stop1) {
    state.stopReason = stop1;
    return 'unproven';
  }
  const n1Fields = n1.ok && n1.status === 200 ? jsonFieldNames(n1.body) : null;
  if (!n1Fields || !sameShape(baseFields, n1Fields)) return 'unproven';
  // The field list is quoted so the receipt check has a verbatim anchor:
  // the list comes from the claimed record's response and must appear
  // verbatim in the neighbour's proof record (its FIELDS line).
  state.evidence.push({
    rung: 'confirm',
    kind: 'idor-neighbor-shape',
    request: `GET ${new URL(replaceId(id + 1)).pathname} (neighbour of ${id})`,
    observed:
      `HTTP 200 with the same JSON field names as the claimed record ` +
      `("${baseFields.join(', ')}"); values never recorded. Body length ${n1.body.length} bytes.`,
    status: 200,
  });
  // Escalate: a second, farther neighbour (id-1, else id+10) matches too.
  const secondId = id > 1 ? id - 1 : id + 10;
  if (state.probesUsed >= state.maxProbes) return 'confirmed';
  state.probesUsed += 1;
  const n2 = await probe({ method: 'GET', url: replaceId(secondId), label: 'idor-escalate' });
  const stop2 = checkStop(n2, state);
  if (stop2) {
    state.stopReason = stop2;
    return 'confirmed';
  }
  const n2Fields = n2.ok && n2.status === 200 ? jsonFieldNames(n2.body) : null;
  if (n2Fields && sameShape(baseFields, n2Fields)) {
    state.evidence.push({
      rung: 'escalate',
      kind: 'idor-second-neighbor-shape',
      request: `GET ${new URL(replaceId(secondId)).pathname} (second neighbour of ${id})`,
      observed:
        `HTTP 200 with the same JSON field names ("${baseFields.join(', ')}"); values never recorded. ` +
        `Cross-record reach proven by shape, not by reading data.`,
      status: 200,
    });
    return 'escalated';
  }
  return 'confirmed';
}

async function runCors(
  finding: LadderFindingInput,
  url: URL,
  canary: string,
  probe: DepthProber,
  state: LadderState,
): Promise<DepthLevel> {
  // The canary origin is ours and unresolvable (.invalid), it can only
  // prove the server echoes an arbitrary origin; no real site is involved
  // and no credentials of any user are sent (the ladder holds none).
  const canaryOrigin = `https://canary-${canary}.bugseek-test.invalid`;
  const headers = { origin: canaryOrigin };
  if (state.probesUsed >= state.maxProbes) return 'unproven';
  state.probesUsed += 1;
  const res = await probe({ method: 'GET', url: url.toString(), headers, label: 'cors-confirm' });
  const stop = checkStop(res, state);
  if (stop) {
    state.stopReason = stop;
    return 'unproven';
  }
  const acao = res.headers?.['access-control-allow-origin'];
  const acac = res.headers?.['access-control-allow-credentials'];
  const echoed = acao === canaryOrigin;
  const creds = (acac ?? '').toLowerCase() === 'true';
  if (!echoed || !creds) return 'unproven';
  state.evidence.push({
    rung: 'confirm',
    kind: 'cors-canary-origin',
    request: `GET ${url.pathname} with Origin: ${canaryOrigin}`,
    observed: `HTTP ${res.status}: Access-Control-Allow-Origin echoed the canary origin exactly and Access-Control-Allow-Credentials: true. No user credentials were sent.`,
    status: res.status,
  });
  // Escalate: a credentialed cross-origin GET actually returns data to the
  // canary origin (proves the server permits the read; no victim data is
  // involved, since the ladder sends no victim session).
  if (state.probesUsed >= state.maxProbes) return 'confirmed';
  state.probesUsed += 1;
  const esc = await probe({ method: 'GET', url: url.toString(), headers, label: 'cors-escalate' });
  const stop2 = checkStop(esc, state);
  if (stop2) {
    state.stopReason = stop2;
    return 'confirmed';
  }
  if (esc.ok && esc.status === 200 && esc.body.length > 0) {
    state.evidence.push({
      rung: 'escalate',
      kind: 'cors-credentialed-read',
      request: `GET ${url.pathname} with Origin: ${canaryOrigin} (credentialed)`,
      observed: `HTTP 200: the server returned ${esc.body.length} bytes to the canary origin with credentials allowed. Body content not recorded (only length).`,
      status: 200,
    });
    return 'escalated';
  }
  return 'confirmed';
}

const GRAPHQL_TYPENAME = JSON.stringify({ query: '{ __typename }' });
const GRAPHQL_INTROSPECTION = JSON.stringify({
  query: '{ __schema { queryType { name } mutationType { name } } }',
});

async function runGraphql(
  finding: LadderFindingInput,
  url: URL,
  _canary: string,
  probe: DepthProber,
  state: LadderState,
): Promise<DepthLevel> {
  const headers = { 'content-type': 'application/json' };
  // Confirm: a read-only `{ __typename }` query returns data. This is a
  // query, never a mutation, no state changes.
  if (state.probesUsed >= state.maxProbes) return 'unproven';
  state.probesUsed += 1;
  const res = await probe({
    method: 'POST',
    url: url.toString(),
    headers,
    body: GRAPHQL_TYPENAME,
    label: 'graphql-confirm',
  });
  const stop = checkStop(res, state);
  if (stop) {
    state.stopReason = stop;
    return 'unproven';
  }
  let hasData = false;
  try {
    const parsed: unknown = JSON.parse(res.body);
    hasData =
      !!parsed && typeof parsed === 'object' && 'data' in (parsed as Record<string, unknown>);
  } catch {
    /* non-JSON, not confirmed */
  }
  if (!res.ok || !hasData) return 'unproven';
  state.evidence.push({
    rung: 'confirm',
    kind: 'graphql-readonly-query',
    request: `POST ${url.pathname} { __typename } (read-only query)`,
    // The "__typename" key is quoted so the receipt check has a verbatim
    // anchor: it appears in the recorded response body ("data" envelope
    // carrying "__typename"), which is what this rung proved.
    observed: `HTTP ${res.status}: GraphQL endpoint returned data for a read-only query ("__typename" present in the response). No mutation was sent.`,
    status: res.status,
  });
  // Escalate: read-only introspection returns the schema.
  if (state.probesUsed >= state.maxProbes) return 'confirmed';
  state.probesUsed += 1;
  const esc = await probe({
    method: 'POST',
    url: url.toString(),
    headers,
    body: GRAPHQL_INTROSPECTION,
    label: 'graphql-escalate',
  });
  const stop2 = checkStop(esc, state);
  if (stop2) {
    state.stopReason = stop2;
    return 'confirmed';
  }
  let hasSchema = false;
  try {
    const parsed: unknown = JSON.parse(esc.body);
    const data = (parsed as Record<string, unknown> | null)?.['data'] as
      | Record<string, unknown>
      | undefined;
    hasSchema = !!data && typeof data['__schema'] === 'object' && data['__schema'] !== null;
  } catch {
    /* non-JSON */
  }
  if (esc.ok && hasSchema) {
    state.evidence.push({
      rung: 'escalate',
      kind: 'graphql-introspection',
      request: `POST ${url.pathname} { __schema { queryType mutationType } } (read-only introspection)`,
      // Same verbatim anchor as the confirm rung: "__schema" is the key
      // the introspection response carried, and it appears verbatim in
      // the recorded response body.
      observed: `HTTP ${esc.status}: introspection returned the schema ("__schema" present in the response). Schema contents not recorded (only that introspection succeeded).`,
      status: esc.status,
    });
    return 'escalated';
  }
  return 'confirmed';
}

// ── Entry point ────────────────────────────────────────────────────────────

/**
 * Run the depth ladder for one finding. Never throws: any probe failure or
 * unexpected error degrades to an explicit hint, so a ladder failure can
 * never drop or corrupt a finding.
 */
export async function validateFindingWithLadder(
  finding: LadderFindingInput,
  prober: DepthProber,
  opts: LadderOptions = {},
): Promise<FindingVerification> {
  const now = opts.now ?? (() => new Date().toISOString());
  const maxProbes = opts.maxProbes ?? MAX_PROBES_DEFAULT;
  const kind = classifyFinding(finding);
  if (kind === 'unprobeable') {
    return untestedVerification(
      `no read-only live probe exists for category "${finding.category}" — the ladder only tests XSS, IDOR, CORS and GraphQL findings live.`,
      now,
    );
  }
  const url = resolveUrl(finding, opts.targetUrl);
  if (!url) {
    return untestedVerification(
      'no usable URL could be resolved from the finding location — the ladder needs a target URL to probe.',
      now,
    );
  }
  const canary = generateCanary();
  const state: LadderState = newLadderState(maxProbes);
  // Wrap the prober so every probe response is offered to the caller's
  // snapshot hook (proof gate) without changing probe behaviour.
  const tracingProber: DepthProber = async (req) => {
    const res = await prober(req);
    if (opts.onProbe) {
      try {
        // Surface everything the caller needs for a proof record: the
        // status, the redacted headers (re-redacted here so a custom
        // prober that did not redact cannot leak cookie/auth values into
        // the hook), and the observed JSON field names (the prober's own
        // shape when it supplies one, else derived from the body).
        const shape = res.shape ?? jsonFieldNames(res.body) ?? undefined;
        opts.onProbe({
          label: req.label,
          url: req.url,
          body: res.body,
          ...(res.status !== undefined ? { status: res.status } : {}),
          ...(res.headers ? { headers: redactHeaders(res.headers) } : {}),
          ...(shape ? { shape } : {}),
        });
      } catch {
        // A snapshot hook must never fail the ladder.
      }
    }
    return res;
  };
  let depth: DepthLevel = 'unproven';
  try {
    if (kind === 'xss') depth = await runXss(finding, url, canary, tracingProber, state);
    else if (kind === 'idor') {
      depth = await runIdor(finding, url, canary, tracingProber, state, opts.allowNeighborShapeProbe ?? true);
    } else if (kind === 'cors') depth = await runCors(finding, url, canary, tracingProber, state);
    else if (kind === 'graphql') depth = await runGraphql(finding, url, canary, tracingProber, state);
  } catch (err) {
    // A ladder crash is a ladder failure, never a finding failure.
    state.stopReason = `ladder error: ${(err as Error).message.slice(0, 200)}`;
    depth = 'unproven';
  }
  if (state.probesUsed >= maxProbes && depth === 'unproven' && !state.stopReason) {
    state.stopReason = `probe budget exhausted (${maxProbes} probes) — ladder stopped`;
  }
  const { impact, summary } = impactFor(depth, kind);
  return {
    status: depth === 'unproven' ? 'hint' : 'verified',
    depth,
    impact,
    impactSummary: state.stopReason
      ? `${summary} Note: ${state.stopReason}.`
      : summary,
    canaryToken: canary,
    evidence: state.evidence,
    ...(state.stopReason ? { stopReason: state.stopReason } : {}),
    testedAt: now(),
    method: LADDER_METHOD,
  };
}

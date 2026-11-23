/**
 * MCP client: remote servers over Streamable HTTP, with a legacy SSE
 * fallback. Written from the public MCP spec. Same-origin redirects only,
 * 8 MiB response cap, 120 s per-call timeout. MCP tools never bypass
 * BugSeek's gates, and tool results are untrusted data. stdio is out of
 * scope: no worker host exists to spawn a local server yet.
 */
import http from 'node:http';
import https from 'node:https';
import { Buffer } from 'node:buffer';
import { Readable } from 'node:stream';
import { config } from '../config.js';
import { resolvePublicAddresses, type ResolvedHostAddress } from '../guardrails/scope.js';
import { pinnedLookup } from '../webcheck/fetch.js';

/** Only 'http' and 'sse'. stdio is not supported here. */
export type McpTransport = 'http' | 'sse';

export const MCP_TRANSPORTS: readonly McpTransport[] = ['http', 'sse'];

/** Protocol version this client offers at initialize time. */
export const MCP_PROTOCOL_VERSION = '2024-11-05';

/** Server versions we have seen in the wild; anything else is still accepted and recorded as-is. */
export const MCP_KNOWN_PROTOCOL_VERSIONS: readonly string[] = [
  '2024-11-05',
  '2025-03-26',
  '2025-06-18',
];

/** Default per-call timeout (ms). */
export const MCP_DEFAULT_TIMEOUT_MS = 120_000;

/** Default response-size cap: 8 MiB, applied to JSON bodies and SSE streams alike. */
export const MCP_MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

/** Redirects are followed manually, at most this many hops. */
export const MCP_MAX_REDIRECTS = 5;

/** Minimal fetch surface the client needs, the global Response satisfies this shape. */
export interface McpFetchResponse {
  readonly status: number;
  readonly headers: { get(name: string): string | null };
  text(): Promise<string>;
  readonly body: ReadableStream<Uint8Array> | null;
}

export type McpFetchFn = (url: string, init?: RequestInit) => Promise<McpFetchResponse>;

export interface McpToolSchema {
  name: string;
  description?: string;
  inputSchema: Record<string, unknown>;
}

export interface McpInitializeResult {
  protocolVersion: string;
  serverInfo?: { name?: string; version?: string };
  capabilities?: Record<string, unknown>;
}

export interface McpToolCallResult {
  content: unknown[];
  isError?: boolean;
  [key: string]: unknown;
}

export interface McpClientOptions {
  url: string;
  transport?: McpTransport;
  /** Extra headers (e.g. Authorization) sent on every request to the configured origin only. */
  headers?: Record<string, string>;
  /** Injectable fetch, defaults to the global fetch. Tests pass a fake. */
  fetchFn?: McpFetchFn;
  /** Per-call timeout in ms (default 120 s). */
  timeoutMs?: number;
  /** Response-size cap in bytes (default 8 MiB). */
  maxResponseBytes?: number;
}

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: number;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc?: string;
  id?: number | string | null;
  result?: unknown;
  error?: { code?: number; message?: string };
}

interface SseEvent {
  event: string;
  data: string;
  id?: string;
}

/**
 * A McpFetchResponse backed by a node:http response stream. The body
 * stays a live stream (SSE needs it); text() drains it once and caches.
 */
class NodeMcpResponse implements McpFetchResponse {
  readonly status: number;
  readonly body: ReadableStream<Uint8Array> | null;
  readonly headers: { get(name: string): string | null };
  private readonly headerMap: Map<string, string>;
  private textCache: string | null = null;

  constructor(status: number, headers: Map<string, string>, stream: Readable | null) {
    this.status = status;
    this.headerMap = headers;
    this.headers = { get: (name: string) => this.headerMap.get(name.toLowerCase()) ?? null };
    this.body = stream
      ? (Readable.toWeb(stream) as unknown as ReadableStream<Uint8Array>)
      : null;
  }

  async text(): Promise<string> {
    if (this.textCache !== null) return this.textCache;
    if (!this.body) return '';
    const reader = this.body.getReader();
    const chunks: Uint8Array[] = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) chunks.push(value);
    }
    reader.releaseLock();
    this.textCache = Buffer.concat(chunks).toString('utf8');
    return this.textCache;
  }
}

/**
 * The default transport: one node:http request that connects only to an
 * address the SSRF guard approved for this URL (pinned lookup). The
 * global fetch cannot take a custom lookup, so a checked hostname could
 * rebind between the check and the connect; this closes that window.
 * Every call re-resolves and re-validates, redirect hops included.
 */
async function nodeFetchPinned(
  url: URL,
  addresses: ResolvedHostAddress[],
  init: RequestInit,
  timeoutMs: number,
): Promise<McpFetchResponse> {
  const isHttps = url.protocol === 'https:';
  const lib = isHttps ? https : http;
  const headersIn = (init.headers ?? {}) as Record<string, string>;
  const body = typeof init.body === 'string' ? Buffer.from(init.body, 'utf8') : null;
  const headers: Record<string, string> = { ...headersIn };
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
        const headersOut = new Map<string, string>();
        for (const [k, v] of Object.entries(res.headers)) {
          if (typeof v === 'string') headersOut.set(k.toLowerCase(), v);
          else if (Array.isArray(v)) headersOut.set(k.toLowerCase(), v.join(', '));
        }
        resolve(new NodeMcpResponse(res.statusCode ?? 0, headersOut, res as unknown as Readable));
      },
    );
    const onAbort = () => req.destroy(new Error('mcp_timeout: request aborted'));
    if (init.signal) {
      if (init.signal.aborted) onAbort();
      else init.signal.addEventListener('abort', onAbort, { once: true });
    }
    req.setTimeout(timeoutMs, () => req.destroy(new Error('mcp_timeout: request timed out')));
    req.on('error', reject);
    req.end(body ?? undefined);
  });
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/** Read-only methods: safe to re-issue once if the SSE stream died mid-call. */
const IDEMPOTENT_METHODS = new Set(['initialize', 'tools/list', 'ping']);

async function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  errorFactory: () => Error,
  onTimeout?: () => void,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          onTimeout?.();
          reject(errorFactory());
        }, ms);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function parseJsonRpcText(text: string): JsonRpcResponse {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error('mcp_bad_response: server returned invalid JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('mcp_bad_response: server returned a JSON value that is not a JSON-RPC object');
  }
  return parsed as JsonRpcResponse;
}

/** Parse one SSE `data:` payload as a JSON-RPC message; null when it is not one (heartbeat, comment, other event). */
function parseJsonRpcEvent(data: string): JsonRpcResponse | null {
  const trimmed = data.trim();
  if (!trimmed.startsWith('{')) return null;
  try {
    const parsed = JSON.parse(trimmed) as Record<string, unknown>;
    if (parsed['jsonrpc'] !== '2.0') return null;
    if (!('result' in parsed) && !('error' in parsed)) return null;
    return parsed as unknown as JsonRpcResponse;
  } catch {
    return null;
  }
}

function assertHttpUrl(raw: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`mcp_invalid_url: ${raw}`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(
      `mcp_invalid_url: only http(s) MCP server URLs are supported, got ${parsed.protocol}`,
    );
  }
  return parsed;
}

function assertTransport(value: unknown): asserts value is McpTransport {
  if (typeof value !== 'string' || !(MCP_TRANSPORTS as readonly string[]).includes(value)) {
    throw new Error(
      `mcp_invalid_transport: ${String(value)} — only 'http' and 'sse' are supported; ` +
        'a stdio MCP server needs a worker host (no process host exists yet)',
    );
  }
}

/**
 * Incremental SSE parser over a ReadableStream. Buffers partial lines,
 * hands out complete events, enforces the byte cap, and reports a clean
 * stream end as null so the caller can tell "no more events" apart
 * from "timed out".
 */
class SseStream {
  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  private readonly decoder = new TextDecoder();
  private textBuffer = '';
  private current: { event: string; data: string[]; id?: string } | null = null;
  private readonly eventQueue: SseEvent[] = [];
  private bytesRead = 0;
  private streamEnded = false;

  constructor(
    stream: ReadableStream<Uint8Array>,
    private readonly maxBytes: number,
  ) {
    this.reader = stream.getReader();
  }

  /** True once a read has returned done, the server closed the stream. */
  get isClosed(): boolean {
    return this.streamEnded;
  }

  async cancel(): Promise<void> {
    this.streamEnded = true;
    try {
      await this.reader.cancel();
    } catch {
      /* already closed */
    }
    try {
      this.reader.releaseLock();
    } catch {
      /* already released */
    }
  }

  private feedText(text: string): void {
    this.textBuffer += text;
    let idx: number;
    while ((idx = this.textBuffer.indexOf('\n')) >= 0) {
      let line = this.textBuffer.slice(0, idx);
      this.textBuffer = this.textBuffer.slice(idx + 1);
      if (line.endsWith('\r')) line = line.slice(0, -1);
      this.feedLine(line);
    }
  }

  private feedLine(line: string): void {
    if (line === '') {
      if (this.current) {
        this.eventQueue.push({
          event: this.current.event || 'message',
          data: this.current.data.join('\n'),
          id: this.current.id,
        });
        this.current = null;
      }
      return;
    }
    if (line.startsWith(':')) return; // SSE comment / heartbeat
    const colon = line.indexOf(':');
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? '' : line.slice(colon + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (!this.current) this.current = { event: 'message', data: [] };
    if (field === 'event') this.current.event = value;
    else if (field === 'data') this.current.data.push(value);
    else if (field === 'id') this.current.id = value;
    // Unknown fields are ignored per the SSE spec.
  }

  private flushPartial(): SseEvent | null {
    if (this.current && (this.current.data.length > 0 || this.current.event !== 'message')) {
      const event: SseEvent = {
        event: this.current.event,
        data: this.current.data.join('\n'),
        id: this.current.id,
      };
      this.current = null;
      return event;
    }
    return null;
  }

  private async pumpUntilEvent(): Promise<SseEvent | null> {
    while (true) {
      if (this.eventQueue.length > 0) return this.eventQueue.shift() as SseEvent;
      if (this.streamEnded) return this.flushPartial();
      const { done, value } = await this.reader.read();
      if (done) {
        this.streamEnded = true;
        const tail = this.decoder.decode();
        if (tail) this.feedText(tail);
        if (this.eventQueue.length > 0) return this.eventQueue.shift() as SseEvent;
        return this.flushPartial();
      }
      this.bytesRead += value.byteLength;
      if (this.bytesRead > this.maxBytes) {
        await this.cancel();
        throw new Error(
          `mcp_response_too_large: SSE stream exceeded ${this.maxBytes} bytes`,
        );
      }
      this.feedText(this.decoder.decode(value, { stream: true }));
    }
  }

  /** Next complete event, or null on clean stream end. Throws on timeout or on the byte cap. */
  async nextEvent(timeoutMs: number): Promise<SseEvent | null> {
    return withTimeout(
      this.pumpUntilEvent(),
      timeoutMs,
      () => new Error('mcp_timeout: timed out waiting for an SSE event'),
      () => void this.cancel(),
    );
  }
}

export class McpClient {
  readonly url: string;
  readonly transport: McpTransport;
  private readonly headers: Record<string, string>;
  private readonly fetchFn: McpFetchFn;
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;
  /** Private targets are refused on the default transport unless allowed in non-production. */
  private readonly allowPrivate: boolean;
  private nextId = 1;
  private sessionId: string | null = null;
  private negotiatedVersion: string | null = null;
  private didInitialize = false;
  private sseSession: { endpoint: string; stream: SseStream } | null = null;

  constructor(opts: McpClientOptions) {
    const parsed = assertHttpUrl(opts.url);
    if (opts.transport !== undefined) assertTransport(opts.transport);
    this.url = parsed.toString();
    this.transport = opts.transport ?? 'http';
    this.headers = { ...(opts.headers ?? {}) };
    this.allowPrivate = config.nodeEnv !== 'production' && config.allowPrivateTargets;
    // An injected fetch owns its transport (tests); the default transport
    // resolves, validates and pins the host on every request.
    this.fetchFn =
      opts.fetchFn ??
      ((url: string, init?: RequestInit) => this.defaultFetch(url, init));
    this.timeoutMs = opts.timeoutMs ?? MCP_DEFAULT_TIMEOUT_MS;
    this.maxResponseBytes = opts.maxResponseBytes ?? MCP_MAX_RESPONSE_BYTES;
  }

  /** Default transport: SSRF-check the URL, then fetch it pinned to the approved addresses. */
  private async defaultFetch(url: string, init?: RequestInit): Promise<McpFetchResponse> {
    const parsed = new URL(url);
    const addresses = await resolvePublicAddresses(parsed.hostname, this.allowPrivate);
    return nodeFetchPinned(parsed, addresses, init ?? {}, this.timeoutMs);
  }

  /** Protocol version the server negotiated at initialize, null before then. */
  get protocolVersion(): string | null {
    return this.negotiatedVersion;
  }

  get isInitialized(): boolean {
    return this.didInitialize;
  }

  /** Handshake: offers our protocol version, records the server's, then sends notifications/initialized. */
  async initialize(): Promise<McpInitializeResult> {
    const result = (await this.request('initialize', {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'bugseek', version: '1.0' },
    })) as Record<string, unknown>;
    const serverVersion =
      typeof result['protocolVersion'] === 'string' ? result['protocolVersion'] : null;
    this.negotiatedVersion = serverVersion ?? MCP_PROTOCOL_VERSION;
    this.didInitialize = true;
    // Best-effort: a failed initialized notification must not fail the handshake.
    await this.notify('notifications/initialized', {}).catch(() => undefined);
    return {
      protocolVersion: this.negotiatedVersion,
      serverInfo: (result['serverInfo'] as McpInitializeResult['serverInfo']) ?? undefined,
      capabilities: (result['capabilities'] as Record<string, unknown>) ?? undefined,
    };
  }

  /** tools/list, the schemas the registry later gates behind skills. */
  async listTools(): Promise<McpToolSchema[]> {
    const result = (await this.request('tools/list', {})) as Record<string, unknown>;
    const tools = result['tools'];
    if (!Array.isArray(tools)) {
      throw new Error('mcp_bad_response: tools/list returned no tools array');
    }
    return tools.map((entry) => {
      const rec = entry as Record<string, unknown>;
      if (typeof rec['name'] !== 'string' || !rec['name']) {
        throw new Error('mcp_bad_response: tools/list returned a tool without a name');
      }
      return {
        name: rec['name'],
        description: typeof rec['description'] === 'string' ? rec['description'] : undefined,
        inputSchema:
          rec['inputSchema'] && typeof rec['inputSchema'] === 'object'
            ? (rec['inputSchema'] as Record<string, unknown>)
            : {},
      };
    });
  }

  /** tools/call. A tool that reports isError throws; the raw result is returned otherwise. */
  async callTool(
    name: string,
    args: Record<string, unknown> = {},
    opts?: { timeoutMs?: number },
  ): Promise<McpToolCallResult> {
    if (!name) throw new Error('mcp_tool_name_required');
    const result = (await this.request(
      'tools/call',
      { name, arguments: args },
      { timeoutMs: opts?.timeoutMs },
    )) as Record<string, unknown>;
    const content = Array.isArray(result['content']) ? (result['content'] as unknown[]) : [];
    const isError = result['isError'] === true;
    if (isError) {
      const text = content
        .map((c) => {
          const rec = c as Record<string, unknown>;
          return typeof rec['text'] === 'string' ? rec['text'] : JSON.stringify(c);
        })
        .join('\n');
      throw new Error(
        `mcp_tool_error: tool ${name} reported an error${text ? `: ${text.slice(0, 500)}` : ''}`,
      );
    }
    return { ...result, content, isError: false };
  }

  /** ping, proves the server is still answering. */
  async ping(): Promise<boolean> {
    await this.request('ping', {});
    return true;
  }

  // ── JSON-RPC plumbing ──────────────────────────────────────────────────

  private async request(
    method: string,
    params: Record<string, unknown>,
    opts?: { timeoutMs?: number },
  ): Promise<unknown> {
    const timeoutMs = opts?.timeoutMs ?? this.timeoutMs;
    const id = this.nextId++;
    const payload: JsonRpcRequest = { jsonrpc: '2.0', id, method, params };
    // The timeout is enforced by this client's own timer (a ref'd
    // setTimeout), not only by the AbortSignal handed to fetch: a
    // fetch that ignores its signal must not be able to hang the call
    // forever, and an unref'd signal timer alone cannot keep the
    // process alive long enough for the timeout to fire.
    const attempt =
      this.transport === 'http'
        ? this.httpRequest(payload, timeoutMs)
        : this.sseRequest(payload, timeoutMs);
    // If the timeout wins the race, the transport may still settle
    // later, mark it handled so a late rejection is never unhandled.
    attempt.catch(() => undefined);
    let response: JsonRpcResponse;
    try {
      response = await withTimeout(
        attempt,
        timeoutMs,
        () => new Error(`mcp_timeout: ${method} did not complete within ${timeoutMs}ms`),
      );
    } catch (err) {
      const message = (err as Error)?.message ?? String(err);
      // AbortSignal.timeout surfaces as a DOMException named TimeoutError.
      if ((err as Error)?.name === 'TimeoutError' || /^mcp_timeout/.test(message)) {
        throw new Error(`mcp_timeout: ${method} did not complete within ${timeoutMs}ms`);
      }
      throw err;
    }
    if (response.error) {
      throw new Error(
        `mcp_error: ${response.error.message ?? 'unknown MCP error'} (code ${response.error.code ?? '?'})`,
      );
    }
    if (!('result' in response)) {
      throw new Error('mcp_bad_response: JSON-RPC response carried neither result nor error');
    }
    return response.result;
  }

  /** A notification (no id, no response expected). Best-effort: never throws. */
  private async notify(method: string, params: Record<string, unknown>): Promise<void> {
    const payload: JsonRpcRequest = { jsonrpc: '2.0', method, params };
    const headers = this.requestHeaders();
    const send = async (): Promise<void> => {
      if (this.transport === 'http') {
        const res = await this.fetchWithRedirects(this.url, {
          method: 'POST',
          headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        await res.text().catch(() => undefined);
      } else {
        const session = await this.ensureSseSession(this.timeoutMs);
        const res = await this.fetchWithRedirects(session.endpoint, {
          method: 'POST',
          headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        await res.text().catch(() => undefined);
      }
    };
    try {
      const pending = send();
      pending.catch(() => undefined);
      // The client's own timer, so a hanging notification cannot stall
      // the handshake even if the fetch ignores its signal.
      await withTimeout(pending, this.timeoutMs, () => new Error('mcp_timeout: notification timed out'));
    } catch {
      // Notifications are fire-and-forget; a failure here must not fail the caller.
    }
  }

  private requestHeaders(): Record<string, string> {
    return {
      ...(this.sessionId ? { 'mcp-session-id': this.sessionId } : {}),
      ...this.headers,
    };
  }

  // ── Streamable HTTP transport ──────────────────────────────────────────

  private async httpRequest(payload: JsonRpcRequest, timeoutMs: number): Promise<JsonRpcResponse> {
    const res = await this.fetchWithRedirects(this.url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        ...this.requestHeaders(),
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs),
    });
    return this.readJsonRpcResponse(res, payload.id as number, timeoutMs);
  }

  // ── Legacy SSE transport ───────────────────────────────────────────────

  private async sseRequest(payload: JsonRpcRequest, timeoutMs: number): Promise<JsonRpcResponse> {
    const attempt = async (): Promise<JsonRpcResponse> => {
      const session = await this.ensureSseSession(timeoutMs);
      const res = await this.fetchWithRedirects(session.endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          ...this.requestHeaders(),
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(timeoutMs),
      });
      this.rememberSessionId(res);
      if (res.status < 200 || res.status >= 300) {
        const snippet = await this.readErrorSnippet(res);
        throw new Error(
          `mcp_http_${res.status}: MCP server answered HTTP ${res.status}${snippet ? `: ${snippet}` : ''}`,
        );
      }
      const contentType = (res.headers.get('content-type') ?? '').toLowerCase();
      if (contentType.includes('application/json')) {
        return parseJsonRpcText(await this.readBodyWithCap(res));
      }
      if (res.status === 202) {
        // Accepted, the response arrives as an event on the GET stream.
        return this.awaitSseResponse(payload.id as number, timeoutMs);
      }
      const text = await this.readBodyWithCap(res);
      if (text.trim()) return parseJsonRpcText(text);
      return this.awaitSseResponse(payload.id as number, timeoutMs);
    };

    try {
      return await attempt();
    } catch (err) {
      const message = (err as Error)?.message ?? '';
      // The GET stream died before the response arrived. Read-only
      // methods are safe to re-issue once over a fresh stream; a
      // tools/call is never retried, it may already have executed.
      if (
        IDEMPOTENT_METHODS.has(payload.method) &&
        message.startsWith('mcp_sse_stream_closed')
      ) {
        this.dropSseSession();
        return attempt();
      }
      throw err;
    }
  }

  private async ensureSseSession(
    timeoutMs: number,
  ): Promise<{ endpoint: string; stream: SseStream }> {
    if (this.sseSession && !this.sseSession.stream.isClosed) return this.sseSession;
    this.dropSseSession();
    const res = await this.fetchWithRedirects(this.url, {
      method: 'GET',
      headers: { accept: 'text/event-stream', ...this.requestHeaders() },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (res.status < 200 || res.status >= 300) {
      const snippet = await this.readErrorSnippet(res);
      throw new Error(
        `mcp_http_${res.status}: MCP server answered HTTP ${res.status}${snippet ? `: ${snippet}` : ''}`,
      );
    }
    this.rememberSessionId(res);
    if (!res.body) {
      throw new Error('mcp_bad_response: SSE endpoint returned no readable body');
    }
    const stream = new SseStream(res.body, this.maxResponseBytes);
    const deadline = Date.now() + timeoutMs;
    try {
      while (true) {
        const remaining = deadline - Date.now();
        if (remaining <= 0) {
          throw new Error('mcp_timeout: timed out waiting for the SSE endpoint event');
        }
        const event = await stream.nextEvent(remaining);
        if (event === null) {
          throw new Error(
            'mcp_sse_no_endpoint: SSE stream ended before the server sent its endpoint event',
          );
        }
        if (event.event === 'endpoint') {
          const endpoint = new URL(event.data.trim(), this.url).toString();
          // The endpoint comes from the server, but a compromised server
          // must not bounce our POSTs (and credentials) elsewhere.
          if (new URL(endpoint).origin !== new URL(this.url).origin) {
            throw new Error(
              `mcp_cross_origin_redirect: MCP server sent an SSE endpoint on ${new URL(endpoint).origin}, ` +
                `which is not the configured server origin ${new URL(this.url).origin}`,
            );
          }
          this.sseSession = { endpoint, stream };
          return this.sseSession;
        }
        // Other events while waiting for the endpoint are ignored.
      }
    } catch (err) {
      await stream.cancel();
      throw err;
    }
  }

  private async awaitSseResponse(id: number, timeoutMs: number): Promise<JsonRpcResponse> {
    const session = this.sseSession;
    if (!session) throw new Error('mcp_sse_no_session: no SSE session is open');
    const deadline = Date.now() + timeoutMs;
    while (true) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        throw new Error('mcp_timeout: timed out waiting for the MCP response on the SSE stream');
      }
      let event: SseEvent | null;
      try {
        event = await session.stream.nextEvent(remaining);
      } catch (err) {
        this.dropSseSession();
        throw err;
      }
      if (event === null) {
        this.dropSseSession();
        throw new Error(
          'mcp_sse_stream_closed: SSE stream ended before the response arrived',
        );
      }
      const parsed = parseJsonRpcEvent(event.data);
      if (!parsed) continue;
      if (parsed.id !== undefined && parsed.id !== id) continue;
      return parsed;
    }
  }

  private dropSseSession(): void {
    const session = this.sseSession;
    this.sseSession = null;
    if (session) void session.stream.cancel();
  }

  // ── Shared helpers ─────────────────────────────────────────────────────

  private rememberSessionId(res: McpFetchResponse): void {
    const sessionId = res.headers.get('mcp-session-id');
    if (sessionId) this.sessionId = sessionId;
  }

  /**
   * fetch with manual redirect handling. Redirects are followed only
   * to the same origin as the configured server URL (max 5 hops); a
   * cross-origin redirect throws instead of being followed, so the
   * Authorization header is never sent to another host.
   */
  private async fetchWithRedirects(url: string, init: RequestInit): Promise<McpFetchResponse> {
    const origin = new URL(this.url).origin;
    let current = url;
    let currentInit = init;
    for (let hop = 0; hop <= MCP_MAX_REDIRECTS; hop++) {
      const res = await this.fetchFn(current, { ...currentInit, redirect: 'manual' });
      const status = res.status;
      if (!REDIRECT_STATUSES.has(status)) return res;
      const location = res.headers.get('location');
      if (!location) return res; // 3xx without a target: let the caller report the status.
      if (hop === MCP_MAX_REDIRECTS) {
        throw new Error(
          `mcp_too_many_redirects: redirect chain exceeded ${MCP_MAX_REDIRECTS} hops`,
        );
      }
      const target = new URL(location, current);
      if (target.origin !== origin) {
        throw new Error(
          `mcp_cross_origin_redirect: MCP server redirected to ${target.origin}, ` +
            `which is not the configured server origin ${origin} — refusing to follow ` +
            `(credentials are never sent to a redirected host)`,
        );
      }
      // 303: follow with GET and no body, per HTTP semantics.
      if (status === 303) {
        currentInit = { ...currentInit, method: 'GET', body: undefined };
      }
      current = target.toString();
    }
    throw new Error(`mcp_too_many_redirects: redirect chain exceeded ${MCP_MAX_REDIRECTS} hops`);
  }

  /** Read a JSON-RPC response that arrived as JSON or as an SSE stream. */
  private async readJsonRpcResponse(
    res: McpFetchResponse,
    id: number,
    timeoutMs: number,
  ): Promise<JsonRpcResponse> {
    this.rememberSessionId(res);
    if (res.status < 200 || res.status >= 300) {
      const snippet = await this.readErrorSnippet(res);
      throw new Error(
        `mcp_http_${res.status}: MCP server answered HTTP ${res.status}${snippet ? `: ${snippet}` : ''}`,
      );
    }
    const contentType = (res.headers.get('content-type') ?? '').toLowerCase();
    if (contentType.includes('text/event-stream')) {
      if (!res.body) {
        throw new Error('mcp_bad_response: SSE response without a readable body');
      }
      const stream = new SseStream(res.body, this.maxResponseBytes);
      try {
        const deadline = Date.now() + timeoutMs;
        while (true) {
          const remaining = deadline - Date.now();
          if (remaining <= 0) {
            throw new Error('mcp_timeout: timed out waiting for the MCP response');
          }
          const event = await stream.nextEvent(remaining);
          if (event === null) {
            throw new Error(
              'mcp_sse_stream_closed: SSE stream ended before the response arrived',
            );
          }
          const parsed = parseJsonRpcEvent(event.data);
          if (!parsed) continue;
          if (parsed.id !== undefined && parsed.id !== id) continue;
          return parsed;
        }
      } finally {
        await stream.cancel();
      }
    }
    return parseJsonRpcText(await this.readBodyWithCap(res));
  }

  /** Read a response body with the size cap enforced while streaming. */
  private async readBodyWithCap(res: McpFetchResponse): Promise<string> {
    if (res.body) {
      const reader = res.body.getReader();
      const chunks: Uint8Array[] = [];
      let total = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.byteLength;
          if (total > this.maxResponseBytes) {
            await reader.cancel().catch(() => undefined);
            throw new Error(
              `mcp_response_too_large: response exceeded ${this.maxResponseBytes} bytes`,
            );
          }
          chunks.push(value);
        }
      } finally {
        try {
          reader.releaseLock();
        } catch {
          /* already released */
        }
      }
      return Buffer.concat(chunks).toString('utf8');
    }
    const text = await res.text();
    if (Buffer.byteLength(text, 'utf8') > this.maxResponseBytes) {
      throw new Error(
        `mcp_response_too_large: response exceeded ${this.maxResponseBytes} bytes`,
      );
    }
    return text;
  }

  /** Short diagnostic snippet of an error body (first 200 chars, newlines stripped). Never includes request headers. */
  private async readErrorSnippet(res: McpFetchResponse): Promise<string> {
    try {
      const text = await this.readBodyWithCap(res);
      return text.replace(/[\r\n]+/g, ' ').trim().slice(0, 200);
    } catch {
      return '';
    }
  }
}

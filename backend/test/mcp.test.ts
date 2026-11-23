/**
 * Unit tests for the MCP client, tool registry, server store and the
 * credential-masking route helper (src/mcp/*, src/routes/mcp.ts).
 * No network, no DB, no LLM, the client is driven by injected fake
 * fetches (real Response objects), the stores are the memory
 * implementations.
 *
 * Run:  npx tsx test/mcp.test.ts   (from backend/)
 */
import { McpClient, type McpFetchFn } from '../src/mcp/client.js';
import { McpToolRegistry } from '../src/mcp/registry.js';
import { MemoryMcpServerStore, validateMcpServerInput } from '../src/mcp/servers.js';
import { MemorySecretStore } from '../src/secrets/store.js';
import { toServerSummary } from '../src/routes/mcp.js';

let failures = 0;
let passes = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else { passes++; console.log(`ok: ${name}`); }
}

async function throwsAsync(name: string, pattern: RegExp, fn: () => Promise<unknown>) {
  let message = '';
  try {
    await fn();
  } catch (err) {
    message = (err as Error).message;
  }
  check(name, pattern.test(message), message || '(did not throw)');
}

function throws(name: string, pattern: RegExp, fn: () => unknown) {
  let message = '';
  try {
    fn();
  } catch (err) {
    message = (err as Error).message;
  }
  check(name, pattern.test(message), message || '(did not throw)');
}

function jsonRpc(id: number | string, result: unknown, headers?: Record<string, string>): Response {
  return new Response(JSON.stringify({ jsonrpc: '2.0', id, result }), {
    status: 200,
    headers: { 'content-type': 'application/json', ...(headers ?? {}) },
  });
}

function jsonRpcError(id: number | string, code: number, message: string): Response {
  return new Response(JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

const TOOLS = [
  { name: 'search', description: 'search the web', inputSchema: { type: 'object', properties: {} } },
  { name: 'fetch', description: 'fetch a url', inputSchema: { type: 'object', properties: {} } },
];

/** Streamable-HTTP fake: answers initialize / tools/list / tools/call / ping from a script. */
function makeHttpFake(seen: Array<{ url: string; method: string; headers: Record<string, string>; body: string }>): McpFetchFn {
  return async (url, init) => {
    const body = typeof init?.body === 'string' ? init.body : '';
    const headers: Record<string, string> = {};
    const rawHeaders = init?.headers as Record<string, string> | undefined;
    if (rawHeaders) for (const [k, v] of Object.entries(rawHeaders)) headers[k.toLowerCase()] = v;
    seen.push({ url, method: init?.method ?? 'GET', headers, body });
    let payload: { id?: number; method?: string; params?: Record<string, unknown> } = {};
    try {
      payload = JSON.parse(body) as typeof payload;
    } catch {
      payload = {};
    }
    if (payload.id === undefined) {
      return new Response(null, { status: 202 }); // notification
    }
    const id = payload.id as number;
    switch (payload.method) {
      case 'initialize':
        return jsonRpc(id, {
          protocolVersion: '2025-03-26',
          capabilities: {},
          serverInfo: { name: 'fake-mcp', version: '0.1' },
        }, { 'mcp-session-id': 'sess-1' });
      case 'tools/list':
        return jsonRpc(id, { tools: TOOLS });
      case 'tools/call': {
        const params = (payload.params ?? {}) as { name?: string; arguments?: Record<string, unknown> };
        if ((params.arguments as Record<string, unknown> | undefined)?.['fail']) {
          return jsonRpc(id, { content: [{ type: 'text', text: 'boom' }], isError: true });
        }
        return jsonRpc(id, { content: [{ type: 'text', text: 'hello from tool' }], isError: false });
      }
      case 'ping':
        return jsonRpc(id, {});
      default:
        return jsonRpcError(id, -32601, 'Method not found');
    }
  };
}

async function main() {
  // ── 1. initialize handshake + tools/list parsing ──
  {
    const seen: Array<{ url: string; method: string; headers: Record<string, string>; body: string }> = [];
    const client = new McpClient({
      url: 'https://mcp.example.com/mcp',
      fetchFn: makeHttpFake(seen),
    });
    const info = await client.initialize();
    check('init: negotiates the server protocol version', info.protocolVersion === '2025-03-26', info);
    check('init: client records the negotiated version', client.protocolVersion === '2025-03-26');
    check('init: client is initialized', client.isInitialized === true);
    const tools = await client.listTools();
    check('list: returns both tools', tools.length === 2 && tools[0]?.name === 'search' && tools[1]?.name === 'fetch', tools);
    check('list: keeps the description', tools[0]?.description === 'search the web', tools[0]);
    // The session id from the initialize response is sent on later requests.
    const listRequest = seen.find((r) => r.body.includes('tools/list'));
    check('session: mcp-session-id forwarded after initialize', listRequest?.headers['mcp-session-id'] === 'sess-1', listRequest?.headers);
    check('ping: answers true', (await client.ping()) === true);
  }

  // ── 2. tools/call success + tool-reported error ──
  {
    const client = new McpClient({ url: 'https://mcp.example.com/mcp', fetchFn: makeHttpFake([]) });
    await client.initialize();
    const result = await client.callTool('search', { q: 'xss' });
    check('call: returns tool content', result.content[0] !== undefined, result);
    check(
      'call: content text survives',
      (result.content[0] as { text?: string })?.text === 'hello from tool',
      result.content,
    );
    await throwsAsync('call: isError tool throws mcp_tool_error', /mcp_tool_error.*boom/, () =>
      client.callTool('search', { fail: true }),
    );
  }

  // ── 3. JSON-RPC error object → mcp_error ──
  {
    const client = new McpClient({ url: 'https://mcp.example.com/mcp', fetchFn: makeHttpFake([]) });
    await throwsAsync('error: JSON-RPC error surfaces as mcp_error', /mcp_error.*Method not found/, () =>
      (client as unknown as { request: (m: string, p: Record<string, unknown>) => Promise<unknown> })
        .request('bogus/method', {}),
    );
  }

  // ── 4. Streamable HTTP may answer tools/list as an SSE stream ──
  {
    const fake: McpFetchFn = async (_url, init) => {
      const body = typeof init?.body === 'string' ? init.body : '';
      const payload = JSON.parse(body) as { id?: number; method?: string };
      if (payload.id === undefined) return new Response(null, { status: 202 });
      if (payload.method === 'initialize') return jsonRpc(payload.id, { protocolVersion: '2024-11-05', capabilities: {}, serverInfo: { name: 'sse-http', version: '0.1' } });
      const sse =
        'event: message\n' +
        `data: ${JSON.stringify({ jsonrpc: '2.0', id: payload.id, result: { tools: TOOLS } })}\n\n`;
      return new Response(sse, { status: 200, headers: { 'content-type': 'text/event-stream' } });
    };
    const client = new McpClient({ url: 'https://mcp.example.com/mcp', fetchFn: fake });
    await client.initialize();
    const tools = await client.listTools();
    check('http+sse: tools/list parsed from an SSE event stream', tools.length === 2 && tools[1]?.name === 'fetch', tools);
  }

  // ── 5. Response-size cap: oversize tools/call errors ──
  {
    const fake: McpFetchFn = async (_url, init) => {
      const body = typeof init?.body === 'string' ? init.body : '';
      const payload = JSON.parse(body) as { id?: number; method?: string };
      if (payload.id === undefined) return new Response(null, { status: 202 });
      if (payload.method === 'initialize') return jsonRpc(payload.id, { protocolVersion: '2024-11-05', capabilities: {}, serverInfo: { name: 'big', version: '0.1' } });
      const big = 'x'.repeat(9 * 1024 * 1024);
      return jsonRpc(payload.id, { content: [{ type: 'text', text: big }] });
    };
    const client = new McpClient({ url: 'https://mcp.example.com/mcp', fetchFn: fake });
    await client.initialize();
    await throwsAsync('cap: 9 MiB tools/call errors with too_large', /mcp_response_too_large/, () =>
      client.callTool('search', {}),
    );
  }

  // ── 6. Cross-origin redirect refused; same-origin redirect followed ──
  {
    const evil: McpFetchFn = async (url) => {
      if (url === 'https://mcp.example.com/mcp') {
        return new Response(null, { status: 302, headers: { location: 'https://evil.example.com/mcp' } });
      }
      return jsonRpc(1, { protocolVersion: '2024-11-05' });
    };
    const client = new McpClient({ url: 'https://mcp.example.com/mcp', fetchFn: evil });
    await throwsAsync(
      'redirect: cross-origin redirect refused',
      /mcp_cross_origin_redirect.*evil\.example\.com/,
      () => client.initialize(),
    );

    const seen: Array<{ url: string; headers: Record<string, string> }> = [];
    const sameOrigin: McpFetchFn = async (url, init) => {
      const headers: Record<string, string> = {};
      const raw = init?.headers as Record<string, string> | undefined;
      if (raw) for (const [k, v] of Object.entries(raw)) headers[k.toLowerCase()] = v;
      seen.push({ url, headers });
      if (url === 'https://mcp.example.com/mcp') {
        return new Response(null, { status: 302, headers: { location: '/mcp/v2' } });
      }
      const body = typeof init?.body === 'string' ? init.body : '';
      const payload = JSON.parse(body) as { id?: number };
      if (payload.id === undefined) return new Response(null, { status: 202 });
      return jsonRpc(payload.id, { protocolVersion: '2024-11-05', capabilities: {}, serverInfo: { name: 'moved', version: '0.1' } });
    };
    const moved = new McpClient({
      url: 'https://mcp.example.com/mcp',
      headers: { authorization: 'Bearer SECRET-TOKEN' },
      fetchFn: sameOrigin,
    });
    const info = await moved.initialize();
    check('redirect: same-origin redirect followed', info.protocolVersion === '2024-11-05', info);
    const followed = seen.find((r) => r.url === 'https://mcp.example.com/mcp/v2');
    check('redirect: credential still sent after a same-origin redirect', followed?.headers['authorization'] === 'Bearer SECRET-TOKEN', followed);
    check('redirect: evil host was never contacted', !seen.some((r) => r.url.includes('evil.example.com')), seen.map((r) => r.url));
  }

  // ── 7. stdio rejected at construction and at config validation ──
  {
    throws('stdio: client rejects a stdio URL', /mcp_invalid_url/, () =>
      new McpClient({ url: 'stdio://my-server' }),
    );
    throws('stdio: client rejects a stdio transport', /mcp_invalid_transport.*worker host/, () =>
      new McpClient({ url: 'https://mcp.example.com/mcp', transport: 'stdio' as never }),
    );
    throws('stdio: config validation rejects stdio', /mcp_invalid_transport.*worker host/, () =>
      validateMcpServerInput({ label: 'x', url: 'https://mcp.example.com/mcp', transport: 'stdio' }),
    );
    throws('stdio: config validation rejects a non-http URL', /mcp_invalid_url/, () =>
      validateMcpServerInput({ label: 'x', url: 'stdio://my-server', transport: 'http' }),
    );
  }

  // ── 8. Per-call timeout ──
  {
    const hanging: McpFetchFn = (_url, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          reject(Object.assign(new Error('The operation timed out.'), { name: 'TimeoutError' }));
        });
      });
    const client = new McpClient({
      url: 'https://mcp.example.com/mcp',
      fetchFn: hanging,
      timeoutMs: 50,
    });
    await throwsAsync('timeout: hanging server errors as mcp_timeout', /mcp_timeout/, () =>
      client.initialize(),
    );
  }

  // ── 9. Legacy SSE fallback (GET stream + endpoint event + POST) ──
  {
    const sseBody =
      'event: endpoint\n' +
      'data: /messages?session=xyz\n\n' +
      'event: message\n' +
      `data: ${JSON.stringify({ jsonrpc: '2.0', id: 1, result: { protocolVersion: '2024-11-05', capabilities: {}, serverInfo: { name: 'sse-fake', version: '0.1' } } })}\n\n` +
      'event: message\n' +
      `data: ${JSON.stringify({ jsonrpc: '2.0', id: 2, result: { tools: TOOLS } })}\n\n`;
    const posts: string[] = [];
    const fake: McpFetchFn = async (url, init) => {
      if ((init?.method ?? 'GET') === 'GET') {
        return new Response(sseBody, { status: 200, headers: { 'content-type': 'text/event-stream' } });
      }
      posts.push(url);
      return new Response(null, { status: 202 });
    };
    const client = new McpClient({ url: 'https://sse.example.com/sse', transport: 'sse', fetchFn: fake });
    const info = await client.initialize();
    check('sse: initialize over legacy SSE', info.protocolVersion === '2024-11-05', info);
    check('sse: POST went to the endpoint event URL', posts[0] === 'https://sse.example.com/messages?session=xyz', posts);
    const tools = await client.listTools();
    check('sse: tools/list over the same stream', tools.length === 2 && tools[0]?.name === 'search', tools);
  }

  // ── 10. SSE stream that dies mid-call: read-only methods reconnect once ──
  {
    let gets = 0;
    const fake: McpFetchFn = async (_url, init) => {
      if ((init?.method ?? 'GET') === 'GET') {
        gets++;
        if (gets === 1) {
          // Endpoint event, then the stream ends before any response.
          return new Response('event: endpoint\ndata: /messages?session=abc\n\n', {
            status: 200,
            headers: { 'content-type': 'text/event-stream' },
          });
        }
        const body =
          'event: endpoint\n' +
          'data: /messages?session=abc\n\n' +
          'event: message\n' +
          `data: ${JSON.stringify({ jsonrpc: '2.0', id: 1, result: { protocolVersion: '2024-11-05', capabilities: {}, serverInfo: { name: 'sse-retry', version: '0.1' } } })}\n\n`;
        return new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } });
      }
      return new Response(null, { status: 202 });
    };
    const client = new McpClient({ url: 'https://sse.example.com/sse', transport: 'sse', fetchFn: fake });
    const info = await client.initialize();
    check('sse-retry: initialize succeeds after the stream is re-established', info.protocolVersion === '2024-11-05', info);
    check('sse-retry: exactly one reconnect happened', gets === 2, gets);
  }

  // ── 11. Registry deferral gate ──
  {
    const registry = new McpToolRegistry();
    registry.registerMcpServer('srv-1', TOOLS, 'http');
    check('defer: tools start deferred', registry.deferredTools('srv-1').length === 2, registry.deferredTools('srv-1'));
    check('defer: deferred entries carry the flag', registry.deferredTools('srv-1')[0]?.deferred === true);
    check('defer: nothing available before a skill loads', registry.availableTools().length === 0);
    check('defer: isToolAvailable is false while deferred', registry.isToolAvailable('srv-1', 'search') === false);
    await throwsAsync('defer: call before unlock throws mcp_tool_deferred', /mcp_tool_deferred/, async () => {
      registry.assertToolAvailable('srv-1', 'search');
    });
    const unlocked = registry.unlockTools('srv-1', 'search-skill');
    check('unlock: unlock returns the tools', unlocked.length === 2, unlocked);
    const available = registry.availableTools();
    check('unlock: tools available after unlock', available.length === 2, available);
    check('unlock: available entry names the skill', available[0]?.unlockedBy === 'search-skill', available[0]);
    check('unlock: isToolAvailable is true after unlock', registry.isToolAvailable('srv-1', 'search') === true);
    registry.assertToolAvailable('srv-1', 'search');
    check('unlock: assert passes after unlock', true);
    await throwsAsync('defer: unknown tool on an unlocked server throws', /mcp_unknown_tool/, async () => {
      registry.assertToolAvailable('srv-1', 'nope');
    });
    await throwsAsync('defer: unknown server throws on unlock', /mcp_unknown_server/, async () => {
      registry.unlockTools('srv-missing', 'some-skill');
    });
    // Re-registering after a reconnect keeps the unlock.
    registry.registerMcpServer('srv-1', [TOOLS[0] as (typeof TOOLS)[number]], 'sse');
    check('defer: re-register keeps the unlock', registry.isToolAvailable('srv-1', 'search') === true);
    const status = registry.listServers();
    check('defer: listServers reports transport + unlock', status[0]?.transport === 'sse' && status[0]?.unlocked === true && status[0]?.unlockedBy === 'search-skill', status);
    check('defer: listServers transport is http|sse only', status.every((s) => s.transport === 'http' || s.transport === 'sse'));
  }

  // ── 12. Server config store (memory) ──
  {
    const store = new MemoryMcpServerStore();
    const created = await store.create({ userId: 'user-1', label: 'search', url: 'https://mcp.example.com/mcp', transport: 'http' });
    check('store: create records the config', created.label === 'search' && created.transport === 'http' && created.enabled === true, created);
    check('store: create stamps createdAt', typeof created.createdAt === 'string' && !Number.isNaN(Date.parse(created.createdAt)));
    await throwsAsync('store: duplicate label for the same user throws', /mcp_server_label_taken/, () =>
      store.create({ userId: 'user-1', label: 'search', url: 'https://other.example.com/mcp', transport: 'sse' }),
    );
    const otherUser = await store.create({ userId: 'user-2', label: 'search', url: 'https://mcp.example.com/mcp', transport: 'http' });
    check('store: same label is fine for another user', otherUser.label === 'search');
    await throwsAsync('store: stdio URL rejected', /mcp_invalid_url/, () =>
      store.create({ userId: 'user-1', label: 'bad', url: 'stdio://x', transport: 'http' }),
    );
    await throwsAsync('store: stdio transport rejected', /mcp_invalid_transport.*worker host/, () =>
      store.create({ userId: 'user-1', label: 'bad2', url: 'https://mcp.example.com/mcp', transport: 'stdio' as never }),
    );
    const mine = await store.listForUser('user-1');
    check('store: listForUser is scoped to the user', mine.length === 1 && mine[0]?.id === created.id, mine);
    check('store: remove by another user fails', (await store.remove(created.id, 'user-2')) === false);
    const disabled = await store.setEnabled(created.id, 'user-1', false);
    check('store: setEnabled disables', disabled !== null && disabled.enabled === false, disabled);
    check('store: remove by the owner works', (await store.remove(created.id, 'user-1')) === true);
    check('store: removed server is gone', (await store.get(created.id)) === null);
  }

  // ── 13. Credentials: hint only, never the value ──
  {
    const secrets = new MemorySecretStore();
    const record = await new MemoryMcpServerStore().create({
      userId: 'user-1',
      label: 'search',
      url: 'https://mcp.example.com/mcp',
      transport: 'http',
    });
    const credential = 'SECRET-TOKEN-ABC123-VALUE';
    await secrets.save({
      userId: 'user-1',
      kind: 'mcp',
      label: record.id,
      encryptedValue: 'ciphertext-not-plaintext',
      hint: 'SECR••••ALUE',
    });
    const summaries = await secrets.list('user-1', 'mcp');
    check('secret: list returns the hint', summaries[0]?.hint === 'SECR••••ALUE', summaries[0]);
    check(
      'secret: list never returns the ciphertext',
      summaries[0] !== undefined && !('encryptedValue' in summaries[0]),
      Object.keys(summaries[0] ?? {}),
    );
    const summary = toServerSummary(record, summaries[0]?.hint ?? null);
    const serialised = JSON.stringify(summary);
    check('summary: plaintext credential never appears in the list response', !serialised.includes(credential), serialised);
    check('summary: hint is present instead', summary.credentialHint === 'SECR••••ALUE', summary);
    check('summary: no credential field at all', !('credential' in summary) && !('apiKey' in summary) && !('encryptedValue' in summary));
  }

  if (failures > 0) { console.error(`${failures} mcp test(s) failed, ${passes} passed`); process.exit(1); }
  console.log(`ALL MCP TESTS PASSED (${passes} checks)`);
  process.exit(0);
}

main().catch((e) => { console.error('mcp test crashed', e); process.exit(1); });

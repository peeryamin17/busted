import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import type { Database } from '../db/db.js';
import { McpClient, type McpFetchFn } from '../mcp/client.js';
import { mcpRegistry, type McpToolRegistry } from '../mcp/registry.js';
import {
  assertMcpServerUrl,
  assertMcpTransport,
  type McpServerRecord,
  type McpServerStore,
} from '../mcp/servers.js';
import type { SecretStore } from '../secrets/store.js';
import { decryptSecret, encryptSecret, maskApiKey } from '../lib/crypto.js';
import { frameToolOutput } from '../llm/boundary.js';

/**
 * MCP routes.
 *
 *   POST   /api/mcp/servers            - configure a remote MCP server (http|sse only; stdio rejected).
 *   GET    /api/mcp/servers            - the caller's servers; credentials masked (hint only).
 *   DELETE /api/mcp/servers/:id        - remove a server and its stored credential.
 *   POST   /api/mcp/servers/:id/test   - initialize + tools/list against the live server;
 *                                        a bad server returns { ok: false, error }, never a 500.
 *   GET    /api/mcp/tools              - available (skill-unlocked) tools only.
 *   POST   /api/mcp/tools/call         - call one unlocked tool; deferred tools are refused (403).
 *
 * Member-authenticated; scoped to the caller, another user's server reads
 * as 404. MCP tools never bypass BugSeek's own gates. This endpoint
 * enforces auth, the skill-deferral gate, the per-call timeout, and the
 * response-size cap. Scope, consent, approvals, target pins, and the
 * noise governor are enforced by the swarm/agent layer before it calls
 * here, and every tool result is untrusted data: the response carries it
 * wrapped in the nonce-tagged boundary markers, so a model must treat it
 * as evidence, never as instructions. Registered in server.ts, not here.
 */

export interface McpRouteDeps {
  db: Database;
  servers: McpServerStore;
  secrets: SecretStore;
  registry?: McpToolRegistry;
}

/** A server row as the API returns it: config plus a masked credential hint, never a credential. */
export interface McpServerSummary {
  id: string;
  userId: string;
  label: string;
  url: string;
  transport: McpServerRecord['transport'];
  enabled: boolean;
  createdAt: string;
  /** Masked hint (first 4 + last 4) from the secrets store, or null when no credential is stored. */
  credentialHint: string | null;
}

export function toServerSummary(
  record: McpServerRecord,
  credentialHint: string | null,
): McpServerSummary {
  return {
    id: record.id,
    userId: record.userId,
    label: record.label,
    url: record.url,
    transport: record.transport,
    enabled: record.enabled,
    createdAt: record.createdAt,
    credentialHint,
  };
}

const createServerSchema = z.object({
  label: z.string().min(1).max(100),
  url: z.string().min(1).max(2000),
  transport: z.string().min(1),
  /** Optional bearer token / credential for the server; stored encrypted, never returned. */
  credential: z.string().min(1).max(4000).optional(),
  enabled: z.boolean().optional(),
});

const callToolSchema = z.object({
  serverId: z.string().min(1),
  tool: z.string().min(1).max(200),
  args: z.record(z.unknown()).optional(),
  /** Per-call timeout override in ms (1 s - 5 min); defaults to the client's 120 s. */
  timeoutMs: z.number().int().min(1000).max(300000).optional(),
});

/**
 * Build a client for one of the caller's servers, loading its stored
 * credential (kind 'mcp', label = server id) and sending it as a
 * Bearer token, or as-is when it already carries an auth scheme.
 * Exported for the agent layer, which needs the same client.
 */
export async function buildMcpClientForServer(
  secrets: SecretStore,
  userId: string,
  server: McpServerRecord,
  opts?: { fetchFn?: McpFetchFn; timeoutMs?: number },
): Promise<McpClient> {
  const headers: Record<string, string> = {};
  const stored = await secrets.get(userId, 'mcp', server.id);
  if (stored) {
    const credential = decryptSecret(stored.encryptedValue);
    headers['authorization'] = /^(Bearer|Basic|Token)\s/i.test(credential)
      ? credential
      : `Bearer ${credential}`;
  }
  return new McpClient({
    url: server.url,
    transport: server.transport,
    headers,
    fetchFn: opts?.fetchFn,
    timeoutMs: opts?.timeoutMs,
  });
}

export async function mcpRoutes(app: FastifyInstance, deps: McpRouteDeps): Promise<void> {
  const { db, servers, secrets } = deps;
  const registry = deps.registry ?? mcpRegistry;
  const authenticate = buildAuthenticate(db);

  /** The server must exist and belong to the caller. */
  async function resolveServer(id: string, userId: string) {
    const server = await servers.get(id);
    if (!server || server.userId !== userId) return null;
    return server;
  }

  app.post('/api/mcp/servers', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const body = createServerSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    try {
      assertMcpServerUrl(body.data.url);
      assertMcpTransport(body.data.transport);
    } catch (err) {
      return reply.status(400).send({ error: (err as Error).message });
    }
    let record: McpServerRecord;
    try {
      record = await servers.create({
        userId: user.id,
        label: body.data.label,
        url: body.data.url,
        transport: body.data.transport as McpServerRecord['transport'],
        enabled: body.data.enabled,
      });
    } catch (err) {
      return reply.status(400).send({ error: (err as Error).message });
    }
    let hint: string | null = null;
    if (body.data.credential) {
      hint = maskApiKey(body.data.credential);
      try {
        await secrets.save({
          userId: user.id,
          kind: 'mcp',
          label: record.id,
          encryptedValue: encryptSecret(body.data.credential),
          hint,
        });
      } catch {
        // Never keep a half-configured server: the credential failed to
        // store, so the server row goes away with it.
        await servers.remove(record.id, user.id).catch(() => undefined);
        return reply.status(500).send({ error: 'Failed to store the server credential' });
      }
    }
    return reply.status(201).send({ server: toServerSummary(record, hint) });
  });

  app.get('/api/mcp/servers', { preHandler: authenticate }, async (request) => {
    const user = requireUser(request);
    const rows = await servers.listForUser(user.id);
    const stored = await secrets.list(user.id, 'mcp');
    const hintByServerId = new Map(stored.map((s) => [s.label, s.hint]));
    return {
      servers: rows.map((row) => toServerSummary(row, hintByServerId.get(row.id) ?? null)),
      // The transports this backend speaks. stdio is not among them:
      // it needs the worker host, so stdio configs are rejected
      // at creation (see assertMcpTransport).
      supportedTransports: ['http', 'sse'],
      stdioSupported: false,
    };
  });

  app.delete('/api/mcp/servers/:id', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const removed = await servers.remove(id, user.id);
    if (!removed) {
      return reply.status(404).send({ error: 'Server not found' });
    }
    await secrets.remove(user.id, 'mcp', id).catch(() => undefined);
    registry.unregisterMcpServer(id);
    return { ok: true };
  });

  app.post('/api/mcp/servers/:id/test', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const server = await resolveServer(id, user.id);
    if (!server) {
      return reply.status(404).send({ error: 'Server not found' });
    }
    // A bad server is a result, not a crash: every failure is surfaced
    // as { ok: false } on a 200, never a 500.
    try {
      const client = await buildMcpClientForServer(secrets, user.id, server);
      const info = await client.initialize();
      const tools = await client.listTools();
      // A successful test registers the tools as deferred: the agent
      // may not call them until a skill unlocks them.
      registry.registerMcpServer(server.id, tools, server.transport);
      return {
        ok: true,
        serverId: server.id,
        protocolVersion: info.protocolVersion,
        toolCount: tools.length,
        tools: tools.map((t) => t.name),
      };
    } catch (err) {
      return { ok: false, serverId: server.id, error: (err as Error).message };
    }
  });

  app.get('/api/mcp/tools', { preHandler: authenticate }, async (request) => {
    const user = requireUser(request);
    const rows = await servers.listForUser(user.id);
    const owned = new Set(rows.map((row) => row.id));
    const tools = registry.availableTools().filter((tool) => owned.has(tool.serverId));
    return { tools };
  });

  app.post('/api/mcp/tools/call', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const body = callToolSchema.safeParse(request.body);
    if (!body.success) {
      return reply.status(400).send({ error: body.error.issues[0]?.message ?? 'Invalid input' });
    }
    const server = await resolveServer(body.data.serverId, user.id);
    if (!server) {
      return reply.status(404).send({ error: 'Server not found' });
    }
    if (!server.enabled) {
      return reply.status(409).send({ error: 'mcp_server_disabled: enable the server before calling its tools' });
    }
    try {
      registry.assertToolAvailable(server.id, body.data.tool);
    } catch (err) {
      return reply.status(403).send({ error: (err as Error).message });
    }
    let client: McpClient;
    try {
      client = await buildMcpClientForServer(secrets, user.id, server);
    } catch (err) {
      return reply.status(502).send({ error: (err as Error).message });
    }
    let result: unknown;
    try {
      result = await client.callTool(body.data.tool, body.data.args ?? {}, {
        timeoutMs: body.data.timeoutMs,
      });
    } catch (err) {
      return reply.status(502).send({ error: (err as Error).message });
    }
    // Tool output is untrusted data: frame it with nonce-tagged
    // boundary markers before anything downstream (a model, a report)
    // sees it, so instructions smuggled into a tool result read as
    // evidence, never as instructions.
    const framed = frameToolOutput(JSON.stringify(result, null, 2));
    return {
      serverId: server.id,
      tool: body.data.tool,
      result,
      framed: framed.framed,
      nonce: framed.nonce,
      untrusted: true,
    };
  });
}

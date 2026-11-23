/**
 * MCP server config persistence: memory and Postgres behind one interface.
 * Config only. Credentials live in the secrets store, never here.
 * Transports are http/sse; stdio is rejected, no process host exists yet.
 */
import { randomUUID } from 'node:crypto';
import { MCP_TRANSPORTS, type McpTransport } from './client.js';

/** One configured MCP server (config only, no credential, ever). */
export interface McpServerRecord {
  id: string;
  userId: string;
  label: string;
  url: string;
  transport: McpTransport;
  enabled: boolean;
  createdAt: string; // ISO
}

export interface CreateMcpServerInput {
  userId: string;
  label: string;
  url: string;
  transport: McpTransport;
  enabled?: boolean;
}

export interface McpServerStore {
  create(input: CreateMcpServerInput): Promise<McpServerRecord>;
  get(id: string): Promise<McpServerRecord | null>;
  /** One user's servers, oldest first. */
  listForUser(userId: string): Promise<McpServerRecord[]>;
  /** True when a row the caller owns existed and was removed. */
  remove(id: string, userId: string): Promise<boolean>;
  /** Enable/disable a server the caller owns; null when it does not exist or is not theirs. */
  setEnabled(id: string, userId: string, enabled: boolean): Promise<McpServerRecord | null>;
}

const nowIso = () => new Date().toISOString();

/** The server URL must be http(s), anything else (stdio:, file:...) is not a remote MCP server. */
export function assertMcpServerUrl(raw: string): URL {
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

/** 'http' | 'sse' only. stdio is rejected, not stored: no process host exists yet. */
export function assertMcpTransport(value: unknown): asserts value is McpTransport {
  if (typeof value !== 'string' || !(MCP_TRANSPORTS as readonly string[]).includes(value)) {
    throw new Error(
      `mcp_invalid_transport: ${String(value)} — only 'http' and 'sse' are supported; ` +
        'a stdio MCP server needs a worker host (no process host exists yet)',
    );
  }
}

/** Validate a raw create/update payload (label, URL, transport) and return the cleaned values. */
export function validateMcpServerInput(input: {
  label: unknown;
  url: unknown;
  transport: unknown;
}): { label: string; url: string; transport: McpTransport } {
  if (typeof input.label !== 'string' || !input.label.trim()) {
    throw new Error('mcp_label_required');
  }
  const label = input.label.trim();
  if (label.length > 100) throw new Error('mcp_label_too_long');
  if (typeof input.url !== 'string' || !input.url.trim()) {
    throw new Error('mcp_url_required');
  }
  const url = assertMcpServerUrl(input.url.trim()).toString();
  if (typeof input.transport !== 'string' || !input.transport) {
    throw new Error('mcp_transport_required');
  }
  assertMcpTransport(input.transport);
  return { label, url, transport: input.transport };
}

// ── Memory implementation ────────────────────────────────────────────────

export class MemoryMcpServerStore implements McpServerStore {
  private servers = new Map<string, McpServerRecord>();

  async create(input: CreateMcpServerInput): Promise<McpServerRecord> {
    const clean = validateMcpServerInput(input);
    if (!input.userId) throw new Error('mcp_user_required');
    for (const existing of this.servers.values()) {
      if (existing.userId === input.userId && existing.label === clean.label) {
        throw new Error(`mcp_server_label_taken: ${clean.label}`);
      }
    }
    const record: McpServerRecord = {
      id: randomUUID(),
      userId: input.userId,
      label: clean.label,
      url: clean.url,
      transport: clean.transport,
      enabled: input.enabled ?? true,
      createdAt: nowIso(),
    };
    this.servers.set(record.id, record);
    return { ...record };
  }

  async get(id: string): Promise<McpServerRecord | null> {
    const found = this.servers.get(id);
    return found ? { ...found } : null;
  }

  async listForUser(userId: string): Promise<McpServerRecord[]> {
    return [...this.servers.values()]
      .filter((s) => s.userId === userId)
      .sort((a, b) => (a.createdAt < b.createdAt ? -1 : 1))
      .map((s) => ({ ...s }));
  }

  async remove(id: string, userId: string): Promise<boolean> {
    const found = this.servers.get(id);
    if (!found || found.userId !== userId) return false;
    return this.servers.delete(id);
  }

  async setEnabled(id: string, userId: string, enabled: boolean): Promise<McpServerRecord | null> {
    const found = this.servers.get(id);
    if (!found || found.userId !== userId) return null;
    found.enabled = enabled;
    return { ...found };
  }
}

// ── Postgres implementation ──────────────────────────────────────────────

/** The only thing the Postgres store needs: a parametrised query function. */
export type McpServerQueryFn = (
  sql: string,
  params: unknown[],
) => Promise<{ rows: Record<string, unknown>[]; rowCount?: number | null }>;

/** pg returns timestamptz as Date; a stubbed query may hand back ISO strings. */
function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

export class PostgresMcpServerStore implements McpServerStore {
  constructor(private readonly query: McpServerQueryFn) {}

  private toRecord(row: Record<string, unknown>): McpServerRecord {
    return {
      id: row['id'] as string,
      userId: row['user_id'] as string,
      label: row['label'] as string,
      url: row['url'] as string,
      transport: row['transport'] as McpTransport,
      enabled: row['enabled'] as boolean,
      createdAt: toIso(row['created_at']),
    };
  }

  async create(input: CreateMcpServerInput): Promise<McpServerRecord> {
    const clean = validateMcpServerInput(input);
    if (!input.userId) throw new Error('mcp_user_required');
    // ON CONFLICT DO NOTHING keeps the (user_id, label) unique index as
    // the final word; a missing row means the label was already taken.
    const { rows } = await this.query(
      `INSERT INTO mcp_servers (user_id, label, url, transport, enabled)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id, label) DO NOTHING
       RETURNING *`,
      [input.userId, clean.label, clean.url, clean.transport, input.enabled ?? true],
    );
    if (!rows[0]) throw new Error(`mcp_server_label_taken: ${clean.label}`);
    return this.toRecord(rows[0]);
  }

  async get(id: string): Promise<McpServerRecord | null> {
    const { rows } = await this.query(`SELECT * FROM mcp_servers WHERE id = $1`, [id]);
    return rows[0] ? this.toRecord(rows[0]) : null;
  }

  async listForUser(userId: string): Promise<McpServerRecord[]> {
    const { rows } = await this.query(
      `SELECT * FROM mcp_servers WHERE user_id = $1 ORDER BY created_at ASC`,
      [userId],
    );
    return rows.map((r) => this.toRecord(r));
  }

  async remove(id: string, userId: string): Promise<boolean> {
    const { rowCount } = await this.query(
      `DELETE FROM mcp_servers WHERE id = $1 AND user_id = $2`,
      [id, userId],
    );
    return (rowCount ?? 0) > 0;
  }

  async setEnabled(id: string, userId: string, enabled: boolean): Promise<McpServerRecord | null> {
    const { rows } = await this.query(
      `UPDATE mcp_servers SET enabled = $1 WHERE id = $2 AND user_id = $3 RETURNING *`,
      [enabled, id, userId],
    );
    return rows[0] ? this.toRecord(rows[0]) : null;
  }
}

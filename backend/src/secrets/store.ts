/**
 * Encrypted-credential store. Ciphertext only: callers encrypt before
 * saving and decrypt after loading. kind namespaces rows per consumer;
 * one row per (userId, kind, label). list returns hints only.
 */
import { randomUUID } from 'node:crypto';

export type SecretKind = 'search' | 'mcp' | 'notify';

export const SECRET_KINDS: readonly SecretKind[] = ['search', 'mcp', 'notify'];

/** One stored credential, ciphertext included (owner-only read). */
export interface SecretRecord {
  id: string;
  userId: string;
  kind: SecretKind;
  label: string;
  /** AES-256-GCM ciphertext (iv:tag:data, base64), never plaintext. */
  encryptedValue: string;
  /** Masked hint (first 4 + last 4), safe to show in the UI. */
  hint: string;
  updatedAt: string; // ISO
}

/** Listing row: everything except the ciphertext. */
export type SecretSummary = Omit<SecretRecord, 'encryptedValue'>;

export interface SaveSecretInput {
  userId: string;
  kind: SecretKind;
  label: string;
  encryptedValue: string;
  hint: string;
}

export interface SecretStore {
  save(input: SaveSecretInput): Promise<SecretRecord>;
  /** Ciphertext included, call only with the owning user's id. */
  get(userId: string, kind: SecretKind, label: string): Promise<SecretRecord | null>;
  /** Hints only, newest first. */
  list(userId: string, kind?: SecretKind): Promise<SecretSummary[]>;
  /** True when a row existed and was removed. */
  remove(userId: string, kind: SecretKind, label: string): Promise<boolean>;
}

const nowIso = () => new Date().toISOString();

function toSummary(rec: SecretRecord): SecretSummary {
  const { encryptedValue: _cipher, ...rest } = rec;
  return rest;
}

export class MemorySecretStore implements SecretStore {
  private secrets = new Map<string, SecretRecord>();

  private key(userId: string, kind: SecretKind, label: string): string {
    return `${userId}${kind}${label}`;
  }

  async save(input: SaveSecretInput): Promise<SecretRecord> {
    const k = this.key(input.userId, input.kind, input.label);
    const existing = this.secrets.get(k);
    const rec: SecretRecord = {
      id: existing?.id ?? randomUUID(),
      userId: input.userId,
      kind: input.kind,
      label: input.label,
      encryptedValue: input.encryptedValue,
      hint: input.hint,
      updatedAt: nowIso(),
    };
    this.secrets.set(k, rec);
    return { ...rec };
  }

  async get(userId: string, kind: SecretKind, label: string): Promise<SecretRecord | null> {
    const rec = this.secrets.get(this.key(userId, kind, label));
    return rec ? { ...rec } : null;
  }

  async list(userId: string, kind?: SecretKind): Promise<SecretSummary[]> {
    return [...this.secrets.values()]
      .filter((r) => r.userId === userId && (kind === undefined || r.kind === kind))
      .sort((a, b) => (a.updatedAt < b.updatedAt ? 1 : -1))
      .map(toSummary);
  }

  async remove(userId: string, kind: SecretKind, label: string): Promise<boolean> {
    return this.secrets.delete(this.key(userId, kind, label));
  }
}

export type SecretQueryFn = (
  sql: string,
  params: unknown[],
) => Promise<{ rows: Record<string, unknown>[]; rowCount?: number | null }>;

export class PostgresSecretStore implements SecretStore {
  constructor(private readonly query: SecretQueryFn) {}

  private toRecord(row: Record<string, unknown>): SecretRecord {
    return {
      id: row['id'] as string,
      userId: row['user_id'] as string,
      kind: row['kind'] as SecretKind,
      label: row['label'] as string,
      encryptedValue: row['encrypted_value'] as string,
      hint: (row['hint'] as string) ?? '',
      updatedAt: (row['updated_at'] as Date).toISOString(),
    };
  }

  async save(input: SaveSecretInput): Promise<SecretRecord> {
    const { rows } = await this.query(
      `INSERT INTO user_secrets (user_id, kind, label, encrypted_value, hint)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id, kind, label)
       DO UPDATE SET encrypted_value = EXCLUDED.encrypted_value,
                     hint = EXCLUDED.hint,
                     updated_at = now()
       RETURNING *`,
      [input.userId, input.kind, input.label, input.encryptedValue, input.hint],
    );
    return this.toRecord(rows[0]);
  }

  async get(userId: string, kind: SecretKind, label: string): Promise<SecretRecord | null> {
    const { rows } = await this.query(
      `SELECT * FROM user_secrets WHERE user_id = $1 AND kind = $2 AND label = $3`,
      [userId, kind, label],
    );
    return rows[0] ? this.toRecord(rows[0]) : null;
  }

  async list(userId: string, kind?: SecretKind): Promise<SecretSummary[]> {
    const { rows } = await this.query(
      kind === undefined
        ? `SELECT id, user_id, kind, label, hint, updated_at FROM user_secrets
           WHERE user_id = $1 ORDER BY updated_at DESC`
        : `SELECT id, user_id, kind, label, hint, updated_at FROM user_secrets
           WHERE user_id = $1 AND kind = $2 ORDER BY updated_at DESC`,
      kind === undefined ? [userId] : [userId, kind],
    );
    return rows.map((row) => ({
      id: row['id'] as string,
      userId: row['user_id'] as string,
      kind: row['kind'] as SecretKind,
      label: row['label'] as string,
      hint: (row['hint'] as string) ?? '',
      updatedAt: (row['updated_at'] as Date).toISOString(),
    }));
  }

  async remove(userId: string, kind: SecretKind, label: string): Promise<boolean> {
    const { rowCount } = await this.query(
      `DELETE FROM user_secrets WHERE user_id = $1 AND kind = $2 AND label = $3`,
      [userId, kind, label],
    );
    return (rowCount ?? 0) > 0;
  }
}

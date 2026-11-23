/**
 * Workspace file metadata: the "recent files" list without walking the
 * disk. Memory and Postgres behind one interface.
 *
 * A row records that a file was uploaded, generated as a report, or taken
 * in by code-intake, at a relative path for a user, optionally tied to a
 * task. Metadata only: the bytes live on disk, which is ephemeral on the
 * hosted backend, so a row may outlive its file after a redeploy. Callers
 * treat a missing file as gone, not as a metadata error.
 *
 * Rows are never updated. Deleting a file removes its row; re-uploading
 * the same path records a fresh row.
 */
import { randomUUID } from 'node:crypto';

export type WorkspaceFileKind = 'upload' | 'report' | 'intake';

export const WORKSPACE_FILE_KINDS: readonly WorkspaceFileKind[] = ['upload', 'report', 'intake'];

/** One recorded upload / generated file. */
export interface WorkspaceFileRecord {
  id: string;
  userId: string;
  taskId: string | null;
  relPath: string;
  sizeBytes: number;
  kind: WorkspaceFileKind;
  createdAt: string; // ISO
}

export interface RecordWorkspaceFileInput {
  userId: string;
  taskId?: string | null;
  relPath: string;
  sizeBytes: number;
  kind: WorkspaceFileKind;
}

export interface WorkspaceMetaStore {
  record(input: RecordWorkspaceFileInput): Promise<WorkspaceFileRecord>;
  get(id: string): Promise<WorkspaceFileRecord | null>;
  /** Newest first, for one user. */
  listRecent(userId: string, limit?: number): Promise<WorkspaceFileRecord[]>;
  /** Every file recorded against one task, newest first. */
  listForTask(taskId: string): Promise<WorkspaceFileRecord[]>;
  /** Remove the row for one user's path. True when a row was removed. */
  removeByPath(userId: string, relPath: string): Promise<boolean>;
}

function assertKind(kind: string): asserts kind is WorkspaceFileKind {
  if (!(WORKSPACE_FILE_KINDS as readonly string[]).includes(kind)) {
    throw new Error(`invalid_workspace_file_kind: ${kind}`);
  }
}

function assertRecordInput(input: RecordWorkspaceFileInput): void {
  if (!input.userId) throw new Error('workspace_file_user_required');
  if (!input.relPath) throw new Error('workspace_file_path_required');
  if (!Number.isInteger(input.sizeBytes) || input.sizeBytes < 0) {
    throw new Error(`invalid_workspace_file_size: ${input.sizeBytes}`);
  }
  assertKind(input.kind);
}

const nowIso = () => new Date().toISOString();

// ── Memory implementation ────────────────────────────────────────────────

export class MemoryWorkspaceMetaStore implements WorkspaceMetaStore {
  private files = new Map<string, WorkspaceFileRecord>();

  async record(input: RecordWorkspaceFileInput): Promise<WorkspaceFileRecord> {
    assertRecordInput(input);
    const record: WorkspaceFileRecord = {
      id: randomUUID(),
      userId: input.userId,
      taskId: input.taskId ?? null,
      relPath: input.relPath,
      sizeBytes: input.sizeBytes,
      kind: input.kind,
      createdAt: nowIso(),
    };
    this.files.set(record.id, record);
    return { ...record };
  }

  async get(id: string): Promise<WorkspaceFileRecord | null> {
    const found = this.files.get(id);
    return found ? { ...found } : null;
  }

  async listRecent(userId: string, limit = 20): Promise<WorkspaceFileRecord[]> {
    const capped = Math.max(1, Math.min(limit, 100));
    return [...this.files.values()]
      .filter((f) => f.userId === userId)
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
      .slice(0, capped)
      .map((f) => ({ ...f }));
  }

  async listForTask(taskId: string): Promise<WorkspaceFileRecord[]> {
    return [...this.files.values()]
      .filter((f) => f.taskId === taskId)
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
      .map((f) => ({ ...f }));
  }

  async removeByPath(userId: string, relPath: string): Promise<boolean> {
    for (const [id, row] of this.files) {
      if (row.userId === userId && row.relPath === relPath) {
        this.files.delete(id);
        return true;
      }
    }
    return false;
  }
}

// ── Postgres implementation ──────────────────────────────────────────────

/** The only thing the Postgres store needs: a parametrised query function. */
export type WorkspaceMetaQueryFn = (
  sql: string,
  params: unknown[],
) => Promise<{ rows: Record<string, unknown>[] }>;

/** pg returns timestamptz as Date; a stubbed query may hand back ISO strings. */
function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

export class PostgresWorkspaceMetaStore implements WorkspaceMetaStore {
  constructor(private readonly query: WorkspaceMetaQueryFn) {}

  private toRecord(row: Record<string, unknown>): WorkspaceFileRecord {
    return {
      id: row['id'] as string,
      userId: row['user_id'] as string,
      taskId: (row['task_id'] as string) ?? null,
      relPath: row['rel_path'] as string,
      sizeBytes: Number(row['size_bytes']),
      kind: row['kind'] as WorkspaceFileKind,
      createdAt: toIso(row['created_at']),
    };
  }

  async record(input: RecordWorkspaceFileInput): Promise<WorkspaceFileRecord> {
    assertRecordInput(input);
    const { rows } = await this.query(
      `INSERT INTO workspace_files (user_id, task_id, rel_path, size_bytes, kind)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [input.userId, input.taskId ?? null, input.relPath, input.sizeBytes, input.kind],
    );
    return this.toRecord(rows[0]);
  }

  async get(id: string): Promise<WorkspaceFileRecord | null> {
    const { rows } = await this.query(`SELECT * FROM workspace_files WHERE id = $1`, [id]);
    return rows[0] ? this.toRecord(rows[0]) : null;
  }

  async listRecent(userId: string, limit = 20): Promise<WorkspaceFileRecord[]> {
    const capped = Math.max(1, Math.min(limit, 100));
    const { rows } = await this.query(
      `SELECT * FROM workspace_files
        WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`,
      [userId, capped],
    );
    return rows.map((r) => this.toRecord(r));
  }

  async listForTask(taskId: string): Promise<WorkspaceFileRecord[]> {
    const { rows } = await this.query(
      `SELECT * FROM workspace_files
        WHERE task_id = $1 ORDER BY created_at DESC`,
      [taskId],
    );
    return rows.map((r) => this.toRecord(r));
  }

  async removeByPath(userId: string, relPath: string): Promise<boolean> {
    const { rows } = await this.query(
      `DELETE FROM workspace_files WHERE user_id = $1 AND rel_path = $2 RETURNING id`,
      [userId, relPath],
    );
    return rows.length > 0;
  }
}

/**
 * Skill-gap ledger: the capability backlog. Dedup is one row per
 * (taskId, capability); Postgres enforces it with a unique index.
 * Ownership is enforced by the routes.
 */
import { randomUUID } from 'node:crypto';

/** One recorded capability gap. */
export interface SkillGapRecord {
  id: string;
  taskId: string;
  userId: string;
  /** Short capability slug, e.g. "websocket-replay" or "graphql-introspection". */
  capability: string;
  /** Free text: what the agent was trying to do when it hit the gap (≤2000 chars). */
  context: string | null;
  createdAt: string; // ISO
}

export interface RecordGapInput {
  taskId: string;
  userId: string;
  capability: string;
  context?: string | null;
}

export interface RecordGapResult {
  record: SkillGapRecord;
  /** True when the gap was already recorded for this task (dedup hit). */
  deduped: boolean;
}

export interface SkillGapStore {
  /**
   * Record a gap, or return the existing row when this task already
   * recorded this capability. Never throws on a duplicate.
   */
  recordGap(input: RecordGapInput): Promise<RecordGapResult>;
  /** Every gap recorded by one user, newest first. */
  listGaps(userId: string): Promise<SkillGapRecord[]>;
  /** Every gap recorded against one task, oldest first. */
  listGapsForTask(taskId: string): Promise<SkillGapRecord[]>;
}

function assertCapability(capability: string): void {
  if (!capability || !capability.trim()) throw new Error('skill_gap_capability_required');
  if (capability.length > 200) throw new Error('skill_gap_capability_too_long');
  if (/\s/.test(capability)) throw new Error('skill_gap_capability_no_spaces');
}

function assertContext(context: string | null | undefined): string | null {
  if (context == null) return null;
  if (context.length > 2000) throw new Error('skill_gap_context_too_long');
  return context;
}

const nowIso = () => new Date().toISOString();

// ── Memory implementation ────────────────────────────────────────────────

export class MemorySkillGapStore implements SkillGapStore {
  private gaps = new Map<string, SkillGapRecord>();

  private dedupKey(taskId: string, capability: string): string {
    return `${taskId}\n${capability}`;
  }

  async recordGap(input: RecordGapInput): Promise<RecordGapResult> {
    assertCapability(input.capability);
    const context = assertContext(input.context);
    const key = this.dedupKey(input.taskId, input.capability);
    const existing = this.gaps.get(key);
    if (existing) return { record: { ...existing }, deduped: true };
    const record: SkillGapRecord = {
      id: randomUUID(),
      taskId: input.taskId,
      userId: input.userId,
      capability: input.capability,
      context,
      createdAt: nowIso(),
    };
    this.gaps.set(key, record);
    return { record: { ...record }, deduped: false };
  }

  async listGaps(userId: string): Promise<SkillGapRecord[]> {
    return [...this.gaps.values()]
      .filter((g) => g.userId === userId)
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
      .map((g) => ({ ...g }));
  }

  async listGapsForTask(taskId: string): Promise<SkillGapRecord[]> {
    return [...this.gaps.values()]
      .filter((g) => g.taskId === taskId)
      .sort((a, b) => (a.createdAt < b.createdAt ? -1 : 1))
      .map((g) => ({ ...g }));
  }
}

// ── Postgres implementation ──────────────────────────────────────────────

/** The only thing the Postgres store needs: a parametrised query function. */
export type SkillGapQueryFn = (
  sql: string,
  params: unknown[],
) => Promise<{ rows: Record<string, unknown>[] }>;

/** pg returns timestamptz as Date; a stubbed query may hand back ISO strings. */
function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

export class PostgresSkillGapStore implements SkillGapStore {
  constructor(private readonly query: SkillGapQueryFn) {}

  private toRecord(row: Record<string, unknown>): SkillGapRecord {
    return {
      id: row['id'] as string,
      taskId: row['task_id'] as string,
      userId: row['user_id'] as string,
      capability: row['capability'] as string,
      context: (row['context'] as string) ?? null,
      createdAt: toIso(row['created_at']),
    };
  }

  async recordGap(input: RecordGapInput): Promise<RecordGapResult> {
    assertCapability(input.capability);
    const context = assertContext(input.context);
    // ON CONFLICT DO NOTHING relies on the unique index on
    // (task_id, capability) from migration 025, the dedup is atomic.
    const { rows } = await this.query(
      `INSERT INTO skill_gaps (task_id, user_id, capability, context)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (task_id, capability) DO NOTHING
       RETURNING *`,
      [input.taskId, input.userId, input.capability, context],
    );
    if (rows[0]) return { record: this.toRecord(rows[0]), deduped: false };
    const { rows: existing } = await this.query(
      `SELECT * FROM skill_gaps WHERE task_id = $1 AND capability = $2`,
      [input.taskId, input.capability],
    );
    if (!existing[0]) {
      throw new Error('skill_gap_dedup_lookup_failed');
    }
    return { record: this.toRecord(existing[0]), deduped: true };
  }

  async listGaps(userId: string): Promise<SkillGapRecord[]> {
    const { rows } = await this.query(
      `SELECT * FROM skill_gaps WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId],
    );
    return rows.map((r) => this.toRecord(r));
  }

  async listGapsForTask(taskId: string): Promise<SkillGapRecord[]> {
    const { rows } = await this.query(
      `SELECT * FROM skill_gaps WHERE task_id = $1 ORDER BY created_at ASC`,
      [taskId],
    );
    return rows.map((r) => this.toRecord(r));
  }
}

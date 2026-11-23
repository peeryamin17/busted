/**
 * Side-question persistence: memory and Postgres behind one interface.
 * Append-only, no update or delete. Listing is per task, newest first.
 */
import { randomUUID } from 'node:crypto';

export interface SideQuestionRecord {
  id: string;
  taskId: string;
  userId: string;
  question: string;
  answer: string;
  /** Length of the frozen snapshot, in characters, that the answer was drawn from. */
  snapshotChars: number;
  createdAt: string; // ISO
}

export interface RecordSideQuestionInput {
  taskId: string;
  userId: string;
  question: string;
  answer: string;
  snapshotChars: number;
}

export interface SideQuestionStore {
  create(input: RecordSideQuestionInput): Promise<SideQuestionRecord>;
  /** Recorded Q&As for one task, newest first. */
  listForTask(taskId: string, userId: string): Promise<SideQuestionRecord[]>;
}

const nowIso = () => new Date().toISOString();

// ── Memory implementation ────────────────────────────────────────────────

export class MemorySideQuestionStore implements SideQuestionStore {
  private questions = new Map<string, SideQuestionRecord>();

  async create(input: RecordSideQuestionInput): Promise<SideQuestionRecord> {
    const record: SideQuestionRecord = {
      id: randomUUID(),
      taskId: input.taskId,
      userId: input.userId,
      question: input.question,
      answer: input.answer,
      snapshotChars: input.snapshotChars,
      createdAt: nowIso(),
    };
    this.questions.set(record.id, record);
    return { ...record };
  }

  async listForTask(taskId: string, userId: string): Promise<SideQuestionRecord[]> {
    return [...this.questions.values()]
      .filter((q) => q.taskId === taskId && q.userId === userId)
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
      .map((q) => ({ ...q }));
  }
}

// ── Postgres implementation ──────────────────────────────────────────────

/** The only thing the Postgres store needs: a parametrised query function. */
export type SideQuestionQueryFn = (
  sql: string,
  params: unknown[],
) => Promise<{ rows: Record<string, unknown>[] }>;

/** pg returns timestamptz as Date; a stubbed query may hand back ISO strings. */
function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

export class PostgresSideQuestionStore implements SideQuestionStore {
  constructor(private readonly query: SideQuestionQueryFn) {}

  private toRecord(row: Record<string, unknown>): SideQuestionRecord {
    return {
      id: row['id'] as string,
      taskId: row['task_id'] as string,
      userId: row['user_id'] as string,
      question: row['question'] as string,
      answer: row['answer'] as string,
      snapshotChars: Number(row['snapshot_chars']),
      createdAt: toIso(row['created_at']),
    };
  }

  async create(input: RecordSideQuestionInput): Promise<SideQuestionRecord> {
    const { rows } = await this.query(
      `INSERT INTO side_questions (task_id, user_id, question, answer, snapshot_chars)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [input.taskId, input.userId, input.question, input.answer, input.snapshotChars],
    );
    return this.toRecord(rows[0]);
  }

  async listForTask(taskId: string, userId: string): Promise<SideQuestionRecord[]> {
    const { rows } = await this.query(
      `SELECT * FROM side_questions WHERE task_id = $1 AND user_id = $2 ORDER BY created_at DESC`,
      [taskId, userId],
    );
    return rows.map((r) => this.toRecord(r));
  }
}

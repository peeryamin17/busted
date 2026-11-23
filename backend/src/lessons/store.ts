/**
 * Lesson persistence: memory and Postgres behind one interface.
 * Mode is 'shadow' (default) or 'off'; there is no inject mode.
 * lessonsForPrompt always returns [] until a code change adds one.
 * Lessons are never deleted.
 */
import { randomUUID } from 'node:crypto';
import type { Lesson, LessonKind } from './extract.js';
import { LESSON_KINDS } from './extract.js';

export type LessonMode = 'shadow' | 'off';

export const LESSON_MODES: readonly LessonMode[] = ['shadow', 'off'];

export const DEFAULT_LESSON_MODE: LessonMode = 'shadow';

export interface RecordLessonInput {
  taskId: string;
  userId: string;
  kind: LessonKind;
  title: string;
  detail: string;
  evidence?: string[];
}

export interface LessonStore {
  record(input: RecordLessonInput): Promise<Lesson>;
  /** A user's lessons, newest first; filter to one task when given. */
  listByUser(userId: string, opts?: { taskId?: string }): Promise<Lesson[]>;
  getMode(userId: string): Promise<LessonMode>;
  setMode(userId: string, mode: LessonMode): Promise<LessonMode>;
  /**
   * Lessons for injection into an agent prompt. Returns [] ALWAYS in
   * this pass, shadow mode is the default and the only mode, and the
   * promotion gate (see the module comment) is closed. Callers must
   * not build their own injection path around this function.
   */
  lessonsForPrompt(userId: string): Promise<Lesson[]>;
}

function assertKind(kind: string): asserts kind is LessonKind {
  if (!(LESSON_KINDS as readonly string[]).includes(kind)) {
    throw new Error(`invalid_lesson_kind: ${kind}`);
  }
}

export function assertLessonMode(mode: string): asserts mode is LessonMode {
  if (!(LESSON_MODES as readonly string[]).includes(mode)) {
    throw new Error(`invalid_lesson_mode: ${mode}`);
  }
}

const nowIso = () => new Date().toISOString();

// ── Memory implementation ────────────────────────────────────────────────

export class MemoryLessonStore implements LessonStore {
  private lessons = new Map<string, Lesson>();
  private modes = new Map<string, LessonMode>();

  async record(input: RecordLessonInput): Promise<Lesson> {
    assertKind(input.kind);
    if (!input.title?.trim()) throw new Error('lesson_title_required');
    const mode = await this.getMode(input.userId);
    const lesson: Lesson = {
      id: randomUUID(),
      taskId: input.taskId,
      userId: input.userId,
      kind: input.kind,
      title: input.title,
      detail: input.detail,
      evidence: input.evidence ? [...input.evidence] : [],
      createdAt: nowIso(),
    };
    // The mode in effect when the lesson was stored, for the audit trail.
    (lesson as unknown as Record<string, unknown>)['mode'] = mode;
    this.lessons.set(lesson.id as string, lesson);
    return { ...lesson, evidence: [...lesson.evidence] };
  }

  async listByUser(userId: string, opts?: { taskId?: string }): Promise<Lesson[]> {
    return [...this.lessons.values()]
      .filter((l) => l.userId === userId && (!opts?.taskId || l.taskId === opts.taskId))
      .sort((a, b) => ((a.createdAt ?? '') < (b.createdAt ?? '') ? 1 : -1))
      .map((l) => ({ ...l, evidence: [...l.evidence] }));
  }

  async getMode(userId: string): Promise<LessonMode> {
    return this.modes.get(userId) ?? DEFAULT_LESSON_MODE;
  }

  async setMode(userId: string, mode: LessonMode): Promise<LessonMode> {
    assertLessonMode(mode);
    this.modes.set(userId, mode);
    return mode;
  }

  async lessonsForPrompt(_userId: string): Promise<Lesson[]> {
    // SHADOW MODE, see the module comment. This returns [] by design
    // in this pass; promotion needs the operator's explicit say-so, an
    // 'inject' mode, a code change to this function, and a test.
    return [];
  }
}

// ── Postgres implementation ──────────────────────────────────────────────

/** The only thing the Postgres store needs: a parametrised query function. */
export type LessonQueryFn = (
  sql: string,
  params: unknown[],
) => Promise<{ rows: Record<string, unknown>[] }>;

/** pg returns timestamptz as Date; a stubbed query may hand back ISO strings. */
function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function toStringArray(value: unknown): string[] {
  if (value == null) return [];
  if (Array.isArray(value)) return value.map((v) => String(v));
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value) as unknown;
      return Array.isArray(parsed) ? parsed.map((v) => String(v)) : [];
    } catch {
      return [];
    }
  }
  return [];
}

export class PostgresLessonStore implements LessonStore {
  constructor(private readonly query: LessonQueryFn) {}

  private toLesson(row: Record<string, unknown>): Lesson {
    return {
      id: row['id'] as string,
      taskId: row['task_id'] as string,
      userId: row['user_id'] as string,
      kind: row['kind'] as LessonKind,
      title: row['title'] as string,
      detail: row['detail'] as string,
      evidence: toStringArray(row['evidence']),
      createdAt: toIso(row['created_at']),
    };
  }

  async record(input: RecordLessonInput): Promise<Lesson> {
    assertKind(input.kind);
    if (!input.title?.trim()) throw new Error('lesson_title_required');
    const mode = await this.getMode(input.userId);
    const { rows } = await this.query(
      `INSERT INTO lessons (task_id, user_id, kind, title, detail, evidence, mode)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7) RETURNING *`,
      [
        input.taskId,
        input.userId,
        input.kind,
        input.title,
        input.detail,
        JSON.stringify(input.evidence ?? []),
        mode,
      ],
    );
    return this.toLesson(rows[0]);
  }

  async listByUser(userId: string, opts?: { taskId?: string }): Promise<Lesson[]> {
    if (opts?.taskId) {
      const { rows } = await this.query(
        `SELECT * FROM lessons WHERE user_id = $1 AND task_id = $2 ORDER BY created_at DESC`,
        [userId, opts.taskId],
      );
      return rows.map((r) => this.toLesson(r));
    }
    const { rows } = await this.query(
      `SELECT * FROM lessons WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId],
    );
    return rows.map((r) => this.toLesson(r));
  }

  async getMode(userId: string): Promise<LessonMode> {
    const { rows } = await this.query(
      `SELECT mode FROM user_lesson_mode WHERE user_id = $1`,
      [userId],
    );
    const mode = rows[0]?.['mode'];
    return typeof mode === 'string' && (LESSON_MODES as readonly string[]).includes(mode)
      ? (mode as LessonMode)
      : DEFAULT_LESSON_MODE;
  }

  async setMode(userId: string, mode: LessonMode): Promise<LessonMode> {
    assertLessonMode(mode);
    await this.query(
      `INSERT INTO user_lesson_mode (user_id, mode, updated_at)
       VALUES ($1, $2, now())
       ON CONFLICT (user_id) DO UPDATE SET mode = EXCLUDED.mode, updated_at = now()`,
      [userId, mode],
    );
    return mode;
  }

  async lessonsForPrompt(_userId: string): Promise<Lesson[]> {
    // SHADOW MODE, see the module comment. This returns [] by design
    // in this pass; promotion needs the operator's explicit say-so, an
    // 'inject' mode, a code change to this function, and a test.
    return [];
  }
}

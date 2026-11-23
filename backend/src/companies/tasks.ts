/**
 * Task-company links. linkTaskToCompany validates the task exists and
 * belongs to the caller before linking; linking twice is a no-op.
 * No foreign key on the task side, so stale links are skipped on resolve.
 */
import type { TaskRecord } from '../graph/types.js';

export interface TaskCompanyLink {
  taskId: string;
  companyId: string;
  userId: string;
  linkedAt: string; // ISO
}

/** What `linkTaskToCompany` needs from the graph layer: one lookup. */
export type GetTaskFn = (id: string) => Promise<TaskRecord | null>;

export interface TaskCompanyLinkStore {
  /** Link a task to a company; idempotent, returns the existing link when already linked. */
  link(taskId: string, companyId: string, userId: string): Promise<{ link: TaskCompanyLink; created: boolean }>;
  /** Remove one link. Returns true when a link was removed. */
  unlink(taskId: string, companyId: string, userId: string): Promise<boolean>;
  /** Task ids linked to a company, oldest link first. */
  tasksForCompany(companyId: string, userId: string): Promise<string[]>;
  /** Company ids linked to a task. */
  companiesForTask(taskId: string, userId: string): Promise<string[]>;
  /** True when at least one task is linked to the company. */
  hasTasks(companyId: string, userId: string): Promise<boolean>;
}

const nowIso = () => new Date().toISOString();

function linkKey(taskId: string, companyId: string): string {
  return `${taskId}:${companyId}`;
}

/**
 * Guarded link: the task must exist and belong to `userId`, or the
 * link is refused, a task id from another account (or a typo) never
 * lands in the mapping. Throws `task_not_found` when the task does
 * not exist and `task_not_owned` when it belongs to someone else.
 */
export async function linkTaskToCompany(
  store: TaskCompanyLinkStore,
  getTask: GetTaskFn,
  taskId: string,
  companyId: string,
  userId: string,
): Promise<{ link: TaskCompanyLink; created: boolean }> {
  const task = await getTask(taskId);
  if (!task) throw new Error('task_not_found');
  if (task.userId !== userId) throw new Error('task_not_owned');
  return store.link(taskId, companyId, userId);
}

/** Task ids linked to a company (thin wrapper over the store, for symmetry with linkTaskToCompany). */
export async function tasksForCompany(
  store: TaskCompanyLinkStore,
  companyId: string,
  userId: string,
): Promise<string[]> {
  return store.tasksForCompany(companyId, userId);
}

// ── Memory implementation ────────────────────────────────────────────────

export class MemoryTaskCompanyStore implements TaskCompanyLinkStore {
  private links = new Map<string, TaskCompanyLink>();

  async link(
    taskId: string,
    companyId: string,
    userId: string,
  ): Promise<{ link: TaskCompanyLink; created: boolean }> {
    const key = linkKey(taskId, companyId);
    const existing = this.links.get(key);
    if (existing && existing.userId === userId) {
      return { link: { ...existing }, created: false };
    }
    const link: TaskCompanyLink = { taskId, companyId, userId, linkedAt: nowIso() };
    this.links.set(key, link);
    return { link: { ...link }, created: true };
  }

  async unlink(taskId: string, companyId: string, userId: string): Promise<boolean> {
    const key = linkKey(taskId, companyId);
    const existing = this.links.get(key);
    if (!existing || existing.userId !== userId) return false;
    this.links.delete(key);
    return true;
  }

  async tasksForCompany(companyId: string, userId: string): Promise<string[]> {
    return [...this.links.values()]
      .filter((l) => l.companyId === companyId && l.userId === userId)
      .sort((a, b) => (a.linkedAt < b.linkedAt ? -1 : 1))
      .map((l) => l.taskId);
  }

  async companiesForTask(taskId: string, userId: string): Promise<string[]> {
    return [...this.links.values()]
      .filter((l) => l.taskId === taskId && l.userId === userId)
      .sort((a, b) => (a.linkedAt < b.linkedAt ? -1 : 1))
      .map((l) => l.companyId);
  }

  async hasTasks(companyId: string, userId: string): Promise<boolean> {
    return [...this.links.values()].some((l) => l.companyId === companyId && l.userId === userId);
  }
}

// ── Postgres implementation ──────────────────────────────────────────────

/** The only thing the Postgres store needs: a parametrised query function. */
export type TaskCompanyQueryFn = (
  sql: string,
  params: unknown[],
) => Promise<{ rows: Record<string, unknown>[] }>;

/** pg returns timestamptz as Date; a stubbed query may hand back ISO strings. */
function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

export class PostgresTaskCompanyStore implements TaskCompanyLinkStore {
  constructor(private readonly query: TaskCompanyQueryFn) {}

  private toLink(row: Record<string, unknown>): TaskCompanyLink {
    return {
      taskId: row['task_id'] as string,
      companyId: row['company_id'] as string,
      userId: row['user_id'] as string,
      linkedAt: toIso(row['linked_at']),
    };
  }

  async link(
    taskId: string,
    companyId: string,
    userId: string,
  ): Promise<{ link: TaskCompanyLink; created: boolean }> {
    const { rows } = await this.query(
      `INSERT INTO task_companies (task_id, company_id, user_id)
       VALUES ($1, $2, $3)
       ON CONFLICT (task_id, company_id) DO NOTHING RETURNING *`,
      [taskId, companyId, userId],
    );
    if (rows[0]) return { link: this.toLink(rows[0]), created: true };
    const found = await this.query(
      `SELECT * FROM task_companies WHERE task_id = $1 AND company_id = $2 AND user_id = $3`,
      [taskId, companyId, userId],
    );
    // The row must exist (we just inserted or it conflicted); the null
    // fallback only covers a stubbed query function in tests.
    if (!found.rows[0]) throw new Error('task_company_link_missing');
    return { link: this.toLink(found.rows[0]), created: false };
  }

  async unlink(taskId: string, companyId: string, userId: string): Promise<boolean> {
    const { rows } = await this.query(
      `DELETE FROM task_companies WHERE task_id = $1 AND company_id = $2 AND user_id = $3 RETURNING *`,
      [taskId, companyId, userId],
    );
    return rows.length > 0;
  }

  async tasksForCompany(companyId: string, userId: string): Promise<string[]> {
    const { rows } = await this.query(
      `SELECT task_id FROM task_companies WHERE company_id = $1 AND user_id = $2 ORDER BY linked_at ASC`,
      [companyId, userId],
    );
    return rows.map((r) => r['task_id'] as string);
  }

  async companiesForTask(taskId: string, userId: string): Promise<string[]> {
    const { rows } = await this.query(
      `SELECT company_id FROM task_companies WHERE task_id = $1 AND user_id = $2 ORDER BY linked_at ASC`,
      [taskId, userId],
    );
    return rows.map((r) => r['company_id'] as string);
  }

  async hasTasks(companyId: string, userId: string): Promise<boolean> {
    const { rows } = await this.query(
      `SELECT 1 FROM task_companies WHERE company_id = $1 AND user_id = $2 LIMIT 1`,
      [companyId, userId],
    );
    return rows.length > 0;
  }
}

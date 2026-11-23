/**
 * Company persistence: memory and Postgres behind one interface.
 * Names are unique per user. Removing a company refuses while any task
 * still references it; a company is never deleted out from under its tasks.
 */
import { randomUUID } from 'node:crypto';

export interface CompanyScope {
  domains: string[];
  notes?: string;
}

export interface Company {
  id: string;
  userId: string;
  name: string;
  scope: CompanyScope;
  createdAt: string; // ISO
}

export interface CreateCompanyInput {
  userId: string;
  name: string;
  scope?: CompanyScope | null;
}

export interface RenameCompanyInput {
  id: string;
  userId: string;
  name?: string;
  scope?: CompanyScope | null;
}

/**
 * Answers whether any task still references a company. The company
 * store does not own the task_companies mapping, so the caller (the
 * route, which owns both stores) supplies this; remove() refuses
 * when it returns true.
 */
export type CompanyLinkChecker = (companyId: string) => Promise<boolean>;

export interface CompanyStore {
  create(input: CreateCompanyInput): Promise<Company>;
  get(id: string, userId: string): Promise<Company | null>;
  list(userId: string): Promise<Company[]>;
  rename(input: RenameCompanyInput): Promise<Company | null>;
  /**
   * Delete a company. Returns null when the id does not belong to the
   * user. Throws `company_has_linked_tasks` when the checker (when
   * given) reports tasks still linked, never cascades. With no
   * checker the caller asserts there is nothing linked.
   */
  remove(id: string, userId: string, hasLinkedTasks?: CompanyLinkChecker): Promise<Company | null>;
}

export const MAX_COMPANY_NAME_LENGTH = 200;

function assertCompanyName(name: string): string {
  const trimmed = name.trim();
  if (!trimmed) throw new Error('company_name_required');
  if (trimmed.length > MAX_COMPANY_NAME_LENGTH) throw new Error('company_name_too_long');
  return trimmed;
}

function normalizeScope(scope: CompanyScope | null | undefined): CompanyScope {
  if (!scope) return { domains: [] };
  const domains = [...new Set(
    (scope.domains ?? []).map((d) => d.trim().toLowerCase()).filter(Boolean),
  )];
  const out: CompanyScope = { domains };
  if (scope.notes != null && scope.notes.trim()) out.notes = scope.notes.trim();
  return out;
}

const nowIso = () => new Date().toISOString();

// ── Memory implementation ────────────────────────────────────────────────

export class MemoryCompanyStore implements CompanyStore {
  private companies = new Map<string, Company>();

  async create(input: CreateCompanyInput): Promise<Company> {
    const name = assertCompanyName(input.name);
    const clash = [...this.companies.values()].some(
      (c) => c.userId === input.userId && c.name.toLowerCase() === name.toLowerCase(),
    );
    if (clash) throw new Error('company_name_exists');
    const company: Company = {
      id: randomUUID(),
      userId: input.userId,
      name,
      scope: normalizeScope(input.scope),
      createdAt: nowIso(),
    };
    this.companies.set(company.id, company);
    return { ...company, scope: { ...company.scope, domains: [...company.scope.domains] } };
  }

  async get(id: string, userId: string): Promise<Company | null> {
    const found = this.companies.get(id);
    if (!found || found.userId !== userId) return null;
    return { ...found, scope: { ...found.scope, domains: [...found.scope.domains] } };
  }

  async list(userId: string): Promise<Company[]> {
    return [...this.companies.values()]
      .filter((c) => c.userId === userId)
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
      .map((c) => ({ ...c, scope: { ...c.scope, domains: [...c.scope.domains] } }));
  }

  async rename(input: RenameCompanyInput): Promise<Company | null> {
    const found = this.companies.get(input.id);
    if (!found || found.userId !== input.userId) return null;
    if (input.name !== undefined) {
      const name = assertCompanyName(input.name);
      const clash = [...this.companies.values()].some(
        (c) => c.id !== input.id && c.userId === input.userId && c.name.toLowerCase() === name.toLowerCase(),
      );
      if (clash) throw new Error('company_name_exists');
      found.name = name;
    }
    if (input.scope !== undefined) found.scope = normalizeScope(input.scope);
    return { ...found, scope: { ...found.scope, domains: [...found.scope.domains] } };
  }

  async remove(
    id: string,
    userId: string,
    hasLinkedTasks?: CompanyLinkChecker,
  ): Promise<Company | null> {
    const found = this.companies.get(id);
    if (!found || found.userId !== userId) return null;
    if (hasLinkedTasks && (await hasLinkedTasks(id))) {
      throw new Error('company_has_linked_tasks');
    }
    this.companies.delete(id);
    return { ...found, scope: { ...found.scope, domains: [...found.scope.domains] } };
  }
}

// ── Postgres implementation ──────────────────────────────────────────────

/** The only thing the Postgres store needs: a parametrised query function. */
export type CompanyQueryFn = (
  sql: string,
  params: unknown[],
) => Promise<{ rows: Record<string, unknown>[] }>;

/** pg returns timestamptz as Date; a stubbed query may hand back ISO strings. */
function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function toScope(value: unknown): CompanyScope {
  if (value == null) return { domains: [] };
  const parsed =
    typeof value === 'string'
      ? (JSON.parse(value) as unknown)
      : (value as unknown);
  if (!parsed || typeof parsed !== 'object') return { domains: [] };
  return normalizeScope(parsed as CompanyScope);
}

export class PostgresCompanyStore implements CompanyStore {
  constructor(private readonly query: CompanyQueryFn) {}

  private toCompany(row: Record<string, unknown>): Company {
    return {
      id: row['id'] as string,
      userId: row['user_id'] as string,
      name: row['name'] as string,
      scope: toScope(row['scope']),
      createdAt: toIso(row['created_at']),
    };
  }

  private async nameTaken(userId: string, name: string, exceptId?: string): Promise<boolean> {
    const { rows } = await this.query(
      exceptId
        ? `SELECT id FROM companies WHERE user_id = $1 AND lower(name) = lower($2) AND id <> $3`
        : `SELECT id FROM companies WHERE user_id = $1 AND lower(name) = lower($2)`,
      exceptId ? [userId, name, exceptId] : [userId, name],
    );
    return rows.length > 0;
  }

  async create(input: CreateCompanyInput): Promise<Company> {
    const name = assertCompanyName(input.name);
    if (await this.nameTaken(input.userId, name)) throw new Error('company_name_exists');
    const scope = normalizeScope(input.scope);
    try {
      const { rows } = await this.query(
        `INSERT INTO companies (user_id, name, scope)
         VALUES ($1, $2, $3::jsonb) RETURNING *`,
        [input.userId, name, JSON.stringify(scope)],
      );
      return this.toCompany(rows[0]);
    } catch (err) {
      // A concurrent insert can still trip the unique index, report it
      // as the same duplicate-name error, not a raw database error.
      if ((err as { code?: string }).code === '23505') throw new Error('company_name_exists');
      throw err;
    }
  }

  async get(id: string, userId: string): Promise<Company | null> {
    const { rows } = await this.query(
      `SELECT * FROM companies WHERE id = $1 AND user_id = $2`,
      [id, userId],
    );
    return rows[0] ? this.toCompany(rows[0]) : null;
  }

  async list(userId: string): Promise<Company[]> {
    const { rows } = await this.query(
      `SELECT * FROM companies WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId],
    );
    return rows.map((r) => this.toCompany(r));
  }

  async rename(input: RenameCompanyInput): Promise<Company | null> {
    const current = await this.get(input.id, input.userId);
    if (!current) return null;
    const name = input.name !== undefined ? assertCompanyName(input.name) : current.name;
    if (input.name !== undefined && (await this.nameTaken(input.userId, name, input.id))) {
      throw new Error('company_name_exists');
    }
    const scope = input.scope !== undefined ? normalizeScope(input.scope) : current.scope;
    try {
      const { rows } = await this.query(
        `UPDATE companies SET name = $1, scope = $2::jsonb WHERE id = $3 AND user_id = $4 RETURNING *`,
        [name, JSON.stringify(scope), input.id, input.userId],
      );
      return rows[0] ? this.toCompany(rows[0]) : null;
    } catch (err) {
      if ((err as { code?: string }).code === '23505') throw new Error('company_name_exists');
      throw err;
    }
  }

  async remove(
    id: string,
    userId: string,
    hasLinkedTasks?: CompanyLinkChecker,
  ): Promise<Company | null> {
    const current = await this.get(id, userId);
    if (!current) return null;
    if (hasLinkedTasks && (await hasLinkedTasks(id))) {
      throw new Error('company_has_linked_tasks');
    }
    const { rows } = await this.query(
      `DELETE FROM companies WHERE id = $1 AND user_id = $2 RETURNING *`,
      [id, userId],
    );
    return rows[0] ? this.toCompany(rows[0]) : null;
  }
}

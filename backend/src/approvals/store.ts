/**
 * Approval queue persistence: memory and Postgres behind one interface.
 * Decisions are recorded forever, never deleted, never re-decided.
 * Postgres takes an injected query function and never imports pg.
 */
import { randomUUID } from 'node:crypto';

export type ApprovalKind = 'tool-call' | 'new-target' | 'judge' | 'rule';

export const APPROVAL_KINDS: readonly ApprovalKind[] = [
  'tool-call',
  'new-target',
  'judge',
  'rule',
];

/** 'skipped' is set by the swarm caller after a denial (see markSkipped). */
export type ApprovalStatus = 'pending' | 'allowed' | 'denied' | 'skipped' | 'expired';

export const APPROVAL_STATUSES: readonly ApprovalStatus[] = [
  'pending',
  'allowed',
  'denied',
  'skipped',
  'expired',
];

export type ApprovalRequestedBy = 'swarm' | 'judge' | 'pin-gate';

export const APPROVAL_REQUESTED_BY: readonly ApprovalRequestedBy[] = [
  'swarm',
  'judge',
  'pin-gate',
];

/** One paused step waiting on (or already decided by) the operator. */
export interface ApprovalRecord {
  id: string;
  taskId: string;
  userId: string;
  kind: ApprovalKind;
  status: ApprovalStatus;
  /** Short human-readable summary of the proposed action (≤500 chars). */
  action: string;
  /**
   * Structured proposal: tool name + args summary, or target host, or
   * judge questions. Kept small and redacted by the caller, never
   * secrets, never raw payloads.
   */
  detail: Record<string, unknown>;
  /** Rule that decided this approval, when a rule did (else null). */
  ruleId: string | null;
  /** 0-100, null until the risk module lands and scores proposals. */
  riskScore: number | null;
  requestedBy: ApprovalRequestedBy;
  /** Deciding user id, or `rule:<ruleId>` for a rule decision. */
  decidedBy: string | null;
  decidedAt: string | null; // ISO
  createdAt: string; // ISO
  expiresAt: string | null; // ISO
}

export interface CreateApprovalInput {
  taskId: string;
  userId: string;
  kind: ApprovalKind;
  action: string;
  detail?: Record<string, unknown> | null;
  ruleId?: string | null;
  riskScore?: number | null;
  requestedBy: ApprovalRequestedBy;
  expiresAt?: string | null;
}

export type ApprovalDecision = 'allow' | 'deny';

export interface ApprovalStore {
  create(input: CreateApprovalInput): Promise<ApprovalRecord>;
  get(id: string): Promise<ApprovalRecord | null>;
  /** Pending approvals for one task, oldest first (work the queue in order). */
  listPending(taskId: string): Promise<ApprovalRecord[]>;
  /** Every approval for one task, pending first, then newest first. */
  listForTask(taskId: string): Promise<ApprovalRecord[]>;
  /**
   * Decide a pending approval. Throws `approval_not_found` when the id
   * does not exist and `approval_not_pending: <status>` when the row
   * is already decided, a decided approval is never silently
   * overwritten. `decidedBy` is the deciding user id, or
   * `rule:<ruleId>` when a stored rule decided it.
   */
  decide(id: string, decision: ApprovalDecision, decidedBy: string): Promise<ApprovalRecord>;
  /**
   * Move a still-pending approval to 'expired' (the wait timed out,
   * timeout defaults to deny, never allow). Returns the current row
   * unchanged when it is already decided, null when it does not exist.
   */
  markExpired(id: string): Promise<ApprovalRecord | null>;
  /**
   * Record a denied step as skipped, for the swarm caller to mark
   * after it has seen a denial. Pending-only, like decide(): throws
   * `approval_not_pending: <status>` on a decided row.
   */
  markSkipped(id: string, decidedBy: string): Promise<ApprovalRecord>;
}

function assertKind(kind: string): asserts kind is ApprovalKind {
  if (!(APPROVAL_KINDS as readonly string[]).includes(kind)) {
    throw new Error(`invalid_approval_kind: ${kind}`);
  }
}

function assertRequestedBy(value: string): asserts value is ApprovalRequestedBy {
  if (!(APPROVAL_REQUESTED_BY as readonly string[]).includes(value)) {
    throw new Error(`invalid_approval_requested_by: ${value}`);
  }
}

function assertAction(action: string): void {
  if (!action || !action.trim()) throw new Error('approval_action_required');
  if (action.length > 500) throw new Error('approval_action_too_long');
}

function assertRiskScore(score: number | null): void {
  if (score == null) return;
  if (!Number.isFinite(score) || score < 0 || score > 100) {
    throw new Error(`invalid_risk_score: ${score}`);
  }
}

const nowIso = () => new Date().toISOString();

// ── Memory implementation ────────────────────────────────────────────────

export class MemoryApprovalStore implements ApprovalStore {
  private approvals = new Map<string, ApprovalRecord>();

  async create(input: CreateApprovalInput): Promise<ApprovalRecord> {
    assertKind(input.kind);
    assertRequestedBy(input.requestedBy);
    assertAction(input.action);
    assertRiskScore(input.riskScore ?? null);
    const now = nowIso();
    const record: ApprovalRecord = {
      id: randomUUID(),
      taskId: input.taskId,
      userId: input.userId,
      kind: input.kind,
      status: 'pending',
      action: input.action,
      detail: input.detail ? { ...input.detail } : {},
      ruleId: input.ruleId ?? null,
      riskScore: input.riskScore ?? null,
      requestedBy: input.requestedBy,
      decidedBy: null,
      decidedAt: null,
      createdAt: now,
      expiresAt: input.expiresAt ?? null,
    };
    this.approvals.set(record.id, record);
    return { ...record, detail: { ...record.detail } };
  }

  async get(id: string): Promise<ApprovalRecord | null> {
    const found = this.approvals.get(id);
    return found ? { ...found, detail: { ...found.detail } } : null;
  }

  async listPending(taskId: string): Promise<ApprovalRecord[]> {
    return [...this.approvals.values()]
      .filter((a) => a.taskId === taskId && a.status === 'pending')
      .sort((a, b) => (a.createdAt < b.createdAt ? -1 : 1))
      .map((a) => ({ ...a, detail: { ...a.detail } }));
  }

  async listForTask(taskId: string): Promise<ApprovalRecord[]> {
    return [...this.approvals.values()]
      .filter((a) => a.taskId === taskId)
      .sort((a, b) => {
        if (a.status === 'pending' && b.status !== 'pending') return -1;
        if (a.status !== 'pending' && b.status === 'pending') return 1;
        return a.createdAt < b.createdAt ? 1 : -1;
      })
      .map((a) => ({ ...a, detail: { ...a.detail } }));
  }

  async decide(id: string, decision: ApprovalDecision, decidedBy: string): Promise<ApprovalRecord> {
    const record = this.approvals.get(id);
    if (!record) throw new Error('approval_not_found');
    if (record.status !== 'pending') {
      throw new Error(`approval_not_pending: ${record.status}`);
    }
    record.status = decision === 'allow' ? 'allowed' : 'denied';
    record.decidedBy = decidedBy;
    record.decidedAt = nowIso();
    return { ...record, detail: { ...record.detail } };
  }

  async markExpired(id: string): Promise<ApprovalRecord | null> {
    const record = this.approvals.get(id);
    if (!record) return null;
    if (record.status === 'pending') {
      record.status = 'expired';
      record.decidedAt = nowIso();
    }
    return { ...record, detail: { ...record.detail } };
  }

  async markSkipped(id: string, decidedBy: string): Promise<ApprovalRecord> {
    const record = this.approvals.get(id);
    if (!record) throw new Error('approval_not_found');
    if (record.status !== 'pending') {
      throw new Error(`approval_not_pending: ${record.status}`);
    }
    record.status = 'skipped';
    record.decidedBy = decidedBy;
    record.decidedAt = nowIso();
    return { ...record, detail: { ...record.detail } };
  }
}

// ── Postgres implementation ──────────────────────────────────────────────

/** The only thing the Postgres store needs: a parametrised query function. */
export type ApprovalQueryFn = (
  sql: string,
  params: unknown[],
) => Promise<{ rows: Record<string, unknown>[] }>;

/** pg returns timestamptz as Date; a stubbed query may hand back ISO strings. */
function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

function toIsoOrNull(value: unknown): string | null {
  if (value == null) return null;
  return toIso(value);
}

function toJson(value: unknown): Record<string, unknown> {
  if (value == null) return {};
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value) as unknown;
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
        ? (parsed as Record<string, unknown>)
        : {};
    } catch {
      return {};
    }
  }
  return value as Record<string, unknown>;
}

export class PostgresApprovalStore implements ApprovalStore {
  constructor(private readonly query: ApprovalQueryFn) {}

  private toRecord(row: Record<string, unknown>): ApprovalRecord {
    return {
      id: row['id'] as string,
      taskId: row['task_id'] as string,
      userId: row['user_id'] as string,
      kind: row['kind'] as ApprovalKind,
      status: row['status'] as ApprovalStatus,
      action: row['action'] as string,
      detail: toJson(row['detail']),
      ruleId: (row['rule_id'] as string) ?? null,
      riskScore: row['risk_score'] == null ? null : Number(row['risk_score']),
      requestedBy: row['requested_by'] as ApprovalRequestedBy,
      decidedBy: (row['decided_by'] as string) ?? null,
      decidedAt: toIsoOrNull(row['decided_at']),
      createdAt: toIso(row['created_at']),
      expiresAt: toIsoOrNull(row['expires_at']),
    };
  }

  async create(input: CreateApprovalInput): Promise<ApprovalRecord> {
    assertKind(input.kind);
    assertRequestedBy(input.requestedBy);
    assertAction(input.action);
    assertRiskScore(input.riskScore ?? null);
    const { rows } = await this.query(
      `INSERT INTO task_approvals
         (task_id, user_id, kind, action, detail, rule_id, risk_score, requested_by, expires_at)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9) RETURNING *`,
      [
        input.taskId,
        input.userId,
        input.kind,
        input.action,
        JSON.stringify(input.detail ?? {}),
        input.ruleId ?? null,
        input.riskScore ?? null,
        input.requestedBy,
        input.expiresAt ?? null,
      ],
    );
    return this.toRecord(rows[0]);
  }

  async get(id: string): Promise<ApprovalRecord | null> {
    const { rows } = await this.query(`SELECT * FROM task_approvals WHERE id = $1`, [id]);
    return rows[0] ? this.toRecord(rows[0]) : null;
  }

  async listPending(taskId: string): Promise<ApprovalRecord[]> {
    const { rows } = await this.query(
      `SELECT * FROM task_approvals
        WHERE task_id = $1 AND status = 'pending' ORDER BY created_at ASC`,
      [taskId],
    );
    return rows.map((r) => this.toRecord(r));
  }

  async listForTask(taskId: string): Promise<ApprovalRecord[]> {
    const { rows } = await this.query(
      `SELECT * FROM task_approvals
        WHERE task_id = $1
        ORDER BY (status = 'pending') DESC, created_at DESC`,
      [taskId],
    );
    return rows.map((r) => this.toRecord(r));
  }

  async decide(id: string, decision: ApprovalDecision, decidedBy: string): Promise<ApprovalRecord> {
    const status = decision === 'allow' ? 'allowed' : 'denied';
    // The status='pending' guard makes the decide atomic: two deciders
    // racing the same row cannot both win, and a decided row is never
    // overwritten.
    const { rows } = await this.query(
      `UPDATE task_approvals
          SET status = $1, decided_by = $2, decided_at = now()
        WHERE id = $3 AND status = 'pending' RETURNING *`,
      [status, decidedBy, id],
    );
    if (rows[0]) return this.toRecord(rows[0]);
    const current = await this.get(id);
    if (!current) throw new Error('approval_not_found');
    throw new Error(`approval_not_pending: ${current.status}`);
  }

  async markExpired(id: string): Promise<ApprovalRecord | null> {
    const { rows } = await this.query(
      `UPDATE task_approvals
          SET status = 'expired', decided_at = now()
        WHERE id = $1 AND status = 'pending' RETURNING *`,
      [id],
    );
    if (rows[0]) return this.toRecord(rows[0]);
    return this.get(id);
  }

  async markSkipped(id: string, decidedBy: string): Promise<ApprovalRecord> {
    const { rows } = await this.query(
      `UPDATE task_approvals
          SET status = 'skipped', decided_by = $1, decided_at = now()
        WHERE id = $2 AND status = 'pending' RETURNING *`,
      [decidedBy, id],
    );
    if (rows[0]) return this.toRecord(rows[0]);
    const current = await this.get(id);
    if (!current) throw new Error('approval_not_found');
    throw new Error(`approval_not_pending: ${current.status}`);
  }
}

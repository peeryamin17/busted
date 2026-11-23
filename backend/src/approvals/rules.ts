/**
 * Standing operator decisions for the approval queue: allow, ask, or deny
 * per proposal kind. Exact-or-prefix match only, never a regex. The most
 * specific rule wins: task-scoped first, then the longest pattern.
 */
import { randomUUID } from 'node:crypto';

export type RulePatternKind = 'tool' | 'target-host' | 'category';

export const RULE_PATTERN_KINDS: readonly RulePatternKind[] = [
  'tool',
  'target-host',
  'category',
];

export type RuleDecision = 'allow' | 'ask' | 'deny';

export const RULE_DECISIONS: readonly RuleDecision[] = ['allow', 'ask', 'deny'];

export interface ApprovalRulePattern {
  kind: RulePatternKind;
  value: string;
}

export interface ApprovalRule {
  id: string;
  userId: string;
  /** Null = applies to all of the user's tasks. */
  taskId: string | null;
  pattern: ApprovalRulePattern;
  decision: RuleDecision;
  /** Set from the UI "always allow this kind" checkbox. */
  alwaysAllow: boolean;
  createdAt: string; // ISO
}

export interface CreateRuleInput {
  userId: string;
  taskId?: string | null;
  pattern: ApprovalRulePattern;
  decision: RuleDecision;
  alwaysAllow?: boolean;
}

/** One proposal to check against the rules. */
export interface RuleCandidate {
  kind: RulePatternKind;
  value: string;
  taskId: string;
}

export function assertRulePattern(pattern: ApprovalRulePattern): void {
  if (!(RULE_PATTERN_KINDS as readonly string[]).includes(pattern.kind)) {
    throw new Error(`invalid_rule_pattern_kind: ${pattern.kind}`);
  }
  if (typeof pattern.value !== 'string' || !pattern.value.trim()) {
    throw new Error('rule_pattern_value_required');
  }
  if (pattern.value.length > 500) throw new Error('rule_pattern_value_too_long');
}

export function assertRuleDecision(decision: string): asserts decision is RuleDecision {
  if (!(RULE_DECISIONS as readonly string[]).includes(decision)) {
    throw new Error(`invalid_rule_decision: ${decision}`);
  }
}

/**
 * Exact-or-prefix match: the candidate matches when its kind is the
 * pattern's kind and its value equals the pattern value or starts with
 * it. Fixed string comparison only, no regex, no user-supplied
 * pattern syntax.
 */
export function matchesPattern(pattern: ApprovalRulePattern, candidate: RuleCandidate): boolean {
  if (pattern.kind !== candidate.kind) return false;
  return candidate.value === pattern.value || candidate.value.startsWith(pattern.value);
}

/**
 * The winning rule for a candidate, or null when nothing matches.
 * Task-scoped rules beat task-wide ones; among those, the longest
 * pattern value (most specific prefix) wins; ties keep the oldest
 * rule, so an operator's earlier rule is not silently shadowed by a
 * later duplicate.
 */
export function findMatchingRule(
  rules: ApprovalRule[],
  candidate: RuleCandidate,
): ApprovalRule | null {
  const matched = rules
    .filter((r) => (r.taskId === null || r.taskId === candidate.taskId))
    .filter((r) => matchesPattern(r.pattern, candidate));
  if (matched.length === 0) return null;
  matched.sort((a, b) => {
    const aScoped = a.taskId !== null ? 0 : 1;
    const bScoped = b.taskId !== null ? 0 : 1;
    if (aScoped !== bScoped) return aScoped - bScoped;
    if (a.pattern.value.length !== b.pattern.value.length) {
      return b.pattern.value.length - a.pattern.value.length;
    }
    return a.createdAt < b.createdAt ? -1 : 1;
  });
  return matched[0];
}

export interface ApprovalRuleStore {
  createRule(input: CreateRuleInput): Promise<ApprovalRule>;
  getRule(id: string): Promise<ApprovalRule | null>;
  /** All of one user's rules (task-scoped and task-wide), oldest first. */
  listRules(userId: string): Promise<ApprovalRule[]>;
  /** One user's rules that apply to a task (its own + task-wide). */
  listRulesForTask(userId: string, taskId: string): Promise<ApprovalRule[]>;
}

const nowIso = () => new Date().toISOString();

// ── Memory implementation ────────────────────────────────────────────────

export class MemoryApprovalRuleStore implements ApprovalRuleStore {
  private rules = new Map<string, ApprovalRule>();

  async createRule(input: CreateRuleInput): Promise<ApprovalRule> {
    assertRulePattern(input.pattern);
    assertRuleDecision(input.decision);
    const rule: ApprovalRule = {
      id: randomUUID(),
      userId: input.userId,
      taskId: input.taskId ?? null,
      pattern: { kind: input.pattern.kind, value: input.pattern.value },
      decision: input.decision,
      alwaysAllow: input.alwaysAllow ?? false,
      createdAt: nowIso(),
    };
    this.rules.set(rule.id, rule);
    return { ...rule, pattern: { ...rule.pattern } };
  }

  async getRule(id: string): Promise<ApprovalRule | null> {
    const found = this.rules.get(id);
    return found ? { ...found, pattern: { ...found.pattern } } : null;
  }

  async listRules(userId: string): Promise<ApprovalRule[]> {
    return [...this.rules.values()]
      .filter((r) => r.userId === userId)
      .sort((a, b) => (a.createdAt < b.createdAt ? -1 : 1))
      .map((r) => ({ ...r, pattern: { ...r.pattern } }));
  }

  async listRulesForTask(userId: string, taskId: string): Promise<ApprovalRule[]> {
    return (await this.listRules(userId)).filter(
      (r) => r.taskId === null || r.taskId === taskId,
    );
  }
}

// ── Postgres implementation ──────────────────────────────────────────────

/** The only thing the Postgres store needs: a parametrised query function. */
export type RuleQueryFn = (
  sql: string,
  params: unknown[],
) => Promise<{ rows: Record<string, unknown>[] }>;

/** pg returns timestamptz as Date; a stubbed query may hand back ISO strings. */
function toIso(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

export class PostgresApprovalRuleStore implements ApprovalRuleStore {
  constructor(private readonly query: RuleQueryFn) {}

  private toRule(row: Record<string, unknown>): ApprovalRule {
    return {
      id: row['id'] as string,
      userId: row['user_id'] as string,
      taskId: (row['task_id'] as string) ?? null,
      pattern: {
        kind: row['pattern_kind'] as RulePatternKind,
        value: row['pattern_value'] as string,
      },
      decision: row['decision'] as RuleDecision,
      alwaysAllow: row['always_allow'] === true,
      createdAt: toIso(row['created_at']),
    };
  }

  async createRule(input: CreateRuleInput): Promise<ApprovalRule> {
    assertRulePattern(input.pattern);
    assertRuleDecision(input.decision);
    const { rows } = await this.query(
      `INSERT INTO approval_rules
         (user_id, task_id, pattern_kind, pattern_value, decision, always_allow)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [
        input.userId,
        input.taskId ?? null,
        input.pattern.kind,
        input.pattern.value,
        input.decision,
        input.alwaysAllow ?? false,
      ],
    );
    return this.toRule(rows[0]);
  }

  async getRule(id: string): Promise<ApprovalRule | null> {
    const { rows } = await this.query(`SELECT * FROM approval_rules WHERE id = $1`, [id]);
    return rows[0] ? this.toRule(rows[0]) : null;
  }

  async listRules(userId: string): Promise<ApprovalRule[]> {
    const { rows } = await this.query(
      `SELECT * FROM approval_rules WHERE user_id = $1 ORDER BY created_at ASC`,
      [userId],
    );
    return rows.map((r) => this.toRule(r));
  }

  async listRulesForTask(userId: string, taskId: string): Promise<ApprovalRule[]> {
    const { rows } = await this.query(
      `SELECT * FROM approval_rules
        WHERE user_id = $1 AND (task_id IS NULL OR task_id = $2)
        ORDER BY created_at ASC`,
      [userId, taskId],
    );
    return rows.map((r) => this.toRule(r));
  }
}

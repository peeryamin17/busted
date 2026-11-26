import type { LLMProvider } from '../llm/provider.js';
import { judgeToolCall, type JudgeResult } from '../guardrails/judge.js';
import { redactText } from '../guardrails/redact.js';
import type { Severity } from '../types.js';
import type { OracleVerdict } from '../reports/poe.js';

// Verification economy: free tool-grounded checks first, oracles next,
// a paid strong-model judgement last, and only for high-stakes claims.
// The free tier costs no LLM calls, so it is uncounted and uncapped.
// The two counted tiers are hard-capped per campaign (one swarm task).

export const MAX_ORACLE_RUNS_PER_CAMPAIGN = 20;
export const MAX_STRONG_RECHECKS_PER_CAMPAIGN = 20;

/** Tiers that spend a capped budget. The free tier is not counted. */
export type CountedTier = 'oracle' | 'strong-model';
export type CorroborationTier = 'free' | CountedTier;
export type CounterOutcome = 'used' | 'skipped-for-cap';

const CAP_FOR_TIER: Record<CountedTier, number> = {
  oracle: MAX_ORACLE_RUNS_PER_CAMPAIGN,
  'strong-model': MAX_STRONG_RECHECKS_PER_CAMPAIGN,
};

/** High-stakes claims: critical or high severity findings. */
export function isHighStakes(severity: Severity): boolean {
  return severity === 'critical' || severity === 'high';
}

/** Ladder kinds whose rung is an oracle (differential or timing). */
export function isOracleKind(kind: string): boolean {
  return kind === 'sqli' || kind === 'ssti' || kind === 'timing';
}

/**
 * A routine-tier judgement never confirms a high-severity finding on
 * its own. For lower severities a routine 'allow' can confirm.
 */
export function routineJudgementConfirms(
  severity: Severity,
  verdict: JudgeResult['verdict'],
): boolean {
  if (isHighStakes(severity)) return false;
  return verdict === 'allow';
}

/** A reasoning-tier re-check can confirm a high-severity finding. */
export function strongJudgementConfirms(verdict: JudgeResult['verdict']): boolean {
  return verdict === 'allow';
}

/**
 * A strong-model re-check runs only when the finding is high-stakes,
 * the free and oracle tiers did not settle it, and there is
 * tool-grounded evidence to re-check. It never confirms from nothing,
 * and low-severity findings never trigger one.
 */
export function needsStrongRecheck(input: {
  severity: Severity;
  settled: boolean;
  hasEvidence: boolean;
}): boolean {
  return isHighStakes(input.severity) && !input.settled && input.hasEvidence;
}

export interface CounterCounts {
  oracleRuns: number;
  strongRechecks: number;
  oracleSkipped: number;
  strongSkipped: number;
}

export interface CounterSkip {
  tier: CountedTier;
  findingRef?: string;
  at: string; // ISO
}

/**
 * Durable per-campaign tier counters. tryUse checks the cap and records
 * the outcome in one call: under the cap it records 'used' and allows
 * the work; at the cap it records 'skipped-for-cap' and denies it, so
 * a skipped run is always on the record, never silent.
 */
export interface CorroborationCounterStore {
  tryUse(
    taskId: string,
    tier: CountedTier,
    findingRef?: string,
  ): Promise<{ allowed: boolean; skippedForCap: boolean }>;
  counts(taskId: string): Promise<CounterCounts>;
  listSkips(taskId: string): Promise<CounterSkip[]>;
}

interface CounterRow {
  tier: CountedTier;
  outcome: CounterOutcome;
  findingRef?: string;
  at: string;
}

/** In-memory store for tests, CLI runs, and per-run caps without a DB. */
export class MemoryCorroborationCounterStore implements CorroborationCounterStore {
  private readonly rows = new Map<string, CounterRow[]>();

  private rowsFor(taskId: string): CounterRow[] {
    let rows = this.rows.get(taskId);
    if (!rows) {
      rows = [];
      this.rows.set(taskId, rows);
    }
    return rows;
  }

  async tryUse(
    taskId: string,
    tier: CountedTier,
    findingRef?: string,
  ): Promise<{ allowed: boolean; skippedForCap: boolean }> {
    const rows = this.rowsFor(taskId);
    const used = rows.filter((r) => r.tier === tier && r.outcome === 'used').length;
    const at = new Date().toISOString();
    if (used >= CAP_FOR_TIER[tier]) {
      rows.push({ tier, outcome: 'skipped-for-cap', findingRef, at });
      return { allowed: false, skippedForCap: true };
    }
    rows.push({ tier, outcome: 'used', findingRef, at });
    return { allowed: true, skippedForCap: false };
  }

  async counts(taskId: string): Promise<CounterCounts> {
    const rows = this.rows.get(taskId) ?? [];
    const count = (tier: CountedTier, outcome: CounterOutcome): number =>
      rows.filter((r) => r.tier === tier && r.outcome === outcome).length;
    return {
      oracleRuns: count('oracle', 'used'),
      strongRechecks: count('strong-model', 'used'),
      oracleSkipped: count('oracle', 'skipped-for-cap'),
      strongSkipped: count('strong-model', 'skipped-for-cap'),
    };
  }

  async listSkips(taskId: string): Promise<CounterSkip[]> {
    const rows = this.rows.get(taskId) ?? [];
    return rows
      .filter((r) => r.outcome === 'skipped-for-cap')
      .map((r) => ({ tier: r.tier, findingRef: r.findingRef, at: r.at }));
  }
}

/** Minimal query surface the Postgres store needs. */
export type CorroborationQueryFn = (
  sql: string,
  params: unknown[],
) => Promise<{ rows: Record<string, unknown>[] }>;

/** Postgres-backed store over corroboration_counters (migration 035). */
export class PostgresCorroborationCounterStore implements CorroborationCounterStore {
  private readonly query: CorroborationQueryFn;

  constructor(query: CorroborationQueryFn) {
    this.query = query;
  }

  async tryUse(
    taskId: string,
    tier: CountedTier,
    findingRef?: string,
  ): Promise<{ allowed: boolean; skippedForCap: boolean }> {
    const { rows } = await this.query(
      `select count(*)::int as n from corroboration_counters
        where task_id = $1 and tier = $2 and outcome = 'used'`,
      [taskId, tier],
    );
    const used = typeof rows[0]?.n === 'number' ? (rows[0].n as number) : 0;
    const outcome: CounterOutcome = used >= CAP_FOR_TIER[tier] ? 'skipped-for-cap' : 'used';
    await this.query(
      `insert into corroboration_counters (task_id, finding_ref, tier, outcome)
       values ($1, $2, $3, $4)`,
      [taskId, findingRef ?? null, tier, outcome],
    );
    return outcome === 'used'
      ? { allowed: true, skippedForCap: false }
      : { allowed: false, skippedForCap: true };
  }

  async counts(taskId: string): Promise<CounterCounts> {
    const { rows } = await this.query(
      `select tier, outcome, count(*)::int as n from corroboration_counters
        where task_id = $1 group by tier, outcome`,
      [taskId],
    );
    const out: CounterCounts = {
      oracleRuns: 0,
      strongRechecks: 0,
      oracleSkipped: 0,
      strongSkipped: 0,
    };
    for (const row of rows) {
      const n = typeof row.n === 'number' ? row.n : 0;
      if (row.tier === 'oracle' && row.outcome === 'used') out.oracleRuns = n;
      if (row.tier === 'strong-model' && row.outcome === 'used') out.strongRechecks = n;
      if (row.tier === 'oracle' && row.outcome === 'skipped-for-cap') out.oracleSkipped = n;
      if (row.tier === 'strong-model' && row.outcome === 'skipped-for-cap') out.strongSkipped = n;
    }
    return out;
  }

  async listSkips(taskId: string): Promise<CounterSkip[]> {
    const { rows } = await this.query(
      `select tier, finding_ref, created_at from corroboration_counters
        where task_id = $1 and outcome = 'skipped-for-cap' order by created_at`,
      [taskId],
    );
    return rows.map((row) => ({
      tier: row.tier as CountedTier,
      findingRef: typeof row.finding_ref === 'string' ? row.finding_ref : undefined,
      at:
        row.created_at instanceof Date
          ? row.created_at.toISOString()
          : typeof row.created_at === 'string'
            ? row.created_at
            : new Date().toISOString(),
    }));
  }
}

/**
 * The policy a run consults: one store behind it, durable when the
 * caller wired one into the task context, per-run memory otherwise.
 * Caps still hold per run either way.
 */
export class CorroborationPolicy {
  private readonly store: CorroborationCounterStore;

  constructor(store?: CorroborationCounterStore) {
    this.store = store ?? new MemoryCorroborationCounterStore();
  }

  tryOracleRun(
    taskId: string,
    findingRef?: string,
  ): Promise<{ allowed: boolean; skippedForCap: boolean }> {
    return this.store.tryUse(taskId, 'oracle', findingRef);
  }

  tryStrongRecheck(
    taskId: string,
    findingRef?: string,
  ): Promise<{ allowed: boolean; skippedForCap: boolean }> {
    return this.store.tryUse(taskId, 'strong-model', findingRef);
  }

  counts(taskId: string): Promise<CounterCounts> {
    return this.store.counts(taskId);
  }

  skips(taskId: string): Promise<CounterSkip[]> {
    return this.store.listSkips(taskId);
  }
}

export interface StrongRecheckInput {
  findingRef: string;
  title: string;
  category: string;
  severity: Severity;
  targetHost?: string;
  scopeSummary?: string;
  /** Short redacted summary of what the free/oracle tiers observed. */
  evidenceSummary?: string;
}

/**
 * Strong-model re-check of a high-stakes finding: a reasoning-tier
 * judge call over the finding's evidence. A judgement call only, it
 * sends no probe, performs no request, and authorises nothing. The
 * judge's risk questions screen whether trusting this confirmation
 * is safe; 'allow' means the strong model concurs, anything else
 * leaves the finding a hint.
 */
export async function strongModelRecheck(
  provider: LLMProvider,
  input: StrongRecheckInput,
): Promise<JudgeResult> {
  return judgeToolCall(
    provider,
    {
      tool: 'confirm_finding',
      args: {
        finding: input.title.slice(0, 200),
        category: input.category,
        severity: input.severity,
        evidence: redactText(input.evidenceSummary ?? '', 1000),
      },
      targetHost: input.targetHost,
      scopeSummary: input.scopeSummary ?? 'authorised swarm scope',
    },
    { tier: 'reasoning' },
  );
}

export type TierVerdict = 'confirmed' | 'refuted' | 'inconclusive';

export interface FreeTierOutcome {
  verdict: TierVerdict;
  /** True when the free tier settled the finding (confirmed or refuted). */
  settled: boolean;
  /** True when the tier produced tool-grounded evidence for the finding. */
  hasEvidence: boolean;
}

export interface OracleTierOutcome {
  verdict: OracleVerdict;
  hasEvidence: boolean;
}

export interface CorroborationRun {
  verdict: TierVerdict;
  tiersRun: CorroborationTier[];
  skippedForCap: CountedTier[];
  strongModelCalled: boolean;
}

/**
 * Run the tiers in order for one finding: free first, then oracles,
 * then the strong model last and only for high-stakes claims. A tier
 * that settles the finding ends the run; a capped tier is skipped and
 * recorded, never run past its cap.
 */
export async function runCorroboration(input: {
  taskId: string;
  findingId: string;
  severity: Severity;
  policy: CorroborationPolicy;
  runFree: () => Promise<FreeTierOutcome>;
  runOracle: () => Promise<OracleTierOutcome>;
  runStrongModel: (tier: 'reasoning') => Promise<JudgeResult>;
}): Promise<CorroborationRun> {
  const tiersRun: CorroborationTier[] = [];
  const skippedForCap: CountedTier[] = [];
  const free = await input.runFree();
  tiersRun.push('free');
  if (free.settled) {
    return { verdict: free.verdict, tiersRun, skippedForCap, strongModelCalled: false };
  }
  let hasEvidence = free.hasEvidence;
  const oracle = await input.policy.tryOracleRun(input.taskId, input.findingId);
  if (!oracle.allowed) {
    skippedForCap.push('oracle');
  } else {
    const outcome = await input.runOracle();
    tiersRun.push('oracle');
    hasEvidence = hasEvidence || outcome.hasEvidence;
    if (outcome.verdict === 'confirmed') {
      return { verdict: 'confirmed', tiersRun, skippedForCap, strongModelCalled: false };
    }
    if (outcome.verdict === 'refuted') {
      return { verdict: 'refuted', tiersRun, skippedForCap, strongModelCalled: false };
    }
  }
  if (!needsStrongRecheck({ severity: input.severity, settled: false, hasEvidence })) {
    return { verdict: 'inconclusive', tiersRun, skippedForCap, strongModelCalled: false };
  }
  const strong = await input.policy.tryStrongRecheck(input.taskId, input.findingId);
  if (!strong.allowed) {
    skippedForCap.push('strong-model');
    return { verdict: 'inconclusive', tiersRun, skippedForCap, strongModelCalled: false };
  }
  const judgement = await input.runStrongModel('reasoning');
  tiersRun.push('strong-model');
  return {
    verdict: strongJudgementConfirms(judgement.verdict) ? 'confirmed' : 'inconclusive',
    tiersRun,
    skippedForCap,
    strongModelCalled: true,
  };
}

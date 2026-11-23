/**
 * Coverage ledger: per task and asset, which risk classes were tested,
 * found, ruled out, or never examined. No entry means untested, never
 * clean. Memory and Postgres behind one interface.
 */

/** Risk classes, in specialist-catalog order, plus 'general'. */
export const RISK_CLASSES: readonly string[] = [
  'recon',
  'secrets',
  'headers',
  'cors',
  'xss',
  'idor',
  'auth',
  'graphql',
  'sourcemap',
  'general',
] as const;

export type RiskClass = (typeof RISK_CLASSES)[number];

/** Human-readable labels for the site panel (kept here so backend and site agree). */
export const RISK_CLASS_LABELS: Record<string, string> = {
  recon: 'Recon',
  secrets: 'Secrets',
  headers: 'Headers & cookies',
  cors: 'CORS',
  xss: 'XSS',
  idor: 'IDOR',
  auth: 'Auth',
  graphql: 'GraphQL',
  sourcemap: 'Source maps',
  general: 'General',
};

export type CoverageOutcome = 'tested' | 'untested' | 'finding' | 'not_applicable';

export const COVERAGE_OUTCOMES: readonly CoverageOutcome[] = [
  'tested',
  'untested',
  'finding',
  'not_applicable',
] as const;

export function isCoverageOutcome(value: unknown): value is CoverageOutcome {
  return (
    typeof value === 'string' &&
    (COVERAGE_OUTCOMES as readonly string[]).includes(value)
  );
}

export interface CoverageEntry {
  id?: string;
  taskId: string;
  /** Asset the entry is about; absent = the task as a whole. */
  assetId?: string;
  /** Human-readable asset (URL or host) for display; absent = task-level. */
  assetValue?: string;
  riskClass: string;
  outcome: CoverageOutcome;
  /** Short redacted evidence snippet, e.g. the probe that was run. */
  evidence?: string;
  /** Why this outcome, e.g. why a class was ruled not applicable. */
  reason?: string;
  createdAt?: string; // ISO
}

export interface CoverageClassCounts {
  tested: number;
  untested: number;
  finding: number;
  notApplicable: number;
}

export interface CoverageSummary {
  byClass: Record<string, CoverageClassCounts>;
  /** Every risk class with zero 'tested'/'finding' entries for the task. */
  untestedClasses: string[];
  /** Distinct assets that have at least one entry. */
  testedAssets: number;
  totalEntries: number;
}

function emptyCounts(): CoverageClassCounts {
  return { tested: 0, untested: 0, finding: 0, notApplicable: 0 };
}

/**
 * Pure summary over a task's entries.
 *
 * THE CORE RULE: a risk class with no entry is 'untested', never clean.
 * `untestedClasses` lists every risk class that has zero 'tested' or
 * 'finding' entries, even classes that were never mentioned anywhere.
 * A 'not_applicable' or 'untested' entry does not count as tested.
 */
export function coverageSummary(entries: CoverageEntry[]): CoverageSummary {
  const byClass: Record<string, CoverageClassCounts> = {};
  for (const rc of RISK_CLASSES) byClass[rc] = emptyCounts();

  const assetKeys = new Set<string>();
  for (const e of entries) {
    const counts = byClass[e.riskClass] ?? (byClass[e.riskClass] = emptyCounts());
    switch (e.outcome) {
      case 'tested':
        counts.tested += 1;
        break;
      case 'untested':
        counts.untested += 1;
        break;
      case 'finding':
        counts.finding += 1;
        break;
      case 'not_applicable':
        counts.notApplicable += 1;
        break;
    }
    const key = e.assetId ?? e.assetValue;
    if (key) assetKeys.add(key);
  }

  const untestedClasses = RISK_CLASSES.filter(
    (rc) => (byClass[rc]?.tested ?? 0) + (byClass[rc]?.finding ?? 0) === 0,
  );

  return {
    byClass,
    untestedClasses,
    testedAssets: assetKeys.size,
    totalEntries: entries.length,
  };
}

/**
 * Finding category → risk class. Covers the specialist ids themselves,
 * the Phase 1 finding categories ('cookies', 'tech', 'dom', 'sinks'),
 * and common aliases. Anything unrecognised maps to 'general'.
 */
const CATEGORY_TO_RISK_CLASS: Record<string, string> = {
  recon: 'recon',
  tech: 'recon',
  secrets: 'secrets',
  secret: 'secrets',
  headers: 'headers',
  cookies: 'headers',
  cookie: 'headers',
  cors: 'cors',
  xss: 'xss',
  dom: 'xss',
  sinks: 'xss',
  idor: 'idor',
  auth: 'auth',
  authentication: 'auth',
  graphql: 'graphql',
  sourcemap: 'sourcemap',
  'source-map': 'sourcemap',
  source_map: 'sourcemap',
  general: 'general',
};

export function riskClassForCategory(category: string): string {
  const normalized = category.trim().toLowerCase();
  return CATEGORY_TO_RISK_CLASS[normalized] ?? 'general';
}

/**
 * Pure helper: turn a finding list into 'finding' ledger entries, one
 * per (risk class, location). Findings with no location become one
 * task-level entry per risk class. Duplicates collapse, the ledger is
 * keyed by (task, asset, risk class), so two findings in the same class
 * on the same asset are one entry.
 */
export function recordFromFindings(
  taskId: string,
  findings: { category: string; location?: string }[],
): CoverageEntry[] {
  const byKey = new Map<string, CoverageEntry>();
  for (const f of findings) {
    const riskClass = riskClassForCategory(f.category);
    const assetValue = f.location?.trim() ? f.location.trim() : undefined;
    const key = `${riskClass}|${assetValue ?? ''}`;
    if (!byKey.has(key)) {
      byKey.set(key, {
        taskId,
        ...(assetValue ? { assetValue } : {}),
        riskClass,
        outcome: 'finding',
      });
    }
  }
  return [...byKey.values()];
}

export interface CoverageStore {
  /**
   * Upsert by (taskId, assetId, riskClass): a later entry for the same
   * triple replaces the earlier one. `assetId` is null for task-level
   * entries (no specific asset).
   */
  recordEntry(entry: CoverageEntry): Promise<CoverageEntry>;
  listEntries(taskId: string): Promise<CoverageEntry[]>;
  getEntry(
    taskId: string,
    assetId: string | null,
    riskClass: string,
  ): Promise<CoverageEntry | null>;
}

/** Map-based store for tests and memory mode. */
export class MemoryCoverageStore implements CoverageStore {
  private readonly rows = new Map<string, CoverageEntry>();
  private seq = 0;

  private key(taskId: string, assetId: string | null, riskClass: string): string {
    return `${taskId}|${assetId ?? ''}|${riskClass}`;
  }

  async recordEntry(entry: CoverageEntry): Promise<CoverageEntry> {
    const assetId = entry.assetId ?? null;
    const k = this.key(entry.taskId, assetId, entry.riskClass);
    const existing = this.rows.get(k);
    const stored: CoverageEntry = {
      ...entry,
      id: existing?.id ?? entry.id ?? `coverage-${++this.seq}`,
      assetId: assetId ?? undefined,
      createdAt: entry.createdAt ?? existing?.createdAt ?? new Date().toISOString(),
    };
    this.rows.set(k, stored);
    return { ...stored };
  }

  async listEntries(taskId: string): Promise<CoverageEntry[]> {
    return [...this.rows.values()]
      .filter((e) => e.taskId === taskId)
      .map((e) => ({ ...e }));
  }

  async getEntry(
    taskId: string,
    assetId: string | null,
    riskClass: string,
  ): Promise<CoverageEntry | null> {
    const found = this.rows.get(this.key(taskId, assetId, riskClass));
    return found ? { ...found } : null;
  }
}

/** Minimal query surface the Postgres store needs, the coordinator wires the pool. */
export type CoverageQueryFn = (
  sql: string,
  params: unknown[],
) => Promise<{ rows: Record<string, unknown>[] }>;

/**
 * Postgres-backed store. The upsert relies on the expression unique
 * index in migration 021 (`(task_id, coalesce(asset_id, zero-uuid),
 * risk_class)`), because a plain unique constraint treats NULL asset_id
 * values as distinct and would let duplicate task-level rows through.
 */
export class PostgresCoverageStore implements CoverageStore {
  private readonly query: CoverageQueryFn;

  constructor(query: CoverageQueryFn) {
    this.query = query;
  }

  private static rowToEntry(row: Record<string, unknown>): CoverageEntry {
    const createdAt = row.created_at;
    return {
      id: typeof row.id === 'string' ? row.id : undefined,
      taskId: String(row.task_id),
      assetId: typeof row.asset_id === 'string' ? row.asset_id : undefined,
      assetValue:
        typeof row.asset_value === 'string' ? row.asset_value : undefined,
      riskClass: String(row.risk_class),
      outcome: isCoverageOutcome(row.outcome) ? row.outcome : 'untested',
      evidence: typeof row.evidence === 'string' ? row.evidence : undefined,
      reason: typeof row.reason === 'string' ? row.reason : undefined,
      createdAt:
        createdAt instanceof Date
          ? createdAt.toISOString()
          : typeof createdAt === 'string'
            ? createdAt
            : undefined,
    };
  }

  async recordEntry(entry: CoverageEntry): Promise<CoverageEntry> {
    const { rows } = await this.query(
      `insert into coverage_ledger
         (task_id, asset_id, asset_value, risk_class, outcome, evidence, reason)
       values ($1, $2, $3, $4, $5, $6, $7)
       on conflict (task_id, (coalesce(asset_id, '00000000-0000-0000-0000-000000000000'::uuid)), risk_class)
       do update set
         asset_value = excluded.asset_value,
         outcome = excluded.outcome,
         evidence = excluded.evidence,
         reason = excluded.reason
       returning id, task_id, asset_id, asset_value, risk_class, outcome, evidence, reason, created_at`,
      [
        entry.taskId,
        entry.assetId ?? null,
        entry.assetValue ?? null,
        entry.riskClass,
        entry.outcome,
        entry.evidence ?? null,
        entry.reason ?? null,
      ],
    );
    const row = rows[0];
    if (!row) throw new Error('coverage_ledger upsert returned no row');
    return PostgresCoverageStore.rowToEntry(row);
  }

  async listEntries(taskId: string): Promise<CoverageEntry[]> {
    const { rows } = await this.query(
      `select id, task_id, asset_id, asset_value, risk_class, outcome, evidence, reason, created_at
         from coverage_ledger where task_id = $1 order by risk_class, asset_value`,
      [taskId],
    );
    return rows.map(PostgresCoverageStore.rowToEntry);
  }

  async getEntry(
    taskId: string,
    assetId: string | null,
    riskClass: string,
  ): Promise<CoverageEntry | null> {
    const { rows } = await this.query(
      `select id, task_id, asset_id, asset_value, risk_class, outcome, evidence, reason, created_at
         from coverage_ledger
        where task_id = $1 and asset_id is not distinct from $2 and risk_class = $3`,
      [taskId, assetId, riskClass],
    );
    const row = rows[0];
    return row ? PostgresCoverageStore.rowToEntry(row) : null;
  }
}

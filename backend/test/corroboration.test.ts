/**
 * Unit tests for the corroboration policy (multiagent/corroboration.ts):
 * tier order, per-campaign caps, the routine-tier rule for high-severity
 * findings, and the judge tier parameter. No network, no DB, no live LLM.
 * The Postgres store is exercised through a fake query function.
 *
 * Run:  npx tsx test/corroboration.test.ts   (from backend/)
 */
import {
  MAX_ORACLE_RUNS_PER_CAMPAIGN,
  MAX_STRONG_RECHECKS_PER_CAMPAIGN,
  CorroborationPolicy,
  MemoryCorroborationCounterStore,
  PostgresCorroborationCounterStore,
  isHighStakes,
  isOracleKind,
  needsStrongRecheck,
  routineJudgementConfirms,
  runCorroboration,
  strongJudgementConfirms,
  strongModelRecheck,
  type CorroborationQueryFn,
  type FreeTierOutcome,
  type OracleTierOutcome,
} from '../src/multiagent/corroboration.js';
import { judgeToolCall } from '../src/guardrails/judge.js';
import {
  makeCompletion,
  type LLMCompletionRequest,
  type LLMProvider,
} from '../src/llm/provider.js';
import {
  validateFindingWithLadder,
  type DepthProber,
} from '../src/multiagent/depthLadder.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

const TASK = '00000000-0000-0000-0000-000000000001';
const JUDGE_ALLOW = JSON.stringify({
  answers: [false, false, false, false, false, false, false, false],
  reason: 'Read-only confirmation, no risk flagged.',
});

/** Fake provider: answers from a canned JSON string, records the request. */
function fakeProvider(text: string): LLMProvider & { seen: LLMCompletionRequest[] } {
  const seen: LLMCompletionRequest[] = [];
  return {
    name: 'fake-judge',
    seen,
    async complete(req: LLMCompletionRequest) {
      seen.push(req);
      return makeCompletion(text, { inputTokens: 10, outputTokens: 10 });
    },
  };
}

function freeOutcome(over: Partial<FreeTierOutcome> = {}): FreeTierOutcome {
  return { verdict: 'inconclusive', settled: false, hasEvidence: true, ...over };
}

function oracleOutcome(over: Partial<OracleTierOutcome> = {}): OracleTierOutcome {
  return { verdict: 'inconclusive', hasEvidence: true, ...over };
}

async function main() {
  // ── 1. Order: free settles → oracle and strong model never run ──
  {
    const policy = new CorroborationPolicy();
    let oracleCalls = 0;
    let strongCalls = 0;
    const run = await runCorroboration({
      taskId: TASK,
      findingId: 'f1',
      severity: 'critical',
      policy,
      runFree: async () => freeOutcome({ verdict: 'confirmed', settled: true }),
      runOracle: async () => { oracleCalls++; return oracleOutcome(); },
      runStrongModel: async () => { strongCalls++; return { verdict: 'allow', answers: [], reason: '' }; },
    });
    check('order: free settles → confirmed', run.verdict === 'confirmed', run);
    check('order: free settles → only free ran', run.tiersRun.join(',') === 'free', run);
    check('order: free settles → oracle never called', oracleCalls === 0);
    check('order: free settles → strong model never called', strongCalls === 0 && run.strongModelCalled === false);
  }

  // ── 2. Order: free inconclusive → oracle confirms → strong never runs ──
  {
    const policy = new CorroborationPolicy();
    let strongCalls = 0;
    const tiers: string[] = [];
    const run = await runCorroboration({
      taskId: TASK,
      findingId: 'f2',
      severity: 'high',
      policy,
      runFree: async () => { tiers.push('free'); return freeOutcome(); },
      runOracle: async () => { tiers.push('oracle'); return oracleOutcome({ verdict: 'confirmed' }); },
      runStrongModel: async () => { strongCalls++; return { verdict: 'allow', answers: [], reason: '' }; },
    });
    check('order: oracle confirms → confirmed', run.verdict === 'confirmed', run);
    check('order: oracle confirms → free then oracle', tiers.join(',') === 'free,oracle', tiers);
    check('order: oracle confirms → strong never called', strongCalls === 0 && run.strongModelCalled === false);
  }

  // ── 3. Order: free + oracle inconclusive, high severity → strong at reasoning tier ──
  {
    const policy = new CorroborationPolicy();
    let strongTier: string | undefined;
    const run = await runCorroboration({
      taskId: TASK,
      findingId: 'f3',
      severity: 'high',
      policy,
      runFree: async () => freeOutcome(),
      runOracle: async () => oracleOutcome(),
      runStrongModel: async (tier) => {
        strongTier = tier;
        return { verdict: 'allow', answers: [], reason: 'strong model concurs' };
      },
    });
    check('order: strong model runs last for high severity', run.strongModelCalled === true, run);
    check('order: strong model called at reasoning tier', strongTier === 'reasoning', strongTier);
    check('order: tiers ran free, oracle, strong-model', run.tiersRun.join(',') === 'free,oracle,strong-model', run);
    check('order: strong allow → confirmed', run.verdict === 'confirmed', run);
  }

  // ── 4. Low severity never triggers a strong-model re-check ──
  {
    const policy = new CorroborationPolicy();
    let strongCalls = 0;
    const run = await runCorroboration({
      taskId: TASK,
      findingId: 'f4',
      severity: 'low',
      policy,
      runFree: async () => freeOutcome(),
      runOracle: async () => oracleOutcome(),
      runStrongModel: async () => { strongCalls++; return { verdict: 'allow', answers: [], reason: '' }; },
    });
    check('low severity → no strong-model call', strongCalls === 0 && run.strongModelCalled === false);
    check('low severity → stays inconclusive', run.verdict === 'inconclusive', run);
    check('low severity → tiers ran free, oracle', run.tiersRun.join(',') === 'free,oracle', run);
  }

  // ── 5. Routine-tier judgement alone never confirms a high-severity finding ──
  {
    check('routine allow never confirms high', routineJudgementConfirms('high', 'allow') === false);
    check('routine allow never confirms critical', routineJudgementConfirms('critical', 'allow') === false);
    check('routine allow can confirm low', routineJudgementConfirms('low', 'allow') === true);
    check('routine allow can confirm medium', routineJudgementConfirms('medium', 'allow') === true);
    check('routine ask confirms nothing', routineJudgementConfirms('low', 'ask') === false);
    check('strong allow confirms', strongJudgementConfirms('allow') === true);
    check('strong ask confirms nothing', strongJudgementConfirms('ask') === false);
  }

  // ── 6. needsStrongRecheck gating ──
  {
    check('recheck: high + unsettled + evidence', needsStrongRecheck({ severity: 'high', settled: false, hasEvidence: true }) === true);
    check('recheck: settled → no', needsStrongRecheck({ severity: 'high', settled: true, hasEvidence: true }) === false);
    check('recheck: no evidence → no', needsStrongRecheck({ severity: 'high', settled: false, hasEvidence: false }) === false);
    check('recheck: low severity → no', needsStrongRecheck({ severity: 'low', settled: false, hasEvidence: true }) === false);
    check('recheck: info → no', needsStrongRecheck({ severity: 'info', settled: false, hasEvidence: true }) === false);
  }

  // ── 7. Oracle cap: 21st run is skipped and recorded ──
  {
    const policy = new CorroborationPolicy();
    let oracleCalls = 0;
    let last: Awaited<ReturnType<typeof runCorroboration>> | undefined;
    for (let i = 0; i < MAX_ORACLE_RUNS_PER_CAMPAIGN + 1; i++) {
      last = await runCorroboration({
        taskId: TASK,
        findingId: `cap-oracle-${i}`,
        severity: 'low',
        policy,
        runFree: async () => freeOutcome(),
        runOracle: async () => { oracleCalls++; return oracleOutcome(); },
        runStrongModel: async () => ({ verdict: 'allow', answers: [], reason: '' }),
      });
    }
    check('oracle cap: only 20 oracle runs executed', oracleCalls === MAX_ORACLE_RUNS_PER_CAMPAIGN, oracleCalls);
    check('oracle cap: 21st run skipped for cap', last?.skippedForCap.join(',') === 'oracle', last);
    check('oracle cap: 21st run did not reach strong model', last?.strongModelCalled === false, last);
    const counts = await policy.counts(TASK);
    check('oracle cap: counts show 20 used, 1 skipped', counts.oracleRuns === 20 && counts.oracleSkipped === 1, counts);
    const skips = await policy.skips(TASK);
    check('oracle cap: skip is recorded, not silent', skips.length === 1 && skips[0]?.tier === 'oracle', skips);
    check('oracle cap: skip names the finding', skips[0]?.findingRef === `cap-oracle-${MAX_ORACLE_RUNS_PER_CAMPAIGN}`, skips);
  }

  // ── 8. Strong-model cap: 21st re-check is skipped and recorded ──
  // Pre-exhaust only the strong budget, so the oracle tier is untouched.
  {
    const policy = new CorroborationPolicy();
    let allowed = 0;
    for (let i = 0; i < MAX_STRONG_RECHECKS_PER_CAMPAIGN; i++) {
      const r = await policy.tryStrongRecheck(TASK, `pre-${i}`);
      if (r.allowed) allowed++;
    }
    check('strong cap: 20 re-checks fit', allowed === MAX_STRONG_RECHECKS_PER_CAMPAIGN, allowed);
    let strongCalls = 0;
    const run = await runCorroboration({
      taskId: TASK,
      findingId: 'cap-strong-21',
      severity: 'critical',
      policy,
      runFree: async () => freeOutcome(),
      runOracle: async () => oracleOutcome(),
      runStrongModel: async () => { strongCalls++; return { verdict: 'allow', answers: [], reason: '' }; },
    });
    check('strong cap: 21st re-check skipped for cap', run.skippedForCap.join(',') === 'strong-model', run);
    check('strong cap: 21st re-check not called', strongCalls === 0 && run.strongModelCalled === false, run);
    check('strong cap: oracle tier still ran', run.tiersRun.join(',') === 'free,oracle', run);
    const counts = await policy.counts(TASK);
    check('strong cap: counts show 20 used, 1 skipped', counts.strongRechecks === 20 && counts.strongSkipped === 1, counts);
    const skips = await policy.skips(TASK);
    check('strong cap: skip is recorded, not silent', skips.length === 1 && skips[0]?.tier === 'strong-model', skips);
    check('strong cap: skip names the finding', skips[0]?.findingRef === 'cap-strong-21', skips);
  }

  // ── 9. Judge tier parameter: default routine, reasoning when asked ──
  {
    const p1 = fakeProvider(JUDGE_ALLOW);
    await judgeToolCall(p1, { tool: 'http_fetch' });
    check('judge: default tier is routine', p1.seen[0]?.tier === 'routine', p1.seen[0]);
    const p2 = fakeProvider(JUDGE_ALLOW);
    await judgeToolCall(p2, { tool: 'http_fetch' }, { tier: 'reasoning' });
    check('judge: explicit tier reaches provider', p2.seen[0]?.tier === 'reasoning', p2.seen[0]);
  }

  // ── 10. Strong-model re-check calls the judge at the reasoning tier ──
  {
    const provider = fakeProvider(JUDGE_ALLOW);
    const result = await strongModelRecheck(provider, {
      findingRef: 'f10',
      title: 'SQL injection in search',
      category: 'SQL injection',
      severity: 'high',
      targetHost: 'example.com',
      evidenceSummary: 'differential oracle: responses differ after normalisation',
    });
    check('strong re-check: judge allow', result.verdict === 'allow', result);
    check('strong re-check: sent at reasoning tier', provider.seen[0]?.tier === 'reasoning', provider.seen[0]);
    check('strong re-check: finding in prompt', provider.seen[0]?.messages.some((m) => m.content.includes('SQL injection in search')) === true);
  }

  // ── 11. Postgres store through a fake query function ──
  {
    type Row = { task_id: string; finding_ref: string | null; tier: string; outcome: string; created_at: Date };
    const rows: Row[] = [];
    const query: CorroborationQueryFn = async (sql, params) => {
      if (sql.includes('count(*)::int as n') && sql.includes('outcome = \'used\'')) {
        const [taskId, tier] = params as [string, string];
        const n = rows.filter((r) => r.task_id === taskId && r.tier === tier && r.outcome === 'used').length;
        return { rows: [{ n }] };
      }
      if (sql.trimStart().startsWith('insert into corroboration_counters')) {
        const [taskId, findingRef, tier, outcome] = params as [string, string | null, string, string];
        rows.push({ task_id: taskId, finding_ref: findingRef, tier, outcome, created_at: new Date() });
        return { rows: [] };
      }
      if (sql.includes('group by tier, outcome')) {
        const [taskId] = params as [string];
        const agg = new Map<string, number>();
        for (const r of rows.filter((x) => x.task_id === taskId)) {
          const k = `${r.tier}|${r.outcome}`;
          agg.set(k, (agg.get(k) ?? 0) + 1);
        }
        return { rows: [...agg.entries()].map(([k, n]) => { const [tier, outcome] = k.split('|'); return { tier, outcome, n }; }) };
      }
      if (sql.includes('outcome = \'skipped-for-cap\'')) {
        const [taskId] = params as [string];
        return { rows: rows.filter((r) => r.task_id === taskId && r.outcome === 'skipped-for-cap').map((r) => ({ tier: r.tier, finding_ref: r.finding_ref, created_at: r.created_at })) };
      }
      throw new Error(`fake query: unexpected SQL: ${sql.slice(0, 80)}`);
    };
    const store = new PostgresCorroborationCounterStore(query);
    const policy = new CorroborationPolicy(store);
    let allowed = 0;
    for (let i = 0; i < MAX_ORACLE_RUNS_PER_CAMPAIGN + 1; i++) {
      const r = await policy.tryOracleRun(TASK, `pg-${i}`);
      if (r.allowed) allowed++;
      else check('pg store: 21st denied and flagged skipped', r.skippedForCap === true, r);
    }
    check('pg store: 20 allowed', allowed === 20, allowed);
    const counts = await policy.counts(TASK);
    check('pg store: counts match', counts.oracleRuns === 20 && counts.oracleSkipped === 1, counts);
    const skips = await policy.skips(TASK);
    check('pg store: skip recorded with finding ref', skips.length === 1 && skips[0]?.findingRef === `pg-${MAX_ORACLE_RUNS_PER_CAMPAIGN}`, skips);
    const memory = new MemoryCorroborationCounterStore();
    check('memory store: fresh task starts at zero', JSON.stringify(await memory.counts(TASK)) === JSON.stringify({ oracleRuns: 0, strongRechecks: 0, oracleSkipped: 0, strongSkipped: 0 }));
  }

  // ── 12. skipOracle: the ladder runs no oracle probe past the cap ──
  {
    let probes = 0;
    const prober: DepthProber = async () => { probes++; return { ok: true, status: 200, headers: {}, body: '' }; };
    const v = await validateFindingWithLadder(
      { category: 'SQL injection', title: 'Boolean-based SQL injection in search', location: 'http://127.0.0.1:9/search?q=1', evidence: '' },
      prober,
      { skipOracle: true },
    );
    check('skipOracle: finding stays a hint', v.status === 'hint', v);
    check('skipOracle: no probe sent', probes === 0, probes);
    check('skipOracle: reason recorded', v.impactSummary.includes('oracle rung skipped'), v.impactSummary);
  }

  // ── 13. Kind and severity helpers ──
  {
    check('isOracleKind: sqli/ssti/timing', isOracleKind('sqli') && isOracleKind('ssti') && isOracleKind('timing'));
    check('isOracleKind: xss is not an oracle kind', isOracleKind('xss') === false);
    check('isHighStakes: critical/high only', isHighStakes('critical') && isHighStakes('high') && !isHighStakes('medium') && !isHighStakes('low'));
  }

  if (failures > 0) {
    console.error(`\n${failures} check(s) failed`);
    process.exit(1);
  }
  console.log('\nall corroboration checks passed');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

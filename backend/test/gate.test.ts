/**
 * Integration tests for the swarm-step gate (src/approvals/gate.ts):
 * standing rules → LLM judge → human approval, with a per-run cache.
 * Fake provider + Memory stores only. No network, no DB, no live LLM.
 *
 * Run:  npx tsx test/gate.test.ts   (from backend/)
 */
import { gateToolCall } from '../src/approvals/gate.js';
import { MemoryApprovalStore } from '../src/approvals/store.js';
import { MemoryApprovalRuleStore } from '../src/approvals/rules.js';
import { makeCompletion, type LLMProvider } from '../src/llm/provider.js';
import type { ScopePolicy } from '../src/types.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) {
    failures++;
    console.error(`FAIL: ${name}`, extra ?? '');
  } else console.log(`ok: ${name}`);
}

const SCOPE: ScopePolicy = {
  mode: 'subdomain',
  includeSubdomains: false,
  excludedHosts: [],
  excludedPaths: [],
  maxRequestsPerSecond: 50,
};
const TARGET = 'https://example.com/';
const USER = 'user-1';
const TASK = 'task-1';

/** Fake provider whose judge answers the caller controls; counts calls. */
function judgeProvider(answers: boolean[], opts: { throw?: boolean } = {}): {
  provider: LLMProvider;
  calls: () => number;
} {
  let n = 0;
  const provider: LLMProvider = {
    name: 'fake-judge',
    async complete() {
      n++;
      if (opts.throw) throw new Error('provider down');
      return makeCompletion(
        JSON.stringify({ answers, reason: 'fake judge verdict' }),
        { inputTokens: 10, outputTokens: 5 },
      );
    },
  };
  return { provider, calls: () => n };
}

function freshStores() {
  return {
    approvals: new MemoryApprovalStore(),
    rules: new MemoryApprovalRuleStore(),
  };
}

async function main(): Promise<void> {
  const allFalse = [false, false, false, false, false, false, false, false];
  const oneTrue = [false, false, true, false, false, false, false, false];

  // 1. No approval queue attached → ungated, judge never called.
  {
    const { provider, calls } = judgeProvider(allFalse);
    const out = await gateToolCall({
      provider,
      taskId: TASK,
      userId: USER,
      tool: 'fetch_url',
      args: { url: 'https://example.com/' },
      targetUrl: TARGET,
      scope: SCOPE,
    });
    check('gate: no queue → proceed', out.proceed === true);
    check('gate: no queue → judge not called', calls() === 0);
  }

  // 2. Standing allow rule → proceed, judge never called, decided by rule.
  {
    const { approvals, rules } = freshStores();
    await rules.createRule({
      userId: USER,
      taskId: TASK,
      pattern: { kind: 'tool', value: 'fetch_url' },
      decision: 'allow',
    });
    const { provider, calls } = judgeProvider(allFalse);
    const out = await gateToolCall({
      provider,
      approvals,
      approvalRules: rules,
      taskId: TASK,
      userId: USER,
      tool: 'fetch_url',
      args: { url: 'https://example.com/' },
      targetUrl: TARGET,
      scope: SCOPE,
    });
    check('gate: allow rule → proceed', out.proceed === true);
    check('gate: allow rule → judge not called', calls() === 0);
    const rows = await approvals.listForTask(TASK);
    check('gate: allow rule → one row, decided by rule', rows.length === 1 && rows[0]!.status === 'allowed' && (rows[0]!.decidedBy ?? '').startsWith('rule:'));
  }

  // 3. Standing deny rule → blocked, judge never called.
  {
    const { approvals, rules } = freshStores();
    await rules.createRule({
      userId: USER,
      taskId: TASK,
      pattern: { kind: 'tool', value: 'probe_idor' },
      decision: 'deny',
    });
    const { provider, calls } = judgeProvider(allFalse);
    const out = await gateToolCall({
      provider,
      approvals,
      approvalRules: rules,
      taskId: TASK,
      userId: USER,
      tool: 'probe_idor',
      args: { url: 'https://example.com/users/2' },
      targetUrl: TARGET,
      scope: SCOPE,
    });
    check('gate: deny rule → blocked', out.proceed === false);
    check('gate: deny rule → judge not called', calls() === 0);
  }

  // 4. No rule + judge all-clear → proceed, row decided by 'judge'.
  {
    const { approvals, rules } = freshStores();
    const { provider, calls } = judgeProvider(allFalse);
    const out = await gateToolCall({
      provider,
      approvals,
      approvalRules: rules,
      taskId: TASK,
      userId: USER,
      tool: 'fetch_url',
      args: { url: 'https://example.com/about' },
      targetUrl: TARGET,
      scope: SCOPE,
    });
    check('gate: judge all-clear → proceed', out.proceed === true);
    check('gate: judge all-clear → judge called once', calls() === 1);
    const rows = await approvals.listForTask(TASK);
    check(
      'gate: judge all-clear → row decided by judge',
      rows.length === 1 && rows[0]!.status === 'allowed' && rows[0]!.decidedBy === 'judge',
    );
  }

  // 5. Judge flags it → pending approval; operator allows → proceed.
  {
    const { approvals, rules } = freshStores();
    const { provider } = judgeProvider(oneTrue);
    const pending = gateToolCall({
      provider,
      approvals,
      approvalRules: rules,
      taskId: TASK,
      userId: USER,
      tool: 'probe_graphql',
      args: { url: 'https://example.com/graphql' },
      targetUrl: TARGET,
      scope: SCOPE,
      timeoutMs: 10_000,
    });
    // Let the gate create the pending row, then decide it as the operator.
    await new Promise((r) => setTimeout(r, 50));
    const rows = await approvals.listPending(TASK);
    check('gate: judge flag → one pending approval', rows.length === 1 && rows[0]!.kind === 'judge');
    await approvals.decide(rows[0]!.id, 'allow', USER);
    const out = await pending;
    check('gate: operator allow → proceed', out.proceed === true);
    check('gate: operator allow → approval id returned', out.approvalId === rows[0]!.id);
  }

  // 6. Judge flags it → operator denies → blocked, never retried.
  {
    const { approvals, rules } = freshStores();
    const { provider } = judgeProvider(oneTrue);
    const pending = gateToolCall({
      provider,
      approvals,
      approvalRules: rules,
      taskId: TASK,
      userId: USER,
      tool: 'probe_graphql',
      args: { url: 'https://example.com/graphql' },
      targetUrl: TARGET,
      scope: SCOPE,
      timeoutMs: 10_000,
    });
    await new Promise((r) => setTimeout(r, 50));
    const rows = await approvals.listPending(TASK);
    await approvals.decide(rows[0]!.id, 'deny', USER);
    const out = await pending;
    check('gate: operator deny → blocked', out.proceed === false);
    const after = await approvals.listForTask(TASK);
    check('gate: operator deny → row stays denied', after[0]!.status === 'denied');
  }

  // 7. Judge provider throws → ask path (pending), timeout → denied.
  {
    const { approvals, rules } = freshStores();
    const { provider } = judgeProvider(allFalse, { throw: true });
    const out = await gateToolCall({
      provider,
      approvals,
      approvalRules: rules,
      taskId: TASK,
      userId: USER,
      tool: 'fetch_url',
      args: { url: 'https://example.com/' },
      targetUrl: TARGET,
      scope: SCOPE,
      timeoutMs: 600,
    });
    check('gate: judge failure → blocked on timeout', out.proceed === false);
    const rows = await approvals.listForTask(TASK);
    check('gate: judge failure → row expired', rows[0]!.status === 'expired');
  }

  // 8. Per-run cache: the same tool call is judged once.
  {
    const { approvals, rules } = freshStores();
    const { provider, calls } = judgeProvider(allFalse);
    const cache = new Map<string, 'allowed' | 'denied'>();
    const base = {
      provider,
      approvals,
      approvalRules: rules,
      taskId: TASK,
      userId: USER,
      tool: 'fetch_url',
      args: { url: 'https://example.com/cached' },
      targetUrl: TARGET,
      scope: SCOPE,
      cache,
    };
    const first = await gateToolCall(base);
    const second = await gateToolCall(base);
    check('gate: cache → both proceed', first.proceed === true && second.proceed === true);
    check('gate: cache → judge called once', calls() === 1);
    const rows = await approvals.listForTask(TASK);
    check('gate: cache → one approval row, not two', rows.length === 1);
  }

  // 9. Store failure → fail closed (step does not run).
  {
    const { rules } = freshStores();
    const { provider } = judgeProvider(allFalse);
    const brokenStore = new Proxy(new MemoryApprovalStore(), {
      get(t, p) {
        if (p === 'create' || p === 'listRulesForTask') {
          return async () => {
            throw new Error('store down');
          };
        }
        const v = (t as unknown as Record<string | symbol, unknown>)[p];
        return typeof v === 'function' ? (v as (...a: unknown[]) => unknown).bind(t) : v;
      },
    });
    const out = await gateToolCall({
      provider,
      approvals: brokenStore as unknown as MemoryApprovalStore,
      approvalRules: rules,
      taskId: TASK,
      userId: USER,
      tool: 'fetch_url',
      args: { url: 'https://example.com/' },
      targetUrl: TARGET,
      scope: SCOPE,
      timeoutMs: 500,
    });
    check('gate: store failure → fail closed', out.proceed === false);
  }

  // 10. Out-of-scope URL scores critical and still goes to the judge (not
  // auto-allowed): the judge clears it here, but the row carries the score.
  {
    const { approvals, rules } = freshStores();
    const { provider } = judgeProvider(allFalse);
    const out = await gateToolCall({
      provider,
      approvals,
      approvalRules: rules,
      taskId: TASK,
      userId: USER,
      tool: 'fetch_url',
      args: { url: 'https://other.example/' },
      targetUrl: TARGET,
      scope: SCOPE,
    });
    const rows = await approvals.listForTask(TASK);
    check('gate: out-of-scope call → risk score ≥ 80 on the row', (rows[0]!.riskScore ?? 0) >= 80);
    check('gate: out-of-scope call → judge still decides', out.proceed === true && (rows[0]!.riskScore ?? 0) >= 80);
  }

  if (failures > 0) {
    console.error(`${failures} GATE TEST(S) FAILED`);
    process.exit(1);
  }
  console.log('ALL GATE TESTS PASSED');
}

main().catch((err) => {
  console.error('gate test crashed:', err);
  process.exit(1);
});

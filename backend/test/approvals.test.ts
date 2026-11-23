/**
 * Unit tests for the approval queue (src/approvals/*). No network, no
 * DB, no LLM, Memory stores only.
 *
 * Run:  npx tsx test/approvals.test.ts   (from backend/)
 */
import { MemoryApprovalStore } from '../src/approvals/store.js';
import {
  MemoryApprovalRuleStore,
  findMatchingRule,
} from '../src/approvals/rules.js';
import {
  batchDecide,
  decide,
  requestApproval,
  waitForDecision,
} from '../src/approvals/service.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function main() {
  const store = new MemoryApprovalStore();
  const rules = new MemoryApprovalRuleStore();

  // ── 1. create → pending ──
  const a1 = await requestApproval(store, {
    taskId: 'task-1',
    userId: 'user-1',
    kind: 'tool-call',
    action: 'Run httpFetch against https://example.com/api',
    detail: { tool: 'httpFetch', args: 'GET /api' },
    requestedBy: 'swarm',
  });
  check('create: status pending', a1.status === 'pending', a1);
  check('create: decidedBy null', a1.decidedBy === null);
  check('create: riskScore null until risk module lands', a1.riskScore === null);
  const pending = await store.listPending('task-1');
  check('create: listed as pending', pending.some((a) => a.id === a1.id));

  // ── 2. decide allow records decidedBy/decidedAt ──
  const allowed = await decide(store, a1.id, 'allow', 'user-1');
  check('decide allow: status allowed', allowed.status === 'allowed', allowed);
  check('decide allow: decidedBy recorded', allowed.decidedBy === 'user-1');
  check('decide allow: decidedAt recorded', typeof allowed.decidedAt === 'string' && allowed.decidedAt.length > 0);

  // ── 3. decide deny ──
  const a2 = await requestApproval(store, {
    taskId: 'task-1',
    userId: 'user-1',
    kind: 'new-target',
    action: 'Expand scope to https://api.example.com',
    detail: { host: 'api.example.com' },
    requestedBy: 'swarm',
  });
  const denied = await decide(store, a2.id, 'deny', 'user-1');
  check('decide deny: status denied', denied.status === 'denied', denied);
  check('decide deny: decidedBy recorded', denied.decidedBy === 'user-1');

  // ── 4. deciding a decided approval errors, never overwrites ──
  let threw = false;
  let errMsg = '';
  try {
    await decide(store, a1.id, 'deny', 'user-1');
  } catch (err) {
    threw = true;
    errMsg = (err as Error).message;
  }
  check('decide decided: throws', threw, errMsg);
  check('decide decided: error names the status', errMsg === 'approval_not_pending: allowed', errMsg);
  const stillAllowed = await store.get(a1.id);
  check('decide decided: row not overwritten', stillAllowed?.status === 'allowed', stillAllowed);

  // ── 5. waitForDecision resolves 'allowed' when decided mid-wait ──
  const a3 = await requestApproval(store, {
    taskId: 'task-1',
    userId: 'user-1',
    kind: 'judge',
    action: 'Judge: is this reflected input a real finding?',
    detail: { questions: ['Is the reflection verbatim?'] },
    requestedBy: 'judge',
  });
  const waiting = waitForDecision(store, a3.id, 5000);
  await sleep(600);
  await decide(store, a3.id, 'allow', 'user-1');
  check('wait: resolves allowed when decided mid-wait', (await waiting) === 'allowed');

  // ── 6. waitForDecision times out to 'denied' and marks expired ──
  const a4 = await requestApproval(store, {
    taskId: 'task-1',
    userId: 'user-1',
    kind: 'tool-call',
    action: 'Run httpFetch against https://example.com/slow',
    detail: { tool: 'httpFetch' },
    requestedBy: 'swarm',
  });
  const outcome = await waitForDecision(store, a4.id, 1100);
  check('wait timeout: resolves denied', outcome === 'denied', outcome);
  const expired = await store.get(a4.id);
  check('wait timeout: approval marked expired', expired?.status === 'expired', expired);

  // ── 7. batch-decide handles a mix of pending + already-decided ──
  const b1 = await requestApproval(store, {
    taskId: 'task-2', userId: 'user-1', kind: 'tool-call',
    action: 'Batch one', detail: {}, requestedBy: 'swarm',
  });
  const b2 = await requestApproval(store, {
    taskId: 'task-2', userId: 'user-1', kind: 'tool-call',
    action: 'Batch two', detail: {}, requestedBy: 'swarm',
  });
  await decide(store, b2.id, 'deny', 'user-1');
  const results = await batchDecide(store, [b1.id, b2.id, 'missing-id'], 'allow', 'user-1');
  check('batch: three results', results.length === 3, results);
  check('batch: pending one decided', results[0].ok === true && results[0].approval?.status === 'allowed', results[0]);
  check('batch: decided one reported, not fatal', results[1].ok === false && (results[1].error ?? '').startsWith('approval_not_pending'), results[1]);
  check('batch: missing one reported, not fatal', results[2].ok === false && results[2].error === 'approval_not_found', results[2]);

  // ── 8. rule matching: exact + prefix ──
  const exactTool = await rules.createRule({
    userId: 'user-1',
    taskId: null,
    pattern: { kind: 'tool', value: 'httpFetch' },
    decision: 'allow',
  });
  const prefixTool = await rules.createRule({
    userId: 'user-1',
    taskId: null,
    pattern: { kind: 'tool', value: 'http' },
    decision: 'deny',
  });
  const hostRule = await rules.createRule({
    userId: 'user-1',
    taskId: 'task-1',
    pattern: { kind: 'target-host', value: 'api.example.com' },
    decision: 'deny',
  });
  const allRules = await rules.listRules('user-1');
  const exact = findMatchingRule(allRules, { kind: 'tool', value: 'httpFetch', taskId: 'task-1' });
  check('rules: exact match wins over shorter prefix', exact?.id === exactTool.id, exact);
  const prefix = findMatchingRule(allRules, { kind: 'tool', value: 'httpPost', taskId: 'task-1' });
  check('rules: prefix match returns the prefix rule', prefix?.id === prefixTool.id && prefix?.decision === 'deny', prefix);
  const host = findMatchingRule(allRules, { kind: 'target-host', value: 'api.example.com', taskId: 'task-1' });
  check('rules: host exact match', host?.id === hostRule.id && host?.decision === 'deny', host);
  const hostOtherTask = findMatchingRule(allRules, { kind: 'target-host', value: 'api.example.com', taskId: 'task-9' });
  check('rules: task-scoped rule does not match another task', hostOtherTask === null, hostOtherTask);
  const noMatch = findMatchingRule(allRules, { kind: 'category', value: 'xss', taskId: 'task-1' });
  check('rules: no match returns null', noMatch === null);

  // ── 9. always-allow rule path records decidedBy as rule:<id> ──
  const alwaysRule = await rules.createRule({
    userId: 'user-1',
    taskId: null,
    pattern: { kind: 'tool', value: 'readFile' },
    decision: 'allow',
    alwaysAllow: true,
  });
  const auto = await requestApproval(
    store,
    {
      taskId: 'task-1',
      userId: 'user-1',
      kind: 'tool-call',
      action: 'Read local bundle file for analysis',
      detail: { tool: 'readFile' },
      requestedBy: 'swarm',
      candidate: { kind: 'tool', value: 'readFile', taskId: 'task-1' },
    },
    { rules },
  );
  check('always-allow: approval auto-allowed', auto.status === 'allowed', auto);
  check('always-allow: decidedBy is rule:<id>', auto.decidedBy === `rule:${alwaysRule.id}`, auto);
  check('always-allow: ruleId stored on the row', auto.ruleId === alwaysRule.id, auto);

  // ── 10. deny rule auto-denies through the same path ──
  const autoDenied = await requestApproval(
    store,
    {
      taskId: 'task-1',
      userId: 'user-1',
      kind: 'new-target',
      action: 'Expand scope to https://api.example.com/v2',
      detail: { host: 'api.example.com' },
      requestedBy: 'swarm',
      candidate: { kind: 'target-host', value: 'api.example.com', taskId: 'task-1' },
    },
    { rules },
  );
  check('rule deny: approval auto-denied', autoDenied.status === 'denied', autoDenied);
  check('rule deny: decidedBy is rule:<id>', autoDenied.decidedBy === `rule:${hostRule.id}`, autoDenied);

  // ── 11. validation: action over 500 chars is refused ──
  let longThrew = false;
  try {
    await requestApproval(store, {
      taskId: 'task-1',
      userId: 'user-1',
      kind: 'tool-call',
      action: 'x'.repeat(501),
      requestedBy: 'swarm',
    });
  } catch {
    longThrew = true;
  }
  check('validation: action over 500 chars refused', longThrew);

  // ── 12. listForTask: pending first, then newest first ──
  await requestApproval(store, {
    taskId: 'task-1', userId: 'user-1', kind: 'tool-call',
    action: 'Still waiting on the operator', detail: {}, requestedBy: 'swarm',
  });
  const listed = await store.listForTask('task-1');
  const firstPending = listed.findIndex((a) => a.status === 'pending');
  const lastPending = listed.map((a) => a.status).lastIndexOf('pending');
  const decidedAfterPending = listed.slice(lastPending + 1).every((a) => a.status !== 'pending');
  check('list: pending rows come first', firstPending === 0 && decidedAfterPending, listed.map((a) => a.status));

  if (failures > 0) { console.error(`${failures} approval test(s) failed`); process.exit(1); }
  console.log('ALL APPROVAL TESTS PASSED');
  process.exit(0);
}

main().catch((e) => { console.error('approvals test crashed', e); process.exit(1); });

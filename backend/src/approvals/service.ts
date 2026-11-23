/**
 * Approval queue decisions. No LLM, no network. A step the operator has
 * not allowed does not run. Waiting times out to denied, never allowed.
 */
import type {
  ApprovalDecision,
  ApprovalRecord,
  ApprovalStore,
  CreateApprovalInput,
} from './store.js';
import {
  findMatchingRule,
  type ApprovalRuleStore,
  type RuleCandidate,
} from './rules.js';

export interface RequestApprovalInput extends CreateApprovalInput {
  /**
   * What the proposal is, in rule-matching terms (e.g. { kind: 'tool',
   * value: 'httpFetch' } or { kind: 'target-host', value: 'api.example.com' }).
   * When given and a rules store is passed, a matching allow/deny rule
   * decides the approval immediately instead of leaving it pending.
   */
  candidate?: RuleCandidate;
}

export interface RequestApprovalOptions {
  rules?: ApprovalRuleStore;
}

/** Poll interval for waitForDecision (ms). */
export const APPROVAL_POLL_MS = 500;

/** Default wait for an operator decision: 5 minutes. */
export const DEFAULT_APPROVAL_TIMEOUT_MS = 5 * 60 * 1000;

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Create an approval for a proposed step. Without a matching rule it
 * is created pending, waiting on the operator. With a matching
 * allow/deny rule (candidate + rules store given) the approval is
 * created and immediately decided through that rule, decidedBy is
 * recorded as `rule:<ruleId>` and ruleId is stored on the row, so the
 * audit trail shows which rule let the step through (or stopped it).
 * An 'ask' rule leaves the approval pending, like no rule at all.
 */
export async function requestApproval(
  store: ApprovalStore,
  input: RequestApprovalInput,
  opts: RequestApprovalOptions = {},
): Promise<ApprovalRecord> {
  if (opts.rules && input.candidate) {
    const rules = await opts.rules.listRulesForTask(input.userId, input.taskId);
    const matched = findMatchingRule(rules, input.candidate);
    if (matched && (matched.decision === 'allow' || matched.decision === 'deny')) {
      const created = await store.create({ ...input, ruleId: matched.id });
      return store.decide(created.id, matched.decision, `rule:${matched.id}`);
    }
  }
  return store.create(input);
}

/**
 * Wait for the operator to decide an approval. Polls the store every
 * 500ms and resolves 'allowed' when the row is allowed, 'denied' when
 * it is denied, skipped or expired. On timeout the approval is marked
 * 'expired' and the promise resolves 'denied', a step the operator
 * never answered does not run. An approval that no longer exists also
 * resolves 'denied' (fail closed).
 */
export async function waitForDecision(
  store: ApprovalStore,
  approvalId: string,
  timeoutMs: number = DEFAULT_APPROVAL_TIMEOUT_MS,
): Promise<'allowed' | 'denied'> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const record = await store.get(approvalId);
    if (!record) return 'denied';
    if (record.status === 'allowed') return 'allowed';
    if (
      record.status === 'denied' ||
      record.status === 'skipped' ||
      record.status === 'expired'
    ) {
      return 'denied';
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      await store.markExpired(approvalId).catch(() => undefined);
      return 'denied';
    }
    await sleep(Math.min(APPROVAL_POLL_MS, remaining));
  }
}

/**
 * Decide a pending approval as the operator. The route does the auth
 * and ownership check (the decider must own the task); the service
 * enforces pending-only, deciding an already-decided approval throws
 * `approval_not_pending: <status>` from the store, never overwriting it.
 */
export async function decide(
  store: ApprovalStore,
  id: string,
  decision: ApprovalDecision,
  userId: string,
): Promise<ApprovalRecord> {
  if (decision !== 'allow' && decision !== 'deny') {
    throw new Error(`invalid_approval_decision: ${decision}`);
  }
  return store.decide(id, decision, userId);
}

export interface BatchDecideResult {
  id: string;
  ok: boolean;
  approval?: ApprovalRecord;
  error?: string;
}

/**
 * Decide several approvals at once. Each pending one is decided;
 * each already-decided or missing one is reported in its own result
 * instead of failing the batch, partial success is the expected
 * outcome when the operator selects a queue that moved meanwhile.
 */
export async function batchDecide(
  store: ApprovalStore,
  ids: string[],
  decision: ApprovalDecision,
  decidedBy: string,
): Promise<BatchDecideResult[]> {
  const results: BatchDecideResult[] = [];
  for (const id of ids) {
    try {
      const approval = await store.decide(id, decision, decidedBy);
      results.push({ id, ok: true, approval });
    } catch (err) {
      results.push({ id, ok: false, error: (err as Error).message });
    }
  }
  return results;
}

/**
 * One-call gate for a swarm step: request the approval (rules
 * applied when a candidate + rules store are given) and wait for the
 * operator. Returns the approval row and the outcome the caller
 * acts on. On 'denied' the caller records the step as skipped in the
 * task todolist and moves on, it never auto-retries the step.
 */
export async function requestAndWait(
  store: ApprovalStore,
  input: RequestApprovalInput,
  opts: RequestApprovalOptions & { timeoutMs?: number } = {},
): Promise<{ approval: ApprovalRecord; outcome: 'allowed' | 'denied' }> {
  const approval = await requestApproval(store, input, opts);
  if (approval.status === 'allowed') return { approval, outcome: 'allowed' };
  if (approval.status !== 'pending') return { approval, outcome: 'denied' };
  const outcome = await waitForDecision(store, approval.id, opts.timeoutMs);
  const latest = (await store.get(approval.id)) ?? approval;
  return { approval: latest, outcome };
}

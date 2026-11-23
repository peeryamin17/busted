/**
 * Swarm-step gate: standing rules, then the LLM judge, then human approval.
 * Fails closed: a store error, a judge error, or a timeout all mean
 * "do not run". Identical tool calls are judged once per run.
 */
import type { GraphStore } from '../graph/store.js';
import type { LLMProvider } from '../llm/provider.js';
import type { ScopePolicy } from '../types.js';
import { isUrlInScope } from '../guardrails/scope.js';
import { redactText } from '../guardrails/redact.js';
import { judgeToolCall } from '../guardrails/judge.js';
import { riskScore, type ActionClass, type ScopePosition } from '../guardrails/risk.js';
import { findMatchingRule, type ApprovalRuleStore } from './rules.js';
import { requestApproval, waitForDecision, DEFAULT_APPROVAL_TIMEOUT_MS } from './service.js';
import type { ApprovalStore } from './store.js';

/** Swarm tool name → risk action class. Unknown tools score as 'other'. */
const TOOL_ACTION_CLASS: Record<string, ActionClass> = {
  fetch_url: 'read-only-fetch',
  fetch_js: 'read-only-fetch',
  fetch_sourcemap: 'read-only-fetch',
  check_security_headers: 'read-only-fetch',
  probe_cors: 'read-only-fetch',
  probe_reflected_xss: 'read-only-fetch',
  inspect_cookies: 'read-only-fetch',
  probe_idor: 'read-only-fetch',
  probe_graphql: 'graphql-query',
};

/** Tools that read session material (cookie attributes, never values). */
const CREDENTIAL_TOUCHING_TOOLS = new Set(['inspect_cookies']);

export interface GateToolCallInput {
  provider: LLMProvider;
  /** Absent = no approval queue attached: the step runs ungated, as before. */
  approvals?: ApprovalStore;
  approvalRules?: ApprovalRuleStore;
  /** Needed only to show the task as paused while waiting on the operator. */
  graph?: GraphStore;
  taskId: string;
  userId: string;
  tool: string;
  args: Record<string, unknown>;
  targetUrl: string;
  scope: ScopePolicy;
  /** Max wait for an operator decision; defaults to 5 minutes. */
  timeoutMs?: number;
  /** Per-run verdict cache (shared across workers of one run). */
  cache?: Map<string, 'allowed' | 'denied'>;
}

export interface GateOutcome {
  proceed: boolean;
  approvalId?: string;
  reason: string;
}

/** Short, redacted, stable summary of the proposed call for the record. */
function argsSummary(args: Record<string, unknown>): string {
  const keys = Object.keys(args).sort();
  const flat: Record<string, unknown> = {};
  for (const k of keys) {
    const v = args[k];
    flat[k] = typeof v === 'string' ? v.slice(0, 120) : v;
  }
  return redactText(JSON.stringify(flat), 300);
}

function scopeSummary(scope: ScopePolicy): string {
  return `mode=${scope.mode}, includeSubdomains=${scope.includeSubdomains}, excludedHosts=${JSON.stringify(scope.excludedHosts ?? [])}, excludedPaths=${JSON.stringify(scope.excludedPaths ?? [])}`;
}

function deriveScopePosition(
  urlStr: string,
  target: URL,
  scope: ScopePolicy,
): { position: ScopePosition; host: string } {
  let host = '';
  try {
    host = new URL(urlStr).hostname.toLowerCase();
  } catch {
    return { position: 'out-of-scope', host: '' };
  }
  if (!isUrlInScope(urlStr, target, scope).allowed) {
    return { position: 'out-of-scope', host };
  }
  const targetHost = target.hostname.toLowerCase();
  if (host === targetHost) return { position: 'primary', host };
  if (host.endsWith(`.${targetHost}`)) return { position: 'subdomain', host };
  return { position: 'edge', host };
}

export async function gateToolCall(input: GateToolCallInput): Promise<GateOutcome> {
  const { provider, approvals, approvalRules, graph, taskId, userId } = input;
  if (!approvals) {
    return { proceed: true, reason: 'no approval queue attached — ungated' };
  }
  const toolUrl =
    typeof input.args?.['url'] === 'string' ? (input.args['url'] as string) : input.targetUrl;
  let target: URL;
  try {
    target = new URL(input.targetUrl);
  } catch {
    return { proceed: false, reason: 'target URL is malformed — fail closed' };
  }
  const { position, host } = deriveScopePosition(toolUrl, target, input.scope);
  const targetHost = target.hostname.toLowerCase();
  const risk = riskScore({
    actionClass: TOOL_ACTION_CLASS[input.tool] ?? 'other',
    url: toolUrl,
    targetHost,
    host: host || undefined,
    scopePosition: position,
    touchesCredentials: CREDENTIAL_TOUCHING_TOOLS.has(input.tool),
    isNewHost: host !== '' && host !== targetHost,
  });

  // Per-run cache: an identical call judged once is judged enough.
  const cacheKey = `${input.tool}|${argsSummary(input.args)}`;
  const cached = input.cache?.get(cacheKey);
  if (cached) {
    return {
      proceed: cached === 'allowed',
      reason: `cached ${cached} verdict for this tool call (judged earlier this run)`,
    };
  }

  const detail = {
    tool: input.tool,
    args: argsSummary(input.args),
    riskBand: risk.band,
    riskReasons: risk.reasons,
  };
  const action = `${input.tool} ${toolUrl}`.slice(0, 500);

  try {
    // 1. Standing rules decide first, no judge when a rule speaks.
    if (approvalRules) {
      const rules = await approvalRules.listRulesForTask(userId, taskId);
      const matched = findMatchingRule(rules, { kind: 'tool', value: input.tool, taskId });
      if (matched && (matched.decision === 'allow' || matched.decision === 'deny')) {
        const record = await requestApproval(
          approvals,
          {
            taskId,
            userId,
            kind: 'tool-call',
            action,
            detail,
            riskScore: risk.score,
            requestedBy: 'swarm',
            candidate: { kind: 'tool', value: input.tool, taskId },
          },
          { rules: approvalRules },
        );
        const allowed = record.status === 'allowed';
        input.cache?.set(cacheKey, allowed ? 'allowed' : 'denied');
        return {
          proceed: allowed,
          approvalId: record.id,
          reason: `${allowed ? 'allowed' : 'denied'} by rule "${matched.pattern.value}" (${matched.id})`,
        };
      }
    }

    // 2. No rule matched: the judge decides, on the cheapest tier.
    const judgement = await judgeToolCall(provider, {
      tool: input.tool,
      args: input.args,
      targetHost,
      scopeSummary: scopeSummary(input.scope),
    });
    if (judgement.verdict === 'allow') {
      const record = await approvals.create({
        taskId,
        userId,
        kind: 'judge',
        action,
        detail: { ...detail, judgeAnswers: judgement.answers, judgeReason: judgement.reason },
        riskScore: risk.score,
        requestedBy: 'judge',
      });
      await approvals.decide(record.id, 'allow', 'judge').catch(() => undefined);
      input.cache?.set(cacheKey, 'allowed');
      return { proceed: true, approvalId: record.id, reason: 'judge cleared all 8 risk questions' };
    }

    // 3. Judge flagged it (or could not decide): wait for the operator.
    const record = await requestApproval(approvals, {
      taskId,
      userId,
      kind: 'judge',
      action,
      detail: { ...detail, judgeAnswers: judgement.answers, judgeReason: judgement.reason },
      riskScore: risk.score,
      requestedBy: 'judge',
    });
    // Show the task as paused while the operator decides; resume after.
    // Both transitions are best-effort: a concurrent waiter may already
    // hold the task paused, and the transition guard throws then.
    await graph?.updateTaskStatus(taskId, 'paused').catch(() => undefined);
    const outcome = await waitForDecision(
      approvals,
      record.id,
      input.timeoutMs ?? DEFAULT_APPROVAL_TIMEOUT_MS,
    );
    await graph?.updateTaskStatus(taskId, 'running').catch(() => undefined);
    input.cache?.set(cacheKey, outcome);
    return {
      proceed: outcome === 'allowed',
      approvalId: record.id,
      reason:
        outcome === 'allowed'
          ? 'operator allowed the step'
          : 'operator denied the step (or the wait timed out) — recorded as skipped, never retried',
    };
  } catch (err) {
    // The approval store (or the judge plumbing around it) failed: fail
    // closed, the step does not run, and the failure is on the record.
    return {
      proceed: false,
      reason: `approval gate failed (${(err as Error).message.slice(0, 120)}) — fail closed`,
    };
  }
}

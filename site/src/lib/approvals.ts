export interface ApprovalRulePattern {
  kind: 'tool' | 'target-host' | 'category';
  value: string;
}

export interface DecideApprovalInput {
  taskId: string;
  approvalId: string;
  decision: 'allow' | 'deny';
  alwaysAllow: boolean;
  pattern: ApprovalRulePattern;
  fetchImpl?: typeof fetch;
}

/**
 * Decide one approval. The standing-rule post runs first and must
 * succeed: if it fails we abort instead of deciding and letting the
 * user believe a rule exists that does not.
 */
export async function decideApproval(input: DecideApprovalInput): Promise<void> {
  const run = input.fetchImpl ?? fetch;
  if (input.decision === 'allow' && input.alwaysAllow) {
    const ruleRes = await run(`/api/tasks/${input.taskId}/approvals/rules`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        pattern: input.pattern,
        decision: 'allow',
        alwaysAllow: true,
        scope: 'task',
      }),
    });
    if (!ruleRes.ok) {
      throw new Error(`Standing rule was not saved (${ruleRes.status})`);
    }
  }
  const res = await run(`/api/tasks/${input.taskId}/approvals/${input.approvalId}/decide`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ decision: input.decision }),
  });
  if (!res.ok) {
    throw new Error(`Decision was not saved (${res.status})`);
  }
}

/** Keep polling while anything is pending, or while the last load failed. */
export function shouldKeepPolling(hasPending: boolean, loadFailed: boolean): boolean {
  return hasPending || loadFailed;
}
